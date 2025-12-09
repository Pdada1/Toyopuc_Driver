# ethernet_ip_adapter.py
from __future__ import annotations

import socket
import struct
import threading
import time
import secrets
from typing import Any, Dict, Optional, Tuple, Callable

from plc import PLC
from tcp_udp_handler import TCPUDPHandler
from eip_protocol import (
    EIPHeader,
    CPF,
    ForwardOpenInfo,
    parse_eip_header,
    parse_cpf,
    extract_unconnected_data_item,
    parse_forward_open,
    build_cpf_with_unconnected_data,
    build_forward_open_success,
)

PayloadCallback = Callable[[int, "EtherNetIPAdapter"], Optional[bytes]]
Addr = Tuple[str, int]


class EtherNetIPAdapter:
    """
    EtherNet/IP adapter for TOYOPUC.

    - Accepts TCP session from PLC.
    - Handles RegisterSession + ForwardOpen.
    - Runs cyclic UDP I/O:
        * T→O: PLC → PC (we parse and expose payload).
        * O→T: PC → PLC (we build from scratch, matching working driver).
    """

    def __init__(self, plc: PLC, net: TCPUDPHandler) -> None:
        self.plc = plc
        self.net = net

        # TCP
        self.conn: Optional[socket.socket] = None
        self._connected = False

        # Session / connections
        self.session_handle = 0
        self.o2t_conn_id = 0  # adapter → PLC
        self.t2o_conn_id = 0  # PLC → adapter
        self.o2t_rpi_us = 0
        self.t2o_rpi_us = 0

        # Sizes
        self.o2t_size_bytes = plc.o2t_size_bytes
        self.t2o_size_bytes = plc.t2o_size_bytes

        # Current O→T payload contents
        self.o2t_payload = bytearray(self.o2t_size_bytes)

        # Last T→O contents for app
        self.last_t2o_payload: Optional[bytes] = None
        self.last_t2o_cip_seq: Optional[int] = None
        self.last_t2o_addr: Optional[Addr] = None

        # UDP state
        self.plc_udp_addr: Optional[Addr] = None
        self.udp_seq_counter = 0
        self.cip_data_seq = 0

        # Cyclic I/O
        self._io_running = False
        self._io_thread: Optional[threading.Thread] = None
        self._io_lock = threading.Lock()

    # ------------------------------------------------------------------
    # TCP connection + handshake
    # ------------------------------------------------------------------

    def open_and_wait_for_connection(self, timeout: Optional[float] = None) -> bool:
        """Accept TCP connection from PLC and prepare UDP."""
        self.net.create_tcp_server(self.plc.tcp_port)
        self.net.create_udp_socket(self.plc.udp_io_port)

        print(
            f"[ADAPTER] Listening TCP:{self.plc.tcp_port}, "
            f"UDP:{self.plc.udp_io_port}"
        )
        print("[ADAPTER] Waiting for PLC TCP connection...")

        start = time.time()
        while True:
            if timeout is not None and time.time() - start > timeout:
                print("[ADAPTER] TCP wait timeout")
                return False

            accepted = self.net.accept_client(timeout=1.0)
            if accepted is None:
                continue

            self.conn, addr = accepted
            self.conn.settimeout(1.0)
            self._connected = True
            print(f"[ADAPTER] TCP connected from {addr}")
            return True

    def handle_tcp_handshake(self, timeout: Optional[float] = None) -> bool:
        """Handle RegisterSession + ForwardOpen from PLC."""
        if not self.conn:
            raise RuntimeError("No TCP connection yet")

        print("[ADAPTER] Starting EIP handshake...")
        start = time.time()

        while True:
            if timeout is not None and time.time() - start > timeout:
                print("[ADAPTER] Handshake timeout")
                return False

            raw = self._safe_recv_tcp(self.conn, 2048)
            if raw is None:
                continue

            try:
                self._handle_eip_tcp_message(self.conn, raw)
            except Exception as ex:
                print(f"[ADAPTER] Handshake error: {ex}")
                return False

            if self.o2t_conn_id != 0 and self.t2o_conn_id != 0:
                print(
                    "[ADAPTER] Handshake complete: "
                    f"O→T=0x{self.o2t_conn_id:08X}, "
                    f"T→O=0x{self.t2o_conn_id:08X}"
                )
                return True

    # ------------------------------------------------------------------
    # Cyclic UDP I/O
    # ------------------------------------------------------------------

    def start_udp_cyclic_thread(
        self,
        payload_callback: Optional[PayloadCallback],
        cycle_time: float,
    ) -> None:
        if self._io_running:
            return

        self._io_running = True

        def loop() -> None:
            print("[ADAPTER] UDP cyclic I/O thread started")
            cycle = 0
            while self._io_running:
                # Allow app to update O→T payload
                if payload_callback is not None:
                    try:
                        new = payload_callback(cycle, self)
                        if new is not None:
                            with self._io_lock:
                                self.set_o2t_payload(new)
                    except Exception as ex:
                        print(f"[ADAPTER] payload_callback error: {ex}")

                # Receive T→O
                data, addr = self.net.recv_udp(bufsize=2048, timeout=cycle_time)
                if data and addr:
                    try:
                        self._handle_udp_t2o(data, addr)
                    except Exception as ex:
                        print(f"[ADAPTER] UDP T→O parse error: {ex}")

                # Send O→T
                if self.plc_udp_addr:
                    pkt = self._build_o2t_udp_packet()
                    if pkt:
                        self.net.send_udp(pkt, self.plc_udp_addr)

                cycle += 1

            print("[ADAPTER] UDP cyclic I/O thread exiting")

        self._io_thread = threading.Thread(target=loop, daemon=True)
        self._io_thread.start()

    def stop_udp_cyclic(self, wait: bool = True) -> None:
        self._io_running = False
        if wait and self._io_thread is not None:
            self._io_thread.join(timeout=2.0)
            self._io_thread = None

    def close(self) -> None:
        print("[ADAPTER] Closing communication...")
        self.stop_udp_cyclic()
        self._connected = False

        if self.conn is not None:
            try:
                self.conn.close()
            except OSError:
                pass
            self.conn = None

        self.net.close()
        print("[ADAPTER] Closed")

    # ------------------------------------------------------------------
    # Application payload & info
    # ------------------------------------------------------------------

    def set_o2t_payload(self, data: bytes) -> None:
        buf = bytearray(self.o2t_size_bytes)
        buf[: min(len(data), self.o2t_size_bytes)] = data[: self.o2t_size_bytes]
        self.o2t_payload = buf

    def get_last_t2o_payload(self) -> Optional[bytes]:
        return self.last_t2o_payload

    def get_last_t2o_info(self) -> Dict[str, Optional[Any]]:
        return {
            "payload": self.last_t2o_payload,
            "cip_seq": self.last_t2o_cip_seq,
            "addr": self.last_t2o_addr,
        }

    # ------------------------------------------------------------------
    # Internal TCP helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_recv_tcp(conn: socket.socket, bufsize: int) -> Optional[bytes]:
        try:
            data = conn.recv(bufsize)
        except socket.timeout:
            return None
        if not data:
            return None
        return data

    def _handle_eip_tcp_message(self, conn: socket.socket, raw: bytes) -> None:
        header: EIPHeader = parse_eip_header(raw)
        if header.command == 0x0065:
            self._handle_register_session(conn, header)
        elif header.command == 0x006F:
            self._handle_send_rrdata(conn, header)
        else:
            print(f"[TCP] Unsupported EIP command: 0x{header.command:04X}")

    def _handle_register_session(self, conn: socket.socket, header: EIPHeader) -> None:
        data = header.data or b"\x01\x00\x00\x00"
        if len(data) >= 4:
            proto_ver, opts = struct.unpack_from("<HH", data, 0)
        else:
            proto_ver, opts = 1, 0

        self.session_handle = 1
        resp_data = struct.pack("<HH", proto_ver, opts)
        resp = self._build_eip_header(
            command=0x0065,
            session=self.session_handle,
            status=0,
            context=header.context,
            options=0,
            data=resp_data,
        )
        self.net.send_tcp(conn, resp)
        print(f"[TCP] RegisterSession complete; session={self.session_handle}")

    # ------------------------------------------------------------------
    # Forward Open — **patched connID mapping**
    # ------------------------------------------------------------------

    def _handle_send_rrdata(self, conn: socket.socket, header: EIPHeader) -> None:
        cpf: CPF = parse_cpf(header.data)
        cip_data = extract_unconnected_data_item(cpf)
        if cip_data is None:
            print("[TCP] No Unconnected Data item in SendRRData")
            return

        fo: ForwardOpenInfo = parse_forward_open(cip_data)

        # Correct mapping:
        #   PLC → PC  (T→O)  uses fo.o2t_conn_id
        #   PC → PLC  (O→T)  uses fo.t2o_conn_id
        if self.t2o_conn_id == 0:
            self.t2o_conn_id = (
                fo.o2t_conn_id if fo.o2t_conn_id != 0 else secrets.randbits(32)
            )
        if self.o2t_conn_id == 0:
            self.o2t_conn_id = (
                fo.t2o_conn_id if fo.t2o_conn_id != 0 else secrets.randbits(32)
            )

        self.o2t_rpi_us = fo.o2t_rpi
        self.t2o_rpi_us = fo.t2o_rpi

        print(
            "[CIP] Forward Open: "
            f"O→T=0x{self.o2t_conn_id:08X}, "
            f"T→O=0x{self.t2o_conn_id:08X}, "
            f"O→T RPI={self.o2t_rpi_us}, T→O RPI={self.t2o_rpi_us}"
        )

        cip_reply = build_forward_open_success(
            fo,
            o2t_conn_id=self.o2t_conn_id,
            t2o_conn_id=self.t2o_conn_id,
        )
        cpf_resp = build_cpf_with_unconnected_data(
            cpf.interface_handle,
            cpf.timeout,
            cip_reply,
        )
        resp = self._build_eip_header(
            command=0x006F,
            session=self.session_handle,
            status=0,
            context=header.context,
            options=0,
            data=cpf_resp,
        )
        self.net.send_tcp(conn, resp)

    @staticmethod
    def _build_eip_header(
        command: int,
        session: int,
        status: int,
        context: bytes,
        options: int,
        data: bytes,
    ) -> bytes:
        if len(context) != 8:
            context = context[:8].ljust(8, b"\x00")
        length = len(data)
        header = struct.pack(
            "<HHII8sI",
            command,
            length,
            session,
            status,
            context,
            options,
        )
        return header + data

    # ------------------------------------------------------------------
    # UDP T→O parse + O→T build
    # ------------------------------------------------------------------

    def _handle_udp_t2o(self, raw: bytes, addr: Addr) -> None:
        """Parse PLC→PC cyclic packet and extract actual T→O application bytes."""
        if len(raw) < 10:
            return

        self.plc_udp_addr = addr

        off = 0
        item_count = struct.unpack_from("<H", raw, off)[0]
        off += 2

        payload: Optional[bytes] = None
        cip_seq: Optional[int] = None

        for _ in range(item_count):
            if off + 4 > len(raw):
                break

            item_type, item_len = struct.unpack_from("<HH", raw, off)
            off += 4
            end = off + item_len
            if end > len(raw):
                break

            item = raw[off:end]
            off = end

            # Connected Data Item (0x00B1)
            if item_type == 0x00B1 and item_len >= 2 + 4:
                # 2 bytes CIP Sequence
                cip_seq = struct.unpack_from("<H", item, 0)[0]

                # 4-byte Toyopuc CIP header we ignore
                app_start = 6
                app_end = app_start + self.t2o_size_bytes

                # Extract exactly t2o_size_bytes
                raw_app = item[app_start:app_end]

                # Pad if fewer bytes (safety measure)
                if len(raw_app) < self.t2o_size_bytes:
                    raw_app = raw_app + b"\x00" * (self.t2o_size_bytes - len(raw_app))

                payload = raw_app

        if payload is not None:
            self.last_t2o_payload = payload
            self.last_t2o_cip_seq = cip_seq
            self.last_t2o_addr = addr

    def _build_o2t_udp_packet(self) -> Optional[bytes]:
        """Build O→T packet using EXACTLY plc.o2t_size_bytes of application data."""
        if self.o2t_conn_id == 0:
            return None
        if self.plc_udp_addr is None:
            return None

        # Increment sequences
        self.udp_seq_counter = (self.udp_seq_counter + 1) & 0xFFFFFFFF
        self.cip_data_seq = (self.cip_data_seq + 1) & 0xFFFF

        # FORCE payload length to exactly o2t_size_bytes
        app = bytes(self.o2t_payload)
        if len(app) < self.o2t_size_bytes:
            app = app + b"\x00" * (self.o2t_size_bytes - len(app))
        else:
            app = app[: self.o2t_size_bytes]

        # Connected Data Item length = 2 (CIP seq) + exact payload size
        b1_len = 2 + self.o2t_size_bytes

        pkt = bytearray()
        pkt += struct.pack("<H", 2)                  # Item count = 2
        pkt += struct.pack("<HHI", 0x8002, 8, self.o2t_conn_id)
        pkt += struct.pack("<I", self.udp_seq_counter)
        pkt += struct.pack("<HHH", 0x00B1, b1_len, self.cip_data_seq)
        pkt += app                                    # Actual data EXACT length

        return bytes(pkt)
