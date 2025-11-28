# ethernet_ip_adapter.py

import socket
import struct
import time
import threading
from typing import Any, Dict, Optional, Tuple, List, Callable

from plc import PLC
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
from tcp_udp_handler import TCPUDPHandler

PayloadCallback = Callable[[int, "EtherNetIPAdapter"], Optional[bytes]]


class EtherNetIPAdapter:
    """
    EtherNet/IP adapter focused on:
      - Managing connection state (session, conn IDs, last I/O)
      - I/O with TCPUDPHandler
      - Using pure protocol helpers from eip_protocol.py
      - Running UDP cyclic I/O in a background thread
    """

    def __init__(self, plc: "PLC", net: "TCPUDPHandler") -> None:
        self.plc = plc
        self.net = net

        # TCP connection state
        self.conn: Optional[socket.socket] = None
        self._connected: bool = False

        # Session / connection state
        self.session_handle: int = 0
        self.o2t_conn_id: int = 0
        self.t2o_conn_id: int = 0
        self.o2t_rpi_us: int = 0
        self.t2o_rpi_us: int = 0

        # Assemblies and sizes
        self.t2o_assembly: int = plc.t2o_assembly
        self.o2t_assembly: int = plc.o2t_assembly
        self.t2o_size_bytes: int = plc.t2o_size_bytes
        self.o2t_size_bytes: int = plc.o2t_size_bytes

        # UDP I/O state
        self.plc_udp_addr: Optional[Tuple[str, int]] = None
        self.udp_header_template: Optional[bytes] = None

        # Sequence counters
        self.udp_seq_counter: int = 0
        self.cip_data_seq: int = 0

        # Current O→T payload
        self.o2t_payload: bytearray = bytearray(self.o2t_size_bytes)

        # Last T→O for reading by user
        self.last_t2o_payload: Optional[bytes] = None
        self.last_t2o_cip_seq: Optional[int] = None
        self.last_t2o_addr: Optional[Tuple[str, int]] = None

        # Cyclic I/O control
        self._io_running: bool = False
        self._io_thread: Optional[threading.Thread] = None
        self._io_lock = threading.Lock()  # protect shared payload/state if needed

    # ------------------------------------------------------------------ #
    # High-level lifecycle (TCP connect + handshake)
    # ------------------------------------------------------------------ #

    def open_and_wait_for_connection(self, timeout: Optional[float] = None) -> bool:
        self.net.create_tcp_server(self.plc.tcp_port)
        self.net.create_udp_socket(self.plc.udp_io_port)

        print(
            f"[ADAPTER] Listening on TCP:{self.plc.tcp_port}, "
            f"UDP:{self.plc.udp_io_port}"
        )
        print("[ADAPTER] Waiting for TCP connection from PLC...")

        self._connected = False
        start = time.time()

        while not self._connected:
            if timeout is not None and (time.time() - start) > timeout:
                print("[ADAPTER] TCP connection timeout.")
                return False

            client = self.net.accept_client(timeout=1.0)
            if client is None:
                continue

            self.conn, addr = client
            self.conn.settimeout(1.0)
            self._connected = True
            print(f"[ADAPTER] TCP connected from {addr}")

        return True

    def handle_tcp_handshake(self, timeout: Optional[float] = None) -> bool:
        if not self._connected or self.conn is None:
            raise RuntimeError("No TCP connection: call open_and_wait_for_connection() first")

        print("[ADAPTER] Starting EIP handshake (RegisterSession + Forward Open)...")

        start = time.time()

        while self.t2o_conn_id == 0:
            if timeout is not None and (time.time() - start) > timeout:
                print("[ADAPTER] Handshake timeout.")
                return False

            raw = self._safe_recv_tcp(self.conn, 2048)
            if raw is None:
                continue

            try:
                self._handle_eip_tcp_message(self.conn, raw)
            except Exception as exc:
                print(f"[ADAPTER] Error during handshake: {exc}")
                return False

        print(
            f"[ADAPTER] Handshake complete. "
            f"O→T ConnID=0x{self.o2t_conn_id:08X}, "
            f"T→O ConnID=0x{self.t2o_conn_id:08X}"
        )
        return True

    # ------------------------------------------------------------------ #
    # Threaded UDP cyclic API
    # ------------------------------------------------------------------ #

    def start_udp_cyclic_thread(
        self,
        payload_callback: Optional[PayloadCallback] = None,
        cycle_time: float = 0.05,
    ) -> None:
        """
        Start UDP cyclic I/O in a background thread.

        This returns immediately; the loop runs until stop_udp_cyclic() is called
        or close() is called.
        """
        if self.net.udp_sock is None:
            raise RuntimeError("UDP socket not created; call open_and_wait_for_connection() first")

        if self._io_thread is not None and self._io_thread.is_alive():
            print("[ADAPTER] UDP cyclic thread already running.")
            return

        self._io_running = True

        def _loop():
            print("[ADAPTER] UDP cyclic I/O thread started.")
            cycle = 0
            while self._io_running:
                # Application payload update
                if payload_callback is not None:
                    try:
                        new_payload = payload_callback(cycle, self)
                        if new_payload is not None:
                            with self._io_lock:
                                self.set_o2t_payload(new_payload)
                    except Exception as exc:
                        print(f"[ADAPTER] payload_callback error: {exc}")

                # Receive one datagram (or timeout)
                data, udp_addr = self.net.recv_udp(bufsize=2048, timeout=cycle_time)
                if data and udp_addr:
                    try:
                        self._handle_udp_message(data, udp_addr)
                    except Exception as exc:
                        print(f"[ADAPTER] UDP handling error: {exc}")

                cycle += 1

            print("[ADAPTER] UDP cyclic I/O thread exiting.")

        self._io_thread = threading.Thread(target=_loop, daemon=True)
        self._io_thread.start()

    def stop_udp_cyclic(self, wait: bool = True) -> None:
        """
        Request the UDP cyclic thread to stop.
        If wait=True, this call will block until the thread has exited.
        """
        self._io_running = False
        if wait and self._io_thread is not None:
            self._io_thread.join(timeout=2.0)
            if self._io_thread.is_alive():
                print("[ADAPTER] Warning: UDP thread did not exit in time.")
            self._io_thread = None

    def close(self) -> None:
        """
        Stop UDP thread and close TCP/UDP sockets.
        """
        print("[ADAPTER] Closing communication...")
        self.stop_udp_cyclic(wait=True)
        self._connected = False

        if self.conn is not None:
            try:
                self.conn.close()
            except OSError:
                pass
            self.conn = None

        self.net.close()
        print("[ADAPTER] Closed.")

    # ------------------------------------------------------------------ #
    # Payload + readback
    # ------------------------------------------------------------------ #

    def set_o2t_payload(self, data: bytes) -> None:
        buf = bytearray(self.o2t_size_bytes)
        buf[: min(len(data), self.o2t_size_bytes)] = data[:self.o2t_size_bytes]
        self.o2t_payload = buf

    def get_last_t2o_payload(self) -> Optional[bytes]:
        return self.last_t2o_payload

    def get_last_t2o_info(self) -> Dict[str, Optional[Any]]:
        return {
            "payload": self.last_t2o_payload,
            "cip_seq": self.last_t2o_cip_seq,
            "addr": self.last_t2o_addr,
        }

    # ------------------------------------------------------------------ #
    # Internal: TCP helpers + dispatch
    # ------------------------------------------------------------------ #

    @staticmethod
    def _safe_recv_tcp(conn: socket.socket, bufsize: int) -> Optional[bytes]:
        try:
            data = conn.recv(bufsize)
        except socket.timeout:
            return None
        except OSError as exc:
            raise ConnectionError(f"TCP receive error: {exc}")

        if not data:
            raise ConnectionError("TCP connection closed by peer")
        return data

    def _handle_eip_tcp_message(self, conn: socket.socket, raw: bytes) -> None:
        header: EIPHeader = parse_eip_header(raw)

        if header.command == 0x0065:      # RegisterSession
            self._handle_register_session(conn, header)
        elif header.command == 0x006F:    # SendRRData
            self._handle_send_rrdata(conn, header)
        else:
            print(f"[TCP] Unsupported EIP command: 0x{header.command:04X}")

    def _handle_register_session(self, conn: socket.socket, header: EIPHeader) -> None:
        if self.session_handle == 0:
            self.session_handle = 1

        data = header.data
        if len(data) < 4:
            proto_ver = 1
            encap_opts = 0
        else:
            proto_ver, encap_opts = struct.unpack_from("<HH", data, 0)

        payload = struct.pack("<HH", proto_ver, encap_opts)
        resp = struct.pack(
            "<HHII8sI",
            0x0065,
            len(payload),
            self.session_handle,
            0,
            header.context,
            header.options,
        ) + payload

        print(f"[TCP] RegisterSession -> session={self.session_handle}")
        self.net.send_tcp(conn, resp)

    def _handle_send_rrdata(self, conn: socket.socket, header: EIPHeader) -> None:
        if self.session_handle == 0:
            print("[TCP] SendRRData received before RegisterSession")
            return

        cpf: CPF = parse_cpf(header.data)
        cip_data = extract_unconnected_data_item(cpf)
        if cip_data is None:
            print("[TCP] No Unconnected Data item in SendRRData")
            return

        try:
            fo: ForwardOpenInfo = parse_forward_open(cip_data)
        except ValueError as exc:
            print(f"[TCP] Unsupported CIP in SendRRData: {exc}")
            return

        if self.o2t_conn_id == 0:
            self.o2t_conn_id = fo.o2t_conn_id or 0x12345678
        if self.t2o_conn_id == 0:
            self.t2o_conn_id = fo.t2o_conn_id or 0x87654321

        self.o2t_rpi_us = fo.o2t_rpi
        self.t2o_rpi_us = fo.t2o_rpi

        print(
            f"[CIP] Forward Open:"
            f" O→T ConnID=0x{self.o2t_conn_id:08X},"
            f" T→O ConnID=0x{self.t2o_conn_id:08X},"
            f" O→T RPI={self.o2t_rpi_us},"
            f" T→O RPI={self.t2o_rpi_us}"
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

        resp = struct.pack(
            "<HHII8sI",
            0x006F,
            len(cpf_resp),
            self.session_handle,
            0,
            header.context,
            header.options,
        ) + cpf_resp

        self.net.send_tcp(conn, resp)

    # ------------------------------------------------------------------ #
    # Internal: UDP I/O
    # ------------------------------------------------------------------ #

    def _handle_udp_message(self, raw: bytes, addr: Tuple[str, int]) -> None:
        parsed = self._parse_udp_io_packet(raw, addr)
        if parsed is None:
            return

        packet = self._build_o2t_udp_packet()
        if packet is None:
            return

        dst_addr = self.plc_udp_addr or addr
        self.net.send_udp(packet, dst_addr)

    def _parse_udp_io_packet(
        self, raw: bytes, addr: Tuple[str, int]
    ) -> Optional[Dict[str, Any]]:
        if len(raw) < 8:
            return None

        self.plc_udp_addr = addr

        idx = raw.find(b"\xB1\x00")
        if idx == -1 or len(raw) < idx + 4:
            print("[UDP] No B1 Connected Data Item found")
            return None

        b1_len = struct.unpack_from("<H", raw, idx + 2)[0]
        b1_payload_offset = idx + 4
        if b1_len < 2:
            print("[UDP] B1 length too small")
            return None

        needed = 2 + self.t2o_size_bytes
        if len(raw) < b1_payload_offset + needed:
            print("[UDP] Packet too short for expected T→O payload")
            return None

        cip_seq_in = struct.unpack_from("<H", raw, b1_payload_offset)[0]
        t2o_start = b1_payload_offset + 2
        t2o_end = t2o_start + self.t2o_size_bytes
        t2o_payload = raw[t2o_start:t2o_end]

        self.last_t2o_payload = t2o_payload
        self.last_t2o_cip_seq = cip_seq_in
        self.last_t2o_addr = addr

        header_template = raw[:b1_payload_offset]
        b1_len_out = 2 + self.o2t_size_bytes
        header_mut = bytearray(header_template)
        struct.pack_into("<H", header_mut, idx + 2, b1_len_out)
        self.udp_header_template = bytes(header_mut)

        print(
            f"[UDP] RX from {addr}, CIPseq=0x{cip_seq_in:04X}, "
            f"T→O asm={t2o_payload.hex(' ')}"
        )

        return {
            "addr": addr,
            "cip_seq_in": cip_seq_in,
            "t2o_payload": t2o_payload,
        }

    def _build_o2t_udp_packet(self) -> Optional[bytes]:
        if self.udp_header_template is None:
            return None
        if self.t2o_conn_id == 0:
            return None

        header = bytearray(self.udp_header_template)

        # Conn ID in Sequenced Address Item
        if len(header) >= 10:
            struct.pack_into("<I", header, 6, self.t2o_conn_id)

        # 32-bit sequence
        if len(header) >= 14:
            struct.pack_into("<I", header, 10, self.udp_seq_counter)
        self.udp_seq_counter = (self.udp_seq_counter + 1) & 0xFFFFFFFF

        # CIP sequence
        cip_seq_out = self.cip_data_seq & 0xFFFF
        self.cip_data_seq = (self.cip_data_seq + 1) & 0xFFFF

        b1_payload = struct.pack("<H", cip_seq_out) + bytes(self.o2t_payload)
        packet = bytes(header) + b1_payload

        print(
            f"[UDP] TX CIPseq=0x{cip_seq_out:04X}, "
            f"O→T asm={self.o2t_payload.hex(' ')}"
        )
        return packet
