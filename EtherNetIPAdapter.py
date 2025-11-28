import socket
import struct
import time
from typing import Any, Dict, Optional, Tuple, List, Callable

from PLC import PLC
from TCPUDPHandler import TCPUDPHandler


PayloadCallback = Callable[[int, "EtherNetIPAdapter"], Optional[bytes]]


class EtherNetIPAdapter:
    """
    Minimal, readable EtherNet/IP adapter.

    High-level methods (used by the manager):

      - open_and_wait_for_connection()
      - handle_tcp_handshake()
      - run_udp_cyclic(payload_callback=None, cycle_time=...)
      - close()

    The payload is NOT hardcoded: a payload_callback can be supplied
    so the program can change the O→T data as it progresses.
    """

    def __init__(self, plc: "PLC", net: "TCPUDPHandler") -> None:
        self.plc = plc
        self.net = net

        # Active TCP connection to PLC (after accept)
        self.conn: Optional[socket.socket] = None

        # Session handle for RegisterSession
        self.session_handle: int = 0

        # Connection parameters from Forward Open
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
        self.udp_seq_counter: int = 0      # 32-bit for Sequenced Address Item
        self.cip_data_seq: int = 0         # 16-bit for B1 Connected Data Item

        # O→T payload (application data only, 10 bytes by default)
        self.o2t_payload: bytearray = bytearray(self.o2t_size_bytes)

         # --- NEW: last T→O data from PLC (via UDP) ---
        self.last_t2o_payload: Optional[bytes] = None
        self.last_t2o_cip_seq: Optional[int] = None
        self.last_t2o_addr: Optional[Tuple[str, int]] = None

    # ======================================================================
    # High-level API methods (used by manager)
    # ======================================================================

    def open_and_wait_for_connection(self, timeout: Optional[float] = None) -> None:
        """
        1) Setup TCP + UDP ports
        2) Block until a TCP client connects
        """
        self.net.create_tcp_server(self.plc.tcp_port)
        self.net.create_udp_socket(self.plc.udp_io_port)

        print(
            f"[ADAPTER] Listening on TCP:{self.plc.tcp_port}, "
            f"UDP:{self.plc.udp_io_port}"
        )
        print("[ADAPTER] Waiting for TCP connection from PLC...")

        start = time.time()

        while True:
            if timeout is not None and (time.time() - start) > timeout:
                raise TimeoutError("Timed out waiting for TCP connection")

            client = self.net.accept_client(timeout=1.0)
            if client is not None:
                self.conn, addr = client
                self.conn.settimeout(1.0)
                print(f"[ADAPTER] TCP connected from {addr}")
                break

    def handle_tcp_handshake(self) -> None:
        """
        2) Handle EIP handshake over TCP:

           - RegisterSession
           - SendRRData with Forward Open
        """
        if self.conn is None:
            raise RuntimeError("No TCP connection: call open_and_wait_for_connection() first")

        print("[ADAPTER] Starting EIP handshake (RegisterSession + Forward Open)...")

        while self.t2o_conn_id == 0:
            try:
                data = self.net.recv_tcp(self.conn, bufsize=2048)
            except socket.timeout:
                continue
            except OSError as e:
                raise ConnectionError(f"TCP error during handshake: {e}")

            if not data:
                raise ConnectionError("TCP connection closed during handshake")

            self.handle_tcp_packet(self.conn, data)

        print(
            f"[ADAPTER] Handshake complete. "
            f"O→T ConnID=0x{self.o2t_conn_id:08X}, "
            f"T→O ConnID=0x{self.t2o_conn_id:08X}"
        )

    def run_udp_cyclic(
        self,
        payload_callback: Optional[PayloadCallback] = None,
        cycle_time: float = 0.05,
    ) -> None:
        """
        3) Run UDP cyclic I/O (blocks until Ctrl+C or error).

        Each cycle:
          - If payload_callback is provided:
                new_payload = payload_callback(cycle_index, self)
                If new_payload is not None:
                    self.set_o2t_payload(new_payload)
          - Receives T→O packet (if any) and replies with current O→T payload.
        """
        if self.net.udp_sock is None:
            raise RuntimeError("UDP socket not created; call open_and_wait_for_connection() first")

        print("[ADAPTER] Starting UDP cyclic I/O. Press Ctrl+C to stop.")

        cycle = 0
        try:
            while True:
                # Let program logic update the payload as it progresses
                if payload_callback is not None:
                    new_payload = payload_callback(cycle, self)
                    if new_payload is not None:
                        self.set_o2t_payload(new_payload)

                data, udp_addr = self.net.recv_udp(bufsize=2048, timeout=cycle_time)
                if data and udp_addr:
                    self.handle_udp_packet(data, udp_addr)

                cycle += 1
        except KeyboardInterrupt:
            print("\n[ADAPTER] UDP cyclic I/O stopped by user.")

    def close(self) -> None:
        """
        4) Close TCP and UDP sockets and clean up.
        """
        print("[ADAPTER] Closing communication...")
        if self.conn:
            try:
                self.conn.close()
            except OSError:
                pass
            self.conn = None
        self.net.close()
        print("[ADAPTER] Closed.")

    # ======================================================================
    # Payload helper
    # ======================================================================

    def set_o2t_payload(self, data: bytes) -> None:
        """
        Helper to set the O→T application payload (10 bytes by default).
        """
        buf = bytearray(self.o2t_size_bytes)
        buf[: min(len(data), self.o2t_size_bytes)] = data[:self.o2t_size_bytes]
        self.o2t_payload = buf

    # ======================================================================
    # TCP HALF (single parser + handlers)
    # ======================================================================

    def parse_tcp_packet(self, raw: bytes) -> Dict[str, Any]:
        if len(raw) < 24:
            raise ValueError("EIP TCP packet too short")

        command, length, session, status = struct.unpack_from("<HHII", raw, 0)
        context = raw[12:20]
        options, = struct.unpack_from("<I", raw, 20)
        data = raw[24:24 + length]

        return {
            "command": command,
            "length": length,
            "session": session,
            "status": status,
            "context": context,
            "options": options,
            "data": data,
        }

    def handle_tcp_packet(self, conn: socket.socket, raw: bytes) -> None:
        pkt = self.parse_tcp_packet(raw)
        cmd = pkt["command"]

        if cmd == 0x0065:  # RegisterSession
            self._handle_register_session(conn, pkt)
        elif cmd == 0x006F:  # SendRRData
            self._handle_send_rrdata(conn, pkt)
        else:
            print(f"[TCP] Unsupported EIP command: 0x{cmd:04X}")

    def _handle_register_session(self, conn: socket.socket, pkt: Dict[str, Any]) -> None:
        if self.session_handle == 0:
            self.session_handle = 1

        data = pkt["data"]
        if len(data) < 4:
            proto_ver = 1
            encap_opts = 0
        else:
            proto_ver, encap_opts = struct.unpack_from("<HH", data, 0)

        payload = struct.pack("<HH", proto_ver, encap_opts)

        header = struct.pack(
            "<HHII8sI",
            0x0065,
            len(payload),
            self.session_handle,
            0,
            pkt["context"],
            pkt["options"],
        )
        resp = header + payload

        print(f"[TCP] RegisterSession -> session={self.session_handle}")
        self.net.send_tcp(conn, resp)

    def _handle_send_rrdata(self, conn: socket.socket, pkt: Dict[str, Any]) -> None:
        if self.session_handle == 0:
            print("[TCP] SendRRData before RegisterSession")
            return

        iface, timeout, cpf_items = self._parse_cpf(pkt["data"])
        cip = self._extract_unconnected_data_item(cpf_items)
        if cip is None:
            print("[TCP] No UnconnectedData item in SendRRData")
            return

        if len(cip) < 2:
            print("[TCP] CIP data too short")
            return

        service = cip[0]
        if service == 0x54:  # Forward Open
            cip_reply = self._handle_cip_forward_open(cip)
        else:
            print(f"[TCP] Unsupported CIP service in SendRRData: 0x{service:02X}")
            return

        cpf_resp = self._build_cpf_with_unconnected_data(iface, timeout, cip_reply)
        header = struct.pack(
            "<HHII8sI",
            0x006F,
            len(cpf_resp),
            self.session_handle,
            0,
            pkt["context"],
            pkt["options"],
        )
        resp = header + cpf_resp

        self.net.send_tcp(conn, resp)

    def _parse_cpf(self, data: bytes) -> Tuple[int, int, List[Tuple[int, bytes]]]:
        if len(data) < 8:
            raise ValueError("CPF too short")

        interface_handle, timeout, item_count = struct.unpack_from("<IHH", data, 0)
        offset = 8
        items: List[Tuple[int, bytes]] = []

        for _ in range(item_count):
            if len(data) < offset + 4:
                break
            item_type, item_len = struct.unpack_from("<HH", data, offset)
            offset += 4
            item_data = data[offset:offset + item_len]
            offset += item_len
            items.append((item_type, item_data))

        return interface_handle, timeout, items

    @staticmethod
    def _extract_unconnected_data_item(
        items: List[Tuple[int, bytes]]
    ) -> Optional[bytes]:
        for item_type, item_data in items:
            if item_type == 0x00B2:
                return item_data
        return None

    def _build_cpf_with_unconnected_data(
        self,
        interface_handle: int,
        timeout: int,
        cip_data: bytes,
    ) -> bytes:
        null_type = 0x0000
        null_len = 0
        unconn_type = 0x00B2
        unconn_len = len(cip_data)

        items = struct.pack("<IHH", interface_handle, timeout, 2)
        items += struct.pack("<HH", null_type, null_len)
        items += struct.pack("<HH", unconn_type, unconn_len)
        items += cip_data
        return items

    def _handle_cip_forward_open(self, cip: bytes) -> bytes:
        service = cip[0]
        path_word_count = cip[1]
        path_len_bytes = path_word_count * 2
        body = cip[2 + path_len_bytes:]

        if service != 0x54:
            raise ValueError("Not Forward Open")

        if len(body) < 36:
            raise ValueError("Forward Open body too short")

        o2t_conn_id = struct.unpack_from("<I", body, 2)[0]
        t2o_conn_id = struct.unpack_from("<I", body, 6)[0]
        conn_serial = struct.unpack_from("<H", body, 10)[0]
        vendor_id = struct.unpack_from("<H", body, 12)[0]
        origin_serial = struct.unpack_from("<I", body, 14)[0]
        o2t_rpi = struct.unpack_from("<I", body, 22)[0]
        t2o_rpi = struct.unpack_from("<I", body, 28)[0]

        self.o2t_conn_id = o2t_conn_id or 0x12345678
        self.t2o_conn_id = t2o_conn_id or 0x87654321
        self.o2t_rpi_us = o2t_rpi
        self.t2o_rpi_us = t2o_rpi

        print(
            f"[CIP] Forward Open:"
            f" O→T ConnID=0x{self.o2t_conn_id:08X},"
            f" T→O ConnID=0x{self.t2o_conn_id:08X},"
            f" O→T RPI={self.o2t_rpi_us},"
            f" T→O RPI={self.t2o_rpi_us}"
        )

        header = bytes([
            service | 0x80,
            0x00,
            0x00,
            0x00,
        ])

        body_resp = struct.pack(
            "<IIHHI",
            self.o2t_conn_id,
            self.t2o_conn_id,
            conn_serial,
            vendor_id,
            origin_serial,
        )
        body_resp += struct.pack("<II", o2t_rpi, t2o_rpi)
        body_resp += struct.pack("BB", 0, 0)

        return header + body_resp

    # ======================================================================
    # UDP CYCLIC IO HALF
    # ======================================================================

    def parse_udp_packet(
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

        min_needed = 2 + self.t2o_size_bytes
        if len(raw) < b1_payload_offset + min_needed:
            print("[UDP] Packet too short for expected T→O payload")
            return None

        cip_seq_in = struct.unpack_from("<H", raw, b1_payload_offset)[0]
        t2o_start = b1_payload_offset + 2
        t2o_end = t2o_start + self.t2o_size_bytes
        t2o_payload = raw[t2o_start:t2o_end]

        # --- NEW: store last T→O data so main can read it ---
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
            "source_addr": addr,
            "cip_seq_in": cip_seq_in,
            "t2o_payload": t2o_payload,
        }

    def handle_udp_packet(self, raw: bytes, addr: Tuple[str, int]) -> None:
        parsed = self.parse_udp_packet(raw, addr)
        if parsed is None:
            return

        packet = self._build_o2t_udp_packet()
        if packet is None:
            return

        dst_addr = self.plc_udp_addr or addr
        self.net.send_udp(packet, dst_addr)

    def _build_o2t_udp_packet(self) -> Optional[bytes]:
        if self.udp_header_template is None:
            return None
        if self.t2o_conn_id == 0:
            return None

        header = bytearray(self.udp_header_template)

        if len(header) >= 10:
            struct.pack_into("<I", header, 6, self.t2o_conn_id)

        if len(header) >= 14:
            struct.pack_into("<I", header, 10, self.udp_seq_counter)
        self.udp_seq_counter = (self.udp_seq_counter + 1) & 0xFFFFFFFF

        cip_seq_out = self.cip_data_seq & 0xFFFF
        self.cip_data_seq = (self.cip_data_seq + 1) & 0xFFFF

        b1_payload = struct.pack("<H", cip_seq_out) + bytes(self.o2t_payload)

        packet = bytes(header) + b1_payload

        print(
            f"[UDP] TX CIPseq=0x{cip_seq_out:04X}, "
            f"O→T asm={self.o2t_payload.hex(' ')}"
        )
        return packet
        # --- NEW: getters for last T→O data ---

    def get_last_t2o_payload(self) -> Optional[bytes]:
        """Return the last T→O application payload received from the PLC."""
        return self.last_t2o_payload

    def get_last_t2o_info(self) -> Dict[str, Optional[object]]:
        """Return last T→O details as a small dict."""
        return {
            "payload": self.last_t2o_payload,
            "cip_seq": self.last_t2o_cip_seq,
            "addr": self.last_t2o_addr,
        }

