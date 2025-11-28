import socket
import struct
import threading
import time
import random
from typing import Dict, Any, Optional


class EtherNetIPAdapter:
    """
    Minimal working EtherNet/IP adapter simulation.

    Features:
      ✔ RegisterSession
      ✔ SendRRData + Forward Open (SUCCESS)
      ✔ Emulates Assembly 100 (O→T) and Assembly 101 (T→O) with 10-byte payloads
      ✔ Receives T→O data over UDP (PLC → PC)
      ✔ Sends O→T data over UDP (PC → PLC)

    NOTE ABOUT CONNECTED DATA ITEM (0x00B1):
      The PLC expects:
        - 2-byte CIP sequence count
        - 10-byte application payload
      So the B1 length (in the CPF) must be 12 bytes (0x000C).
    """

    TCP_PORT = 44818               # EtherNet/IP encapsulation port
    UDP_IO_PORT = 0x08AE           # 2222 (I/O real-time port)

    def __init__(self, host: str = "0.0.0.0"):
        self.host = host

        self._running = False

        # Sockets
        self._tcp_server_sock: Optional[socket.socket] = None
        self._udp_sock: Optional[socket.socket] = None

        # Threads
        self._tcp_thread: Optional[threading.Thread] = None
        self._udp_rx_thread: Optional[threading.Thread] = None
        self._udp_tx_thread: Optional[threading.Thread] = None

        # PLC address for UDP I/O
        self._plc_ip: Optional[str] = None

        # EtherNet/IP Session
        self._session_handle: Optional[int] = None

        # Assemblies (10-byte data payloads, excluding CIP sequence count)
        self._t2o_assembly = 101
        self._o2t_assembly = 100
        self._t2o_size_bytes = 10   # PLC → PC (T→O) application data bytes
        self._o2t_size_bytes = 10   # PC → PLC (O→T) application data bytes

        # Forward Open parameters (from PLC)
        self._o2t_conn_id: Optional[int] = None
        self._t2o_conn_id: Optional[int] = None
        self._o2t_rpi_us: Optional[int] = None
        self._t2o_rpi_us: Optional[int] = None

        # I/O packet template (everything up to, but NOT including, the B1 payload)
        self._udp_header_template: Optional[bytes] = None

        # Outgoing O→T payload (10 bytes of application data)
        self._o2t_payload = bytearray(self._o2t_size_bytes)

        # 32-bit sequence for Sequenced Address Item
        self._udp_seq_counter = 0

        # 16-bit CIP Sequence Count for Connected Data Item (0x00B1)
        self._cip_data_seq = 0

        self._lock = threading.Lock()

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def start(self) -> None:
        """Start TCP server + UDP RX/TX threads."""
        if self._running:
            return
        self._running = True

        # TCP server
        self._tcp_server_sock = self._create_tcp_server_socket(self.host, self.TCP_PORT)
        self._tcp_thread = threading.Thread(
            target=self._tcp_server_loop, name="EIP-TCP-Server", daemon=True
        )
        self._tcp_thread.start()

        # UDP socket (shared by RX and TX)
        self._udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp_sock.bind((self.host, self.UDP_IO_PORT))

        self._udp_rx_thread = threading.Thread(
            target=self._udp_rx_loop, name="EIP-UDP-RX", daemon=True
        )
        self._udp_rx_thread.start()

        self._udp_tx_thread = threading.Thread(
            target=self._udp_tx_loop, name="EIP-UDP-TX", daemon=True
        )
        self._udp_tx_thread.start()

        print(f"[ADAPTER] Started (TCP {self.TCP_PORT}, UDP {self.UDP_IO_PORT})")

    def stop(self) -> None:
        """Stop all threads + sockets gracefully."""
        self._running = False

        if self._tcp_server_sock:
            try:
                self._tcp_server_sock.close()
            except OSError:
                pass
            self._tcp_server_sock = None

        if self._udp_sock:
            try:
                self._udp_sock.close()
            except OSError:
                pass
            self._udp_sock = None

        print("[ADAPTER] Stopping...")

    def set_o2t_payload(self, data: bytes) -> None:
        """
        Set the 10-byte application payload sent PC→PLC (O→T).

        This EXCLUDES the 2-byte CIP sequence count, which is added automatically.
        """
        with self._lock:
            buf = bytearray(self._o2t_size_bytes)
            buf[: min(len(data), self._o2t_size_bytes)] = data[:self._o2t_size_bytes]
            self._o2t_payload = buf

    # -------------------------------------------------------------------------
    # TCP Server / Accept Loop
    # -------------------------------------------------------------------------

    def _create_tcp_server_socket(self, host: str, port: int) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen()
        print(f"[TCP] Listening on {host}:{port}")
        return s

    def _tcp_server_loop(self) -> None:
        sock = self._tcp_server_sock
        if sock is None:
            return

        while self._running:
            try:
                sock.settimeout(1.0)
                try:
                    conn, addr = sock.accept()
                except socket.timeout:
                    continue
            except OSError:
                break

            print(f"[TCP] Client connected: {addr} {conn}")
            self._handle_client(conn)

        print("[TCP] Server loop exited")

    def _receive_tcp_data(self, conn: socket.socket, chunk: int = 2048):
        """Generator yielding TCP packets."""
        while self._running:
            try:
                data = conn.recv(chunk)
                if not data:
                    break
                yield data
            except OSError:
                break

    # -------------------------------------------------------------------------
    # EIP/CIP Parsing
    # -------------------------------------------------------------------------

    def _parse_eip_header(self, pkt: bytes):
        if len(pkt) < 24:
            raise ValueError("EIP packet too short")

        command, length, sess, status = struct.unpack_from("<HHII", pkt, 0)
        sender_ctx = pkt[12:20]
        options, = struct.unpack_from("<I", pkt, 20)
        if len(pkt) < 24 + length:
            raise ValueError("EIP packet truncated")
        data = pkt[24:24 + length]
        return command, length, sess, status, sender_ctx, options, data

    def _build_register_session_response(self, req: bytes, sess: int):
        cmd, length, _, _, sender_ctx, opts, data = self._parse_eip_header(req)
        proto, opts2 = struct.unpack("<HH", data)

        payload = struct.pack("<HH", proto, opts2)
        length = len(payload)

        header = struct.pack(
            "<HHII8sI",
            0x0065,
            length,
            sess,
            0,
            sender_ctx,
            opts,
        )
        return header + payload

    def _parse_send_rr_data_payload(self, user: bytes):
        iface, timeout, count = struct.unpack_from("<IHH", user, 0)
        offset = 8
        items = []

        for _ in range(count):
            typ, ln = struct.unpack_from("<HH", user, offset)
            offset += 4
            data = user[offset:offset + ln]
            offset += ln
            items.append((typ, data))
        return iface, timeout, items

    # -------------------------------------------------------------------------
    # CIP Forward Open Parsing
    # -------------------------------------------------------------------------

    @staticmethod
    def _parse_cip_service_and_path(cip: bytes):
        svc = cip[0]
        path_words = cip[1]
        plen = path_words * 2
        path = cip[2:2 + plen]
        rem = cip[2 + plen:]
        return svc, path_words, path, rem

    @staticmethod
    def _parse_forward_open_request(cip: bytes) -> Dict[str, Any]:
        svc, psz, path, rem = EtherNetIPAdapter._parse_cip_service_and_path(cip)

        if svc != 0x54:
            raise ValueError("Not Forward Open")

        o2t_id = struct.unpack_from("<I", rem, 2)[0]
        t2o_id = struct.unpack_from("<I", rem, 6)[0]
        serial = struct.unpack_from("<H", rem, 10)[0]
        vendor = struct.unpack_from("<H", rem, 12)[0]
        origin_sn = struct.unpack_from("<I", rem, 14)[0]

        o2t_rpi = struct.unpack_from("<I", rem, 22)[0]
        o2t_params = struct.unpack_from("<H", rem, 26)[0]
        t2o_rpi = struct.unpack_from("<I", rem, 28)[0]
        t2o_params = struct.unpack_from("<H", rem, 32)[0]

        cp_words = rem[35]
        cp_bytes = cp_words * 2
        conn_path = rem[36:36 + cp_bytes]

        return dict(
            service=svc,
            o2t_conn_id=o2t_id,
            t2o_conn_id=t2o_id,
            conn_serial=serial,
            origin_vendor=vendor,
            origin_serial=origin_sn,
            o2t_rpi=o2t_rpi,
            o2t_params=o2t_params,
            t2o_rpi=t2o_rpi,
            t2o_params=t2o_params,
            conn_path=conn_path,
        )

    @staticmethod
    def _extract_assemblies_from_conn_path(cp: bytes):
        if len(cp) < 8:
            return None
        # Expect last bytes: 2C 65 2C 64  (for 101 / 100)
        return {
            "t2o_asm": cp[-3],  # 0x65
            "o2t_asm": cp[-1],  # 0x64
        }

    def _assign_connection_ids(self, req: Dict[str, Any]) -> None:
        """
        Ensure both O→T and T→O connection IDs are non-zero.
        If the originator passes 0 for either, allocate a new ID.
        """
        if req["o2t_conn_id"] == 0:
            req["o2t_conn_id"] = random.randint(1, 0xFFFFFFFF)
            print(f"[CIP] Assigned O→T ConnID: 0x{req['o2t_conn_id']:08X}")

        if req["t2o_conn_id"] == 0:
            req["t2o_conn_id"] = random.randint(1, 0xFFFFFFFF)
            print(f"[CIP] Assigned T→O ConnID: 0x{req['t2o_conn_id']:08X}")

    @staticmethod
    def _build_forward_open_success(req: Dict[str, Any]):
        """
        Build CIP Forward Open Success reply body.

        Layout after the 4-byte service/status header:

          UDINT O->T Connection ID
          UDINT T->O Connection ID
          UINT  Connection Serial Number
          UINT  Originator Vendor ID
          UDINT Originator Serial Number
          UDINT O->T API
          UDINT T->O API
          USINT App Reply Size (0 here)
          USINT Reserved (0 here)
        """
        svc = req["service"]
        o2t_conn_id = req["o2t_conn_id"]
        t2o_conn_id = req["t2o_conn_id"]

        # Service | reserved | general status | additional status size
        h = bytes([
            svc | 0x80,
            0x00,
            0x00,  # general status = success
            0x00,  # additional status size = 0
        ])

        # Use RPI values as the APIs (cyclic)
        o2t_api = req["o2t_rpi"]
        t2o_api = req["t2o_rpi"]

        body = struct.pack(
            "<IIHHI",
            o2t_conn_id,
            t2o_conn_id,
            req["conn_serial"],
            req["origin_vendor"],
            req["origin_serial"],
        )
        body += struct.pack("<II", o2t_api, t2o_api)
        body += struct.pack("BB", 0, 0)  # App reply size = 0, reserved = 0

        return h + body

    # -------------------------------------------------------------------------
    # Build SendRRData Response (CPF)
    # -------------------------------------------------------------------------

    def _build_send_rrdata_response(
        self,
        session: int,
        ctx: bytes,
        cip_resp: bytes,
        iface: int,
        timeout: int,
    ) -> bytes:
        null_type = 0x0000
        null_len = 0

        unconn_type = 0x00B2
        unconn_len = len(cip_resp)

        cpf = struct.pack("<IHH", iface, timeout, 2)
        cpf += struct.pack("<HH", null_type, null_len)
        cpf += struct.pack("<HH", unconn_type, unconn_len)
        cpf += cip_resp

        header = struct.pack(
            "<HHII8sI",
            0x006F,          # SendRRData
            len(cpf),
            session,
            0,
            ctx,
            0,
        )

        return header + cpf

    # -------------------------------------------------------------------------
    # CIP Command Dispatch
    # -------------------------------------------------------------------------

    def _handle_client(self, conn: socket.socket):
        with conn:
            for pkt in self._receive_tcp_data(conn):
                self._handle_eip_packet(conn, pkt)

    def _handle_eip_packet(self, conn: socket.socket, pkt: bytes):
        try:
            cmd, ln, sess, status, ctx, opts, user = self._parse_eip_header(pkt)
        except Exception as e:
            print("[CIP] Bad header:", e)
            return

        if cmd == 0x0065:
            print("[CIP] RegisterSession")
            with self._lock:
                if self._session_handle is None:
                    self._session_handle = 1

            rsp = self._build_register_session_response(pkt, self._session_handle)
            conn.sendall(rsp)
            print("[CIP] RegisterSession OK")

        elif cmd == 0x006F:
            print("[CIP] SendRRData")
            self._handle_send_rr_data(conn, user, ctx)

        else:
            print(f"[CIP] Unsupported EIP cmd 0x{cmd:04X}")

    def _handle_send_rr_data(self, conn, user, ctx):
        if self._session_handle is None:
            return

        iface, timeout, items = self._parse_send_rr_data_payload(user)

        cip_data = None
        for t, d in items:
            if t == 0x00B2:
                cip_data = d
                break
        if cip_data is None:
            print("[CIP] No UnconnectedData item")
            return

        svc, psz, path, rem = self._parse_cip_service_and_path(cip_data)

        if svc != 0x54:
            print(f"[CIP] Unsupported CIP service 0x{svc:02X}")
            return

        print("[CIP] Forward Open request")

        req = self._parse_forward_open_request(cip_data)
        self._assign_connection_ids(req)
        asm = self._extract_assemblies_from_conn_path(req["conn_path"])

        with self._lock:
            self._o2t_conn_id = req["o2t_conn_id"]
            self._t2o_conn_id = req["t2o_conn_id"]
            self._o2t_rpi_us = req["o2t_rpi"]
            self._t2o_rpi_us = req["t2o_rpi"]
            if asm:
                self._t2o_assembly = asm["t2o_asm"]
                self._o2t_assembly = asm["o2t_asm"]

        cip_resp = self._build_forward_open_success(req)
        eip_resp = self._build_send_rrdata_response(
            self._session_handle,
            ctx,
            cip_resp,
            iface,
            timeout,
        )
        conn.sendall(eip_resp)
        print("[CIP] Forward Open SUCCESS sent.")
        print(
            f"[CIP] O→T ConnID=0x{self._o2t_conn_id:08X}, "
            f"T→O ConnID=0x{self._t2o_conn_id:08X}\n"
        )

    # -------------------------------------------------------------------------
    # UDP I/O RX (PLC → PC)
    # -------------------------------------------------------------------------

    def _udp_rx_loop(self):
        sock = self._udp_sock
        if sock is None:
            return

        print("[UDP-RX] Listening for PLC I/O packets...")

        while self._running:
            try:
                sock.settimeout(1.0)
                try:
                    data, addr = sock.recvfrom(2048)
                except socket.timeout:
                    continue
            except OSError:
                break

            plc_ip, plc_port = addr
            with self._lock:
                if self._plc_ip is None:
                    self._plc_ip = plc_ip

            # --- Find the Connected Data Item (0x00B1) ---
            idx = data.find(b"\xb1\x00")
            if idx == -1:
                print("[UDP-RX] No B1 Connected Data Item in packet, skipping.")
                continue

            b1_len = struct.unpack_from("<H", data, idx + 2)[0]
            # Start of B1 payload (CIP seq + data)
            b1_payload_offset = idx + 4

            if b1_len < 2:
                print("[UDP-RX] B1 length too small, skipping.")
                continue

            # Need at least 2 (CIP seq) + 10 (data)
            min_needed = 2 + self._t2o_size_bytes
            if len(data) < b1_payload_offset + min_needed:
                print("[UDP-RX] Packet too short for 2+10 bytes, skipping.")
                continue

            # CIP sequence from PLC
            cip_seq = struct.unpack_from("<H", data, b1_payload_offset)[0]

            # T→O assembly data from PLC = 10 bytes after CIP seq
            asm_start = b1_payload_offset + 2
            asm_end = asm_start + self._t2o_size_bytes
            payload = data[asm_start:asm_end]

            # Build header template: everything up to the B1 payload
            header = bytearray(data[:b1_payload_offset])

            # For our outgoing direction, B1 length = 2 (seq) + 10 (data) = 12
            b1_len_out = 2 + self._o2t_size_bytes
            struct.pack_into("<H", header, idx + 2, b1_len_out)

            with self._lock:
                self._udp_header_template = bytes(header)

            print(
                f"[UDP-RX] Template updated length={len(self._udp_header_template)} "
                f"(B1 len from PLC was {b1_len}, we will use {b1_len_out})"
            )
            print(f"[UDP-RX] CIP seq (PLC→PC) = 0x{cip_seq:04X}")
            print(f"[UDP-RX] T→O Assembly {self._t2o_assembly}: {payload.hex(' ')}")

        print("[UDP-RX] Loop exited")

    # -------------------------------------------------------------------------
    # UDP I/O TX (PC → PLC)
    # -------------------------------------------------------------------------

    def _udp_tx_loop(self):
        sock = self._udp_sock
        if sock is None:
            return

        print("[UDP-TX] Sender started")

        while self._running:
            time.sleep(0.05)  # ~20 Hz

            with self._lock:
                # Need a live connection and a header template
                if (
                    self._plc_ip is None
                    or self._udp_header_template is None
                    or self._t2o_conn_id in (None, 0)
                ):
                    continue

                header = bytearray(self._udp_header_template)

                # Patch T→O ConnID (PC → PLC from PLC's view) into Sequenced Address Item
                # Layout (inside CPF after item count):
                #   [0:2]  type = 0x8002
                #   [2:4]  length = 8
                #   [4:8]  Connection ID
                #   [8:12] 32-bit sequence
                struct.pack_into("<I", header, 6, self._t2o_conn_id)

                # 32-bit sequence counter for address item
                struct.pack_into("<I", header, 10, self._udp_seq_counter)
                self._udp_seq_counter += 1

                # CIP data sequence for Connected Data Item (0x00B1)
                cip_seq = self._cip_data_seq & 0xFFFF
                self._cip_data_seq = (self._cip_data_seq + 1) & 0xFFFF

                # Build B1 payload: [2-byte CIP seq] + [10-byte application data]
                b1_payload = struct.pack("<H", cip_seq) + bytes(self._o2t_payload)
                b1_len = len(b1_payload)  # should be 12

                # Patch B1 length field in header
                b1_idx = header.find(b"\xb1\x00")
                if b1_idx != -1:
                    struct.pack_into("<H", header, b1_idx + 2, b1_len)

                packet = bytes(header) + b1_payload
                dst = self._plc_ip

            try:
                sock.sendto(packet, (dst, self.UDP_IO_PORT))
                print(
                    f"[UDP-TX] Sent O→T CIPseq=0x{cip_seq:04X} "
                    f"asm={self._o2t_payload.hex(' ')}"
                )
            except OSError:
                pass

        print("[UDP-TX] Loop exited")


# -------------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------------

if __name__ == "__main__":
    adapter = EtherNetIPAdapter("0.0.0.0")
    try:
        adapter.start()

        counter = 0
        while True:
            # Example rotating pattern for 10-byte O→T bytes (application data only)
            payload = bytes([counter & 0xFF] + [i for i in range(1, 10)])
            adapter.set_o2t_payload(payload)
            counter += 1
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nStopping adapter...")
        adapter.stop()
