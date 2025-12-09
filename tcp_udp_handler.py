# tcp_udp_handler.py
from __future__ import annotations

import socket
from typing import Optional, Tuple

Addr = Tuple[str, int]


class TCPUDPHandler:
    """
    Thin wrapper around TCP/UDP sockets.

    Knows nothing about EtherNet/IP itself. Just:
      - Creates/accepts TCP servers.
      - Creates UDP sockets.
      - Sends/receives raw bytes.
    """

    def __init__(self, bind_host: str = "0.0.0.0") -> None:
        self.bind_host = bind_host
        self.tcp_server: Optional[socket.socket] = None
        self.udp_sock: Optional[socket.socket] = None

    # ------------------------------------------------------------------
    # TCP
    # ------------------------------------------------------------------

    def create_tcp_server(self, port: int) -> None:
        if self.tcp_server is not None:
            return

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.bind_host, port))
        srv.listen(1)
        self.tcp_server = srv

    def accept_client(
        self,
        timeout: float = 1.0,
    ) -> Optional[Tuple[socket.socket, Addr]]:
        if self.tcp_server is None:
            raise RuntimeError("TCP server not created")

        self.tcp_server.settimeout(timeout)
        try:
            conn, addr = self.tcp_server.accept()
        except socket.timeout:
            return None
        return conn, addr

    def send_tcp(self, conn: socket.socket, data: bytes) -> None:
        conn.sendall(data)

    # ------------------------------------------------------------------
    # UDP
    # ------------------------------------------------------------------

    def create_udp_socket(self, port: int) -> None:
        if self.udp_sock is not None:
            return

        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except OSError:
            pass
        udp.bind((self.bind_host, port))
        self.udp_sock = udp

    def recv_udp(
        self,
        bufsize: int = 2048,
        timeout: float = 1.0,
    ) -> Tuple[Optional[bytes], Optional[Addr]]:
        if self.udp_sock is None:
            raise RuntimeError("UDP socket not created")

        self.udp_sock.settimeout(timeout)
        try:
            data, addr = self.udp_sock.recvfrom(bufsize)
        except socket.timeout:
            return None, None
        return data, addr

    def send_udp(self, data: bytes, addr: Addr) -> None:
        if self.udp_sock is None:
            raise RuntimeError("UDP socket not created")
        self.udp_sock.sendto(data, addr)

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def close(self) -> None:
        if self.tcp_server is not None:
            try:
                self.tcp_server.close()
            except OSError:
                pass
            self.tcp_server = None

        if self.udp_sock is not None:
            try:
                self.udp_sock.close()
            except OSError:
                pass
            self.udp_sock = None
