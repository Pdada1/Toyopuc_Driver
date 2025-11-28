import socket
from typing import Optional, Tuple


class TCPUDPHandler:
    """
    Thin wrapper around TCP/UDP socket handling.

    This class JUST manages sockets and sending/receiving raw bytes.
    The EtherNetIPAdapter is responsible for protocol-level logic.
    """

    def __init__(self, bind_host: str = "0.0.0.0") -> None:
        self.bind_host = bind_host
        self._tcp_server_sock: Optional[socket.socket] = None
        self._udp_sock: Optional[socket.socket] = None

    # --- TCP helpers --------------------------------------------------------

    def create_tcp_server(self, port: int, backlog: int = 5) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.bind_host, port))
        s.listen(backlog)
        self._tcp_server_sock = s
        print(f"[TCP] Listening on {self.bind_host}:{port}")
        return s

    @property
    def tcp_server_sock(self) -> Optional[socket.socket]:
        return self._tcp_server_sock

    def accept_client(
        self, timeout: float = 1.0
    ) -> Optional[Tuple[socket.socket, Tuple[str, int]]]:
        if self._tcp_server_sock is None:
            return None
        self._tcp_server_sock.settimeout(timeout)
        try:
            return self._tcp_server_sock.accept()
        except (socket.timeout, OSError):
            return None

    @staticmethod
    def recv_tcp(conn: socket.socket, bufsize: int = 2048) -> bytes:
        return conn.recv(bufsize)

    @staticmethod
    def send_tcp(conn: socket.socket, payload: bytes) -> None:
        conn.sendall(payload)

    # --- UDP helpers --------------------------------------------------------

    def create_udp_socket(self, port: int) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.bind_host, port))
        self._udp_sock = sock
        print(f"[UDP] Bound on {self.bind_host}:{port}")
        return sock

    @property
    def udp_sock(self) -> Optional[socket.socket]:
        return self._udp_sock

    def recv_udp(
        self, bufsize: int = 2048, timeout: float = 1.0
    ) -> Tuple[Optional[bytes], Optional[Tuple[str, int]]]:
        if self._udp_sock is None:
            return None, None
        self._udp_sock.settimeout(timeout)
        try:
            data, addr = self._udp_sock.recvfrom(bufsize)
            return data, addr
        except (socket.timeout, OSError):
            return None, None

    def send_udp(self, payload: bytes, addr: Tuple[str, int]) -> None:
        if self._udp_sock is None:
            return
        try:
            self._udp_sock.sendto(payload, addr)
        except OSError:
            pass

    # --- Cleanup ------------------------------------------------------------

    def close(self) -> None:
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
