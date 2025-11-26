""" Class to implement a EIP Driver for PLC

"""

import socket

class EIP_Driver:
    def __init__(self,tcp_port=44818, udp_port=2222,host=socket.gethostbyname(socket.gethostname())) -> None:
        self.tcp_port=tcp_port
        self.udp_port=udp_port
        self.host=host
        self.tcp_socket=None
    
    "Creates a tcp connection and setups for the hardware "
    def prep_tcp_socket(self):
        self.tcp_socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.tcp_socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        try:
            self.tcp_socket.bind((self.host, self.tcp_port))
        except OSError as e:
            print(f"[TCP] Bind failed on {self.host}:{self.tcp_port}: {e}")

        try:
            self.tcp_socket.listen()
        except OSError as e:
            print(f"[TCP] listen failed on {self.host}:{self.tcp_port}: {e}")
    
    def start_tcp_socket(self):
        if self.tcp_socket is None:
            print(f"A port has not been prepped to start yet\n")
            return
        else:
            addr = None
            conn = None
            connected=False
            while not connected:
                try:
                    self.tcp_socket.settimeout(1.0)
                    try:
                        conn, addr = self.tcp_socket.accept()
                    except socket.timeout:
                        continue
                except OSError:
                    break #Fix this later- Justin

            print(f"[TCP] Client connected: {addr}")



