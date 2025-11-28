from dataclasses import dataclass
import json


@dataclass
class PLC:
    """
    Configuration for a PLC / EtherNet/IP connection.

    Attributes
    ----------
    ip : str
        IP address of the PLC (originator).
    tcp_port : int
        EtherNet/IP encapsulation TCP port (default 44818).
    udp_io_port : int
        UDP I/O port for real-time data (default 0x08AE = 2222).
    t2o_assembly : int
        T→O (PLC → Adapter) assembly instance.
    o2t_assembly : int
        O→T (Adapter → PLC) assembly instance.
    t2o_size_bytes : int
        Application payload bytes for T→O direction (excluding CIP seq).
    o2t_size_bytes : int
        Application payload bytes for O→T direction (excluding CIP seq).
    """

    def __init__(self, ip, tcp_port: int = 44818, udp_io_port: int = 0x08AE, t2o_assembly: int = 101, o2t_assembly: int = 100, t2o_size_bytes: int = 10, o2t_size_bytes: int = 10) -> None:
        self.ip = ip
        self.tcp_port = tcp_port
        self.udp_io_port = udp_io_port
        self.t2o_assembly=t2o_assembly
        self.o2t_assembly=o2t_assembly
        self.t2o_size_bytes=t2o_size_bytes
        self.o2t_size_bytes=o2t_size_bytes

    @classmethod
    def from_json(cls, path: str) -> "PLC":
        """
        Load PLC configuration from a JSON file.

        Expected JSON format example:

        {
          "ip": "192.168.0.10",
          "tcp_port": 44818,
          "udp_io_port": 2222,
          "t2o_assembly": 101,
          "o2t_assembly": 100,
          "t2o_size_bytes": 10,
          "o2t_size_bytes": 10
        }
        """
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(**data)
