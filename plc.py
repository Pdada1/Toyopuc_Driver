# plc.py
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Union
import json

JsonPath = Union[str, Path]


@dataclass(frozen=True)
class PLC:
    """
    Configuration for a TOYOPUC EtherNet/IP connection.

    ip              : PLC IP address (originator).
    tcp_port        : EtherNet/IP encapsulation TCP port (default 44818).
    udp_io_port     : UDP I/O port (TOYOPUC default 0x08AE = 2222).
    t2o_assembly    : T→O (PLC → adapter) assembly instance.
    o2t_assembly    : O→T (adapter → PLC) assembly instance.
    t2o_size_bytes  : Application payload size from PLC to adapter.
    o2t_size_bytes  : Application payload size from adapter to PLC.
    """

    ip: str
    tcp_port: int = 44818
    udp_io_port: int = 2222
    t2o_assembly: int = 101
    o2t_assembly: int = 100
    t2o_size_bytes: int = 10
    o2t_size_bytes: int = 10

    @classmethod
    def from_json(cls, path: JsonPath) -> "PLC":
        """
        Load PLC configuration from a JSON file.

        Example JSON:
        {
          "ip": "192.168.0.10",
          "tcp_port": 44818,
          "udp_io_port": 2222,
          "t2o_assembly": 101,
          "o2t_assembly": 100,
          "t2o_size_bytes": 14,
          "o2t_size_bytes": 10
        }
        """
        p = Path(path)
        with p.open("r", encoding="utf-8") as f:
            data: Dict[str, Any] = json.load(f)
        return cls(**data)
