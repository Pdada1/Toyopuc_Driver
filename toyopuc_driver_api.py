# toyopuc_driver_api.py
from __future__ import annotations

import threading
import time
from typing import Optional, Callable

from plc import PLC
from ethernet_ip_manager import EthernetIPManager
from ethernet_ip_adapter import EtherNetIPAdapter


class ToyopucDriver:
    """
    High-level TOYOPUC driver API.

    H-frame style usage:

        plc_cfg = PLC(ip="192.168.0.10", t2o_size_bytes=14, o2t_size_bytes=10)
        drv = ToyopucDriver(plc_cfg, bind_host="192.168.0.37", cycle_time=0.05)
        drv.connect()

        try:
            drv.write_o2t(b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A")
            time.sleep(1.0)
            print("T→O:", drv.read_t2o_hex())
        finally:
            drv.close()
    """

    def __init__(
        self,
        plc_cfg: PLC,
        bind_host: str = "0.0.0.0",
        cycle_time: float = 0.05,
    ) -> None:
        self._plc_cfg = plc_cfg
        self._manager = EthernetIPManager(plc_cfg, bind_host=bind_host)
        self._cycle_time = float(cycle_time)

        self._o2t_lock = threading.Lock()
        self._o2t_bytes = bytearray(plc_cfg.o2t_size_bytes)

        self._adapter: Optional[EtherNetIPAdapter] = None
        self._connected = False

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def connect(
        self,
        connect_timeout: Optional[float] = 30.0,
        handshake_timeout: Optional[float] = 30.0,
    ) -> None:
        ok = self._manager.open_connection(
            connect_timeout=connect_timeout,
            handshake_timeout=handshake_timeout,
        )
        if not ok:
            raise RuntimeError("Failed EIP connection/handshake with PLC")

        self._adapter = self._manager.adapter
        self._connected = True

        self._manager.start_cyclic(
            payload_callback=self._payload_callback,
            cycle_time=self._cycle_time,
        )

    def close(self) -> None:
        self._manager.stop_cyclic(wait=True)
        self._manager.close()
        self._adapter = None
        self._connected = False

    @property
    def is_connected(self) -> bool:
        return self._connected

    # ------------------------------------------------------------------
    # Internal callback for cyclic I/O
    # ------------------------------------------------------------------

    def _payload_callback(
        self,
        cycle_index: int,
        adapter: EtherNetIPAdapter,
    ) -> bytes:
        del cycle_index, adapter  # unused
        with self._o2t_lock:
            return bytes(self._o2t_bytes)

    # ------------------------------------------------------------------
    # Public I/O helpers
    # ------------------------------------------------------------------

    def write_o2t(self, payload: bytes) -> None:
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError("payload must be bytes or bytearray")

        with self._o2t_lock:
            buf = bytearray(self._plc_cfg.o2t_size_bytes)
            buf[: min(len(payload), len(buf))] = payload[: len(buf)]
            self._o2t_bytes = buf

    def read_t2o_hex(self, sep: str = " ") -> str:
        data = self._manager.get_last_t2o_payload()
        if data is None:
            return "<no T→O data yet>"
        return data.hex(sep)

    # ------------------------------------------------------------------
    # Blocking helper (optional)
    # ------------------------------------------------------------------

    def wait_for_t2o_condition(
        self,
        predicate: Callable[[bytes], bool],
        timeout_s: float,
        poll_interval_s: float = 0.01,
    ) -> bool:
        deadline = time.time() + max(0.0, float(timeout_s))
        poll = max(0.0, float(poll_interval_s))

        while time.time() < deadline:
            data = self._manager.get_last_t2o_payload()
            if data is not None and predicate(data):
                return True
            time.sleep(poll)

        return False
