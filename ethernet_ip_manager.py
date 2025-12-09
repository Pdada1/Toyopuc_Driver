# ethernet_ip_manager.py
from __future__ import annotations

from typing import Optional

from plc import PLC
from tcp_udp_handler import TCPUDPHandler
from ethernet_ip_adapter import EtherNetIPAdapter, PayloadCallback


class EthernetIPManager:
    """
    Small orchestrator for EtherNet/IP.

    - Owns TCPUDPHandler (sockets).
    - Owns EtherNetIPAdapter (EIP logic).
    - Exposes a minimal lifecycle API used by ToyopucDriver.
    """

    def __init__(self, plc_cfg: PLC, bind_host: str = "0.0.0.0") -> None:
        self.plc_cfg = plc_cfg
        self.net = TCPUDPHandler(bind_host=bind_host)
        self.adapter = EtherNetIPAdapter(plc_cfg, self.net)

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def open_connection(
        self,
        connect_timeout: Optional[float] = 30.0,
        handshake_timeout: Optional[float] = 30.0,
    ) -> bool:
        if not self.adapter.open_and_wait_for_connection(timeout=connect_timeout):
            return False
        return self.adapter.handle_tcp_handshake(timeout=handshake_timeout)

    def start_cyclic(
        self,
        payload_callback: Optional[PayloadCallback],
        cycle_time: float,
    ) -> None:
        self.adapter.start_udp_cyclic_thread(payload_callback, cycle_time)

    def stop_cyclic(self, wait: bool = True) -> None:
        self.adapter.stop_udp_cyclic(wait=wait)

    def close(self) -> None:
        self.adapter.close()

    # ------------------------------------------------------------------
    # Read helpers
    # ------------------------------------------------------------------

    def get_last_t2o_payload(self):
        return self.adapter.get_last_t2o_payload()

    def get_last_t2o_info(self):
        return self.adapter.get_last_t2o_info()
