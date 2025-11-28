# ethernet_ip_manager.py

from typing import Optional

from plc import PLC
from tcp_udp_handler import TCPUDPHandler
from ethernet_ip_adapter import EtherNetIPAdapter, PayloadCallback


class EthernetIPManager:
    """
    Top-level wrapper for application code.

    Public API
    ----------
    - open_connection(connect_timeout=None, handshake_timeout=None) -> bool
    - start_cyclic(payload_callback=None, cycle_time=0.05)
    - stop_cyclic(wait=True)
    - get_last_t2o_payload()
    - get_last_t2o_info()
    - close()
    """

    def __init__(self, plc_cfg: PLC, bind_host: str = "0.0.0.0") -> None:
        self.plc_cfg = plc_cfg
        self.net = TCPUDPHandler(bind_host=bind_host)
        self.adapter = EtherNetIPAdapter(plc_cfg, self.net)

    def open_connection(
        self,
        connect_timeout: Optional[float] = None,
        handshake_timeout: Optional[float] = None,
    ) -> bool:
        if not self.adapter.open_and_wait_for_connection(timeout=connect_timeout):
            return False
        return self.adapter.handle_tcp_handshake(timeout=handshake_timeout)

    def start_cyclic(
        self,
        payload_callback: Optional[PayloadCallback] = None,
        cycle_time: float = 0.05,
    ) -> None:
        """
        Start UDP cyclic communication in a background thread.
        """
        self.adapter.start_udp_cyclic_thread(
            payload_callback=payload_callback,
            cycle_time=cycle_time,
        )

    def stop_cyclic(self, wait: bool = True) -> None:
        """
        Request cyclic communication to stop.
        """
        self.adapter.stop_udp_cyclic(wait=wait)

    def get_last_t2o_payload(self):
        return self.adapter.get_last_t2o_payload()

    def get_last_t2o_info(self):
        return self.adapter.get_last_t2o_info()

    def close(self) -> None:
        self.adapter.close()
