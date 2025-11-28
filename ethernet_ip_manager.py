from typing import Optional
from plc import PLC
from tcp_udp_handler import TCPUDPHandler
from ethernet_ip_adapter import EtherNetIPAdapter, PayloadCallback


class EthernetIPManager:
    """
    Top-level manager that the user's main() interacts with.
    """

    def __init__(self, plc_cfg: PLC, bind_host: str = "0.0.0.0") -> None:
        self.plc_cfg = plc_cfg
        self.net = TCPUDPHandler(bind_host=bind_host)
        self.adapter = EtherNetIPAdapter(plc_cfg, self.net)

    def open_connection(self, timeout: float | None = None) -> None:
        """
        - Setup TCP/UDP ports
        - Wait for TCP connection
        - Perform RegisterSession + Forward Open
        """
        self.adapter.open_and_wait_for_connection(timeout=timeout)
        self.adapter.handle_tcp_handshake()

    def run_cyclic(
        self,
        payload_callback: PayloadCallback | None = None,
        cycle_time: float = 0.05,
    ) -> None:
        """
        Start the UDP cyclic communication loop (blocking).

        payload_callback(cycle_index, adapter) can update the payload each cycle.
        """
        self.adapter.run_udp_cyclic(
            payload_callback=payload_callback,
            cycle_time=cycle_time,
        )

    def close(self) -> None:
        """
        Close TCP/UDP and clean up.
        """
        self.adapter.close()
        
    def get_last_t2o_payload(self) -> Optional[bytes]:
        return self.adapter.get_last_t2o_payload()

    def get_last_t2o_info(self) -> dict:
        return self.adapter.get_last_t2o_info()
