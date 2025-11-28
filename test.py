#!/usr/bin/env python3

from PLC import PLC
from EthernetIPManager import EthernetIPManager
from EtherNetIPAdapter import EtherNetIPAdapter


def payload_callback(cycle_index: int, adapter: EtherNetIPAdapter) -> bytes:
    # Read last T→O payload from PLC (may be None initially)
    last = adapter.get_last_t2o_payload()
    if last is not None:
        print(f"[MAIN] Last T→O from PLC: {last.hex(' ')}")

    # Compute what to send O→T for this cycle
    # Example: mirror first byte, then fixed pattern
    first = last[0] if last else 0
    return bytes([first] + [1, 2, 3, 4, 5, 6, 7, 8, 9])


def main() -> None:
    plc_cfg = PLC(
        ip="192.168.0.10",
        tcp_port=44818,
        udp_io_port=0x08AE,
        t2o_assembly=101,
        o2t_assembly=100,
        t2o_size_bytes=10,
        o2t_size_bytes=10,
    )

    manager = EthernetIPManager(plc_cfg, bind_host="0.0.0.0")

    try:
        manager.open_connection()
        manager.run_cyclic(
            payload_callback=payload_callback,
            cycle_time=0.05,
        )
    finally:
        manager.close()


if __name__ == "__main__":
    main()
