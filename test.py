#!/usr/bin/env python3

import time
import keyboard
from plc import PLC
from ethernet_ip_manager import EthernetIPManager
from ethernet_ip_adapter import EtherNetIPAdapter


def payload_callback(cycle_index: int, adapter: EtherNetIPAdapter) -> bytes:
    """
    Called in the adapter's background UDP thread once per cycle.

    Use this to compute the O→T payload based on current program state
    and the latest T→O data from the PLC.
    """
    last = adapter.get_last_t2o_payload()

    # Example: debug-print every 50 cycles
    if last is not None and cycle_index % 50 == 0:
        print(f"[PAYLOAD_CB] Last T→O from PLC: {last.hex(' ')}")

    # Example payload: first byte mirrors PLC's first byte (or cycle index),
    # remaining bytes are a simple pattern.
    first = last[0] if last else (cycle_index & 0xFF)
    return bytes([first] + [1, 2, 3, 4, 5, 6, 7, 8, 9])


def main() -> None:
    # 1) PLC configuration
    plc_cfg = PLC(
        ip="192.168.0.10",
        tcp_port=44818,
        udp_io_port=0x08AE,
        t2o_assembly=101,
        o2t_assembly=100,
        t2o_size_bytes=10,
        o2t_size_bytes=10,
    )

    # Bind host is your PC's IP on the PLC network
    manager = EthernetIPManager(plc_cfg, bind_host="192.168.0.37")

    # 2) Open connection (TCP/UDP + RegisterSession + Forward Open)
    ok = manager.open_connection(connect_timeout=30.0, handshake_timeout=30.0)
    if not ok:
        print("[MAIN] Failed to open connection / handshake.")
        return

    # 3) Start UDP cyclic I/O in background thread
    manager.start_cyclic(
        payload_callback=payload_callback,
        cycle_time=0.05,  # 50 ms target
    )

    print("[MAIN] Cyclic I/O running in background.")
    while keyboard.is_pressed("q") is False:
        time.sleep(0.1)
    manager.stop_cyclic(wait=True)
    manager.close()
    print("[MAIN] Shutdown complete.")


if __name__ == "__main__":
    main()
