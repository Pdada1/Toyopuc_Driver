# main_toyopuc.py
from __future__ import annotations

import time
from typing import Final

from plc import PLC
from toyopuc_driver_api import ToyopucDriver

PLC_IP: Final = "192.168.0.10"   # TOYOPUC PLC IP
PC_IP: Final = "192.168.0.37"    # Your PC IP on the same network
CYCLE_TIME_S: Final = 0.05       # 50 ms
O2T_SIZE: Final = 10
T2O_SIZE: Final = 10


def main() -> None:
    plc_cfg = PLC(
        ip=PLC_IP,
        tcp_port=44818,
        udp_io_port=2222,
        t2o_assembly=101,
        o2t_assembly=100,
        t2o_size_bytes=T2O_SIZE,
        o2t_size_bytes=O2T_SIZE,
    )

    drv = ToyopucDriver(plc_cfg, bind_host=PC_IP, cycle_time=CYCLE_TIME_S)

    print("[MAIN] Waiting for PLC connection + Forward Open...")
    drv.connect()
    print("[MAIN] Connected. Cyclic I/O running in background.")

    try:
        # Periodically write some pattern and print last T→O
        for i in range(20):
            payload = bytes([(i & 0xFF)] + [1, 2, 3, 4, 5, 6, 7, 8, 9])
            drv.write_o2t(payload)

            time.sleep(0.5)
            print(f"[MAIN] T→O payload: {drv.read_t2o_hex()}")

        # Example: wait until bit 0 of first T→O byte is set
        def bit0_is_set(data: bytes) -> bool:
            return bool(data and (data[0] & 0x01))

        print("[MAIN] Waiting for PLC to set bit 0 of first T→O byte...")
        ok = drv.wait_for_t2o_condition(bit0_is_set, timeout_s=10.0)
        print("[MAIN] Condition result:", ok)

    finally:
        print("[MAIN] Shutting down driver...")
        drv.close()
        print("[MAIN] Shutdown complete.")


if __name__ == "__main__":
    main()
