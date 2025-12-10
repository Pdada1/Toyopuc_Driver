# test.py
from __future__ import annotations

import time
from typing import Final

from plc import PLC
from toyopuc_driver_api import ToyopucDriver

PLC_IP: Final = "192.168.0.10"   # TOYOPUC PLC IP
PC_IP: Final = "192.168.0.37"    # Your PC IP on the same network
CYCLE_TIME_S: Final = 0.05       # 50 ms
O2T_SIZE: Final = 8
T2O_SIZE: Final = 8
LED_ON_PLC: Final=b"1111000000000000"
LED_ON_PICO: Final=b"LED ON\r\n" 
LED_OFF_PLC: Final=b"0011000000000000"
LED_OFF_PICO: Final=b"LED OFF\r\n" 

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
    i=0

    while True:
        try:
            payload = bytes([( i & 0xFF)] + [1, 2, 3, 4, 5, 6, 7, 8, 9])
            i+=1
            drv.write_o2t(payload)
            time.sleep(0.5)
            receive=drv.read_t2o_hex()
            print(f"[MAIN] T→O payload: {receive}")
            #if receive == LED_ON_PLC:
                #Serial.send (LED_ON_PICO)
            #elif recieve == LED_OFF_PLC:
                #Serial.send (LED_OFF_PICO)
        
        except KeyboardInterrupt:
            break
        finally:
            print("[MAIN] Shutting down driver...")
            drv.close()
            print("[MAIN] Shutdown complete.")


if __name__ == "__main__":
    main()
