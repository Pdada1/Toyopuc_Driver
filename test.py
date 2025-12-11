# test.py
from __future__ import annotations
from serial import Serial
import threading
import time
from typing import Final

from plc import PLC
from toyopuc_driver_api import ToyopucDriver

PLC_IP: Final = "192.168.0.10"   # TOYOPUC PLC IP
PC_IP: Final = "192.168.0.37"    # Your PC IP on the same network
CYCLE_TIME_S: Final = 0.05       # 50 ms
O2T_SIZE: Final = 8
T2O_SIZE: Final = 8
LED_ON_PLC: Final="00 00 11 11 00 00 00 00"
LED_ON_PICO: Final=b"LED ON\r\n" 
LED_OFF_PLC: Final="00 00 11 00 00 00 00 00"
LED_OFF_PICO: Final=b"LED OFF\r\n" 
PICO_PORT: Final="COM5"  # Adjust as needed

ser = Serial(port=PICO_PORT, baudrate=115200, timeout=0.5)


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
    count=True
    while True:
        try:
            payload = bytes([( i & 0xFF)] + [1, 2, 3, 4, 5, 6, 7, 8, 9])
            if count:
                i+=1
            drv.write_o2t(payload)
            time.sleep(0.5)
            receive=drv.read_t2o_hex()
            print(f"[MAIN] T→O payload: {receive}")
            line = ser.readline()   # read a '\n' terminated line
            if line:
                recv=line.decode('utf-8').rstrip()
                print(f"PICO:", recv)
                if recv=="Button Pressed":
                    count=(count!=True)
                    print(count)
            if receive == LED_ON_PLC:
                ser.write(LED_ON_PICO)
                ser.flush()
            elif receive == LED_OFF_PLC:
                ser.write(LED_OFF_PICO)
                ser.flush()
        except KeyboardInterrupt:
            break

    print("[MAIN] Shutting down driver...")
    drv.close()
    print("[MAIN] Shutdown complete.")


if __name__ == "__main__":
    main()
