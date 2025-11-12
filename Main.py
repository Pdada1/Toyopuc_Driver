#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
from datetime import datetime

PLC_IP   = "192.168.0.10"
PLC_PORT = 9600
TIMEOUT  = 3.0


def hexdump(b: bytes) -> str:
    return "-".join(f"{x:02X}" for x in b)


def bcd_to_int(b: int) -> int:
    return ((b >> 4) * 10) + (b & 0x0F)


def build_read_clock_cmd() -> bytes:
    # 00 00 03 00 32 70 00
    header = b"\x00\x00"
    length = b"\x03\x00"   # little endian length = 3 bytes of following data (32 70 00)
    cmd    = b"\x32\x70\x00"
    return header + length + cmd


def parse_clock_reply(data: bytes) -> datetime:
    """
    Expected reply:
    80 00 0A 00 32 70 00 SS MM HH DD MM YY DW
    (All BCD except DW)
    """
    if len(data) < 14:
        raise ValueError("Incomplete reply")

    # Verify header
    if data[0:2] != b"\x80\x00":
        raise ValueError(f"Unexpected header {data[0:2].hex()}")

    # Verify command echo
    if data[4:7] != b"\x32\x70\x00":
        raise ValueError("Wrong command echo in reply")

    # Extract BCD bytes (starting at byte 7)
    bcd = data[7:14]
    sec, minute, hour, day, month, year, dow = bcd

    # Convert
    Y = 2000 + bcd_to_int(year)
    M = bcd_to_int(month)
    D = bcd_to_int(day)
    h = bcd_to_int(hour)
    m = bcd_to_int(minute)
    s = bcd_to_int(sec)

    return datetime(Y, M, D, h, m, s)


def read_plc_clock(ip: str = PLC_IP, port: int = PLC_PORT, timeout: float = TIMEOUT):
    req = build_read_clock_cmd()
    print("TX:", hexdump(req))

    with socket.create_connection((ip, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(req)
        data = s.recv(1024)

    print("RX:", hexdump(data))
    dt = parse_clock_reply(data)
    print("PLC Clock:", dt.isoformat(sep=" "))
    return dt


if __name__ == "__main__":
    try:
        read_plc_clock()
    except Exception as e:
        print("ERROR:", e)
