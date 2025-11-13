
from __future__ import annotations
from datetime import datetime

@staticmethod
def read_clock() -> bytes:
    sub_le=0x0070
    return b"\x32" + sub_le.to_bytes(2, "little")

@staticmethod
def bcd(x: int) -> int: return ((x // 10) << 4) | (x % 10)

@staticmethod
def set_clock(dt: datetime) -> bytes:
    yy = dt.year % 100
    dow = dt.isoweekday() % 7
    body = bytes([bcd(dt.second), bcd(dt.minute), bcd(dt.hour),
                    bcd(dt.day), bcd(dt.month), bcd(yy), dow])
    return b"\x32" + (0x0071).to_bytes(2, "little") + body

@staticmethod
def read_bit(bit_addr: int, transfer_no: int | None = None) -> bytes:
    if transfer_no is None:
        return b"\x20" + bit_addr.to_bytes(2, "little")
    return b"\x20" + bytes([transfer_no]) + bit_addr.to_bytes(2, "little")

@staticmethod
def read_words(start_word_addr: int, count_words: int) -> bytes:
    return b"\x1C" + start_word_addr.to_bytes(2, "little") + count_words.to_bytes(2, "little")
