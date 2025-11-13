
from __future__ import annotations
from datetime import datetime

@staticmethod
def hexdump(b: bytes) -> str:
    return "-".join(f"{x:02X}" for x in b)

@staticmethod
def extract_payload(raw_frame: bytes) -> bytes:
        """
        Given a full TOYOPUC reply frame:
            [80 00] [LEN lo hi] [payload...]
        return only the payload portion.

        Example:
            raw -> 80 00 07 00 1C 00 01 02 03 04
            returns -> 1C 00 01 02 03 04
        """
        if len(raw_frame) < 5:
            raise ValueError("Frame too short to contain header and length")

        if raw_frame[:2] != b"\x80\x00":
            raise ValueError(f"Invalid header: {raw_frame[:2].hex()}")

        length = int.from_bytes(raw_frame[2:4], "little")
        payload = raw_frame[4:4+length]

        if len(payload) != length:
            raise ValueError("Frame length does not match payload size")

        return payload

@staticmethod
def split(rx: bytes) -> tuple[int, bytes]:
    if len(rx) < 5 or rx[:2] != b"\x80\x00":
        raise ValueError(f"Bad reply header: {hexdump(rx)}")
    ln = int.from_bytes(rx[2:4], "little")
    payload = rx[4:4+ln]
    if not payload: raise ValueError("Empty payload")
    return payload[0], payload

@staticmethod
def _bcd(b: int) -> int: return ((b >> 4) * 10) + (b & 0x0F)

@staticmethod
def _bcd_word_2digit(word: int) -> int:
    """
    Manual: '0102' represents '12'.
    That means each BYTE is one BCD number:
        high byte = tens, low byte = ones.
    Example:
        0x0102 -> 0x01 and 0x02 -> 1*10 + 2 = 12
        0x0405 -> 4*10 + 5 = 45
    """
    tens = (word >> 8) & 0xFF   # high byte
    ones = word & 0xFF          # low byte
    return tens * 10 + ones

@staticmethod
def clock(payload: bytes) -> datetime:
    payload=extract_payload(payload)
    if payload[:3] != b"\x32\x70\x00" or len(payload) < 10:
        raise ValueError(f"Clock payload unexpected: {hexdump(payload)}")
    s, m, h, d, mo, yy, _dw = payload[3:10]
    return datetime(2000 + _bcd(yy), _bcd(mo), _bcd(d), _bcd(h), _bcd(m), _bcd(s))

@staticmethod
def bit(payload: bytes) -> int:
    payload=extract_payload(payload)
    if payload[0] != 0x20: raise ValueError(f"Bit payload unexpected: {hexdump(payload)}")
    val = payload[-1]
    if val not in (0,1): raise ValueError(f"Bit value unexpected: {val}")
    return val

@staticmethod
def words(payload: bytes) -> list[int]:
    payload=extract_payload(payload)
    if payload[0] != 0x1C: raise ValueError(f"Words payload unexpected: {hexdump(payload)}")
    data = payload[1:]
    if len(data) % 2: raise ValueError(f"Words payload odd: {hexdump(payload)}")
    out = []
    for i in range(0, len(data), 2):
        lo, hi = data[i], data[i+1]
        out.append((hi << 8) | lo)
    return out

@staticmethod
def parse_s200_block(words: list[int]) -> dict:
    """
    Parse S200–S209 error block.
    Input: list of 10 WORD values [S200..S209]
    Returns: dict containing decoded info.
    """
    if len(words) < 10:
        raise ValueError("Need 10 words (S200..S209) to parse error block")

    s200, s201, s202, s203, s204, s205, s206, s207, s208, s209 = words[:10]

    error_code = hex(s200)

    # Error info bytes (each word contains two 8-bit values)
    info1 = s201 & 0xFF
    info2 = (s201 >> 8) & 0xFF
    info3 = s202 & 0xFF
    info4 = (s202 >> 8) & 0xFF

    # BCD-coded time values
    sec   = _bcd_word_2digit(s203)
    minute= _bcd_word_2digit(s204)
    hour  = _bcd_word_2digit(s205)
    day   = _bcd_word_2digit(s206)
    month = _bcd_word_2digit(s207)
    year2 = _bcd_word_2digit(s208)

    # Lower byte of S209 is day-of-week (0–6)
    dow = s209 & 0xFF

    # Build datetime safely (TOYOPUC uses YY for year: 00–99)
    from datetime import datetime
    detection_time = None
    try:
        year_full = 2000 + year2  # adjust century as desired
        detection_time = datetime(year_full, month, day, hour, minute, sec)
    except ValueError:
        # Invalid timestamp: leave detection_time = None
        pass

    return {
        "error_code": error_code,
        "info1": info1,
        "info2": info2,
        "info3": info3,
        "info4": info4,
        "second": sec,
        "minute": minute,
        "hour": hour,
        "day": day,
        "month": month,
        "year": 2000 + year2,
        "day_of_week": dow,
        "datetime": detection_time,
        "raw_words": words[:10],
    }

