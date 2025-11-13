
from __future__ import annotations
import socket
from typing import Optional
from payloads import read_bit, read_clock, read_words,set_clock
from parsers import clock, bit, words,parse_s200_block
from datetime import datetime
from addressing import Addressing

def hexdump(b: bytes) -> str:
    return "-".join(f"{x:02X}" for x in b)

class ToyopucDriver:
    """Central driver with a *generic* send method.

    Handles TCP + frame wrapping: [00 00][LEN lo hi][payload...].

    """
    REQ_HDR = b"\x00\x00"

    def __init__(self, ip: str, port: int = 9600, timeout: float = 5.0, verbose: bool = True):
        self.ip, self.port, self.timeout, self.verbose = ip, port, timeout, verbose
        self._sock: Optional[socket.socket] = None

    def connect(self) -> None:
        if self._sock: return
        s = socket.create_connection((self.ip, self.port), timeout=self.timeout)
        s.settimeout(self.timeout)
        self._sock = s

    def close(self) -> None:
        if self._sock:
            try: self._sock.close()
            finally: self._sock = None

    def send_payload(self, payload: bytes) -> bytes:
        """Send raw payload bytes and return raw reply frame."""
        assert self._sock is not None, "Call connect() first."
        frame = self.REQ_HDR + len(payload).to_bytes(2, "little") + payload
        self._sock.sendall(frame)
        rx = self._sock.recv(4096)
        return rx
    
    def extract_payload(self, raw_frame: bytes) -> bytes:
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

    # simple wrappers that delegate to send_payload
    def read_clock(self) -> datetime:
        rx=self.send_payload(read_clock())
        return clock(rx)
    
    def set_clock(self, dt:datetime) -> bytes:
        return self.send_payload(set_clock(dt))
    
    def read_bytes(self, start_word_addr: int, count: int) -> list[int]:
        rx = self.send_payload(read_words(start_word_addr,count))
        return words(rx)
    
    def read_bit(self, bit_addr: int, transfer_no: int | None = None) -> int:
        rx = self.send_payload(read_bit(bit_addr, transfer_no))
        return bit(rx)
    
    def read_error_bits(self):
        rx=self.read_bytes(Addressing.word_address("V",0x000),1)[0] & 0x07
        print("V001= "+str(rx &0x001)+" V002= "+str(rx>>1 &0x01)+" V003= "+str(rx>>2 &0x01))

    def read_latest_error(self) -> dict:
        v001 = Addressing.word_address("S", 0x200)
        return parse_s200_block(self.read_bytes(v001,10))

