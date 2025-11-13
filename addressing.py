
from __future__ import annotations

class Addressing:
    BIT_BASE = {"K":0x0200, "V":0x0500, "L":0x0800, "XY":0x1000, "M":0x1800}
    WORD_BASE= {"D":0x1000, "V":0x0050, "S":0x0200}

    @classmethod
    def bit_address(cls, area: str, idx_hex: int) -> int:
        return cls.BIT_BASE[area.upper()] + idx_hex

    @classmethod
    def d_word_address(cls, offset_hex: int) -> int:
        return cls.WORD_BASE["D"] + offset_hex
    
    @classmethod
    def word_address(cls, word_area: str, offset_hex: int) -> int:
        return cls.WORD_BASE[word_area.upper()] + offset_hex

    @staticmethod
    def parse_symbol(sym: str) -> tuple[str, int]:
        s = sym.strip().upper().replace(" ", "")
        if s.startswith("XY"): area, rest = "XY", s[2:]
        else: area, rest = s[0], s[1:]
        if not rest: raise ValueError("Missing offset")
        return area, int(rest, 16)
