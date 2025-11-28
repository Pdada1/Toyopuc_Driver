# eip_protocol.py

from dataclasses import dataclass
from typing import List, Tuple, Optional


# ---------- Basic types ----------

@dataclass
class EIPHeader:
    command: int
    length: int
    session: int
    status: int
    context: bytes
    options: int
    data: bytes


@dataclass
class CPFItem:
    item_type: int
    data: bytes


@dataclass
class CPF:
    interface_handle: int
    timeout: int
    items: List[CPFItem]


@dataclass
class ForwardOpenInfo:
    service: int
    path: bytes
    o2t_conn_id: int
    t2o_conn_id: int
    conn_serial: int
    vendor_id: int
    origin_serial: int
    o2t_rpi: int
    t2o_rpi: int


# ---------- Parsing helpers (pure) ----------

import struct


def parse_eip_header(raw: bytes) -> EIPHeader:
    """
    Parse EtherNet/IP encapsulation header.
    """
    if len(raw) < 24:
        raise ValueError("EIP TCP packet too short")

    command, length, session, status = struct.unpack_from("<HHII", raw, 0)
    context = raw[12:20]
    options, = struct.unpack_from("<I", raw, 20)
    data = raw[24:24 + length]

    return EIPHeader(
        command=command,
        length=length,
        session=session,
        status=status,
        context=context,
        options=options,
        data=data,
    )


def parse_cpf(data: bytes) -> CPF:
    """
    Parse Common Packet Format payload.
    """
    if len(data) < 8:
        raise ValueError("CPF too short")

    interface_handle, timeout, item_count = struct.unpack_from("<IHH", data, 0)
    offset = 8
    items: List[CPFItem] = []

    for _ in range(item_count):
        if len(data) < offset + 4:
            raise ValueError(f"CPF truncated: expected {item_count} items, parsed {len(items)}")
        item_type, item_len = struct.unpack_from("<HH", data, offset)
        offset += 4
        item_data = data[offset:offset + item_len]
        offset += item_len
        items.append(CPFItem(item_type=item_type, data=item_data))

    return CPF(
        interface_handle=interface_handle,
        timeout=timeout,
        items=items,
    )


def extract_unconnected_data_item(cpf: CPF) -> Optional[bytes]:
    """
    Return Unconnected Data item payload (type 0x00B2), if present.
    """
    for item in cpf.items:
        if item.item_type == 0x00B2:
            return item.data
    return None


def parse_forward_open(cip: bytes) -> ForwardOpenInfo:
    """
    Parse CIP Forward Open request (service 0x54) into a dataclass.
    """
    if len(cip) < 2:
        raise ValueError("CIP data too short for Forward Open")

    service = cip[0]
    if service != 0x54:
        raise ValueError("Not a Forward Open (service != 0x54)")

    path_word_count = cip[1]
    path_len_bytes = path_word_count * 2
    if len(cip) < 2 + path_len_bytes + 36:
        raise ValueError("Forward Open message too short")

    path = cip[2:2 + path_len_bytes]
    body = cip[2 + path_len_bytes:]

    o2t_conn_id = struct.unpack_from("<I", body, 2)[0]
    t2o_conn_id = struct.unpack_from("<I", body, 6)[0]
    conn_serial = struct.unpack_from("<H", body, 10)[0]
    vendor_id = struct.unpack_from("<H", body, 12)[0]
    origin_serial = struct.unpack_from("<I", body, 14)[0]
    o2t_rpi = struct.unpack_from("<I", body, 22)[0]
    t2o_rpi = struct.unpack_from("<I", body, 28)[0]

    return ForwardOpenInfo(
        service=service,
        path=path,
        o2t_conn_id=o2t_conn_id,
        t2o_conn_id=t2o_conn_id,
        conn_serial=conn_serial,
        vendor_id=vendor_id,
        origin_serial=origin_serial,
        o2t_rpi=o2t_rpi,
        t2o_rpi=t2o_rpi,
    )


# ---------- Builders (pure) ----------

def build_cpf_with_unconnected_data(
    interface_handle: int,
    timeout: int,
    cip_data: bytes,
) -> bytes:
    """
    Build CPF block with:
      - Null Address item (0x0000)
      - Unconnected Data item (0x00B2)
    """
    null_type = 0x0000
    null_len = 0
    unconn_type = 0x00B2
    unconn_len = len(cip_data)

    return (
        struct.pack("<IHH", interface_handle, timeout, 2)
        + struct.pack("<HH", null_type, null_len)
        + struct.pack("<HH", unconn_type, unconn_len)
        + cip_data
    )


def build_forward_open_success(
    fo: ForwardOpenInfo,
    o2t_conn_id: int,
    t2o_conn_id: int,
) -> bytes:
    """
    Build CIP Forward Open success body (no encapsulation / CPF).
    """
    header = bytes([
        fo.service | 0x80,  # response
        0x00,
        0x00,               # general status = success
        0x00,               # additional status size
    ])

    body = struct.pack(
        "<IIHHI",
        o2t_conn_id,
        t2o_conn_id,
        fo.conn_serial,
        fo.vendor_id,
        fo.origin_serial,
    )
    body += struct.pack("<II", fo.o2t_rpi, fo.t2o_rpi)
    body += struct.pack("BB", 0, 0)  # app size, reserved

    return header + body
