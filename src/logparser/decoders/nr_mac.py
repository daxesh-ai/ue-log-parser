"""NR MAC DL/UL Transport Block decoders (log codes 0xB8C9 / 0xB8A1).

DL (0xB8C9): Per-slot DL TB — MCS, total TB size, num slots.
UL (0xB8A1): Per-slot UL TB — MCS, total UL bytes, num slots.

Header format (version 1, 20 bytes):
  [0:4]   Version + padding
  [4:8]   System timestamp (ticks)
  [8:12]  Reserved
  [12:16] Total TB bytes (u32 LE)  ← DL: total DL bytes, UL: total UL bytes
  [16:20] Config info

Per-record (DL: 144 bytes, UL: 72 bytes):
  [14]    MCS index (0-31)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime


@dataclass
class MacDlTbSample:
    """A single MAC DL Transport Block sample."""
    timestamp: datetime
    mcs: int       # MCS index 0-31
    tb_size: int   # Total DL TB bytes in this packet
    num_slots: int # Number of slot records


@dataclass
class MacUlTbSample:
    """A single MAC UL Transport Block sample."""
    timestamp: datetime
    mcs: int       # UL MCS index 0-31 (255 = no grant)
    tb_size: int   # Total UL TB bytes
    num_slots: int


def decode_mac_dl_tb(payload: bytes, timestamp: datetime) -> MacDlTbSample | None:
    """Decode a 0xB8C9 DL TB packet."""
    if len(payload) < 36:
        return None

    if payload[0] != 1:
        return None

    tb_total_bytes = struct.unpack_from("<I", payload, 12)[0]
    num_records = (len(payload) - 20) // 144

    if num_records <= 0:
        return None

    mcs = payload[34] if len(payload) > 34 else 0
    if mcs > 31:
        mcs = 0

    return MacDlTbSample(
        timestamp=timestamp,
        mcs=mcs,
        tb_size=tb_total_bytes,
        num_slots=num_records,
    )


def decode_mac_ul_tb(payload: bytes, timestamp: datetime) -> MacUlTbSample | None:
    """Decode a 0xB8A1 UL TB packet.

    Header: 20 bytes. u32@12 = num_sub_PDUs (variable-length records).
    Unlike DL (fixed 144-byte records), UL records are variable-length
    so MCS cannot be reliably extracted from a fixed byte offset.
    We extract the sub-PDU count and total data length as UL activity proxy.
    """
    if len(payload) < 24:
        return None

    if payload[0] != 1:
        return None

    num_sub_pdus = struct.unpack_from("<I", payload, 12)[0]
    if num_sub_pdus == 0 or num_sub_pdus > 100:
        return None

    # Total UL data bytes = payload length - header
    ul_data_bytes = len(payload) - 20

    # MCS not reliably extractable from variable-length UL records
    # Use -1 to indicate "unknown"
    return MacUlTbSample(
        timestamp=timestamp,
        mcs=-1,   # Unknown for variable-length UL records
        tb_size=ul_data_bytes,
        num_slots=num_sub_pdus,
    )
