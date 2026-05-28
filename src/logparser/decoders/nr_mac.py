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

    Same header layout as DL but per-record is 72 bytes.
    """
    if len(payload) < 28:
        return None

    if payload[0] != 1:
        return None

    tb_total_bytes = struct.unpack_from("<I", payload, 12)[0]
    num_records = (len(payload) - 20) // 72

    if num_records <= 0:
        return None

    # MCS at same relative position within record
    mcs = payload[34] if len(payload) > 34 else 0
    if mcs > 31:
        mcs = 0

    return MacUlTbSample(
        timestamp=timestamp,
        mcs=mcs,
        tb_size=tb_total_bytes,
        num_slots=num_records,
    )
