"""NR RLC DL Stats decoder (log code 0x1874).

Extracts per-bearer RLC retransmission counts and max-retx-reached events.
These directly correlate with SCG failures (rlc-MaxNumRetx cause).

Record format (version 17):
  header: 8 bytes (version + padding)
  per-bearer records: variable, contains retx_count and max_retx flag
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime


@dataclass
class RlcDlStats:
    """Per-bearer RLC DL statistics snapshot."""
    timestamp: datetime
    retx_count: int        # Cumulative RLC retransmissions
    max_retx_reached: bool # True if rlc-MaxNumRetx was triggered


def decode_rlc_dl_stats(payload: bytes, timestamp: datetime) -> RlcDlStats | None:
    """Decode a 0x1874 RLC stats packet.

    The structure has a fixed header followed by bearer records.
    We extract cumulative retx_count and the max_retx_reached flag.
    Version 17: header=8, retx at offset 28 (u32), max_retx flag at offset 32.
    """
    if len(payload) < 36:
        return None

    version = payload[0]
    if version != 17:
        return None

    # Cumulative retransmission count across all bearers
    retx_count = struct.unpack_from("<I", payload, 28)[0]
    max_retx_reached = (payload[32] != 0)

    return RlcDlStats(
        timestamp=timestamp,
        retx_count=retx_count,
        max_retx_reached=max_retx_reached,
    )
