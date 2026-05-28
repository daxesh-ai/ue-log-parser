"""NR MAC RACH status decoder (log code 0xB888).

Extracts RACH power control and Timing Advance status.
This log contains periodic status dumps (not individual RACH attempts).
Key values tracked:
- Timing Advance (proportional to distance to cell)
- PRACH power control state
- Active status (result field)

Record format (version 1, 92 bytes total = 8-byte header + 84-byte record):
  [8:12]  System timestamp (u32)
  [12]    Result/status (1=active)
  [20:22] num_preamble_tx (u16) — slowly incrementing counter
  [28:30] Timing Advance value (u16, ~845 = typical)
  [32:34] Timing Advance secondary (u16)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime


@dataclass
class RachStatus:
    """RACH power control and timing advance status snapshot."""
    timestamp: datetime
    timing_advance: int  # TA value (proportional to cell distance)
    preamble_count: int  # Cumulative preamble transmissions
    active: bool


def decode_rach_status(payload: bytes, timestamp: datetime) -> RachStatus | None:
    """Decode a 0xB888 RACH status packet."""
    if len(payload) < 40:
        return None

    version = payload[0]
    if version != 1:
        return None

    rec = payload[8:]  # Skip 8-byte header

    result = rec[4]  # 1 = active/success
    preamble_count = struct.unpack_from("<H", rec, 16)[0]
    timing_advance = struct.unpack_from("<H", rec, 28)[0]

    return RachStatus(
        timestamp=timestamp,
        timing_advance=timing_advance,
        preamble_count=preamble_count,
        active=(result == 1),
    )
