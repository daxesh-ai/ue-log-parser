"""NR UL Power Control decoder (log code 0xB8A7).

Extracts UL power configuration and power headroom indicators.
Used to detect "UE power limited" scenarios where the UE cannot
reach the gNB due to insufficient transmit power margin.

Record format (version 5, hdr=8, rec=76 bytes):
  [0]     Carrier index
  [2:4]   SFN (u16 LE)
  [17]    Pcmax FR2 (dBm) — typically 20 dBm for iPhone mmWave
  [18]    Pcmax FR1 (dBm) — typically 23 dBm for iPhone sub-6
  [19]    Power control param (alpha/P0 related)
  [20]    Power control param
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime


@dataclass
class UlPowerConfig:
    """UL power control configuration snapshot."""
    timestamp: datetime
    carrier_id: int
    sfn: int
    pcmax_fr1_dbm: int   # Max UE power for FR1 (sub-6 GHz)
    pcmax_fr2_dbm: int   # Max UE power for FR2 (mmWave)
    power_headroom_limited: bool  # True if PHR ≈ 0 (inferred)


def decode_ul_power_config(payload: bytes, timestamp: datetime) -> UlPowerConfig | None:
    """Decode a 0xB8A7 UL power control config packet."""
    if len(payload) < 28:
        return None

    version = payload[0]
    if version != 5:
        return None

    hdr = 8
    rec = payload[hdr:]
    if len(rec) < 21:
        return None

    carrier_id = rec[0]
    sfn = struct.unpack_from("<H", rec, 2)[0]
    pcmax_fr2 = rec[17]  # FR2 max power (typically 20 dBm)
    pcmax_fr1 = rec[18]  # FR1 max power (typically 23 dBm)

    # Infer power-limited state: if Pcmax is unusually low (< 15 dBm for FR1)
    # or if the config shows restricted power class
    power_limited = pcmax_fr1 < 15 or pcmax_fr2 < 10

    return UlPowerConfig(
        timestamp=timestamp,
        carrier_id=carrier_id,
        sfn=sfn,
        pcmax_fr1_dbm=pcmax_fr1,
        pcmax_fr2_dbm=pcmax_fr2,
        power_headroom_limited=power_limited,
    )
