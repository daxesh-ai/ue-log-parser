"""NR PDCP throughput decoder (log code 0x1CE2).

Extracts signaling-bearer byte counters. Note: in most QUTS captures,
0x1CE2 tracks RRC/NAS bearer (SRB) throughput, not DRB user-plane.
For real DL user-plane throughput, use MAC DL TB (0xB8C9) aggregation.

We expose the delta throughput between consecutive packets as a low-rate
signaling overhead metric.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime


@dataclass
class PdcpThroughputSample:
    """PDCP throughput snapshot."""
    timestamp: datetime
    dl_bytes_cumulative: int  # Cumulative DL bytes (signaling bearer)
    dl_mbps: float            # Instantaneous DL Mbps (delta from previous)
    is_signaling: bool = True # True = SRB, False = DRB user-plane


def decode_pdcp_throughput(
    payload: bytes,
    timestamp: datetime,
    prev_bytes: int = 0,
    prev_timestamp: datetime | None = None,
) -> PdcpThroughputSample | None:
    """Decode a 0x1CE2 PDCP stats packet."""
    if len(payload) < 12:
        return None

    version = payload[0]
    if version != 8:
        return None

    dl_bytes = struct.unpack_from("<I", payload, 4)[0]

    dl_mbps = 0.0
    if prev_bytes is not None and prev_timestamp is not None:
        delta_bytes = dl_bytes - prev_bytes
        dt = (timestamp - prev_timestamp).total_seconds()
        if dt > 0 and 0 < delta_bytes < 10_000_000:
            dl_mbps = delta_bytes * 8 / dt / 1e6

    return PdcpThroughputSample(
        timestamp=timestamp,
        dl_bytes_cumulative=dl_bytes,
        dl_mbps=dl_mbps,
    )
