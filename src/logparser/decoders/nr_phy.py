"""NR PHY decoder — serving cell measurements, CQI/RI, SSB/CSI-RS beams, HARQ.

Log codes:
  0xB883 — NR L1 Serving Cell Measurement (RSRP/SINR per carrier, version 26)
  0xB8D1 — NR PDSCH CSI Information (CQI/RI per carrier, version 7)
  0xB884 — NR SSB Serving/Neighbor Measurements (RSRP per cell, version 5)
  0xB885 — NR CSI-RS Measurements (RSRP per cell, version 20)
  0xB896 — NR MAC DL HARQ feedback (ACK/NACK counts → BLER, version 0)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class PhyMeasurement:
    """A single PHY-layer serving cell measurement sample (0xB883)."""
    timestamp: datetime
    carrier_id: int
    sfn: int
    rsrp_dbm: float   # RSRP in dBm (-156 to -31)
    rsrp_index: int   # 3GPP RSRP index (0-127)
    sinr_db: float = 0.0  # SINR in dB


@dataclass
class PhyCqiSample:
    """Per-carrier CQI and RI from PDSCH CSI report (0xB8D1)."""
    timestamp: datetime
    carrier_id: int
    cqi: int     # Wideband CQI index 1-15 (0 = out-of-range/invalid)
    ri: int      # Rank Indicator 1-4


@dataclass
class PhyBeamMeasurement:
    """Per-cell RSRP from SSB or CSI-RS beam measurements (0xB884/0xB885)."""
    timestamp: datetime
    source: str       # "SSB" or "CSI-RS"
    pci: int
    rsrp_dbm: float


def decode_phy_measurements(payload: bytes, timestamp: datetime) -> list[PhyMeasurement]:
    """Decode a 0xB883 packet into per-carrier RSRP/SINR measurements."""
    if len(payload) < 12:
        return []

    version = payload[0]
    if version < 20:
        return []

    num_cells = payload[7]
    if num_cells == 0 or num_cells > 8:
        return []

    header_size = 8
    rec_size = 44
    results = []

    for cell_idx in range(num_cells):
        offset = header_size + cell_idx * rec_size
        if offset + rec_size > len(payload):
            rec_size = len(payload) - header_size
            if rec_size < 12:
                break

        r = payload[offset:offset + rec_size]
        if len(r) < 12:
            break

        carrier_id = r[0]
        sfn = struct.unpack_from("<H", r, 2)[0]

        val_a = struct.unpack_from("<H", r, 8)[0]
        rsrp_index = (val_a >> 6) & 0x7F
        rsrp_dbm = rsrp_index - 156

        val_b = struct.unpack_from("<H", r, 10)[0]
        sinr_raw = (val_b >> 6) & 0xFF
        sinr_db = (sinr_raw / 2.0) - 20.0

        if rsrp_dbm < -156 or rsrp_dbm > -30:
            continue
        if carrier_id > 31:
            continue

        results.append(PhyMeasurement(
            timestamp=timestamp,
            carrier_id=carrier_id,
            sfn=sfn,
            rsrp_dbm=rsrp_dbm,
            rsrp_index=rsrp_index,
            sinr_db=sinr_db,
        ))

    return results


def decode_phy_cqi(payload: bytes, timestamp: datetime) -> list[PhyCqiSample]:
    """Decode a 0xB8D1 PDSCH CSI packet into per-carrier CQI/RI samples.

    Record format (version 7, header=20, rec_size=168):
      [0]     Carrier index
      [2:4]   SFN (u16 LE)
      [12]    Packed: low-nibble = wideband CQI (1-15), bits[5:4] = RI (0-3 → 1-4)
    """
    if len(payload) < 24:
        return []

    version = payload[0]
    if version != 7:
        return []

    header_size = 20
    rec_size = 168

    if (len(payload) - header_size) % rec_size != 0:
        return []

    n = (len(payload) - header_size) // rec_size
    results = []

    for i in range(n):
        offset = header_size + i * rec_size
        r = payload[offset:offset + rec_size]
        if len(r) < 13:
            break

        carrier_id = r[0]
        if carrier_id > 31:
            continue

        cqi = r[12] & 0x0F          # lower nibble: wideband CQI index
        ri = ((r[12] >> 4) & 0x3) + 1  # bits [5:4] → RI 1-4

        if cqi == 0:  # CQI=0 means out-of-range / no report
            continue

        results.append(PhyCqiSample(
            timestamp=timestamp,
            carrier_id=carrier_id,
            cqi=cqi,
            ri=ri,
        ))

    return results


def decode_ssb_measurements(payload: bytes, timestamp: datetime) -> list[PhyBeamMeasurement]:
    """Decode a 0xB884 SSB measurement packet into per-cell RSRP.

    Record format (version 5, header=8, rec_size=32):
      [0:2]   Packed: lower 10 bits = PCI
      [2:4]   SFN (u16 LE)
      [8:10]  Packed RSRP: bits [12:6] = 7-bit index, index-156 = dBm
    """
    if len(payload) < 12:
        return []

    version = payload[0]
    if version != 5:
        return []

    num_cells = payload[7]
    if num_cells == 0 or num_cells > 16:
        return []

    header_size = 8
    rec_size = (len(payload) - header_size) // num_cells
    if rec_size < 12:
        return []

    results = []
    for i in range(num_cells):
        offset = header_size + i * rec_size
        r = payload[offset:offset + rec_size]
        if len(r) < 10:
            break

        pci = struct.unpack_from("<H", r, 0)[0] & 0x3FF
        val_a = struct.unpack_from("<H", r, 8)[0]
        rsrp_index = (val_a >> 6) & 0x7F
        rsrp_dbm = rsrp_index - 156

        if rsrp_dbm < -156 or rsrp_dbm > -30:
            continue
        if pci > 1007:
            continue

        results.append(PhyBeamMeasurement(
            timestamp=timestamp,
            source="SSB",
            pci=pci,
            rsrp_dbm=rsrp_dbm,
        ))

    return results


def decode_csirs_measurements(payload: bytes, timestamp: datetime) -> list[PhyBeamMeasurement]:
    """Decode a 0xB885 CSI-RS measurement packet into per-cell RSRP.

    Record format (version 20, header=8):
      [0:2]   Packed: lower 10 bits = PCI
      [22:24] Packed RSRP: bits [12:6] = 7-bit index, index-156 = dBm
    """
    if len(payload) < 12:
        return []

    version = payload[0]
    if version != 20:
        return []

    num_cells = payload[7]
    if num_cells == 0 or num_cells > 16:
        return []

    header_size = 8
    rec_size = (len(payload) - header_size) // num_cells
    if rec_size < 24:
        return []

    results = []
    for i in range(num_cells):
        offset = header_size + i * rec_size
        r = payload[offset:offset + rec_size]
        if len(r) < 24:
            break

        pci = struct.unpack_from("<H", r, 0)[0] & 0x3FF
        val_a = struct.unpack_from("<H", r, 22)[0]
        rsrp_index = (val_a >> 6) & 0x7F
        rsrp_dbm = rsrp_index - 156

        if rsrp_dbm < -156 or rsrp_dbm > -30:
            continue
        if pci > 1007:
            continue

        results.append(PhyBeamMeasurement(
            timestamp=timestamp,
            source="CSI-RS",
            pci=pci,
            rsrp_dbm=rsrp_dbm,
        ))

    return results


@dataclass
class HarqSample:
    """DL HARQ ACK/NACK feedback sample (0xB896)."""
    timestamp: datetime
    ack_count: int    # number of ACKs in this packet
    nack_count: int   # number of NACKs (retransmissions triggered)
    bler_pct: float   # packet BLER = nack/(ack+nack)*100


def decode_harq_feedback(payload: bytes, timestamp: datetime) -> HarqSample | None:
    """Decode a 0xB896 HARQ feedback packet into ACK/NACK counts.

    Header: 20 bytes (version=0 at [0], num_records at [7]).
    Data at offset 20:
      u32@0 = NACK count (retransmissions triggered)
      u32@4 = ACK count  (successful first transmissions)
    """
    if len(payload) < 28:
        return None

    if payload[0] != 0:
        return None  # Only version 0 supported

    nack = struct.unpack_from("<I", payload, 20)[0]
    ack = struct.unpack_from("<I", payload, 24)[0]

    total = ack + nack
    if total == 0:
        return None

    bler_pct = nack / total * 100.0

    return HarqSample(
        timestamp=timestamp,
        ack_count=ack,
        nack_count=nack,
        bler_pct=bler_pct,
    )
