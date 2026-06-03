"""VoIP/Video QoE Metrics — MOS, jitter, packet loss, freeze detection.

Computes quality metrics from RTP streams extracted from PCAP files.
Activates only when RTP traffic is present in the loaded file.

Metrics:
- MOS (Mean Opinion Score): ITU-T G.107 E-model estimation
- Jitter: inter-packet delay variation
- Packet Loss: gaps in RTP sequence numbers
- Video Freeze: gaps > threshold between consecutive video packets
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class RtpPacket:
    """A single RTP packet extracted from PCAP."""
    timestamp: float     # Wall-clock time (epoch seconds)
    ssrc: int           # Stream identifier
    seq: int            # Sequence number (0-65535)
    rtp_ts: int         # RTP timestamp
    payload_type: int   # Codec identifier
    marker: bool        # Frame boundary marker
    src_port: int = 0
    dst_port: int = 0


@dataclass
class QoeResult:
    """QoE metrics for a single RTP stream (one call leg)."""
    ssrc: int
    codec: str
    direction: str           # "UL" or "DL" (inferred from port)
    duration_sec: float
    packet_count: int
    packet_loss_pct: float
    jitter_ms: float         # Average inter-packet jitter
    max_jitter_ms: float
    mos_score: float         # 1.0 - 5.0 (ITU-T G.107)
    freeze_events: int       # Gaps > freeze_threshold
    freeze_duration_sec: float
    max_gap_ms: float


# RTP Payload Type → Codec mapping (common)
_CODEC_MAP = {
    0: "G.711-ulaw",
    8: "G.711-alaw",
    9: "G.722",
    96: "AMR-WB",       # Dynamic, commonly 96
    97: "AMR-NB",       # Dynamic, commonly 97
    98: "EVS",          # Dynamic
    99: "H.264",        # Dynamic, video
    100: "H.265",       # Dynamic, video
    101: "telephone-event",  # DTMF
    111: "opus",        # WebRTC
    112: "AMR-WB",      # Alternative dynamic
    116: "EVS",         # Alternative dynamic
}

# Codec → Equipment Impairment Factor (Ie) for E-model
_CODEC_IE = {
    "G.711-ulaw": 0,
    "G.711-alaw": 0,
    "G.722": 5,
    "AMR-WB": 7,
    "AMR-NB": 20,
    "EVS": 5,
    "opus": 8,
    "H.264": 0,   # Video — not applicable for voice MOS
    "H.265": 0,
}


def compute_qoe(
    streams: dict[int, list[RtpPacket]],
    freeze_threshold_ms: float = 200.0,
) -> list[QoeResult]:
    """Compute QoE metrics for each RTP stream.

    Args:
        streams: dict of SSRC → list of RtpPackets (sorted by timestamp)
        freeze_threshold_ms: gap threshold for video freeze detection
    """
    results = []

    for ssrc, packets in streams.items():
        if len(packets) < 10:
            continue  # Too few packets for meaningful analysis

        packets.sort(key=lambda p: p.timestamp)

        codec = _CODEC_MAP.get(packets[0].payload_type, f"PT{packets[0].payload_type}")
        is_video = codec in ("H.264", "H.265")
        duration = packets[-1].timestamp - packets[0].timestamp
        if duration <= 0:
            continue

        # ── Packet Loss ────────────────────────────────────────────────────
        loss_pct = _calculate_packet_loss(packets)

        # ── Jitter ─────────────────────────────────────────────────────────
        jitter_ms, max_jitter_ms = _calculate_jitter(packets)

        # ── MOS (voice only) ──────────────────────────────────────────────
        if is_video:
            mos = 0.0  # Not applicable for video
        else:
            mos = _estimate_mos(codec, loss_pct, jitter_ms)

        # ── Freeze Detection (video + voice) ──────────────────────────────
        freezes, freeze_dur, max_gap = _detect_freezes(packets, freeze_threshold_ms)

        # ── Direction (heuristic: lower port = server/network side) ────────
        direction = "DL" if packets[0].dst_port < packets[0].src_port else "UL"

        results.append(QoeResult(
            ssrc=ssrc,
            codec=codec,
            direction=direction,
            duration_sec=duration,
            packet_count=len(packets),
            packet_loss_pct=loss_pct,
            jitter_ms=jitter_ms,
            max_jitter_ms=max_jitter_ms,
            mos_score=mos,
            freeze_events=freezes,
            freeze_duration_sec=freeze_dur,
            max_gap_ms=max_gap,
        ))

    return results


def _calculate_packet_loss(packets: list[RtpPacket]) -> float:
    """Calculate packet loss from RTP sequence number gaps."""
    if len(packets) < 2:
        return 0.0

    first_seq = packets[0].seq
    last_seq = packets[-1].seq

    # Handle wraparound at 65536
    if last_seq < first_seq:
        expected = (65536 - first_seq) + last_seq + 1
    else:
        expected = last_seq - first_seq + 1

    received = len(packets)
    if expected <= 0:
        return 0.0

    lost = max(0, expected - received)
    return (lost / expected) * 100.0


def _calculate_jitter(packets: list[RtpPacket]) -> tuple[float, float]:
    """Calculate inter-packet delay variation (jitter) in milliseconds."""
    if len(packets) < 3:
        return 0.0, 0.0

    # Compute inter-arrival time deltas
    deltas = []
    for i in range(1, len(packets)):
        dt = (packets[i].timestamp - packets[i - 1].timestamp) * 1000.0  # ms
        deltas.append(dt)

    if not deltas:
        return 0.0, 0.0

    # Expected interval (median of deltas)
    sorted_deltas = sorted(deltas)
    median_interval = sorted_deltas[len(sorted_deltas) // 2]

    # Jitter = absolute deviation from expected interval
    jitter_values = [abs(d - median_interval) for d in deltas]
    avg_jitter = sum(jitter_values) / len(jitter_values)
    max_jitter = max(jitter_values)

    return avg_jitter, max_jitter


def _estimate_mos(codec: str, packet_loss_pct: float, jitter_ms: float,
                  one_way_delay_ms: float = 50.0) -> float:
    """Estimate MOS using simplified ITU-T G.107 E-model.

    R = R0 - Is - Id - Ie_eff + A
    MOS = 1 + 0.035*R + R*(R-60)*(100-R)*7e-6

    Where:
    - R0 = 93.2 (basic signal-to-noise)
    - Is = 0 (simultaneous impairment, negligible)
    - Id = delay impairment
    - Ie_eff = equipment impairment (codec + loss)
    - A = advantage factor (0 for wired, 5 for cellular)
    """
    R0 = 93.2
    A = 5.0  # Cellular advantage factor

    # Delay impairment (Id)
    d = one_way_delay_ms + jitter_ms * 2  # Effective one-way delay
    if d < 177.3:
        Id = 0.024 * d + 0.11 * (d - 177.3) * (1 if d > 177.3 else 0)
    else:
        Id = 0.024 * d + 0.11 * (d - 177.3)

    # Equipment impairment (Ie_eff) — codec-specific + packet loss
    Ie = _CODEC_IE.get(codec, 15)
    # Packet loss increases Ie: simplified Bpl model
    Bpl = 25.1  # Packet loss robustness factor (codec-dependent)
    if packet_loss_pct > 0:
        Ie_eff = Ie + (95 - Ie) * (packet_loss_pct / (packet_loss_pct + Bpl))
    else:
        Ie_eff = Ie

    # R-factor
    R = R0 - Id - Ie_eff + A
    R = max(0, min(100, R))  # Clamp to [0, 100]

    # R → MOS conversion
    if R < 6.5:
        mos = 1.0
    elif R > 100:
        mos = 4.5
    else:
        mos = 1 + 0.035 * R + R * (R - 60) * (100 - R) * 7e-6

    return round(max(1.0, min(5.0, mos)), 2)


def _detect_freezes(packets: list[RtpPacket], threshold_ms: float) -> tuple[int, float, float]:
    """Detect freeze events (gaps > threshold between consecutive packets).

    Returns: (freeze_count, total_freeze_duration_sec, max_gap_ms)
    """
    if len(packets) < 2:
        return 0, 0.0, 0.0

    freeze_count = 0
    freeze_duration_total = 0.0
    max_gap = 0.0

    for i in range(1, len(packets)):
        gap_ms = (packets[i].timestamp - packets[i - 1].timestamp) * 1000.0
        if gap_ms > max_gap:
            max_gap = gap_ms
        if gap_ms > threshold_ms:
            freeze_count += 1
            freeze_duration_total += gap_ms / 1000.0

    return freeze_count, freeze_duration_total, max_gap
