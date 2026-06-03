"""Field Reference Database — compare session against expected carrier config.

Loads a reference JSON defining expected bands, thresholds, and configuration
per carrier (auto-detected from PLMN or ARFCN patterns). Flags deviations
from expected values as recommendations.

Reference file search order:
1. ~/.logparser/reference.json (user customization)
2. data/reference/default_reference.json (bundled with package)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from logparser.core.session import LogSession


@dataclass
class FieldDeviation:
    """A detected deviation from expected field configuration."""
    metric: str
    expected: str
    actual: str
    severity_multiplier: float  # 1.0=at threshold, 2.0=2x over


def load_reference(path: Path | None = None) -> dict | None:
    """Load carrier reference database. Returns None if not found."""
    search_paths = []
    if path:
        search_paths.append(path)
    search_paths.append(Path.home() / ".logparser" / "reference.json")
    search_paths.append(Path(__file__).parent.parent.parent.parent / "data" / "reference" / "default_reference.json")

    for p in search_paths:
        if p.exists():
            try:
                with open(p) as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                continue
    return None


def detect_carrier(session: LogSession, reference: dict) -> str | None:
    """Auto-detect carrier from session data (ARFCN patterns, PLMN)."""
    carriers = reference.get("carriers", {})

    # Method 1: Check PLMN from NAS messages
    for msg in session.messages:
        if msg.decoded_tree and isinstance(msg.decoded_tree, dict):
            tree_str = str(msg.decoded_tree)
            for carrier_name, carrier_data in carriers.items():
                plmns = carrier_data.get("plmn", [])
                for plmn in plmns:
                    if plmn in tree_str:
                        return carrier_name

    # Method 2: Match ARFCN to carrier-specific bands
    from logparser.decoders.info_extractor import _arfcn_to_band
    session_bands = set()
    for msg in session.messages:
        if msg.arfcn and msg.arfcn > 0:
            band = _arfcn_to_band(msg.arfcn)
            if band:
                session_bands.add(band)

    # Score each carrier by how many of its bands match
    best_carrier = None
    best_score = 0
    for carrier_name, carrier_data in carriers.items():
        carrier_bands = set(carrier_data.get("bands", {}).keys())
        overlap = len(session_bands & carrier_bands)
        if overlap > best_score:
            best_score = overlap
            best_carrier = carrier_name

    return best_carrier


def check_field_deviations(session: LogSession) -> list:
    """Compare session metrics against field reference and return Recommendations."""
    from logparser.analysis.recommendations import Recommendation
    from logparser.core.enums import Severity

    reference = load_reference()
    if not reference:
        return []

    carrier = detect_carrier(session, reference)
    if not carrier:
        return []

    carrier_data = reference["carriers"].get(carrier, {})
    thresholds = carrier_data.get("thresholds", {})
    bands = carrier_data.get("bands", {})

    recs = []
    deviations = []

    # ── Check RSRP against threshold ──────────────────────────────────────────
    phy = getattr(session, "phy_measurements", [])
    if phy:
        rsrps = [m.rsrp_dbm for m in phy]
        avg_rsrp = sum(rsrps) / len(rsrps)
        min_rsrp_threshold = thresholds.get("min_rsrp_dbm", -120)
        if avg_rsrp < min_rsrp_threshold:
            deviation = abs(avg_rsrp - min_rsrp_threshold)
            deviations.append(FieldDeviation(
                metric="Average RSRP",
                expected=f"> {min_rsrp_threshold} dBm",
                actual=f"{avg_rsrp:.1f} dBm",
                severity_multiplier=deviation / 10.0,
            ))

    # ── Check BLER against threshold ──────────────────────────────────────────
    harq = getattr(session, "harq_samples", [])
    if harq:
        total_ack = sum(s.ack_count for s in harq)
        total_nack = sum(s.nack_count for s in harq)
        total = total_ack + total_nack
        if total > 0:
            bler = total_nack / total * 100
            max_bler = thresholds.get("max_bler_pct", 2.0)
            if bler > max_bler:
                deviations.append(FieldDeviation(
                    metric="DL HARQ BLER",
                    expected=f"< {max_bler}%",
                    actual=f"{bler:.2f}%",
                    severity_multiplier=bler / max_bler,
                ))

    # ── Check T300 timeout count ──────────────────────────────────────────────
    t300_count = sum(1 for m in session.messages
                     if m.severity.name == "FAILURE" and "T300" in " ".join(m.annotations))
    max_t300 = thresholds.get("max_t300_timeout_count", 5)
    if t300_count > max_t300:
        deviations.append(FieldDeviation(
            metric="T300 Timeouts",
            expected=f"≤ {max_t300}",
            actual=str(t300_count),
            severity_multiplier=t300_count / max_t300,
        ))

    # ── Check RRC Reject count ────────────────────────────────────────────────
    reject_count = sum(1 for m in session.messages
                       if "reject" in m.summary.lower() or "Reject" in m.summary)
    max_rejects = thresholds.get("max_rrc_reject_count", 10)
    if reject_count > max_rejects:
        deviations.append(FieldDeviation(
            metric="RRC Rejects",
            expected=f"≤ {max_rejects}",
            actual=str(reject_count),
            severity_multiplier=reject_count / max_rejects,
        ))

    # ── Check SCG Failure count ───────────────────────────────────────────────
    scg_count = sum(1 for m in session.messages
                    if "SCGFailure" in m.summary or "MCGFailure" in m.summary)
    max_scg = thresholds.get("max_scg_failure_count", 3)
    if scg_count > max_scg:
        deviations.append(FieldDeviation(
            metric="SCG/MCG Failures",
            expected=f"≤ {max_scg}",
            actual=str(scg_count),
            severity_multiplier=scg_count / max_scg,
        ))

    # ── Build recommendations from deviations (max 3) ─────────────────────────
    deviations.sort(key=lambda d: -d.severity_multiplier)

    for dev in deviations[:3]:
        if dev.severity_multiplier >= 3.0:
            severity = "Critical"
        elif dev.severity_multiplier >= 1.5:
            severity = "Major"
        else:
            severity = "Minor"

        recs.append(Recommendation(
            rank=0,
            category="Field",
            issue=f"Field Deviation: {dev.metric} ({carrier})",
            severity=severity,
            count=1,
            msg_indices=[session.messages[0].index] if session.messages else [],
            root_cause=(
                f"Session metric '{dev.metric}' deviates from {carrier} reference baseline. "
                f"Expected: {dev.expected}. Actual: {dev.actual}. "
                f"Deviation is {dev.severity_multiplier:.1f}x above threshold."
            ),
            recommendation=(
                f"1. Verify {dev.metric} is within normal range for this cell/location\n"
                f"2. Compare against historical baseline for this site\n"
                f"3. If persistent: escalate to network engineering\n"
                f"4. Reference: {carrier} baseline → {dev.expected}"
            ),
            parameter=f"{dev.metric}, carrier={carrier}",
        ))

    return recs
