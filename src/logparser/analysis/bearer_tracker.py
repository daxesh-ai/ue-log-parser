"""Bearer / QoS Flow Tracker — tracks E-RAB and PDU Session lifecycle.

Extracts bearer events from:
- NAS messages: Attach Accept (QCI), Activate Bearer, Deactivate Bearer
- S1AP messages (via info field): E-RAB Setup/Release/Modify
- NGAP messages: PDU Session Setup/Modification

Produces a timeline of bearer states for each EBI (EPS Bearer Identity)
or QFI (QoS Flow Identifier).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

from logparser.core.message import ParsedMessage
from logparser.core.session import LogSession


@dataclass
class BearerEvent:
    """A single bearer lifecycle event."""
    timestamp: datetime
    msg_index: int
    event_type: str    # "setup", "modify", "release", "activate", "deactivate"
    bearer_id: int     # EBI (4-15) or QFI (0-63)
    qci_5qi: int       # QCI (LTE) or 5QI (NR) — 0 if unknown
    apn: str           # APN/DNN name if available
    cause: str         # Release/failure cause if applicable


# QCI/5QI → service type mapping
_QCI_5QI_MAP = {
    1: "Conversational Voice (GBR)",
    2: "Conversational Video (GBR)",
    3: "Real-time Gaming (GBR)",
    4: "Non-conversational Video (GBR)",
    5: "IMS Signaling (non-GBR)",
    6: "Video Streaming (non-GBR)",
    7: "Voice/Video/Interactive Gaming (non-GBR)",
    8: "Best Effort (Web/Email)",
    9: "Best Effort (default)",
    65: "Mission Critical Voice (GBR)",
    66: "Non-Mission-Critical Voice (GBR)",
    69: "Mission Critical Data (non-GBR)",
    70: "Multimedia Priority (non-GBR)",
    79: "V2X Messages (GBR)",
    80: "Low-Latency eMBB (non-GBR)",
}


def format_qci(qci: int) -> str:
    """Format QCI/5QI with description."""
    desc = _QCI_5QI_MAP.get(qci, "Unknown")
    return f"QCI/5QI={qci} ({desc})"


def build_bearer_events(session: LogSession) -> list[BearerEvent]:
    """Scan session messages and extract bearer lifecycle events."""
    events = []

    for msg in session.messages:
        summary = msg.summary.lower()
        tree = msg.decoded_tree

        # ── NAS: Attach Accept / Activate Bearer ────────────────────────────
        if tree and isinstance(tree, dict):
            tree_str = str(tree)

            if "attachaccept" in summary or "ActivateDefaultEPSBearerContextRequest" in tree_str:
                # Extract QCI and EBI
                qci_match = re.search(r"'QCI':\s*(\d+)", tree_str)
                ebi_match = re.search(r"'EPSBearerId':\s*(\d+)", tree_str)
                apn_match = re.search(r"'Value':\s*'([^']+)'", tree_str)

                qci = int(qci_match.group(1)) if qci_match else 0
                ebi = int(ebi_match.group(1)) if ebi_match else 5
                apn = apn_match.group(1) if apn_match else ""

                events.append(BearerEvent(
                    timestamp=msg.timestamp,
                    msg_index=msg.index,
                    event_type="setup",
                    bearer_id=ebi,
                    qci_5qi=qci,
                    apn=apn,
                    cause="",
                ))

            elif "deactivate" in summary.lower() and "bearer" in summary.lower():
                ebi_match = re.search(r"'EPSBearerId':\s*(\d+)", tree_str)
                ebi = int(ebi_match.group(1)) if ebi_match else 0
                events.append(BearerEvent(
                    timestamp=msg.timestamp,
                    msg_index=msg.index,
                    event_type="release",
                    bearer_id=ebi,
                    qci_5qi=0,
                    apn="",
                    cause="NAS deactivation",
                ))

        # ── S1AP: E-RAB events from info field ──────────────────────────────
        if msg.channel == "S1AP" and msg.info:
            info = msg.info
            if "Bearer:" in info:
                ebi_match = re.search(r"EBI=(\d+)", info)
                ebi = int(ebi_match.group(1)) if ebi_match else 0

                if "Release" in msg.summary or "release" in msg.summary.lower():
                    cause = ""
                    cause_match = re.search(r"Cause:([^\|]+)", info)
                    if cause_match:
                        cause = cause_match.group(1).strip()
                    events.append(BearerEvent(
                        timestamp=msg.timestamp,
                        msg_index=msg.index,
                        event_type="release",
                        bearer_id=ebi,
                        qci_5qi=0,
                        apn="",
                        cause=cause,
                    ))
                elif "Setup" in msg.summary or "Modification" in msg.summary:
                    events.append(BearerEvent(
                        timestamp=msg.timestamp,
                        msg_index=msg.index,
                        event_type="modify" if "Modification" in msg.summary else "setup",
                        bearer_id=ebi,
                        qci_5qi=0,
                        apn="",
                        cause="",
                    ))

        # ── UEContextRelease with cause ──────────────────────────────────────
        if "UEContextRelease" in msg.summary and msg.info and "Cause:" in msg.info:
            cause = msg.info.split("Cause:")[1].split("|")[0].strip() if "Cause:" in msg.info else ""
            events.append(BearerEvent(
                timestamp=msg.timestamp,
                msg_index=msg.index,
                event_type="release",
                bearer_id=0,  # All bearers released
                qci_5qi=0,
                apn="",
                cause=cause,
            ))

    return events
