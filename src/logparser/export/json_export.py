"""JSON export for LogSession."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from logparser.core.session import LogSession


def _to_serializable(obj):
    """Convert non-JSON-serializable types."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Not serializable: {type(obj)}")


def session_to_dict(session: LogSession) -> dict:
    """Serialize a LogSession to a JSON-compatible dict."""
    messages = []
    for msg in session.messages:
        messages.append({
            "index": msg.index,
            "timestamp": msg.timestamp.isoformat(),
            "protocol": msg.protocol.name,
            "direction": msg.direction.value,
            "channel": msg.channel,
            "summary": msg.summary,
            "severity": msg.severity.name,
            "source": msg.source_entity,
            "target": msg.target_entity,
            "pci": msg.pci,
            "arfcn": msg.arfcn,
            "bearer_id": msg.bearer_id,
            "info": msg.info,
            "annotations": msg.annotations,
        })

    phy = [
        {
            "ts": s.timestamp.isoformat(),
            "carrier_id": s.carrier_id,
            "rsrp_dbm": s.rsrp_dbm,
            "sinr_db": round(s.sinr_db, 1),
        }
        for s in getattr(session, "phy_measurements", [])
    ]

    cqi = [
        {
            "ts": s.timestamp.isoformat(),
            "carrier_id": s.carrier_id,
            "cqi": s.cqi,
            "ri": s.ri,
        }
        for s in getattr(session, "phy_cqi_samples", [])
    ]

    mac_dl = [
        {
            "ts": s.timestamp.isoformat(),
            "mcs": s.mcs,
            "tb_bytes": s.tb_size,
        }
        for s in getattr(session, "mac_dl_samples", [])
    ]

    mac_ul = [
        {
            "ts": s.timestamp.isoformat(),
            "mcs": s.mcs,
            "tb_bytes": s.tb_size,
        }
        for s in getattr(session, "mac_ul_samples", [])
    ]

    return {
        "filename": session.filename,
        "message_count": len(session.messages),
        "phy_sample_count": len(phy),
        "mac_dl_sample_count": len(mac_dl),
        "messages": messages,
        "phy_measurements": phy,
        "phy_cqi_samples": cqi,
        "mac_dl_samples": mac_dl,
        "mac_ul_samples": mac_ul,
    }


def export_json(session: LogSession, output_path: Path, compact: bool = False) -> None:
    """Export session to JSON file."""
    data = session_to_dict(session)
    indent = None if compact else 2
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=indent, default=_to_serializable)
