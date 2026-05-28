"""CSV export for log sessions."""

from __future__ import annotations

import csv
from pathlib import Path

from logparser.core.session import LogSession


def export_csv(session: LogSession, output_path: Path) -> None:
    """Export a LogSession to CSV."""
    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Index", "Timestamp", "Protocol", "Direction", "Channel",
            "Summary", "Severity", "PCI", "ARFCN", "Annotations",
        ])
        for msg in session.messages:
            writer.writerow([
                msg.index,
                msg.timestamp.isoformat(),
                msg.protocol.name,
                msg.direction.value,
                msg.channel,
                msg.summary,
                msg.severity.name,
                msg.pci,
                msg.arfcn,
                "; ".join(msg.annotations) if msg.annotations else "",
            ])
