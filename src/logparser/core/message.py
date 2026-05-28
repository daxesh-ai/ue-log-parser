from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .enums import Direction, Protocol, Severity


@dataclass(slots=True)
class ParsedMessage:
    index: int
    timestamp: datetime
    protocol: Protocol
    direction: Direction
    channel: str
    summary: str
    raw_payload: bytes
    decoded_tree: dict | tuple | None = None
    decoded_text: str = ""
    log_code: int = 0
    severity: Severity = Severity.NORMAL
    annotations: list[str] = field(default_factory=list)
    source_entity: str = "UE"
    target_entity: str = "gNB"
    # Sub-header metadata
    pci: int = 0
    arfcn: int = 0
    bearer_id: int = -1  # SRB/DRB ID: 0=SRB0, 1=SRB1, 2=SRB2, 3=SRB3, -1=unknown
    # Extracted IE info (PCell, SCell, Band, 5QI, etc.)
    info: str = ""
    # Source file (multi-file sessions only)
    source_file: str = ""
