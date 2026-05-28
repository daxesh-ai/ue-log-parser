from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol as TypingProtocol

from logparser.core.enums import Direction


@dataclass(frozen=True, slots=True)
class StrippedPayload:
    """Result of stripping Qualcomm sub-headers from a Diag payload."""

    pdu: bytes  # Pure ASN.1 or NAS PDU bytes
    channel: str  # Channel name (e.g., "DL-DCCH", "UL-CCCH")
    direction: Direction
    pci: int = 0
    arfcn: int = 0
    sfn: int = 0
    bearer_id: int = -1  # SRB/DRB ID: 0=SRB0, 1=SRB1, 2=SRB2, 3=SRB3, -1=unknown


class HeaderStripper(TypingProtocol):
    def strip(self, payload: bytes) -> StrippedPayload | None:
        """Strip sub-headers from the Diag payload. Returns None if parsing fails."""
        ...
