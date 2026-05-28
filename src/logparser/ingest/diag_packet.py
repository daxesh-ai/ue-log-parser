from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class DiagPacket:
    """A single Qualcomm Diag log packet extracted from a QUTS container."""

    log_code: int
    timestamp: datetime
    payload: bytes  # Full payload including sub-headers (after DLF header strip)
    version: int = 0  # Diag packet version from the DLF header area
