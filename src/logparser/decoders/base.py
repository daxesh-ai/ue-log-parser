from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol as TypingProtocol

from logparser.core.enums import Direction, Protocol


@dataclass(slots=True)
class DecodeResult:
    summary: str
    decoded_tree: dict | tuple | None
    decoded_text: str
    protocol: Protocol
    direction: Direction
    channel: str
    source_entity: str = "UE"
    target_entity: str = "gNB"


class Decoder(TypingProtocol):
    def decode(self, pdu: bytes, channel: str, direction: Direction) -> DecodeResult | None:
        """Decode a PDU. Returns None if decoding fails."""
        ...
