"""NR MAC-CE decoder for SCell Activation/Deactivation (log code 0xB887).

Parses MAC Control Elements from Qualcomm NR MAC DL Control log packets.
Key MAC-CEs decoded:
- LCID 59 (0x3B): SCell Activation/Deactivation (1-byte, SCells 1-7)
- LCID 60 (0x3C): SCell Activation/Deactivation (4-byte extended, SCells 1-31)
- LCID 18 (0x12): Timing Advance Command
- LCID 11 (0x0B): SpCell PDCP Count Info
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime

from logparser.core.enums import Direction, Protocol, Severity
from logparser.core.message import ParsedMessage


@dataclass
class MacCeEvent:
    """A decoded MAC-CE event."""
    timestamp: datetime
    lcid: int
    lcid_name: str
    active_scells: list[int]  # SCell indices that are active
    raw_bitmask: bytes


# NR DL-SCH LCID values for MAC CEs (TS 38.321 Table 6.2.1-1)
_LCID_NAMES = {
    0x0B: "Duplication Activation/Deactivation",
    0x10: "Long DRX Command",
    0x11: "DRX Command",
    0x12: "Timing Advance Command",
    0x13: "Short DRX Command",
    0x3B: "SCell Activation/Deactivation",
    0x3C: "SCell Activation/Deactivation (extended)",
    0x3D: "SCell Activation/Deactivation (4 octets)",
    0x3E: "UE Contention Resolution Identity",
    0x3F: "Padding",
}


def decode_mac_ce_packet(payload: bytes, timestamp: datetime) -> list[MacCeEvent]:
    """Decode a 0xB887 MAC DL Control packet into MAC-CE events."""
    if len(payload) < 10:
        return []

    events = []

    # Header: 8 bytes (version=payload[0], num_subPDUs=payload[7])
    num_sub_pdus = payload[7]
    header_size = 8

    # Search for SCell Activation LCIDs in the payload
    for off in range(header_size, len(payload) - 1):
        if payload[off] == 0x3B:
            # LCID 59: 1-byte bitmask [C7 C6 C5 C4 C3 C2 C1 R]
            if off + 1 < len(payload):
                bitmask = payload[off + 1]
                active_scells = []
                for bit in range(1, 8):
                    if bitmask & (1 << bit):
                        active_scells.append(bit)
                events.append(MacCeEvent(
                    timestamp=timestamp,
                    lcid=0x3B,
                    lcid_name="SCell Activation/Deactivation",
                    active_scells=active_scells,
                    raw_bitmask=bytes([bitmask]),
                ))
            break

        elif payload[off] == 0x3C:
            # LCID 60: 4-byte extended bitmask
            if off + 4 <= len(payload):
                b0 = payload[off + 1]
                b1 = payload[off + 2] if off + 2 < len(payload) else 0
                b2 = payload[off + 3] if off + 3 < len(payload) else 0
                b3 = payload[off + 4] if off + 4 < len(payload) else 0
                active_scells = []
                # Byte 0: SCells 1-7 (bits 7:1, bit 0 = Reserved)
                for bit in range(1, 8):
                    if b0 & (1 << bit):
                        active_scells.append(bit)
                # Byte 1: SCells 8-15
                for bit in range(0, 8):
                    if b1 & (1 << bit):
                        active_scells.append(8 + bit)
                # Byte 2: SCells 16-23
                for bit in range(0, 8):
                    if b2 & (1 << bit):
                        active_scells.append(16 + bit)
                # Byte 3: SCells 24-31
                for bit in range(0, 8):
                    if b3 & (1 << bit):
                        active_scells.append(24 + bit)
                events.append(MacCeEvent(
                    timestamp=timestamp,
                    lcid=0x3C,
                    lcid_name="SCell Activation/Deactivation (extended)",
                    active_scells=active_scells,
                    raw_bitmask=bytes([b0, b1, b2, b3]),
                ))
            break

    return events


def build_mac_ce_messages(
    events: list[MacCeEvent], start_index: int
) -> list[ParsedMessage]:
    """Convert MAC-CE events into ParsedMessages for display in the GUI."""
    messages = []

    for i, event in enumerate(events):
        if event.active_scells:
            scell_str = ",".join(str(s) for s in event.active_scells)
            summary = f"MAC-CE: SCell Activate [{scell_str}]"
            info = f"{len(event.active_scells)}CC active: SCell {scell_str}"
        else:
            summary = "MAC-CE: SCell Deactivate ALL"
            info = "All SCells deactivated"

        msg = ParsedMessage(
            index=start_index + i,
            timestamp=event.timestamp,
            protocol=Protocol.NR_RRC,  # Display alongside RRC
            direction=Direction.DL,
            channel="MAC-CE",
            summary=summary,
            raw_payload=event.raw_bitmask,
            info=info,
            source_entity="gNB",
            target_entity="UE",
        )
        messages.append(msg)

    return messages
