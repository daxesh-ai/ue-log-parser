"""NAS (5G and LTE) sub-header strippers.

NR NAS (0xB97F) and LTE NAS (0xB0EC/0xB0ED) have simpler sub-headers
since NAS messages don't have an RRC channel — they're just plain L3 PDUs.
"""

from __future__ import annotations

import struct

from logparser.core.enums import Direction
from .base import StrippedPayload


class NrNasHeaderStripper:
    """Strips sub-headers from NR NAS (5G NAS) log packets (0xB97F)."""

    def strip(self, payload: bytes) -> StrippedPayload | None:
        if len(payload) < 4:
            return None

        # NR NAS sub-header is typically very short:
        # version(1) + direction(1) + length(2) + PDU
        # But versions vary. Try to find the NAS PDU.
        version = payload[0]

        if version >= 0x10 and len(payload) >= 8:
            # Larger header format
            direction_byte = payload[1]
            pdu_len = struct.unpack_from("<H", payload, 4)[0]
            header_size = 8
            if pdu_len > 0 and header_size + pdu_len <= len(payload):
                pdu = payload[header_size : header_size + pdu_len]
                direction = Direction.UL if direction_byte == 1 else Direction.DL
                return StrippedPayload(pdu=pdu, channel="NAS", direction=direction)

        # Minimal header: first byte = version, then PDU
        # Try progressive offsets
        for offset in (4, 2, 8, 6):
            if offset < len(payload):
                pdu = payload[offset:]
                # NAS messages start with specific protocol discriminators
                if len(pdu) >= 2 and (pdu[0] & 0x0F) in (0x02, 0x07, 0x7E):
                    return StrippedPayload(
                        pdu=pdu, channel="NAS", direction=Direction.UNKNOWN
                    )

        # Last resort: skip version byte only
        return StrippedPayload(
            pdu=payload[1:], channel="NAS", direction=Direction.UNKNOWN
        )


class LteNasHeaderStripper:
    """Strips sub-headers from LTE NAS log packets (0xB0EC/0xB0ED).

    0xB0EC = downlink (network → UE)
    0xB0ED = uplink (UE → network)
    """

    def __init__(self, is_uplink: bool):
        self._direction = Direction.UL if is_uplink else Direction.DL

    def strip(self, payload: bytes) -> StrippedPayload | None:
        if len(payload) < 4:
            return None

        # LTE NAS header: version(1) + padding(3) + PDU
        # or: version(1) + length(2) + PDU
        version = payload[0]

        # Try: length at offset 1-2, PDU at offset 3
        if len(payload) >= 5:
            pdu_len = struct.unpack_from("<H", payload, 1)[0]
            if 0 < pdu_len <= len(payload) - 3:
                pdu = payload[3 : 3 + pdu_len]
                if len(pdu) >= 2 and (pdu[0] & 0x0F) in (0x02, 0x07):
                    return StrippedPayload(
                        pdu=pdu, channel="NAS", direction=self._direction
                    )

        # Try: 4-byte header, PDU starts at offset 4
        if len(payload) > 4:
            pdu = payload[4:]
            if len(pdu) >= 2 and (pdu[0] & 0x0F) in (0x02, 0x07):
                return StrippedPayload(
                    pdu=pdu, channel="NAS", direction=self._direction
                )

        # Fallback
        return StrippedPayload(
            pdu=payload[1:], channel="NAS", direction=self._direction
        )
