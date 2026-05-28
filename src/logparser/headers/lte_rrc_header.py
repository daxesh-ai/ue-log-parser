"""LTE RRC OTA sub-header stripper for log code 0xB0C0.

Supports multiple sub-header versions:

Version 27 (0x1B) — 21-byte header:
  Byte 0:      Version (0x1B = 27)
  Bytes 1-3:   Flags
  Bytes 4-5:   PCI (uint16 LE)
  Bytes 6-9:   EARFCN info
  Byte 10:     Direction / additional flags
  Bytes 11-13: SFN / cell info
  Byte 14:     Channel type
  Bytes 15-18: Reserved
  Bytes 19-20: PDU length (uint16 LE)
  Byte 21+:    ASN.1 PDU

Legacy versions (< 20) — 12-byte header:
  Byte 0:      Version
  Byte 1:      RRC release
  Byte 2:      Radio bearer ID
  Byte 3:      PCI
  Bytes 4-5:   EARFCN (uint16 LE)
  Bytes 6-7:   SFN (uint16 LE)
  Byte 8:      Channel type
  Byte 9:      Reserved
  Bytes 10-11: PDU length (uint16 LE)
  Byte 12+:    ASN.1 PDU
"""

from __future__ import annotations

import struct

from logparser.core.enums import Direction
from .base import StrippedPayload

# Channel type → (channel_name, direction)
_LTE_CHANNEL_MAP: dict[int, tuple[str, Direction]] = {
    1: ("UL-CCCH", Direction.UL),
    2: ("UL-DCCH", Direction.UL),
    3: ("DL-CCCH", Direction.DL),
    4: ("DL-DCCH", Direction.DL),
    5: ("BCCH-BCH", Direction.DL),
    6: ("BCCH-DL-SCH", Direction.DL),
    7: ("PCCH", Direction.DL),
    8: ("MCCH", Direction.DL),
    9: ("DL-DCCH", Direction.DL),
}


class LteRrcHeaderStripper:
    """Strips Qualcomm sub-headers from LTE RRC OTA (0xB0C0) payloads."""

    def strip(self, payload: bytes) -> StrippedPayload | None:
        if len(payload) < 13:
            return None

        version = payload[0]

        if version >= 25:
            return self._strip_v25plus(payload)
        elif version >= 20:
            return self._strip_v20(payload)
        else:
            return self._strip_legacy(payload)

    def _strip_v25plus(self, payload: bytes) -> StrippedPayload | None:
        """Version 25+: 21-byte header, uint16 PDU length at offset 19."""
        if len(payload) < 22:
            return None

        pdu_len = struct.unpack_from("<H", payload, 19)[0]
        header_size = 21

        if pdu_len == 0 or header_size + pdu_len > len(payload):
            return None

        pdu = payload[header_size : header_size + pdu_len]
        pci = struct.unpack_from("<H", payload, 4)[0]
        earfcn = struct.unpack_from("<H", payload, 8)[0]  # Approximate
        channel_byte = payload[14]

        channel, direction = _LTE_CHANNEL_MAP.get(
            channel_byte, ("DL-DCCH", Direction.DL)
        )

        return StrippedPayload(
            pdu=pdu,
            channel=channel,
            direction=direction,
            pci=pci,
            arfcn=earfcn,
        )

    def _strip_v20(self, payload: bytes) -> StrippedPayload | None:
        """Version 20-24: variable header, try common sizes."""
        # Try 21-byte header first (same as v25+)
        if len(payload) >= 22:
            pdu_len = struct.unpack_from("<H", payload, 19)[0]
            if pdu_len > 0 and 21 + pdu_len <= len(payload):
                pdu = payload[21 : 21 + pdu_len]
                channel_byte = payload[14] if len(payload) > 14 else 4
                channel, direction = _LTE_CHANNEL_MAP.get(
                    channel_byte, ("DL-DCCH", Direction.DL)
                )
                pci = struct.unpack_from("<H", payload, 4)[0]
                return StrippedPayload(
                    pdu=pdu, channel=channel, direction=direction, pci=pci,
                )

        # Fallback to legacy
        return self._strip_legacy(payload)

    def _strip_legacy(self, payload: bytes) -> StrippedPayload | None:
        """Legacy versions (< 20): 12-byte header."""
        if len(payload) < 13:
            return None

        pci = payload[3]
        earfcn = struct.unpack_from("<H", payload, 4)[0]
        sfn = struct.unpack_from("<H", payload, 6)[0]
        channel_byte = payload[8]
        pdu_len = struct.unpack_from("<H", payload, 10)[0]
        header_size = 12

        if pdu_len == 0 or header_size + pdu_len > len(payload):
            return None

        pdu = payload[header_size : header_size + pdu_len]

        channel, direction = _LTE_CHANNEL_MAP.get(
            channel_byte, ("DL-DCCH", Direction.DL)
        )

        return StrippedPayload(
            pdu=pdu,
            channel=channel,
            direction=direction,
            pci=pci,
            arfcn=earfcn,
            sfn=sfn,
        )
