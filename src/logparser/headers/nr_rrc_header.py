"""NR RRC OTA sub-header stripper for log code 0xB821.

Supports multiple sub-header versions:

Version 26 (0x1A) — 35-byte header:
  Bytes 0-8:   Version, flags, RB indicator, spec version
  Bytes 9-10:  PCI (uint16 LE)
  Bytes 11-16: Cell info
  Bytes 17-20: NR-ARFCN (uint32 LE)
  Bytes 21-24: SFN, channel type
  Bytes 25-28: Reserved
  Bytes 29-32: PDU length (uint32 LE)
  Bytes 33-34: Reserved
  Byte 35+:    ASN.1 PDU

Version 19 (0x13) — 32-byte header:
  Bytes 0-8:   Version, flags, RB indicator, spec version
  Bytes 9-10:  PCI (uint16 LE)
  Bytes 11-16: Cell info
  Bytes 17-20: NR-ARFCN (uint32 LE)
  Bytes 21-24: SFN, channel type
  Bytes 25-28: Reserved
  Bytes 29-30: PDU length (uint16 LE)
  Byte 31:     Reserved
  Byte 32+:    ASN.1 PDU
"""

from __future__ import annotations

import struct

from logparser.core.enums import Direction
from .base import StrippedPayload

# Channel type byte (24) → channel name mapping
_CHANNEL_MAP: dict[int, tuple[str, Direction]] = {
    1: ("UL-CCCH", Direction.UL),
    2: ("DL-DCCH", Direction.DL),
    3: ("DL-DCCH", Direction.DL),
    4: ("DL-DCCH", Direction.DL),
    5: ("BCCH-BCH", Direction.DL),
    6: ("BCCH-DL-SCH", Direction.DL),
    7: ("UL-DCCH", Direction.UL),
    8: ("UL-CCCH1", Direction.UL),
    9: ("DL-DCCH", Direction.DL),
    0x13: ("UL-DCCH", Direction.UL),
    0x14: ("DL-CCCH", Direction.DL),
    0x15: ("UL-CCCH", Direction.UL),
    0x16: ("DL-CCCH", Direction.DL),
}


class NrRrcHeaderStripper:
    """Strips Qualcomm sub-headers from NR RRC OTA (0xB821) payloads."""

    def strip(self, payload: bytes) -> StrippedPayload | None:
        if len(payload) < 32:
            return None

        version = payload[0]

        if version >= 0x1A:  # Version 26+
            return self._strip_v26(payload)
        elif version >= 0x13:  # Version 19-25
            return self._strip_v19(payload)
        else:
            # Try v19 format as fallback for unknown older versions
            return self._strip_v19(payload)

    def _strip_v26(self, payload: bytes) -> StrippedPayload | None:
        """Version 26+: 35-byte header, uint32 PDU length at offset 29."""
        if len(payload) < 36:
            return None

        pdu_len = struct.unpack_from("<I", payload, 29)[0]
        header_size = 35

        if pdu_len == 0 or header_size + pdu_len > len(payload):
            return None

        return self._build_result(payload, header_size, pdu_len)

    def _strip_v19(self, payload: bytes) -> StrippedPayload | None:
        """Version 19-25: 32-byte header, uint16 PDU length at offset 29."""
        if len(payload) < 33:
            return None

        pdu_len = struct.unpack_from("<H", payload, 29)[0]
        header_size = 32

        if pdu_len == 0 or header_size + pdu_len > len(payload):
            # Try with uint32 in case this is actually a newer version
            if len(payload) >= 36:
                pdu_len = struct.unpack_from("<I", payload, 29)[0]
                header_size = 35
                if pdu_len > 0 and header_size + pdu_len <= len(payload):
                    return self._build_result(payload, header_size, pdu_len)
            return None

        return self._build_result(payload, header_size, pdu_len)

    def _build_result(
        self, payload: bytes, header_size: int, pdu_len: int
    ) -> StrippedPayload:
        pdu = payload[header_size : header_size + pdu_len]

        # Extract metadata (common layout across versions)
        pci = struct.unpack_from("<H", payload, 9)[0]
        arfcn = struct.unpack_from("<I", payload, 17)[0]
        sfn = struct.unpack_from("<H", payload, 21)[0]
        channel_byte = payload[24]
        rb_indicator = payload[6]

        # Bearer ID: 0=SRB0, 1=SRB1, 2=SRB2, 3=SRB3, 0xFF→0
        bearer_id = rb_indicator if rb_indicator <= 3 else 0

        # Determine channel and direction
        if channel_byte in _CHANNEL_MAP:
            channel, direction = _CHANNEL_MAP[channel_byte]
        else:
            if rb_indicator == 2:
                channel, direction = "UL-DCCH", Direction.UL
            elif rb_indicator == 0xFF:
                channel, direction = "UL-CCCH", Direction.UL
            else:
                channel, direction = "DL-DCCH", Direction.DL

        return StrippedPayload(
            pdu=pdu,
            channel=channel,
            direction=direction,
            pci=pci,
            arfcn=arfcn,
            sfn=sfn,
            bearer_id=bearer_id,
        )
