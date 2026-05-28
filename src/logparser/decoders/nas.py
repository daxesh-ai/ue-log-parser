"""5G NAS and LTE NAS decoders using pycrate."""

from __future__ import annotations

import json

from logparser.core.enums import Direction, Protocol
from .base import DecodeResult


class NrNasDecoder:
    """Decodes 5G NAS messages (TS 24.501) using pycrate."""

    def decode(
        self, pdu: bytes, channel: str, direction: Direction
    ) -> DecodeResult | None:
        if not pdu or len(pdu) < 2:
            return None

        try:
            from pycrate_mobile.NAS5G import parse_NAS5G

            nas_msg, err = parse_NAS5G(pdu, inner=True)
            if err:
                return None

            summary = self._extract_type(nas_msg)
            decoded_text = nas_msg.show()

            try:
                decoded_tree = json.loads(nas_msg.to_json())
            except Exception:
                decoded_tree = {"raw": decoded_text}

            source = "UE" if direction == Direction.UL else "AMF"
            target = "AMF" if direction == Direction.UL else "UE"

            return DecodeResult(
                summary=summary,
                decoded_tree=decoded_tree,
                decoded_text=decoded_text,
                protocol=Protocol.NR_NAS,
                direction=direction,
                channel="5G-NAS",
                source_entity=source,
                target_entity=target,
            )
        except Exception:
            return None

    def _extract_type(self, nas_msg) -> str:
        try:
            # pycrate NAS messages have a _name attribute
            name = getattr(nas_msg, "_name", None)
            if name:
                return name
            # Try getting the message type from the header
            header = nas_msg.get("NAS5GMMHeader", None) or nas_msg.get("NAS5GSMHeader", None)
            if header:
                msg_type = header.get("Type", None)
                if msg_type:
                    return str(msg_type)
        except Exception:
            pass
        return "5G NAS"


class LteNasDecoder:
    """Decodes LTE NAS messages (TS 24.301) using pycrate."""

    def decode(
        self, pdu: bytes, channel: str, direction: Direction
    ) -> DecodeResult | None:
        if not pdu or len(pdu) < 2:
            return None

        try:
            from pycrate_mobile.NASLTE import parse_NASLTE_MO, parse_NASLTE_MT

            if direction == Direction.UL:
                nas_msg, err = parse_NASLTE_MO(pdu, inner=True)
            else:
                nas_msg, err = parse_NASLTE_MT(pdu, inner=True)

            if err:
                # Try the other direction
                if direction == Direction.UL:
                    nas_msg, err = parse_NASLTE_MT(pdu, inner=True)
                else:
                    nas_msg, err = parse_NASLTE_MO(pdu, inner=True)
                if err:
                    return None

            summary = self._extract_type(nas_msg)
            decoded_text = nas_msg.show()

            try:
                decoded_tree = json.loads(nas_msg.to_json())
            except Exception:
                decoded_tree = {"raw": decoded_text}

            source = "UE" if direction == Direction.UL else "MME"
            target = "MME" if direction == Direction.UL else "UE"

            return DecodeResult(
                summary=summary,
                decoded_tree=decoded_tree,
                decoded_text=decoded_text,
                protocol=Protocol.LTE_NAS,
                direction=direction,
                channel="LTE-NAS",
                source_entity=source,
                target_entity=target,
            )
        except Exception:
            return None

    def _extract_type(self, nas_msg) -> str:
        try:
            name = getattr(nas_msg, "_name", None)
            if name:
                return name
        except Exception:
            pass
        return "LTE NAS"
