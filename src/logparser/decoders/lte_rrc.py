"""LTE RRC decoder using pycrate (UPER encoding, TS 36.331)."""

from __future__ import annotations

from logparser.core.enums import Direction, Protocol
from .base import DecodeResult

_pdu_objects: dict | None = None


def _get_pdu_objects() -> dict:
    global _pdu_objects
    if _pdu_objects is None:
        from pycrate_asn1dir import RRCLTE
        _pdu_objects = {
            "DL-DCCH": RRCLTE.EUTRA_RRC_Definitions.DL_DCCH_Message,
            "UL-DCCH": RRCLTE.EUTRA_RRC_Definitions.UL_DCCH_Message,
            "DL-CCCH": RRCLTE.EUTRA_RRC_Definitions.DL_CCCH_Message,
            "UL-CCCH": RRCLTE.EUTRA_RRC_Definitions.UL_CCCH_Message,
            "BCCH-BCH": RRCLTE.EUTRA_RRC_Definitions.BCCH_BCH_Message,
            "BCCH-DL-SCH": RRCLTE.EUTRA_RRC_Definitions.BCCH_DL_SCH_Message,
            "PCCH": RRCLTE.EUTRA_RRC_Definitions.PCCH_Message,
            "MCCH": RRCLTE.EUTRA_RRC_Definitions.MCCH_Message,
        }
    return _pdu_objects


def _extract_message_type(val: dict | tuple) -> str:
    msg = val.get("message") if isinstance(val, dict) else None
    if not isinstance(msg, tuple) or len(msg) != 2:
        return "Unknown"
    choice_name, choice_val = msg
    if choice_name == "c1" and isinstance(choice_val, tuple) and len(choice_val) == 2:
        return choice_val[0]
    return choice_name


def _decode_nr_config_container(raw: bytes) -> dict | None:
    """Decode an embedded NR RRCReconfiguration or CellGroupConfig OCTET STRING.

    In EN-DC, LTE rrcConnectionReconfiguration carries an nr-Config-r15
    OCTET STRING that contains either a full NR RRCReconfiguration or
    a CellGroupConfig. Used for SCG addition and PSCell configuration.
    """
    if not raw or len(raw) < 4:
        return None
    try:
        from pycrate_asn1dir import RRCNR
        pdu = RRCNR.NR_RRC_Definitions.RRCReconfiguration
        pdu.from_uper(raw)
        val = pdu.get_val()
        if val and isinstance(val, dict) and "criticalExtensions" in str(val):
            return {"(decoded NR-RRCReconfiguration)": val}
    except Exception:
        pass

    try:
        from pycrate_asn1dir import RRCNR
        pdu = RRCNR.NR_RRC_Definitions.CellGroupConfig
        pdu.from_uper(raw)
        val = pdu.get_val()
        if val and isinstance(val, dict):
            return {"(decoded NR-CellGroupConfig)": val}
    except Exception:
        pass

    return None


def _find_nr_config(tree, depth: int = 0) -> bytes | None:
    """Recursively find the nr-Config OCTET STRING in a decoded LTE RRC tree."""
    if depth > 8:
        return None
    if isinstance(tree, dict):
        for key, val in tree.items():
            if "nr-Config" in key or "nr-SCG" in key:
                if isinstance(val, bytes):
                    return val
                elif isinstance(val, tuple) and len(val) == 2:
                    # CHOICE or setup: ('setup', b'...')
                    if isinstance(val[1], bytes):
                        return val[1]
                    result = _find_nr_config(val[1], depth + 1)
                    if result:
                        return result
            result = _find_nr_config(val, depth + 1)
            if result:
                return result
    elif isinstance(tree, tuple) and len(tree) == 2 and isinstance(tree[0], str):
        return _find_nr_config(tree[1], depth + 1)
    elif isinstance(tree, list):
        for item in tree[:3]:
            result = _find_nr_config(item, depth + 1)
            if result:
                return result
    return None


class LteRrcDecoder:
    """Decodes LTE RRC messages using pycrate UPER decoder."""

    _FALLBACK_CHANNELS = {
        "DL-DCCH": ["UL-DCCH", "DL-CCCH"],
        "UL-DCCH": ["DL-DCCH", "UL-CCCH"],
        "DL-CCCH": ["DL-DCCH"],
        "UL-CCCH": ["DL-CCCH", "UL-DCCH"],
    }

    def decode(
        self, pdu: bytes, channel: str, direction: Direction
    ) -> DecodeResult | None:
        if not pdu:
            return None

        pdus = _get_pdu_objects()
        channels_to_try = [channel] + self._FALLBACK_CHANNELS.get(channel, [])

        for ch in channels_to_try:
            pdu_obj = pdus.get(ch)
            if pdu_obj is None:
                continue

            try:
                pdu_obj.from_uper(pdu)
                val = pdu_obj.get_val()

                msg = val.get("message") if isinstance(val, dict) else None
                if isinstance(msg, tuple) and msg[0] == "messageClassExtension":
                    continue

                summary = _extract_message_type(val)

                # EN-DC: decode embedded NR config in rrcConnectionReconfiguration
                if "rrcConnectionReconfiguration" in summary and "Complete" not in summary:
                    nr_raw = _find_nr_config(val)
                    if nr_raw:
                        nr_decoded = _decode_nr_config_container(nr_raw)
                        if nr_decoded:
                            if isinstance(val, dict):
                                val = dict(val)
                                val["(EN-DC NR-Config)"] = nr_decoded
                            summary = "rrcConnectionReconfiguration [EN-DC]"

                try:
                    decoded_text = pdu_obj.to_asn1()
                except Exception:
                    decoded_text = str(val)

                actual_direction = direction
                if ch.startswith("UL"):
                    actual_direction = Direction.UL
                elif ch.startswith("DL") or ch.startswith("BCCH"):
                    actual_direction = Direction.DL

                source = "UE" if actual_direction == Direction.UL else "eNB"
                target = "eNB" if actual_direction == Direction.UL else "UE"

                return DecodeResult(
                    summary=summary,
                    decoded_tree=val,
                    decoded_text=decoded_text,
                    protocol=Protocol.LTE_RRC,
                    direction=actual_direction,
                    channel=ch,
                    source_entity=source,
                    target_entity=target,
                )
            except Exception:
                continue

        return None
