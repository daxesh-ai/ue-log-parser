"""NR RRC decoder using pycrate (UPER encoding, TS 38.331)."""

from __future__ import annotations

from logparser.core.enums import Direction, Protocol
from .base import DecodeResult

# Lazy-load pycrate to avoid import time cost
_pdu_objects: dict | None = None


def _get_pdu_objects() -> dict:
    global _pdu_objects
    if _pdu_objects is None:
        from pycrate_asn1dir import RRCNR
        _pdu_objects = {
            "DL-DCCH": RRCNR.NR_RRC_Definitions.DL_DCCH_Message,
            "UL-DCCH": RRCNR.NR_RRC_Definitions.UL_DCCH_Message,
            "DL-CCCH": RRCNR.NR_RRC_Definitions.DL_CCCH_Message,
            "UL-CCCH": RRCNR.NR_RRC_Definitions.UL_CCCH_Message,
            "UL-CCCH1": RRCNR.NR_RRC_Definitions.UL_CCCH1_Message,
            "BCCH-BCH": RRCNR.NR_RRC_Definitions.BCCH_BCH_Message,
            "BCCH-DL-SCH": RRCNR.NR_RRC_Definitions.BCCH_DL_SCH_Message,
            "PCCH": RRCNR.NR_RRC_Definitions.PCCH_Message,
        }
    return _pdu_objects


def _extract_message_type(val: dict | tuple) -> str:
    """Walk the decoded tree to find the RRC message type name."""
    msg = val.get("message") if isinstance(val, dict) else None
    if not isinstance(msg, tuple) or len(msg) != 2:
        return "Unknown"

    choice_name, choice_val = msg
    if choice_name == "c1" and isinstance(choice_val, tuple) and len(choice_val) == 2:
        msg_type = choice_val[0]
        # Extract additional info for important message types
        extra = _extract_extra_info(msg_type, choice_val[1])
        if extra:
            return f"{msg_type} [{extra}]"
        return msg_type
    elif choice_name == "messageClassExtension":
        return "messageClassExtension"
    return choice_name


def _extract_extra_info(msg_type: str, content) -> str:
    """Extract cause/reason from reject and release messages."""
    if not isinstance(content, dict):
        return ""

    ce = content.get("criticalExtensions")
    if not isinstance(ce, tuple) or len(ce) != 2:
        return ""

    _, inner = ce
    if not isinstance(inner, dict):
        return ""

    if msg_type == "rrcReject":
        wait_time = inner.get("waitTime")
        if wait_time is not None:
            return f"wait={wait_time}s"
        return "no wait"

    elif msg_type == "rrcRelease":
        # Check for redirected carrier info
        redirected = inner.get("redirectedCarrierInfo")
        if redirected and isinstance(redirected, tuple):
            return f"redirect→{redirected[0]}"
        deprioritisation = inner.get("deprioritisationReq")
        if deprioritisation:
            return "deprioritised"
        return ""

    elif msg_type == "rrcSetup":
        return ""

    elif msg_type == "securityModeCommand":
        sec_config = inner.get("securityConfigSMC")
        if isinstance(sec_config, dict):
            sec_algo = sec_config.get("securityAlgorithmConfig")
            if isinstance(sec_algo, dict):
                cipher = sec_algo.get("cipheringAlgorithm", "")
                integrity = sec_algo.get("integrityProtAlgorithm", "")
                return f"{cipher},{integrity}"
        return ""

    elif msg_type == "scgFailureInformation":
        # Extract failureType from FailureReportSCG
        failure_report = inner.get("failureReportSCG")
        if isinstance(failure_report, dict):
            failure_type = failure_report.get("failureType", "")
            return f"failureType={failure_type}"
        return "SCG-Failure"

    elif msg_type == "scgFailureInformationEUTRA":
        failure_report = inner.get("failureReportSCG-EUTRA")
        if isinstance(failure_report, dict):
            failure_type = failure_report.get("failureType", "")
            return f"EUTRA failureType={failure_type}"
        return "SCG-Failure-EUTRA"

    elif msg_type == "failureInformation":
        # MCG failure indication (NR-DC MCG failure reported to SN)
        failure_info = inner.get("failureInfoRLC-Bearer")
        if isinstance(failure_info, dict):
            cell_group = failure_info.get("cellGroupId", "?")
            lcid = failure_info.get("logicalChannelIdentity", "?")
            failure_type = failure_info.get("failureType", "?")
            return f"cellGroup={cell_group},LCID={lcid},{failure_type}"
        return ""

    elif msg_type == "mobilityFromNRCommand":
        # Inter-RAT HO: NR → LTE
        target_rat = inner.get("targetRAT-Type", "")
        return f"InterRAT→{target_rat}"

    return ""


def _decode_inner_containers(val):
    """Recursively decode OCTET STRING containers that hold nested ASN.1.

    Walks the decoded tree and replaces raw bytes with decoded sub-structures
    for known container types (UE-NR-Capability, UE-EUTRA-Capability, NAS PDUs).
    """
    if isinstance(val, dict):
        result = {}
        for key, v in val.items():
            if key == "ue-CapabilityRAT-Container" and isinstance(v, bytes):
                decoded = _try_decode_ue_capability(v, result.get("rat-Type"))
                result[key] = decoded if decoded else v
            elif key in ("dedicatedNAS-Message", "nas-MessageContainer") and isinstance(v, bytes):
                decoded = _try_decode_nas(v)
                result[key] = decoded if decoded else v
            elif key in ("masterCellGroup", "secondaryCellGroup") and isinstance(v, bytes):
                decoded = _try_decode_cell_group_config(v)
                result[key] = decoded if decoded else v
            elif key == "dedicatedNAS-MessageList" and isinstance(v, list):
                result[key] = [
                    _try_decode_nas(item) if isinstance(item, bytes) else _decode_inner_containers(item)
                    for item in v
                ]
            else:
                result[key] = _decode_inner_containers(v)
        return result
    elif isinstance(val, tuple):
        if len(val) == 2 and isinstance(val[0], str):
            return (val[0], _decode_inner_containers(val[1]))
        else:
            return val
    elif isinstance(val, list):
        return [_decode_inner_containers(item) for item in val]
    else:
        return val


def _try_decode_cell_group_config(raw: bytes) -> dict | None:
    """Try to decode CellGroupConfig OCTET STRING."""
    try:
        from pycrate_asn1dir import RRCNR
        pdu = RRCNR.NR_RRC_Definitions.CellGroupConfig
        pdu.from_uper(raw)
        decoded = pdu.get_val()
        # Recursively decode inner containers in the cell group
        return {"(decoded CellGroupConfig)": _decode_inner_containers(decoded)}
    except Exception:
        pass
    return None


def _try_decode_ue_capability(raw: bytes, rat_type=None) -> dict | None:
    """Try to decode UE capability container bytes."""
    try:
        from pycrate_asn1dir import RRCNR
        # Try NR capability first
        pdu = RRCNR.NR_RRC_Definitions.UE_NR_Capability
        pdu.from_uper(raw)
        decoded = pdu.get_val()
        return {"(decoded UE-NR-Capability)": _decode_inner_containers(decoded)}
    except Exception:
        pass

    try:
        from pycrate_asn1dir import RRCLTE
        # Try LTE capability
        pdu = RRCLTE.EUTRA_RRC_Definitions.UE_EUTRA_Capability
        pdu.from_uper(raw)
        decoded = pdu.get_val()
        return {"(decoded UE-EUTRA-Capability)": decoded}
    except Exception:
        pass

    # Try MRDC capability
    try:
        from pycrate_asn1dir import RRCNR
        pdu = RRCNR.NR_RRC_Definitions.UE_MRDC_Capability
        pdu.from_uper(raw)
        decoded = pdu.get_val()
        return {"(decoded UE-MRDC-Capability)": decoded}
    except Exception:
        pass

    return None


def _try_decode_nas(raw: bytes) -> dict | None:
    """Try to decode NAS PDU bytes embedded in RRC messages."""
    try:
        from pycrate_mobile.NAS5G import parse_NAS5G
        nas_msg, err = parse_NAS5G(raw, inner=True)
        if not err:
            import json
            return {"(decoded 5G-NAS)": json.loads(nas_msg.to_json())}
    except Exception:
        pass

    try:
        from pycrate_mobile.NASLTE import parse_NASLTE_MO
        nas_msg, err = parse_NASLTE_MO(raw, inner=True)
        if not err:
            import json
            return {"(decoded LTE-NAS)": json.loads(nas_msg.to_json())}
    except Exception:
        pass

    return None


def _extract_sib_types(val: dict | tuple) -> str:
    """For BCCH-DL-SCH messages, identify which SIBs are present."""
    msg = val.get("message") if isinstance(val, dict) else None
    if not isinstance(msg, tuple):
        return "SystemInformation"

    _, c1_val = msg
    if not isinstance(c1_val, tuple):
        return "SystemInformation"

    msg_type, content = c1_val
    if msg_type == "systemInformationBlockType1":
        return "SIB1"
    elif msg_type == "systemInformation":
        if isinstance(content, dict):
            ce = content.get("criticalExtensions")
            if isinstance(ce, tuple) and len(ce) == 2:
                _, si_content = ce
                if isinstance(si_content, dict):
                    sib_list = si_content.get("sib-TypeAndInfo", [])
                    sib_names = []
                    for item in sib_list:
                        if isinstance(item, tuple) and len(item) == 2:
                            sib_names.append(item[0])
                    if sib_names:
                        return "SI: " + ", ".join(sib_names)
        return "SystemInformation"
    return msg_type


class NrRrcDecoder:
    """Decodes NR RRC messages using pycrate UPER decoder."""

    # Priority order for trying channels when the provided channel fails
    _FALLBACK_CHANNELS = {
        "DL-DCCH": ["UL-DCCH", "DL-CCCH", "UL-CCCH"],
        "UL-DCCH": ["DL-DCCH", "UL-CCCH", "DL-CCCH"],
        "DL-CCCH": ["DL-DCCH", "UL-CCCH"],
        "UL-CCCH": ["UL-CCCH1", "DL-CCCH", "UL-DCCH"],
        "UL-CCCH1": ["UL-CCCH", "UL-DCCH"],
        "BCCH-BCH": ["BCCH-DL-SCH"],
        "BCCH-DL-SCH": ["BCCH-BCH", "DL-DCCH"],
        "PCCH": ["DL-CCCH"],
    }

    def decode(
        self, pdu: bytes, channel: str, direction: Direction
    ) -> DecodeResult | None:
        if not pdu:
            return None

        pdus = _get_pdu_objects()

        # Try the specified channel first, then fallbacks
        channels_to_try = [channel] + self._FALLBACK_CHANNELS.get(channel, [])

        for ch in channels_to_try:
            pdu_obj = pdus.get(ch)
            if pdu_obj is None:
                continue

            try:
                pdu_obj.from_uper(pdu)
                val = pdu_obj.get_val()

                # Validate: reject messageClassExtension (usually means wrong channel)
                msg = val.get("message") if isinstance(val, dict) else None
                if isinstance(msg, tuple) and msg[0] == "messageClassExtension":
                    continue

                # Validate: reject criticalExtensionsFuture (wrong channel)
                if isinstance(msg, tuple) and len(msg) == 2:
                    _, c1_val = msg
                    if isinstance(c1_val, tuple) and len(c1_val) == 2:
                        _, inner = c1_val
                        if isinstance(inner, dict):
                            ce = inner.get("criticalExtensions")
                            if isinstance(ce, tuple) and ce[0] == "criticalExtensionsFuture":
                                continue

                # Recursively decode inner containers (UE capabilities, NAS)
                val = _decode_inner_containers(val)

                # Determine message type
                if ch in ("BCCH-DL-SCH", "BCCH-BCH"):
                    summary = _extract_sib_types(val)
                else:
                    summary = _extract_message_type(val)


                # Get text representation
                try:
                    decoded_text = pdu_obj.to_asn1()
                except Exception:
                    decoded_text = str(val)

                # Direction from channel
                actual_direction = direction
                if ch.startswith("UL"):
                    actual_direction = Direction.UL
                elif ch.startswith("DL") or ch.startswith("BCCH") or ch.startswith("PCCH"):
                    actual_direction = Direction.DL

                source = "UE" if actual_direction == Direction.UL else "gNB"
                target = "gNB" if actual_direction == Direction.UL else "UE"

                # If decoded as 'spare', try r16/r17 standalone PDUs
                if summary.startswith("spare"):
                    r16_result = _try_r16_standalone(pdu, actual_direction)
                    if r16_result is not None:
                        return r16_result

                return DecodeResult(
                    summary=summary,
                    decoded_tree=val,
                    decoded_text=decoded_text,
                    protocol=Protocol.NR_RRC,
                    direction=actual_direction,
                    channel=ch,
                    source_entity=source,
                    target_entity=target,
                )
            except Exception:
                continue

        return None


# ── r16/r17 standalone PDU fallback ─────────────────────────────────────────

_R16_STANDALONE_PDUS: list[tuple[str, str, str]] = [
    # (summary_name, pycrate_class_name, direction: UL/DL/UNKNOWN)
    ("MCGFailureInformation", "MCGFailureInformation_r16", "UL"),
    ("SCGFailureInformation", "SCGFailureInformation", "UL"),
    ("SCGFailureInformationEUTRA", "SCGFailureInformationEUTRA", "UL"),
    ("ULDedicatedMessageSegment", "ULDedicatedMessageSegment_r16", "UL"),
    ("FailureInformation", "FailureInformation", "UL"),
]


def _try_r16_standalone(pdu: bytes, direction: "Direction") -> "DecodeResult | None":
    """Try decoding as an r16/r17 standalone PDU.

    Used as a second-pass when the channel-based decoder returns a 'spare' name,
    meaning the message type exists in pycrate as a standalone ASN.1 PDU but
    is not yet in the DL-DCCH/UL-DCCH c1 CHOICE schema.
    """
    try:
        from pycrate_asn1dir import RRCNR
    except ImportError:
        return None

    for summary, class_name, dir_hint in _R16_STANDALONE_PDUS:
        try:
            pdu_cls = getattr(RRCNR.NR_RRC_Definitions, class_name, None)
            if pdu_cls is None:
                continue
            pdu_cls.from_uper(pdu)
            val = pdu_cls.get_val()
            if not val:
                continue
            val = _decode_inner_containers(val)
            actual_dir = Direction.UL if dir_hint == "UL" else direction
            source = "UE" if actual_dir == Direction.UL else "gNB"
            target = "gNB" if actual_dir == Direction.UL else "UE"
            # Extract failure type if present for better summary
            failure_type = _find_failure_type(val)
            full_summary = f"{summary}" + (f" [{failure_type}]" if failure_type else "")
            try:
                decoded_text = pdu_cls.to_asn1()
            except Exception:
                decoded_text = str(val)
            return DecodeResult(
                summary=full_summary,
                decoded_tree=val,
                decoded_text=decoded_text,
                protocol=Protocol.NR_RRC,
                direction=actual_dir,
                channel="UL-DCCH",
                source_entity=source,
                target_entity=target,
            )
        except Exception:
            continue

    return None


def _find_failure_type(val) -> str:
    """Extract failureType from SCGFailureInformation / MCGFailureInformation."""
    if not isinstance(val, dict):
        return ""
    for key in ("failureReportSCG", "failureReportMCG-r16", "failureInfoRLC-Bearer"):
        report = val.get(key)
        if isinstance(report, dict):
            ft = report.get("failureType") or report.get("failureType-r16")
            if ft:
                return str(ft)
    # Nested search one level
    for v in val.values():
        if isinstance(v, dict):
            ft = v.get("failureType") or v.get("failureType-r16")
            if ft:
                return str(ft)
    return ""
