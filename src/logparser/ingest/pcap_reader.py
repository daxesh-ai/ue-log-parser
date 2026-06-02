"""PCAP/PCAPNG reader — uses tshark subprocess for reliable protocol decoding.

Supports: NR RRC, LTE RRC, NAS, SIP, PFCP, S1AP, NGAP, GTP, Diameter.
"""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from logparser.core.enums import Direction, Protocol, Severity
from logparser.core.message import ParsedMessage
from logparser.core.session import LogSession

TSHARK_PATH = "/Applications/Wireshark.app/Contents/MacOS/tshark"


def is_pcap_file(filepath: Path) -> bool:
    """Check if file is PCAP or PCAPNG."""
    try:
        with open(filepath, "rb") as f:
            magic = f.read(4)
            return magic in (b"\x0a\x0d\x0d\x0a", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4")
    except OSError:
        return False


def load_pcap(filepath: Path, progress_callback=None) -> LogSession:
    """Load PCAP/PCAPNG using tshark and return a LogSession."""
    session = LogSession(filename=filepath.name)

    # Run tshark to get packet summaries + detailed fields
    result = subprocess.run(
        [
            TSHARK_PATH, "-r", str(filepath),
            "-T", "fields",
            "-e", "frame.number",        # 0
            "-e", "frame.time_epoch",    # 1
            "-e", "_ws.col.Protocol",    # 2
            "-e", "_ws.col.Info",        # 3
            "-e", "ip.src",              # 4
            "-e", "ip.dst",              # 5
            "-e", "ipv6.src",            # 6
            "-e", "ipv6.dst",            # 7
            "-e", "sip.from.user",       # 8
            "-e", "sip.to.user",         # 9
            "-e", "sip.Method",          # 10
            "-e", "sip.Status-Code",     # 11
            "-e", "sip.CSeq.method",     # 12
            "-e", "sdp.media",           # 13
            "-e", "pfcp.msg_type",       # 14
            "-e", "pfcp.cause",          # 15
            "-e", "gtpv2.message_type",  # 16
            "-e", "gtpv2.cause",         # 17
            "-e", "s1ap.procedureCode",  # 18
            "-e", "diameter.cmd.code",   # 19
            "-e", "sip.P-Access-Network-Info",  # 20
            "-e", "s1ap.e_RAB_ID",       # 21
            "-e", "s1ap.radioNetwork",   # 22
            "-e", "ngap.procedureCode",  # 23
            "-e", "ngap.Cause",          # 24
            "-E", "separator=\t",
            "-E", "quote=n",
            "-E", "occurrence=f",
        ],
        capture_output=True, text=True, timeout=120,
    )

    if result.returncode != 0:
        raise ValueError(f"tshark error: {result.stderr[:200]}")

    lines = result.stdout.strip().split("\n")
    messages = []

    telecom_protocols = {
        "NR-RRC", "LTE-RRC", "NAS-5GS", "NAS-EPS",
        "S1AP", "NGAP", "PFCP", "GTP", "GTPv2",
        "SIP", "SIP/SDP", "Diameter", "RTP", "RTCP",
        "GTP/SIP", "GTP/SIP/XML", "GTP/SIP/SDP",
    }

    for i, line in enumerate(lines):
        if not line.strip():
            continue

        parts = line.split("\t")
        if len(parts) < 4:
            continue

        def _get(idx):
            return parts[idx].strip() if idx < len(parts) else ""

        frame_num = _get(0)
        epoch = _get(1)
        proto_col = _get(2)
        info_col = _get(3)
        src = _get(4)
        dst = _get(5)
        ipv6_src = _get(6)
        ipv6_dst = _get(7)
        sip_from = _get(8)
        sip_to = _get(9)
        sip_method = _get(10)
        sip_status = _get(11)
        sip_cseq = _get(12)
        sdp_media = _get(13)
        pfcp_type = _get(14)
        pfcp_cause = _get(15)
        gtpv2_type = _get(16)
        gtpv2_cause = _get(17)
        s1ap_proc = _get(18)
        diameter_cmd = _get(19)
        p_access_net_info = _get(20)
        s1ap_erab_id = _get(21)
        s1ap_radio_cause = _get(22)
        ngap_proc = _get(23)
        ngap_cause = _get(24)

        # Use IPv6 if IPv4 not available
        if not src:
            src = ipv6_src
        if not dst:
            dst = ipv6_dst

        # Filter to telecom protocols only
        if not any(tp in proto_col for tp in telecom_protocols):
            continue

        # Parse timestamp
        try:
            ts = datetime.fromtimestamp(float(epoch), tz=timezone.utc)
        except (ValueError, OSError):
            continue

        # Map protocol
        protocol, channel, direction, source_entity, target_entity = _map_protocol(
            proto_col, info_col, src, dst
        )

        # Build decoded tree with all available fields
        decoded_tree = _build_decoded_tree(
            info_col, src or ipv6_src, dst or ipv6_dst, proto_col,
            sip_from, sip_to, sip_method, sip_status, sip_cseq, sdp_media,
            pfcp_type, pfcp_cause, gtpv2_type, gtpv2_cause, s1ap_proc, diameter_cmd,
            p_access_net_info,
        )

        # Build info field
        info = ""
        if "SIP" in proto_col or "SIP" in channel:
            info = _build_sip_info(sip_from, sip_to, sip_method, sip_status, sip_cseq, sdp_media, p_access_net_info)
        elif "PFCP" in proto_col:
            info = _build_pfcp_info(pfcp_type, pfcp_cause)
        elif "S1AP" in proto_col:
            info = _build_s1ap_info(s1ap_proc, info_col, s1ap_erab_id, s1ap_radio_cause)
        elif "NGAP" in proto_col:
            info = _build_ngap_info(ngap_proc, info_col, ngap_cause)
        elif "GTP" in proto_col and "SIP" not in proto_col:
            info = _build_gtp_info(gtpv2_type, gtpv2_cause)
        elif "Diameter" in proto_col:
            info = _build_diameter_info(diameter_cmd)

        msg = ParsedMessage(
            index=len(messages),
            timestamp=ts,
            protocol=protocol,
            direction=direction,
            channel=channel,
            summary=info_col[:100],
            raw_payload=b"",
            decoded_tree=decoded_tree,
            source_entity=source_entity,
            target_entity=target_entity,
            info=info,
        )
        messages.append(msg)

        if progress_callback and len(messages) % 50 == 0:
            progress_callback(len(messages), len(messages) + 100)

    session.messages = messages

    if progress_callback:
        progress_callback(len(messages), len(messages))

    return session


def _build_sip_info(sip_from: str, sip_to: str, method: str, status: str, cseq: str, sdp_media: str, p_access_net_info: str = "") -> str:
    """Build info string for SIP messages: caller → callee, media type, call type."""
    parts = []

    # Caller → Callee (phone numbers)
    caller = _format_phone(sip_from)
    callee = _format_phone(sip_to)
    if caller and callee and caller != callee:
        parts.append(f"{caller}→{callee}")
    elif caller:
        parts.append(caller)

    # Media type (voice, video, conference)
    if sdp_media:
        media_types = []
        if "audio" in sdp_media:
            media_types.append("Voice")
        if "video" in sdp_media:
            media_types.append("Video")
        if len(media_types) > 1:
            parts.append("Video+Voice")
        elif media_types:
            parts.append(media_types[0])

    # P-Access-Network-Info (RAT type for voice)
    if p_access_net_info:
        rat = _parse_access_network_info(p_access_net_info)
        if rat:
            parts.append(f"RAT:{rat}")

    # Response context (for status responses)
    if status and cseq and not method:
        parts.append(f"({cseq})")

    return " | ".join(parts)


_PFCP_MSG_TYPES = {
    "1": "Heartbeat Request", "2": "Heartbeat Response",
    "50": "Session Establishment Request", "51": "Session Establishment Response",
    "52": "Session Modification Request", "53": "Session Modification Response",
    "54": "Session Deletion Request", "55": "Session Deletion Response",
    "56": "Session Report Request", "57": "Session Report Response",
}

_PFCP_CAUSES = {"1": "Success", "2": "Rejected", "64": "No Established Session"}

_GTP_MSG_TYPES = {
    "1": "Echo Request", "2": "Echo Response",
    "32": "Create Session Request", "33": "Create Session Response",
    "34": "Modify Bearer Request", "35": "Modify Bearer Response",
    "36": "Delete Session Request", "37": "Delete Session Response",
    "95": "Create Bearer Request", "96": "Create Bearer Response",
    "97": "Update Bearer Request", "98": "Update Bearer Response",
    "99": "Delete Bearer Request", "100": "Delete Bearer Response",
}

_GTP_CAUSES = {"16": "Accepted", "64": "No Resources", "74": "Service Denied"}

_S1AP_PROCEDURES = {
    "0": "HandoverPreparation", "1": "HandoverResourceAllocation",
    "3": "HandoverNotification", "9": "InitialContextSetup",
    "17": "UEContextRelease", "23": "UEContextReleaseRequest",
    "12": "InitialUEMessage", "13": "DownlinkNASTransport",
    "14": "UplinkNASTransport", "22": "UECapabilityInfoIndication",
    "18": "CellTrafficTrace",
}

_DIAMETER_CMDS = {
    "265": "AA-Answer/Request (Rx)", "258": "Re-Auth",
    "272": "CC-Request/Answer", "274": "Abort-Session",
    "275": "Session-Termination", "271": "Accounting",
}


def _build_decoded_tree(info, src, dst, proto, sip_from, sip_to, sip_method,
                        sip_status, sip_cseq, sdp_media, pfcp_type, pfcp_cause,
                        gtpv2_type, gtpv2_cause, s1ap_proc, diameter_cmd,
                        p_access_net_info: str = "") -> dict:
    """Build a comprehensive decoded tree for the IE view."""
    tree = {}

    # Common fields
    if src:
        tree["Source"] = src
    if dst:
        tree["Destination"] = dst
    tree["Protocol"] = proto

    # SIP fields
    if sip_method or sip_status:
        sip = {}
        if sip_method:
            sip["Method"] = sip_method
        if sip_status:
            sip["Status-Code"] = sip_status
        if sip_from:
            sip["From"] = sip_from
        if sip_to:
            sip["To"] = sip_to
        if sip_cseq:
            sip["CSeq"] = sip_cseq
        if p_access_net_info:
            sip["P-Access-Network-Info"] = p_access_net_info
            rat = _parse_access_network_info(p_access_net_info)
            if rat:
                sip["Access-RAT"] = rat
        if sdp_media:
            sip["SDP-Media"] = sdp_media
            # Parse media type
            if "audio" in sdp_media:
                sip["Media-Type"] = "Voice (Audio)"
                # Extract codec info
                codecs = sdp_media.split("RTP/AVP")[-1].strip() if "RTP/AVP" in sdp_media else ""
                if codecs:
                    sip["Codecs (RTP Payload Types)"] = codecs
                # Extract port
                parts = sdp_media.split()
                if len(parts) >= 2:
                    sip["RTP-Port"] = parts[1]
        tree["SIP"] = sip

    # PFCP fields
    if pfcp_type:
        pfcp = {}
        pfcp["Message-Type"] = _PFCP_MSG_TYPES.get(pfcp_type, f"Type {pfcp_type}")
        if pfcp_cause:
            pfcp["Cause"] = _PFCP_CAUSES.get(pfcp_cause, f"Cause {pfcp_cause}")
        tree["PFCP"] = pfcp

    # GTPv2 fields
    if gtpv2_type:
        gtp = {}
        gtp["Message-Type"] = _GTP_MSG_TYPES.get(gtpv2_type, f"Type {gtpv2_type}")
        if gtpv2_cause:
            gtp["Cause"] = _GTP_CAUSES.get(gtpv2_cause, f"Cause {gtpv2_cause}")
        tree["GTPv2"] = gtp

    # S1AP fields
    if s1ap_proc:
        s1ap = {}
        s1ap["Procedure"] = _S1AP_PROCEDURES.get(s1ap_proc, f"Proc {s1ap_proc}")
        tree["S1AP"] = s1ap

    # Diameter fields
    if diameter_cmd:
        dia = {}
        dia["Command"] = _DIAMETER_CMDS.get(diameter_cmd, f"Cmd {diameter_cmd}")
        tree["Diameter"] = dia

    # Info summary
    tree["Info"] = info

    return tree


def _build_pfcp_info(pfcp_type: str, pfcp_cause: str) -> str:
    """Build info for PFCP messages."""
    msg_name = _PFCP_MSG_TYPES.get(pfcp_type, "")
    if pfcp_cause and pfcp_cause != "1":
        cause_name = _PFCP_CAUSES.get(pfcp_cause, f"Cause:{pfcp_cause}")
        return f"{cause_name}" if msg_name else ""
    return ""


_S1AP_RADIO_CAUSES = {
    "0": "unspecified",
    "1": "tx2relocoverall-expiry",
    "2": "successful-handover",
    "3": "release-due-to-eutran-generated-reason",
    "4": "handover-cancelled",
    "5": "partial-handover",
    "6": "ho-failure-in-target-EPC-eNB-or-target-system",
    "7": "ho-target-not-allowed",
    "8": "tS1relocoverall-expiry",
    "9": "tS1relocprep-expiry",
    "10": "cell-not-available",
    "11": "unknown-targetID",
    "14": "no-radio-resources-available-in-target-cell",
    "15": "unknown-mme-ue-s1ap-id",
    "16": "unknown-enb-ue-s1ap-id",
    "18": "failure-in-radio-interface-procedure",
    "20": "invalid-qos-combination",
    "21": "radio-connection-with-ue-lost",
    "24": "interaction-with-other-procedure",
    "36": "encryption-and-or-integrity-protection-algorithms-not-supported",
}


def _build_s1ap_info(s1ap_proc: str, info_col: str, erab_id: str = "", radio_cause: str = "") -> str:
    """Build info for S1AP messages with bearer and cause details."""
    parts = []

    # E-RAB ID
    if erab_id:
        # Map common E-RAB IDs to bearers
        erab_names = {"5": "Default-DRB", "6": "IMS-Signaling", "7": "VoLTE-QCI1"}
        name = erab_names.get(erab_id, f"EBI-{erab_id}")
        parts.append(f"Bearer:{name}(EBI={erab_id})")

    # Radio cause
    if radio_cause:
        cause_name = _S1AP_RADIO_CAUSES.get(radio_cause, f"cause-{radio_cause}")
        parts.append(f"Cause:{cause_name}")

    # Also try to extract from info column
    if not parts:
        if "cause=" in info_col.lower():
            cause_start = info_col.lower().index("cause=")
            cause = info_col[cause_start:].split("]")[0].split(",")[0]
            parts.append(cause.replace("cause=", "").strip())
        elif "cause" in info_col.lower():
            for part in info_col.split("["):
                if "cause" in part.lower():
                    parts.append(part.strip().rstrip("]"))
                    break

    return " | ".join(parts)


def _build_ngap_info(ngap_proc: str, info_col: str, ngap_cause: str = "") -> str:
    """Build info for NGAP messages."""
    parts = []
    if ngap_cause:
        parts.append(f"Cause:{ngap_cause}")
    # Extract from info column
    if not parts and "cause" in info_col.lower():
        for part in info_col.split("["):
            if "cause" in part.lower():
                parts.append(part.strip().rstrip("]"))
                break
    return " | ".join(parts)


def _build_gtp_info(gtpv2_type: str, gtpv2_cause: str) -> str:
    """Build info for GTP messages."""
    if gtpv2_cause:
        return _GTP_CAUSES.get(gtpv2_cause, f"Cause:{gtpv2_cause}")
    return ""


def _build_diameter_info(diameter_cmd: str) -> str:
    """Build info for Diameter messages."""
    return _DIAMETER_CMDS.get(diameter_cmd, "")


def _format_phone(number: str) -> str:
    """Format phone number for display."""
    if not number:
        return ""
    # Only format if it looks like a phone number (digits, +, -)
    clean = number.replace("+", "").replace("-", "").replace(" ", "")
    if not clean.isdigit():
        return ""
    if len(clean) == 11 and clean[0] == "1":
        # US number: +1-XXX-XXX-XXXX
        return f"+1-{clean[1:4]}-{clean[4:7]}-{clean[7:]}"
    elif len(clean) == 10:
        return f"{clean[:3]}-{clean[3:6]}-{clean[6:]}"
    elif len(clean) > 7:
        return f"+{clean}"
    return number


def _parse_access_network_info(p_ani: str) -> str:
    """Parse P-Access-Network-Info header to extract RAT type.

    Examples:
      "3GPP-NR; utran-cell-id-3gpp=..." → "NR"
      "3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=..." → "LTE"
      "IEEE-802.11; i-wlan-node-id=..." → "WiFi"
      "3GPP-NR-5G; ..." → "NR"
    """
    if not p_ani:
        return ""
    p_ani_lower = p_ani.lower()
    if "ieee-802.11" in p_ani_lower or "i-wlan" in p_ani_lower or "wifi" in p_ani_lower:
        return "WiFi"
    elif "3gpp-nr" in p_ani_lower or "nr-5g" in p_ani_lower or "ngran" in p_ani_lower:
        return "NR"
    elif "e-utran" in p_ani_lower or "eutran" in p_ani_lower:
        return "LTE"
    elif "utran" in p_ani_lower:
        return "UTRAN"
    return p_ani.split(";")[0].strip()


def _map_protocol(proto_col: str, info: str, src: str, dst: str):
    """Map tshark protocol column to our Protocol enum and determine entities."""
    info_lower = info.lower()
    protocol = Protocol.UNKNOWN
    channel = proto_col
    direction = Direction.UNKNOWN
    source_entity = src[-12:] if src else "?"
    target_entity = dst[-12:] if dst else "?"

    if "NR-RRC" in proto_col:
        protocol = Protocol.NR_RRC
        channel = "NR-RRC"
        if "UL" in info or "ul" in info:
            direction = Direction.UL
            source_entity = "UE"
            target_entity = "gNB"
        else:
            direction = Direction.DL
            source_entity = "gNB"
            target_entity = "UE"

    elif "LTE-RRC" in proto_col:
        protocol = Protocol.LTE_RRC
        channel = "LTE-RRC"
        if "UL" in info:
            direction = Direction.UL
            source_entity = "UE"
            target_entity = "eNB"
        else:
            direction = Direction.DL
            source_entity = "eNB"
            target_entity = "UE"

    elif "NAS-5GS" in proto_col or "nas-5gs" in proto_col:
        protocol = Protocol.NR_NAS
        channel = "5G-NAS"
        source_entity = "UE"
        target_entity = "AMF"

    elif "NAS-EPS" in proto_col or "nas-eps" in proto_col:
        protocol = Protocol.LTE_NAS
        channel = "LTE-NAS"
        source_entity = "UE"
        target_entity = "MME"

    elif "S1AP" in proto_col:
        protocol = Protocol.S1AP
        channel = "S1AP"
        source_entity = "eNB"
        target_entity = "MME"

    elif "NGAP" in proto_col:
        protocol = Protocol.NGAP
        channel = "NGAP"
        source_entity = "gNB"
        target_entity = "AMF"

    elif "SIP" in proto_col:
        protocol = Protocol.NR_NAS  # Reuse NAS slot for SIP/IMS
        channel = "SIP"
        if "request:" in info_lower or "invite" in info_lower or "register" in info_lower or "subscribe" in info_lower:
            source_entity = "UE"
            target_entity = "P-CSCF"
            direction = Direction.UL
        elif "status:" in info_lower:
            source_entity = "P-CSCF"
            target_entity = "UE"
            direction = Direction.DL
        else:
            source_entity = "P-CSCF"
            target_entity = "UE"
            direction = Direction.DL

    elif "RTP" in proto_col or "RTCP" in proto_col:
        protocol = Protocol.NR_NAS
        channel = "RTP"
        source_entity = "UE"
        target_entity = "IMS-MGW"
        direction = Direction.UL

    elif "PFCP" in proto_col:
        protocol = Protocol.NGAP  # Reuse for core network
        channel = "PFCP"
        source_entity = "SMF"
        target_entity = "UPF"
        if "response" in info_lower:
            source_entity = "UPF"
            target_entity = "SMF"

    elif "GTP" in proto_col:
        protocol = Protocol.NGAP
        channel = "GTP"
        source_entity = "gNB"
        target_entity = "UPF"

    elif "Diameter" in proto_col:
        protocol = Protocol.NGAP
        channel = "Diameter"
        source_entity = "AMF"
        target_entity = "HSS"

    return protocol, channel, direction, source_entity, target_entity
