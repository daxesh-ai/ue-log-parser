"""Technology Transition Tracker — detects LTE ↔ NSA ↔ SA ↔ WiFi transitions.

Also tracks voice call state: VoNR, VoLTE, VoWiFi, EPSFB with handover detection.
Produces a session summary like: "VoNR → VoWiFi → VoNR (Successful)"
"""

from __future__ import annotations

from logparser.core.enums import Protocol
from logparser.core.message import ParsedMessage


class TechState:
    __slots__ = ("tech", "voice", "transition_reason")

    def __init__(self, tech: str = "Unknown", voice: str = "Idle", transition_reason: str = ""):
        self.tech = tech
        self.voice = voice
        self.transition_reason = transition_reason

    def __str__(self):
        parts = [self.tech]
        if self.voice != "Idle":
            parts.append(self.voice)
        return " | ".join(parts)


class VoiceEvent:
    """A voice call event (setup, handover, teardown)."""
    __slots__ = ("msg_index", "event_type", "voice_rat", "detail")

    def __init__(self, msg_index: int, event_type: str, voice_rat: str, detail: str = ""):
        self.msg_index = msg_index
        self.event_type = event_type  # "setup", "ho", "release", "fail"
        self.voice_rat = voice_rat    # "VoNR", "VoLTE", "VoWiFi", "EPSFB"
        self.detail = detail


class TechTransitionTracker:
    """Tracks RAT mode and voice call state across the message sequence."""

    def __init__(self):
        self._states: list[TechState] = []
        self._transitions: list[tuple[int, str, str]] = []
        self.voice_events: list[VoiceEvent] = []
        self.session_summary: str = ""

    @property
    def transitions(self) -> list[tuple[int, str, str]]:
        return self._transitions

    def build_states(self, messages: list[ParsedMessage]) -> None:
        """Compute tech state at each message index."""
        self._states = []
        self._transitions = []
        self.voice_events = []

        # Bootstrap initial tech state from the first few protocol types
        # A pure NR-RRC log is 5G NR by definition; a pure LTE-RRC log is LTE.
        initial_tech = "Unknown"
        has_nr_rrc = any(m.protocol == Protocol.NR_RRC for m in messages[:20])
        has_lte_rrc = any(m.protocol == Protocol.LTE_RRC for m in messages[:20])
        has_lte_nas = any(m.protocol == Protocol.LTE_NAS for m in messages[:20])
        has_nr_nas  = any(m.protocol == Protocol.NR_NAS  for m in messages[:20])

        if has_nr_rrc and not has_lte_rrc and not has_lte_nas:
            initial_tech = "5G NR"   # Pure NR log — NRDC, SA, or standalone NR
        elif has_lte_rrc and not has_nr_rrc:
            initial_tech = "LTE"     # Pure LTE log
        elif has_lte_rrc and has_nr_rrc:
            initial_tech = "5G NSA (EN-DC)"  # Mixed LTE+NR
        elif has_nr_nas and not has_lte_nas:
            initial_tech = "5G SA"
        elif has_lte_nas:
            initial_tech = "LTE"

        current = TechState(tech=initial_tech)
        voice_active = False
        voice_rat_history: list[str] = []
        call_success = False

        for msg in messages:
            prev_tech = current.tech
            prev_voice = current.voice
            current = self._detect(msg, current)
            self._states.append(TechState(current.tech, current.voice, current.transition_reason))

            # Track tech transitions (skip Unknown→X as those are bootstrap, not real HOs)
            if current.tech != prev_tech and prev_tech not in ("Unknown", ""):
                self._transitions.append((msg.index, prev_tech, current.tech))

            # Track voice events
            if current.voice != prev_voice:
                if current.voice != "Idle" and prev_voice == "Idle":
                    # Call started
                    voice_active = True
                    v_rat = self._get_voice_rat(current)
                    voice_rat_history = [v_rat]
                    self.voice_events.append(VoiceEvent(msg.index, "setup", v_rat, msg.summary))

                elif current.voice == "Idle" and prev_voice != "Idle":
                    # Call ended
                    voice_active = False
                    v_rat = self._get_voice_rat(current)
                    is_fail = "reject" in msg.summary.lower() or "fail" in msg.summary.lower()
                    self.voice_events.append(VoiceEvent(
                        msg.index, "fail" if is_fail else "release", v_rat, msg.summary
                    ))
                    call_success = not is_fail

                elif voice_active:
                    # Voice RAT changed during call = handover
                    v_rat = self._get_voice_rat(current)
                    if v_rat and voice_rat_history and v_rat != voice_rat_history[-1]:
                        voice_rat_history.append(v_rat)
                        self.voice_events.append(VoiceEvent(
                            msg.index, "ho", v_rat,
                            f"{voice_rat_history[-2]}→{v_rat}"
                        ))

            # Also detect voice HO from tech changes during active voice
            if voice_active and current.tech != prev_tech and prev_tech != "Unknown":
                v_rat = self._get_voice_rat(current)
                if v_rat and voice_rat_history and v_rat != voice_rat_history[-1]:
                    voice_rat_history.append(v_rat)
                    self.voice_events.append(VoiceEvent(
                        msg.index, "ho", v_rat,
                        f"{voice_rat_history[-2]}→{v_rat}"
                    ))

        # Build session summary
        self.session_summary = self._build_summary(voice_rat_history, call_success, voice_active)

    def get_state_at(self, index: int) -> TechState:
        if 0 <= index < len(self._states):
            return self._states[index]
        return TechState()


    def _build_summary(self, rat_history: list[str], success: bool, still_active: bool) -> str:
        """Build session summary string from voice events AND tech transitions."""
        # Also build from tech transitions (IMS access path changes)
        access_path = []
        for _, from_t, to_t in self._transitions:
            rat = self._tech_to_voice_rat(to_t)
            if rat and (not access_path or access_path[-1] != rat):
                access_path.append(rat)

        # Prefer the longer/more detailed path
        if rat_history:
            deduped = [rat_history[0]]
            for r in rat_history[1:]:
                if r != deduped[-1]:
                    deduped.append(r)
        else:
            deduped = []

        # Use whichever has more transitions
        path_list = access_path if len(access_path) > len(deduped) else deduped

        if not path_list:
            # Build from tech transitions alone
            if self._transitions:
                path_list = []
                for _, from_t, to_t in self._transitions:
                    r = self._tech_to_voice_rat(from_t)
                    if r and (not path_list or path_list[-1] != r):
                        path_list.append(r)
                    r = self._tech_to_voice_rat(to_t)
                    if r and (not path_list or path_list[-1] != r):
                        path_list.append(r)

        if not path_list:
            return "No voice session"

        path = " → ".join(path_list)

        if still_active:
            return f"Active: {path}"
        elif success or not rat_history:
            if len(path_list) > 1:
                return f"Multi-RAT session: {path}"
            else:
                return f"Successful voice: {path}"
        else:
            return f"Failed voice: {path}"

    @staticmethod
    def _tech_to_voice_rat(tech: str) -> str:
        """Convert tech string to voice RAT name."""
        if "WiFi" in tech or "ePDG" in tech:
            return "VoWiFi"
        elif "5G" in tech or "NR" in tech:
            return "VoNR"
        elif "LTE" in tech:
            return "VoLTE"
        elif "IMS" in tech:
            return "IMS"
        return ""

    def _get_voice_rat(self, state: TechState) -> str:
        """Determine voice RAT from current state."""
        tech = state.tech
        voice = state.voice

        if "WiFi" in tech:
            return "VoWiFi"
        elif "5G SA" in tech or "5G NSA" in tech or "NR" in tech:
            if "EPSFB" in voice or "EPSFB" in tech:
                return "EPSFB→VoLTE"
            return "VoNR"
        elif "LTE" in tech:
            if "EPSFB" in tech:
                return "EPSFB→VoLTE"
            return "VoLTE"
        elif "IMS" in voice or "Call" in voice:
            return "IMS"
        elif "VoNR" in voice:
            return "VoNR"
        elif "VoLTE" in voice:
            return "VoLTE"
        elif "VoWiFi" in voice:
            return "VoWiFi"
        return "IMS"

    def _detect(self, msg: ParsedMessage, prev: TechState) -> TechState:
        """Detect technology and voice state from a single message."""
        tech = prev.tech
        voice = prev.voice
        reason = ""

        summary_lower = msg.summary.lower()
        info_lower = msg.info.lower() if msg.info else ""
        channel = msg.channel.lower() if msg.channel else ""

        # --- SIP-based voice detection ---
        if channel == "sip" or "sip" in summary_lower:
            if "invite" in summary_lower and "method" not in summary_lower:
                voice = "Calling"
                if "WiFi" in tech or "ePDG" in tech:
                    voice = "VoWiFi"
                elif "5G" in tech or "NR" in tech:
                    voice = "VoNR"
                elif "LTE" in tech:
                    voice = "VoLTE"
                else:
                    voice = "IMS Call"  # Unknown RAT — just say IMS
                reason = "SIP INVITE"
            elif "bye" in summary_lower:
                voice = "Idle"
                reason = "SIP BYE (call ended)"
            elif "cancel" in summary_lower:
                voice = "Idle"
                reason = "SIP CANCEL"
            elif "183" in summary_lower or "180" in summary_lower:
                # Early media / ringing — call in progress
                if voice == "Calling":
                    pass  # Keep current voice state
            elif "200 ok" in summary_lower and "invite" in summary_lower:
                # Call connected
                if "VoNR" not in voice and "VoLTE" not in voice and "VoWiFi" not in voice:
                    if "5G" in tech:
                        voice = "VoNR"
                    elif "WiFi" in tech:
                        voice = "VoWiFi"
                    else:
                        voice = "VoLTE"
            elif "update" in summary_lower and voice != "Idle":
                # SIP UPDATE during call — possible media path switch (HO)
                reason = "SIP UPDATE (media switch)"

        # --- RRC-based tech detection ---
        elif msg.protocol == Protocol.NR_RRC:
            # Any NR RRC message confirms 5G is active — upgrade Unknown/LTE
            if tech in ("Unknown", "LTE"):
                tech = "5G NR"
                reason = "NR RRC message"
            if "rrcsetup" in summary_lower and "request" not in summary_lower:
                tech = "5G SA"
                reason = "NR RRC Setup"
            elif "rrcreconfiguration" in summary_lower:
                if "scell" in info_lower or "pscell" in info_lower:
                    if "NSA" in tech or "EN-DC" in tech:
                        pass  # Already NSA
                    elif "5G" not in tech:
                        tech = "5G NR"
                        reason = "NR CA/DC active"
            elif "rrcrelease" in summary_lower:
                if "deprioritised" in info_lower:
                    tech = "LTE (Depri)"
                    reason = "NR deprioritised"
                elif "redirect" in info_lower and ("lte" in info_lower or "b" in info_lower):
                    tech = "LTE (EPSFB)"
                    reason = "EPS Fallback"
                    if voice != "Idle":
                        voice = "EPSFB→VoLTE"

        elif msg.protocol == Protocol.LTE_RRC:
            if "rrcconnectionreconfiguration" in summary_lower:
                if msg.decoded_tree:
                    tree_str = str(msg.decoded_tree)[:2000]
                    if "nr-Config" in tree_str or "secondaryCellGroup" in tree_str:
                        tech = "5G NSA (EN-DC)"
                        reason = "SCG added via LTE"
                    elif tech == "Unknown":
                        tech = "LTE"
            elif "rrcconnectionsetup" in summary_lower:
                tech = "LTE"
                reason = "LTE RRC Setup"

        # --- NAS detection ---
        elif msg.protocol == Protocol.NR_NAS:
            if "registration" in summary_lower and "request" in summary_lower:
                tech = "5G SA"
                reason = "5G NAS Registration"

        elif msg.protocol == Protocol.LTE_NAS:
            if "attach" in summary_lower and "request" in summary_lower:
                tech = "LTE"
                reason = "LTE Attach"

        # --- S1AP detection (LTE radio is active) ---
        elif msg.protocol == Protocol.S1AP:
            if tech != "LTE" and "5G" not in tech:
                # S1AP means LTE radio is being used (even if 5G core)
                pass  # Don't override — could be 5G core with LTE radio (N26)
            if "handoverrequest" in summary_lower and "ack" not in summary_lower:
                reason = "S1AP Handover"
                if voice != "Idle":
                    reason = "Mid-call HO (S1AP)"
            elif "initialuemessage" in summary_lower or "initialcontextsetup" in summary_lower:
                # UE connecting to LTE
                if "NR" in tech and voice != "Idle":
                    tech = "LTE"
                    voice = "VoLTE"
                    reason = "HO to LTE (S1AP)"

        # --- WiFi detection ---
        if "wifi" in summary_lower or "iwlan" in summary_lower or "epdg" in summary_lower:
            tech = "WiFi"
            reason = "WiFi detected"
            if voice != "Idle" and "VoWiFi" not in voice:
                voice = "VoWiFi"
                reason = "HO to VoWiFi"

        # --- Core Network (PFCP/GTP) based RAT detection ---
        if channel == "pfcp" or channel == "gtp":
            decoded = msg.decoded_tree if msg.decoded_tree else {}
            src_ip = decoded.get("src", "") or decoded.get("Source", "")
            dst_ip = decoded.get("dst", "") or decoded.get("Destination", "")

            # Identify access type from PFCP endpoints
            is_wifi_path = "123:191" in src_ip or "123:192" in dst_ip
            is_nr_path = "137:191" in src_ip or "137:192" in dst_ip

            # PFCP Modification/Report on a path → that path is active
            if "modification" in summary_lower or "report" in summary_lower:
                if is_nr_path and tech == "Unknown":
                    tech = "5G NR"
                    reason = "NR session active"
                elif is_wifi_path and tech == "Unknown":
                    tech = "WiFi (ePDG)"
                    reason = "WiFi session active"

            if "session establishment" in summary_lower and "request" in summary_lower:
                if is_wifi_path:
                    if "WiFi" not in tech:
                        tech = "WiFi (ePDG)"
                        reason = "WiFi PDU Session Up"
                    if voice != "Idle":
                        voice = "VoWiFi"
                        reason = "HO → VoWiFi"
                elif is_nr_path:
                    if "NR" not in tech and "5G" not in tech:
                        tech = "5G NR"
                        reason = "NR PDU Session Up"
                    if voice != "Idle" and "VoNR" not in voice:
                        voice = "VoNR"
                        reason = "HO → VoNR"

            elif "session deletion" in summary_lower and "request" in summary_lower:
                if is_nr_path:
                    if voice != "Idle":
                        tech = "WiFi (ePDG)"
                        voice = "VoWiFi"
                        reason = "NR released → VoWiFi"
                    else:
                        tech = "WiFi (ePDG)" if "WiFi" in tech else tech
                        reason = "NR PDU Session Down"
                elif is_wifi_path:
                    if voice != "Idle":
                        tech = "5G NR"
                        voice = "VoNR"
                        reason = "WiFi released → VoNR"
                    else:
                        tech = "5G NR" if "NR" in tech or "5G" in tech else tech
                        reason = "WiFi PDU Session Down"

            elif "create session" in summary_lower:
                reason = "GTP Tunnel Created"

        # --- SIP REGISTER transitions (IMS access change) ---
        if channel == "sip" and "register" in summary_lower:
            if "remove" in summary_lower and "binding" in summary_lower:
                reason = "IMS Deregistering (access switch)"
            elif "1 binding" in summary_lower and "remove" not in summary_lower and "200" not in summary_lower:
                # Only change voice RAT if we KNOW the tech (from PFCP/RRC)
                if "WiFi" in tech or "ePDG" in tech:
                    reason = "IMS on WiFi"
                    if voice != "Idle":
                        voice = "VoWiFi"
                elif "NR" in tech or "5G" in tech:
                    reason = "IMS on NR"
                    if voice != "Idle":
                        voice = "VoNR"
                elif "LTE" in tech:
                    reason = "IMS on LTE"
                    if voice != "Idle":
                        voice = "VoLTE"
                # If tech is Unknown, don't guess the voice RAT

        return TechState(tech, voice, reason)
