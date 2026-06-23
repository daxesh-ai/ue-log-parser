"""Recommendations Engine — analyzes logs and provides 3GPP parameter recommendations.

Scans for:
- T300/T304/T310/T311 timer expiries
- RRC rejects and causes
- Handover failures (HO prep, HO exec)
- NAS registration/service failures
- SIP call failures (403, 486, 503)
- Voice RAT handover failures (VoNR↔VoWiFi incomplete)
- CA deactivation patterns
- Cell reselection issues

For each issue: identifies the problem, severity, count, and recommends
specific 3GPP parameters to tune (TTT, Hysteresis, QFI, T300 timer, etc.)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from logparser.core.enums import Protocol, Severity
from logparser.core.message import ParsedMessage
from logparser.core.session import LogSession


@dataclass
class Recommendation:
    """A single issue with recommended action."""
    rank: int
    category: str        # "RRC", "NAS", "HO", "Voice", "CA", "SIP"
    issue: str           # Short description
    severity: str        # "Critical", "Major", "Minor"
    count: int           # How many times seen
    msg_indices: list[int]  # Message indices where issue occurred
    root_cause: str      # Technical explanation
    recommendation: str  # 3GPP parameter to tune
    parameter: str       # Specific parameter name


def analyze_session(session: LogSession) -> list[Recommendation]:
    """Run all analyzers and return ranked recommendations."""
    recommendations: list[Recommendation] = []

    _check_t300_timeouts(session, recommendations)
    _check_t304_ho_failures(session, recommendations)
    _check_t310_rlf(session, recommendations)
    _check_rrc_rejects(session, recommendations)
    _check_rrc_releases(session, recommendations)
    _check_reestablishments(session, recommendations)
    _check_nas_failures(session, recommendations)
    _check_pcap_failures(session, recommendations)
    _check_sip_failures(session, recommendations)
    _check_voice_ho_failures(session, recommendations)
    _check_p_access_network_info(session, recommendations)
    _check_mcs_rsrp_mismatch(session, recommendations)
    _check_cqi_scell_failures(session, recommendations)
    _check_rlc_max_retx(session, recommendations)
    _check_harq_bler(session, recommendations)
    _check_scg_failures(session, recommendations)
    _check_b1_threshold_drops(session, recommendations)
    _check_ca_issues(session, recommendations)
    _check_deprioritisation(session, recommendations)
    _check_security_mode_failures(session, recommendations)
    _check_pci_mod3_conflicts(session, recommendations)
    _check_ul_power_limited(session, recommendations)
    _check_measurement_gap_missing(session, recommendations)
    _check_measurement_gaps(session, recommendations)

    # Optional: VoIP/Video QoE check
    _check_qoe_degradation(session, recommendations)

    # Optional: ML Anomaly Detection
    try:
        from logparser.analysis.ml_anomaly import ml_analyze_session
        recommendations.extend(ml_analyze_session(session))
    except (ImportError, Exception):
        pass  # scikit-learn not installed or model not trained

    # Optional: Field Reference Database comparison
    try:
        from logparser.analysis.field_reference import check_field_deviations
        recommendations.extend(check_field_deviations(session))
    except Exception:
        pass

    # Sort by severity then count
    severity_order = {"Critical": 0, "Major": 1, "Minor": 2}
    recommendations.sort(key=lambda r: (severity_order.get(r.severity, 3), -r.count))

    # Assign ranks
    for i, r in enumerate(recommendations):
        r.rank = i + 1

    return recommendations[:20]  # Top 20


def _check_t300_timeouts(session: LogSession, recs: list):
    """T300 timer expiry — RRC Setup not received after Request."""
    indices = []
    for msg in session.messages:
        if msg.severity == Severity.FAILURE and "T300" in " ".join(msg.annotations):
            indices.append(msg.index)

    if indices:
        recs.append(Recommendation(
            rank=0, category="RRC",
            issue=f"T300 Timeout — RRC Connection Setup Failure ({len(indices)}x)",
            severity="Critical" if len(indices) > 3 else "Major",
            count=len(indices),
            msg_indices=indices,
            root_cause=(
                "UE sent RRCSetupRequest but did not receive RRCSetup within T300 (2s). "
                "Indicates uplink coverage issue, RACH failure, or gNB congestion."
            ),
            recommendation=(
                "1. Check UL coverage (RSRP > -110dBm at cell edge)\n"
                "2. Increase RACH resources (msg1-FDM, preamble retries)\n"
                "3. If congestion: increase maxPUSCH-Resources or add capacity"
            ),
            parameter="T300, msg1-FrequencyStart, preambleTransMax",
        ))


def _check_t304_ho_failures(session: LogSession, recs: list):
    """T304 timer expiry — Handover execution failure.

    Detects:
    1. reconfigurationWithSync (PCell or PSCell change) NOT followed by Complete
    2. Reestablishment with cause=handoverFailure
    3. Annotations from the timer-based rules engine
    """
    timer_indices = []
    for msg in session.messages:
        if msg.severity == Severity.FAILURE and "T304" in " ".join(msg.annotations):
            timer_indices.append(msg.index)

    # Also detect HO failures structurally:
    # reconfigurationWithSync followed by reestablishment (no Complete in between)
    ho_starts = []
    for msg in session.messages:
        if msg.info and ("PCell:" in msg.info or "PSCell:" in msg.info):
            if "rrcReconfiguration" in msg.summary and "Complete" not in msg.summary:
                ho_starts.append(msg)

    structural_failures = []
    for ho_msg in ho_starts:
        # Look ahead for Complete or Reestablishment
        found_complete = False
        for future in session.messages[ho_msg.index + 1:ho_msg.index + 15]:
            if "ReconfigurationComplete" in future.summary:
                found_complete = True
                break
            if "reestablishment" in future.summary.lower() and "request" in future.summary.lower():
                if ho_msg.index not in timer_indices:
                    structural_failures.append(ho_msg.index)
                break

    all_indices = list(set(timer_indices + structural_failures))

    if all_indices:
        # Extract target PCI from the HO messages for better diagnostics
        target_info = ""
        for idx in all_indices[:3]:
            if idx < len(session.messages):
                msg = session.messages[idx]
                if msg.info and "PCI" in msg.info:
                    target_info = f" Target: {msg.info.split('|')[0].strip()}"
                    break

        recs.append(Recommendation(
            rank=0, category="HO",
            issue=f"T304 Timeout — Handover Execution Failure ({len(all_indices)}x)",
            severity="Critical",
            count=len(all_indices),
            msg_indices=all_indices,
            root_cause=(
                "UE received reconfigurationWithSync (HO command) but failed to "
                "synchronize to target cell within T304. Target cell may have poor "
                f"DL coverage or the RACH on target failed.{target_info}"
            ),
            recommendation=(
                "1. Verify target cell DL coverage at HO boundary\n"
                "2. Increase T304 timer (100ms → 200ms for Intra-NR, 500ms → 1000ms for PSCell)\n"
                "3. Adjust A3 offset/TTT to trigger HO earlier (reduce TTT by 40ms)\n"
                "4. Check if target PCI has pilot pollution (mod-3 conflict)\n"
                "5. Verify RACH config on target cell (preamble format, power ramp)"
            ),
            parameter="T304, timeToTrigger (TTT), a3-Offset, hysteresis, RACH-ConfigCommon",
        ))


def _check_t310_rlf(session: LogSession, recs: list):
    """T310 timer expiry — Radio Link Failure detection.

    T310 starts after N310 consecutive out-of-sync indications.
    If not recovered (N311 in-sync) before T310 expires → RLF → reestablishment.
    """
    indices = []
    for msg in session.messages:
        if msg.severity == Severity.FAILURE and "T310" in " ".join(msg.annotations):
            indices.append(msg.index)
        # Also detect from reestablishment cause
        elif ("reestablishment" in msg.summary.lower() and "request" in msg.summary.lower()
              and msg.info and "otherFailure" in msg.info):
            indices.append(msg.index)

    if indices:
        recs.append(Recommendation(
            rank=0, category="RRC",
            issue=f"T310 Expiry — Radio Link Failure ({len(indices)}x)",
            severity="Critical",
            count=len(indices),
            msg_indices=indices,
            root_cause=(
                "UE declared Radio Link Failure after T310 expiry (N310 consecutive "
                "out-of-sync indications without N311 recovery). Indicates sudden DL "
                "quality degradation — likely coverage hole or severe interference."
            ),
            recommendation=(
                "1. Increase T310 timer (1000ms → 2000ms) if transient fading\n"
                "2. Reduce N310 threshold (1 → 2) to be less aggressive on OOS detection\n"
                "3. Reduce TTT for A3 event to trigger HO before RLF\n"
                "4. Add missing neighbor cells if PCI in reestablishment is unknown\n"
                "5. Check for pilot pollution at RLF locations"
            ),
            parameter="T310, N310, N311, timeToTrigger, qRxLevMin",
        ))


def _check_mcs_rsrp_mismatch(session: LogSession, recs: list):
    """MCS drops while RSRP > -90dBm — indicates interference or scheduling issue.

    Uses real PHY/MAC data when available:
    - session.phy_measurements: actual per-carrier RSRP
    - session.mac_dl_samples: actual MCS per slot
    Falls back to RRC measurement report proxy if no PHY/MAC data.
    """
    import re

    # === Method 1: Real PHY + MAC correlation (preferred) ===
    phy_data = getattr(session, "phy_measurements", [])
    mac_data = getattr(session, "mac_dl_samples", [])

    if phy_data and mac_data:
        # Find time windows where RSRP > -90 but MCS drops to 0 (retransmission)
        # Build RSRP time windows
        strong_rsrp_times = []
        for m in phy_data:
            if m.rsrp_dbm > -90:
                strong_rsrp_times.append(m.timestamp)

        # Find MCS 0 events during strong RSRP
        mcs_drop_count = 0
        mcs_drop_during_strong = 0
        for sample in mac_data:
            if sample.mcs == 0:
                mcs_drop_count += 1
                # Check if any PHY measurement within ±1s shows RSRP > -90
                for phy in phy_data:
                    dt = abs((sample.timestamp - phy.timestamp).total_seconds())
                    if dt < 1.0 and phy.rsrp_dbm > -90:
                        mcs_drop_during_strong += 1
                        break

        if mcs_drop_during_strong > 10:
            # Find closest RRC message to report
            msg_indices = []
            for msg in session.messages[:5]:
                msg_indices.append(msg.index)

            recs.append(Recommendation(
                rank=0, category="RRC",
                issue=f"MCS Drop to 0 with RSRP > -90dBm ({mcs_drop_during_strong}x)",
                severity="Critical" if mcs_drop_during_strong > 50 else "Major",
                count=mcs_drop_during_strong,
                msg_indices=msg_indices,
                root_cause=(
                    f"MAC layer shows {mcs_drop_during_strong} MCS-0 slots (retransmissions) "
                    f"while PHY RSRP was above -90dBm. Total MCS-0 rate: "
                    f"{100*mcs_drop_count/max(1,len(mac_data)):.1f}%. "
                    "This confirms interference (low SINR despite good reference signal power)."
                ),
                recommendation=(
                    "1. Check SINR/CQI — RSRP is fine but SINR is degraded by interference\n"
                    "2. Enable IRC (Interference Rejection Combining) on gNB\n"
                    "3. Apply PCI mod-3 planning to reduce pilot pollution\n"
                    "4. Tighten CQI outer-loop (BLER target 1% → 0.1%)\n"
                    "5. Consider frequency-domain ICIC or CoMP for cell-edge UEs"
                ),
                parameter="SINR, CQI-offset, MCS-table, BLER-target, PCI-mod3, IRC-enable",
            ))
        return  # Don't fall through to proxy method

    # === Method 2: RRC measurement report proxy (no PHY/MAC data) ===
    strong_rsrp_indices = []
    recent_strong_rsrp = False
    strong_rsrp_msg_idx = None

    for msg in session.messages:
        if not msg.info:
            continue

        if "RSRP" in msg.info and "Serv" in msg.info:
            rsrp_matches = re.findall(r"RSRP(\d+)", msg.info)
            for rsrp_str in rsrp_matches:
                rsrp_index = int(rsrp_str)
                rsrp_dbm = rsrp_index - 156
                if rsrp_dbm > -90:
                    recent_strong_rsrp = True
                    strong_rsrp_msg_idx = msg.index
                else:
                    recent_strong_rsrp = False

        elif recent_strong_rsrp and (
            "reestablishment" in msg.summary.lower()
            or (msg.severity == Severity.FAILURE and "T310" in " ".join(msg.annotations))
        ):
            strong_rsrp_indices.append(strong_rsrp_msg_idx)
            recent_strong_rsrp = False

    if strong_rsrp_indices:
        recs.append(Recommendation(
            rank=0, category="RRC",
            issue=f"RLF/MCS Drop with Strong RSRP > -90dBm ({len(strong_rsrp_indices)}x)",
            severity="Critical",
            count=len(strong_rsrp_indices),
            msg_indices=strong_rsrp_indices,
            root_cause=(
                "Radio Link Failure or reestablishment occurred while serving cell RSRP "
                "was above -90dBm. This indicates interference (low SINR despite good RSRP)."
            ),
            recommendation=(
                "1. Check SINR/CQI at failure location\n"
                "2. Enable IRC (Interference Rejection Combining) on gNB\n"
                "3. Apply PCI planning / mod-3 optimization\n"
                "4. Increase CQI outer-loop offset (BLER target 1% → 0.1%)\n"
                "5. Consider ICIC or CoMP"
            ),
            parameter="SINR, CQI-offset, MCS-table, BLER-target, PCI-mod3, IRC-enable",
        ))


def _check_p_access_network_info(session: LogSession, recs: list):
    """P-Access-Network-Info RAT changes without successful VoWiFi→VoNR handover.

    Tracks P-Access-Network-Info changes in SIP messages. If RAT changes from
    WiFi to NR but the voice session fails (no 200 OK / BYE with failure), it
    indicates an incomplete eSRVCC / voice handover.
    """
    # Track P-Access-Network-Info transitions
    last_rat = None
    transition_indices = []
    transition_success = []
    pending_wifi_to_nr = False
    pending_idx = None

    for msg in session.messages:
        if not msg.decoded_tree or not isinstance(msg.decoded_tree, dict):
            continue

        sip_tree = msg.decoded_tree.get("SIP")
        if not isinstance(sip_tree, dict):
            continue

        access_rat = sip_tree.get("Access-RAT", "")
        if not access_rat:
            continue

        # Detect RAT change
        if last_rat and access_rat != last_rat:
            if last_rat == "WiFi" and access_rat == "NR":
                pending_wifi_to_nr = True
                pending_idx = msg.index
            elif last_rat == "WiFi" and access_rat == "LTE":
                pending_wifi_to_nr = True
                pending_idx = msg.index

        last_rat = access_rat

        # Check if transition resulted in failure (SIP failure code after RAT change)
        if pending_wifi_to_nr:
            status = sip_tree.get("Status-Code", "")
            if status and status.startswith(("4", "5", "6")):
                # Failed after RAT transition
                transition_indices.append(pending_idx)
                pending_wifi_to_nr = False
            elif status == "200":
                # Success
                pending_wifi_to_nr = False

    # Also check tech_tracker for VoWiFi→VoNR HO failures
    if hasattr(session, "tech_tracker"):
        tracker = session.tech_tracker
        for event in tracker.voice_events:
            if event.event_type == "fail" and "WiFi" in (event.detail or ""):
                if event.msg_index not in transition_indices:
                    transition_indices.append(event.msg_index)

    if transition_indices:
        recs.append(Recommendation(
            rank=0, category="Voice",
            issue=f"VoWiFi→VoNR Handover Failure ({len(transition_indices)}x)",
            severity="Critical",
            count=len(transition_indices),
            msg_indices=transition_indices,
            root_cause=(
                "P-Access-Network-Info changed from WiFi to NR/LTE but the voice "
                "session did not complete the handover successfully. The eSRVCC/DAPS "
                "procedure failed — voice call may have dropped during RAT transition. "
                "This typically occurs when N3IWF→AMF tunnel teardown races with "
                "target RAT bearer setup."
            ),
            recommendation=(
                "1. Increase VoWiFi-to-VoNR HO preparation timer (allow more setup time)\n"
                "2. Verify N3IWF/ePDG configuration for smooth tunnel migration\n"
                "3. Ensure QFI-1 (voice) bearer is established on target RAT before WiFi release\n"
                "4. Check SRNS relocation timer between source and target AMF\n"
                "5. If repeated: disable aggressive WiFi offload during active calls"
            ),
            parameter="QFI-1, N3IWF-reloc-timer, ePDG-handoff, VoWiFi-HO-guard-timer, SRNS-reloc",
        ))


def _check_harq_bler(session: LogSession, recs: list):
    """Detect high DL HARQ BLER from real ACK/NACK data (0xB896).

    BLER > 10% = Critical (significant retransmissions hurting throughput)
    BLER > 2%  = Major (above typical 1% outer-loop target)
    """
    harq_data = getattr(session, "harq_samples", [])
    if not harq_data:
        return

    total_ack = sum(s.ack_count for s in harq_data)
    total_nack = sum(s.nack_count for s in harq_data)
    total = total_ack + total_nack
    if total == 0:
        return

    bler = total_nack / total * 100.0

    if bler < 2.0:
        return  # Normal range, no recommendation needed

    severity = "Critical" if bler > 10.0 else "Major"
    msg_indices = [session.messages[0].index] if session.messages else []

    recs.append(Recommendation(
        rank=0, category="RRC",
        issue=f"High DL HARQ BLER: {bler:.1f}% ({total_nack:,} retx / {total:,} total)",
        severity=severity,
        count=total_nack,
        msg_indices=msg_indices,
        root_cause=(
            f"Real HARQ feedback shows {bler:.1f}% DL Block Error Rate "
            f"({total_nack:,} NACKs out of {total:,} TB transmissions). "
            f"Target is typically 1% (outer-loop BLER target). "
            f"{'Above 10% causes significant throughput loss (~1 retx per 10 TBs). ' if bler > 10 else ''}"
            f"Likely cause: low SINR due to interference or coverage edge."
        ),
        recommendation=(
            "1. Check SINR at failure locations — BLER correlates with SINR < 5dB\n"
            "2. Tighten CQI outer-loop (BLER target 1% → 0.1%) if scheduler allows\n"
            "3. Enable HARQ combining (chase combining or incremental redundancy)\n"
            "4. If BLER > 10%: check for interference (PCI mod-3 collision, pilot pollution)\n"
            "5. Verify max HARQ retransmissions (maxNrofHARQ-Processes setting)"
        ),
        parameter="PDSCH-BLER-target, CQI-offset, maxHARQ-Tx, SINR-threshold",
    ))


def _check_rlc_max_retx(session: LogSession, recs: list):
    """Detect rlc-MaxNumRetx events from RLC DL stats (0x1874).

    Correlates RLC max-retx events with SCG failure messages.
    """
    rlc_data = getattr(session, "rlc_dl_stats", [])
    if not rlc_data:
        return

    max_retx_events = [s for s in rlc_data if s.max_retx_reached]
    if not max_retx_events:
        return

    # Correlate with SCG failures
    scg_msgs = [m for m in session.messages if "scgfailure" in m.summary.lower()]
    correlated = 0
    msg_indices = []
    for evt in max_retx_events:
        for msg in scg_msgs:
            dt = abs((msg.timestamp - evt.timestamp).total_seconds())
            if dt < 2.0:
                correlated += 1
                msg_indices.append(msg.index)
                break

    total_events = len(max_retx_events)
    severity = "Critical" if correlated > 0 else "Major"

    recs.append(Recommendation(
        rank=0, category="HO",
        issue=f"RLC MaxNumRetx Reached ({total_events}x, {correlated} → SCG Failure)",
        severity=severity,
        count=total_events,
        msg_indices=msg_indices or [s.timestamp and 0 for s in max_retx_events[:1]],
        root_cause=(
            f"RLC layer exhausted maximum retransmissions (rlc-MaxNumRetx) {total_events} times. "
            f"{correlated} events were followed by SCG failure within 2 seconds. "
            "This indicates severe radio conditions on the SCG link — the UE cannot "
            "deliver packets despite multiple retries."
        ),
        recommendation=(
            "1. Check SCG link quality at failure locations (RSRP/SINR)\n"
            "2. Increase rlc-MaxRetxThreshold (4 → 8) for transient fading\n"
            "3. Trigger earlier SCG release when RLC retx rate is high\n"
            "4. If persistent: lower B1 threshold to avoid SCG add at coverage edge"
        ),
        parameter="rlc-MaxRetxThreshold, B1-Threshold-SCG, SCG-T310",
    ))


def _check_cqi_scell_failures(session: LogSession, recs: list):
    """Detect SCell activated by MAC-CE but CQI=0/low immediately after.

    Correlates MAC-CE SCell activation events with CQI samples within ±500ms.
    If CQI drops to 0 or stays at 1-2 after activation, the SCell is physically
    unreachable — the activation threshold is too aggressive.
    """
    cqi_data = getattr(session, "phy_cqi_samples", [])
    if not cqi_data:
        return

    # Find MAC-CE SCell activation messages
    scell_activations = [
        m for m in session.messages
        if m.channel == "MAC-CE" and "Activate" in m.summary and m.info
    ]
    if not scell_activations:
        return

    bad_activations = []
    for act_msg in scell_activations:
        t_act = act_msg.timestamp
        # Check CQI samples within 500ms after activation
        post_cqi = [
            s for s in cqi_data
            if 0 <= (s.timestamp - t_act).total_seconds() <= 0.5
        ]
        if post_cqi:
            min_cqi = min(s.cqi for s in post_cqi)
            if min_cqi <= 2:  # CQI 1-2 = extremely poor signal, ~QPSK 1/8
                bad_activations.append(act_msg.index)

    if bad_activations:
        recs.append(Recommendation(
            rank=0, category="CA",
            issue=f"SCell Activated with CQI ≤ 2 ({len(bad_activations)}x)",
            severity="Major",
            count=len(bad_activations),
            msg_indices=bad_activations,
            root_cause=(
                "MAC-CE SCell Activation was followed by CQI index ≤ 2 within 500ms, "
                "indicating the SCell signal quality is too poor to sustain the "
                "activation. The SCell activation RSRP/SINR threshold is too low — "
                "the scheduler is adding a carrier that the UE cannot use effectively."
            ),
            recommendation=(
                "1. Raise sCellActivation RSRP threshold (add hysteresis)\n"
                "2. Increase sCellDeactivationTimer to avoid rapid on/off cycling\n"
                "3. Check SCell antenna/beam alignment at problematic locations\n"
                "4. If CQI=0: the SCell is completely unreachable — check coverage"
            ),
            parameter="sCellActivationRSRP, sCellDeactivationTimer, CQI-threshold",
        ))


def _check_scg_failures(session: LogSession, recs: list):
    """SCG/MCG Failure detection for NR-DC and EN-DC.

    Detects:
    - SCGFailureInformation (UE reports SCG drop to MN)
    - MCGFailureInformation (UE reports MCG drop to SN, NR-DC r16+)
    - failureType: t310-Expiry, randomAccessProblem, rlc-MaxNumRetx,
                   srb3-IntegrityFailure (security key mismatch)
    - sk-Counter in reconfiguration (indicates key refresh)
    """
    scg_failure_indices = []
    mcg_failure_indices = []
    srb3_integrity_indices = []
    sk_counter_msgs = []

    for msg in session.messages:
        summary_lower = msg.summary.lower()
        info = msg.info or ""

        # SCGFailureInformation
        if "scgfailureinformation" in summary_lower:
            scg_failure_indices.append(msg.index)
            if "srb3" in info.lower() or "integrity" in info.lower():
                srb3_integrity_indices.append(msg.index)

        # MCGFailureInformation (r16)
        elif "mcgfailureinformation" in summary_lower:
            mcg_failure_indices.append(msg.index)

        # failureInformation (generic RLC bearer failure)
        elif "failureinformation" in summary_lower and "cellgroup" in (msg.info or "").lower():
            if "MCG" in info:
                mcg_failure_indices.append(msg.index)
            else:
                scg_failure_indices.append(msg.index)

        # Detect SRB3 messages (direct SN→UE signaling in NR-DC/EN-DC)
        if msg.bearer_id == 3:
            # SRB3 messages can carry SCGFailure, measurementReport (for SCG), etc.
            if "scgfailure" in summary_lower:
                scg_failure_indices.append(msg.index)
                if "srb3" in (msg.info or "").lower() or "integrity" in (msg.info or "").lower():
                    srb3_integrity_indices.append(msg.index)

        # Track sk-Counter in reconfigurations (key refresh indicator)
        if msg.decoded_tree and "rrcReconfiguration" in summary_lower:
            tree_str = str(msg.decoded_tree)
            if "sk-Counter" in tree_str or "sk_Counter" in tree_str:
                sk_counter_msgs.append(msg.index)

    # SCG Failure report
    if scg_failure_indices:
        has_srb3 = len(srb3_integrity_indices) > 0

        if has_srb3:
            recs.append(Recommendation(
                rank=0, category="HO",
                issue=f"SRB3 Integrity Failure — Security Key Mismatch ({len(srb3_integrity_indices)}x)",
                severity="Critical",
                count=len(srb3_integrity_indices),
                msg_indices=srb3_integrity_indices,
                root_cause=(
                    "UE reported SCG Failure with cause srb3-IntegrityFailure. This means "
                    "the Secondary gNB's security key (S-K_gNB) does not match what the UE "
                    "derived. The SRB3 integrity check failed — typically caused by sk-Counter "
                    "desync between MN and SN, or stale security context after handover."
                ),
                recommendation=(
                    "1. Check sk-Counter synchronization between MN and SN\n"
                    "2. Verify S-K_gNB derivation: MN must send correct sk-Counter in SN Addition\n"
                    "3. If after HO: ensure security context is refreshed (new sk-Counter)\n"
                    "4. Check X2/Xn interface for correct SecurityKey IE transfer\n"
                    "5. Consider enabling key refresh on every PSCell change"
                ),
                parameter="sk-Counter, S-K_gNB, SecurityKey IE, SRB3-Config",
            ))

        # General SCG failures (non-SRB3)
        non_srb3 = [i for i in scg_failure_indices if i not in srb3_integrity_indices]
        if non_srb3:
            recs.append(Recommendation(
                rank=0, category="HO",
                issue=f"SCG Failure — Secondary Node Drop ({len(non_srb3)}x)",
                severity="Critical" if len(non_srb3) > 3 else "Major",
                count=len(non_srb3),
                msg_indices=non_srb3,
                root_cause=(
                    "UE sent SCGFailureInformation to Master Node — the Secondary Cell Group "
                    "(PSCell/SCells on SN) experienced failure. Common causes: t310-Expiry "
                    "(SCG RLF), randomAccessProblem (RACH on PSCell failed), rlc-MaxNumRetx "
                    "(RLC layer exhausted retransmissions)."
                ),
                recommendation=(
                    "1. Check PSCell coverage at failure locations\n"
                    "2. If t310-Expiry: increase SCG T310 or improve SN coverage\n"
                    "3. If randomAccessProblem: tune SN RACH config (power ramp, retries)\n"
                    "4. If rlc-MaxNumRetx: check for high BLER on SCG bearers\n"
                    "5. Verify SN addition thresholds (B1 RSRP > -110dBm)"
                ),
                parameter="SCG-T310, SCG-RACH-Config, B1-Threshold, rlc-MaxRetx, PSCell-RSRP",
            ))

    # MCG Failure (NR-DC: secondary reports master dropped)
    if mcg_failure_indices:
        recs.append(Recommendation(
            rank=0, category="HO",
            issue=f"MCG Failure — Master Node Drop ({len(mcg_failure_indices)}x)",
            severity="Critical",
            count=len(mcg_failure_indices),
            msg_indices=mcg_failure_indices,
            root_cause=(
                "In NR-DC, the UE reported MCGFailureInformation via SRB3 to the Secondary "
                "Node — the Master Cell Group lost radio link. This is unique to NR-DC where "
                "SRB3 provides a backup signaling path. The MN's coverage failed while SN "
                "was still reachable."
            ),
            recommendation=(
                "1. Check MN (MCG) coverage at failure point\n"
                "2. Verify MCG T310/N310 timer settings\n"
                "3. If frequent: consider making the better-covered node the MN\n"
                "4. Enable fast MCG recovery via SRB3 (avoid full reestablishment)\n"
                "5. Check if MN RSRP was already below threshold before failure"
            ),
            parameter="MCG-T310, MCG-N310, SRB3-Config, MCG-RSRP-threshold",
        ))

    # sk-Counter observation (indicates key refreshes — not a failure but context)
    if len(sk_counter_msgs) > 3:
        recs.append(Recommendation(
            rank=0, category="HO",
            issue=f"Frequent sk-Counter Key Refresh ({len(sk_counter_msgs)}x)",
            severity="Minor",
            count=len(sk_counter_msgs),
            msg_indices=sk_counter_msgs[:10],
            root_cause=(
                f"sk-Counter was updated {len(sk_counter_msgs)} times, indicating frequent "
                "PSCell changes requiring security key derivation. Each sk-Counter increment "
                "triggers S-K_gNB re-derivation. If combined with SRB3 integrity failures, "
                "the key refresh mechanism may have a race condition."
            ),
            recommendation=(
                "1. This is informational — sk-Counter refresh is normal during PSCell changes\n"
                "2. If paired with srb3-IntegrityFailure: investigate MN/SN key sync\n"
                "3. High count suggests frequent PSCell mobility — tune SCG HO thresholds"
            ),
            parameter="sk-Counter, S-K_gNB, PSCell-change-threshold",
        ))


def _check_b1_threshold_drops(session: LogSession, recs: list):
    """Correlate 5G drops with weak B1 measurement reports.

    Uses real SSB/CSI-RS beam data (0xB884/0xB885) when available,
    otherwise falls back to RRC measurement report parsing.
    """
    import re

    # === Method 1: Use real beam measurements (preferred) ===
    beam_data = getattr(session, "phy_beam_samples", [])
    if beam_data:
        weak_beams = [b for b in beam_data if b.rsrp_dbm < -115]
        if weak_beams:
            # Check if any weak beam measurement is followed by SCG failure
            scg_failure_times = [
                m.timestamp for m in session.messages
                if "scgfailure" in m.summary.lower() or
                   ("reestablishment" in m.summary.lower() and "request" in m.summary.lower())
            ]
            weak_with_failure = []
            for beam in weak_beams:
                for t_fail in scg_failure_times:
                    if 0 <= (t_fail - beam.timestamp).total_seconds() <= 5.0:
                        weak_with_failure.append(beam)
                        break

            if weak_with_failure:
                msg_indices = [session.messages[0].index] if session.messages else []
                recs.append(Recommendation(
                    rank=0, category="HO",
                    issue=f"5G {weak_with_failure[0].source} at < -115dBm → Drop ({len(weak_with_failure)}x)",
                    severity="Critical",
                    count=len(weak_with_failure),
                    msg_indices=msg_indices,
                    root_cause=(
                        f"Real {weak_with_failure[0].source} beam measurements show "
                        f"neighbor cell RSRP below -115dBm, and SCG failure occurred "
                        f"within 5s. The B1 threshold is too low — NR is added at "
                        f"coverage edge with insufficient signal quality."
                    ),
                    recommendation=(
                        "1. Increase B1-Threshold-NR-RSRP to ≥ -110dBm\n"
                        "2. Add B1 hysteresis (2-3 dB)\n"
                        "3. Increase TTT for B1 (40ms → 160ms)\n"
                        "4. Consider RSRQ-based B1 in interference-limited areas"
                    ),
                    parameter="B1-Threshold-NR-RSRP, B1-Hysteresis, B1-TTT, A4-Threshold",
                ))
            return  # Don't fall through

    # === Method 2: RRC measurement report proxy ===
    # Find measurement reports with weak NR neighbor RSRP
    weak_b1_indices = []
    weak_rsrp_followed_by_failure = []

    for i, msg in enumerate(session.messages):
        if "measurementreport" not in msg.summary.lower():
            continue
        if not msg.info:
            continue

        # Check for weak neighbor RSRP in measurement report
        # RSRP index 0-127: dBm = index - 156, so -115dBm = index 41
        neigh_matches = re.findall(r"Neigh:PCI\d+\s*RSRP(\d+)", msg.info)
        for rsrp_str in neigh_matches:
            rsrp_index = int(rsrp_str)
            rsrp_dbm = rsrp_index - 156
            if rsrp_dbm < -115:
                weak_b1_indices.append(msg.index)
                # Check if followed by SCG failure or reestablishment within 10 msgs
                for future in session.messages[i + 1:i + 15]:
                    if ("scgfailure" in future.summary.lower() or
                        "reestablishment" in future.summary.lower() or
                        (future.severity == Severity.FAILURE and "T304" in " ".join(future.annotations))):
                        weak_rsrp_followed_by_failure.append(msg.index)
                        break
                break  # Only count once per message

    if weak_rsrp_followed_by_failure:
        recs.append(Recommendation(
            rank=0, category="HO",
            issue=f"5G Addition at Weak Signal < -115dBm → Drop ({len(weak_rsrp_followed_by_failure)}x)",
            severity="Critical",
            count=len(weak_rsrp_followed_by_failure),
            msg_indices=weak_rsrp_followed_by_failure,
            root_cause=(
                "NR measurement report showed neighbor NR cell RSRP below -115dBm, "
                "and the subsequent SCG addition/PSCell change failed. The Event B1 "
                "threshold is too low — UE is being directed to add an NR leg that "
                "doesn't have sufficient signal strength to sustain the connection."
            ),
            recommendation=(
                "1. Increase B1-Threshold-NR-RSRP (from current to ≥ -110dBm)\n"
                "2. Add hysteresis to B1 event (2-3 dB)\n"
                "3. Increase TTT for B1 event (40ms → 160ms)\n"
                "4. Consider RSRQ-based B1 in interference-limited areas\n"
                "5. If EN-DC: also verify A4 event threshold for SN release"
            ),
            parameter="B1-Threshold-NR-RSRP, B1-Hysteresis, B1-TTT, A4-Threshold",
        ))
    elif weak_b1_indices:
        recs.append(Recommendation(
            rank=0, category="HO",
            issue=f"NR Measurements Below -115dBm ({len(weak_b1_indices)}x)",
            severity="Minor",
            count=len(weak_b1_indices),
            msg_indices=weak_b1_indices[:10],
            root_cause=(
                "Measurement reports show NR neighbor cells with RSRP below -115dBm. "
                "While no immediate failure was correlated, these weak measurements "
                "indicate the UE is at NR coverage edge. Future SCG additions at these "
                "levels are risky."
            ),
            recommendation=(
                "1. Monitor for future SCG failures at these locations\n"
                "2. Consider raising B1-Threshold to avoid adding NR at coverage edge\n"
                "3. Verify NR cell coverage extends to where B1 reports trigger"
            ),
            parameter="B1-Threshold-NR-RSRP, NR-coverage-planning",
        ))


def _check_rrc_rejects(session: LogSession, recs: list):
    """RRC Setup Reject — network refusing connections."""
    indices = []
    for msg in session.messages:
        if "rrcReject" in msg.summary or "rrcConnectionReject" in msg.summary:
            indices.append(msg.index)

    if indices:
        recs.append(Recommendation(
            rank=0, category="RRC",
            issue=f"RRC Connection Rejected ({len(indices)}x)",
            severity="Critical" if len(indices) > 5 else "Major",
            count=len(indices),
            msg_indices=indices,
            root_cause=(
                "Network rejected RRC connection setup. Typical causes: "
                "congestion (no RRC resources), access barring, or load balancing."
            ),
            recommendation=(
                "1. Check cell congestion level (connected UE count vs capacity)\n"
                "2. Review Access Barring config (UAC/EAB parameters)\n"
                "3. If waitTime present: network is overloaded, add capacity\n"
                "4. Check if specific establishment causes are barred"
            ),
            parameter="waitTime, uac-BarringFactor, maxConnectedUEs",
        ))


def _check_rrc_releases(session: LogSession, recs: list):
    """RRC Release patterns — check for abnormal releases."""
    release_indices = []
    redirect_indices = []
    for msg in session.messages:
        if "rrcRelease" in msg.summary or "rrcConnectionRelease" in msg.summary:
            if "redirect" in msg.info.lower() if msg.info else False:
                redirect_indices.append(msg.index)
            else:
                release_indices.append(msg.index)

    if redirect_indices:
        recs.append(Recommendation(
            rank=0, category="RRC",
            issue=f"RRC Release with Redirection ({len(redirect_indices)}x)",
            severity="Minor",
            count=len(redirect_indices),
            msg_indices=redirect_indices,
            root_cause=(
                "Network released connection with frequency redirect. "
                "Could be load balancing, inter-RAT reselection, or EPSFB for voice."
            ),
            recommendation=(
                "1. If EPSFB: verify VoNR is properly configured\n"
                "2. If load balancing: check inter-freq measurement config\n"
                "3. Review cellReselectionPriority values"
            ),
            parameter="redirectedCarrierInfo, cellReselectionPriority",
        ))


def _check_reestablishments(session: LogSession, recs: list):
    """RRC Reestablishment — indicates Radio Link Failure (RLF)."""
    indices = []
    for msg in session.messages:
        if "reestablishment" in msg.summary.lower() and "request" in msg.summary.lower():
            indices.append(msg.index)

    if indices:
        recs.append(Recommendation(
            rank=0, category="RRC",
            issue=f"RRC Reestablishment (Radio Link Failure) ({len(indices)}x)",
            severity="Critical",
            count=len(indices),
            msg_indices=indices,
            root_cause=(
                "UE detected Radio Link Failure (T310 expiry after N310 out-of-sync). "
                "Indicates sudden DL quality drop — interference, mobility gap, or HO too late."
            ),
            recommendation=(
                "1. Check coverage at reestablishment locations\n"
                "2. Reduce TTT (timeToTrigger) for earlier HO\n"
                "3. Increase T310 timer or N310 threshold if transient\n"
                "4. Check for missing neighbor relations"
            ),
            parameter="T310, N310, N311, timeToTrigger, hysteresis",
        ))


def _check_pcap_failures(session: LogSession, recs: list):
    """Detect failures in PCAP-sourced messages (S1AP, NAS, GTP).

    Complements the RRC-focused rules by catching network-side events:
    - PDN connectivity / PDU Session rejects with ESM/EMM cause
    - EPS Fallback triggers (VoNR→VoLTE, 5G→EPS)
    - PLMN mismatch causing IMS PDN rejection
    - UEContextRelease due to radio failure (not user inactivity)
    """
    pdn_reject_indices = []
    pdn_reject_causes = []
    eps_fallback_indices = []
    plmn_mismatch_indices = []
    ue_release_failures = []

    for msg in session.messages:
        summary = msg.summary.lower()
        info = (msg.info or "").lower()
        annotations = " ".join(msg.annotations).lower()

        # PDN/PDU session rejects
        if "pdn connectivity reject" in summary or "pdu session reject" in summary:
            pdn_reject_indices.append(msg.index)
            # Extract ESM cause from info
            cause_info = msg.info or ""
            if cause_info:
                pdn_reject_causes.append(cause_info)
            elif "not subscribed" in summary:
                pdn_reject_causes.append("ESM #33 — Service not subscribed")
            elif "not authorized" in summary:
                pdn_reject_causes.append("ESM #35 — Not authorized")

        # EPS Fallback (VoNR → VoLTE / 5GS → EPS)
        if any(kw in summary for kw in [
            "ims-voice-eps-fallback", "rat-fallback", "fivegs-to-eps",
            "eps-fallback", "voice-eps-fallback",
        ]):
            eps_fallback_indices.append(msg.index)

        # PLMN mismatch — detected if "PLMN not allowed" or "not authorized" in NAS reject
        if ("plmn not allowed" in summary or "plmn not allowed" in info or
                "plmn not allowed" in annotations or "plmn mismatch" in info):
            plmn_mismatch_indices.append(msg.index)

        # UE context release due to radio failure (not normal)
        if "uecontextrelease" in summary.replace(" ", "").lower():
            if any(kw in summary for kw in [
                "radio-connection-with-ue-lost", "failure-in-radio",
                "handover-failure",
            ]):
                ue_release_failures.append(msg.index)

    # PDN reject recommendation
    if pdn_reject_indices:
        cause_str = "; ".join(set(pdn_reject_causes)) if pdn_reject_causes else "unknown ESM cause"
        recs.append(Recommendation(
            rank=0, category="NAS",
            issue=f"PDN/PDU Session Rejected ({len(pdn_reject_indices)}x) — {cause_str}",
            severity="Critical",
            count=len(pdn_reject_indices),
            msg_indices=pdn_reject_indices,
            root_cause=(
                f"Network rejected PDN Connectivity / PDU Session Request. "
                f"Cause: {cause_str}. "
                f"This prevents the UE from establishing or continuing data connectivity. "
                f"Common causes: subscription mismatch, APN not provisioned, PLMN policy."
            ),
            recommendation=(
                "1. Check UE subscription in HSS/UDM for requested APN\n"
                "2. Verify PLMN/HPLMN policy allows this APN in visited network\n"
                "3. Check PDN type (IPv4/IPv6/IPv4v6) matches subscription\n"
                "4. For IMS APN: verify IMS subscription is provisioned\n"
                "5. TS 23.502 §4.13.3.1: MME must honor HPLMN IMS context on fallback"
            ),
            parameter="APN-config, IMS-subscription, PLMN-policy, ESM-cause",
        ))

    # EPS Fallback recommendation
    if eps_fallback_indices:
        recs.append(Recommendation(
            rank=0, category="Voice",
            issue=f"EPS Fallback Triggered ({len(eps_fallback_indices)}x) — VoNR→VoLTE",
            severity="Major",
            count=len(eps_fallback_indices),
            msg_indices=eps_fallback_indices,
            root_cause=(
                "VoNR call triggered EPS Fallback — the 5G network could not support "
                "IMS voice and redirected the UE to LTE (4G) for voice service. "
                "This indicates either: VoNR not provisioned/capable at this cell, "
                "or PLMN policy forces CSFB for specific subscription types."
            ),
            recommendation=(
                "1. Verify VoNR capability at the serving gNB\n"
                "2. Check UE IMS registration in 5G context before fallback\n"
                "3. Verify 5QI-1 bearer was offered before fallback trigger\n"
                "4. Check eMSC/5GC interworking configuration\n"
                "5. If PLMN mismatch: see HPLMN policy for roaming IMS"
            ),
            parameter="VoNR-config, 5QI-1, eMSC-interwork, EPS-fallback-policy",
        ))

    # PLMN mismatch
    if plmn_mismatch_indices:
        recs.append(Recommendation(
            rank=0, category="NAS",
            issue=f"PLMN Mismatch — Visited PLMN Not Allowed ({len(plmn_mismatch_indices)}x)",
            severity="Critical",
            count=len(plmn_mismatch_indices),
            msg_indices=plmn_mismatch_indices,
            root_cause=(
                "Network rejected request due to PLMN mismatch between UE's "
                "HPLMN (home network) and the serving/visited PLMN. "
                "Subscription policy 'Visited PLMN not allowed' may be blocking "
                "IMS/data PDN continuation during inter-PLMN handover."
            ),
            recommendation=(
                "1. Check roaming agreement between HPLMN and VPLMN\n"
                "2. Verify MME is using correct HPLMN from 5GC context (TS 23.502)\n"
                "3. Check subscriber profile: allowed PLMNs list in HSS/UDM\n"
                "4. For EPS Fallback: MME must preserve HPLMN from 5G context"
            ),
            parameter="HPLMN-policy, roaming-agreement, HSS-PLMN-list",
        ))

    # UE context release failures
    if ue_release_failures:
        recs.append(Recommendation(
            rank=0, category="HO",
            issue=f"UE Context Released — Radio Failure ({len(ue_release_failures)}x)",
            severity="Major",
            count=len(ue_release_failures),
            msg_indices=ue_release_failures,
            root_cause=(
                "S1AP UEContextRelease triggered by radio layer failure "
                "(radio-connection-with-ue-lost or handover-failure). "
                "UE dropped from the network due to radio link problem."
            ),
            recommendation=(
                "1. Check DL coverage at UE location\n"
                "2. Verify HO preparation was successful before execution\n"
                "3. Check T310 timer and N310 threshold configuration\n"
                "4. Review neighbor cell list for missing cells"
            ),
            parameter="T310, N310, HO-preparation, coverage",
        ))


def _check_nas_failures(session: LogSession, recs: list):
    """NAS registration/service rejects."""
    indices = []
    for msg in session.messages:
        summary_lower = msg.summary.lower()
        if ("registrationreject" in summary_lower or "servicereject" in summary_lower or
                "attachreject" in summary_lower or "registration reject" in summary_lower):
            indices.append(msg.index)

    if indices:
        recs.append(Recommendation(
            rank=0, category="NAS",
            issue=f"NAS Registration/Service Reject ({len(indices)}x)",
            severity="Critical",
            count=len(indices),
            msg_indices=indices,
            root_cause=(
                "Core network rejected registration or service request. "
                "Check 5GMM cause value for specific reason (e.g., #5 IMEI not accepted, "
                "#11 PLMN not allowed, #22 congestion)."
            ),
            recommendation=(
                "1. Check 5GMM/EMM cause code in the reject message\n"
                "2. If cause #22 (congestion): scale AMF/MME capacity\n"
                "3. If cause #11 (PLMN): verify roaming agreements\n"
                "4. If repeated: check subscriber provisioning in UDM/HSS"
            ),
            parameter="5GMM-Cause, T3510, T3511",
        ))


def _check_sip_failures(session: LogSession, recs: list):
    """SIP call setup failures (4xx/5xx responses)."""
    failure_indices = []
    for msg in session.messages:
        if msg.severity == Severity.FAILURE and msg.channel == "SIP":
            failure_indices.append(msg.index)

    if failure_indices:
        recs.append(Recommendation(
            rank=0, category="Voice",
            issue=f"SIP Call Failure ({len(failure_indices)}x)",
            severity="Critical" if len(failure_indices) > 2 else "Major",
            count=len(failure_indices),
            msg_indices=failure_indices,
            root_cause=(
                "IMS call signaling failure detected (4xx/5xx SIP response). "
                "403=Forbidden (auth), 486=Busy, 503=Service Unavailable. "
                "Check P-CSCF/S-CSCF connectivity and IMS registration status."
            ),
            recommendation=(
                "1. Check IMS registration status before call attempt\n"
                "2. If 403: verify IPSec SA between UE and P-CSCF\n"
                "3. If 503: check IMS core capacity (S-CSCF, TAS)\n"
                "4. Verify dedicated QoS bearer (QCI-1/5QI-1) is established"
            ),
            parameter="QCI-1, 5QI-1, P-CSCF-Address, IMS-Registration-Timer",
        ))


def _check_voice_ho_failures(session: LogSession, recs: list):
    """Voice handover failures (incomplete VoNR↔VoWiFi transitions)."""
    if not hasattr(session, "tech_tracker"):
        return

    tracker = session.tech_tracker
    # Check for transitions that are followed quickly by failures
    for event in tracker.voice_events:
        if event.event_type == "fail":
            recs.append(Recommendation(
                rank=0, category="Voice",
                issue="Voice Call Failure During RAT Transition",
                severity="Critical",
                count=1,
                msg_indices=[event.msg_index],
                root_cause=(
                    f"Voice session failed during or after RAT transition ({event.detail}). "
                    "The SRVC (Single Radio Voice Call Continuity) or eSRVCC procedure did not complete."
                ),
                recommendation=(
                    "1. Verify eSRVCC/SRVCC is configured between source and target\n"
                    "2. Check N26 interface between AMF and MME for inter-RAT\n"
                    "3. For VoWiFi↔VoNR: verify ePDG/N3IWF tunnel setup time\n"
                    "4. Ensure QFI-1 bearer is maintained during transition"
                ),
                parameter="eSRVCC, N26-interface, QFI, VoWiFi-to-VoNR-timer",
            ))
            break


def _check_ca_issues(session: LogSession, recs: list):
    """CA activation/deactivation and SCell addition failures."""
    # Track SCell additions and check for subsequent failures
    scell_add_indices = []
    scell_add_followed_by_failure = []

    reconfigs = [m for m in session.messages if "rrcReconfiguration" in m.summary and "Complete" not in m.summary]
    completes = {m.index for m in session.messages if "ReconfigurationComplete" in m.summary}

    for msg in session.messages:
        if msg.info and "SCell" in msg.info and "PCI" in msg.info:
            scell_add_indices.append(msg.index)

            # Check if this SCell addition was followed by Complete
            # Look for Complete within next 5 messages
            has_complete = False
            for future_msg in session.messages[msg.index:msg.index + 10]:
                if future_msg.index in completes:
                    has_complete = True
                    break
                if "Failure" in future_msg.summary or "reestablishment" in future_msg.summary.lower():
                    scell_add_followed_by_failure.append(msg.index)
                    break

    # SCell addition failure
    if scell_add_followed_by_failure:
        recs.append(Recommendation(
            rank=0, category="CA",
            issue=f"SCell Addition Failure ({len(scell_add_followed_by_failure)}x)",
            severity="Critical",
            count=len(scell_add_followed_by_failure),
            msg_indices=scell_add_followed_by_failure,
            root_cause=(
                "RRCReconfiguration with sCellToAddModList was followed by "
                "RRCReconfigurationFailure or RRC Reestablishment. The UE could not "
                "activate the configured SCell — likely unsupported band combination, "
                "RF front-end conflict, or timing advance issue."
            ),
            recommendation=(
                "1. Verify UE supported CA band combinations (UE-MRDC-Capability)\n"
                "2. Check for RF front-end conflicts (e.g., n77 + n258 sharing)\n"
                "3. Increase sCellDeactivationTimer to avoid premature removal\n"
                "4. Verify Timing Advance Group (TAG) assignment for SCell\n"
                "5. Check SCell RSRP meets sCellActivationThreshold"
            ),
            parameter="sCellToAddModList, CA-BandCombination, TAG, sCellDeactivationTimer",
        ))

    # No CA at all despite many reconfigs
    if not scell_add_indices and len(reconfigs) > 5:
        recs.append(Recommendation(
            rank=0, category="CA",
            issue="No CA Activation Observed",
            severity="Minor",
            count=1,
            msg_indices=[reconfigs[0].index],
            root_cause=(
                "Multiple RRC Reconfigurations but no SCell additions detected. "
                "UE may not be getting CA despite being in a CA-capable cell."
            ),
            recommendation=(
                "1. Verify UE CA band combination capability\n"
                "2. Check sCellToAddModList is being sent by gNB\n"
                "3. Review scheduler CA activation thresholds\n"
                "4. Check if SCell deactivation timer is too aggressive"
            ),
            parameter="sCellDeactivationTimer, CA-BandCombination, sCellIndex",
        ))

    # Frequent SCell re-additions (ping-pong)
    if len(scell_add_indices) > 6:
        recs.append(Recommendation(
            rank=0, category="CA",
            issue=f"Frequent SCell Re-Addition ({len(scell_add_indices)}x)",
            severity="Major",
            count=len(scell_add_indices),
            msg_indices=scell_add_indices[:10],
            root_cause=(
                f"SCell was added {len(scell_add_indices)} times, suggesting repeated "
                "activation/deactivation cycles. The sCellDeactivationTimer may be too "
                "short, or the SCell signal is fluctuating around the activation threshold."
            ),
            recommendation=(
                "1. Increase sCellDeactivationTimer (e.g., 320ms → 640ms or infinity)\n"
                "2. Add hysteresis to SCell activation RSRP threshold\n"
                "3. Check SCell signal stability at cell edge\n"
                "4. Review if CQI-based deactivation is too aggressive"
            ),
            parameter="sCellDeactivationTimer, sCellActivation-RSRP-threshold, CQI-threshold",
        ))


def _check_deprioritisation(session: LogSession, recs: list):
    """NR deprioritisation patterns."""
    indices = []
    for msg in session.messages:
        if "deprioritised" in msg.summary.lower() or "deprioritised" in (msg.info or "").lower():
            indices.append(msg.index)

    if indices:
        recs.append(Recommendation(
            rank=0, category="RRC",
            issue=f"NR Deprioritisation ({len(indices)}x)",
            severity="Major",
            count=len(indices),
            msg_indices=indices,
            root_cause=(
                "Network deprioritised NR frequency, forcing UE to LTE for the timer duration. "
                "Indicates NR cell congestion or coverage issue at that location."
            ),
            recommendation=(
                "1. Check NR cell load at deprioritisation time\n"
                "2. If coverage: extend NR coverage or adjust B1 threshold\n"
                "3. Review deprioritisationTimer value (currently forcing LTE for N minutes)\n"
                "4. Consider disabling deprioritisation if causing service impact"
            ),
            parameter="deprioritisationTimer, B1-Threshold-NR, interFreqReselection",
        ))


def _check_security_mode_failures(session: LogSession, recs: list):
    """Security mode failures."""
    indices = []
    for msg in session.messages:
        if "securitymodefailure" in msg.summary.lower():
            indices.append(msg.index)

    if indices:
        recs.append(Recommendation(
            rank=0, category="NAS",
            issue=f"Security Mode Failure ({len(indices)}x)",
            severity="Major",
            count=len(indices),
            msg_indices=indices,
            root_cause=(
                "UE rejected the security mode command. Could be algorithm mismatch "
                "or integrity check failure. Prevents encrypted communication."
            ),
            recommendation=(
                "1. Verify supported ciphering algorithms match (NEA0/1/2/3)\n"
                "2. Check integrity algorithms (NIA1/2/3)\n"
                "3. If after HO: possible security context mismatch\n"
                "4. Review UE capability for algorithm support"
            ),
            parameter="cipheringAlgorithm, integrityProtAlgorithm, SecurityAlgorithmConfig",
        ))


def _check_ul_power_limited(session: LogSession, recs: list):
    """Detect UE uplink power-limited scenarios.

    When Pcmax is low (power class restriction) or UL MCS drops while
    DL RSRP is still good, the UE may be at cell edge for uplink only.
    Also flags if FR2 Pcmax < 20 dBm (unexpected for Power Class 3).
    """
    ul_power = getattr(session, "ul_power_config", [])
    mac_ul = getattr(session, "mac_ul_samples", [])

    if not ul_power:
        return

    # Check for FR2 Pcmax=0 (mmWave module off) or FR1 significantly below 23
    low_power_events = [p for p in ul_power if p.pcmax_fr2_dbm == 0 or p.pcmax_fr1_dbm < 15]

    # Check for UL MCS degradation (MCS 0 = max power, retransmission)
    ul_mcs0_count = sum(1 for s in mac_ul if s.mcs == 0)
    ul_total = len(mac_ul)
    ul_mcs0_pct = (ul_mcs0_count / max(1, ul_total)) * 100

    # Combine: if low Pcmax + high UL MCS-0 → power limited
    if low_power_events:
        recs.append(Recommendation(
            rank=0, category="RRC",
            issue=f"UL Power Restricted — Pcmax below normal ({len(low_power_events)}x)",
            severity="Major",
            count=len(low_power_events),
            msg_indices=[session.messages[0].index] if session.messages else [],
            root_cause=(
                f"UL power control config shows Pcmax below normal levels "
                f"(FR1: {ul_power[0].pcmax_fr1_dbm} dBm, FR2: {ul_power[0].pcmax_fr2_dbm} dBm). "
                f"Normal Power Class 3: FR1=23 dBm, FR2=20 dBm. "
                f"Low Pcmax reduces UL coverage radius and causes UL throughput drops."
            ),
            recommendation=(
                "1. Check SAR (Specific Absorption Rate) restrictions — hand/head proximity reduces Pcmax\n"
                "2. Verify P-Max from SIB1 is not artificially limiting UE power\n"
                "3. Check for thermal throttling reducing max Tx power\n"
                "4. If FR2 Pcmax < 20: antenna module may be disabled (thermal/grip)"
            ),
            parameter="Pcmax, P-Max-SIB1, SAR-backoff, thermalMitigation",
        ))
    elif ul_mcs0_pct > 15 and ul_total > 100:
        recs.append(Recommendation(
            rank=0, category="RRC",
            issue=f"UL Quality Degradation — {ul_mcs0_pct:.1f}% UL MCS-0",
            severity="Major" if ul_mcs0_pct > 30 else "Minor",
            count=ul_mcs0_count,
            msg_indices=[session.messages[0].index] if session.messages else [],
            root_cause=(
                f"UL MAC shows {ul_mcs0_pct:.1f}% MCS-0 transmissions ({ul_mcs0_count:,}/{ul_total:,}). "
                f"While Pcmax appears normal ({ul_power[0].pcmax_fr1_dbm}/{ul_power[0].pcmax_fr2_dbm} dBm), "
                f"the high UL error rate suggests the UE is at uplink coverage edge "
                f"or experiencing UL interference."
            ),
            recommendation=(
                "1. Check UL SINR at gNB receiver — UE signal may be drowned by interference\n"
                "2. Verify TPC (Transmit Power Control) is converging — check power ramp\n"
                "3. If at cell edge: reduce UL BLER target or add UL coverage solutions\n"
                "4. Check for UL pilot pollution from neighboring cells"
            ),
            parameter="UL-BLER-target, TPC-accumulation, P0-PUSCH, alpha",
        ))


def _check_pci_mod3_conflicts(session: LogSession, recs: list):
    """Detect PCI mod-3 conflicts between serving and neighbor cells.

    When serving PCI % 3 == neighbor PCI % 3, the PSS (Primary Sync Signal)
    sequences are identical, causing reference signal interference.
    This degrades CQI/SINR without reducing RSRP — a key interference pattern.
    """
    import re

    serving_pcis: set[int] = set()
    neighbor_pcis: set[int] = set()

    for msg in session.messages:
        if not msg.info:
            continue
        # Serving cells: PCell/PSCell/SCell with PCI in info field
        if any(x in msg.info for x in ("PCell:", "PSCell:", "SCell")):
            for pci_str in re.findall(r"PCI:?(\d+)", msg.info):
                serving_pcis.add(int(pci_str))
        # Neighbors from measurement reports
        if "Neigh:PCI" in msg.info:
            for pci_str in re.findall(r"Neigh:PCI(\d+)", msg.info):
                neighbor_pcis.add(int(pci_str))

    # Also extract from SSB beam measurements
    beam_data = getattr(session, "phy_beam_samples", [])
    for b in beam_data:
        if b.pci not in serving_pcis:
            neighbor_pcis.add(b.pci)

    # Check mod-3 conflicts
    conflicts = []
    for s_pci in serving_pcis:
        for n_pci in neighbor_pcis:
            if s_pci != n_pci and s_pci % 3 == n_pci % 3:
                conflicts.append((s_pci, n_pci))

    if conflicts:
        unique_n = set(c[1] for c in conflicts)
        recs.append(Recommendation(
            rank=0, category="RRC",
            issue=f"PCI Mod-3 Conflict ({len(unique_n)} neighbor(s) with same PSS sequence)",
            severity="Major" if len(unique_n) > 2 else "Minor",
            count=len(unique_n),
            msg_indices=[session.messages[0].index] if session.messages else [],
            root_cause=(
                f"Detected {len(unique_n)} neighbor cells with PCI mod-3 == serving PCI mod-3. "
                f"Conflicts: {[(s, n) for s, n in conflicts[:5]]}. "
                f"When PCI % 3 matches, the PSS (Primary Sync Signal) is identical, "
                f"causing reference signal interference and SINR degradation even at good RSRP."
            ),
            recommendation=(
                "1. Verify PCI assignment plan (ensure mod-3 separation between neighbors)\n"
                "2. If SINR issues observed: PCI mod-3 collision is the likely root cause\n"
                "3. Request PCI replan from network engineering team\n"
                "4. Check if the conflicting neighbor is a co-located sector (same site = expected)"
            ),
            parameter="PCI-plan, mod-3-separation, PSS-sequence-assignment",
        ))


def _check_qoe_degradation(session: LogSession, recs: list):
    """Check VoIP/Video QoE metrics for quality degradation."""
    qoe = getattr(session, "qoe_metrics", [])
    if not qoe:
        return

    for call in qoe:
        # VoIP MOS degradation
        if call.mos_score > 0 and call.mos_score < 3.5:
            severity = "Critical" if call.mos_score < 2.5 else "Major"
            recs.append(Recommendation(
                rank=0, category="QoE",
                issue=f"VoIP MOS {call.mos_score:.1f} — Quality Degradation ({call.codec})",
                severity=severity,
                count=1,
                msg_indices=[session.messages[0].index] if session.messages else [],
                root_cause=(
                    f"Voice call quality below acceptable threshold. "
                    f"MOS={call.mos_score:.1f} (threshold=3.5). "
                    f"Codec={call.codec}, Jitter={call.jitter_ms:.1f}ms, "
                    f"Loss={call.packet_loss_pct:.1f}%, Duration={call.duration_sec:.0f}s."
                ),
                recommendation=(
                    "1. Check radio link quality during the call (RSRP/SINR)\n"
                    "2. If jitter high: check MAC scheduler prioritization for QCI-1\n"
                    "3. If loss high: check RLC AM mode for voice bearer\n"
                    "4. Verify dedicated QoS bearer (5QI=1) was established"
                ),
                parameter="5QI-1, PDCP-config, jitter-buffer, codec-rate",
            ))

        # Video freeze detection
        if call.freeze_events > 0:
            severity = "Critical" if call.freeze_duration_sec > 5.0 else "Major"
            recs.append(Recommendation(
                rank=0, category="QoE",
                issue=f"Video Freeze Detected ({call.freeze_events}x, {call.freeze_duration_sec:.1f}s total)",
                severity=severity,
                count=call.freeze_events,
                msg_indices=[session.messages[0].index] if session.messages else [],
                root_cause=(
                    f"Video stream experienced {call.freeze_events} freeze events "
                    f"(total {call.freeze_duration_sec:.1f}s). Max gap: {call.max_gap_ms:.0f}ms. "
                    f"Codec: {call.codec}. This indicates packet loss bursts or "
                    f"sustained throughput drops below video bitrate requirement."
                ),
                recommendation=(
                    "1. Check DL throughput during freeze periods\n"
                    "2. Verify QoS bearer for video (5QI=2 or 5QI=7)\n"
                    "3. If during HO: check HO interruption time\n"
                    "4. Check TCP/UDP buffer at application layer"
                ),
                parameter="5QI-2, DL-throughput, HO-interruption-time",
            ))

        # High packet loss (even if MOS is still acceptable)
        if call.packet_loss_pct > 5.0:
            recs.append(Recommendation(
                rank=0, category="QoE",
                issue=f"High RTP Packet Loss: {call.packet_loss_pct:.1f}% ({call.codec})",
                severity="Major",
                count=1,
                msg_indices=[session.messages[0].index] if session.messages else [],
                root_cause=(
                    f"RTP stream (SSRC={call.ssrc:#x}) has {call.packet_loss_pct:.1f}% "
                    f"packet loss over {call.duration_sec:.0f}s. "
                    f"This exceeds the 1-2% threshold for acceptable voice/video quality."
                ),
                recommendation=(
                    "1. Check HARQ BLER during the call period\n"
                    "2. Verify RLC mode (AM with retransmission for voice)\n"
                    "3. Check for handover-related packet loss\n"
                    "4. Monitor PDCP discard timer configuration"
                ),
                parameter="RLC-mode, PDCP-discardTimer, HARQ-maxRetx",
            ))


def _check_measurement_gap_missing(session: LogSession, recs: list):
    """Detect inter-frequency measurement objects configured without a measurement gap.

    In NR, when the UE is configured with measurement objects on frequencies
    different from the serving cell, it needs a measurement gap to tune its
    receiver to those frequencies. Without a gap, the UE either:
    - Cannot measure (blind spot → late HO)
    - Uses SSB-based measurement within serving BWP (only works for intra-band)

    This check flags: inter-freq measObjects present but no measGapConfig.
    """
    import re

    serving_freqs: set[int] = set()
    inter_freq_objects: set[int] = set()
    has_gap_config = False
    gap_released = False
    msg_indices = []

    for msg in session.messages:
        if not msg.decoded_tree or "rrcReconfiguration" not in msg.summary:
            continue

        tree_str = str(msg.decoded_tree)

        # Track measGapConfig presence
        if "measGapConfig" in tree_str:
            if "'release'" in tree_str[tree_str.find("measGapConfig"):tree_str.find("measGapConfig") + 100]:
                gap_released = True
            else:
                has_gap_config = True
                gap_released = False

        # Extract serving cell frequency (from spCellConfig or PCell info)
        if msg.arfcn and msg.arfcn > 0:
            serving_freqs.add(msg.arfcn)

        # Extract measurement object frequencies
        if "measConfig" in tree_str and "measObjectToAddModList" in tree_str:
            # Find all ssbFrequency / carrierFreq values
            freqs = re.findall(r"(?:ssbFrequency|carrierFreq).*?(\d{5,7})", tree_str)
            for f_str in freqs:
                freq = int(f_str)
                if freq not in serving_freqs and freq > 100000:  # Skip LTE EARFCNs
                    inter_freq_objects.add(freq)
                    msg_indices.append(msg.index)

    # Flag: inter-freq objects exist but no gap configured (or gap was released)
    if inter_freq_objects and (not has_gap_config or gap_released):
        # Determine if these are truly inter-band (need gap) vs intra-band (gap-less possible)
        from logparser.decoders.info_extractor import _arfcn_to_band
        serving_bands = {_arfcn_to_band(f) for f in serving_freqs if f > 0}
        inter_bands = {_arfcn_to_band(f) for f in inter_freq_objects}

        # True inter-band: different bands need measurement gaps
        cross_band = inter_bands - serving_bands - {""}
        if cross_band:
            recs.append(Recommendation(
                rank=0, category="HO",
                issue=f"No Measurement Gap for Inter-Band Objects ({len(cross_band)} bands)",
                severity="Major",
                count=len(inter_freq_objects),
                msg_indices=msg_indices[:5],
                root_cause=(
                    f"UE configured with inter-band measurement objects on bands "
                    f"{sorted(cross_band)} but measGapConfig is "
                    f"{'released' if gap_released else 'not configured'}. "
                    f"Without a measurement gap, the UE cannot tune to these frequencies "
                    f"to measure neighbor cells — causing blind spots and late handovers. "
                    f"Serving bands: {sorted(serving_bands - {''})}."
                ),
                recommendation=(
                    "1. Configure measGapConfig with appropriate gap pattern (gapOffset)\n"
                    "2. Use FR2 gap pattern (ms20) for mmWave measurements\n"
                    "3. If gap-less measurement supported (intra-band SSB): verify UE capability\n"
                    "4. Check if measGapRelease was intentional (e.g., after HO completion)\n"
                    "5. Missing gaps cause delayed A3/B1 events → late HO → RLF"
                ),
                parameter="measGapConfig, gapOffset, mgl, mgrp, mgta, needForGap",
            ))
        elif inter_freq_objects and not cross_band:
            # Same band but different ARFCN — might still need gap for FR2
            fr2_freqs = {f for f in inter_freq_objects if f > 2000000}
            if fr2_freqs and not has_gap_config:
                recs.append(Recommendation(
                    rank=0, category="HO",
                    issue=f"No Measurement Gap for FR2 Inter-Freq ({len(fr2_freqs)} objects)",
                    severity="Minor",
                    count=len(fr2_freqs),
                    msg_indices=msg_indices[:3],
                    root_cause=(
                        f"FR2 measurement objects configured on {len(fr2_freqs)} frequencies "
                        f"without measGapConfig. FR2 beam sweeping typically requires gaps "
                        f"unless the UE supports simultaneous multi-panel reception."
                    ),
                    recommendation=(
                        "1. Verify UE capability: needForGapsIntra/InterFreq per band\n"
                        "2. If beam-based: SSB measurement without gap may be supported\n"
                        "3. Monitor for late or missing measurement reports on these freqs"
                    ),
                    parameter="measGapConfig, needForGapsIntraFreq-FR2, ssb-MTC",
                ))


def _check_measurement_gaps(session: LogSession, recs: list):
    """Check for measurement report patterns indicating coverage issues."""
    meas_reports = [m for m in session.messages if "measurementreport" in m.summary.lower()]

    if len(meas_reports) > 10:
        # Many measurement reports without successful HO could indicate ping-pong
        ho_msgs = [m for m in session.messages if "reconfigurationwithsync" in str(m.decoded_tree or "").lower()]
        if len(ho_msgs) > 3:
            recs.append(Recommendation(
                rank=0, category="HO",
                issue=f"Frequent Handovers ({len(ho_msgs)}x) — Possible Ping-Pong",
                severity="Major",
                count=len(ho_msgs),
                msg_indices=[m.index for m in ho_msgs[:5]],
                root_cause=(
                    "Multiple handovers in a short period suggests ping-pong between cells. "
                    "TTT (Time To Trigger) or Hysteresis may be too low."
                ),
                recommendation=(
                    "1. Increase timeToTrigger (TTT) from 40ms → 160ms\n"
                    "2. Increase a3-Offset (1dB → 3dB)\n"
                    "3. Add hysteresis (0.5dB → 2dB)\n"
                    "4. Review CIO (Cell Individual Offset) for specific cells"
                ),
                parameter="timeToTrigger, a3-Offset, hysteresis, cellIndividualOffset",
            ))
