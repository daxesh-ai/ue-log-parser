"""Feature extraction — converts LogSession into a fixed-length numpy vector.

No ML dependencies required (pure numpy). The feature vector captures
the key characteristics of a session for anomaly detection.

Feature vector (30 features):
  PHY: rsrp_mean, rsrp_std, rsrp_min, sinr_mean, sinr_std (5)
  CQI: cqi_mean, cqi_std, cqi_min (3)
  MAC DL: mcs_mean, mcs_std, mcs_0_pct, throughput_mbps_avg, throughput_mbps_peak (5)
  MAC UL: ul_tb_count, ul_pct_of_dl (2)
  HARQ: bler_pct, bler_max_per_bucket (2)
  RRC: reestablishment_count, t300_count, t304_count, scg_failure_count (4)
  HO: ho_count, rat_transition_count (2)
  CA: max_cc_count, scell_add_count, scell_deactivate_count (3)
  NAS: reject_count (1)
  Session: duration_sec, message_count, decode_rate_pct (3)
"""

from __future__ import annotations

import numpy as np

from logparser.core.session import LogSession


FEATURE_NAMES = [
    "rsrp_mean", "rsrp_std", "rsrp_min", "sinr_mean", "sinr_std",
    "cqi_mean", "cqi_std", "cqi_min",
    "mcs_mean", "mcs_std", "mcs_0_pct", "throughput_mbps_avg", "throughput_mbps_peak",
    "ul_tb_count", "ul_pct_of_dl",
    "bler_pct", "bler_max_bucket",
    "reestablishment_count", "t300_count", "t304_count", "scg_failure_count",
    "ho_count", "rat_transition_count",
    "max_cc_count", "scell_add_count", "scell_deactivate_count",
    "reject_count",
    "duration_sec", "message_count", "decode_rate_pct",
]

NUM_FEATURES = len(FEATURE_NAMES)  # 30


def extract_features(session: LogSession) -> np.ndarray:
    """Extract a 30-element feature vector from a LogSession.

    Returns np.array of shape (30,) with float64 values.
    Missing data → 0.0 (safe default for anomaly detection).
    """
    features = np.zeros(NUM_FEATURES, dtype=np.float64)

    # ── PHY RSRP/SINR ────────────────────────────────────────────────────────
    phy = getattr(session, "phy_measurements", [])
    if phy:
        rsrps = np.array([m.rsrp_dbm for m in phy])
        sinrs = np.array([m.sinr_db for m in phy])
        features[0] = np.mean(rsrps)      # rsrp_mean
        features[1] = np.std(rsrps)       # rsrp_std
        features[2] = np.min(rsrps)       # rsrp_min
        features[3] = np.mean(sinrs)      # sinr_mean
        features[4] = np.std(sinrs)       # sinr_std

    # ── CQI ───────────────────────────────────────────────────────────────────
    cqi = getattr(session, "phy_cqi_samples", [])
    if cqi:
        cqi_vals = np.array([s.cqi for s in cqi])
        features[5] = np.mean(cqi_vals)   # cqi_mean
        features[6] = np.std(cqi_vals)    # cqi_std
        features[7] = np.min(cqi_vals)    # cqi_min

    # ── MAC DL ────────────────────────────────────────────────────────────────
    mac_dl = getattr(session, "mac_dl_samples", [])
    if mac_dl:
        mcs_vals = np.array([s.mcs for s in mac_dl])
        tb_sizes = np.array([s.tb_size for s in mac_dl])
        features[8] = np.mean(mcs_vals)   # mcs_mean
        features[9] = np.std(mcs_vals)    # mcs_std
        features[10] = np.sum(mcs_vals == 0) / max(1, len(mcs_vals)) * 100  # mcs_0_pct

        # Throughput estimate (total bytes / duration)
        if len(mac_dl) > 1:
            duration = (mac_dl[-1].timestamp - mac_dl[0].timestamp).total_seconds()
            if duration > 0:
                total_bytes = np.sum(tb_sizes)
                features[11] = total_bytes * 8 / duration / 1e6  # throughput_avg_mbps
                # Peak (max in 100ms bucket)
                features[12] = np.max(tb_sizes) * 8 / 0.1 / 1e6  # peak_mbps_approx

    # ── MAC UL ────────────────────────────────────────────────────────────────
    mac_ul = getattr(session, "mac_ul_samples", [])
    features[13] = len(mac_ul)           # ul_tb_count
    if mac_dl:
        features[14] = len(mac_ul) / max(1, len(mac_dl)) * 100  # ul_pct_of_dl

    # ── HARQ BLER ─────────────────────────────────────────────────────────────
    harq = getattr(session, "harq_samples", [])
    if harq:
        total_ack = sum(s.ack_count for s in harq)
        total_nack = sum(s.nack_count for s in harq)
        total = total_ack + total_nack
        features[15] = (total_nack / max(1, total)) * 100  # bler_pct
        if harq:
            per_pkt_bler = [s.bler_pct for s in harq]
            features[16] = max(per_pkt_bler)  # bler_max_bucket

    # ── RRC State ─────────────────────────────────────────────────────────────
    for msg in session.messages:
        s = msg.summary.lower()
        if "reestablishment" in s and "request" in s:
            features[17] += 1  # reestablishment_count
        if msg.annotations and any("T300" in a for a in msg.annotations):
            features[18] += 1  # t300_count
        if msg.annotations and any("T304" in a for a in msg.annotations):
            features[19] += 1  # t304_count
        if "scgfailure" in s or "mcgfailure" in s:
            features[20] += 1  # scg_failure_count

    # ── HO ────────────────────────────────────────────────────────────────────
    tech_tracker = getattr(session, "tech_tracker", None)
    if tech_tracker:
        features[21] = sum(1 for m in session.messages
                           if m.info and "PSCell:" in m.info)  # ho_count
        features[22] = len(getattr(tech_tracker, "_transitions", []))  # rat_transitions

    # ── CA ────────────────────────────────────────────────────────────────────
    mac_ce = [m for m in session.messages if "MAC-CE" in m.channel]
    if mac_ce:
        import re
        cc_counts = []
        for m in mac_ce:
            match = re.search(r"(\d+)CC active", m.info or "")
            if match:
                cc_counts.append(int(match.group(1)))
        if cc_counts:
            features[23] = max(cc_counts)  # max_cc_count
        features[24] = sum(1 for m in mac_ce if "Activate" in m.summary)  # scell_add
        features[25] = sum(1 for m in mac_ce if "Deactivate" in m.summary)  # scell_deactivate

    # ── NAS ───────────────────────────────────────────────────────────────────
    features[26] = sum(1 for m in session.messages
                       if "reject" in m.summary.lower())  # reject_count

    # ── Session ───────────────────────────────────────────────────────────────
    if session.messages:
        duration = (session.messages[-1].timestamp - session.messages[0].timestamp).total_seconds()
        features[27] = duration  # duration_sec
    features[28] = len(session.messages)  # message_count
    decoded = sum(1 for m in session.messages if m.decoded_tree is not None)
    features[29] = decoded / max(1, len(session.messages)) * 100  # decode_rate_pct

    return features
