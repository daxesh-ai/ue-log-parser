# 5G/4G Log Parser — Remaining Implementation Plan

## Current State (Completed)

| Layer | Coverage | Log Codes |
|:------|:---------|:----------|
| NR RRC | Full ASN.1 decode, SRB0-3, NRDC/EN-DC, PSCell/SCell | 0xB821 |
| LTE RRC | Full ASN.1 decode | 0xB0C0 |
| LTE NAS | Standalone decode | 0xB0EC, 0xB0ED |
| 5G NAS | Embedded in RRC (dedicatedNAS-Message) | (inside 0xB821) |
| PCAP | SIP/PFCP/GTP/S1AP/NGAP/Diameter + P-Access-Network-Info | tshark |
| MAC-CE | SCell Activation/Deactivation bitmask (LCID 59/60) | 0xB887 |
| PHY L1 | Per-carrier RSRP + SINR (serving cells) | 0xB883 |
| MAC DL | MCS index + TB size (DL throughput) | 0xB8C9 |
| MAC RACH | Timing Advance + preamble count (status) | 0xB888 |
| Analysis | T300/T304/T310, SCG/MCG failure, SRB3, VoWiFi→VoNR, MCS+RSRP correlation, B1 threshold, SCell ping-pong | Engine |
| GUI | Signaling tab, Performance tab (RSRP/MCS graphs), Recommendations tab, Open Folder | PySide6 |

---

## Phase 1: HIGH Priority (Completes Existing Features)

### 1.1 NR PHY PDSCH — CQI/RI/PMI per SCell (0xB8D1)
**Why:** Enables "CQI=0 means SCell activation failed" check from MAC-CE.
**Effort:** ~2 hours
**Approach:**
- Analyze 0xB8D1 structure (8,957 packets available)
- Extract per-SCell CQI (0-15), RI (1-4), wideband PMI
- Store in `session.phy_cqi_samples`
- Add to Performance tab as CQI graph
- Wire into recommendations: "SCell activated but CQI=0 for >100ms → activation failure"

### 1.2 LTE RRC Embedded NR Container (EN-DC)
**Why:** Completes EN-DC flow — shows SCG addition from LTE side.
**Effort:** ~3 hours
**Approach:**
- In `LteRrcDecoder`, detect `rrcConnectionReconfiguration` with `nr-Config` / `nr-SCG`
- Decode the OCTET STRING as `RRCReconfiguration` using NR ASN.1
- Extract PSCell PCI, band, SCell config from within
- Tag these messages with `bearer_id` and show "LTE-RRC (EN-DC)" in channel

### 1.3 NR PHY SSB/CSI-RS Measurements (0xB884/B885)
**Why:** Gives per-beam neighbor cell measurements — completes B1 threshold analysis.
**Effort:** ~2 hours
**Approach:**
- Analyze 0xB884 (SSB) and 0xB885 (CSI-RS) structures
- Extract per-neighbor: PCI + RSRP + RSRQ per beam
- Feed into `_check_b1_threshold_drops()` for accurate B1-triggered failure correlation

---

## Phase 2: MEDIUM Priority (Advanced Analysis)

### 2.1 NR MAC UL TB (0xB8A1)
**Why:** UL MCS + BSR for uplink quality and buffer status.
**Effort:** ~1 hour (likely same format as 0xB8C9)
**Approach:**
- Decode same structure as DL TB but for uplink
- Add `session.mac_ul_samples` with UL MCS, TB size
- Add to Performance tab as UL MCS graph

### 2.2 NR RLC DL Stats (0x1874)
**Why:** RLC retransmissions map directly to `rlc-MaxNumRetx` SCG failure cause.
**Effort:** ~2 hours
**Approach:**
- Analyze 0x1874 structure
- Extract: retx_count, max_retx_reached, AM/UM mode, bearer_id
- Add recommendation: "RLC MaxRetx reached → SCG failure imminent"

### 2.3 NR PDCP Throughput (0x1CE2)
**Why:** Actual user-plane throughput (more accurate than TB size estimate).
**Effort:** ~1 hour
**Approach:**
- Analyze 0x1CE2 structure
- Extract: DL bytes, UL bytes, per-bearer throughput
- Replace TB-size-based estimate in Performance tab with real throughput

### 2.4 CLI Mode Recommendations Output
**Why:** Engineers need Top 20 output without launching GUI.
**Effort:** ~30 min
**Approach:**
- In `cli.py`, after loading session, call `analyze_session()`
- Print formatted table of recommendations to stdout
- Add `--json` flag for machine-readable output

---

## Phase 3: LOW Priority (Polish & Future)

### 3.1 NR MAC HARQ ACK/NACK (0xB896)
**Why:** Real BLER measurement (currently estimated from MCS 0 rate).
**Approach:** Decode HARQ feedback, compute per-carrier BLER over time.

### 3.2 pycrate ASN.1 Version Update
**Why:** Decode "spare" r16/r17 messages (SCGFailureInformation, MCGFailureInformation).
**Approach:** Update pycrate or provide custom NR-RRC-Definitions with r17 extensions.

### 3.3 Performance Tab: Throughput vs Time Graph
**Why:** Show actual DL/UL throughput timeline alongside RSRP/MCS.
**Approach:** Use PDCP throughput (phase 2.3) or aggregate MAC TB sizes over 100ms windows.

### 3.4 Export: Protocol Summary Report
**Why:** One-page PDF/HTML summary with Top 20 issues + key metrics.
**Approach:** Generate HTML with embedded graphs, export via QWebEngineView or matplotlib.

### 3.5 Multi-File / Drive Test Mode
**Why:** Combine multiple .hdf files from a drive test into one timeline.
**Approach:** Load multiple files, merge by timestamp, add GPS correlation if available.

---

## Execution Priority

```
Week 1: Phase 1 (1.1 + 1.2 + 1.3) — Completes protocol coverage
Week 2: Phase 2 (2.1 + 2.2 + 2.3 + 2.4) — Advanced analysis + CLI
Week 3+: Phase 3 — Polish, export, multi-file
```

## Key Metrics

- **Signaling decode rate:** 99% (8 "spare" messages remaining = r16/r17 ASN.1 gap)
- **PHY/MAC coverage:** RSRP, SINR, MCS, SCell activation, RACH TA
- **Packet processing:** 97,035 / 311,980 (31% of total packets in file)
- **Target:** 50%+ with Phase 1 complete (adds ~22K packets from 0xB8D1/B884/B885)
