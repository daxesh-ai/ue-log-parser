# 5G/4G Log Parser — Team Demo

## What Is It?
A QCAT-style protocol analyzer built from scratch for 5G/4G/WiFi signaling analysis.
Dark-themed GUI, drag-and-drop, instant decode — no QCAT license needed.

---

## Key Capabilities

| Feature | What It Does |
|:--------|:-------------|
| **Multi-Format Ingest** | .hdf (QUTS), .pcap, .zip/.tar (auto-extract), Apple bb-trace folders |
| **Full Protocol Decode** | NR RRC, LTE RRC, 5G NAS, LTE NAS, SIP, PFCP, GTP, S1AP, NGAP |
| **3-Pane Signaling View** | Message list + Ladder diagram + IE tree (auto-expand) |
| **MAC-CE Decode** | SCell Activation/Deactivation bitmask (LCID 59/60) |
| **PHY Measurements** | Real-time RSRP + SINR per carrier (from L1 logs) |
| **MAC DL MCS** | Per-slot MCS index + TB size for throughput estimation |
| **NRDC / EN-DC** | PSCell change detection, SRB1/SRB2/SRB3 labeling, sk-Counter |
| **Top 20 Recommendations** | Auto-detects protocol failures with 3GPP parameter suggestions |
| **Voice Tracking** | VoNR ↔ VoLTE ↔ VoWiFi transitions, P-Access-Network-Info |

---

## Automated Issue Detection (Recommendations Tab)

| Category | What It Catches | Parameter Suggested |
|:---------|:----------------|:--------------------|
| T300 Timeout | RRC Setup failure (RACH issue) | T300, preambleTransMax |
| T304 Timeout | Handover execution failure | TTT, a3-Offset, hysteresis |
| T310 / RLF | Radio Link Failure | T310, N310, N311 |
| MCS + RSRP | Interference (good RSRP but MCS drops) | CQI-offset, BLER-target, IRC |
| SCell Failure | CA activation failed after config | Band-Combo, TAG, sCellDeactTimer |
| SCG Failure | Secondary Node drop (NR-DC) | SCG-T310, B1-Threshold |
| SRB3 Integrity | Security key mismatch (S-K_gNB) | sk-Counter, SecurityKey |
| VoWiFi→VoNR | Voice HO failure during RAT change | QFI-1, N3IWF, ePDG-handoff |
| B1 Threshold | 5G added at signal < -115 dBm → drop | B1-Threshold, B1-Hysteresis |

---

## Demo Flow (3 files)

### Demo 1: NRDC Forge Building (.hdf)
**Story:** "Indoor mmWave deployment, 11CC carrier aggregation"
- Show: MAC-CE SCell activations (up to 11CC!)
- Show: Performance tab → RSRP graph, MCS graph
- Show: Recommendations → "MCS Drop with RSRP > -90 (7,970x)" = interference
- Highlight: PSCell:PCI325 n258 + 4 SCells on mmWave

### Demo 2: iPhone17 IMS (.hdf)
**Story:** "VoNR call with severe network issues"
- Show: 41 RRC Rejects + 38 T300 timeouts = network congestion
- Show: SCell Addition Failure (9x) + SCell Ping-Pong (18x)
- Show: RAT column showing VoNR ↔ VoLTE transitions (27 transitions!)
- Show: Recommendations tab → all 7 issues ranked by severity

### Demo 3: VoNR Mobility PCAP (.pcapng)
**Story:** "Voice call mobility across NY/NJ cells"
- Show: SIP ladder diagram (INVITE → 200 OK → BYE)
- Show: P-Access-Network-Info = "3GPP-NR-FDD" (RAT tracking in SIP)
- Show: IE tree with SIP fields (From, To, CSeq, SDP-Media)
- Highlight: Phone numbers, codec info, call flow

---

## Architecture (1 slide)

```
┌─────────────────────────────────────────────────────┐
│                   PySide6 GUI                        │
│  ┌──────────┐ ┌──────────┐ ┌───────────────────┐   │
│  │ Signaling│ │ CA/Perf  │ │ Recommendations   │   │
│  │ 3-Pane   │ │ RSRP/MCS │ │ Top 20 Issues     │   │
│  └──────────┘ └──────────┘ └───────────────────┘   │
├─────────────────────────────────────────────────────┤
│              Analysis Engine                         │
│  Timer rules (JSON) │ Tech Tracker │ CA Tracker      │
├─────────────────────────────────────────────────────┤
│              Decoders                                │
│  NR RRC │ LTE RRC │ NAS │ MAC-CE │ PHY │ MAC DL     │
├─────────────────────────────────────────────────────┤
│              Ingest                                  │
│  QUTS (.hdf) │ PCAP (tshark) │ Archive │ bb-trace   │
└─────────────────────────────────────────────────────┘
```

---

## How to Run

```bash
cd ~/parser
PYTHONPATH=src python3 -m logparser              # GUI
PYTHONPATH=src python3 -m logparser file.hdf     # GUI + auto-load
PYTHONPATH=src python3 -m logparser --cli file.hdf  # CLI mode
```

---

## What's Next (Roadmap)

1. CQI per SCell (validates MAC-CE activation)
2. EN-DC: LTE-embedded NR container decode
3. CLI recommendations output (JSON export)
4. PDCP throughput + HARQ BLER
5. Multi-file drive test mode
