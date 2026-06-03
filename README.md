# 5G/4G UE Log Parser

**QCAT-style protocol analyzer** for Qualcomm QUTS (.hdf) and Apple baseband logs. Decodes NR/LTE RRC, NAS, MAC, PHY layers with automated failure detection and 3GPP parameter recommendations.

## Features

| Layer | What It Decodes |
|:------|:----------------|
| **NR RRC** | Full ASN.1 (TS 38.331), SRB0-3, NRDC PSCell, EN-DC, SCGFailureInformation |
| **LTE RRC** | Full ASN.1 (TS 36.331), embedded NR container decode for EN-DC |
| **5G NAS** | Embedded in RRC (dedicatedNAS-Message), cause code lookup |
| **LTE NAS** | Standalone (0xB0EC/0xB0ED) + embedded, QCI/bearer tracking |
| **PHY** | RSRP, SINR, CQI/RI, SSB/CSI-RS beams per carrier |
| **MAC** | DL/UL MCS, TB size, MAC-CE SCell Activation, HARQ BLER |
| **S1AP/NGAP** | Bearer-level QoS (E-RAB ID, QCI/5QI, cause codes) |
| **SIP/IMS** | Call flow, P-Access-Network-Info RAT tracking |
| **Apple** | .logarchive (CommCenter), sysdiagnose, WiFi scan |

## Automated Analysis (Top 20 Recommendations)

| Detection | What It Catches |
|:----------|:----------------|
| T300/T304/T310 Timer | RRC setup, HO, RLF failures |
| MCS + RSRP Mismatch | Interference (good RSRP but bad MCS) |
| SCG Failure | rlc-MaxNumRetx, t313-Expiry, srb3-IntegrityFailure |
| PCI Mod-3 | PSS reference signal interference |
| Measurement Gap | Missing gap for inter-band measurements |
| SCell Activation | CQI=0 after MAC-CE activation |
| UL Power Limited | mmWave module OFF (FR2 Pcmax=0) |
| VoWiFi→VoNR HO | P-Access-Network-Info change without success |
| B1 Threshold | 5G added below -115 dBm → drop |
| HARQ BLER | Real ACK/NACK > 2% threshold |

## Install

```bash
# Clone
git clone https://github.com/daxesh-ai/ue-log-parser.git
cd ue-log-parser

# Dependencies
pip install pycrate PySide6 pyqtgraph numpy

# Optional: tshark for PCAP support
# brew install wireshark (or install Wireshark.app)
```

## Usage

### GUI Mode
```bash
PYTHONPATH=src python3 -m logparser                    # Launch GUI
PYTHONPATH=src python3 -m logparser file.hdf           # Open file directly
```

### CLI Mode
```bash
PYTHONPATH=src python3 -m logparser --cli file.hdf --recommendations      # Top 20 issues
PYTHONPATH=src python3 -m logparser --cli file.hdf --recommendations --json  # JSON output
PYTHONPATH=src python3 -m logparser --cli file.hdf --report out.html      # HTML report
PYTHONPATH=src python3 -m logparser --cli file.hdf --json-export out.json # Full export
PYTHONPATH=src python3 -m logparser --cli --dir /logs/                    # Batch mode
PYTHONPATH=src python3 -m logparser --cli file1.hdf file2.hdf             # Multi-file merge
```

## Supported File Formats

| Format | Source | Description |
|:-------|:-------|:------------|
| `.hdf` | Qualcomm QUTS | Primary baseband log format (MergedFile_Diag.hdf) |
| `.pcap` / `.pcapng` | Network capture | SIP, PFCP, GTP, S1AP, NGAP, Diameter via tshark |
| `.logarchive` | Apple Unified Log | CommCenter cellular events, IMS, WiFi |
| `sysdiagnose_*.tar.gz` | Apple sysdiagnose | System logs + WiFi scan + logarchive |
| `.zip` / `.tar.gz` | Archives | Auto-extracts and finds .hdf/.pcap inside |
| bb-trace directories | Apple baseband | Finds sibling MergedFile_Diag.hdf |

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   PySide6 GUI                        │
│  ┌──────────┐ ┌──────────────┐ ┌──────────────┐    │
│  │Signaling │ │ Performance  │ │Recommendations│    │
│  │ 3-Pane   │ │ RSRP/MCS/CA │ │  Top 20      │    │
│  └──────────┘ └──────────────┘ └──────────────┘    │
├─────────────────────────────────────────────────────┤
│              Analysis Engine                         │
│  Timer rules │ Tech Tracker │ CA Tracker │ Bearer   │
├─────────────────────────────────────────────────────┤
│              Decoders                                │
│  NR RRC │ LTE RRC │ NAS │ MAC-CE │ PHY │ MAC │ RLC  │
├─────────────────────────────────────────────────────┤
│              Ingest                                  │
│  QUTS (.hdf) │ PCAP (tshark) │ logarchive │ Archive │
└─────────────────────────────────────────────────────┘
```

## Log Codes Decoded

| Code | Layer | What |
|:-----|:------|:-----|
| 0xB821 | NR RRC | All message types, SRB0-3, bearer ID |
| 0xB0C0 | LTE RRC | All message types, EN-DC nr-Config |
| 0xB0EC/ED | LTE NAS | MO/MT NAS messages |
| 0xB883 | NR PHY | Per-carrier RSRP + SINR |
| 0xB8D1 | NR PHY | CQI + RI per carrier |
| 0xB884/B885 | NR PHY | SSB/CSI-RS beam measurements |
| 0xB8C9 | NR MAC | DL TB: MCS index + size |
| 0xB8A1 | NR MAC | UL TB: sub-PDU count + size |
| 0xB887 | NR MAC | SCell Activation bitmask (LCID 59/60) |
| 0xB896 | NR MAC | HARQ ACK/NACK (BLER) |
| 0xB8A7 | NR MAC | UL Power Control (Pcmax FR1/FR2) |
| 0x1874 | NR RLC | Retransmission stats |
| 0x1CE2 | NR PDCP | Throughput counters |

## Band Mapping (US Carriers)

| Band | Frequency | ARFCN Range | Carrier |
|:-----|:----------|:------------|:--------|
| n261 | 27.5-28.35 GHz | 2070833-2084999 | Verizon/AT&T mmWave |
| n260 | 37-40 GHz | 2229167-2279166 | US 39 GHz mmWave |
| n77 | 3.7-4.2 GHz | 646667-680000 | Verizon C-band |
| n78 | 3.3-3.7 GHz | 620000-646666 | T-Mobile/Global C-band |
| n66 | 2.1 GHz | 422000-440000 | AWS (all carriers) |
| n2 | 1.9 GHz | 386000-398000 | PCS (Verizon/AT&T) |
| n5 | 850 MHz | 173800-178800 | 850 MHz (Verizon CLR) |
| n12 | 700 MHz | 145800-149200 | US 700 A/B/C |
| n71 | 600 MHz | 123400-130400 | T-Mobile 600 |

## Running Tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## License

Private / Internal Use
