# Weekly Execution Plan — May 19-23, 2026 (Mon-Fri)

## Status: Monday DONE (completed May 15 catch-up) ✅

## Goal: Close Tier 2 gaps → ship production-grade tool

---

## Monday (May 19) — Measurement Gap + Multi-Source Fusion

### AM: Measurement Gap Analysis (4h)
**What:** Detect inter-frequency measurement gaps from RRC reconfigurations.
- Parse `measGapConfig` from `rrcReconfiguration` decoded trees
- Identify gap patterns (gapOffset, measGapLength, gapUE)
- Flag "no measurement gap configured but inter-freq neighbors reported" → blind spot
- New recommendation: "Missing Measurement Gap for Inter-Freq B1 Events"

**Files:** `info_extractor.py`, `recommendations.py`

### PM: Multi-Source Fusion Mode (4h)
**What:** Overlay PCAP (network) + logarchive (Apple) + QUTS (baseband) on one timeline.
- New function: `load_multi_source(paths: list[Path]) → LogSession`
- Auto-detect format per file and merge by timestamp
- Tag each message with `source_type: "QUTS"|"PCAP"|"logarchive"`
- Add "Source" column to message table (only shown in fusion mode)

**Files:** `pipeline.py`, `message.py`, `main_window.py`

---

## Tuesday (May 20) — S1AP/NGAP Deep Decode

### AM: S1AP Bearer-Level Parsing (4h)
**What:** Extract QoS/5QI/EBI from S1AP and NGAP PCAP messages.
- Add tshark fields: `s1ap.e_RABSetupListBearerSURes`, `ngap.qosFlowIdentifier`, `ngap.fiveQI`
- Parse bearer setup/modification/release events
- Build `session.bearer_events` timeline (bearer_id, 5QI, timestamp, event_type)

**Files:** `pcap_reader.py`, `session.py`

### PM: NAS QoS Flow Tracking (4h)
**What:** Track PDU Session establishment and modification.
- From NAS decoded trees: extract `PDUSessionEstablishmentAccept`, `PDUSessionModification`
- Track 5QI assignment per PDU session over time
- New info field: "PDU Session 1: 5QI=9 (best effort)" or "5QI=1 (voice GBR)"

**Files:** `nas.py`, `info_extractor.py`, `session.py`

---

## Wednesday (May 21) — Per-LCID MAC + Code Quality

### AM: Per-LCID MAC Sub-PDU Parser (4h)
**What:** Parse MAC sub-headers to separate SRB from DRB traffic.
- In 0xB8C9 DL TB: each 144-byte record has MAC sub-PDUs with LCID headers
- Parse LCID from sub-PDU headers: LCID 0=CCCH, 1-3=SRB, 4+=DRB
- Compute per-LCID byte counts → separate signaling overhead from user data
- Show SRB vs DRB breakdown in Performance tab throughput hover

**Files:** `nr_mac.py`, `performance_tab.py`

### PM: Code Quality Sprint (4h)
- Extract all magic numbers (20, 32, 35, 144, 72) → `src/logparser/core/constants.py`
- Add `logger.debug()` calls in all decoder `except Exception:` blocks
- Add 10 more unit tests (NAS cause, UL power, PCI mod-3, band mapping)
- Add `~/.logparser.toml` config file (max_plot_points, default_filters)
- Set up pre-commit: `ruff check` + `ruff format`

**Files:** `constants.py` (new), all decoders, `tests/`, `.pre-commit-config.yaml`

---

## Thursday (May 22) — Apple .acp + GPS

### AM: Apple .acp Binary Format (4h)
**What:** Parse raw .acp files directly without requiring MergedFile_Diag.hdf.
- Reverse-engineer frame format from .acp file samples
- .acp files have 4-byte header `0x0F 0x00 0x01 0x01` + frame records
- Each frame: timestamp + DIAG_LOG_F record (same as QUTS after header strip)
- Build `AcpReader` class that yields `DiagPacket` (same interface as `QutsReader`)

**Files:** `ingest/acp_reader.py` (rewrite), `pipeline.py`

### PM: GPS/Location Extraction (4h)
**What:** If bb-trace contains location data, extract and store.
- Check sysdiagnose for `LocationLogs/` or `locationd` entries in logarchive
- Parse CommCenter cell location reports (EARFCN + PCI → approximate location)
- Store as `session.location_events: list[(timestamp, lat, lon)]`
- Optional: CLI `--kml-export` for Google Earth visualization

**Files:** `logarchive_reader.py`, `session.py`, `cli.py`

---

## Friday (May 23) — Real-Time Stream + Documentation

### AM: Real-Time QXDM UDP Listener (4h)
**What:** Listen on UDP socket for live QXDM-compatible diag stream.
- New class: `LiveStreamReader(port=4000)` → yields `DiagPacket`
- Same interface as `QutsReader` but non-blocking (asyncio or threading)
- GUI: "Start Live Capture" button on landing page → real-time message list
- CLI: `logparser-cli --live :4000` → stream decoded messages to stdout

**Files:** `ingest/live_reader.py` (new), `main_window.py`, `cli.py`

### PM: Documentation + README (4h)
- Write professional `README.md` for GitHub (features, install, usage, screenshots)
- Add `docs/ARCHITECTURE.md` — module diagram, data flow, extension guide
- Add `docs/SUPPORTED_LOG_CODES.md` — table of all decoded log codes
- Update `pyproject.toml` with proper metadata, dependencies, entry_points
- Tag release: `git tag v1.0.0` → push tags

**Files:** `README.md`, `docs/`, `pyproject.toml`

---

## Daily Schedule

| Day | AM (4h) | PM (4h) | Deliverable |
|:----|:--------|:--------|:------------|
| Mon | Measurement Gap | Multi-Source Fusion | New recommendation + fusion mode |
| Tue | S1AP/NGAP Deep | NAS QoS Flow | Bearer timeline + 5QI tracking |
| Wed | Per-LCID MAC | Code Quality | Accurate throughput + tests + config |
| Thu | Apple .acp Parser | GPS/Location | Direct .acp loading + KML export |
| Fri | Real-Time Stream | Docs + README | Live capture + v1.0 release |

---

## Success Criteria (EOD Friday)

- [ ] Measurement gap detection in recommendations
- [ ] Multi-source fusion (PCAP + logarchive + QUTS in one session)
- [ ] S1AP/NGAP bearer-level QoS extraction from PCAP
- [ ] NAS 5QI flow tracking with info field enrichment
- [ ] Per-LCID MAC SRB/DRB separation in throughput
- [ ] All magic numbers in constants.py
- [ ] 22+ unit tests passing
- [ ] Apple .acp binary parser (direct loading without MergedFile)
- [ ] GPS/location extraction from sysdiagnose
- [ ] Real-time UDP listener for live QXDM stream
- [ ] README.md + architecture docs
- [ ] Git tag v1.0.0 pushed

## Estimated Coverage After This Week

- **Single-file analysis:** 90% → **97%**
- **Enterprise platform:** 65% → **82%**
- **Production readiness:** Ship-ready for internal team use
