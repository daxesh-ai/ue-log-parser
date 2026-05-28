# Action Plan — 5G/4G Log Parser
# Current State: ~54% complete → Target: ~85% in 4 weeks

---

## Sprint 1 — Week 1 (Critical Blockers) ✅ COMPLETED 2026-05-14

| # | Task | Files | Status |
|---|------|-------|--------|
| 1.1 | **0xB8D1 CQI/RI/PMI decoder** | `nr_phy.py`, `session.py`, `pipeline.py`, `performance_tab.py`, `recommendations.py` | ✅ Done |
| 1.2 | **LTE RRC EN-DC nr-Config** | `lte_rrc.py` | ✅ Done |
| 1.3 | **0xB884/B885 SSB/CSI-RS beams** | `nr_phy.py`, `session.py`, `pipeline.py` | ✅ Done |
| 1.4 | **CLI `--recommendations --json`** | `cli.py` | ✅ Done |

**Results:**
- 7,026 CQI samples decoded (0xB8D1) — CQI distribution 7-14 (healthy 64QAM-256QAM range)
- 29,848 beam measurements (0xB884=SSB, 0xB885=CSI-RS)
- New recommendation: "SCell Activated with CQI ≤ 2 (4x)" — catches bad CA activation
- B1 threshold check now uses real SSB/CSI-RS beam RSRP instead of RRC proxy
- CLI: `logparser-cli file.hdf --recommendations` (color text) and `--json` (machine-readable)

---

## Sprint 2 — Week 2 (High-Value Decoders) ✅ COMPLETED 2026-05-14

| # | Task | Files | Hours |
|---|------|-------|-------|
| 2.0 | **Per-carrier throughput graph** | `performance_tab.py` | ✅ Done |
| 2.1 | **0xB8A1 UL MAC TB** | `nr_mac.py`, `session.py`, `pipeline.py` | ✅ Done |
| 2.2 | **0x1874 RLC DL Stats** | `nr_rlc.py` (new), `session.py`, `pipeline.py`, `recommendations.py` | ✅ Done |
| 2.3 | **0x1CE2 PDCP Throughput** | `nr_pdcp.py` (new), `session.py`, `pipeline.py` | ✅ Done |
| 2.4 | **JSON export** | `export/json_export.py` (new), `cli.py` | ✅ Done |
| 2.5 | **Unit tests (12 tests)** | `tests/test_decoders.py` | ✅ Done |

**Results:**
- DL Throughput: peak 1,420 Mbps, avg 245 Mbps (from MAC TB 0xB8C9)
- UL: 45,107 samples (0xB8A1), RLC: 26,494 stats (0x1874), PDCP: 5,531 (0x1CE2)
- Per-carrier throughput: stacked area chart (MCG/SCG labeled, CQI-weighted)
- JSON export: `--json-export out.json` in CLI
- 12/12 unit tests pass

---

## Sprint 3 — Week 3 (Medium Polish)

| # | Task | Files | Hours |
|---|------|-------|-------|
| 3.1 | **0xB896 HARQ ACK/NACK** | `nr_phy.py`, `session.py`, `pipeline.py`, `recommendations.py`, `performance_tab.py` | 3h |
| 3.2 | **HTML/PDF Top-20 report** | `export/report_export.py` (new), `cli.py`, `recommendations_tab.py` | 4h |
| 3.3 | **Multi-file drive test** | `pipeline.py`, `session.py`, `main_window.py`, `cli.py` | 6h |

**Outcome:** Real BLER replaces MCS-0 proxy, shareable report, drive-test merging

---

## Sprint 4 — Week 4 (Polish)

| # | Task | Files | Hours |
|---|------|-------|-------|
| 4.1 | **Search/filter UI** | `message_list/model.py`, `main_window.py` | 4h |
| 4.2 | **BLER/FER plot** | `performance_tab.py` | 2h |
| 4.3 | **pycrate r17 ASN.1 update** | `pyproject.toml`, `nr_rrc.py` | 3h |

**Outcome:** Regex search in message list, BLER graph, r16/r17 spare messages decoded

---

## Summary

| Week | Hours | Coverage Gain | Cumulative |
|:-----|:------|:--------------|:-----------|
| Week 1 | 15h | +15% | 69% |
| Week 2 | 15h | +12% | 81% |
| Week 3 | 13h | +8%  | 89% |
| Week 4 | 9h  | +5%  | 94% |
| **Total** | **52h** | **+40%** | **~94%** |

---

## Key Rules (Apply to Every Task)

1. New session fields → `field(default_factory=list)` in `session.py`
2. New PHY/MAC decoders → extend `_load_phy_mac_data()` in `pipeline.py`, NOT `_REGISTRY`
3. `_REGISTRY` is ONLY for ASN.1 signaling (RRC/NAS)
4. New graphs → `getattr(session, "field", [])` guard in `performance_tab.py`
5. New analysis rules → register in `analyze_session()` call list
6. CLI flags are additive — never break existing behavior
7. All new decoders go in `src/logparser/decoders/` — no logic in `pipeline.py`

---

## Critical Files for Implementation

```
src/logparser/decoders/nr_phy.py       ← extend for CQI, SSB, HARQ
src/logparser/decoders/nr_mac.py       ← extend for UL TB
src/logparser/pipeline.py              ← extend _load_phy_mac_data()
src/logparser/core/session.py          ← add new list fields
src/logparser/gui/performance_tab.py   ← add CQI, UL MCS, PDCP, BLER plots
src/logparser/analysis/recommendations.py ← add CQI+RLC+HARQ checkers
src/logparser/cli.py                   ← add --recommendations --json
```
