"""CA (Carrier Aggregation) tracker — extracts PCell/SCell config over time.

Builds a timeline of CA events from rrcReconfiguration messages:
- SCell additions (with PCI, band, bandwidth)
- SCell removals
- PCell/PSCell changes (handovers)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from logparser.core.message import ParsedMessage
from logparser.decoders.info_extractor import _find, _arfcn_to_band


@dataclass
class CellConfig:
    cell_type: str  # "PCell", "PSCell", "SCell1", "SCell2", etc.
    pci: int = 0
    arfcn: int = 0
    band: str = ""
    bandwidth_mhz: int = 0
    scs_khz: int = 0  # subcarrier spacing


@dataclass
class CAEvent:
    timestamp: datetime
    msg_index: int
    event_type: str  # "add", "remove", "modify", "handover"
    cells: list[CellConfig] = field(default_factory=list)
    combo_str: str = ""  # e.g., "3CC: n77+n5+n77"


@dataclass
class CAState:
    """Current CA state at a point in time."""
    pcell: CellConfig | None = None
    pscell: CellConfig | None = None
    scells: list[CellConfig] = field(default_factory=list)

    @property
    def num_cc(self) -> int:
        count = 0
        if self.pcell:
            count += 1
        if self.pscell:
            count += 1
        count += len(self.scells)
        return count

    @property
    def combo_str(self) -> str:
        bands = []
        if self.pcell and self.pcell.band:
            bands.append(self.pcell.band)
        if self.pscell and self.pscell.band:
            bands.append(self.pscell.band)
        for sc in self.scells:
            if sc.band:
                bands.append(sc.band)
        if not bands:
            return "No CA"
        return f"{len(bands)}CC: {'+'.join(bands)}"


class CATracker:
    """Tracks CA configuration over time from RRC messages."""

    def __init__(self):
        self.events: list[CAEvent] = []
        self._states: list[CAState] = []  # one per message index
        self._current = CAState()

    def build_from_messages(self, messages: list[ParsedMessage]) -> None:
        """Scan all messages and build CA timeline."""
        self.events = []
        self._states = []
        self._current = CAState()

        for msg in messages:
            # Track PCell from sub-header PCI/ARFCN (always available)
            if msg.pci and msg.arfcn and self._current.pcell is None:
                band = _arfcn_to_band(msg.arfcn)
                self._current.pcell = CellConfig(
                    cell_type="PCell", pci=msg.pci,
                    arfcn=msg.arfcn, band=band,
                    bandwidth_mhz=self._estimate_bw_from_band(band),
                )
            elif msg.pci and msg.arfcn and self._current.pcell:
                # PCell change (different PCI = handover)
                if msg.pci != self._current.pcell.pci and msg.pci != 0:
                    band = _arfcn_to_band(msg.arfcn)
                    self._current.pcell = CellConfig(
                        cell_type="PCell", pci=msg.pci,
                        arfcn=msg.arfcn, band=band,
                        bandwidth_mhz=self._estimate_bw_from_band(band),
                    )

            # Process rrcReconfiguration for SCell changes
            if "rrcReconfiguration" in msg.summary and "Complete" not in msg.summary:
                if msg.decoded_tree:
                    self._process_reconfig(msg)

            self._states.append(CAState(
                pcell=self._current.pcell,
                pscell=self._current.pscell,
                scells=list(self._current.scells),
            ))

    def get_state_at(self, index: int) -> CAState:
        if 0 <= index < len(self._states):
            return self._states[index]
        return CAState()

    def _process_reconfig(self, msg: ParsedMessage):
        """Extract CA config changes from an rrcReconfiguration."""
        tree = msg.decoded_tree
        content = self._get_reconfig_content(tree)
        if not content:
            return

        # Look for cell group configs
        nce = content.get("nonCriticalExtension") if isinstance(content, dict) else None
        if not isinstance(nce, dict):
            return

        mcg_raw = nce.get("masterCellGroup")
        scg_raw = nce.get("secondaryCellGroup")

        # Also check deeper nonCriticalExtension
        nce2 = nce.get("nonCriticalExtension")
        if isinstance(nce2, dict):
            if not mcg_raw:
                mcg_raw = nce2.get("masterCellGroup")
            if not scg_raw:
                scg_raw = nce2.get("secondaryCellGroup")

        cells_found = []

        if mcg_raw:
            mcg = self._unwrap(mcg_raw)
            if isinstance(mcg, dict):
                self._extract_cells_from_group(mcg, cells_found, is_scg=False)

        if scg_raw:
            scg = self._unwrap(scg_raw)
            if isinstance(scg, dict):
                self._extract_cells_from_group(scg, cells_found, is_scg=True)

        if cells_found:
            event = CAEvent(
                timestamp=msg.timestamp,
                msg_index=msg.index,
                event_type="add",
                cells=cells_found,
                combo_str=self._current.combo_str,
            )
            self.events.append(event)

    def _extract_cells_from_group(self, cg: dict, cells: list, is_scg: bool):
        """Extract cell configs from a CellGroupConfig."""
        # SpCell (PCell or PSCell)
        sp_cell = cg.get("spCellConfig")
        if isinstance(sp_cell, dict):
            reconfig = sp_cell.get("reconfigurationWithSync")
            if isinstance(reconfig, dict):
                pci = _find(reconfig, "physCellId", 3)
                freq = _find(reconfig, "absoluteFrequencySSB", 4) or _find(reconfig, "ssbFrequency", 4)
                bw = self._extract_bandwidth(reconfig)

                if pci is not None:
                    band = _arfcn_to_band(freq) if freq else ""
                    cell_type = "PSCell" if is_scg else "PCell"
                    cell = CellConfig(
                        cell_type=cell_type, pci=pci,
                        arfcn=freq or 0, band=band, bandwidth_mhz=bw,
                    )
                    cells.append(cell)
                    if is_scg:
                        self._current.pscell = cell
                    else:
                        self._current.pcell = cell

        # SCells
        scell_list = cg.get("sCellToAddModList")
        if isinstance(scell_list, list):
            new_scells = []
            for sc in scell_list:
                if not isinstance(sc, dict):
                    continue
                idx = sc.get("sCellIndex", 0)
                sc_common = sc.get("sCellConfigCommon")
                if isinstance(sc_common, dict):
                    pci = _find(sc_common, "physCellId", 3)
                    freq = _find(sc_common, "absoluteFrequencySSB", 3) or _find(sc_common, "dl-CarrierFreq", 3)
                    bw = self._extract_bandwidth(sc_common)
                    band = _arfcn_to_band(freq) if freq else ""

                    cell = CellConfig(
                        cell_type=f"SCell{idx}", pci=pci or 0,
                        arfcn=freq or 0, band=band, bandwidth_mhz=bw,
                    )
                    cells.append(cell)
                    new_scells.append(cell)

            if new_scells:
                self._current.scells = new_scells

        # SCell removals
        scell_release = cg.get("sCellToReleaseList")
        if isinstance(scell_release, list) and scell_release:
            self._current.scells = [
                sc for sc in self._current.scells
                if int(sc.cell_type.replace("SCell", "") or 0) not in scell_release
            ]

    def _extract_bandwidth(self, config: dict) -> int:
        """Extract bandwidth in MHz from config."""
        # Look for locationAndBandwidth or scs-SpecificCarrierList
        carrier_list = _find(config, "scs-SpecificCarrierList", 4)
        if isinstance(carrier_list, list) and carrier_list:
            for carrier in carrier_list:
                if isinstance(carrier, dict):
                    carrier_bw = carrier.get("carrierBandwidth")
                    if isinstance(carrier_bw, int):
                        # carrierBandwidth is in RBs, convert to approximate MHz
                        # 273 RB = 100 MHz (SCS 30kHz), 52 RB = 20 MHz
                        if carrier_bw >= 270:
                            return 100
                        elif carrier_bw >= 133:
                            return 50
                        elif carrier_bw >= 100:
                            return 40
                        elif carrier_bw >= 51:
                            return 20
                        elif carrier_bw >= 24:
                            return 10
                        elif carrier_bw >= 11:
                            return 5
        return 0

    def _get_reconfig_content(self, tree) -> dict | None:
        if not isinstance(tree, dict):
            return None
        msg = tree.get("message")
        if not isinstance(msg, tuple) or len(msg) != 2:
            return None
        _, c1 = msg
        if not isinstance(c1, tuple) or len(c1) != 2:
            return None
        _, content = c1
        if not isinstance(content, dict):
            return None
        ce = content.get("criticalExtensions")
        if isinstance(ce, tuple) and len(ce) == 2:
            _, inner = ce
            if isinstance(inner, dict):
                return inner
        return content

    def _unwrap(self, val):
        if isinstance(val, dict):
            if "(decoded CellGroupConfig)" in val:
                return val["(decoded CellGroupConfig)"]
            return val
        elif isinstance(val, tuple) and len(val) == 2 and isinstance(val[0], str):
            return val[1] if isinstance(val[1], dict) else None
        return None

    @staticmethod
    def _estimate_bw_from_band(band: str) -> int:
        """Estimate typical bandwidth for a band (when not available from RRC)."""
        bw_map = {
            "n77": 100, "n78": 100, "n79": 100,
            "n258": 100, "n260": 100, "n261": 100,
            "n5": 10, "n2": 20, "n7": 20, "n25": 20,
            "n12": 10, "n14": 10, "n71": 20, "n28": 20,
            "B1": 20, "B2": 20, "B3": 20, "B4": 20,
            "B5": 10, "B7": 20, "B12": 10, "B13": 10,
            "B14": 10, "B66": 20, "B71": 20,
        }
        return bw_map.get(band, 20)


def estimate_throughput_mbps(state: CAState) -> float:
    """Estimate theoretical max DL throughput from CA config.

    Approximation: BW(MHz) × spectral_efficiency × MIMO_layers
    - Sub-6: ~3.5 bps/Hz with 4x4 MIMO (256QAM, ~0.9 coding rate)
    - Low-band: ~2 bps/Hz with 2x2 MIMO
    - mmWave: ~4 bps/Hz with higher order MIMO
    """
    total = 0.0

    for cell in [state.pcell, state.pscell] + state.scells:
        if cell is None:
            continue
        bw = cell.bandwidth_mhz or 20
        band = cell.band

        if band in ("n258", "n260", "n261"):
            # mmWave: 4x4 MIMO, 256QAM
            eff = 4.0
        elif band in ("n77", "n78", "n79"):
            # C-band: 4x4 MIMO, 256QAM
            eff = 3.5
        elif band in ("n5", "n12", "n14", "n71", "n28"):
            # Low-band: 2x2 MIMO
            eff = 1.8
        else:
            # Mid-band default
            eff = 2.5

        total += bw * eff

    return total
