"""Performance Tab — CA config cards, throughput graphs, timeline.

Performance design:
- All data computation happens in a background QThread (PlotWorker)
- UI thread only calls plot() with pre-computed numpy arrays
- QScrollArea wraps all plots so only visible ones are rendered
- Max 300 points per series (aggressive downsampling)
- Plots are grouped into tabs: Throughput | RF Quality | CA Events
"""

from __future__ import annotations

import numpy as np

try:
    from PySide6.QtCore import Qt, QThread, Signal, QObject
    from PySide6.QtGui import QFont
    from PySide6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
        QTableWidget, QTableWidgetItem, QHeaderView,
        QScrollArea, QTabWidget, QPushButton,
    )
except ImportError:
    from PyQt6.QtCore import Qt, QThread, QObject
    from PyQt6.QtCore import pyqtSignal as Signal
    from PyQt6.QtGui import QFont
    from PyQt6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
        QTableWidget, QTableWidgetItem, QHeaderView,
        QScrollArea, QTabWidget, QPushButton,
    )

import pyqtgraph as pg

from logparser.analysis.ca_tracker import CATracker, CellConfig, estimate_throughput_mbps
from logparser.core.session import LogSession

# ── colour palette ──────────────────────────────────────────────────────────
_BAND_COLORS = {
    "n77": "#4CAF50", "n78": "#66BB6A", "n79": "#81C784",
    "n5": "#FF9800", "n2": "#2196F3", "n7": "#42A5F5",
    "n25": "#1E88E5", "n12": "#FF5722", "n14": "#E64A19",
    "n71": "#E91E63", "n28": "#F06292",
    "n258": "#9C27B0", "n260": "#AB47BC", "n261": "#BA68C8",
    "B13": "#F44336", "B4": "#2196F3", "B66": "#1976D2",
    "B71": "#E91E63", "B2": "#03A9F4", "B5": "#FF9800",
}

_CC_PALETTE = [
    (30, 120, 200),   # PCell  — blue
    (26, 140, 26),    # SCell1 — green
    (200, 80, 200),   # SCG    — magenta
    (200, 120, 0),    # SCG    — orange
    (0, 180, 180),    # SCG    — cyan
    (180, 30, 30),    # SCG    — red
    (150, 50, 200),   # SCG    — purple
    (100, 100, 100),  # other  — grey
]

MAX_PTS = 300   # max rendered points per series
TPUT_BUCKET_S = 0.5   # throughput bucket width (seconds)


# ── background worker ────────────────────────────────────────────────────────
class PlotWorker(QObject):
    """Computes all plot data off the UI thread."""

    ready = Signal(dict)   # emits a dict of pre-computed arrays

    def __init__(self, session: LogSession, tracker: CATracker):
        super().__init__()
        self._session = session
        self._tracker = tracker

    def run(self):
        result: dict = {}
        session = self._session
        tracker = self._tracker

        try:
            result["events"] = self._compute_events(session, tracker)
            result["throughput"] = self._compute_throughput(session)
            result["per_cc"] = self._compute_per_cc(session, tracker)
            result["rsrp"] = self._compute_rsrp(session)
            result["cqi"] = self._compute_cqi(session)
            result["mcs"] = self._compute_mcs(session)
            result["bler"] = self._compute_bler(session)
            result["timeline"] = self._compute_timeline(tracker, session)
        except Exception as e:
            result["error"] = str(e)

        self.ready.emit(result)

    # ── individual computations ──────────────────────────────────────────────

    def _compute_events(self, session, ca_tracker):
        """Build unified Mobility & CA Events timeline.

        Returns list of events:
        {"t": float (seconds from start), "y": int (lane), "label": str, "color": tuple}
        Lanes: 3=RAT Change, 2=PSCell/HO, 1=SCell Add (RRC), 0=MAC-CE Activate
        """
        if not session.messages:
            return {}

        # Use tech_tracker (on session) for RAT/voice events; ca_tracker for CA
        tech = getattr(session, "tech_tracker", None)

        t0 = session.messages[0].timestamp

        def ts(msg):
            return (msg.timestamp - t0).total_seconds()

        events = []

        # Lane 3: RAT transitions (from TechTransitionTracker on session)
        transitions = getattr(tech, "_transitions", []) if tech else []
        for msg_idx, from_rat, to_rat in transitions:
            if msg_idx < len(session.messages):
                msg = session.messages[msg_idx]
                t = ts(msg)
                label = f"{from_rat} → {to_rat}"
                color = (30, 144, 255) if "5G" in to_rat else (200, 80, 80)
                events.append({"t": t, "y": 3, "label": label, "color": color})

        # Lane 2: HO / PSCell change (RRC reconfig with PSCell or PCell info)
        for msg in session.messages:
            if msg.info and ("PSCell:" in msg.info or "PCell:" in msg.info):
                t = ts(msg)
                label = f"HO/PSCell: {msg.info.split('|')[0].strip()}"
                events.append({"t": t, "y": 2, "label": label, "color": (255, 165, 0)})

        # Lane 1: SCell Add from RRC reconfigurations
        for msg in session.messages:
            if msg.info and "SCell" in msg.info and "PCI" in msg.info:
                if "PSCell" not in msg.info:  # Already in lane 2
                    t = ts(msg)
                    label = f"SCell Add: {msg.info[:60]}"
                    events.append({"t": t, "y": 1, "label": label, "color": (50, 200, 50)})

        # Lane 0: MAC-CE SCell Activation (sampled — show every 5th to avoid overcrowding)
        mac_ce = [m for m in session.messages if "MAC-CE" in m.channel and m.info]
        step = max(1, len(mac_ce) // 60)  # max 60 MAC-CE markers
        for msg in mac_ce[::step]:
            t = ts(msg)
            n_cc = 0
            import re
            m = re.search(r"(\d+)CC active", msg.info)
            if m:
                n_cc = int(m.group(1))
            if n_cc == 0:
                label = "SCell Deactivate"
                color = (200, 50, 50)
            else:
                label = f"MAC-CE: {n_cc}CC active"
                color = (100, 220, 100)
            events.append({"t": t, "y": 0, "label": label, "color": color})

        # Voice events (from TechTransitionTracker)
        voice_events = getattr(tech, "voice_events", []) if tech else []
        for ev in voice_events:
            if ev.msg_index < len(session.messages):
                msg = session.messages[ev.msg_index]
                t = ts(msg)
                if ev.event_type == "setup":
                    label = f"Call Start ({ev.voice_rat})"
                    color = (0, 200, 200)
                elif ev.event_type == "release":
                    label = "Call End"
                    color = (150, 150, 150)
                elif ev.event_type == "ho":
                    label = f"Voice HO: {ev.detail}"
                    color = (255, 140, 0)
                else:
                    label = f"Call {ev.event_type}"
                    color = (255, 80, 80)
                events.append({"t": t, "y": 2.5, "label": label, "color": color})

        # x/y arrays per lane for rendering
        lanes = {
            3: ("RAT Change", (30, 144, 255)),
            2: ("HO / PSCell", (255, 165, 0)),
            1: ("SCell Add (RRC)", (50, 200, 50)),
            0: ("MAC-CE Activate", (100, 200, 100)),
        }

        duration = ts(session.messages[-1]) if len(session.messages) > 1 else 1.0
        return {
            "events": events,
            "duration": duration,
            "lanes": lanes,
            "has_data": len(events) > 0,
        }

    def _compute_throughput(self, session):
        mac_dl = getattr(session, "mac_dl_samples", [])
        mac_ul = getattr(session, "mac_ul_samples", [])
        if not mac_dl:
            return {}

        t0 = mac_dl[0].timestamp
        # bucket → bytes
        dl_b: dict[float, int] = {}
        for s in mac_dl:
            b = round((s.timestamp - t0).total_seconds() / TPUT_BUCKET_S) * TPUT_BUCKET_S
            dl_b[b] = dl_b.get(b, 0) + s.tb_size

        ul_b: dict[float, int] = {}
        for s in mac_ul:
            b = round((s.timestamp - t0).total_seconds() / TPUT_BUCKET_S) * TPUT_BUCKET_S
            ul_b[b] = ul_b.get(b, 0) + s.tb_size

        x_dl = np.array(sorted(dl_b.keys()), dtype=np.float32)
        y_dl = np.array([dl_b[k] * 8 / TPUT_BUCKET_S / 1e6 for k in x_dl], dtype=np.float32)
        x_dl, y_dl = _downsample(x_dl, y_dl)

        ul_result = {}
        if ul_b:
            x_ul = np.array(sorted(ul_b.keys()), dtype=np.float32)
            y_ul = np.array([ul_b[k] * 8 / TPUT_BUCKET_S / 1e6 for k in x_ul], dtype=np.float32)
            x_ul, y_ul = _downsample(x_ul, y_ul)
            ul_result = {"x": x_ul, "y": y_ul}

        peak = float(y_dl.max()) if len(y_dl) else 0
        avg = float(y_dl.mean()) if len(y_dl) else 0
        return {"dl": {"x": x_dl, "y": y_dl}, "ul": ul_result, "peak": peak, "avg": avg}

    def _compute_per_cc(self, session, tracker=None):
        mac_dl = getattr(session, "mac_dl_samples", [])
        cqi_data = getattr(session, "phy_cqi_samples", [])
        if not mac_dl:
            return {}

        # avg CQI per carrier → weight
        from collections import defaultdict
        cqi_by_cc: dict = defaultdict(list)
        for s in cqi_data:
            cqi_by_cc[s.carrier_id].append(s.cqi)
        avg_cqi = {cc: sum(v) / len(v) for cc, v in cqi_by_cc.items() if v}

        if not avg_cqi:
            return {}

        # Limit to top 6 carriers by CQI sample count
        top_cc = sorted(avg_cqi.keys(), key=lambda c: -len(cqi_by_cc[c]))[:6]
        top_cc = sorted(top_cc)  # ascending order for stacking
        total_w = sum(avg_cqi.get(cc, 8) for cc in top_cc)

        t0 = mac_dl[0].timestamp
        total_b: dict[float, float] = {}
        for s in mac_dl:
            b = round((s.timestamp - t0).total_seconds() / TPUT_BUCKET_S) * TPUT_BUCKET_S
            total_b[b] = total_b.get(b, 0) + s.tb_size * 8 / TPUT_BUCKET_S / 1e6

        buckets = sorted(total_b.keys())
        x_all = np.array(buckets, dtype=np.float32)
        y_total = np.array([total_b[b] for b in buckets], dtype=np.float32)

        cc_series = []
        # Build carrier_id → PCI/Band from CA tracker max state
        cc_pci_band: dict[int, str] = {}
        if tracker and tracker._states:
            best = max(tracker._states, key=lambda s: s.num_cc)
            all_cells = []
            if best.pcell:
                all_cells.append(best.pcell)
            if best.pscell:
                all_cells.append(best.pscell)
            all_cells.extend(best.scells)
            for j, cell in enumerate(all_cells):
                if j < len(top_cc):
                    pci_info = ""
                    if cell.pci:
                        pci_info = f" PCI:{cell.pci}"
                    if cell.band:
                        pci_info += f" {cell.band}"
                    cc_pci_band[top_cc[j]] = pci_info

        accumulated = np.zeros(len(x_all), dtype=np.float32)
        for i, cc in enumerate(top_cc):
            w = avg_cqi.get(cc, 8) / total_w
            y_cc = y_total * w
            y_base = accumulated.copy()
            accumulated += y_cc
            # MCG vs SCG label with PCI/Band
            max_cc = max(top_cc)
            scg_thresh = max_cc // 2 if max_cc > 4 else max_cc
            pci_band = cc_pci_band.get(cc, "")
            if i == 0:
                label = f"PCell (MCG){pci_band}"
            elif cc <= scg_thresh:
                label = f"SCell{cc} (MCG){pci_band}"
            elif i == len([c for c in top_cc if c <= scg_thresh]):
                label = f"PSCell{cc} (SCG){pci_band}"
            else:
                label = f"SCell{cc} (SCG){pci_band}"
            xs, yb, yt = _downsample3(x_all, y_base, accumulated.copy())
            cc_series.append({
                "x": xs, "y_base": yb, "y_top": yt,
                "label": label, "color": _CC_PALETTE[i % len(_CC_PALETTE)],
            })

        xt, yt = _downsample(x_all, y_total)
        peak = float(y_total.max()) if len(y_total) else 0
        avg = float(y_total.mean()) if len(y_total) else 0
        return {
            "series": cc_series, "total_x": xt, "total_y": yt,
            "num_cc": len(top_cc), "peak": peak, "avg": avg,
        }

    def _compute_rsrp(self, session):
        phy = getattr(session, "phy_measurements", [])
        if not phy:
            return {}
        from collections import defaultdict
        by_cc: dict = defaultdict(list)
        for m in phy:
            by_cc[m.carrier_id].append(m)
        t0 = phy[0].timestamp
        top = sorted(by_cc.keys(), key=lambda c: -len(by_cc[c]))[:4]
        series = []
        for i, cc in enumerate(sorted(top)):
            samps = by_cc[cc]
            step = max(1, len(samps) // MAX_PTS)
            x = np.array([(s.timestamp - t0).total_seconds() for s in samps[::step]], dtype=np.float32)
            y = np.array([s.rsrp_dbm for s in samps[::step]], dtype=np.float32)
            series.append({"x": x, "y": y, "label": f"CC{cc}",
                           "color": _CC_PALETTE[i % len(_CC_PALETTE)]})
        return {"series": series, "count": len(phy)}

    def _compute_cqi(self, session):
        cqi = getattr(session, "phy_cqi_samples", [])
        if not cqi:
            return {}
        from collections import defaultdict
        by_cc: dict = defaultdict(list)
        for s in cqi:
            by_cc[s.carrier_id].append(s)
        t0 = cqi[0].timestamp
        top = sorted(by_cc.keys(), key=lambda c: -len(by_cc[c]))[:4]
        series = []
        for i, cc in enumerate(sorted(top)):
            samps = by_cc[cc]
            step = max(1, len(samps) // MAX_PTS)
            x = np.array([(s.timestamp - t0).total_seconds() for s in samps[::step]], dtype=np.float32)
            y = np.array([s.cqi for s in samps[::step]], dtype=np.float32)
            series.append({"x": x, "y": y, "label": f"CC{cc}",
                           "color": _CC_PALETTE[i % len(_CC_PALETTE)]})
        return {"series": series, "count": len(cqi)}

    def _compute_mcs(self, session):
        mac = getattr(session, "mac_dl_samples", [])
        if not mac:
            return {}
        t0 = mac[0].timestamp
        step = max(1, len(mac) // MAX_PTS)
        subs = mac[::step]
        x = np.array([(s.timestamp - t0).total_seconds() for s in subs], dtype=np.float32)
        y = np.array([s.mcs for s in subs], dtype=np.float32)
        # MCS-0 markers (capped at 100)
        mcs0_mask = y == 0
        x0 = x[mcs0_mask][:100]
        y0 = y[mcs0_mask][:100]
        return {"x": x, "y": y, "x0": x0, "y0": y0, "count": len(mac)}

    def _compute_bler(self, session):
        harq = getattr(session, "harq_samples", [])
        if not harq:
            return {}
        t0 = harq[0].timestamp
        # 1-second buckets
        buckets: dict[float, list] = {}
        for s in harq:
            b = round((s.timestamp - t0).total_seconds())
            buckets.setdefault(b, []).append(s)
        x_list = sorted(buckets.keys())
        y_list = []
        for b in x_list:
            samps = buckets[b]
            ack = sum(s.ack_count for s in samps)
            nack = sum(s.nack_count for s in samps)
            total = ack + nack
            y_list.append(nack / total * 100.0 if total > 0 else 0.0)
        x = np.array(x_list, dtype=np.float32)
        y = np.array(y_list, dtype=np.float32)
        x, y = _downsample(x, y)
        avg = float(np.mean(y)) if len(y) else 0
        total_nack = sum(s.nack_count for s in harq)
        total = sum(s.ack_count + s.nack_count for s in harq)
        overall = total_nack / total * 100 if total > 0 else 0
        return {"x": x, "y": y, "avg": avg, "overall": overall, "count": len(harq)}

    def _compute_timeline(self, tracker, session):
        rows = []
        msgs = session.messages
        if tracker._states and tracker._states[0].pcell and msgs:
            s = tracker._states[0]
            rows.append((
                msgs[0].timestamp.strftime("%H:%M:%S.%f")[:-3],
                str(s.num_cc),
                f"PCI:{s.pcell.pci} {s.pcell.band}",
                "",
                f"{estimate_throughput_mbps(s):.0f}",
            ))
        for ev in tracker.events:
            s = tracker.get_state_at(ev.msg_index)
            pcell_str = f"PCI:{s.pcell.pci} {s.pcell.band}" if s.pcell else ""
            scell_str = " | ".join(
                f"PCI:{c.pci} {c.band}" for c in s.scells if c.pci
            )
            rows.append((
                ev.timestamp.strftime("%H:%M:%S.%f")[:-3],
                str(s.num_cc), pcell_str, scell_str,
                f"{estimate_throughput_mbps(s):.0f}",
            ))
        return rows


# ── helpers ──────────────────────────────────────────────────────────────────
def _downsample(x: np.ndarray, y: np.ndarray, n: int = MAX_PTS):
    if len(x) <= n:
        return x, y
    idx = np.round(np.linspace(0, len(x) - 1, n)).astype(int)
    return x[idx], y[idx]


def _downsample3(x, yb, yt, n: int = MAX_PTS):
    """Downsample three parallel arrays."""
    if len(x) <= n:
        return x, yb, yt
    idx = np.round(np.linspace(0, len(x) - 1, n)).astype(int)
    return x[idx], yb[idx], yt[idx]


def _make_plot(height: int = 160, legend: bool = False) -> pg.PlotWidget:
    pw = pg.PlotWidget()
    pw.setBackground("#1e1e1e")
    pw.showGrid(x=True, y=True, alpha=0.2)
    pw.setMinimumHeight(height)
    pw.setMaximumHeight(height + 20)
    if legend:
        pw.addLegend(offset=(5, 5), labelTextColor=(200, 200, 200))
    return pw


# ── CC card ──────────────────────────────────────────────────────────────────
class PlotToggleBar(QWidget):
    """A row of toggle chips that show/hide (label, plot) pairs instantly.

    Usage:
        bar = PlotToggleBar()
        bar.add("DL/UL", label_widget, plot_widget, default_on=True)
        bar.add("Per-Carrier", label2, plot2, default_on=True)
        layout.addWidget(bar)
    """

    _ON_STYLE = (
        "QPushButton {{ background: {color}; color: white; border: none; "
        "border-radius: 10px; font-size: 11px; font-weight: bold; "
        "padding: 3px 12px; }}"
        "QPushButton:hover {{ background: {hover}; }}"
    )
    _OFF_STYLE = (
        "QPushButton { background: #2a2a2a; color: #666; border: 1px solid #3a3a3a; "
        "border-radius: 10px; font-size: 11px; padding: 3px 12px; }"
        "QPushButton:hover { background: #333; color: #aaa; border-color: #555; }"
    )
    _COLORS = [
        ("#1565C0", "#0d47a1"),   # blue
        ("#2e7d32", "#1b5e20"),   # green
        ("#6a1b9a", "#4a148c"),   # purple
        ("#e65100", "#bf360c"),   # orange
        ("#00695c", "#004d40"),   # teal
        ("#c62828", "#b71c1c"),   # red
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._layout = QHBoxLayout(self)
        self._layout.setContentsMargins(0, 2, 0, 4)
        self._layout.setSpacing(6)
        self._entries: list[tuple] = []  # (btn, label_w, plot_w, color_idx)
        self._color_idx = 0

    def add(
        self,
        label: str,
        label_widget: QWidget,
        plot_widget: QWidget,
        default_on: bool = True,
    ) -> QPushButton:
        """Register a (label_widget, plot_widget) pair with a toggle chip."""
        idx = self._color_idx % len(self._COLORS)
        self._color_idx += 1
        color, hover = self._COLORS[idx]

        btn = QPushButton(label)
        btn.setCheckable(True)
        btn.setChecked(default_on)
        btn.setFixedHeight(22)
        btn.setSizePolicy(btn.sizePolicy().horizontalPolicy(),
                          btn.sizePolicy().verticalPolicy())

        # Apply initial style
        self._apply_style(btn, default_on, color, hover)

        # Wire toggle
        def _on_toggle(checked, b=btn, lw=label_widget, pw=plot_widget,
                       c=color, h=hover):
            lw.setVisible(checked)
            pw.setVisible(checked)
            self._apply_style(b, checked, c, h)

        btn.toggled.connect(_on_toggle)

        # Set initial visibility
        label_widget.setVisible(default_on)
        plot_widget.setVisible(default_on)

        self._layout.addWidget(btn)
        self._entries.append((btn, label_widget, plot_widget, idx))
        return btn

    def add_stretch(self):
        self._layout.addStretch()

    def _apply_style(self, btn: QPushButton, on: bool, color: str, hover: str):
        if on:
            btn.setStyleSheet(
                self._ON_STYLE.format(color=color, hover=hover)
            )
        else:
            btn.setStyleSheet(self._OFF_STYLE)


class CCCard(QFrame):
    def __init__(self, cell: CellConfig, parent=None):
        super().__init__(parent)
        self.setFrameStyle(QFrame.StyledPanel | QFrame.Raised)
        self.setFixedSize(120, 72)
        color = _BAND_COLORS.get(cell.band, "#607D8B")
        self.setStyleSheet(f"QFrame {{ background: {color}; border-radius: 6px; }}")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 2, 4, 2)
        layout.setSpacing(1)
        for text, size, bold in [
            (cell.cell_type, 8, True),
            (cell.band or f"ARFCN:{cell.arfcn}", 12, True),
            (f"PCI:{cell.pci}" if cell.pci else "", 8, False),
        ]:
            lbl = QLabel(text)
            lbl.setFont(QFont("Menlo", size, QFont.Bold if bold else QFont.Normal))
            lbl.setStyleSheet("color: white;")
            lbl.setAlignment(Qt.AlignCenter)
            layout.addWidget(lbl)


# ── main tab widget ───────────────────────────────────────────────────────────
class PerformanceTab(QWidget):
    """CA & Performance dashboard — tabbed layout, background computation."""

    def __init__(self, parent=None):
        super().__init__()
        self._worker = None
        self._thread = None
        # Store rendered data for hover lookup: {plot_widget → [(x_arr, y_arr, label)]}
        self._hover_data: dict = {}
        self._crosshairs: dict = {}   # plot_widget → InfiniteLine
        self._hover_proxies: list = []  # keep references to prevent GC
        self._setup_ui()

    # ── UI setup ─────────────────────────────────────────────────────────────
    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(6, 6, 6, 6)
        root.setSpacing(4)

        # CC cards row (always visible)
        cards_row = QWidget()
        cards_layout = QHBoxLayout(cards_row)
        cards_layout.setContentsMargins(0, 0, 0, 0)
        self._combo_label = QLabel("No data")
        self._combo_label.setFont(QFont("Menlo", 11, QFont.Bold))
        self._combo_label.setStyleSheet("color: #4CAF50;")
        cards_layout.addWidget(self._combo_label)
        cards_layout.addStretch()
        self._cards_widget = QWidget()
        self._cards_layout = QHBoxLayout(self._cards_widget)
        self._cards_layout.setSpacing(4)
        self._cards_layout.setContentsMargins(0, 0, 0, 0)
        self._cards_layout.addStretch()
        cards_layout.addWidget(self._cards_widget)
        root.addWidget(cards_row)

        # Status label
        self._status_label = QLabel("Load a file to see performance data")
        self._status_label.setStyleSheet("color: #888; font-size: 11px;")
        root.addWidget(self._status_label)

        # Tabs: Throughput | RF Quality | CA Events
        self._tabs = QTabWidget()
        self._tabs.setDocumentMode(True)
        root.addWidget(self._tabs)

        # ── Tab 1: Throughput ────────────────────────────────────────────────
        tput_tab = QWidget()
        tput_layout = QVBoxLayout(tput_tab)
        tput_layout.setSpacing(4)
        tput_layout.setContentsMargins(4, 4, 4, 4)

        # Plot widgets (created before toggle bar so bar can reference them)
        self._tput_label = QLabel("DL/UL Throughput")
        self._tput_label.setStyleSheet("color: #aaa; font-size: 11px;")
        self._tput_plot = _make_plot(200)
        self._tput_plot.setLabel("left", "Mbps", color="#aaa")
        self._tput_plot.setLabel("bottom", "Time (s)", color="#aaa")
        self._tput_plot.addLegend(offset=(5, 5), labelTextColor=(200, 200, 200))

        self._per_cc_label = QLabel("Per-Carrier Throughput  (MCG=blue/green  SCG=purple/orange)")
        self._per_cc_label.setStyleSheet("color: #4CAF50; font-size: 11px; font-weight: bold;")
        self._per_cc_plot = _make_plot(220, legend=True)
        self._per_cc_plot.setLabel("left", "Mbps", color="#aaa")
        self._per_cc_plot.setLabel("bottom", "Time (s)", color="#aaa")

        self._events_label = QLabel("Mobility & CA Events")
        self._events_label.setStyleSheet("color: #aaa; font-size: 11px;")
        self._events_plot = _make_plot(140)
        self._events_plot.setLabel("left", "Event Type", color="#aaa")
        self._events_plot.setLabel("bottom", "Time (s)", color="#aaa")
        # Y-axis tick labels for event lanes
        self._events_plot.getAxis("left").setTicks([
            [(0, "MAC-CE"), (1, "SCell(RRC)"), (2, "HO"), (3, "RAT")]
        ])
        self._events_plot.setYRange(-0.5, 3.5)
        self._events_plot.addLegend(offset=(5, 5), labelTextColor=(200, 200, 200))

        # Toggle bar — Throughput tab
        # Defaults: DL/UL=ON, Per-Carrier=ON, Events=ON
        self._tput_toggle = PlotToggleBar()
        self._tput_toggle.add("DL/UL", self._tput_label, self._tput_plot, default_on=True)
        self._tput_toggle.add("Per-Carrier", self._per_cc_label, self._per_cc_plot, default_on=True)
        self._tput_toggle.add("Events", self._events_label, self._events_plot, default_on=True)
        self._tput_toggle.add_stretch()
        tput_layout.addWidget(self._tput_toggle)

        tput_layout.addWidget(self._tput_label)
        tput_layout.addWidget(self._tput_plot)
        tput_layout.addWidget(self._per_cc_label)
        tput_layout.addWidget(self._per_cc_plot)
        tput_layout.addWidget(self._events_label)
        tput_layout.addWidget(self._events_plot)

        self._tabs.addTab(tput_tab, "Throughput")

        # ── Tab 2: RF Quality ────────────────────────────────────────────────
        rf_tab = QWidget()
        rf_layout = QVBoxLayout(rf_tab)
        rf_layout.setSpacing(4)
        rf_layout.setContentsMargins(4, 4, 4, 4)

        self._rsrp_label = QLabel("PHY RSRP per Carrier (dBm)")
        self._rsrp_label.setStyleSheet("color: #aaa; font-size: 11px;")
        self._rsrp_plot = _make_plot(180, legend=True)
        self._rsrp_plot.setLabel("left", "RSRP (dBm)", color="#aaa")
        self._rsrp_plot.setLabel("bottom", "Time (s)", color="#aaa")
        self._rsrp_plot.addLine(y=-90, pen=pg.mkPen((200, 50, 50), style=Qt.PenStyle.DashLine, width=1))

        self._cqi_label = QLabel("CQI per Carrier (0xB8D1)")
        self._cqi_label.setStyleSheet("color: #aaa; font-size: 11px;")
        self._cqi_plot = _make_plot(160, legend=True)
        self._cqi_plot.setLabel("left", "CQI", color="#aaa")
        self._cqi_plot.setLabel("bottom", "Time (s)", color="#aaa")
        self._cqi_plot.setYRange(0, 16)
        self._cqi_plot.addLine(y=4, pen=pg.mkPen((200, 100, 0), style=Qt.PenStyle.DashLine, width=1))

        self._mcs_label = QLabel("MAC DL MCS Index (0xB8C9)")
        self._mcs_label.setStyleSheet("color: #aaa; font-size: 11px;")
        self._mcs_plot = _make_plot(160)
        self._mcs_plot.setLabel("left", "MCS", color="#aaa")
        self._mcs_plot.setLabel("bottom", "Time (s)", color="#aaa")

        self._bler_label = QLabel("DL HARQ BLER % (from 0xB896)")
        self._bler_label.setStyleSheet("color: #aaa; font-size: 11px;")
        self._bler_plot = _make_plot(160)
        self._bler_plot.setLabel("left", "BLER %", color="#aaa")
        self._bler_plot.setLabel("bottom", "Time (s)", color="#aaa")
        self._bler_plot.addLine(y=10, pen=pg.mkPen((220, 50, 50), style=Qt.PenStyle.DashLine, width=1))
        self._bler_plot.addLine(y=2, pen=pg.mkPen((220, 150, 0), style=Qt.PenStyle.DashLine, width=1))

        # Toggle bar — RF Quality tab
        # Defaults: RSRP=ON, CQI=OFF, MCS=ON, BLER=OFF
        self._rf_toggle = PlotToggleBar()
        self._rf_toggle.add("RSRP", self._rsrp_label, self._rsrp_plot, default_on=True)
        self._rf_toggle.add("CQI", self._cqi_label, self._cqi_plot, default_on=False)
        self._rf_toggle.add("MCS", self._mcs_label, self._mcs_plot, default_on=True)
        self._rf_toggle.add("BLER", self._bler_label, self._bler_plot, default_on=False)
        self._rf_toggle.add_stretch()
        rf_layout.addWidget(self._rf_toggle)

        rf_layout.addWidget(self._rsrp_label)
        rf_layout.addWidget(self._rsrp_plot)
        rf_layout.addWidget(self._cqi_label)
        rf_layout.addWidget(self._cqi_plot)
        rf_layout.addWidget(self._mcs_label)
        rf_layout.addWidget(self._mcs_plot)
        rf_layout.addWidget(self._bler_label)
        rf_layout.addWidget(self._bler_plot)

        self._tabs.addTab(rf_tab, "RF Quality")

        # ── Tab 3: CA Events ─────────────────────────────────────────────────
        ca_tab = QWidget()
        ca_layout = QVBoxLayout(ca_tab)
        ca_layout.setContentsMargins(4, 4, 4, 4)

        self._timeline_table = QTableWidget()
        self._timeline_table.setColumnCount(5)
        self._timeline_table.setHorizontalHeaderLabels(
            ["Time", "CC#", "PCell", "SCells", "Max DL (Mbps)"]
        )
        self._timeline_table.horizontalHeader().setStretchLastSection(True)
        self._timeline_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeToContents
        )
        self._timeline_table.setAlternatingRowColors(True)
        self._timeline_table.setStyleSheet(
            "QTableWidget { background: #1e1e1e; color: #ddd; }"
            "QHeaderView::section { background: #333; color: #ddd; }"
        )
        ca_layout.addWidget(self._timeline_table)
        self._tabs.addTab(ca_tab, "CA Events")

        # Shared hover label (shown at bottom of window)
        self._hover_label = QLabel("")
        self._hover_label.setStyleSheet(
            "color: #80cbc4; font-size: 11px; font-family: Menlo; padding: 2px 6px;"
        )
        self._hover_label.setFixedHeight(18)
        root.addWidget(self._hover_label)

        # Wire crosshairs on all graph plots
        self._setup_hover_on(self._tput_plot,    "DL/UL Throughput")
        self._setup_hover_on(self._per_cc_plot,  "Per-Carrier")
        self._setup_hover_on(self._events_plot,      "Mobility Events")
        self._events_hover_list: list = []  # event list for proximity lookup
        self._setup_hover_on(self._rsrp_plot,    "RSRP")
        self._setup_hover_on(self._cqi_plot,     "CQI")
        self._setup_hover_on(self._mcs_plot,     "MCS")
        self._setup_hover_on(self._bler_plot,    "BLER")

    def _setup_hover_on(self, plot: pg.PlotWidget, name: str):
        """Add crosshair line + tooltip to a plot widget."""
        vline = pg.InfiniteLine(angle=90, movable=False,
                                pen=pg.mkPen((120, 120, 120), width=1,
                                             style=Qt.PenStyle.DashLine))
        vline.setVisible(False)
        plot.addItem(vline, ignoreBounds=True)
        self._crosshairs[plot] = vline

        proxy = pg.SignalProxy(
            plot.scene().sigMouseMoved,
            rateLimit=30,
            slot=lambda ev, pw=plot, nm=name: self._on_hover(ev[0], pw, nm),
        )
        self._hover_proxies.append(proxy)

    def _on_hover(self, pos, plot: pg.PlotWidget, name: str):
        """Update crosshair and tooltip when mouse moves over a plot."""
        if not plot.sceneBoundingRect().contains(pos):
            vline = self._crosshairs.get(plot)
            if vline:
                vline.setVisible(False)
            return

        mouse_point = plot.getPlotItem().vb.mapSceneToView(pos)
        x = mouse_point.x()

        vline = self._crosshairs.get(plot)
        if vline:
            vline.setPos(x)
            vline.setVisible(True)

        import numpy as np
        parts = [f"t={x:.1f}s"]

        # Special case: Events plot — find nearest event and show its label
        if plot is self._events_plot:
            events = getattr(self, "_events_hover_list", [])
            if events:
                nearest = min(events, key=lambda e: abs(e["t"] - x), default=None)
                if nearest and abs(nearest["t"] - x) < 10:
                    lane_names = {0: "MAC-CE", 1: "SCell(RRC)", 2: "HO", 3: "RAT Change"}
                    lane = lane_names.get(int(nearest["y"]), "Event")
                    parts.append(f"{lane}: {nearest['label']}")
                    # Also show nearby events within ±5s
                    nearby = [e for e in events if abs(e["t"] - x) < 5 and e is not nearest][:3]
                    for e in nearby:
                        parts.append(e["label"][:40])
            self._hover_label.setText(f"  Events  |  " + "  ·  ".join(parts))
            return

        # Standard series hover
        series_list = self._hover_data.get(plot, [])
        for x_arr, y_arr, label, unit in series_list:
            if len(x_arr) == 0:
                continue
            idx = int(np.argmin(np.abs(x_arr - x)))
            val = y_arr[idx]
            parts.append(f"{label}: {val:.1f}{unit}")

        self._hover_label.setText(f"  {name}  |  " + "  ·  ".join(parts))

    def _register_hover(self, plot: pg.PlotWidget, x_arr, y_arr,
                        label: str, unit: str = ""):
        """Register a data series for hover tooltip lookup."""
        import numpy as np
        if plot not in self._hover_data:
            self._hover_data[plot] = []
        self._hover_data[plot].append((
            np.asarray(x_arr, dtype=np.float32),
            np.asarray(y_arr, dtype=np.float32),
            label, unit,
        ))

    # ── public API ────────────────────────────────────────────────────────────
    def load_session(self, session: LogSession):
        """Start background computation then populate all plots."""
        # Increment session counter — stale worker results check this
        self._session_id = getattr(self, "_session_id", 0) + 1
        current_id = self._session_id

        self._status_label.setText("Computing plots…")

        # Clear all plots and hover data immediately
        for plot in (self._tput_plot, self._per_cc_plot, self._events_plot,
                     self._rsrp_plot, self._cqi_plot, self._mcs_plot, self._bler_plot):
            plot.clear()
        self._timeline_table.setRowCount(0)
        self._hover_data.clear()
        self._hover_label.setText("")

        tracker = CATracker()
        tracker.build_from_messages(session.messages)
        self._update_cards(tracker)

        # Disconnect + kill any previous worker to avoid stale signal delivery
        if self._worker is not None:
            try:
                self._worker.ready.disconnect()
            except Exception:
                pass
        if self._thread and self._thread.isRunning():
            self._thread.quit()
            self._thread.wait(200)

        self._thread = QThread()
        self._worker = PlotWorker(session, tracker)
        self._worker.moveToThread(self._thread)

        # Capture current_id in closure so stale results are silently dropped
        def _guarded_ready(data, sid=current_id):
            if getattr(self, "_session_id", 0) == sid:
                self._on_data_ready(data)

        self._worker.ready.connect(_guarded_ready)
        self._thread.started.connect(self._worker.run)
        self._thread.start()

    # ── slots ─────────────────────────────────────────────────────────────────
    def _on_data_ready(self, data: dict):
        """Called on UI thread when worker has finished (guarded against stale results)."""
        if self._thread:
            self._thread.quit()

        if "error" in data:
            self._status_label.setText(f"Error: {data['error']}")
            return

        self._render_events(data.get("events", {}))
        self._render_throughput(data.get("throughput", {}))
        self._render_per_cc(data.get("per_cc", {}))
        self._render_rsrp(data.get("rsrp", {}))
        self._render_cqi(data.get("cqi", {}))
        self._render_mcs(data.get("mcs", {}))
        self._render_bler(data.get("bler", {}))
        self._render_timeline(data.get("timeline", []))
        self._status_label.setText("")

    # ── render methods (UI thread, fast — just plot() calls) ─────────────────
    def _render_throughput(self, d: dict):
        self._tput_plot.clear()
        if not d:
            self._tput_label.setText("DL/UL — No MAC TB data")
            return
        dl = d.get("dl", {})
        ul = d.get("ul", {})
        if "x" in dl:
            self._tput_plot.plot(
                dl["x"], dl["y"],
                pen=pg.mkPen((26, 180, 26), width=2),
                fillLevel=0, fillBrush=pg.mkBrush(26, 180, 26, 35),
                name="DL",
            )
            self._register_hover(self._tput_plot, dl["x"], dl["y"], "DL", " Mbps")
        if "x" in ul:
            self._tput_plot.plot(
                ul["x"], ul["y"],
                pen=pg.mkPen((200, 120, 0), width=1.5),
                name="UL",
            )
            self._register_hover(self._tput_plot, ul["x"], ul["y"], "UL", " Mbps")
        self._tput_label.setText(
            f"DL/UL Throughput  —  Peak: {d['peak']:.0f} Mbps  Avg: {d['avg']:.0f} Mbps"
        )

    def _render_per_cc(self, d: dict):
        self._per_cc_plot.clear()
        if not d or not d.get("series"):
            self._per_cc_label.setText("Per-Carrier — No CQI data for weighting")
            return

        for s in d["series"]:
            c = s["color"]
            # Filled band between base and top
            fill = pg.FillBetweenItem(
                pg.PlotDataItem(s["x"], s["y_base"]),
                pg.PlotDataItem(s["x"], s["y_top"]),
                brush=pg.mkBrush((*c, 100)),
            )
            self._per_cc_plot.addItem(fill)
            self._per_cc_plot.plot(
                s["x"], s["y_top"],
                pen=pg.mkPen(c, width=1.5),
                name=s["label"],
            )

        self._per_cc_plot.plot(
            d["total_x"], d["total_y"],
            pen=pg.mkPen((220, 220, 220), width=2, style=Qt.PenStyle.DashLine),
            name=f"Total ({d['num_cc']}CC)",
        )
        # Register each carrier for hover
        for s in d["series"]:
            self._register_hover(self._per_cc_plot, s["x"], s["y_top"],
                                 s["label"].split(" (")[0], " Mbps")
        self._register_hover(self._per_cc_plot, d["total_x"], d["total_y"],
                             f"Total ({d['num_cc']}CC)", " Mbps")
        self._per_cc_label.setText(
            f"Per-Carrier  [{d['num_cc']}CC]  Peak: {d['peak']:.0f} Mbps  "
            f"Avg: {d['avg']:.0f} Mbps  (MCG=blue/green  SCG=purple/orange)"
        )

    def _render_events(self, d: dict):
        """Render Mobility & CA Events timeline as a swim-lane scatter plot."""
        self._events_plot.clear()
        if not d or not d.get("has_data"):
            self._events_label.setText("Mobility & CA Events — No events detected")
            return

        events = d["events"]
        # Group by color and render as scatter
        from collections import defaultdict
        color_groups: dict = defaultdict(lambda: {"x": [], "y": []})
        for ev in events:
            key = ev["color"]
            color_groups[key]["x"].append(ev["t"])
            color_groups[key]["y"].append(ev["y"])

        # Build scatter items per unique color (one per lane type)
        lane_labels = {0: "MAC-CE", 1: "SCell RRC", 2: "HO", 3: "RAT Change"}
        lane_colors = {
            0: (100, 220, 100),   # green — MAC-CE
            1: (50, 200, 50),     # darker green — SCell RRC
            2: (255, 165, 0),     # orange — HO
            3: (30, 144, 255),    # blue — RAT
        }
        for lane_y, lane_name in lane_labels.items():
            xs = [ev["t"] for ev in events if int(ev["y"]) == lane_y]
            ys = [ev["y"] for ev in events if int(ev["y"]) == lane_y]
            if xs:
                color = lane_colors[lane_y]
                sc = pg.ScatterPlotItem(
                    xs, ys, size=10,
                    pen=pg.mkPen(None),
                    brush=pg.mkBrush(*color, 200),
                    symbol="o" if lane_y in (0, 3) else "t" if lane_y == 1 else "s",
                    name=lane_name,
                )
                self._events_plot.addItem(sc)

        # Voice events (lane 2.5) — star shape
        voice_xs = [ev["t"] for ev in events if abs(ev["y"] - 2.5) < 0.1]
        voice_ys = [ev["y"] for ev in events if abs(ev["y"] - 2.5) < 0.1]
        if voice_xs:
            sc = pg.ScatterPlotItem(
                voice_xs, voice_ys, size=12,
                pen=pg.mkPen(None),
                brush=pg.mkBrush(0, 220, 220, 220),
                symbol="star", name="Voice",
            )
            self._events_plot.addItem(sc)

        # Store event lookup for hover
        self._events_hover_list = events  # for tooltip lookup
        self._events_plot.setYRange(-0.5, 3.7)

        n_total = len(events)
        n_ho = sum(1 for e in events if e["y"] == 2)
        n_rat = sum(1 for e in events if e["y"] == 3)
        n_scell = sum(1 for e in events if e["y"] in (0, 1))
        self._events_label.setText(
            f"Mobility & CA Events — {n_total} total  |  "
            f"HO:{n_ho}  RAT-change:{n_rat}  SCell:{n_scell}"
        )

    def _render_rsrp(self, d: dict):
        self._rsrp_plot.clear()
        if not d or not d.get("series"):
            self._rsrp_label.setText("PHY RSRP — Not available (log 0xB883 absent — iPhone signaling-only capture)")
            return
        for s in d["series"]:
            self._rsrp_plot.plot(
                s["x"], s["y"],
                pen=pg.mkPen(s["color"], width=1.5),
                name=s["label"],
            )
            self._register_hover(self._rsrp_plot, s["x"], s["y"],
                                 s["label"], " dBm")
        self._rsrp_label.setText(f"PHY RSRP — {d['count']:,} samples")

    def _render_cqi(self, d: dict):
        self._cqi_plot.clear()
        if not d or not d.get("series"):
            self._cqi_label.setText("CQI — Not available (log 0xB8D1 absent — PHY layer not captured)")
            return
        for s in d["series"]:
            self._cqi_plot.plot(
                s["x"], s["y"],
                pen=pg.mkPen(s["color"], width=1.5),
                name=s["label"],
            )
            self._register_hover(self._cqi_plot, s["x"], s["y"],
                                 s["label"], "")
        self._cqi_label.setText(f"CQI per Carrier — {d['count']:,} samples")

    def _render_mcs(self, d: dict):
        self._mcs_plot.clear()
        if not d or "x" not in d:
            self._mcs_label.setText("MCS — Not available (log 0xB8C9 absent — MAC layer not captured)")
            return
        self._mcs_plot.plot(d["x"], d["y"], pen=pg.mkPen((80, 130, 220), width=1))
        self._register_hover(self._mcs_plot, d["x"], d["y"], "MCS", "")
        if len(d["x0"]):
            sc = pg.ScatterPlotItem(
                d["x0"], d["y0"], size=5,
                pen=pg.mkPen(None),
                brush=pg.mkBrush(220, 50, 50, 180),
            )
            self._mcs_plot.addItem(sc)
        self._mcs_label.setText(f"MAC DL MCS — {d['count']:,} samples")

    def _render_bler(self, d: dict):
        self._bler_plot.clear()
        if not d or "x" not in d:
            self._bler_label.setText("HARQ BLER — Not available (log 0xB896 absent)")
            return
        pen = pg.mkPen((220, 80, 80), width=1.5)
        self._bler_plot.plot(d["x"], d["y"], pen=pen,
                             fillLevel=0, fillBrush=pg.mkBrush(220, 80, 80, 30))
        self._register_hover(self._bler_plot, d["x"], d["y"], "BLER", "%")
        self._bler_label.setText(
            f"DL HARQ BLER — Overall: {d['overall']:.2f}%  "
            f"Avg per bucket: {d['avg']:.2f}%  "
            f"({d['count']:,} HARQ reports)"
        )

    def _render_timeline(self, rows: list):
        self._timeline_table.setRowCount(len(rows))
        for ri, row in enumerate(rows):
            for ci, val in enumerate(row):
                item = QTableWidgetItem(val)
                if ci == 4:
                    item.setFont(QFont("Menlo", 10, QFont.Bold))
                self._timeline_table.setItem(ri, ci, item)

    def _update_cards(self, tracker: CATracker):
        while self._cards_layout.count() > 1:
            item = self._cards_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        max_state = max(tracker._states, key=lambda s: s.num_cc, default=None) if tracker._states else None
        if not max_state:
            self._combo_label.setText("No CA data")
            return

        cells = []
        if max_state.pcell:
            cells.append(max_state.pcell)
        if max_state.pscell:
            cells.append(max_state.pscell)
        cells.extend(max_state.scells)

        for cell in cells:
            card = CCCard(cell)
            self._cards_layout.insertWidget(self._cards_layout.count() - 1, card)

        tp = estimate_throughput_mbps(max_state)
        self._combo_label.setText(
            f"{max_state.combo_str}  |  Max DL: ~{tp:.0f} Mbps"
        )
