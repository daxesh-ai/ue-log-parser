"""Message list table model — QAbstractTableModel backed by LogSession."""

from __future__ import annotations

try:
    from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
    from PySide6.QtGui import QColor, QFont
except ImportError:
    from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt
    from PyQt6.QtGui import QColor, QFont

from logparser.core.enums import Severity
from logparser.core.message import ParsedMessage
from logparser.core.session import LogSession

COLUMNS = ["RAT", "#", "Timestamp", "Protocol", "Dir", "Channel", "Summary", "Info"]

# ── Severity — used as row background tint on top of protocol color ──────────
_SEVERITY_COLORS = {
    Severity.FAILURE: QColor(180, 40, 40),
    Severity.WARNING: QColor(180, 120, 30),
    Severity.INFO:    QColor(40, 60, 120),
}

# ── Per-protocol row background tints (XCAL-style) ───────────────────────────
_PROTOCOL_ROW_COLORS = {
    "NR_RRC":   QColor(0,  55, 25),   # dark green tint
    "LTE_RRC":  QColor(0,  25, 75),   # dark blue tint
    "NR_NAS":   QColor(25, 50, 75),   # blue-green
    "LTE_NAS":  QColor(0,  45, 65),   # teal
    "S1AP":     QColor(45, 25, 75),   # purple
    "NGAP":     QColor(55, 25, 75),   # purple
    "SIP":      QColor(65, 15, 55),   # magenta/pink
    "UNKNOWN":  QColor(30, 30, 30),   # near-black for MAC-CE etc.
}

# Severity overlay: adds these RGB deltas to the protocol color
_SEVERITY_OVERLAY = {
    Severity.FAILURE: (120, -20, -20),   # push red up
    Severity.WARNING: (100,  40, -30),   # push orange
}

# ── RAT chip colors ───────────────────────────────────────────────────────────
_RAT_COLORS = {
    "5G SA": QColor(0, 180, 0),
    "5G NR": QColor(0, 180, 0),
    "5G NSA": QColor(0, 140, 0),
    "5G NSA (EN-DC)": QColor(0, 140, 0),
    "LTE": QColor(30, 120, 200),
    "LTE (EPSFB)": QColor(200, 120, 0),
    "LTE (Depri)": QColor(200, 50, 50),
    "WiFi": QColor(0, 180, 220),
    "WiFi (ePDG)": QColor(0, 180, 220),
    "VoNR":  QColor(0, 200, 0),
    "VoLTE": QColor(30, 140, 220),
    "VoWiFi": QColor(0, 200, 220),
    "IMS":   QColor(150, 80, 200),
}

# ── Protocol prefix labels (XCAL vH20 / vH40 style) ─────────────────────────
_PROTOCOL_PREFIX = {
    "NR_RRC":  "5GNR ",
    "LTE_RRC": "LTE ",
    "NR_NAS":  "5GMM ",
    "LTE_NAS": "EPS ",
    "S1AP":    "S1AP ",
    "NGAP":    "NGAP ",
    "SIP":     "SIP ",
}

# ── String color highlighting (XCAL String Color Setting) ────────────────────
# Maps lowercase keyword → foreground QColor for Summary column
STRING_COLORS: dict[str, QColor] = {
    "handover":       QColor(255, 220, 50),   # yellow
    "reject":         QColor(255, 100, 100),  # red
    "deprioritised":  QColor(255, 160, 0),    # orange
    "srvcc":          QColor(0,   220, 220),  # cyan
    "failure":        QColor(255, 100, 100),  # red
    "failed":         QColor(255, 100, 100),  # red
    "reestablishment":QColor(255, 160, 80),   # orange
    "release":        QColor(180, 180, 180),  # light gray
    "rrcsetup":       QColor(120, 220, 120),  # light green
    "registration":   QColor(120, 200, 255),  # light blue
    "vonr":           QColor(100, 255, 100),  # bright green
    "volte":          QColor(80,  160, 255),  # blue
    "vowifi":         QColor(0,   220, 220),  # cyan
    "scgfailure":     QColor(255, 80,  80),   # red
}


def _blend_color(base: QColor, overlay: tuple[int, int, int]) -> QColor:
    """Clamp-blend RGB delta onto base color."""
    r = max(0, min(255, base.red()   + overlay[0]))
    g = max(0, min(255, base.green() + overlay[1]))
    b = max(0, min(255, base.blue()  + overlay[2]))
    return QColor(r, g, b)


class MessageTableModel(QAbstractTableModel):
    """Virtual table model for the message list."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._session: LogSession | None = None
        self._filtered: list[ParsedMessage] | None = None
        self._tech_tracker = None

    def set_session(self, session: LogSession) -> None:
        self.beginResetModel()
        self._session = session
        self._filtered = None
        self._tech_tracker = getattr(session, "tech_tracker", None)
        self.endResetModel()

    def set_filtered(self, messages: list[ParsedMessage] | None) -> None:
        self.beginResetModel()
        self._filtered = messages
        self.endResetModel()

    @property
    def _messages(self) -> list[ParsedMessage]:
        if self._filtered is not None:
            return self._filtered
        if self._session:
            return self._session.messages
        return []

    def get_message(self, row: int) -> ParsedMessage | None:
        msgs = self._messages
        if 0 <= row < len(msgs):
            return msgs[row]
        return None

    def row_for_index(self, msg_index: int) -> int:
        for row, msg in enumerate(self._messages):
            if msg.index == msg_index:
                return row
        return -1

    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self._messages)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return COLUMNS[section]
        return None

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid():
            return None

        msg = self._messages[index.row()]
        col = index.column()

        # ── Display ───────────────────────────────────────────────────────────
        if role == Qt.DisplayRole:
            if col == 0:
                return self._get_rat_label(msg.index)
            elif col == 1:
                return msg.index
            elif col == 2:
                return msg.timestamp.strftime("%H:%M:%S.%f")[:-3]
            elif col == 3:
                return msg.protocol.name
            elif col == 4:
                return msg.direction.value
            elif col == 5:
                return self._get_channel_display(msg)
            elif col == 6:
                # XCAL-style: prepend protocol version prefix
                prefix = _PROTOCOL_PREFIX.get(msg.protocol.name, "")
                return prefix + msg.summary
            elif col == 7:
                return msg.info

        # ── Background — protocol tint + severity overlay ────────────────────
        elif role == Qt.BackgroundRole:
            if col == 0:
                return self._get_rat_color(msg.index)

            # Protocol base color
            proto_name = msg.protocol.name
            # MAC-CE and other non-protocol messages
            if msg.channel == "MAC-CE":
                base = QColor(45, 35, 0)   # dark amber for MAC-CE
            elif msg.channel in ("S1AP", "PFCP", "GTP", "Diameter", "NGAP"):
                base = _PROTOCOL_ROW_COLORS.get(msg.channel,
                       _PROTOCOL_ROW_COLORS.get(proto_name,
                       _PROTOCOL_ROW_COLORS["UNKNOWN"]))
            else:
                base = _PROTOCOL_ROW_COLORS.get(proto_name,
                       _PROTOCOL_ROW_COLORS["UNKNOWN"])

            # Severity overlay
            overlay = _SEVERITY_OVERLAY.get(msg.severity)
            if overlay:
                return _blend_color(base, overlay)
            return base

        # ── Foreground ────────────────────────────────────────────────────────
        elif role == Qt.ForegroundRole:
            if col == 0:
                return QColor(255, 255, 255)
            if col == 5 and msg.bearer_id == 3:
                return QColor(255, 100, 255)   # SRB3 magenta
            # String color highlighting for Summary column
            if col == 6:
                summary_lower = (msg.summary or "").lower()
                for keyword, color in STRING_COLORS.items():
                    if keyword in summary_lower:
                        return color
            # Failure text: bright red; Warning: bright orange
            if msg.severity == Severity.FAILURE:
                return QColor(255, 140, 140)
            elif msg.severity == Severity.WARNING:
                return QColor(255, 200, 100)

        # ── Font — bold for failures ──────────────────────────────────────────
        elif role == Qt.FontRole:
            if msg.severity == Severity.FAILURE:
                f = QFont()
                f.setBold(True)
                return f

        # ── Tooltip ───────────────────────────────────────────────────────────
        elif role == Qt.ToolTipRole:
            parts = []
            if msg.bearer_id == 3:
                parts.append("⚡ SRB3 — Direct gNB-to-UE link (NR-DC/EN-DC)")
            if msg.annotations:
                parts.extend(msg.annotations)
            if msg.info:
                parts.append(msg.info)
            if msg.pci:
                parts.append(f"PCI: {msg.pci}")
            if msg.arfcn:
                parts.append(f"ARFCN: {msg.arfcn}")
            if msg.bearer_id >= 0:
                srb_name = {0: "SRB0", 1: "SRB1", 2: "SRB2", 3: "SRB3"}.get(
                    msg.bearer_id, f"RB{msg.bearer_id}"
                )
                parts.append(f"Bearer: {srb_name}")
            return "\n".join(parts) if parts else None

        return None

    @staticmethod
    def _get_channel_display(msg: ParsedMessage) -> str:
        if msg.bearer_id >= 0 and msg.protocol.name == "NR_RRC":
            srb_name = {0: "SRB0", 1: "SRB1", 2: "SRB2", 3: "SRB3"}.get(msg.bearer_id)
            if srb_name:
                return f"{msg.channel} ({srb_name})"
        return msg.channel

    def _get_rat_label(self, msg_index: int) -> str:
        if not self._tech_tracker:
            return ""
        state = self._tech_tracker.get_state_at(msg_index)
        tech = state.tech
        voice = state.voice

        if voice and voice != "Idle":
            if "VoNR"  in voice: return "VoNR"
            if "VoLTE" in voice: return "VoLTE"
            if "VoWiFi"in voice: return "VoWiFi"
            if "EPSFB" in voice: return "EPSFB"
            if "IMS"   in voice or "Call" in voice: return "IMS"

        if "5G SA" in tech or "5G NR" in tech: return "NR"
        if "NSA"   in tech or "EN-DC" in tech: return "NSA"
        if "WiFi"  in tech or "ePDG"  in tech: return "WiFi"
        if "EPSFB" in tech: return "EPSFB"
        if "Depri" in tech: return "Depri"
        if "LTE"   in tech: return "LTE"
        return ""

    def _get_rat_color(self, msg_index: int) -> QColor | None:
        if not self._tech_tracker:
            return None
        state = self._tech_tracker.get_state_at(msg_index)
        for key, color in _RAT_COLORS.items():
            if key in state.voice and state.voice != "Idle":
                return color
        for key, color in _RAT_COLORS.items():
            if key in state.tech:
                return color
        return QColor(60, 60, 60)
