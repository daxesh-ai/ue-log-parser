"""Message list table model — QAbstractTableModel backed by LogSession."""

from __future__ import annotations

try:
    from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
    from PySide6.QtGui import QColor
except ImportError:
    from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt
    from PyQt6.QtGui import QColor

from logparser.core.enums import Severity
from logparser.core.message import ParsedMessage
from logparser.core.session import LogSession

COLUMNS = ["RAT", "#", "Timestamp", "Protocol", "Dir", "Channel", "Summary", "Info"]

_SEVERITY_COLORS = {
    Severity.FAILURE: QColor(180, 40, 40),     # Dark red — rejects, timeouts, call drops
    Severity.WARNING: QColor(180, 120, 30),    # Dark orange — reestablishment, release
    Severity.INFO: QColor(40, 60, 120),        # Dark blue — info
}

# RAT/Tech state → color for the RAT column
_RAT_COLORS = {
    "5G SA": QColor(0, 180, 0),         # Green
    "5G NR": QColor(0, 180, 0),         # Green
    "5G NSA": QColor(0, 140, 0),        # Dark green
    "5G NSA (EN-DC)": QColor(0, 140, 0),
    "LTE": QColor(30, 120, 200),        # Blue
    "LTE (EPSFB)": QColor(200, 120, 0), # Orange
    "LTE (Depri)": QColor(200, 50, 50), # Red
    "WiFi": QColor(0, 180, 220),        # Cyan
    "WiFi (ePDG)": QColor(0, 180, 220),
    "VoNR": QColor(0, 200, 0),          # Bright green
    "VoLTE": QColor(30, 140, 220),      # Blue
    "VoWiFi": QColor(0, 200, 220),      # Cyan
    "IMS": QColor(150, 80, 200),        # Purple for IMS/SIP
}


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
        """Find the row number for a given message index, or -1 if not visible."""
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

        if role == Qt.DisplayRole:
            if col == 0:
                # RAT column — show short tech label
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
                return msg.summary
            elif col == 7:
                return msg.info

        elif role == Qt.BackgroundRole:
            # RAT column gets colored background
            if col == 0:
                return self._get_rat_color(msg.index)
            # Severity colors for other columns
            color = _SEVERITY_COLORS.get(msg.severity)
            if color:
                return color

        elif role == Qt.ForegroundRole:
            if col == 0:
                return QColor(255, 255, 255)  # White text on colored RAT cell
            # Highlight SRB3 channel column in magenta
            if col == 5 and msg.bearer_id == 3:
                return QColor(255, 100, 255)  # Magenta for SRB3

        elif role == Qt.ToolTipRole:
            parts = []
            if msg.bearer_id == 3:
                parts.append("⚡ SRB3 — Direct gNB-to-UE link (NR-DC/EN-DC)")
            if msg.annotations:
                parts.extend(msg.annotations)
            if msg.info:
                parts.append(msg.info)
            if msg.pci:
                parts.append(f"Sub-header PCI: {msg.pci}")
            if msg.arfcn:
                parts.append(f"Sub-header ARFCN: {msg.arfcn}")
            if msg.bearer_id >= 0:
                srb_name = {0: "SRB0", 1: "SRB1", 2: "SRB2", 3: "SRB3"}.get(msg.bearer_id, f"RB{msg.bearer_id}")
                parts.append(f"Bearer: {srb_name}")
            return "\n".join(parts) if parts else None

        return None

    @staticmethod
    def _get_channel_display(msg: ParsedMessage) -> str:
        """Format channel with SRB indicator for NR RRC messages."""
        if msg.bearer_id >= 0 and msg.protocol.name == "NR_RRC":
            srb_name = {0: "SRB0", 1: "SRB1", 2: "SRB2", 3: "SRB3"}.get(msg.bearer_id)
            if srb_name:
                return f"{msg.channel} ({srb_name})"
        return msg.channel

    def _get_rat_label(self, msg_index: int) -> str:
        """Get short RAT label for display."""
        if not self._tech_tracker:
            return ""
        state = self._tech_tracker.get_state_at(msg_index)
        tech = state.tech
        voice = state.voice

        # Prefer voice state if active
        if voice and voice != "Idle":
            if "VoNR" in voice:
                return "VoNR"
            elif "VoLTE" in voice:
                return "VoLTE"
            elif "VoWiFi" in voice:
                return "VoWiFi"
            elif "EPSFB" in voice:
                return "EPSFB"
            elif "IMS" in voice or "Call" in voice:
                return "IMS"

        # Tech state
        if "5G SA" in tech or "5G NR" in tech:
            return "NR"
        elif "NSA" in tech or "EN-DC" in tech:
            return "NSA"
        elif "WiFi" in tech or "ePDG" in tech:
            return "WiFi"
        elif "EPSFB" in tech:
            return "EPSFB"
        elif "Depri" in tech:
            return "Depri"
        elif "LTE" in tech:
            return "LTE"
        return ""

    def _get_rat_color(self, msg_index: int) -> QColor | None:
        """Get background color for RAT column."""
        if not self._tech_tracker:
            return None
        state = self._tech_tracker.get_state_at(msg_index)
        tech = state.tech
        voice = state.voice

        # Voice states take priority for color
        if voice and voice != "Idle":
            for key, color in _RAT_COLORS.items():
                if key in voice:
                    return color

        # Tech states
        for key, color in _RAT_COLORS.items():
            if key in tech:
                return color

        return QColor(60, 60, 60)  # Dark gray for unknown
