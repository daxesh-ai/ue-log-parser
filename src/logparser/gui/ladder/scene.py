"""Ladder diagram (sequence diagram) using QGraphicsScene."""

from __future__ import annotations

try:
    from PySide6.QtCore import Qt, QRectF, Signal
    from PySide6.QtGui import QColor, QFont, QPen, QBrush, QPainterPath
    from PySide6.QtWidgets import QGraphicsScene, QGraphicsItem, QGraphicsLineItem, QGraphicsSceneMouseEvent
except ImportError:
    from PyQt6.QtCore import Qt, QRectF
    from PyQt6.QtCore import pyqtSignal as Signal
    from PyQt6.QtGui import QColor, QFont, QPen, QBrush, QPainterPath
    from PyQt6.QtWidgets import QGraphicsScene, QGraphicsItem, QGraphicsLineItem, QGraphicsSceneMouseEvent

from logparser.core.message import ParsedMessage
from logparser.core.session import LogSession

ENTITY_SPACING = 250
ROW_HEIGHT = 28
HEADER_HEIGHT = 40
ARROW_HEAD_SIZE = 8
ENTITY_LINE_COLOR = QColor(80, 80, 80)
ARROW_COLOR = QColor(180, 180, 180)
HIGHLIGHT_COLOR = QColor(50, 180, 255)
LABEL_FONT = QFont("Menlo", 8)


class ArrowItem(QGraphicsItem):
    """A horizontal arrow representing one message between entities."""

    def __init__(self, src_x: float, dst_x: float, y: float, label: str, msg_index: int):
        super().__init__()
        self._src_x = src_x
        self._dst_x = dst_x
        self._y = y
        self._label = label
        self._msg_index = msg_index
        self._highlighted = False
        self.setFlag(QGraphicsItem.ItemIsSelectable, True)

    @property
    def msg_index(self) -> int:
        return self._msg_index

    def set_highlighted(self, highlighted: bool) -> None:
        self._highlighted = highlighted
        self.update()

    def boundingRect(self) -> QRectF:
        left = min(self._src_x, self._dst_x) - 10
        right = max(self._src_x, self._dst_x) + 10
        return QRectF(left, self._y - 12, right - left, 24)

    def paint(self, painter, option, widget=None):
        pen_color = HIGHLIGHT_COLOR if self._highlighted else ARROW_COLOR
        pen = QPen(pen_color, 2 if self._highlighted else 1)
        painter.setPen(pen)

        # Draw line
        painter.drawLine(int(self._src_x), int(self._y), int(self._dst_x), int(self._y))

        # Draw arrowhead at destination
        direction = 1 if self._dst_x > self._src_x else -1
        ax = self._dst_x - direction * ARROW_HEAD_SIZE
        painter.drawLine(
            int(self._dst_x), int(self._y),
            int(ax), int(self._y - ARROW_HEAD_SIZE / 2),
        )
        painter.drawLine(
            int(self._dst_x), int(self._y),
            int(ax), int(self._y + ARROW_HEAD_SIZE / 2),
        )

        # Draw label above arrow (use pen color for visibility on dark bg)
        painter.setFont(LABEL_FONT)
        painter.setPen(QPen(QColor(200, 200, 200) if not self._highlighted else HIGHLIGHT_COLOR))
        mid_x = (self._src_x + self._dst_x) / 2
        painter.drawText(int(mid_x - 60), int(self._y - 4), self._label)


class LadderScene(QGraphicsScene):
    """Sequence diagram scene with entity lines and message arrows."""

    # Emitted when user clicks an arrow — carries the message index
    message_clicked = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._entities: list[str] = []
        self._entity_x: dict[str, float] = {}
        self._arrows: dict[int, ArrowItem] = {}
        self._highlighted_index: int = -1

    def build_from_session(self, session: LogSession) -> None:
        self.clear()
        self._arrows.clear()
        self.setBackgroundBrush(QBrush(QColor(30, 30, 30)))

        # Determine entities from messages
        entities_set: set[str] = set()
        for msg in session.messages:
            entities_set.add(msg.source_entity)
            entities_set.add(msg.target_entity)

        # Order: UE first, then network entities
        order = ["UE", "gNB", "eNB", "AMF", "MME", "P-CSCF", "SMF", "UPF", "HSS", "IMS-MGW"]
        self._entities = [e for e in order if e in entities_set]
        for e in entities_set:
            if e not in self._entities:
                self._entities.append(e)

        # Calculate X positions
        for i, entity in enumerate(self._entities):
            self._entity_x[entity] = 80 + i * ENTITY_SPACING

        total_height = HEADER_HEIGHT + len(session.messages) * ROW_HEIGHT + 40

        # Draw entity header labels (white for dark theme)
        header_font = QFont("Menlo", 10, QFont.Bold)
        for entity in self._entities:
            x = self._entity_x[entity]
            text = self.addText(entity, header_font)
            text.setDefaultTextColor(QColor(220, 220, 220))
            text.setPos(x - text.boundingRect().width() / 2, 5)

        # Draw vertical entity lines
        pen = QPen(ENTITY_LINE_COLOR, 1, Qt.PenStyle.DashLine)
        for entity in self._entities:
            x = self._entity_x[entity]
            line = self.addLine(x, HEADER_HEIGHT, x, total_height, pen)

        # Draw message arrows
        for msg in session.messages:
            y = HEADER_HEIGHT + msg.index * ROW_HEIGHT + ROW_HEIGHT / 2
            src_x = self._entity_x.get(msg.source_entity, 80)
            dst_x = self._entity_x.get(msg.target_entity, 80 + ENTITY_SPACING)

            if src_x == dst_x:
                dst_x += 30  # Self-message offset

            arrow = ArrowItem(src_x, dst_x, y, msg.summary, msg.index)
            self.addItem(arrow)
            self._arrows[msg.index] = arrow

        self.setSceneRect(
            0, 0,
            80 + len(self._entities) * ENTITY_SPACING + 80,
            total_height,
        )

    def mousePressEvent(self, event) -> None:
        """Emit message_clicked when user clicks an arrow."""
        item = self.itemAt(event.scenePos(), self.views()[0].transform() if self.views() else __import__('PySide6.QtGui', fromlist=['QTransform']).QTransform())
        if isinstance(item, ArrowItem):
            self.message_clicked.emit(item.msg_index)
            self.highlight_message(item.msg_index)
        super().mousePressEvent(event)

    def highlight_message(self, msg_index: int) -> None:
        # Remove previous highlight
        if self._highlighted_index >= 0 and self._highlighted_index in self._arrows:
            self._arrows[self._highlighted_index].set_highlighted(False)

        # Apply new highlight
        self._highlighted_index = msg_index
        if msg_index in self._arrows:
            self._arrows[msg_index].set_highlighted(True)
