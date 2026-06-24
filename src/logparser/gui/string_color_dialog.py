"""String Color Setting dialog — XCAL-style per-keyword color configuration.

Opens a dialog where the user can:
- See current keyword → color mappings
- Add new keywords with a color picker
- Remove keywords
- Reset to defaults

Changes apply immediately to the message list (live preview).
"""

from __future__ import annotations

try:
    from PySide6.QtCore import Qt, Signal
    from PySide6.QtGui import QColor, QFont
    from PySide6.QtWidgets import (
        QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
        QTableWidget, QTableWidgetItem, QColorDialog, QLineEdit,
        QHeaderView, QDialogButtonBox,
    )
except ImportError:
    from PyQt6.QtCore import Qt
    from PyQt6.QtCore import pyqtSignal as Signal
    from PyQt6.QtGui import QColor, QFont
    from PyQt6.QtWidgets import (
        QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
        QTableWidget, QTableWidgetItem, QColorDialog, QLineEdit,
        QHeaderView, QDialogButtonBox,
    )

from logparser.gui.message_list.model import STRING_COLORS


class StringColorDialog(QDialog):
    """XCAL-style String Color Setting dialog.

    Allows user to view/edit keyword → foreground color mappings for
    the Summary column in the message list.
    """

    colors_changed = Signal()   # emitted when user applies changes

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("String Color Setting")
        self.setMinimumSize(520, 400)
        self.setStyleSheet(
            "QDialog{background:#1e1e1e;color:#ddd;}"
            "QTableWidget{background:#141414;color:#ddd;gridline-color:#333;border:1px solid #333;}"
            "QTableWidget::item:selected{background:#1565C0;}"
            "QHeaderView::section{background:#252525;color:#aaa;border:1px solid #333;padding:4px;}"
            "QLineEdit{background:#2a2a2a;color:#ddd;border:1px solid #444;border-radius:3px;padding:3px 6px;}"
            "QPushButton{background:#333;color:#ddd;border:1px solid #444;border-radius:3px;padding:4px 12px;}"
            "QPushButton:hover{background:#404040;}"
        )
        self._setup_ui()
        self._load_colors()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        # Description
        desc = QLabel(
            "Define foreground colors for keywords in the Summary column.\n"
            "Keywords are case-insensitive. First match wins."
        )
        desc.setStyleSheet("color:#888;font-size:11px;")
        layout.addWidget(desc)

        # Table
        self._table = QTableWidget()
        self._table.setColumnCount(3)
        self._table.setHorizontalHeaderLabels(["Keyword", "Color", "Preview"])
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.verticalHeader().setVisible(False)
        self._table.cellDoubleClicked.connect(self._on_cell_double_clicked)
        layout.addWidget(self._table)

        # Add row controls
        add_row = QWidget()
        add_layout = QHBoxLayout(add_row)
        add_layout.setContentsMargins(0, 0, 0, 0)
        add_layout.setSpacing(6)

        add_layout.addWidget(QLabel("Keyword:"))
        self._new_keyword = QLineEdit()
        self._new_keyword.setPlaceholderText("e.g. handover")
        self._new_keyword.setFixedWidth(160)
        add_layout.addWidget(self._new_keyword)

        self._color_preview = QPushButton("  ●  ")
        self._color_preview.setFixedWidth(40)
        self._selected_color = QColor(255, 220, 50)
        self._update_color_btn()
        self._color_preview.clicked.connect(self._pick_color)
        add_layout.addWidget(self._color_preview)

        add_btn = QPushButton("Add")
        add_btn.setStyleSheet(
            "QPushButton{background:#0066cc;color:white;border:none;border-radius:3px;padding:4px 16px;}"
            "QPushButton:hover{background:#0052a3;}"
        )
        add_btn.clicked.connect(self._add_keyword)
        add_layout.addWidget(add_btn)

        remove_btn = QPushButton("Remove Selected")
        remove_btn.clicked.connect(self._remove_selected)
        add_layout.addWidget(remove_btn)

        reset_btn = QPushButton("Reset Defaults")
        reset_btn.clicked.connect(self._reset_defaults)
        add_layout.addWidget(reset_btn)

        add_layout.addStretch()
        layout.addWidget(add_row)

        # OK / Cancel
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.setStyleSheet(
            "QPushButton{background:#333;color:#ddd;border:1px solid #555;border-radius:3px;padding:4px 20px;}"
            "QPushButton:hover{background:#444;}"
        )
        buttons.accepted.connect(self._apply_and_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _load_colors(self):
        """Load current STRING_COLORS into the table."""
        self._table.setRowCount(0)
        for keyword, color in STRING_COLORS.items():
            self._add_table_row(keyword, color)

    def _add_table_row(self, keyword: str, color: QColor):
        row = self._table.rowCount()
        self._table.insertRow(row)

        kw_item = QTableWidgetItem(keyword)
        kw_item.setFont(QFont("Menlo", 10))
        self._table.setItem(row, 0, kw_item)

        color_item = QTableWidgetItem(color.name().upper())
        color_item.setBackground(color)
        color_item.setForeground(
            QColor(0, 0, 0) if color.lightness() > 128 else QColor(255, 255, 255)
        )
        color_item.setFont(QFont("Menlo", 10))
        self._table.setItem(row, 1, color_item)

        preview_item = QTableWidgetItem(f"  {keyword}  ")
        preview_item.setForeground(color)
        preview_item.setFont(QFont("Menlo", 10))
        self._table.setItem(row, 2, preview_item)

    def _on_cell_double_clicked(self, row: int, col: int):
        """Double-click to edit color of a row."""
        color_item = self._table.item(row, 1)
        if not color_item:
            return
        current = QColor(color_item.text())
        new_color = QColorDialog.getColor(current, self, "Pick Color")
        if new_color.isValid():
            color_item.setText(new_color.name().upper())
            color_item.setBackground(new_color)
            color_item.setForeground(
                QColor(0, 0, 0) if new_color.lightness() > 128 else QColor(255, 255, 255)
            )
            preview = self._table.item(row, 2)
            if preview:
                preview.setForeground(new_color)

    def _pick_color(self):
        new_color = QColorDialog.getColor(self._selected_color, self, "Pick Color")
        if new_color.isValid():
            self._selected_color = new_color
            self._update_color_btn()

    def _update_color_btn(self):
        c = self._selected_color
        text_color = "black" if c.lightness() > 128 else "white"
        self._color_preview.setStyleSheet(
            f"QPushButton{{background:{c.name()};color:{text_color};"
            f"border:1px solid #555;border-radius:3px;padding:2px;}}"
        )

    def _add_keyword(self):
        keyword = self._new_keyword.text().strip().lower()
        if not keyword:
            return
        # Check for duplicate
        for row in range(self._table.rowCount()):
            item = self._table.item(row, 0)
            if item and item.text().lower() == keyword:
                return
        self._add_table_row(keyword, self._selected_color)
        self._new_keyword.clear()

    def _remove_selected(self):
        rows = set(idx.row() for idx in self._table.selectedIndexes())
        for row in sorted(rows, reverse=True):
            self._table.removeRow(row)

    def _reset_defaults(self):
        from logparser.gui.message_list.model import STRING_COLORS as _defaults
        self._table.setRowCount(0)
        for keyword, color in _defaults.items():
            self._add_table_row(keyword, color)

    def _apply_and_accept(self):
        """Apply dialog settings to STRING_COLORS and close."""
        from logparser.gui.message_list import model as _model

        new_colors: dict = {}
        for row in range(self._table.rowCount()):
            kw_item = self._table.item(row, 0)
            color_item = self._table.item(row, 1)
            if kw_item and color_item:
                keyword = kw_item.text().strip().lower()
                color = QColor(color_item.text())
                if keyword and color.isValid():
                    new_colors[keyword] = color

        # Update the module-level dict in place
        _model.STRING_COLORS.clear()
        _model.STRING_COLORS.update(new_colors)

        self.colors_changed.emit()
        self.accept()
