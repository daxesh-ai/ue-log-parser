"""Recommendations Tab — displays Top 20 protocol issues with 3GPP parameter suggestions."""

from __future__ import annotations

try:
    from PySide6.QtCore import Qt, Signal
    from PySide6.QtGui import QFont, QColor
    from PySide6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget,
        QTableWidgetItem, QTextEdit, QSplitter, QHeaderView, QPushButton,
        QFrame,
    )
except ImportError:
    from PyQt6.QtCore import Qt
    from PyQt6.QtCore import pyqtSignal as Signal
    from PyQt6.QtGui import QFont, QColor
    from PyQt6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget,
        QTableWidgetItem, QTextEdit, QSplitter, QHeaderView, QPushButton,
        QFrame,
    )

from logparser.analysis.recommendations import Recommendation, analyze_session
from logparser.core.session import LogSession


class RecommendationsTab(QWidget):
    """Tab showing Top 20 protocol issues with 3GPP parameter recommendations."""

    navigate_to_message = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._recommendations: list[Recommendation] = []
        self._session: LogSession | None = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)

        # Header
        header_layout = QHBoxLayout()
        title = QLabel("Protocol Issue Analysis")
        title.setFont(QFont("Helvetica", 16, QFont.Bold))
        header_layout.addWidget(title)
        header_layout.addStretch()

        self._summary_label = QLabel("Load a file to analyze")
        self._summary_label.setStyleSheet("color: #888; font-size: 12px;")
        header_layout.addWidget(self._summary_label)

        export_btn = QPushButton("Export Report")
        export_btn.setFixedSize(130, 28)
        export_btn.setStyleSheet(
            "QPushButton { background: #0066cc; color: white; border-radius: 4px; font-size: 12px; }"
            "QPushButton:hover { background: #0052a3; }"
            "QPushButton:disabled { background: #444; color: #666; }"
        )
        export_btn.clicked.connect(self._export_report)
        export_btn.setEnabled(False)
        self._export_btn = export_btn
        header_layout.addWidget(export_btn)

        layout.addLayout(header_layout)

        layout.addSpacing(8)

        # Splitter: table on top, detail on bottom
        splitter = QSplitter(Qt.Vertical)

        # Issues table
        self._table = QTableWidget()
        self._table.setColumnCount(6)
        self._table.setHorizontalHeaderLabels([
            "#", "Category", "Issue", "Severity", "Count", "Parameter"
        ])
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setSelectionMode(QTableWidget.SingleSelection)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.currentCellChanged.connect(self._on_row_selected)
        splitter.addWidget(self._table)

        # Detail panel
        detail_frame = QFrame()
        detail_frame.setFrameStyle(QFrame.StyledPanel)
        detail_layout = QVBoxLayout(detail_frame)
        detail_layout.setContentsMargins(12, 8, 12, 8)

        self._detail_title = QLabel("Select an issue above for details")
        self._detail_title.setFont(QFont("Helvetica", 13, QFont.Bold))
        self._detail_title.setWordWrap(True)
        detail_layout.addWidget(self._detail_title)

        self._detail_text = QTextEdit()
        self._detail_text.setReadOnly(True)
        self._detail_text.setFont(QFont("Menlo", 11))
        self._detail_text.setStyleSheet(
            "QTextEdit { background: #1e1e1e; color: #ddd; border: none; }"
        )
        detail_layout.addWidget(self._detail_text)

        splitter.addWidget(detail_frame)
        splitter.setSizes([350, 250])

        layout.addWidget(splitter)

    def load_session(self, session: LogSession):
        """Analyze session and populate the recommendations table."""
        self._session = session
        self._recommendations = analyze_session(session)
        self._populate_table()

        total = len(self._recommendations)
        critical = sum(1 for r in self._recommendations if r.severity == "Critical")
        major = sum(1 for r in self._recommendations if r.severity == "Major")

        if total == 0:
            self._summary_label.setText("No protocol issues detected")
            self._summary_label.setStyleSheet("color: #4caf50; font-size: 12px;")
        else:
            self._summary_label.setText(
                f"{total} issues found — {critical} Critical, {major} Major"
            )
            color = "#f44336" if critical > 0 else "#ff9800"
            self._summary_label.setStyleSheet(f"color: {color}; font-size: 12px; font-weight: bold;")

        self._export_btn.setEnabled(True)

    def _export_report(self):
        """Export Top-20 report to HTML or PDF."""
        if not self._session:
            return
        try:
            from PySide6.QtWidgets import QFileDialog, QMessageBox
        except ImportError:
            from PyQt6.QtWidgets import QFileDialog, QMessageBox

        path, _ = QFileDialog.getSaveFileName(
            self, "Export Protocol Report", "",
            "HTML Report (*.html);;PDF Report (*.pdf)"
        )
        if not path:
            return

        from pathlib import Path as _Path
        from logparser.export.report_export import export_html_report, export_pdf_report
        output = _Path(path)
        try:
            if path.endswith(".pdf"):
                export_pdf_report(self._session, self._recommendations, output)
            else:
                if not path.endswith(".html"):
                    output = output.with_suffix(".html")
                export_html_report(self._session, self._recommendations, output)
            QMessageBox.information(self, "Report Exported",
                                    f"Report saved to:\n{output}")
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", str(e))

    def _populate_table(self):
        self._table.setRowCount(len(self._recommendations))

        severity_colors = {
            "Critical": QColor("#f44336"),
            "Major": QColor("#ff9800"),
            "Minor": QColor("#ffc107"),
        }

        category_colors = {
            "RRC": QColor("#42a5f5"),
            "NAS": QColor("#ab47bc"),
            "HO": QColor("#66bb6a"),
            "Voice": QColor("#26c6da"),
            "CA": QColor("#ffa726"),
            "SIP": QColor("#ef5350"),
        }

        for row, rec in enumerate(self._recommendations):
            # Rank
            rank_item = QTableWidgetItem(str(rec.rank))
            rank_item.setTextAlignment(Qt.AlignCenter)
            self._table.setItem(row, 0, rank_item)

            # Category
            cat_item = QTableWidgetItem(rec.category)
            cat_item.setTextAlignment(Qt.AlignCenter)
            cat_color = category_colors.get(rec.category, QColor("#888"))
            cat_item.setForeground(cat_color)
            cat_item.setFont(QFont("Helvetica", 11, QFont.Bold))
            self._table.setItem(row, 1, cat_item)

            # Issue
            issue_item = QTableWidgetItem(rec.issue)
            self._table.setItem(row, 2, issue_item)

            # Severity
            sev_item = QTableWidgetItem(rec.severity)
            sev_item.setTextAlignment(Qt.AlignCenter)
            sev_color = severity_colors.get(rec.severity, QColor("#888"))
            sev_item.setForeground(sev_color)
            sev_item.setFont(QFont("Helvetica", 11, QFont.Bold))
            self._table.setItem(row, 3, sev_item)

            # Count
            count_item = QTableWidgetItem(str(rec.count))
            count_item.setTextAlignment(Qt.AlignCenter)
            self._table.setItem(row, 4, count_item)

            # Parameter
            param_item = QTableWidgetItem(rec.parameter)
            param_item.setForeground(QColor("#80cbc4"))
            self._table.setItem(row, 5, param_item)

    def _on_row_selected(self, row: int, col: int, prev_row: int, prev_col: int):
        if row < 0 or row >= len(self._recommendations):
            return

        rec = self._recommendations[row]
        self._detail_title.setText(f"#{rec.rank} [{rec.category}] {rec.issue}")

        # Build detail text
        lines = []
        lines.append(f"SEVERITY: {rec.severity}   |   OCCURRENCES: {rec.count}")
        lines.append("")
        lines.append("─── ROOT CAUSE ───")
        lines.append(rec.root_cause)
        lines.append("")
        lines.append("─── RECOMMENDATION ───")
        lines.append(rec.recommendation)
        lines.append("")
        lines.append("─── 3GPP PARAMETERS ───")
        lines.append(rec.parameter)
        lines.append("")
        lines.append("─── MESSAGE INDICES ───")
        indices_str = ", ".join(f"#{i}" for i in rec.msg_indices[:20])
        if len(rec.msg_indices) > 20:
            indices_str += f" ... (+{len(rec.msg_indices) - 20} more)"
        lines.append(indices_str)

        self._detail_text.setPlainText("\n".join(lines))
