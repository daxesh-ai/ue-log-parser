"""Main window with landing page and 3-pane QCAT-style analysis view."""

from __future__ import annotations

from pathlib import Path

try:
    from PySide6.QtCore import Qt, QThread, Signal, QModelIndex, QSortFilterProxyModel, QTimer
    from PySide6.QtGui import QFont, QDragEnterEvent, QDropEvent
    from PySide6.QtWidgets import (
        QMainWindow, QSplitter, QTableView, QTreeView, QGraphicsView,
        QToolBar, QFileDialog, QProgressBar, QStatusBar, QHeaderView,
        QComboBox, QLabel, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
        QStackedWidget, QFrame, QTabWidget, QLineEdit, QMenu, QPlainTextEdit,
    )
except ImportError:
    from PyQt6.QtCore import Qt, QThread, QModelIndex, QSortFilterProxyModel, QTimer
    from PyQt6.QtCore import pyqtSignal as Signal
    from PyQt6.QtGui import QFont, QDragEnterEvent, QDropEvent
    from PyQt6.QtWidgets import (
        QMainWindow, QSplitter, QTableView, QTreeView, QGraphicsView,
        QToolBar, QFileDialog, QProgressBar, QStatusBar, QHeaderView,
        QComboBox, QLabel, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
        QStackedWidget, QFrame, QTabWidget, QLineEdit, QMenu, QPlainTextEdit,
    )

from logparser.core.enums import Protocol, Direction
from logparser.core.session import LogSession
from logparser.pipeline import load_file


def _format_hex_dump(data: bytes) -> str:
    """Format raw bytes as XCAL-style L3 hex dump.
    e.g.  0000  28 13 83 02 00 B8 1E 7E  (....~
    """
    if not data:
        return "  (no payload)"
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {i:04X}  {hex_part:<47}  {ascii_part}")
    return "\n".join(lines)


class FilterChipBar(QWidget):
    """XCAL-style filter chip bar — toggle chips for quick protocol/severity filters.

    Multiple chips can be active simultaneously (OR within same group, AND across groups).
    """

    filters_changed = Signal()

    # chip definitions: (label, group, filter_fn_name, color)
    _CHIPS = [
        ("NR RRC",   "proto",    "NR_RRC",    "#2e7d32"),
        ("LTE RRC",  "proto",    "LTE_RRC",   "#1565C0"),
        ("NAS",      "proto",    "NAS",       "#6a1b9a"),
        ("SIP/IMS",  "proto",    "SIP",       "#c62828"),
        ("MAC-CE",   "channel",  "MAC-CE",    "#795548"),
        ("Failures", "severity", "FAILURE",   "#e65100"),
        ("UL",       "dir",      "UL",        "#00695c"),
        ("DL",       "dir",      "DL",        "#00838f"),
    ]

    _BTN_ON = (
        "QPushButton {{ background:{color}; color:white; border:none; "
        "border-radius:9px; font-size:11px; font-weight:bold; padding:2px 10px; }}"
        "QPushButton:hover {{ background:{hover}; }}"
    )
    _BTN_OFF = (
        "QPushButton { background:#222; color:#666; border:1px solid #333; "
        "border-radius:9px; font-size:11px; padding:2px 10px; }"
        "QPushButton:hover { background:#2a2a2a; color:#aaa; }"
    )

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        self._active: set[str] = set()   # set of filter keys
        self._buttons: dict[str, QPushButton] = {}

        for label, group, key, color in self._CHIPS:
            btn = QPushButton(label)
            btn.setCheckable(True)
            btn.setFixedHeight(20)
            btn.setProperty("filter_key", key)
            btn.setProperty("chip_color", color)
            btn.setStyleSheet(self._BTN_OFF)
            btn.toggled.connect(lambda checked, k=key, b=btn: self._on_toggle(k, b, checked))
            layout.addWidget(btn)
            self._buttons[key] = btn

        layout.addStretch()

    def _on_toggle(self, key: str, btn: QPushButton, checked: bool):
        if checked:
            self._active.add(key)
            color = btn.property("chip_color")
            # Darken hover color slightly
            btn.setStyleSheet(
                self._BTN_ON.format(color=color, hover=color)
            )
        else:
            self._active.discard(key)
            btn.setStyleSheet(self._BTN_OFF)
        self.filters_changed.emit()

    def active_keys(self) -> set[str]:
        return set(self._active)

    def clear_all(self):
        for key, btn in self._buttons.items():
            btn.blockSignals(True)
            btn.setChecked(False)
            btn.setStyleSheet(self._BTN_OFF)
            btn.blockSignals(False)
        self._active.clear()


class MessageFilterProxyModel(QSortFilterProxyModel):
    """Proxy that filters rows by text search AND active filter chips."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._text = ""
        self._chip_keys: set[str] = set()

    def set_filter(self, text: str) -> None:
        self._text = text.strip().lower()
        self.invalidateFilter()

    def set_chip_filters(self, keys: set[str]) -> None:
        self._chip_keys = keys
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent) -> bool:
        model = self.sourceModel()
        if model is None:
            return True

        try:
            role = Qt.ItemDataRole.DisplayRole
        except AttributeError:
            role = Qt.DisplayRole

        # ── Chip filters ─────────────────────────────────────────────────────
        if self._chip_keys:
            msg = model.get_message(source_row)
            if msg:
                proto = msg.protocol.name
                channel = msg.channel
                from logparser.core.enums import Severity

                # Protocol chips (OR within protocol group)
                proto_chips = {"NR_RRC", "LTE_RRC"}
                nas_chips   = {"NAS"}
                sip_chips   = {"SIP"}
                mac_chips   = {"MAC-CE"}
                fail_chips  = {"FAILURE"}
                dir_chips   = {"UL", "DL"}

                active_proto = self._chip_keys & (proto_chips | nas_chips | sip_chips | mac_chips)
                active_fail  = self._chip_keys & fail_chips
                active_dir   = self._chip_keys & dir_chips

                if active_proto:
                    match = False
                    if "NR_RRC"  in active_proto and proto == "NR_RRC":   match = True
                    if "LTE_RRC" in active_proto and proto == "LTE_RRC":  match = True
                    if "NAS"     in active_proto and "NAS" in proto:      match = True
                    if "SIP"     in active_proto and channel == "SIP":    match = True
                    if "MAC-CE"  in active_proto and channel == "MAC-CE": match = True
                    if not match:
                        return False

                if active_fail:
                    if msg.severity != Severity.FAILURE:
                        return False

                if active_dir:
                    dir_val = msg.direction.value.upper()
                    if not any(d in dir_val for d in active_dir):
                        return False

        # ── Text search ───────────────────────────────────────────────────────
        if self._text:
            for col in (3, 5, 6, 7):
                idx = model.index(source_row, col, source_parent)
                val = model.data(idx, role)
                if val and self._text in str(val).lower():
                    return True
            return False

        return True

from .message_list.model import MessageTableModel
from .ie_tree.model import IETreeModel
from .ladder.scene import LadderScene
from .performance_tab import PerformanceTab
from .recommendations_tab import RecommendationsTab


class LoaderThread(QThread):
    """Background thread for loading and decoding one or multiple log files."""

    progress = Signal(int, int)
    finished_loading = Signal(object)
    error = Signal(str)

    def __init__(self, filepath: Path | list, parent=None):
        super().__init__(parent)
        self._filepath = filepath  # Path or list[Path]

    def run(self):
        try:
            if isinstance(self._filepath, list):
                from logparser.pipeline import load_files
                session = load_files(self._filepath, progress_callback=self._on_progress)
            else:
                session = load_file(self._filepath, progress_callback=self._on_progress)
            self.finished_loading.emit(session)
        except Exception as e:
            self.error.emit(str(e))

    def _on_progress(self, current: int, total: int):
        self.progress.emit(current, total)


class LandingPage(QWidget):
    """Landing page with file upload options."""

    file_selected = Signal(str)
    files_selected = Signal(list)  # list of str paths (multi-file)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self._setup_ui()

    def show_loading(self, filename: str):
        """Show loading indicator on the landing page."""
        self._loading_label.setText(f"Loading: {filename}")
        self._loading_label.show()
        self._loading_progress.show()
        self._loading_progress.setValue(0)
        self._loading_progress.setMaximum(0)  # Indeterminate until we know total

    def update_progress(self, current: int, total: int):
        self._loading_progress.setMaximum(total)
        self._loading_progress.setValue(current)
        pct = int(100 * current / max(1, total))
        self._loading_label.setText(f"Decoding messages... {current}/{total} ({pct}%)")

    def hide_loading(self):
        self._loading_label.hide()
        self._loading_progress.hide()

    def show_error(self, error: str):
        self._loading_label.setText(f"Error: {error}")
        self._loading_label.setStyleSheet("color: red; font-size: 13px;")
        self._loading_label.show()
        self._loading_progress.hide()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)

        # Title
        title = QLabel("5G/4G Log Parser")
        title.setFont(QFont("Helvetica", 28, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        subtitle = QLabel("QCAT-style Protocol Analyzer")
        subtitle.setFont(QFont("Helvetica", 14))
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("color: #888;")
        layout.addWidget(subtitle)

        layout.addSpacing(40)

        # Drop zone
        drop_frame = QFrame()
        drop_frame.setFrameStyle(QFrame.StyledPanel)
        drop_frame.setStyleSheet(
            "QFrame { border: 2px dashed #555; border-radius: 12px; "
            "background: #2a2a2a; padding: 40px; }"
        )
        drop_layout = QVBoxLayout(drop_frame)
        drop_layout.setAlignment(Qt.AlignCenter)

        drop_label = QLabel("Drop .hdf, .pcap, bb-trace folder, .logarchive, or sysdiagnose here")
        drop_label.setFont(QFont("Helvetica", 16))
        drop_label.setAlignment(Qt.AlignCenter)
        drop_label.setStyleSheet("color: #aaa; border: none;")
        drop_layout.addWidget(drop_label)

        drop_layout.addSpacing(20)

        # Buttons
        btn_layout = QHBoxLayout()

        open_hdf_btn = QPushButton("Open .hdf File")
        open_hdf_btn.setFixedSize(160, 40)
        open_hdf_btn.setStyleSheet(
            "QPushButton { background: #0066cc; color: white; border-radius: 6px; "
            "font-size: 14px; font-weight: bold; }"
            "QPushButton:hover { background: #0052a3; }"
        )
        open_hdf_btn.clicked.connect(self._open_hdf)
        btn_layout.addWidget(open_hdf_btn)

        open_folder_btn = QPushButton("Open Folder")
        open_folder_btn.setFixedSize(160, 40)
        open_folder_btn.setStyleSheet(
            "QPushButton { background: #339966; color: white; border-radius: 6px; "
            "font-size: 14px; font-weight: bold; }"
            "QPushButton:hover { background: #267a52; }"
        )
        open_folder_btn.clicked.connect(self._open_folder)
        btn_layout.addWidget(open_folder_btn)

        open_any_btn = QPushButton("Open Other")
        open_any_btn.setFixedSize(160, 40)
        open_any_btn.setStyleSheet(
            "QPushButton { background: #555; color: white; border-radius: 6px; "
            "font-size: 14px; }"
            "QPushButton:hover { background: #333; }"
        )
        open_any_btn.clicked.connect(self._open_any)
        btn_layout.addWidget(open_any_btn)

        open_multi_btn = QPushButton("Open Multiple")
        open_multi_btn.setFixedSize(160, 40)
        open_multi_btn.setStyleSheet(
            "QPushButton { background: #774499; color: white; border-radius: 6px; "
            "font-size: 14px; }"
            "QPushButton:hover { background: #5c3377; }"
        )
        open_multi_btn.clicked.connect(self._open_multiple)
        btn_layout.addWidget(open_multi_btn)

        drop_layout.addLayout(btn_layout)

        layout.addWidget(drop_frame)

        layout.addSpacing(20)

        # Supported formats info
        formats_label = QLabel(
            "Supported: .hdf  .pcap  .pcapng  .logarchive  sysdiagnose.tar.gz  .zip  .tar\n"
            "Apple bb-trace  |  Apple sysdiagnose  |  Qualcomm QUTS  |  PCAP\n"
            "Protocols: NR RRC, LTE RRC, 5G NAS, LTE NAS, SIP, IMS, CommCenter"
        )
        formats_label.setAlignment(Qt.AlignCenter)
        formats_label.setStyleSheet("color: #999; font-size: 11px;")
        layout.addWidget(formats_label)

        layout.addSpacing(20)

        # Loading indicator (hidden by default)
        self._loading_label = QLabel("")
        self._loading_label.setAlignment(Qt.AlignCenter)
        self._loading_label.setStyleSheet("color: #0066cc; font-size: 13px; font-weight: bold;")
        self._loading_label.hide()
        layout.addWidget(self._loading_label)

        self._loading_progress = QProgressBar()
        self._loading_progress.setMaximumWidth(400)
        self._loading_progress.setMinimumWidth(300)
        self._loading_progress.hide()
        layout.addWidget(self._loading_progress, alignment=Qt.AlignCenter)

    def _open_hdf(self):
        filepath, _ = QFileDialog.getOpenFileName(
            self, "Open Log File", "",
            "QUTS Log Files (*.hdf);;All Files (*)",
        )
        if filepath:
            self.file_selected.emit(filepath)

    def _open_any(self):
        filepath, _ = QFileDialog.getOpenFileName(
            self, "Open Log File", "",
            "All Supported (*.hdf *.pcap *.pcapng *.zip *.tar *.tar.gz *.tar.bz2 *.bz2);;QUTS (*.hdf);;PCAP (*.pcap *.pcapng);;Archives (*.zip *.tar *.tar.gz *.tar.bz2 *.bz2);;All Files (*)",
        )
        if filepath:
            self.file_selected.emit(filepath)

    def _open_folder(self):
        folder = QFileDialog.getExistingDirectory(
            self, "Open bb-trace / Log Folder", "",
        )
        if folder:
            self.file_selected.emit(folder)

    def _open_multiple(self):
        filepaths, _ = QFileDialog.getOpenFileNames(
            self, "Open Multiple Log Files", "",
            "All Supported (*.hdf *.pcap *.pcapng *.zip *.tar *.tar.gz *.tar.bz2);;QUTS (*.hdf);;All Files (*)",
        )
        if len(filepaths) == 1:
            self.file_selected.emit(filepaths[0])
        elif len(filepaths) > 1:
            self.files_selected.emit(filepaths)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        urls = event.mimeData().urls()
        if urls:
            filepath = urls[0].toLocalFile()
            self.file_selected.emit(filepath)


class MainWindow(QMainWindow):
    """Main window with landing page → analysis view flow."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("5G/4G Log Parser")
        self.setMinimumSize(1200, 800)
        self.setAcceptDrops(True)

        self._session: LogSession | None = None
        self._setup_models()
        self._setup_menus()
        self._setup_ui()
        self._connect_signals()

    def _setup_models(self):
        self._msg_model = MessageTableModel()
        self._proxy_model = MessageFilterProxyModel()
        self._proxy_model.setSourceModel(self._msg_model)
        self._ie_model = IETreeModel()
        self._ladder_scene = LadderScene()

    def _setup_menus(self):
        menu_bar = self.menuBar()
        file_menu = menu_bar.addMenu("&File")

        open_action = file_menu.addAction("&Open...")
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self._open_file)

        file_menu.addSeparator()
        export_csv_action = file_menu.addAction("Export &CSV...")
        export_csv_action.triggered.connect(self._export_csv)

    def _setup_ui(self):
        self._stack = QStackedWidget()
        self.setCentralWidget(self._stack)

        # --- Page 0: Landing ---
        self._landing = LandingPage()
        self._landing.file_selected.connect(lambda fp: self._load_file(Path(fp)))
        self._landing.files_selected.connect(
            lambda fps: self._load_file([Path(fp) for fp in fps])
        )
        self._stack.addWidget(self._landing)

        # --- Page 1: Analysis View ---
        analysis_widget = QWidget()
        analysis_layout = QVBoxLayout(analysis_widget)
        analysis_layout.setContentsMargins(0, 0, 0, 0)
        analysis_layout.setSpacing(0)

        # Tech Status Header
        self._tech_header = QLabel("  MODE: -- | VOICE: --")
        self._tech_header.setFixedHeight(28)
        self._tech_header.setStyleSheet(
            "background-color: #333; color: white; font-size: 12px; "
            "font-weight: bold; padding: 4px 12px; font-family: Menlo;"
        )
        analysis_layout.addWidget(self._tech_header)

        # ── Toolbar Row 1: Open + Export + Search + Progress ──────────────────
        toolbar_widget = QWidget()
        toolbar_layout = QHBoxLayout(toolbar_widget)
        toolbar_layout.setContentsMargins(8, 3, 8, 3)
        toolbar_layout.setSpacing(4)

        open_btn = QPushButton("Open")
        open_btn.setFixedHeight(24)
        open_btn.setStyleSheet(
            "QPushButton{background:#0066cc;color:white;border-radius:4px;padding:2px 10px;}"
            "QPushButton:hover{background:#0052a3;}"
        )
        open_btn.clicked.connect(self._open_file)
        toolbar_layout.addWidget(open_btn)

        # Export ▾ dropdown button
        self._export_btn = QPushButton("Export ▾")
        self._export_btn.setFixedHeight(24)
        self._export_btn.setStyleSheet(
            "QPushButton{background:#444;color:white;border-radius:4px;padding:2px 10px;}"
            "QPushButton:hover{background:#555;}"
        )
        self._export_btn.clicked.connect(self._show_export_menu)
        toolbar_layout.addWidget(self._export_btn)

        toolbar_layout.addSpacing(8)

        self._search_box = QLineEdit()
        self._search_box.setPlaceholderText("🔍  Search messages...")
        self._search_box.setFixedHeight(24)
        self._search_box.setMinimumWidth(200)
        self._search_box.setStyleSheet(
            "QLineEdit{background:#2a2a2a;color:#ddd;border:1px solid #444;"
            "border-radius:4px;padding:2px 8px;}"
            "QLineEdit:focus{border-color:#0066cc;}"
        )
        self._search_box.textChanged.connect(self._on_search_changed)
        toolbar_layout.addWidget(self._search_box)

        toolbar_layout.addStretch()

        self._status_label = QLabel("Ready")
        self._status_label.setStyleSheet("color:#aaa;font-size:11px;")
        toolbar_layout.addWidget(self._status_label)

        self._progress = QProgressBar()
        self._progress.setMaximumWidth(130)
        self._progress.setFixedHeight(16)
        self._progress.hide()
        toolbar_layout.addWidget(self._progress)

        analysis_layout.addWidget(toolbar_widget)

        # ── Filter Chip Bar (XCAL Filtering buttons) ──────────────────────────
        chip_row = QWidget()
        chip_row.setStyleSheet("background:#1a1a1a;")
        chip_layout = QHBoxLayout(chip_row)
        chip_layout.setContentsMargins(8, 2, 8, 2)
        chip_layout.setSpacing(0)

        chip_label = QLabel("Filter: ")
        chip_label.setStyleSheet("color:#666;font-size:11px;")
        chip_layout.addWidget(chip_label)

        self._filter_chips = FilterChipBar()
        self._filter_chips.filters_changed.connect(self._on_chip_filter_changed)
        chip_layout.addWidget(self._filter_chips)

        clear_btn = QPushButton("Clear")
        clear_btn.setFixedHeight(18)
        clear_btn.setStyleSheet(
            "QPushButton{background:transparent;color:#666;border:1px solid #333;"
            "border-radius:3px;font-size:10px;padding:0px 6px;}"
            "QPushButton:hover{color:#aaa;border-color:#555;}"
        )
        clear_btn.clicked.connect(self._clear_all_filters)
        chip_layout.addWidget(clear_btn)

        analysis_layout.addWidget(chip_row)

        # Tabs
        self._tabs = QTabWidget()
        analysis_layout.addWidget(self._tabs)

        # --- Tab 1: Signaling ---
        signaling_widget = QWidget()
        sig_layout = QVBoxLayout(signaling_widget)
        sig_layout.setContentsMargins(0, 0, 0, 0)

        v_splitter = QSplitter(Qt.Vertical)
        h_splitter = QSplitter(Qt.Horizontal)

        # Message list
        self._msg_view = QTableView()
        self._msg_view.setModel(self._proxy_model)
        self._msg_view.setSelectionBehavior(QTableView.SelectRows)
        self._msg_view.setSelectionMode(QTableView.SingleSelection)
        self._msg_view.setAlternatingRowColors(False)  # we handle colors ourselves
        self._msg_view.verticalHeader().setVisible(False)
        self._msg_view.horizontalHeader().setStretchLastSection(True)
        self._msg_view.verticalHeader().setDefaultSectionSize(20)
        self._msg_view.setWordWrap(False)
        self._msg_view.setFont(QFont("Menlo", 10))
        h_splitter.addWidget(self._msg_view)

        # Ladder diagram
        self._ladder_view = QGraphicsView()
        self._ladder_view.setScene(self._ladder_scene)
        self._ladder_view.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        h_splitter.addWidget(self._ladder_view)

        h_splitter.setSizes([700, 400])
        v_splitter.addWidget(h_splitter)

        # IE Tree + Hex panel (stacked in a vertical splitter)
        ie_container = QWidget()
        ie_layout = QVBoxLayout(ie_container)
        ie_layout.setContentsMargins(0, 0, 0, 0)
        ie_layout.setSpacing(0)

        # Decoded/Hex toggle strip
        toggle_strip = QWidget()
        toggle_strip.setStyleSheet("background:#1e1e1e;")
        toggle_layout = QHBoxLayout(toggle_strip)
        toggle_layout.setContentsMargins(4, 2, 4, 2)
        toggle_layout.setSpacing(4)

        self._decoded_btn = QPushButton("Decoded")
        self._decoded_btn.setCheckable(True)
        self._decoded_btn.setChecked(True)
        self._decoded_btn.setFixedHeight(18)
        self._decoded_btn.setStyleSheet(
            "QPushButton{background:#1565C0;color:white;border:none;border-radius:3px;"
            "font-size:10px;padding:0 8px;}"
            "QPushButton:!checked{background:#2a2a2a;color:#666;}"
        )
        self._decoded_btn.toggled.connect(self._on_ie_view_toggle)
        toggle_layout.addWidget(self._decoded_btn)

        self._hex_btn = QPushButton("L3 Hex")
        self._hex_btn.setCheckable(True)
        self._hex_btn.setFixedHeight(18)
        self._hex_btn.setStyleSheet(
            "QPushButton{background:#2a2a2a;color:#666;border:none;border-radius:3px;"
            "font-size:10px;padding:0 8px;}"
            "QPushButton:checked{background:#333;color:#80cbc4;}"
        )
        self._hex_btn.toggled.connect(self._on_hex_view_toggle)
        toggle_layout.addWidget(self._hex_btn)

        toggle_layout.addStretch()
        ie_layout.addWidget(toggle_strip)

        # IE Tree
        self._ie_view = QTreeView()
        self._ie_view.setModel(self._ie_model)
        self._ie_view.setAlternatingRowColors(True)
        self._ie_view.header().setStretchLastSection(True)
        self._ie_view.setAnimated(False)
        self._ie_view.setFont(QFont("Menlo", 10))
        ie_layout.addWidget(self._ie_view)

        # L3 Hex panel (hidden by default)
        self._hex_view = QPlainTextEdit()
        self._hex_view.setReadOnly(True)
        self._hex_view.setFont(QFont("Menlo", 10))
        self._hex_view.setStyleSheet(
            "QPlainTextEdit{background:#111;color:#80cbc4;border:none;"
            "font-family:Menlo,Courier;}"
        )
        self._hex_view.setPlaceholderText("Select a message to see raw L3 bytes")
        self._hex_view.hide()
        ie_layout.addWidget(self._hex_view)

        v_splitter.addWidget(ie_container)
        v_splitter.setSizes([450, 350])
        sig_layout.addWidget(v_splitter)

        self._tabs.addTab(signaling_widget, "Signaling")

        # --- Tab 2: CA & Performance ---
        self._perf_tab = PerformanceTab()
        self._tabs.addTab(self._perf_tab, "CA & Performance")

        # --- Tab 3: Recommendations ---
        self._recs_tab = RecommendationsTab()
        self._recs_tab.navigate_to_message.connect(self._navigate_to_msg)
        self._tabs.addTab(self._recs_tab, "Recommendations")

        self._stack.addWidget(analysis_widget)

        # ── XCAL-style status bar ─────────────────────────────────────────────
        self._statusbar = QStatusBar()
        self._statusbar.setStyleSheet(
            "QStatusBar{background:#111;color:#666;font-size:11px;}"
            "QStatusBar::item{border:none;}"
        )
        self.setStatusBar(self._statusbar)

        self._sb_gps     = QLabel("  No GPS  ")
        self._sb_logging = QLabel("  No Logging  ")
        self._sb_cpu     = QLabel("  CPU: --  ")
        self._sb_memory  = QLabel("  Memory: --  ")

        for lbl in (self._sb_gps, self._sb_logging, self._sb_cpu, self._sb_memory):
            lbl.setStyleSheet(
                "color:#888;font-size:11px;padding:0 4px;"
                "border-left:1px solid #333;"
            )
            self._statusbar.addPermanentWidget(lbl)

        # CPU/Memory update timer
        self._sys_timer = QTimer(self)
        self._sys_timer.timeout.connect(self._update_sys_stats)
        self._sys_timer.start(2000)
        self._update_sys_stats()

    def _connect_signals(self):
        self._msg_view.selectionModel().currentRowChanged.connect(self._on_message_selected)
        self._ladder_scene.message_clicked.connect(self._navigate_to_msg)

    # ── New XCAL-style handlers ───────────────────────────────────────────────

    def _show_export_menu(self):
        """Show Export ▾ dropdown menu."""
        menu = QMenu(self)
        menu.setStyleSheet(
            "QMenu{background:#2a2a2a;color:#ddd;border:1px solid #444;}"
            "QMenu::item:selected{background:#0066cc;}"
        )
        menu.addAction("Export CSV...",    self._export_csv)
        menu.addAction("Export JSON...",   self._export_json)
        menu.addAction("Export Report...", self._export_report)
        menu.exec(self._export_btn.mapToGlobal(self._export_btn.rect().bottomLeft()))

    def _export_json(self):
        if not self._session:
            return
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Export JSON", "", "JSON Files (*.json);;All Files (*)"
        )
        if filepath:
            from logparser.export.json_export import export_json
            export_json(self._session, Path(filepath))
            self._status_label.setText(f"Exported to {Path(filepath).name}")

    def _export_report(self):
        if not self._session:
            return
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Export Report", "", "HTML (*.html);;PDF (*.pdf);;All Files (*)"
        )
        if filepath:
            from logparser.analysis.recommendations import analyze_session
            from logparser.export.report_export import export_html_report, export_pdf_report
            recs = analyze_session(self._session)
            if filepath.endswith(".pdf"):
                export_pdf_report(self._session, recs, Path(filepath))
            else:
                export_html_report(self._session, recs, Path(filepath))
            self._status_label.setText(f"Report saved to {Path(filepath).name}")

    def _on_chip_filter_changed(self):
        """Apply chip filter keys to the proxy model."""
        keys = self._filter_chips.active_keys()
        self._proxy_model.set_chip_filters(keys)
        visible = self._proxy_model.rowCount()
        total = self._msg_model.rowCount()
        if keys or self._search_box.text():
            self._status_label.setText(f"Showing {visible} of {total} messages")
        elif self._session:
            self._status_label.setText(
                f"{self._session.filename} — {len(self._session.messages)} messages"
            )

    def _clear_all_filters(self):
        """Clear all chip filters and search box."""
        self._filter_chips.clear_all()
        self._search_box.clear()
        self._proxy_model.set_chip_filters(set())
        self._proxy_model.set_filter("")

    def _on_ie_view_toggle(self, checked: bool):
        if checked:
            self._hex_btn.setChecked(False)
            self._ie_view.show()
            self._hex_view.hide()
            self._decoded_btn.setStyleSheet(
                "QPushButton{background:#1565C0;color:white;border:none;"
                "border-radius:3px;font-size:10px;padding:0 8px;}"
            )

    def _on_hex_view_toggle(self, checked: bool):
        if checked:
            self._decoded_btn.setChecked(False)
            self._ie_view.hide()
            self._hex_view.show()
            self._hex_btn.setStyleSheet(
                "QPushButton{background:#333;color:#80cbc4;border:none;"
                "border-radius:3px;font-size:10px;padding:0 8px;}"
            )
        else:
            self._decoded_btn.setChecked(True)

    def _update_sys_stats(self):
        """Update CPU/Memory in status bar every 2 seconds."""
        try:
            import psutil
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory().percent
            self._sb_cpu.setText(f"  CPU: {cpu:.0f}%  ")
            self._sb_memory.setText(f"  Memory: {mem:.0f}%  ")
            # Color-code high usage
            cpu_color = "#f44336" if cpu > 80 else "#ff9800" if cpu > 50 else "#888"
            mem_color = "#f44336" if mem > 85 else "#ff9800" if mem > 70 else "#888"
            self._sb_cpu.setStyleSheet(
                f"color:{cpu_color};font-size:11px;padding:0 4px;border-left:1px solid #333;"
            )
            self._sb_memory.setStyleSheet(
                f"color:{mem_color};font-size:11px;padding:0 4px;border-left:1px solid #333;"
            )
        except ImportError:
            self._sb_cpu.setText("  CPU: N/A  ")
            self._sb_memory.setText("  Memory: N/A  ")

    def _on_search_changed(self, text: str):
        self._proxy_model.set_filter(text)
        visible = self._proxy_model.rowCount()
        total = self._msg_model.rowCount()
        if text:
            self._status_label.setText(f"Showing {visible} of {total} messages")
        elif self._session:
            self._status_label.setText(
                f"{self._session.filename} — {len(self._session.messages)} messages"
            )

    def _open_file(self):
        filepath, _ = QFileDialog.getOpenFileName(
            self, "Open Log File", "",
            "All Supported (*.hdf *.zip *.tar *.tar.gz *.tar.bz2 *.bz2 *.tgz *.pcap *.pcapng *.dlf);;QUTS (*.hdf);;Archives (*.zip *.tar *.tar.gz *.tar.bz2 *.bz2 *.tgz);;PCAP (*.pcap *.pcapng);;DLF (*.dlf);;All Files (*)",
        )
        if filepath:
            self._load_file(Path(filepath))

    def _load_file(self, filepath):
        """Load a single file (Path) or multiple files (list[Path])."""
        # Show progress on landing page
        if isinstance(filepath, list):
            display_name = f"{len(filepath)} files"
        else:
            display_name = filepath.name
        self._landing.show_loading(display_name)

        # Also update toolbar progress if already on analysis view
        self._status_label.setText(f"Loading {display_name}...")
        self._progress.show()
        self._progress.setValue(0)
        self._progress.setMaximum(0)  # Indeterminate initially

        self._loader = LoaderThread(filepath, self)
        self._loader.progress.connect(self._on_load_progress)
        self._loader.finished_loading.connect(self._on_load_complete)
        self._loader.error.connect(self._on_load_error)
        self._loader.start()

    def _on_load_progress(self, current: int, total: int):
        self._progress.setMaximum(total)
        self._progress.setValue(current)
        # Update landing page progress too
        self._landing.update_progress(current, total)

    def _on_load_complete(self, session: LogSession):
        self._session = session
        self._progress.hide()
        self._landing.hide_loading()

        # Reset all filters
        self._search_box.blockSignals(True)
        self._search_box.clear()
        self._search_box.blockSignals(False)
        self._proxy_model.set_filter("")
        self._filter_chips.clear_all()
        self._proxy_model.set_chip_filters(set())
        self._msg_model.set_filtered(None)

        # Update status bar logging indicator
        self._sb_logging.setText(f"  File: {session.filename[:20]}  ")

        # Clear IE tree (ladder is cleared inside build_from_session)
        self._ie_model.set_message(None)

        # Switch to analysis view
        self._stack.setCurrentIndex(1)

        self._status_label.setText(
            f"{session.filename} — {len(session.messages)} messages"
        )

        self._msg_model.set_session(session)
        self._ladder_scene.build_from_session(session)

        # Auto-size columns
        for i in range(self._msg_model.columnCount()):
            self._msg_view.resizeColumnToContents(i)

        # Populate CA & Performance tab
        self._perf_tab.load_session(session)

        # Populate Recommendations tab
        self._recs_tab.load_session(session)

        self.setWindowTitle(f"5G/4G Log Parser — {session.filename}")

    def _on_load_error(self, error_msg: str):
        self._progress.hide()
        self._status_label.setText(f"Error: {error_msg}")
        self._landing.show_error(error_msg)

    def _on_message_selected(self, current: QModelIndex, previous: QModelIndex):
        if not current.isValid():
            return
        source_idx = self._proxy_model.mapToSource(current)
        if not source_idx.isValid():
            return
        msg = self._msg_model.get_message(source_idx.row())
        if msg:
            self._ie_model.set_message(msg)
            self._expand_all_tree()
            self._update_tech_header(msg.index)

            # Update L3 hex panel
            self._hex_view.setPlainText(_format_hex_dump(msg.raw_payload or b""))

            # Scroll ladder
            arrow = self._ladder_scene._arrows.get(msg.index)
            if arrow:
                rect = arrow.mapToScene(arrow.boundingRect()).boundingRect()
                self._ladder_view.centerOn(rect.center().x(), rect.center().y())
                self._ladder_scene.highlight_message(msg.index)

    def _update_tech_header(self, msg_index: int):
        """Update the RAT mode status bar based on current message position."""
        if not self._session or not hasattr(self._session, "tech_tracker"):
            return

        tracker = self._session.tech_tracker
        state = tracker.get_state_at(msg_index)
        tech = state.tech
        voice = state.voice

        # Format display
        text = f"  MODE: {tech}"
        if voice != "Idle":
            text += f"  |  VOICE: {voice}"
        if state.transition_reason:
            text += f"  ({state.transition_reason})"

        # Add session summary if voice events exist
        if tracker.session_summary and "No voice" not in tracker.session_summary:
            text += f"    [{tracker.session_summary}]"

        self._tech_header.setText(text)

        # Color based on technology
        if "5G SA" in tech:
            style = "background-color: #1a8c1a; color: white;"
        elif "5G NSA" in tech or "EN-DC" in tech:
            style = "background-color: #2a7a2a; color: white;"
        elif "EPSFB" in tech or "Fallback" in tech:
            style = "background-color: #cc6600; color: white;"
        elif "LTE" in tech:
            style = "background-color: #0055aa; color: white;"
        elif "WiFi" in tech:
            style = "background-color: #0099cc; color: white;"
        elif "Depri" in tech:
            style = "background-color: #cc3300; color: white;"
        else:
            style = "background-color: #333; color: white;"

        self._tech_header.setStyleSheet(
            f"{style} font-size: 12px; font-weight: bold; "
            f"padding: 4px 12px; font-family: Menlo;"
        )

    def _navigate_to_msg(self, msg_index: int):
        """Navigate to a specific message by index (from recommendations tab)."""
        self._tabs.setCurrentIndex(0)  # Switch to Signaling tab
        # Clear search so the target row is visible
        self._search_box.clear()
        row = self._msg_model.row_for_index(msg_index)
        if row >= 0:
            source_idx = self._msg_model.index(row, 0)
            proxy_idx = self._proxy_model.mapFromSource(source_idx)
            self._msg_view.setCurrentIndex(proxy_idx)
            self._msg_view.scrollTo(proxy_idx)

    def _expand_all_tree(self):
        """Expand all nodes in the IE tree for immediate visibility."""
        self._ie_view.expandAll()

    def _apply_filters(self):
        """Legacy method — filter state now managed by chip bar + proxy model."""
        if not self._session:
            return
        visible = self._proxy_model.rowCount()
        self._status_label.setText(
            f"{self._session.filename} — {visible} messages shown"
        )

    def _export_csv(self):
        if not self._session:
            return
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Export CSV", "", "CSV Files (*.csv);;All Files (*)"
        )
        if filepath:
            from logparser.export.csv_export import export_csv
            export_csv(self._session, Path(filepath))
            self._status_label.setText(f"Exported to {Path(filepath).name}")

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if not urls:
            return
        paths = [Path(u.toLocalFile()) for u in urls]
        if len(paths) > 1:
            # Multi-file drop — filter to supported formats
            supported = (".hdf", ".pcap", ".pcapng")
            valid = [p for p in paths if p.suffix.lower() in supported]
            if valid:
                self._load_file(valid)
            return
        filepath = paths[0]
        if filepath.is_dir():
            self._load_file(filepath)
            return
        supported = (".hdf", ".zip", ".tar", ".gz", ".bz2", ".tgz", ".pcap", ".pcapng")
        name_lower = filepath.name.lower()
        if (filepath.suffix.lower() in supported
                or name_lower.endswith((".tar.gz", ".tar.bz2"))
                or name_lower.startswith("sysdiagnose")):
            self._load_file(filepath)

    def load_from_path(self, filepath: Path):
        """Load a file directly (for programmatic use)."""
        self._load_file(filepath)
