"""Application entry point."""

from __future__ import annotations

import sys
from pathlib import Path


def main():
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError:
        from PyQt6.QtWidgets import QApplication
    from logparser.gui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("5G/4G Log Parser")
    app.setOrganizationName("LogParser")

    # Apply dark theme
    qss_path = Path(__file__).parent / "gui" / "resources" / "dark_theme.qss"
    if qss_path.exists():
        app.setStyleSheet(qss_path.read_text())

    window = MainWindow()
    window.show()

    # If a file path was passed as argument, load it
    if len(sys.argv) > 1:
        filepath = Path(sys.argv[1])
        if filepath.exists():
            window.load_from_path(filepath)

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
