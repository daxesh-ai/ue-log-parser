"""Qt compatibility shim — supports both PySide6 and PyQt6.

Import from this module instead of PySide6/PyQt6 directly.
Whichever is installed will be used automatically.
"""

import importlib

_QT_BINDING = None


def _detect_binding():
    global _QT_BINDING
    if _QT_BINDING:
        return _QT_BINDING

    for binding in ("PySide6", "PyQt6"):
        try:
            importlib.import_module(binding)
            _QT_BINDING = binding
            return binding
        except ImportError:
            continue

    raise ImportError(
        "No Qt binding found. Install one of:\n"
        "  pip install PySide6\n"
        "  pip install PyQt6"
    )


# Detect and expose
BINDING = _detect_binding()

if BINDING == "PySide6":
    from PySide6.QtCore import *  # noqa: F401, F403
    from PySide6.QtGui import *  # noqa: F401, F403
    from PySide6.QtWidgets import *  # noqa: F401, F403
    from PySide6 import QtCore, QtGui, QtWidgets  # noqa: F401
    # PySide6 uses Signal/Slot directly
    Signal = QtCore.Signal
elif BINDING == "PyQt6":
    from PyQt6.QtCore import *  # noqa: F401, F403
    from PyQt6.QtGui import *  # noqa: F401, F403
    from PyQt6.QtWidgets import *  # noqa: F401, F403
    from PyQt6 import QtCore, QtGui, QtWidgets  # noqa: F401
    # PyQt6 uses pyqtSignal
    Signal = QtCore.pyqtSignal
