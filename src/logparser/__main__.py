"""Allow running as: python -m logparser"""

import sys

HAS_GUI = False
try:
    import PySide6  # noqa: F401
    HAS_GUI = True
except ImportError:
    try:
        import PyQt6  # noqa: F401
        HAS_GUI = True
    except ImportError:
        pass


if HAS_GUI and "--cli" not in sys.argv:
    from logparser.app import main
else:
    from logparser.cli import main

main()
