"""Logging configuration for the 5G/4G Log Parser.

Usage:
    from logparser.core.logging import get_logger
    logger = get_logger(__name__)
    logger.debug("Decoded %d messages", count)
    logger.warning("Unknown log code 0x%04X", code)
"""

import logging
import sys

_configured = False


def get_logger(name: str) -> logging.Logger:
    """Get a named logger with standard configuration."""
    global _configured
    if not _configured:
        _configure_root()
        _configured = True
    return logging.getLogger(name)


def _configure_root():
    """Configure root logger with stderr handler."""
    root = logging.getLogger("logparser")
    root.setLevel(logging.WARNING)  # Default: only warnings+

    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(logging.DEBUG)
    fmt = logging.Formatter(
        "%(levelname).1s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    handler.setFormatter(fmt)
    root.addHandler(handler)


def set_verbose(enabled: bool = True):
    """Enable debug-level logging (call with --verbose flag)."""
    root = logging.getLogger("logparser")
    root.setLevel(logging.DEBUG if enabled else logging.WARNING)
