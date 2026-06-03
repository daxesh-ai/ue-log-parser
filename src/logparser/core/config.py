"""User configuration management.

Loads settings from ~/.logparser.toml if present, otherwise uses defaults.
Provides a simple get() interface for the rest of the codebase.
"""

from __future__ import annotations

from pathlib import Path

_CONFIG: dict | None = None
_CONFIG_PATH = Path.home() / ".logparser.toml"

_DEFAULTS = {
    "max_plot_points": 300,
    "throughput_bucket_seconds": 0.5,
    "default_protocol_filter": "All",
    "default_direction_filter": "All",
    "tshark_path": "/Applications/Wireshark.app/Contents/MacOS/tshark",
    "max_messages_display": 100000,
    "verbose_logging": False,
}


def get(key: str, default=None):
    """Get a config value by key. Returns default if not set."""
    config = _load()
    return config.get(key, _DEFAULTS.get(key, default))


def _load() -> dict:
    """Load config from TOML file, or return defaults."""
    global _CONFIG
    if _CONFIG is not None:
        return _CONFIG

    _CONFIG = dict(_DEFAULTS)

    if _CONFIG_PATH.exists():
        try:
            import tomllib
            with open(_CONFIG_PATH, "rb") as f:
                user_config = tomllib.load(f)
            _CONFIG.update(user_config)
        except Exception:
            pass  # Invalid TOML → use defaults silently

    return _CONFIG
