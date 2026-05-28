"""Rule-based protocol health engine — detects failures from JSON config.

Covers:
- Timer-based failures (T300, T304, T310/T311, NAS timers)
- Explicit reject messages (red)
- Warning messages like reestablishment/release (orange)
- Configurable via rules.json
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence

from logparser.core.enums import Severity
from logparser.core.message import ParsedMessage

# Load rules
_RULES_PATH = Path(__file__).parent / "rules.json"


def _load_rules() -> dict:
    with open(_RULES_PATH) as f:
        return json.load(f)


class ProtocolHealthAnalyzer:
    """JSON-driven failure detection engine.

    Red (FAILURE): Rejects, timer timeouts, call drops
    Orange (WARNING): Reestablishments, releases, deprioritization
    """

    def __init__(self):
        self._rules = _load_rules()

    def analyze(self, messages: Sequence[ParsedMessage]) -> list[tuple[int, Severity, str]]:
        annotations: list[tuple[int, Severity, str]] = []

        # 1. Timer-based failure detection
        for timer in self._rules["timers"]:
            self._check_timer(messages, timer, annotations)

        # 2. Explicit reject detection
        self._check_rejects(messages, annotations)

        # 3. Warning messages
        self._check_warnings(messages, annotations)

        # Deduplicate by message index (keep highest severity)
        return self._deduplicate(annotations)

    def _check_timer(
        self,
        messages: Sequence[ParsedMessage],
        timer: dict,
        annotations: list,
    ):
        """Check for timer expiry: start_msg not followed by stop_msg within timeout."""
        start_pattern = timer["start_msg"].lower()
        stop_pattern = timer["stop_msg"].lower()
        fail_pattern = timer.get("fail_msg", "").lower() if timer.get("fail_msg") else None
        timeout_ms = timer["timeout_ms"]
        timer_id = timer["id"]
        description = timer["description"]
        severity = Severity.FAILURE if timer["severity"] == "FAILURE" else Severity.WARNING

        pending_start_idx: int | None = None
        pending_start_time = None

        for msg in messages:
            summary_lower = msg.summary.lower()

            # Check if this is a start message
            if start_pattern in summary_lower:
                pending_start_idx = msg.index
                pending_start_time = msg.timestamp

            # Check if this is a stop (success) message
            elif stop_pattern in summary_lower and pending_start_idx is not None:
                pending_start_idx = None
                pending_start_time = None

            # Check if this is an explicit failure message
            elif fail_pattern and fail_pattern in summary_lower and pending_start_idx is not None:
                annotations.append(
                    (msg.index, severity, f"{timer_id}: {description}")
                )
                pending_start_idx = None
                pending_start_time = None

            # Check for timeout
            elif pending_start_time is not None:
                elapsed_ms = (msg.timestamp - pending_start_time).total_seconds() * 1000
                if elapsed_ms > timeout_ms:
                    annotations.append(
                        (pending_start_idx, severity,
                         f"{timer_id} Timeout ({elapsed_ms:.0f}ms): {description}")
                    )
                    pending_start_idx = None
                    pending_start_time = None

    def _check_rejects(self, messages: Sequence[ParsedMessage], annotations: list):
        """Flag explicit reject messages."""
        reject_patterns = [r.lower() for r in self._rules["reject_messages"]]

        # Track which indices already have annotations
        annotated = {a[0] for a in annotations}

        for msg in messages:
            if msg.index in annotated:
                continue
            summary_lower = msg.summary.lower()
            for pattern in reject_patterns:
                if pattern in summary_lower:
                    annotations.append(
                        (msg.index, Severity.FAILURE, f"Reject: {msg.summary}")
                    )
                    break

    def _check_warnings(self, messages: Sequence[ParsedMessage], annotations: list):
        """Flag warning-level messages (reestablishment, release)."""
        warning_patterns = [w.lower() for w in self._rules["warning_messages"]]
        annotated = {a[0] for a in annotations}

        for msg in messages:
            if msg.index in annotated:
                continue
            summary_lower = msg.summary.lower()
            for pattern in warning_patterns:
                if pattern in summary_lower:
                    annotations.append(
                        (msg.index, Severity.WARNING, msg.summary)
                    )
                    break

    def _deduplicate(
        self, annotations: list[tuple[int, Severity, str]]
    ) -> list[tuple[int, Severity, str]]:
        """Keep only highest severity annotation per message index."""
        severity_rank = {Severity.FAILURE: 2, Severity.WARNING: 1, Severity.INFO: 0}
        best: dict[int, tuple[int, Severity, str]] = {}

        for idx, sev, text in annotations:
            if idx not in best or severity_rank[sev] > severity_rank[best[idx][1]]:
                best[idx] = (idx, sev, text)

        return list(best.values())


# Keep backward compatibility with old import
class RrcStateAnalyzer:
    """Legacy wrapper — delegates to ProtocolHealthAnalyzer."""

    def analyze(self, messages: Sequence[ParsedMessage]) -> list[tuple[int, Severity, str]]:
        return ProtocolHealthAnalyzer().analyze(messages)


class NasRegistrationAnalyzer:
    """No-op — NAS failures now handled by ProtocolHealthAnalyzer rules."""

    def analyze(self, messages: Sequence[ParsedMessage]) -> list[tuple[int, Severity, str]]:
        return []
