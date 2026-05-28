"""Analysis engine — runs state machine analyzers over a LogSession."""

from __future__ import annotations

from typing import Protocol as TypingProtocol, Sequence

from logparser.core.enums import Severity
from logparser.core.message import ParsedMessage
from logparser.core.session import LogSession


class Analyzer(TypingProtocol):
    def analyze(self, messages: Sequence[ParsedMessage]) -> list[tuple[int, Severity, str]]:
        """Analyze messages, return list of (msg_index, severity, annotation_text)."""
        ...


class AnalysisEngine:
    """Runs all registered analyzers over a session."""

    def __init__(self):
        self._analyzers: list[Analyzer] = []

    def register(self, analyzer: Analyzer) -> None:
        self._analyzers.append(analyzer)

    def analyze(self, session: LogSession) -> None:
        from logparser.core.enums import Severity

        # Pre-annotate SCGFailureInformation messages as FAILURE severity
        for msg in session.messages:
            if "SCGFailure" in msg.summary or "MCGFailure" in msg.summary:
                msg.severity = Severity.FAILURE
                if not msg.info and msg.decoded_tree:
                    ft = _extract_failure_type(msg.decoded_tree)
                    if ft:
                        msg.info = f"failureType: {ft}"

        # Enrich NAS reject messages with cause code lookup
        _enrich_nas_causes(session.messages)

        for analyzer in self._analyzers:
            annotations = analyzer.analyze(session.messages)
            session.apply_annotations(annotations)


def _enrich_nas_causes(messages) -> None:
    """Add human-readable cause codes to NAS reject messages."""
    import re
    from logparser.decoders.nas_causes import format_cause

    for msg in messages:
        summary = msg.summary.lower()
        # Only process NAS reject/failure messages
        if not any(kw in summary for kw in ("reject", "failure", "deny")):
            continue
        if not msg.decoded_tree or not isinstance(msg.decoded_tree, dict):
            continue

        # Search the decoded tree for cause code (5GMM or EMM)
        cause = _find_cause_code(msg.decoded_tree)
        if cause is not None:
            is_5g = "5g" in summary or "registration" in summary
            cause_str = format_cause(cause, is_5g=is_5g)
            if msg.info:
                msg.info = f"{cause_str} | {msg.info}"
            else:
                msg.info = cause_str


def _find_cause_code(tree, depth: int = 0) -> int | None:
    """Recursively find a cause code value in a decoded NAS tree."""
    if depth > 6:
        return None
    if isinstance(tree, dict):
        for key, val in tree.items():
            key_lower = key.lower()
            if "cause" in key_lower and isinstance(val, int):
                return val
            if "cause" in key_lower and isinstance(val, dict):
                # Nested: {"5GMMCause": {"V": 22}}
                v = val.get("V") or val.get("val") or val.get("value")
                if isinstance(v, int):
                    return v
            result = _find_cause_code(val, depth + 1)
            if result is not None:
                return result
    elif isinstance(tree, list):
        for item in tree[:5]:
            result = _find_cause_code(item, depth + 1)
            if result is not None:
                return result
    return None


def _extract_failure_type(tree) -> str:
    """Walk decoded tree to find failureType."""
    if isinstance(tree, dict):
        for key, val in tree.items():
            if key in ("failureType", "failureType-r16"):
                return str(val)
            result = _extract_failure_type(val)
            if result:
                return result
    elif isinstance(tree, (tuple, list)):
        for item in (tree if isinstance(tree, list) else [tree[1]] if len(tree) == 2 else []):
            result = _extract_failure_type(item)
            if result:
                return result
    return ""
