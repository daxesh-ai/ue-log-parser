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
        # Pre-annotate SCGFailureInformation messages as FAILURE severity
        for msg in session.messages:
            if "SCGFailure" in msg.summary or "MCGFailure" in msg.summary:
                from logparser.core.enums import Severity
                msg.severity = Severity.FAILURE
                # Extract failureType into info field
                if not msg.info and msg.decoded_tree:
                    ft = _extract_failure_type(msg.decoded_tree)
                    if ft:
                        msg.info = f"failureType: {ft}"

        for analyzer in self._analyzers:
            annotations = analyzer.analyze(session.messages)
            session.apply_annotations(annotations)


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
