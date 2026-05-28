from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .enums import Direction, Protocol, Severity
from .message import ParsedMessage


@dataclass
class LogSession:
    filename: str
    messages: list[ParsedMessage] = field(default_factory=list)
    # PHY-layer measurement time series (from 0xB883)
    phy_measurements: list = field(default_factory=list)
    # MAC DL TB samples for MCS/throughput analysis (from 0xB8C9)
    mac_dl_samples: list = field(default_factory=list)
    # CQI/RI per carrier from PDSCH CSI reports (from 0xB8D1)
    phy_cqi_samples: list = field(default_factory=list)
    # SSB/CSI-RS beam measurements per PCI (from 0xB884/0xB885)
    phy_beam_samples: list = field(default_factory=list)
    # MAC UL TB samples (from 0xB8A1)
    mac_ul_samples: list = field(default_factory=list)
    # RLC DL stats (retransmissions) from 0x1874
    rlc_dl_stats: list = field(default_factory=list)
    # PDCP signaling throughput from 0x1CE2
    pdcp_samples: list = field(default_factory=list)
    # DL HARQ ACK/NACK feedback (BLER) from 0xB896
    harq_samples: list = field(default_factory=list)
    # UL power control config from 0xB8A7
    ul_power_config: list = field(default_factory=list)
    # Source file names (for multi-file sessions)
    source_files: list = field(default_factory=list)

    def filter(
        self,
        protocols: set[Protocol] | None = None,
        directions: set[Direction] | None = None,
        severity: Severity | None = None,
    ) -> list[ParsedMessage]:
        result = self.messages
        if protocols:
            result = [m for m in result if m.protocol in protocols]
        if directions:
            result = [m for m in result if m.direction in directions]
        if severity:
            result = [m for m in result if m.severity == severity]
        return result

    def apply_annotations(self, annotations: list[tuple[int, Severity, str]]) -> None:
        """Apply analysis annotations to messages by index."""
        idx_map = {m.index: m for m in self.messages}
        for msg_index, sev, text in annotations:
            msg = idx_map.get(msg_index)
            if msg:
                msg.severity = sev
                msg.annotations.append(text)
