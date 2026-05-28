"""Apple .logarchive / sysdiagnose reader.

Uses the macOS /usr/bin/log tool to extract cellular and IMS events from:
  - *.logarchive directories (Apple Unified Log format)
  - sysdiagnose_*.tar.gz archives (contains system_logs.logarchive + more)

Extracts and maps to ParsedMessage:
  - CommCenter cell info (LTE/NR EARFCN, PCI, RSRP, registration state)
  - IMS/SIP events (registration, call setup, teardown, failures)
  - Network failures (QMI errors, attach rejects, handovers)
  - 5G status changes (EN-DC, SA, UWB indicator)
  - WiFi scan results from sysdiagnose WiFi/wifi_scan.txt

Requires macOS with /usr/bin/log available.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Iterator

from logparser.core.enums import Direction, Protocol, Severity
from logparser.core.message import ParsedMessage
from logparser.core.session import LogSession

# ── log tool predicates ──────────────────────────────────────────────────────

# Targeted predicate: CommCenter cellular + IMS + failures
_BB_PREDICATE = (
    'process == "CommCenter" AND ('
    '  message CONTAINS "LTE Serving" OR '
    '  message CONTAINS "NR Neighbor" OR '
    '  message CONTAINS "NRARFCN" OR '
    '  message CONTAINS "EARFCN" OR '
    '  message CONTAINS "5G_Uwb" OR '
    '  message CONTAINS "5G_NrConnected" OR '
    '  message CONTAINS "5G_Nr" OR '
    '  message CONTAINS "kCTRegistration" OR '
    '  message CONTAINS "SIP" OR '
    '  message CONTAINS "sip.reg" OR '
    '  message CONTAINS "IMS" OR '
    '  message CONTAINS "ims.awd" OR '
    '  message CONTAINS "INVITE" OR '
    '  message CONTAINS "BYE" OR '
    '  message CONTAINS "REGISTER" OR '
    '  message CONTAINS "RegistrationClient" OR '
    '  message CONTAINS "ImsTcpNw" OR '
    '  message CONTAINS "handoff" OR '
    '  message CONTAINS "handover" OR '
    '  message CONTAINS "SRVCC" OR '
    '  message CONTAINS "eSRVCC" OR '
    '  message CONTAINS "VoLTE" OR '
    '  message CONTAINS "VoNR" OR '
    '  message CONTAINS "reject" OR '
    '  message CONTAINS "attach" OR '
    '  message CONTAINS "Attach" OR '
    '  message CONTAINS "NETWORK_NOT_READY" OR '
    '  message CONTAINS "pdp_ip" OR '
    '  message CONTAINS "endc_sub6" OR '
    '  message CONTAINS "nr_sa" OR '
    '  message CONTAINS "KeepAlive" '
    ')'
)


@dataclass
class LogEntry:
    """A single entry from the logarchive."""
    timestamp: datetime
    process: str
    subsystem: str
    category: str
    message: str


# ── log tool invocation ───────────────────────────────────────────────────────

def _log_tool_available() -> bool:
    return os.path.exists("/usr/bin/log")


def _stream_log_entries(
    archive_path: Path,
    predicate: str,
    max_entries: int = 10000,
) -> list[LogEntry]:
    """Run /usr/bin/log show and parse syslog-format output.

    Uses --style syslog for reliable line-by-line parsing.
    The JSON output from log show is multiple concatenated JSON objects
    (not an array) which can be 250MB+ for large archives — syslog is faster.
    """
    if not _log_tool_available():
        raise RuntimeError(
            "macOS /usr/bin/log tool not available. "
            "logarchive files require macOS to decode."
        )

    cmd = [
        "/usr/bin/log", "show",
        str(archive_path),
        "--predicate", predicate,
        "--style", "syslog",
        "--info",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        raise ValueError(f"log tool timed out reading {archive_path.name}")

    return _parse_syslog_output(result.stdout, max_entries=max_entries)


def _parse_log_ts(ts_str: str) -> datetime:
    """Parse Apple log timestamp: '2025-11-12 08:49:24.097320-0500'"""
    # Replace space with T, handle timezone offset
    ts_str = ts_str.replace(" ", "T", 1)
    # Python fromisoformat handles ±HHMM offsets in 3.11+, fallback for older
    try:
        return datetime.fromisoformat(ts_str)
    except ValueError:
        # Trim microseconds if too many digits
        base, _, tz = ts_str.partition(".")
        micro_and_tz = _ + tz
        # Find where timezone starts
        for i, c in enumerate(micro_and_tz):
            if c in "+-" and i > 0:
                micro = micro_and_tz[:i].ljust(6, "0")[:6]
                tz_part = micro_and_tz[i:]
                sign = 1 if tz_part[0] == "+" else -1
                hh = int(tz_part[1:3])
                mm = int(tz_part[3:5])
                offset = timedelta(hours=hh, minutes=mm) * sign
                naive = datetime.strptime(f"{base}.{micro}", "%Y-%m-%dT%H:%M:%S.%f")
                return naive.replace(tzinfo=timezone(offset))
    return datetime.now(timezone.utc)


def _parse_syslog_output(text: str, max_entries: int = 10000) -> list[LogEntry]:
    """Parse syslog-format output from /usr/bin/log show --style syslog.

    Format: "2025-11-12 08:49:24.097320-0500  localhost CommCenter[110]: (lib.dylib) [subsystem:category] message"
    or:     "2025-11-12 08:49:24.097320-0500  localhost CommCenter[110]: message"
    """
    # Match timestamp + host + process[pid]: rest
    pattern = re.compile(
        r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+[+-]\d{4})\s+"
        r"\S+\s+(\w[\w.]*)\[\d+\]:\s*(.+)$"
    )
    # Extract subsystem/category from [subsystem:category] prefix
    subcat_pattern = re.compile(r"^\(.*?\)\s+\[([^\]:]+):([^\]]*)\]\s+(.+)$")

    entries = []
    for line in text.splitlines():
        if len(entries) >= max_entries:
            break
        line = line.strip()
        if not line:
            continue
        m = pattern.match(line)
        if not m:
            continue
        try:
            ts = _parse_log_ts(m.group(1))
        except Exception:
            continue

        process = m.group(2)
        rest = m.group(3)

        # Try to extract subsystem:category
        subsystem, category = "", ""
        sc = subcat_pattern.match(rest)
        if sc:
            subsystem = sc.group(1)
            category = sc.group(2)
            message = sc.group(3)
        else:
            # Strip leading (library) prefix if present
            message = re.sub(r"^\(.*?\)\s+", "", rest)

        entries.append(LogEntry(
            timestamp=ts,
            process=process,
            subsystem=subsystem,
            category=category,
            message=message.strip(),
        ))

    return entries


# ── event parsing ─────────────────────────────────────────────────────────────

# QMI NAS service message IDs (partial, key ones)
_NAS_MSG_IDS = {
    "0x5568": "NAS Cell Signal Report",
    "0x0022": "NAS Get Signal Strength",
    "0x0033": "NAS Get Cell Location Info",
    "0x006C": "NAS Get RSRP",
    "0x006F": "NAS System Selection Pref",
}

_5G_STATUS_MAP = {
    "5G_Uwb": "5G mmWave (UWB)",
    "5G_NrConnected": "5G NR Connected",
    "5G_Nr": "5G NR",
    "5G_NrNsa": "5G NSA (EN-DC)",
    "5G_NrSa": "5G SA",
    "LTE": "LTE",
    "LTE_CA": "LTE-CA",
    "3G": "3G",
}


def _classify_entry(entry: LogEntry) -> tuple[str, str, Direction, Severity, str]:
    """Return (summary, channel, direction, severity, info) for a log entry."""
    msg = entry.message
    msg_lower = msg.lower()
    severity = Severity.NORMAL
    direction = Direction.UNKNOWN
    channel = "CommCenter"
    info = ""

    # ── Cell info reports ────────────────────────────────────────────────────
    if "LTE Serving Cells" in msg or "EARFCN" in msg:
        m = re.search(r"EARFCN:\s*(\d+).*?PCI:\s*(\d+).*?RSRP:\s*(-?\d+)", msg)
        if m and int(m.group(3)) != 32767:
            earfcn, pci, rsrp = int(m.group(1)), int(m.group(2)), int(m.group(3))
            # Apple stores RSRP differently — large negative = actual value
            if rsrp > 32000:
                rsrp_dbm = rsrp - 65536  # unsigned → signed
            else:
                rsrp_dbm = rsrp
            info = f"EARFCN:{earfcn} PCI:{pci} RSRP:{rsrp_dbm}dBm"
            return "LTE Cell Info", "Cell", Direction.DL, Severity.NORMAL, info

    if "NRARFCN" in msg:
        m = re.search(r"NRARFCN:\s*(\d+).*?PCI:\s*(\d+).*?RSRP:\s*(-?\d+)", msg)
        if m:
            nrarfcn, pci, rsrp_raw = int(m.group(1)), int(m.group(2)), int(m.group(3))
            rsrp_dbm = rsrp_raw - (1 << 32) if rsrp_raw > 32768 else rsrp_raw
            is_sa = "Is SA: 1" in msg
            rat = "NR SA" if is_sa else "NR NSA"
            info = f"NR-ARFCN:{nrarfcn} PCI:{pci} RSRP:{rsrp_dbm}dBm {'SA' if is_sa else 'NSA/EN-DC'}"
            return f"{rat} Cell Info", "Cell", Direction.DL, Severity.NORMAL, info

    # ── 5G status changes ────────────────────────────────────────────────────
    if "kCTRegistrationDataIndicatorStatus" in msg or "5G_" in msg:
        for key, label in _5G_STATUS_MAP.items():
            if key in msg:
                return f"Data Indicator: {label}", "Status", Direction.DL, Severity.NORMAL, label

    # ── IMS / SIP events ─────────────────────────────────────────────────────
    if "SipStack" in msg or "sip.reg" in entry.category or "RegistrationClient" in msg:
        if "registered" in msg_lower or "Registration" in msg:
            return "IMS Registration", "IMS", Direction.UL, Severity.NORMAL, msg[:80]
        if "deregister" in msg_lower or "termination" in msg_lower:
            severity = Severity.WARNING
            return "IMS Deregistration", "IMS", Direction.UL, severity, msg[:80]
        if "fail" in msg_lower or "error" in msg_lower or "reject" in msg_lower:
            severity = Severity.FAILURE
            return "IMS Registration Failure", "IMS", Direction.DL, severity, msg[:80]
        return "IMS/SIP Event", "IMS", Direction.UNKNOWN, Severity.NORMAL, msg[:80]

    if "ImsTcpNw" in msg:
        if "closed" in msg_lower or "cancel" in msg_lower:
            severity = Severity.WARNING
            return "IMS TCP Connection Closed", "IMS", Direction.DL, severity, msg[:80]
        return "IMS TCP Event", "IMS", Direction.UNKNOWN, Severity.NORMAL, msg[:80]

    if "KeepAlive" in msg and "IMS" in msg:
        return "IMS KeepAlive", "IMS", Direction.UL, Severity.NORMAL, ""

    # ── Network failures ─────────────────────────────────────────────────────
    if "NETWORK_NOT_READY" in msg or "Get Cell Info failed" in msg:
        severity = Severity.FAILURE
        return "Network Not Ready", "CommCenter", Direction.DL, severity, msg[:80]

    if "reject" in msg_lower or "fail" in msg_lower:
        severity = Severity.FAILURE
        return "Network Failure", "CommCenter", Direction.DL, severity, msg[:80]

    # ── EN-DC / handover ─────────────────────────────────────────────────────
    if "endc_sub6" in msg_lower:
        return "EN-DC Sub-6 Bearer", "Bearer", Direction.DL, Severity.NORMAL, msg[:80]

    if "handoff" in msg_lower or "handover" in msg_lower or "SRVCC" in msg:
        return "Handover Event", "Mobility", Direction.UNKNOWN, Severity.WARNING, msg[:80]

    if "pdp_ip" in msg_lower:
        return "PDP Context Event", "Bearer", Direction.DL, Severity.NORMAL, msg[:80]

    if "attach" in msg_lower:
        return "Attach Event", "NAS", Direction.UL, Severity.NORMAL, msg[:60]

    return "CommCenter Event", "CommCenter", Direction.UNKNOWN, Severity.NORMAL, msg[:80]


def _entries_to_messages(
    entries: list[LogEntry],
    start_index: int = 0,
) -> list[ParsedMessage]:
    """Convert LogEntry objects to ParsedMessage objects."""
    messages = []
    # Deduplicate consecutive identical messages
    prev_summary = None

    for i, entry in enumerate(entries):
        summary, channel, direction, severity, info = _classify_entry(entry)

        # Skip pure noise (SAR, grip, OBD callbacks)
        if any(skip in entry.message for skip in [
            "AppleSARFusion", "OBD State", "Grip State",
            "Sending SAR", "Sending Grip", "Hand Detection",
            "On Body Callback",
        ]):
            continue

        # Deduplicate identical consecutive summaries (cell polling every ~1s)
        if summary == prev_summary and summary in ("LTE Cell Info", "NR NSA Cell Info"):
            # Only keep every 10th duplicate for display
            if i % 10 != 0:
                continue
        prev_summary = summary

        msg = ParsedMessage(
            index=start_index + len(messages),
            timestamp=entry.timestamp,
            protocol=Protocol.NR_NAS,   # Apple baseband uses NAS-like protocol
            direction=direction,
            channel=channel,
            summary=summary,
            raw_payload=b"",
            decoded_tree={"message": entry.message, "subsystem": entry.subsystem},
            decoded_text=entry.message,
            source_entity="CommCenter",
            target_entity="Baseband",
            info=info,
            severity=severity,
        )
        messages.append(msg)

    return messages


# ── sysdiagnose extras ────────────────────────────────────────────────────────

@dataclass
class SysdiagnoseInfo:
    """Metadata extracted from a sysdiagnose archive."""
    wifi_scan: list[dict]       # [{bssid, ssid, rssi, channel, phy}]
    pcap_paths: list[Path]      # extracted .pcap paths
    logarchive_path: Path | None


def _parse_wifi_scan(text: str) -> list[dict]:
    """Parse WiFi/wifi_scan.txt into structured records."""
    networks = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("bssid="):
            continue
        rec: dict = {}
        for field in line.split(", "):
            if "=" in field:
                k, _, v = field.partition("=")
                rec[k.strip()] = v.strip()
        # Parse RSSI as int
        try:
            rec["rssi"] = int(rec.get("rssi", "0"))
        except ValueError:
            rec["rssi"] = 0
        networks.append(rec)
    return sorted(networks, key=lambda n: n["rssi"], reverse=True)


def extract_sysdiagnose(
    archive_path: Path,
    dest_dir: Path | None = None,
) -> SysdiagnoseInfo:
    """Extract a sysdiagnose .tar.gz and return structured metadata."""
    if dest_dir is None:
        dest_dir = Path(tempfile.mkdtemp(prefix="sysdiag_"))

    with tarfile.open(archive_path, "r:gz") as tf:
        tf.extractall(dest_dir, filter="data")

    # Find the root directory inside
    roots = [d for d in dest_dir.iterdir() if d.is_dir()]
    root = roots[0] if roots else dest_dir

    # WiFi scan
    wifi_scan = []
    wifi_file = root / "WiFi" / "wifi_scan.txt"
    if wifi_file.exists():
        wifi_scan = _parse_wifi_scan(wifi_file.read_text(errors="replace"))

    # PCAP files
    pcap_paths = list(root.rglob("*.pcap"))

    # logarchive
    logarchive = None
    for la in root.rglob("*.logarchive"):
        if la.is_dir():
            logarchive = la
            break
    if logarchive is None:
        la_file = root / "system_logs.logarchive"
        if la_file.exists():
            logarchive = la_file

    return SysdiagnoseInfo(
        wifi_scan=wifi_scan,
        pcap_paths=pcap_paths,
        logarchive_path=logarchive,
    )


# ── public API ────────────────────────────────────────────────────────────────

def is_logarchive(path: Path) -> bool:
    """Check if path is a .logarchive directory."""
    return path.is_dir() and path.suffix.lower() == ".logarchive"


def is_sysdiagnose(path: Path) -> bool:
    """Check if path is a sysdiagnose .tar.gz archive."""
    name = path.name.lower()
    return name.startswith("sysdiagnose") and (
        name.endswith(".tar.gz") or name.endswith(".tgz")
    )


def load_logarchive(
    archive_path: Path,
    progress_callback=None,
) -> LogSession:
    """Load a .logarchive directory and return a LogSession with cellular events."""
    if not _log_tool_available():
        raise ValueError(
            "macOS /usr/bin/log tool not found.\n"
            ".logarchive files require macOS to decode.\n"
            "Run this tool on a Mac to analyze Apple baseband logs."
        )

    if progress_callback:
        progress_callback(0, 100)

    entries = _stream_log_entries(archive_path, _BB_PREDICATE)

    if progress_callback:
        progress_callback(50, 100)

    session = LogSession(filename=archive_path.name)
    session.messages = _entries_to_messages(entries)

    if progress_callback:
        progress_callback(100, 100)

    return session


def load_sysdiagnose(
    archive_path: Path,
    progress_callback=None,
) -> LogSession:
    """Extract a sysdiagnose .tar.gz and load its cellular log data."""
    if progress_callback:
        progress_callback(0, 100)

    dest = Path(tempfile.mkdtemp(prefix="sysdiag_"))
    try:
        info = extract_sysdiagnose(archive_path, dest)

        if progress_callback:
            progress_callback(30, 100)

        session = LogSession(filename=archive_path.name)

        # Load from logarchive if available and log tool present
        if info.logarchive_path and _log_tool_available():
            entries = _stream_log_entries(info.logarchive_path, _BB_PREDICATE)
            session.messages = _entries_to_messages(entries)
        elif info.pcap_paths:
            # Fall back to largest PCAP
            pcap = max(info.pcap_paths, key=lambda p: p.stat().st_size)
            from logparser.ingest.pcap_reader import load_pcap
            session = load_pcap(pcap, progress_callback)
            session.filename = archive_path.name
        else:
            raise ValueError(
                f"No usable data found in sysdiagnose archive.\n"
                f"  - logarchive: {'found' if info.logarchive_path else 'not found'}\n"
                f"  - PCAPs: {len(info.pcap_paths)}\n"
                f"  - WiFi scan: {len(info.wifi_scan)} networks\n"
                f"Tip: The log tool requires macOS. PCap files were{'nt' if not info.pcap_paths else ''} available."
            )

        # Attach wifi scan as session metadata
        if info.wifi_scan:
            session.__dict__["wifi_scan"] = info.wifi_scan

        if progress_callback:
            progress_callback(100, 100)

        return session

    finally:
        # Clean up temp extraction (on success and failure)
        import shutil as _shutil
        _shutil.rmtree(dest, ignore_errors=True)


# ── CLI usage ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m logparser.ingest.logarchive_reader <path>")
        print("  <path> can be: .logarchive directory or sysdiagnose_*.tar.gz")
        sys.exit(1)

    path = Path(sys.argv[1])

    if is_logarchive(path):
        session = load_logarchive(path)
    elif is_sysdiagnose(path):
        session = load_sysdiagnose(path)
    else:
        print(f"Unknown file type: {path.suffix}", file=sys.stderr)
        sys.exit(1)

    print(f"Loaded {len(session.messages)} events from {path.name}")
    print()
    for msg in session.messages[:30]:
        sev = f"[{msg.severity.name}]" if msg.severity != Severity.NORMAL else ""
        print(f"  {msg.timestamp.strftime('%H:%M:%S.%f')[:-3]}  "
              f"{msg.channel:<12} {msg.summary:<35} {msg.info[:60]}")
        if sev:
            print(f"    {sev}")
