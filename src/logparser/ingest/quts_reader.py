"""Parser for Qualcomm QUTS (.hdf) container format.

QUTS files have:
- 4-byte magic: b'.hdf'
- 4-byte version (LE uint32, typically 5)
- Copyright string with length prefix
- QUTS marker
- Records separated by b'\\xff\\xff\\xff\\xff'

Each DIAG_LOG_F record (opcode 0x10) contains:
  [opcode:1][pending:1][outer_len:2 LE][inner_len:2 LE][log_code:2 LE][timestamp:8][payload]
"""

from __future__ import annotations

import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

from .diag_packet import DiagPacket

QUTS_MAGIC = b".hdf"
RECORD_SEPARATOR = b"\xff\xff\xff\xff"
DIAG_LOG_F = 0x10

# Qualcomm timestamp epoch: January 6, 1980 UTC
_QUALCOMM_EPOCH = datetime(1980, 1, 6, tzinfo=timezone.utc)


def decode_qualcomm_timestamp(ts_bytes: bytes) -> datetime:
    """Decode 8-byte Qualcomm CDMA timestamp to datetime."""
    ts = struct.unpack("<Q", ts_bytes)[0]
    if ts == 0:
        return _QUALCOMM_EPOCH
    seconds = (ts >> 20) / 50.0
    fraction = (ts & 0xFFFFF) / 0x100000
    total = seconds + fraction
    # Guard against invalid timestamps (> year 2100 or negative)
    if total > 4_000_000_000 or total < 0:
        return _QUALCOMM_EPOCH
    try:
        return _QUALCOMM_EPOCH + timedelta(seconds=total)
    except (OverflowError, OSError):
        return _QUALCOMM_EPOCH


def is_quts_file(filepath: Path) -> bool:
    """Check if a file is in QUTS format by reading the magic bytes."""
    try:
        with open(filepath, "rb") as f:
            return f.read(4) == QUTS_MAGIC
    except OSError:
        return False


class QutsReader:
    """Reads a QUTS (.hdf) file and yields DiagPackets."""

    def __init__(self, filepath: Path):
        self._filepath = filepath

    def read_packets(
        self, progress_callback: callable | None = None
    ) -> Iterator[DiagPacket]:
        """Yield DiagPackets from the QUTS file in file order."""
        with open(self._filepath, "rb") as f:
            data = f.read()

        file_size = len(data)
        pos = 0

        # Skip file header — find the first record separator
        first_sep = data.find(RECORD_SEPARATOR, 0x100)
        if first_sep == -1:
            return
        pos = first_sep

        packet_count = 0
        while pos < file_size:
            sep_pos = data.find(RECORD_SEPARATOR, pos)
            if sep_pos == -1:
                break

            rec_start = sep_pos + 4
            if rec_start + 16 > file_size:
                break

            opcode = data[rec_start]

            if opcode == DIAG_LOG_F:
                # Parse DLF-style record
                inner_len = struct.unpack_from("<H", data, rec_start + 4)[0]
                log_code = struct.unpack_from("<H", data, rec_start + 6)[0]
                ts_bytes = data[rec_start + 8 : rec_start + 16]

                payload_start = rec_start + 16
                payload_len = inner_len - 12  # inner_len includes len(2)+code(2)+ts(8)

                if payload_len > 0 and payload_start + payload_len <= file_size:
                    payload = data[payload_start : payload_start + payload_len]
                    timestamp = decode_qualcomm_timestamp(ts_bytes)

                    yield DiagPacket(
                        log_code=log_code,
                        timestamp=timestamp,
                        payload=payload,
                    )
                    packet_count += 1

                    if progress_callback and packet_count % 100 == 0:
                        progress_callback(sep_pos, file_size)

            pos = sep_pos + 5  # Move past separator + 1 byte to avoid re-matching

        if progress_callback:
            progress_callback(file_size, file_size)
