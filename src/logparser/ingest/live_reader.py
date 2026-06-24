"""Real-time QXDM UDP Listener — streams live diag packets from QXDM/QPST.

Listens on a UDP socket for Qualcomm DIAG frames forwarded by QXDM
(Qualcomm eXtensible Diagnostic Monitor) or a compatible forwarder.

Usage:
  # CLI
  logparser-cli --live :4000          # listen on all interfaces, port 4000
  logparser-cli --live 192.168.1.5:4000  # from specific host

  # Programmatic
  from logparser.ingest.live_reader import LiveReader
  reader = LiveReader(host="0.0.0.0", port=4000)
  for packet in reader.read_packets():
      print(packet.log_code, packet.timestamp)

Frame format expected:
  Standard Qualcomm DIAG UDP framing:
  [2 bytes: frame_length LE] [2 bytes: log_code LE] [8 bytes: timestamp] [payload]

  OR raw HDLC-framed DIAG stream:
  0x7E ... 0x7E  (HDLC escape-coded DIAG frames)
"""

from __future__ import annotations

import socket
import struct
import threading
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

from logparser.ingest.diag_packet import DiagPacket
from logparser.ingest.quts_reader import decode_qualcomm_timestamp

# QXDM forwarding protocol constants
_DIAG_LOG_CODE_OFFSET = 2     # log code at byte offset 2 in DIAG frame
_DIAG_TIMESTAMP_OFFSET = 4    # timestamp at byte offset 4
_DIAG_PAYLOAD_OFFSET = 12     # payload starts at byte 12
_MIN_FRAME_SIZE = 16           # minimum valid DIAG frame
_MAX_FRAME_SIZE = 65535


class LiveReader:
    """UDP socket listener that yields DiagPacket objects in real time.

    Same interface as QutsReader so it slots directly into the pipeline.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 4000,
                 timeout_sec: float = 30.0):
        self._host = host
        self._port = port
        self._timeout = timeout_sec
        self._stop_event = threading.Event()
        self._socket: socket.socket | None = None

    def stop(self):
        """Stop listening."""
        self._stop_event.set()
        if self._socket:
            try:
                self._socket.close()
            except OSError:
                pass

    def read_packets(self) -> Iterator[DiagPacket]:
        """Listen for UDP DIAG frames and yield DiagPackets.

        Yields packets until stop() is called or timeout expires without data.
        """
        self._stop_event.clear()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(self._timeout)
        self._socket = sock

        try:
            sock.bind((self._host, self._port))

            while not self._stop_event.is_set():
                try:
                    data, addr = sock.recvfrom(65536)
                except socket.timeout:
                    return  # No data within timeout — stop
                except OSError:
                    return  # Socket closed

                # Parse one or more DIAG frames from the UDP payload
                yield from _parse_udp_payload(data)

        finally:
            sock.close()
            self._socket = None


def _parse_udp_payload(data: bytes) -> Iterator[DiagPacket]:
    """Parse a UDP datagram that may contain one or more DIAG frames."""
    if not data or len(data) < _MIN_FRAME_SIZE:
        return

    # Strategy 1: Length-prefixed frames (QXDM forwarding mode)
    if _looks_like_length_prefixed(data):
        yield from _parse_length_prefixed(data)
        return

    # Strategy 2: Raw HDLC framing (0x7E boundaries)
    if data[0] == 0x7E or 0x7E in data[:10]:
        yield from _parse_hdlc_framed(data)
        return

    # Strategy 3: Single raw DIAG frame (no framing)
    packet = _try_parse_raw_diag(data)
    if packet:
        yield packet


def _looks_like_length_prefixed(data: bytes) -> bool:
    """Heuristic: check if data starts with a valid length prefix."""
    if len(data) < 4:
        return False
    frame_len = struct.unpack_from("<H", data, 0)[0]
    return 16 <= frame_len <= len(data)


def _parse_length_prefixed(data: bytes) -> Iterator[DiagPacket]:
    """Parse length-prefixed DIAG frames: [u16_len][u16_log_code][u64_ts][payload]"""
    offset = 0
    while offset + 4 <= len(data):
        frame_len = struct.unpack_from("<H", data, offset)[0]
        if frame_len < _MIN_FRAME_SIZE or offset + frame_len > len(data):
            break

        frame = data[offset: offset + frame_len]
        packet = _try_parse_raw_diag(frame[2:])  # skip the length prefix bytes
        if packet:
            yield packet

        offset += frame_len


def _parse_hdlc_framed(data: bytes) -> Iterator[DiagPacket]:
    """Parse HDLC 0x7E-framed DIAG stream."""
    frames = data.split(b'\x7e')
    for frame in frames:
        if len(frame) < _MIN_FRAME_SIZE:
            continue
        # HDLC escape decoding
        frame = frame.replace(b'\x7d\x5e', b'\x7e').replace(b'\x7d\x5d', b'\x7d')
        # Check CRC (last 2 bytes are CRC16 — skip for now, just check length)
        if len(frame) >= _MIN_FRAME_SIZE:
            packet = _try_parse_raw_diag(frame)
            if packet:
                yield packet


def _try_parse_raw_diag(data: bytes) -> DiagPacket | None:
    """Try to parse a raw DIAG frame: [cmd=0x10][u16_len][u16_log_code][u64_ts][payload]"""
    if len(data) < _MIN_FRAME_SIZE:
        return None

    # DIAG LOG_F command code check
    cmd = data[0]
    if cmd not in (0x10, 0x00):  # 0x10=LOG_F, 0x00 can appear in some variants
        return None

    try:
        # Log code at offset 3 (after cmd + u16_length)
        log_code = struct.unpack_from("<H", data, 3)[0]
        if log_code == 0:
            return None

        # Timestamp at offset 5 (QUTS Qualcomm epoch: 1980-01-06, 50Hz ticks)
        ts_bytes = data[5:13]
        timestamp = decode_qualcomm_timestamp(ts_bytes)

        # Payload starts at offset 13
        payload = data[13:]
        if not payload:
            return None

        return DiagPacket(
            log_code=log_code,
            timestamp=timestamp,
            payload=payload,
        )
    except (struct.error, Exception):
        return None


def parse_host_port(address: str) -> tuple[str, int]:
    """Parse 'host:port' or ':port' address string."""
    if ":" in address:
        parts = address.rsplit(":", 1)
        host = parts[0] or "0.0.0.0"
        port = int(parts[1])
    else:
        host = "0.0.0.0"
        port = int(address)
    return host, port
