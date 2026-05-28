"""Pipeline: orchestrates file loading → header stripping → decoding → session."""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from .analysis.engine import AnalysisEngine
from .analysis.rrc_state import NasRegistrationAnalyzer, RrcStateAnalyzer
from .core.enums import Direction, Protocol, Severity
from .decoders.info_extractor import extract_info
from .core.message import ParsedMessage
from .core.session import LogSession
from .decoders.base import DecodeResult
from .decoders.lte_rrc import LteRrcDecoder
from .decoders.nas import LteNasDecoder, NrNasDecoder
from .decoders.nr_rrc import NrRrcDecoder
from .headers.base import StrippedPayload
from .headers.lte_rrc_header import LteRrcHeaderStripper
from .headers.nas_header import LteNasHeaderStripper, NrNasHeaderStripper
from .headers.nr_rrc_header import NrRrcHeaderStripper
from .ingest.archive import extract_hdf_from_archive, is_archive
from .ingest.diag_packet import DiagPacket
from .ingest.quts_reader import QutsReader, is_quts_file

# Log code → (HeaderStripper, Decoder, Protocol) mapping
_REGISTRY: dict[int, tuple] = {}


def _build_registry() -> dict[int, tuple]:
    nr_rrc_strip = NrRrcHeaderStripper()
    lte_rrc_strip = LteRrcHeaderStripper()
    nr_nas_strip = NrNasHeaderStripper()
    lte_nas_dl_strip = LteNasHeaderStripper(is_uplink=False)
    lte_nas_ul_strip = LteNasHeaderStripper(is_uplink=True)

    nr_rrc_dec = NrRrcDecoder()
    lte_rrc_dec = LteRrcDecoder()
    nr_nas_dec = NrNasDecoder()
    lte_nas_dec = LteNasDecoder()

    return {
        0xB821: (nr_rrc_strip, nr_rrc_dec, Protocol.NR_RRC),
        0xB0C0: (lte_rrc_strip, lte_rrc_dec, Protocol.LTE_RRC),
        0xB0EC: (lte_nas_dl_strip, lte_nas_dec, Protocol.LTE_NAS),
        0xB0ED: (lte_nas_ul_strip, lte_nas_dec, Protocol.LTE_NAS),
        # Note: 0xB97F is NR ML1 Measurement Database (not NAS signaling).
        # 5G NAS is decoded from within RRC via dedicatedNAS-Message containers.
    }


def _find_log_in_dir(dirpath: Path) -> Path | None:
    """Search a directory for the best log file (.hdf or .pcap)."""
    hdf_files = []
    pcap_files = []
    for f in dirpath.rglob("*"):
        if not f.is_file():
            continue
        if f.suffix.lower() == ".hdf":
            hdf_files.append(f)
        elif f.suffix.lower() in (".pcap", ".pcapng"):
            pcap_files.append(f)
    # Prefer largest .hdf
    if hdf_files:
        return max(hdf_files, key=lambda f: f.stat().st_size)
    if pcap_files:
        return max(pcap_files, key=lambda f: f.stat().st_size)
    return None


def load_file(
    filepath: Path,
    progress_callback: Callable[[int, int], None] | None = None,
) -> LogSession:
    """Load a .hdf (QUTS) file and return a fully decoded LogSession."""
    global _REGISTRY
    if not _REGISTRY:
        _REGISTRY = _build_registry()

    # Handle .logarchive directories (Apple Unified Log)
    from .ingest.logarchive_reader import is_logarchive, is_sysdiagnose, load_logarchive, load_sysdiagnose
    if is_logarchive(filepath):
        return load_logarchive(filepath, progress_callback)
    if is_sysdiagnose(filepath):
        return load_sysdiagnose(filepath, progress_callback)

    # Handle Apple .acp / bb-trace directories, or any directory
    from .ingest.acp_reader import is_acp_file, find_hdf_for_acp
    if filepath.is_dir() or is_acp_file(filepath):
        hdf_path = find_hdf_for_acp(filepath)
        if hdf_path is None:
            # Try to find any .hdf or .pcap in the directory
            hdf_path = _find_log_in_dir(filepath)
        if hdf_path is None:
            raise ValueError(
                f"No log file found in {filepath.name}.\n"
                f"Expected MergedFile_Diag.hdf, .hdf, or .pcap inside the folder."
            )
        filepath = hdf_path

    # Handle archives: extract and find .hdf inside
    if is_archive(filepath):
        extracted = extract_hdf_from_archive(filepath)
        if extracted is None:
            raise ValueError(f"No .hdf log file found inside archive: {filepath.name}")
        filepath = extracted

    # Handle PCAP/PCAPNG files via pyshark
    from .ingest.pcap_reader import is_pcap_file, load_pcap
    if is_pcap_file(filepath):
        session = load_pcap(filepath, progress_callback)
        # Run analysis
        engine = AnalysisEngine()
        engine.register(RrcStateAnalyzer())
        engine.register(NasRegistrationAnalyzer())
        engine.analyze(session)
        _apply_tech_tracking(session)
        return session

    if not is_quts_file(filepath):
        raise ValueError(f"Unsupported file format: {filepath}")

    from .core.logging import get_logger
    logger = get_logger("logparser.pipeline")

    reader = QutsReader(filepath)
    session = LogSession(filename=filepath.name)

    # ── SINGLE-PASS: read all packets once, dispatch to signaling + PHY/MAC ──
    signaling_packets: list[DiagPacket] = []
    mac_ce_packets: list[DiagPacket] = []
    phy_mac_packets: list[DiagPacket] = []

    _PHY_MAC_CODES = {0xB883, 0xB8D1, 0xB884, 0xB885, 0xB8C9, 0xB8A1,
                      0x1874, 0x1CE2, 0xB896, 0xB8A7}
    _MAC_CE_CODE = 0xB887

    packet_count = 0
    for packet in reader.read_packets():
        packet_count += 1
        code = packet.log_code
        if code in _REGISTRY:
            signaling_packets.append(packet)
        if code == _MAC_CE_CODE:
            mac_ce_packets.append(packet)
        elif code in _PHY_MAC_CODES:
            phy_mac_packets.append(packet)

    logger.debug("Read %d total packets: %d signaling, %d MAC-CE, %d PHY/MAC",
                 packet_count, len(signaling_packets), len(mac_ce_packets), len(phy_mac_packets))

    # Sort signaling by timestamp
    signaling_packets.sort(key=lambda p: p.timestamp)
    total = len(signaling_packets)
    for i, packet in enumerate(signaling_packets):
        stripper, decoder, protocol = _REGISTRY[packet.log_code]

        # Strip sub-headers
        stripped = stripper.strip(packet.payload)
        if stripped is None:
            # Create a "decode failed" message
            msg = ParsedMessage(
                index=i,
                timestamp=packet.timestamp,
                protocol=protocol,
                direction=Direction.UNKNOWN,
                channel="?",
                summary="[Header parse failed]",
                raw_payload=packet.payload,
                log_code=packet.log_code,
                severity=Severity.INFO,
            )
            session.messages.append(msg)
            continue

        # Decode
        result = decoder.decode(stripped.pdu, stripped.channel, stripped.direction)

        if result is not None:
            # Extract key info from decoded IEs
            info = extract_info(result.decoded_tree, result.summary)

            msg = ParsedMessage(
                index=i,
                timestamp=packet.timestamp,
                protocol=result.protocol,
                direction=result.direction,
                channel=result.channel,
                summary=result.summary,
                raw_payload=stripped.pdu,
                decoded_tree=result.decoded_tree,
                decoded_text=result.decoded_text,
                log_code=packet.log_code,
                source_entity=result.source_entity,
                target_entity=result.target_entity,
                pci=stripped.pci,
                arfcn=stripped.arfcn,
                bearer_id=stripped.bearer_id,
                info=info,
            )
        else:
            msg = ParsedMessage(
                index=i,
                timestamp=packet.timestamp,
                protocol=protocol,
                direction=stripped.direction,
                channel=stripped.channel,
                summary="[Decode failed]",
                raw_payload=stripped.pdu,
                log_code=packet.log_code,
                severity=Severity.INFO,
                pci=stripped.pci,
                arfcn=stripped.arfcn,
                bearer_id=stripped.bearer_id,
            )

        session.messages.append(msg)

        if progress_callback and (i % 50 == 0 or i == total - 1):
            progress_callback(i + 1, total)

    # Decode MAC-CE SCell Activation/Deactivation (from cached packets)
    _load_mac_ce_events_from_packets(mac_ce_packets, session)

    # Load PHY/MAC data (from cached packets — no re-read!)
    _load_phy_mac_data_from_packets(phy_mac_packets, session)

    # Re-sort all messages by timestamp (MAC-CE interleaved with RRC)
    session.messages.sort(key=lambda m: m.timestamp)
    for i, msg in enumerate(session.messages):
        msg.index = i

    # Run analysis engine
    engine = AnalysisEngine()
    engine.register(RrcStateAnalyzer())
    engine.register(NasRegistrationAnalyzer())
    engine.analyze(session)

    _apply_tech_tracking(session)
    return session


def load_files(
    filepaths: list[Path],
    progress_callback: Callable[[int, int], None] | None = None,
) -> LogSession:
    """Load multiple .hdf/.pcap files and merge by timestamp into one session."""
    import sys
    merged = LogSession(filename=f"{len(filepaths)} files merged")
    merged.source_files = [p.name for p in filepaths]
    all_messages = []

    total_files = len(filepaths)
    for file_idx, filepath in enumerate(filepaths):
        try:
            def file_progress(cur, tot, fi=file_idx, tf=total_files):
                if progress_callback:
                    overall = (fi * 100 + (100 * cur // max(1, tot))) // tf
                    progress_callback(overall, 100)

            session = load_file(filepath, file_progress)
            # Tag each message with its source file
            fname = filepath.name
            for msg in session.messages:
                msg.source_file = fname
            all_messages.extend(session.messages)
            # Merge time series
            for attr in ("phy_measurements", "phy_cqi_samples", "phy_beam_samples",
                         "mac_dl_samples", "mac_ul_samples", "rlc_dl_stats",
                         "pdcp_samples", "harq_samples"):
                getattr(merged, attr).extend(getattr(session, attr, []))
        except Exception as e:
            print(f"Warning: skipping {filepath.name}: {e}", file=sys.stderr)

    # Sort by timestamp and re-index
    all_messages.sort(key=lambda m: m.timestamp)
    for i, msg in enumerate(all_messages):
        msg.index = i
    merged.messages = all_messages

    if progress_callback:
        progress_callback(90, 100)

    # Re-run analysis on merged session
    engine = AnalysisEngine()
    engine.register(RrcStateAnalyzer())
    engine.register(NasRegistrationAnalyzer())
    engine.analyze(merged)
    _apply_tech_tracking(merged)

    if progress_callback:
        progress_callback(100, 100)

    return merged


def _load_phy_mac_data(reader, session: LogSession) -> None:
    """Load PHY/MAC time-series data from all measurement log codes."""
    from .decoders.nr_phy import (
        decode_phy_measurements, decode_phy_cqi,
        decode_ssb_measurements, decode_csirs_measurements,
        decode_harq_feedback,
    )
    from .decoders.nr_mac import decode_mac_dl_tb, decode_mac_ul_tb
    from .decoders.nr_rlc import decode_rlc_dl_stats
    from .decoders.nr_pdcp import decode_pdcp_throughput

    phy_samples = []
    cqi_samples = []
    beam_samples = []
    mac_dl = []
    mac_ul = []
    rlc_stats = []
    pdcp_samples = []
    harq_samples = []
    prev_pdcp_bytes = None
    prev_pdcp_ts = None

    for packet in reader.read_packets():
        code = packet.log_code
        if code == 0xB883:
            phy_samples.extend(decode_phy_measurements(packet.payload, packet.timestamp))
        elif code == 0xB8D1:
            cqi_samples.extend(decode_phy_cqi(packet.payload, packet.timestamp))
        elif code == 0xB884:
            beam_samples.extend(decode_ssb_measurements(packet.payload, packet.timestamp))
        elif code == 0xB885:
            beam_samples.extend(decode_csirs_measurements(packet.payload, packet.timestamp))
        elif code == 0xB8C9:
            s = decode_mac_dl_tb(packet.payload, packet.timestamp)
            if s:
                mac_dl.append(s)
        elif code == 0xB8A1:
            s = decode_mac_ul_tb(packet.payload, packet.timestamp)
            if s:
                mac_ul.append(s)
        elif code == 0x1874:
            s = decode_rlc_dl_stats(packet.payload, packet.timestamp)
            if s:
                rlc_stats.append(s)
        elif code == 0xB896:
            s = decode_harq_feedback(packet.payload, packet.timestamp)
            if s:
                harq_samples.append(s)
        elif code == 0x1CE2:
            s = decode_pdcp_throughput(
                packet.payload, packet.timestamp,
                prev_pdcp_bytes, prev_pdcp_ts,
            )
            if s:
                prev_pdcp_bytes = s.dl_bytes_cumulative
                prev_pdcp_ts = packet.timestamp
                pdcp_samples.append(s)

    session.phy_measurements = phy_samples
    session.phy_cqi_samples = cqi_samples
    session.phy_beam_samples = beam_samples
    session.mac_dl_samples = mac_dl
    session.mac_ul_samples = mac_ul
    session.rlc_dl_stats = rlc_stats
    session.pdcp_samples = pdcp_samples
    session.harq_samples = harq_samples


def _load_mac_ce_events_from_packets(packets: list, session: LogSession) -> None:
    """Read MAC-CE SCell Activation events from pre-cached 0xB887 packets."""
    from .decoders.mac_ce import decode_mac_ce_packet, build_mac_ce_messages

    mac_events = []
    for packet in packets:
        events = decode_mac_ce_packet(packet.payload, packet.timestamp)
        mac_events.extend(events)

    if mac_events:
        filtered = _deduplicate_mac_events(mac_events)
        msgs = build_mac_ce_messages(filtered, start_index=len(session.messages))
        session.messages.extend(msgs)


def _load_phy_mac_data_from_packets(packets: list, session: LogSession) -> None:
    """Load PHY/MAC time-series from pre-cached packets (single-pass)."""
    from .decoders.nr_phy import (
        decode_phy_measurements, decode_phy_cqi,
        decode_ssb_measurements, decode_csirs_measurements,
        decode_harq_feedback,
    )
    from .decoders.nr_mac import decode_mac_dl_tb, decode_mac_ul_tb
    from .decoders.nr_rlc import decode_rlc_dl_stats
    from .decoders.nr_pdcp import decode_pdcp_throughput
    from .decoders.nr_ul_power import decode_ul_power_config

    phy_samples = []
    cqi_samples = []
    beam_samples = []
    ul_power = []
    mac_dl = []
    mac_ul = []
    rlc_stats = []
    pdcp_samples = []
    harq_samples = []
    prev_pdcp_bytes = None
    prev_pdcp_ts = None

    for packet in packets:
        code = packet.log_code
        if code == 0xB883:
            phy_samples.extend(decode_phy_measurements(packet.payload, packet.timestamp))
        elif code == 0xB8D1:
            cqi_samples.extend(decode_phy_cqi(packet.payload, packet.timestamp))
        elif code == 0xB884:
            beam_samples.extend(decode_ssb_measurements(packet.payload, packet.timestamp))
        elif code == 0xB885:
            beam_samples.extend(decode_csirs_measurements(packet.payload, packet.timestamp))
        elif code == 0xB8C9:
            s = decode_mac_dl_tb(packet.payload, packet.timestamp)
            if s:
                mac_dl.append(s)
        elif code == 0xB8A1:
            s = decode_mac_ul_tb(packet.payload, packet.timestamp)
            if s:
                mac_ul.append(s)
        elif code == 0xB896:
            s = decode_harq_feedback(packet.payload, packet.timestamp)
            if s:
                harq_samples.append(s)
        elif code == 0xB8A7:
            s = decode_ul_power_config(packet.payload, packet.timestamp)
            if s:
                ul_power.append(s)
        elif code == 0x1874:
            s = decode_rlc_dl_stats(packet.payload, packet.timestamp)
            if s:
                rlc_stats.append(s)
        elif code == 0x1CE2:
            s = decode_pdcp_throughput(
                packet.payload, packet.timestamp,
                prev_pdcp_bytes, prev_pdcp_ts,
            )
            if s:
                prev_pdcp_bytes = s.dl_bytes_cumulative
                prev_pdcp_ts = packet.timestamp
                pdcp_samples.append(s)

    session.phy_measurements = phy_samples
    session.phy_cqi_samples = cqi_samples
    session.phy_beam_samples = beam_samples
    session.mac_dl_samples = mac_dl
    session.mac_ul_samples = mac_ul
    session.rlc_dl_stats = rlc_stats
    session.pdcp_samples = pdcp_samples
    session.harq_samples = harq_samples
    session.ul_power_config = ul_power


# Legacy wrappers (kept for backward compat with load_files multi-file merge)
def _load_mac_ce_events(reader, session: LogSession) -> None:
    """Read MAC-CE SCell Activation events from 0xB887 log code."""
    from .decoders.mac_ce import decode_mac_ce_packet, build_mac_ce_messages

    mac_events = []
    for packet in reader.read_packets():
        if packet.log_code == 0xB887:
            events = decode_mac_ce_packet(packet.payload, packet.timestamp)
            mac_events.extend(events)

    if mac_events:
        # Only include activation/deactivation transitions (not every identical repeat)
        filtered = _deduplicate_mac_events(mac_events)
        msgs = build_mac_ce_messages(filtered, start_index=len(session.messages))
        session.messages.extend(msgs)


def _deduplicate_mac_events(events) -> list:
    """Keep only MAC-CE events where the activation set changes."""
    if not events:
        return []
    result = [events[0]]
    last_set = tuple(sorted(events[0].active_scells))
    for event in events[1:]:
        current_set = tuple(sorted(event.active_scells))
        if current_set != last_set:
            result.append(event)
            last_set = current_set
    return result


def _apply_tech_tracking(session: LogSession) -> None:
    """Build tech transitions and annotate voice events."""
    from .analysis.tech_tracker import TechTransitionTracker
    tracker = TechTransitionTracker()
    tracker.build_states(session.messages)
    session.tech_tracker = tracker

    # Annotate voice HO events in message info
    for event in tracker.voice_events:
        if event.msg_index < len(session.messages):
            msg = session.messages[event.msg_index]
            if event.event_type == "ho":
                ho_info = f"Voice HO: {event.detail}"
                msg.info = f"{ho_info} | {msg.info}" if msg.info else ho_info
            elif event.event_type == "setup":
                setup_info = f"Call Setup ({event.voice_rat})"
                msg.info = f"{setup_info} | {msg.info}" if msg.info else setup_info
            elif event.event_type == "release":
                msg.info = f"Call End | {msg.info}" if msg.info else "Call End"
            elif event.event_type == "fail":
                msg.info = f"Call FAILED | {msg.info}" if msg.info else "Call FAILED"
