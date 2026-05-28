"""Integration tests for the full parsing pipeline."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from logparser.core.enums import Direction, Protocol, Severity
from logparser.ingest.quts_reader import QutsReader, is_quts_file
from logparser.pipeline import load_file

# Sample files (update paths as needed)
SAMPLE_DIR = Path("/Users/pateda2/Downloads/Dax Share")
SAMPLE_NR = SAMPLE_DIR / "iPhone17PM-NRDC.hdf"


def test_quts_detection():
    assert is_quts_file(SAMPLE_NR)
    assert not is_quts_file(Path("/dev/null"))


def test_quts_reader():
    reader = QutsReader(SAMPLE_NR)
    packets = list(reader.read_packets())
    assert len(packets) > 0
    # All packets should have valid timestamps and log codes
    for p in packets:
        assert p.log_code > 0
        assert p.timestamp.year >= 2020
        assert len(p.payload) > 0


def test_pipeline_nr_rrc():
    session = load_file(SAMPLE_NR)
    assert session.filename == "iPhone17PM-NRDC.hdf"
    assert len(session.messages) > 100

    # Check decode rate
    decoded = sum(1 for m in session.messages if m.decoded_tree is not None)
    assert decoded / len(session.messages) > 0.90  # At least 90%

    # Check message structure
    for msg in session.messages:
        assert msg.protocol in (Protocol.NR_RRC, Protocol.LTE_RRC, Protocol.NR_NAS, Protocol.LTE_NAS)
        assert msg.timestamp.year >= 2020
        assert msg.channel != ""
        assert msg.summary != ""


def test_analysis_detects_failures():
    session = load_file(SAMPLE_NR)
    failures = [m for m in session.messages if m.severity == Severity.FAILURE]
    # This file has known T300 timeouts
    assert len(failures) > 0
    # Check annotations are populated
    for f in failures:
        assert len(f.annotations) > 0


def test_rrc_directions():
    session = load_file(SAMPLE_NR)
    ul_msgs = [m for m in session.messages if m.direction == Direction.UL]
    dl_msgs = [m for m in session.messages if m.direction == Direction.DL]
    # Should have both UL and DL messages
    assert len(ul_msgs) > 0
    assert len(dl_msgs) > 0


if __name__ == "__main__":
    test_quts_detection()
    print("✓ test_quts_detection")
    test_quts_reader()
    print("✓ test_quts_reader")
    test_pipeline_nr_rrc()
    print("✓ test_pipeline_nr_rrc")
    test_analysis_detects_failures()
    print("✓ test_analysis_detects_failures")
    test_rrc_directions()
    print("✓ test_rrc_directions")
    print("\nAll tests passed!")
