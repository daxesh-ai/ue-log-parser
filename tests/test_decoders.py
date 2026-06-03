"""Unit tests for PHY/MAC decoders."""

import struct
import unittest
from datetime import datetime, timezone

TS = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _make_phy_b883_payload(version=26, num_cells=1, rsrp_index=66, carrier_id=4):
    """Build a minimal 0xB883 payload with one cell record."""
    # Header: 8 bytes, version at [0], num_cells at [7]
    header = bytes([version, 0, 3, 0, 0, 0, 0, num_cells])
    # Record: 44 bytes, carrier_id at [0], SFN at [2:4], RSRP packed at [8:10]
    # RSRP: (rsrp_index << 6) stored in u16 at offset 8
    val_a = (rsrp_index & 0x7F) << 6
    val_b = 118 << 6  # SINR raw ~39 dB
    rec = bytes([carrier_id, 0]) + struct.pack("<H", 1216)  # SFN
    rec += bytes(4)  # slot info
    rec += struct.pack("<H", val_a) + struct.pack("<H", val_b)
    rec += bytes(44 - len(rec))
    return header + rec


def _make_cqi_b8d1_payload(carrier_id=4, cqi=14, ri=0):
    """Build a minimal 0xB8D1 payload with one record."""
    header = bytes([7, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])  # 20 bytes
    # Record: 168 bytes, carrier at [0], CQI at [12] lower nibble
    cqi_byte = (cqi & 0x0F) | ((ri & 0x3) << 4)
    rec = bytes([carrier_id, 0]) + struct.pack("<H", 1300)  # SFN at [2]
    rec += bytes(8)  # offsets 4-11
    rec += bytes([cqi_byte])  # offset 12
    rec += bytes(168 - len(rec))
    return header + rec


def _make_mac_dl_payload(mcs=20, tb_bytes=76028, num_records=2):
    """Build a 0xB8C9 payload."""
    header = bytes([1, 0, 3, 0]) + bytes(8) + struct.pack("<I", tb_bytes) + bytes(4)  # 20 bytes
    records = bytes(144 * num_records)
    # Set MCS at offset 14 of first record
    rec_list = bytearray(records)
    rec_list[14] = mcs
    return bytes(header) + bytes(rec_list)


class TestPhyMeasurements(unittest.TestCase):
    def test_rsrp_extraction(self):
        from logparser.decoders.nr_phy import decode_phy_measurements
        payload = _make_phy_b883_payload(rsrp_index=66, carrier_id=4)
        results = decode_phy_measurements(payload, TS)
        assert len(results) == 1
        assert results[0].rsrp_dbm == 66 - 156  # -90 dBm
        assert results[0].carrier_id == 4

    def test_invalid_version_rejected(self):
        from logparser.decoders.nr_phy import decode_phy_measurements
        payload = _make_phy_b883_payload(version=5)  # too old
        results = decode_phy_measurements(payload, TS)
        assert results == []

    def test_carrier_id_filter(self):
        from logparser.decoders.nr_phy import decode_phy_measurements
        payload = _make_phy_b883_payload(carrier_id=200)  # > 31, should be filtered
        results = decode_phy_measurements(payload, TS)
        assert results == []

    def test_rsrp_out_of_range_filtered(self):
        from logparser.decoders.nr_phy import decode_phy_measurements
        # rsrp_index=127 -> -29 dBm, above the -30 upper bound -> filtered
        payload = _make_phy_b883_payload(rsrp_index=127, carrier_id=0)
        results = decode_phy_measurements(payload, TS)
        assert results == []


class TestCqiDecoder(unittest.TestCase):
    def test_cqi_extraction(self):
        from logparser.decoders.nr_phy import decode_phy_cqi
        payload = _make_cqi_b8d1_payload(carrier_id=4, cqi=14, ri=0)
        results = decode_phy_cqi(payload, TS)
        assert len(results) == 1
        assert results[0].cqi == 14
        assert results[0].carrier_id == 4
        assert results[0].ri == 1  # 0 → +1 = RI 1

    def test_cqi_zero_filtered(self):
        from logparser.decoders.nr_phy import decode_phy_cqi
        payload = _make_cqi_b8d1_payload(cqi=0)
        results = decode_phy_cqi(payload, TS)
        assert results == []

    def test_wrong_version_rejected(self):
        from logparser.decoders.nr_phy import decode_phy_cqi
        bad = bytearray(_make_cqi_b8d1_payload())
        bad[0] = 5  # wrong version
        assert decode_phy_cqi(bytes(bad), TS) == []


class TestMacDlDecoder(unittest.TestCase):
    def test_mcs_extraction(self):
        from logparser.decoders.nr_mac import decode_mac_dl_tb
        payload = _make_mac_dl_payload(mcs=20, tb_bytes=76028, num_records=2)
        result = decode_mac_dl_tb(payload, TS)
        assert result is not None
        assert result.mcs == 20
        assert result.tb_size == 76028
        assert result.num_slots == 2

    def test_invalid_version(self):
        from logparser.decoders.nr_mac import decode_mac_dl_tb
        bad = bytearray(_make_mac_dl_payload())
        bad[0] = 2
        assert decode_mac_dl_tb(bytes(bad), TS) is None

    def test_mcs_out_of_range_clamped(self):
        from logparser.decoders.nr_mac import decode_mac_dl_tb
        payload = _make_mac_dl_payload(mcs=255)  # invalid → clamped to 0
        result = decode_mac_dl_tb(payload, TS)
        assert result is not None
        assert result.mcs == 0


class TestSsbDecoder(unittest.TestCase):
    def test_ssb_rsrp(self):
        from logparser.decoders.nr_phy import decode_ssb_measurements
        # Build minimal 0xB884 payload: version=5, num_cells=1, rec_size=32
        rsrp_index = 66  # -90 dBm
        val_a = (rsrp_index & 0x7F) << 6
        pci = 325 & 0x3FF
        header = bytes([5, 0, 3, 0, 0, 0, 0, 1])  # num_cells=1
        rec = struct.pack("<H", pci) + struct.pack("<H", 1216)  # pci + SFN
        rec += bytes(4)
        rec += struct.pack("<H", val_a)  # RSRP at offset 8
        rec += bytes(32 - len(rec))
        payload = header + rec
        results = decode_ssb_measurements(payload, TS)
        assert len(results) == 1
        assert results[0].pci == 325
        assert results[0].rsrp_dbm == -90
        assert results[0].source == "SSB"


class TestJsonExport(unittest.TestCase):
    def test_session_to_dict(self):
        from logparser.core.session import LogSession
        from logparser.core.message import ParsedMessage
        from logparser.core.enums import Direction, Protocol, Severity
        from logparser.export.json_export import session_to_dict
        import json

        session = LogSession(filename="test.hdf")
        msg = ParsedMessage(
            index=0, timestamp=TS, protocol=Protocol.NR_RRC,
            direction=Direction.DL, channel="DL-DCCH",
            summary="rrcReconfiguration", raw_payload=b"",
        )
        session.messages.append(msg)

        d = session_to_dict(session)
        assert d["filename"] == "test.hdf"
        assert d["message_count"] == 1
        assert d["messages"][0]["protocol"] == "NR_RRC"
        assert d["messages"][0]["severity"] == "NORMAL"

        # Must be JSON serializable
        serialized = json.dumps(d)
        assert "rrcReconfiguration" in serialized


class TestNasCauseLookup(unittest.TestCase):
    def test_5gmm_cause_known(self):
        from logparser.decoders.nas_causes import format_cause
        result = format_cause(22, is_5g=True)
        assert "#22" in result
        assert "Congestion" in result

    def test_5gmm_cause_unknown(self):
        from logparser.decoders.nas_causes import format_cause
        result = format_cause(999, is_5g=True)
        assert "#999" in result
        assert "Unknown" in result

    def test_emm_cause_known(self):
        from logparser.decoders.nas_causes import format_cause
        result = format_cause(11, is_5g=False)
        assert "PLMN not allowed" in result

    def test_emm_cause_congestion(self):
        from logparser.decoders.nas_causes import format_cause
        result = format_cause(22, is_5g=False)
        assert "Congestion" in result


class TestBandMapping(unittest.TestCase):
    def test_verizon_n261_mmwave(self):
        from logparser.decoders.info_extractor import _arfcn_to_band
        assert _arfcn_to_band(2070875) == "n261"
        assert _arfcn_to_band(2084999) == "n261"

    def test_verizon_n77_cband(self):
        from logparser.decoders.info_extractor import _arfcn_to_band
        assert _arfcn_to_band(648672) == "n77"
        assert _arfcn_to_band(660000) == "n77"

    def test_verizon_n2_pcs(self):
        from logparser.decoders.info_extractor import _arfcn_to_band
        assert _arfcn_to_band(386000) == "n2"
        assert _arfcn_to_band(398000) == "n2"

    def test_n66_aws(self):
        from logparser.decoders.info_extractor import _arfcn_to_band
        assert _arfcn_to_band(422000) == "n66"

    def test_n5_850mhz(self):
        from logparser.decoders.info_extractor import _arfcn_to_band
        assert _arfcn_to_band(173800) == "n5"
        assert _arfcn_to_band(178800) == "n5"

    def test_n260_39ghz(self):
        from logparser.decoders.info_extractor import _arfcn_to_band
        assert _arfcn_to_band(2250000) == "n260"

    def test_lte_b13(self):
        from logparser.decoders.info_extractor import _arfcn_to_band
        assert _arfcn_to_band(5180) == "B13"


class TestUlPowerDecoder(unittest.TestCase):
    def test_normal_power(self):
        from logparser.decoders.nr_ul_power import decode_ul_power_config
        # Build minimal 0xB8A7 payload: ver=5, hdr=8, rec with Pcmax at [17],[18]
        header = bytes([5, 0, 3, 0, 0, 0, 0, 1])
        rec = bytes(17) + bytes([20, 23]) + bytes(76 - 19)  # FR2=20, FR1=23
        payload = header + rec
        result = decode_ul_power_config(payload, TS)
        assert result is not None
        assert result.pcmax_fr1_dbm == 23
        assert result.pcmax_fr2_dbm == 20
        assert not result.power_headroom_limited

    def test_low_power_fr2(self):
        from logparser.decoders.nr_ul_power import decode_ul_power_config
        header = bytes([5, 0, 3, 0, 0, 0, 0, 1])
        rec = bytes(17) + bytes([0, 23]) + bytes(76 - 19)  # FR2=0 (module off)
        payload = header + rec
        result = decode_ul_power_config(payload, TS)
        assert result is not None
        assert result.pcmax_fr2_dbm == 0
        assert result.power_headroom_limited


class TestHarqDecoder(unittest.TestCase):
    def test_harq_bler_calculation(self):
        from logparser.decoders.nr_phy import decode_harq_feedback
        # Build 0xB896 payload: ver=0, hdr=20, nack@20, ack@24
        header = bytes(20)  # version=0 at [0]
        nack = struct.pack("<I", 100)   # 100 NACKs
        ack = struct.pack("<I", 9900)   # 9900 ACKs
        payload = header + nack + ack
        result = decode_harq_feedback(payload, TS)
        assert result is not None
        assert result.nack_count == 100
        assert result.ack_count == 9900
        assert abs(result.bler_pct - 1.0) < 0.01  # 1% BLER

    def test_harq_zero_total(self):
        from logparser.decoders.nr_phy import decode_harq_feedback
        header = bytes(20)
        payload = header + struct.pack("<I", 0) + struct.pack("<I", 0)
        result = decode_harq_feedback(payload, TS)
        assert result is None  # Zero total → skip


class TestBearerTracker(unittest.TestCase):
    def test_qci_format(self):
        from logparser.analysis.bearer_tracker import format_qci
        assert "Voice" in format_qci(1)
        assert "GBR" in format_qci(1)
        assert "Best Effort" in format_qci(8)
        assert "IMS" in format_qci(5)
