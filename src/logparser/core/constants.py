"""Constants used across the log parser codebase.

Centralizes magic numbers for header sizes, record sizes, and log codes
so they can be referenced by name rather than scattered numeric literals.
"""

# ── Log Codes ─────────────────────────────────────────────────────────────────

# Signaling (decoded via ASN.1 through _REGISTRY)
LOG_NR_RRC_OTA = 0xB821
LOG_LTE_RRC_OTA = 0xB0C0
LOG_LTE_NAS_DL = 0xB0EC
LOG_LTE_NAS_UL = 0xB0ED

# PHY Layer
LOG_NR_PHY_SERVING_CELL = 0xB883    # RSRP/SINR per carrier
LOG_NR_PHY_PDSCH_CSI = 0xB8D1      # CQI/RI per carrier
LOG_NR_PHY_SSB_MEAS = 0xB884       # SSB beam measurements
LOG_NR_PHY_CSIRS_MEAS = 0xB885     # CSI-RS beam measurements

# MAC Layer
LOG_NR_MAC_DL_TB = 0xB8C9          # DL Transport Block (MCS, TB size)
LOG_NR_MAC_UL_TB = 0xB8A1          # UL Transport Block
LOG_NR_MAC_CE = 0xB887             # MAC Control Elements (SCell activation)
LOG_NR_MAC_HARQ = 0xB896           # HARQ ACK/NACK feedback
LOG_NR_MAC_RACH = 0xB888           # RACH status / timing advance
LOG_NR_MAC_UL_POWER = 0xB8A7       # UL power control config

# RLC / PDCP
LOG_NR_RLC_DL_STATS = 0x1874       # RLC retransmission stats
LOG_NR_PDCP_STATS = 0x1CE2         # PDCP throughput counters

# ── Sub-Header Sizes ──────────────────────────────────────────────────────────

# NR RRC OTA (0xB821)
NR_RRC_HEADER_V26_SIZE = 35         # Version 26+ header bytes
NR_RRC_HEADER_V19_SIZE = 32         # Version 19-25 header bytes
NR_RRC_PCI_OFFSET = 9               # PCI field at byte 9 (u16 LE)
NR_RRC_ARFCN_OFFSET = 17            # ARFCN field at byte 17 (u32 LE)
NR_RRC_CHANNEL_BYTE = 24            # Channel type byte
NR_RRC_BEARER_BYTE = 6              # SRB/DRB indicator byte

# LTE RRC OTA (0xB0C0)
LTE_RRC_HEADER_V25_SIZE = 21        # Version 25+ header
LTE_RRC_HEADER_LEGACY_SIZE = 12     # Legacy (< v20) header

# ── Record Sizes ──────────────────────────────────────────────────────────────

# 0xB8C9 MAC DL Transport Block
MAC_DL_TB_HEADER_SIZE = 20          # Packet header bytes
MAC_DL_TB_RECORD_SIZE = 144         # Per-slot record size
MAC_DL_TB_MCS_OFFSET = 14          # MCS byte within record

# 0xB883 PHY Serving Cell
PHY_SERVING_HEADER_SIZE = 8         # Packet header
PHY_SERVING_RECORD_SIZE = 44        # Per-cell record
PHY_RSRP_OFFSET = 8                # Packed RSRP field offset in record
PHY_SINR_OFFSET = 10               # Packed SINR field offset in record

# 0xB8D1 PDSCH CSI (CQI/RI)
PHY_CSI_HEADER_SIZE = 20            # Packet header
PHY_CSI_RECORD_SIZE = 168           # Per-record size
PHY_CQI_BYTE = 12                  # CQI nibble at record byte 12

# 0xB884 SSB Measurements
PHY_SSB_HEADER_SIZE = 8
PHY_SSB_RECORD_SIZE = 32

# 0xB887 MAC-CE
MAC_CE_HEADER_SIZE = 8              # Packet header

# ── RSRP/SINR Conversion ─────────────────────────────────────────────────────

RSRP_INDEX_OFFSET = -156            # RSRP_dBm = index + RSRP_INDEX_OFFSET
RSRP_BIT_SHIFT = 6                  # Extract 7-bit index: (u16 >> 6) & 0x7F
RSRP_BIT_MASK = 0x7F

SINR_BIT_SHIFT = 6                  # Extract 8-bit raw: (u16 >> 6) & 0xFF
SINR_BIT_MASK = 0xFF
SINR_SCALE = 0.5                    # SINR_dB = raw * 0.5 - 20
SINR_OFFSET = -20.0

# ── Carrier Limits ────────────────────────────────────────────────────────────

MAX_CARRIER_ID = 31                 # NR supports max 32 CCs (0-31)
MAX_PCI = 1007                      # NR PCI range 0-1007

# ── MAC-CE LCIDs (TS 38.321) ─────────────────────────────────────────────────

LCID_SCELL_ACTIVATION = 59          # SCell Activation/Deactivation (1 byte)
LCID_SCELL_ACTIVATION_EXT = 60      # SCell Activation/Deactivation (4 bytes)
LCID_TIMING_ADVANCE = 18            # Timing Advance Command
LCID_DRX_COMMAND = 19               # DRX Command
LCID_LONG_DRX = 16                  # Long DRX Command

# ── Performance Tab ───────────────────────────────────────────────────────────

MAX_PLOT_POINTS = 300               # Max points per graph series
THROUGHPUT_BUCKET_SECONDS = 0.5     # Throughput aggregation window

# ── SRB Identifiers ──────────────────────────────────────────────────────────

SRB0 = 0   # CCCH (initial access, before security)
SRB1 = 1   # Primary DCCH signaling (MN → UE)
SRB2 = 2   # NAS-carrying bearer (lower priority)
SRB3 = 3   # Direct SN → UE (NR-DC/EN-DC only)
