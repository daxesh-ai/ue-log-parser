from enum import Enum, auto


class Protocol(Enum):
    NR_RRC = auto()
    LTE_RRC = auto()
    NR_NAS = auto()
    LTE_NAS = auto()
    NGAP = auto()
    S1AP = auto()
    NR_ML1 = auto()
    UNKNOWN = auto()


class Direction(Enum):
    UL = "UL"
    DL = "DL"
    UNKNOWN = "?"


class Severity(Enum):
    NORMAL = auto()
    WARNING = auto()
    FAILURE = auto()
    INFO = auto()


class NrRrcChannel(Enum):
    UL_CCCH = "UL-CCCH"
    UL_CCCH1 = "UL-CCCH1"
    UL_DCCH = "UL-DCCH"
    DL_CCCH = "DL-CCCH"
    DL_DCCH = "DL-DCCH"
    BCCH_BCH = "BCCH-BCH"
    BCCH_DL_SCH = "BCCH-DL-SCH"
    PCCH = "PCCH"


class LteRrcChannel(Enum):
    UL_CCCH = "UL-CCCH"
    UL_DCCH = "UL-DCCH"
    DL_CCCH = "DL-CCCH"
    DL_DCCH = "DL-DCCH"
    BCCH_BCH = "BCCH-BCH"
    BCCH_DL_SCH = "BCCH-DL-SCH"
    PCCH = "PCCH"
    MCCH = "MCCH"
