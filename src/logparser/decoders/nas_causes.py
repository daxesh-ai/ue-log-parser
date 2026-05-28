"""NAS cause code lookup tables — 3GPP TS 24.501 (5GMM) and TS 24.301 (EMM).

Maps numeric cause values to human-readable reasons for reject messages.
"""

# 5GMM Cause codes (TS 24.501 §9.11.3.2)
_5GMM_CAUSES: dict[int, str] = {
    2:  "IMSI unknown in HSS",
    3:  "Illegal UE",
    5:  "PEI not accepted",
    6:  "Illegal ME",
    7:  "5GS services not allowed",
    9:  "UE identity cannot be derived",
    10: "Implicitly de-registered",
    11: "PLMN not allowed",
    12: "Tracking area not allowed",
    13: "Roaming not allowed in this TA",
    15: "No suitable cells in TA",
    20: "MAC failure",
    21: "Synch failure",
    22: "Congestion",
    23: "UE security capabilities mismatch",
    24: "Security mode rejected, unspecified",
    26: "Non-5G authentication unacceptable",
    27: "N1 mode not allowed",
    28: "Restricted service area",
    31: "Redirection to EPC required",
    43: "LADN not available",
    62: "No network slices available",
    65: "Maximum number of PDU sessions reached",
    67: "Insufficient resources for specific slice",
    69: "Non-3GPP access to 5GCN not allowed",
    71: "Serving network not authorized",
    72: "Temporarily not authorized for this SNPN",
    73: "Permanently not authorized for this SNPN",
    74: "Not authorized for this CAG",
    75: "Wireline access area not allowed",
    76: "Payload was not forwarded",
    90: "Payload was not forwarded",
    95: "Semantically incorrect message",
    96: "Invalid mandatory information",
    97: "Message type non-existent",
    99: "Message type not compatible",
    100: "Information element non-existent",
    101: "Conditional IE error",
    111: "Protocol error, unspecified",
}

# EMM Cause codes (TS 24.301 §9.9.3.9)
_EMM_CAUSES: dict[int, str] = {
    2:  "IMSI unknown in HSS",
    3:  "Illegal UE",
    5:  "IMEI not accepted",
    6:  "Illegal ME",
    7:  "EPS services not allowed",
    8:  "EPS/non-EPS services not allowed",
    9:  "UE identity cannot be derived",
    10: "Implicitly detached",
    11: "PLMN not allowed",
    12: "Tracking area not allowed",
    13: "Roaming not allowed in this TA",
    14: "EPS services not allowed in PLMN",
    15: "No suitable cells in TA",
    16: "MSC temporarily not reachable",
    17: "Network failure",
    19: "ESM failure",
    20: "MAC failure",
    21: "Synch failure",
    22: "Congestion",
    23: "UE security capabilities mismatch",
    25: "Not authorized for this CSG",
    26: "Requested service option not authorized",
    35: "Requested service option not subscribed",
    39: "CS service temporarily not available",
    40: "No EPS bearer context activated",
    42: "Severe network failure",
    95: "Semantically incorrect message",
    96: "Invalid mandatory information",
    97: "Message type non-existent",
    99: "Message type not compatible",
    100: "Information element non-existent",
    101: "Conditional IE error",
    111: "Protocol error, unspecified",
}


def lookup_5gmm_cause(code: int) -> str:
    """Return human-readable 5GMM cause reason."""
    return _5GMM_CAUSES.get(code, f"Unknown cause #{code}")


def lookup_emm_cause(code: int) -> str:
    """Return human-readable EMM cause reason."""
    return _EMM_CAUSES.get(code, f"Unknown cause #{code}")


def format_cause(code: int, is_5g: bool = True) -> str:
    """Format cause code: '#22 Congestion'"""
    if is_5g:
        return f"#{code} {lookup_5gmm_cause(code)}"
    else:
        return f"#{code} {lookup_emm_cause(code)}"
