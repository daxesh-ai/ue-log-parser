"""Extract RF optimization-relevant info from decoded IE trees.

Extracts what a telecom engineer needs for drive test / optimization:
- PCI (Physical Cell ID) — for serving and neighbor cells
- ARFCN/Band — for frequency identification
- RSRP/RSRQ — signal quality from measurement reports
- PCell/SCell with PCI — for CA and handover analysis
- 5QI/QCI — QoS flow identification
- Reject causes — why procedures failed
- Handover target — PCI and frequency of target cell
"""

from __future__ import annotations


def extract_info(decoded_tree, summary: str) -> str:
    """Extract key RF/optimization info from decoded tree."""
    if not decoded_tree:
        return ""

    inner = _get_rrc_content(decoded_tree)
    if not inner:
        return ""

    msg_lower = summary.lower()

    if "rrcreconfiguration" in msg_lower and "complete" not in msg_lower:
        return _info_rrc_reconfiguration(inner)
    elif "measurementreport" in msg_lower:
        return _info_measurement_report(inner)
    elif "rrcrelease" in msg_lower:
        return _info_rrc_release(inner)
    elif "rrcsetup" in msg_lower and "request" not in msg_lower and "complete" not in msg_lower:
        return _info_rrc_setup(inner)
    elif "rrcsetuprequest" in msg_lower:
        return _info_rrc_setup_request(decoded_tree)
    elif "rrcreject" in msg_lower:
        return _info_rrc_reject(inner)
    elif "securitymodecommand" in msg_lower:
        return _info_security_mode(inner)
    elif "rrcreestablishment" in msg_lower and "request" in msg_lower:
        return _info_reestablishment_request(decoded_tree)
    elif "rrcresume" in msg_lower and "request" not in msg_lower and "complete" not in msg_lower:
        return _info_rrc_resume(inner)
    elif "scgfailureinformation" in msg_lower:
        return _info_scg_failure(inner)
    elif "failureinformation" in msg_lower:
        return _info_failure_information(inner)
    elif "mobilityfromnrcommand" in msg_lower:
        return _info_mobility_from_nr(inner)

    return ""


def _info_rrc_reconfiguration(content) -> str:
    """Extract PCell/SCell PCI, ARFCN, CA config from rrcReconfiguration."""
    parts = []

    # Look in nonCriticalExtension for masterCellGroup / secondaryCellGroup
    nce = content.get("nonCriticalExtension") if isinstance(content, dict) else None
    if isinstance(nce, dict):
        mcg = _unwrap_choice(nce.get("masterCellGroup"))
        scg = _unwrap_choice(nce.get("secondaryCellGroup"))

        if isinstance(mcg, dict):
            _extract_cell_group(mcg, parts, "MCG")

        if isinstance(scg, dict):
            _extract_cell_group(scg, parts, "SCG")

        # Check deeper nonCriticalExtension (common in newer ASN.1 versions)
        nce2 = nce.get("nonCriticalExtension")
        if isinstance(nce2, dict):
            mcg2 = _unwrap_choice(nce2.get("masterCellGroup"))
            scg2 = _unwrap_choice(nce2.get("secondaryCellGroup"))
            if isinstance(mcg2, dict):
                _extract_cell_group(mcg2, parts, "MCG")
            if isinstance(scg2, dict):
                _extract_cell_group(scg2, parts, "SCG")

            # NRDC: mrdc-SecondaryCellGroupConfig → nr-SCG → RRCReconfiguration
            nce3 = nce2.get("nonCriticalExtension")
            if isinstance(nce3, dict):
                _extract_mrdc_scg(nce3, parts)

    # Also check measConfig for measurement objects
    if not parts:
        meas = content.get("measConfig") if isinstance(content, dict) else None
        if isinstance(meas, dict):
            obj_list = meas.get("measObjectToAddModList")
            if isinstance(obj_list, list) and obj_list:
                freqs = []
                for obj in obj_list[:3]:
                    if isinstance(obj, dict):
                        meas_obj = obj.get("measObject")
                        if isinstance(meas_obj, tuple) and len(meas_obj) == 2:
                            rat, obj_content = meas_obj
                            if isinstance(obj_content, dict):
                                freq = obj_content.get("ssbFrequency") or obj_content.get("carrierFreq")
                                if freq:
                                    freqs.append(f"{_arfcn_to_band(freq)}")
                if freqs:
                    parts.append("Meas:" + ",".join(freqs))

    return " | ".join(parts)


def _extract_cell_group(cg: dict, parts: list, prefix: str):
    """Extract PCI/ARFCN from a CellGroupConfig."""
    # SpCell (PCell or PSCell)
    sp_cell = cg.get("spCellConfig")
    if isinstance(sp_cell, dict):
        reconfig = sp_cell.get("reconfigurationWithSync")
        if isinstance(reconfig, dict):
            pci = _find(reconfig, "physCellId", 3)
            freq = _find(reconfig, "absoluteFrequencySSB", 4) or _find(reconfig, "ssbFrequency", 4)
            if pci is not None:
                band_str = _arfcn_to_band(freq) if freq else ""
                cell_label = "PCell" if prefix == "MCG" else "PSCell"
                info = f"{cell_label}:PCI{pci}"
                if band_str:
                    info += f" {band_str}"
                parts.append(info)

    # SCells (CA) — only show if we have real cell identity (PCI/freq)
    scell_list = cg.get("sCellToAddModList")
    if isinstance(scell_list, list):
        for scell in scell_list[:4]:
            if isinstance(scell, dict):
                idx = scell.get("sCellIndex", "?")
                sc_common = scell.get("sCellConfigCommon")
                if isinstance(sc_common, dict):
                    pci = _find(sc_common, "physCellId", 3)
                    freq = _find(sc_common, "absoluteFrequencySSB", 3) or _find(sc_common, "dl-CarrierFreq", 3)
                    band_str = _arfcn_to_band(freq) if freq else ""
                    if pci is not None:
                        parts.append(f"SCell{idx}:PCI{pci} {band_str}".strip())
                    elif freq:
                        parts.append(f"SCell{idx}:{band_str}")
                # No sCellConfigCommon = just a modification, skip it


def _extract_mrdc_scg(nce3: dict, parts: list):
    """Extract NRDC SCG info from mrdc-SecondaryCellGroupConfig.

    Path: mrdc-SecondaryCellGroupConfig → (setup) → mrdc-SecondaryCellGroup
         → (nr-SCG) → (RRCReconfiguration) → criticalExtensions
         → secondaryCellGroup → CellGroupConfig
    """
    mrdc_raw = nce3.get("mrdc-SecondaryCellGroupConfig")
    if not isinstance(mrdc_raw, tuple) or len(mrdc_raw) != 2:
        return
    # ('setup', {'mrdc-SecondaryCellGroup': ...})
    setup_dict = mrdc_raw[1]
    if not isinstance(setup_dict, dict):
        return
    mrdc_cg = setup_dict.get("mrdc-SecondaryCellGroup")
    if not isinstance(mrdc_cg, tuple):
        return
    # ('nr-SCG', ('RRCReconfiguration', {...}))
    nr_scg = mrdc_cg[1]
    if not isinstance(nr_scg, tuple) or len(nr_scg) != 2:
        return
    scg_reconfig = nr_scg[1]
    if not isinstance(scg_reconfig, dict):
        return
    # Navigate into criticalExtensions
    ce = scg_reconfig.get("criticalExtensions")
    if isinstance(ce, tuple) and len(ce) == 2:
        scg_content = ce[1]
        if isinstance(scg_content, dict):
            # secondaryCellGroup is the CellGroupConfig for SCG
            scg_cg = _unwrap_choice(scg_content.get("secondaryCellGroup"))
            if isinstance(scg_cg, dict):
                _extract_cell_group(scg_cg, parts, "SCG")
            # Also check nonCriticalExtension inside SCG reconfig
            scg_nce = scg_content.get("nonCriticalExtension")
            if isinstance(scg_nce, dict):
                scg_cg2 = _unwrap_choice(scg_nce.get("secondaryCellGroup"))
                if isinstance(scg_cg2, dict):
                    _extract_cell_group(scg_cg2, parts, "SCG")


def _info_measurement_report(content) -> str:
    """Extract serving cell RSRP and neighbor PCIs from measurement report."""
    parts = []
    meas_results = _find(content, "measResults", 2)
    if not isinstance(meas_results, dict):
        return ""

    # Serving cells
    serv_list = meas_results.get("measResultServingMOList")
    if isinstance(serv_list, list):
        for serv in serv_list[:3]:
            if not isinstance(serv, dict):
                continue
            cell_id = serv.get("servCellId", "?")
            meas_res = serv.get("measResultServingCell")
            if isinstance(meas_res, dict):
                cell_res = meas_res.get("measResult")
                if isinstance(cell_res, dict):
                    # cellResults is a CHOICE
                    rsrp_choice = cell_res.get("cellResults")
                    rsrp_val = None
                    if isinstance(rsrp_choice, tuple) and "rsrp" in str(rsrp_choice[0]).lower():
                        rsrp_val = rsrp_choice[1]
                    elif isinstance(cell_res.get("cellResults"), dict):
                        rsrp_val = cell_res["cellResults"].get("resultsSSB-Cell", {}).get("rsrp")

                    if rsrp_val is not None:
                        parts.append(f"Serv{cell_id}:RSRP{rsrp_val}")
                    else:
                        parts.append(f"Serv{cell_id}")

    # Neighbor cells
    neigh = meas_results.get("measResultNeighCells")
    if isinstance(neigh, tuple) and len(neigh) == 2:
        _, neigh_list = neigh
        if isinstance(neigh_list, list):
            for n in neigh_list[:3]:
                if isinstance(n, dict):
                    pci = n.get("physCellId")
                    meas_res = n.get("measResult")
                    rsrp_val = None
                    if isinstance(meas_res, dict):
                        cell_res = meas_res.get("cellResults")
                        if isinstance(cell_res, tuple):
                            rsrp_val = cell_res[1] if isinstance(cell_res[1], int) else None
                    if pci is not None:
                        info = f"Neigh:PCI{pci}"
                        if rsrp_val is not None:
                            info += f" RSRP{rsrp_val}"
                        parts.append(info)

    return " | ".join(parts)


def _info_rrc_release(content) -> str:
    """Extract redirect/deprioritization info from rrcRelease."""
    parts = []

    redirect = _find(content, "redirectedCarrierInfo", 2)
    if isinstance(redirect, tuple) and len(redirect) == 2:
        rat, freq_info = redirect
        if isinstance(freq_info, dict):
            freq = freq_info.get("carrierFreq") or _find(freq_info, "carrierFreq", 2)
            band = _arfcn_to_band(freq) if freq else ""
            parts.append(f"Redirect→{rat} {band}".strip())
        elif isinstance(freq_info, int):
            parts.append(f"Redirect→{rat} {_arfcn_to_band(freq_info)}")
        else:
            parts.append(f"Redirect→{rat}")

    depri = _find(content, "deprioritisationReq", 2)
    if depri:
        parts.append("Deprioritised")

    # Cell reselection priorities — show actual bands
    prio = _find(content, "cellReselectionPriorities", 2)
    if isinstance(prio, dict) and not parts:
        nr_list = prio.get("freqPriorityListNR")
        if isinstance(nr_list, list):
            bands = []
            for item in nr_list[:5]:
                if isinstance(item, dict):
                    freq = item.get("carrierFreq")
                    if freq:
                        bands.append(_arfcn_to_band(freq))
            if bands:
                parts.append("Resel→" + ",".join(bands))

        eutra_list = prio.get("freqPriorityListEUTRA")
        if isinstance(eutra_list, list):
            bands = []
            for item in eutra_list[:5]:
                if isinstance(item, dict):
                    freq = item.get("carrierFreq")
                    if freq:
                        bands.append(_arfcn_to_band(freq))
            if bands:
                parts.append("LTE:" + ",".join(bands))

    return " | ".join(parts)


def _info_rrc_setup(content) -> str:
    """Extract cell info from rrcSetup."""
    # Usually just confirms connection setup, not much extra info
    return ""


def _info_rrc_setup_request(tree) -> str:
    """Extract establishment cause from rrcSetupRequest."""
    cause = _find(tree, "establishmentCause", 5)
    if cause and isinstance(cause, str):
        return cause
    return ""


def _info_rrc_reject(content) -> str:
    """Extract wait time from rrcReject."""
    wait = _find(content, "waitTime", 3)
    if wait is not None:
        return f"Wait:{wait}s"
    return ""


def _info_security_mode(content) -> str:
    """Extract ciphering/integrity algorithms."""
    cipher = _find(content, "cipheringAlgorithm", 4)
    integrity = _find(content, "integrityProtAlgorithm", 4)
    parts = []
    if cipher:
        parts.append(str(cipher))
    if integrity:
        parts.append(str(integrity))
    return ",".join(parts)


def _info_reestablishment_request(tree) -> str:
    """Extract reestablishment cause and PCI."""
    cause = _find(tree, "reestablishmentCause", 5)
    pci = _find(tree, "physCellId", 5)
    parts = []
    if pci is not None:
        parts.append(f"PCI:{pci}")
    if cause:
        parts.append(str(cause))
    return " | ".join(parts)


def _info_rrc_resume(content) -> str:
    """Extract info from rrcResume."""
    return ""


def _info_scg_failure(content) -> str:
    """Extract SCGFailureInformation details: failureType, measurements."""
    parts = []

    failure_report = content.get("failureReportSCG")
    if isinstance(failure_report, dict):
        failure_type = failure_report.get("failureType", "")
        if failure_type:
            parts.append(f"failureType:{failure_type}")
            # srb3-IntegrityFailure = security key mismatch (S-K_gNB)
            if "srb3" in str(failure_type).lower() or "integrity" in str(failure_type).lower():
                parts.append("⚠ SRB3-IntegrityFailure (S-K_gNB mismatch)")

        # Measurement results at failure time
        meas_scg = failure_report.get("measResultSCG-Failure")
        if isinstance(meas_scg, dict):
            # Extract RSRP of failing cell
            meas_list = meas_scg.get("measResultPerMOList")
            if isinstance(meas_list, list):
                for meas in meas_list[:2]:
                    if isinstance(meas, dict):
                        rsrp = _find(meas, "rsrp", 4)
                        if rsrp is not None:
                            parts.append(f"SCG-RSRP:{rsrp}")

    # Also check for EUTRA variant
    failure_report_eutra = content.get("failureReportSCG-EUTRA")
    if isinstance(failure_report_eutra, dict):
        failure_type = failure_report_eutra.get("failureType", "")
        if failure_type:
            parts.append(f"EUTRA-failureType:{failure_type}")

    return " | ".join(parts)


def _info_failure_information(content) -> str:
    """Extract failureInformation (MCG/generic RLC bearer failure)."""
    parts = []
    rlc_info = content.get("failureInfoRLC-Bearer")
    if isinstance(rlc_info, dict):
        cell_group = rlc_info.get("cellGroupId")
        lcid = rlc_info.get("logicalChannelIdentity")
        failure_type = rlc_info.get("failureType")
        if cell_group is not None:
            group_name = "MCG" if cell_group == 0 else f"SCG(id={cell_group})"
            parts.append(group_name)
        if lcid is not None:
            # LCID 1=SRB1, 2=SRB2, 3=SRB3, 4+=DRB
            srb_name = {1: "SRB1", 2: "SRB2", 3: "SRB3"}.get(lcid, f"DRB(LCID={lcid})")
            parts.append(srb_name)
        if failure_type:
            parts.append(str(failure_type))
    return " | ".join(parts)


def _info_mobility_from_nr(content) -> str:
    """Extract inter-RAT mobility command info (NR → LTE/EUTRA)."""
    parts = []
    target_rat = content.get("targetRAT-Type")
    if target_rat:
        parts.append(f"Target:{target_rat}")
    # Look for nas-SecurityParamFromNR
    nas_sec = content.get("nas-SecurityParamFromNR")
    if nas_sec:
        parts.append("NAS-Security-Provided")
    return " | ".join(parts)


# --- Utility functions ---

def _get_rrc_content(tree) -> dict | None:
    """Navigate through message → c1 → msgType → criticalExtensions → content."""
    if not isinstance(tree, dict):
        return None
    msg = tree.get("message")
    if not isinstance(msg, tuple) or len(msg) != 2:
        return tree
    _, c1 = msg
    if not isinstance(c1, tuple) or len(c1) != 2:
        return None
    _, content = c1
    if not isinstance(content, dict):
        return None
    ce = content.get("criticalExtensions")
    if isinstance(ce, tuple) and len(ce) == 2:
        _, inner = ce
        if isinstance(inner, dict):
            return inner
    return content


def _unwrap_choice(val):
    """Unwrap a CHOICE tuple like ('CellGroupConfig', {...}) or decoded wrapper."""
    if isinstance(val, dict):
        if "(decoded CellGroupConfig)" in val:
            return val["(decoded CellGroupConfig)"]
        return val
    elif isinstance(val, tuple) and len(val) == 2 and isinstance(val[0], str):
        inner = val[1]
        if isinstance(inner, dict):
            return inner
    return None


def _find(data, key: str, max_depth: int):
    """Find a key in nested structure."""
    if max_depth <= 0:
        return None
    if isinstance(data, dict):
        if key in data:
            return data[key]
        for v in data.values():
            r = _find(v, key, max_depth - 1)
            if r is not None:
                return r
    elif isinstance(data, tuple) and len(data) == 2 and isinstance(data[0], str):
        return _find(data[1], key, max_depth - 1)
    elif isinstance(data, list):
        for item in data[:5]:
            r = _find(item, key, max_depth - 1)
            if r is not None:
                return r
    return None


def _arfcn_to_band(arfcn) -> str:
    """Convert NR-ARFCN to approximate band name."""
    if not isinstance(arfcn, int) or arfcn == 0:
        return ""

    # NR-ARFCN → band (DL). FR1 (0-3 GHz): freq_MHz = ARFCN * 0.005
    #                         FR1 upper (3-24 GHz): freq_MHz = 3000 + (ARFCN-600000)*0.015
    # Rule: more specific (narrower) bands listed before supersets.

    # ── Sub-1 GHz ──────────────────────────────────────────────────────────────
    if   123400 <= arfcn <= 130400: return "n71"  # 617-652 MHz  T-Mobile 600 MHz
    elif 145800 <= arfcn <= 149200: return "n12"  # 729-746 MHz  US 700 MHz A/B/C
    elif 151600 <= arfcn <= 153600: return "n14"  # 758-768 MHz  FirstNet 700 D
    elif 151600 <= arfcn <= 160600: return "n28"  # 758-803 MHz  APT 700 (intl)
    elif 173800 <= arfcn <= 178800: return "n5"   # 869-894 MHz  US 850 MHz (Verizon/AT&T)
    elif 171800 <= arfcn <= 178800: return "n26"  # 859-894 MHz  extended 850 (intl)

    # ── 1-2 GHz ────────────────────────────────────────────────────────────────
    elif 386000 <= arfcn <= 398000: return "n2"   # 1930-1990 MHz  US PCS 1900 (Verizon/AT&T)
    elif 398001 <= arfcn <= 399000: return "n25"  # 1990-1995 MHz  extended PCS (Sprint)
    elif 422000 <= arfcn <= 440000: return "n66"  # 2110-2200 MHz  AWS (Verizon/T-Mobile/AT&T)

    # ── 2-3 GHz ────────────────────────────────────────────────────────────────
    elif 499200 <= arfcn <= 537999: return "n41"  # 2496-2690 MHz  TDD (T-Mobile 2.5 GHz)
    elif 524000 <= arfcn <= 538000: return "n7"   # 2620-2690 MHz  FDD DL (international)

    # ── FR1 upper: 3-7 GHz — formula: 3000+(ARFCN-600000)*0.015 ───────────────
    elif 620000 <= arfcn <= 646666: return "n78"  # 3300-3700 MHz  global C-band
    elif 636667 <= arfcn <= 646666: return "n48"  # 3550-3700 MHz  CBRS (subset of n78)
    elif 646667 <= arfcn <= 680000: return "n77"  # 3700-4200 MHz  C-band (Verizon 3.7-3.98 GHz)
    elif 693334 <= arfcn <= 733333: return "n79"  # 4400-5000 MHz  Japan/international

    # ── FR2 mmWave — narrower bands checked first ──────────────────────────────
    elif 2070833 <= arfcn <= 2084999: return "n261"  # 27.5-28.35 GHz  Verizon/AT&T 28 GHz
    elif 2229167 <= arfcn <= 2279166: return "n260"  # 37-40 GHz       US 39 GHz
    elif 2270833 <= arfcn <= 2337499: return "n259"  # 39.5-43.5 GHz   international
    elif 2054167 <= arfcn <= 2104165: return "n257"  # 26.5-29.5 GHz   international
    elif 2016667 <= arfcn <= 2070832: return "n258"  # 24.25-27.5 GHz  international

    # LTE EARFCN ranges
    elif 0 <= arfcn <= 599:
        return "B1"
    elif 600 <= arfcn <= 1199:
        return "B2"
    elif 1200 <= arfcn <= 1949:
        return "B3"
    elif 1950 <= arfcn <= 2399:
        return "B4"
    elif 2400 <= arfcn <= 2649:
        return "B5"
    elif 2750 <= arfcn <= 3449:
        return "B7"
    elif 3450 <= arfcn <= 3799:
        return "B8"
    elif 5010 <= arfcn <= 5179:
        return "B12"
    elif 5180 <= arfcn <= 5279:
        return "B13"
    elif 5280 <= arfcn <= 5379:
        return "B14"
    elif 5730 <= arfcn <= 5849:
        return "B17"
    elif 6150 <= arfcn <= 6449:
        return "B20"
    elif 6600 <= arfcn <= 7399:
        return "B22"
    elif 8040 <= arfcn <= 8689:
        return "B25"
    elif 8690 <= arfcn <= 9039:
        return "B26"
    elif 9210 <= arfcn <= 9659:
        return "B28"
    elif 9770 <= arfcn <= 10159:
        return "B30"
    elif 36000 <= arfcn <= 36199:
        return "B33"
    elif 36200 <= arfcn <= 36349:
        return "B34"
    elif 36350 <= arfcn <= 36949:
        return "B38"
    elif 37750 <= arfcn <= 38249:
        return "B40"
    elif 38250 <= arfcn <= 38649:
        return "B41"
    elif 39650 <= arfcn <= 41589:
        return "B42"
    elif 41590 <= arfcn <= 43589:
        return "B43"
    elif 65536 <= arfcn <= 66435:
        return "B66"
    elif 66436 <= arfcn <= 67335:
        return "B71"

    return f"ARFCN{arfcn}"
