"""Wireless collectors for Cisco WLCs (Catalyst 9800), run by the switch poller as extra groups of a `role = "wlc"` device.

Each collector walks registry objects only (app/wireless/oids.py), keys rows by the MIB INDEX structure and reports
per-metric capability from what the controller actually returned: a column that comes back empty is "missing"
(→ unsupported / unavailable), never zero. Where two MIBs describe the same thing (AIRESPACE-WIRELESS-MIB and the
CISCO-LWAPP MIBs), both are read and every value keeps the MIB it came from.

Index layouts (from the MIB INDEX clauses):
    bsnAPTable, cLApTable                         AP base-radio MAC (6 sub-identifiers)
    bsnAPIf*Table, cLApDot11IfTable               AP MAC . slot
    bsnAPIfChannelNoise/InterferenceInfoTable     AP MAC . slot . channel   (the radio's current channel row is used)
    bsnAPIfRadarChannelStatisticsTable            AP MAC . slot . channel   (every channel radar was heard on)
    bsnAPIfRxNeighborsTable                       AP MAC . slot . neighbour radio MAC (6 sub-identifiers)
    bsnAPIfSmtParam / RecommendedRFParameters / Dot11PhyTxPower, cLApDot11RadioTable   AP MAC . slot
    cLApRadioWlanInfoTable                        AP MAC . slot . WLAN index
    clcCdpApCacheTable                            AP MAC . device index
    cLWlanConfigTable, bsnDot11EssTable           WLAN index
    cldcClientTable, bsnMobileStation(Stats)Table client MAC
"""
from __future__ import annotations

from ..switches.collect import Ctx, mac, num, text
from .oids import ENUMS, OBJ

MIB_AIRESPACE = "AIRESPACE-WIRELESS-MIB"


def _idx_mac(idx: str) -> tuple[str, list[int]]:
    parts = [int(x) for x in idx.split(".") if x != ""]
    if len(parts) < 6 or any(p > 255 for p in parts[:6]):
        return "", []
    return ":".join(f"{p:02x}" for p in parts[:6]), parts[6:]


async def _walk(ctx: Ctx, names: list[str], max_rows: int | None = None) -> tuple[dict[str, dict], dict[str, int]]:
    """Walk registry columns side by side → ({index: {object: value}}, {object: rows returned})."""
    bases = {OBJ[n]["oid"]: n for n in names}
    res = await ctx.client.walk_multi(list(bases), max_rows=max_rows)
    rows: dict[str, dict] = {}
    counts: dict[str, int] = {}
    for b, n in bases.items():
        got = res.get(b, [])
        counts[n] = len(got)
        for o, v in got:
            rows.setdefault(o[len(b) + 1:], {})[n] = v
    return rows, counts


def _report(ctx: Ctx, group: str, counts: dict[str, int], extra: dict[str, int] | None = None) -> None:
    """Capability per metric key of the group: ok when any of its source objects returned rows."""
    by_metric: dict[str, int] = {}
    for n, o in OBJ.items():
        if o["group"] == group and o["metric"]:
            by_metric[o["metric"]] = by_metric.get(o["metric"], 0) + counts.get(n, 0)
    for k, v in (extra or {}).items():
        by_metric[k] = by_metric.get(k, 0) + v
    for k, v in by_metric.items():
        (ctx.outcome.ok if v else ctx.outcome.missing)(k, v)


def enum(name: str, v) -> str:
    n = num(v)
    return ENUMS.get(name, {}).get(n, str(n) if n is not None else "") if n is not None else ""


BAND_BSN = {"dot11b": "2.4", "dot11a": "5", "dot116ghz": "6", "dot11xor56ghz": "5/6", "uwb": "uwb"}
BAND_CLD = {"dot11bg": "2.4", "dot11a": "5", "dot11_6ghz": "6", "dot11_xor_5_6ghz": "5/6", "dot11abgn": "", "rlan": "rlan", "uwb": "uwb"}
BAND_PROTO = {"dot11a": "5", "dot11n5": "5", "dot11ac": "5", "dot11ax5": "5", "dot11b": "2.4", "dot11g": "2.4", "dot11n24": "2.4",
              "dot11ax24": "2.4", "dot11ax6": "6"}
XOR_BAND = {"radioband24G": "2.4", "radioband5G": "5", "radioband6G": "6"}
WIDTH = {"five": 5, "ten": 10, "twenty": 20, "fourty": 40, "eighty": 80, "onesixty": 160, "eightyeighty": 160}


# ------------------------------------------------------------------ access points
AP_BSN = ["bsnAPName", "bsnAPLocation", "bsnAPOperationStatus", "bsnAPSoftwareVersion", "bsnAPModel", "bsnAPSerialNumber",
          "bsnApIpAddress", "bsnAPNumOfSlots", "bsnAPPrimaryMwarName", "bsnAPAdminStatus", "bsnAPGroupVlanName"]
AP_CL = ["cLApName", "cLApUpTime", "cLLwappUpTime", "cLApLastRebootReason", "cLApAssociatedClientCount", "cLApCpuCurrentUsage",
         "cLApMemoryCurrentUsage", "cLApAssocFailTimes", "cLApReassocFailCount", "cLApSiteTagName", "cLApRfTagName", "cLApPolicyTagName",
         "cLApPowerStatus"]


async def collect_aps(ctx: Ctx) -> dict:
    bsn, c1 = await _walk(ctx, AP_BSN)
    cl, c2 = await _walk(ctx, AP_CL)
    aps: dict[str, dict] = {}
    for src, rows in ((MIB_AIRESPACE, bsn), ("CISCO-LWAPP-AP-MIB", cl)):
        for idx, r in rows.items():
            m, _ = _idx_mac(idx)
            if not m:
                continue
            a = aps.setdefault(m, {"mac": m, "sources": []})
            a["sources"].append(src)
            for k, v in r.items():
                a[k] = v
    out = {}
    for m, a in aps.items():
        up = num(a.get("cLApUpTime"))
        jup = num(a.get("cLLwappUpTime"))
        out[m] = {
            "mac": m, "name": text(a.get("cLApName")) or text(a.get("bsnAPName")), "ip": a.get("bsnApIpAddress") if isinstance(a.get("bsnApIpAddress"), str) else "",
            "model": text(a.get("bsnAPModel")), "serial": text(a.get("bsnAPSerialNumber")), "software": text(a.get("bsnAPSoftwareVersion")),
            "location": text(a.get("bsnAPLocation")), "oper_status": enum("bsnAPOperationStatus", a.get("bsnAPOperationStatus")),
            "admin_enabled": None if num(a.get("bsnAPAdminStatus")) is None else num(a.get("bsnAPAdminStatus")) == 1,
            "slots": num(a.get("bsnAPNumOfSlots")), "controller": text(a.get("bsnAPPrimaryMwarName")), "vlan_group": text(a.get("bsnAPGroupVlanName")),
            "uptime_s": up // 100 if up is not None else None, "join_uptime_s": jup // 100 if jup is not None else None,
            "reboot_reason": enum("cLApLastRebootReason", a.get("cLApLastRebootReason")),
            "clients": num(a.get("cLApAssociatedClientCount")), "cpu_pct": num(a.get("cLApCpuCurrentUsage")), "mem_pct": num(a.get("cLApMemoryCurrentUsage")),
            "assoc_fail": num(a.get("cLApAssocFailTimes")), "reassoc_fail": num(a.get("cLApReassocFailCount")),
            "power_status": enum("cLApPowerStatus", a.get("cLApPowerStatus")),
            "tags": {k: text(a.get(o)) for k, o in (("site", "cLApSiteTagName"), ("rf", "cLApRfTagName"), ("policy", "cLApPolicyTagName")) if text(a.get(o))},
            "sources": sorted(set(a["sources"])),
        }
    counts = {**c1, **c2}
    _report(ctx, "wireless_ap", counts)
    # a controller that answers but whose AP tables are both empty: inventory unknown, not "every AP down"
    table_ok = bool(c1.get("bsnAPName") or c2.get("cLApName"))
    return {"wireless_aps": out, "wireless_ap_table_ok": table_ok}


CDP = ["clcCdpApCacheNeighName", "clcCdpApCacheNeighAddress", "clcCdpApCacheNeighInterface", "clcCdpApCachePlatform"]


async def collect_ap_cdp(ctx: Ctx) -> dict:
    rows, counts = await _walk(ctx, CDP)
    out: dict[str, dict] = {}
    for idx, r in rows.items():
        m, _ = _idx_mac(idx)
        if not m or m in out:
            continue
        addr = r.get("clcCdpApCacheNeighAddress")
        if isinstance(addr, bytes) and len(addr) == 4:
            addr = ".".join(str(b) for b in addr)
        out[m] = {"switch": text(r.get("clcCdpApCacheNeighName")), "address": addr if isinstance(addr, str) else "",
                  "port": text(r.get("clcCdpApCacheNeighInterface")), "platform": text(r.get("clcCdpApCachePlatform"))}
    _report(ctx, "wireless_ap_cdp", counts)
    return {"wireless_ap_cdp": out}


# ------------------------------------------------------------------ radios
RADIO = ["bsnAPIfType", "bsnAPIfPhyChannelNumber", "bsnAPIfPhyTxPowerLevel", "bsnAPIfOperStatus", "bsnAPIfAdminStatus", "bsnApIfNoOfUsers"]
LOAD = ["bsnAPIfLoadChannelUtilization", "bsnAPIfLoadTxUtilization", "bsnAPIfLoadRxUtilization", "bsnAPIfPoorSNRClients"]
CNT = ["bsnAPIfDot11TransmittedFrameCount", "bsnAPIfDot11RetryCount", "bsnAPIfDot11FailedCount", "bsnAPIfDot11FCSErrorCount",
       "bsnAPIfDot11ACKFailureCount"]


async def collect_radios(ctx: Ctx) -> dict:
    r1, c1 = await _walk(ctx, RADIO)
    r2, c2 = await _walk(ctx, LOAD)
    r3, c3 = await _walk(ctx, CNT)
    r4, c4 = await _walk(ctx, ["cLAp11ChannelBandwidth", "cLApDot11IfLinkChangeCount", "cLApDot11XorRadioBand"])
    radios: dict[tuple, dict] = {}
    for rows in (r1, r2, r3, r4):
        for idx, r in rows.items():
            m, rest = _idx_mac(idx)
            if not m or not rest:
                continue
            radios.setdefault((m, rest[0]), {}).update(r)
    out = {}
    for (m, slot), r in radios.items():
        typ = enum("bsnAPIfType", r.get("bsnAPIfType"))
        width = enum("cLAp11ChannelBandwidth", r.get("cLAp11ChannelBandwidth"))
        band = BAND_BSN.get(typ, "")
        xor = XOR_BAND.get(enum("cLApDot11XorRadioBand", r.get("cLApDot11XorRadioBand")), "")
        if xor and band in ("", "5/6"):   # dual-band radio (or a type value outside the MIB enumeration): use its operating band
            band = xor
        out[f"{m}/{slot}"] = {
            "ap_mac": m, "slot": slot, "radio_type": typ, "band": band,
            "channel": num(r.get("bsnAPIfPhyChannelNumber")), "tx_power_level": num(r.get("bsnAPIfPhyTxPowerLevel")),
            "oper_up": None if num(r.get("bsnAPIfOperStatus")) is None else num(r.get("bsnAPIfOperStatus")) == 2,
            "admin_enabled": None if num(r.get("bsnAPIfAdminStatus")) is None else num(r.get("bsnAPIfAdminStatus")) == 1,
            "clients": num(r.get("bsnApIfNoOfUsers")), "channel_width_mhz": WIDTH.get(width),
            "channel_util_pct": num(r.get("bsnAPIfLoadChannelUtilization")), "tx_util_pct": num(r.get("bsnAPIfLoadTxUtilization")),
            "rx_util_pct": num(r.get("bsnAPIfLoadRxUtilization")), "poor_snr_clients": num(r.get("bsnAPIfPoorSNRClients")),
            "link_changes": num(r.get("cLApDot11IfLinkChangeCount")),
            "counters": {k: num(r.get(o)) for k, o in (("tx_frames", "bsnAPIfDot11TransmittedFrameCount"), ("retries", "bsnAPIfDot11RetryCount"),
                                                         ("failed", "bsnAPIfDot11FailedCount"), ("fcs_errors", "bsnAPIfDot11FCSErrorCount"),
                                                         ("ack_failures", "bsnAPIfDot11ACKFailureCount")) if num(r.get(o)) is not None},
        }
    _report(ctx, "wireless_radio", {**c1, **c2, **c3, **c4})
    return {"wireless_radios": out}


async def collect_radio_rf(ctx: Ctx) -> dict:
    """Noise and 802.11 interference are tabled per channel; keep the row of each radio's current channel."""
    current = {k: v.get("channel") for k, v in (ctx.prev.get("wireless_radios") or {}).items()}
    n_rows, c1 = await _walk(ctx, ["bsnAPIfDBNoisePower"], max_rows=200_000)
    i_rows, c2 = await _walk(ctx, ["bsnAPIfInterferenceUtilization", "bsnAPIfInterferencePower"], max_rows=200_000)
    out: dict[str, dict] = {}
    for rows, fields in ((n_rows, (("noise_dbm", "bsnAPIfDBNoisePower"),)),
                         (i_rows, (("interference_pct", "bsnAPIfInterferenceUtilization"), ("interference_dbm", "bsnAPIfInterferencePower")))):
        for idx, r in rows.items():
            m, rest = _idx_mac(idx)
            if not m or len(rest) < 2:
                continue
            key, ch = f"{m}/{rest[0]}", rest[1]
            if current.get(key) is not None and ch != current[key]:
                continue
            d = out.setdefault(key, {"channel": ch})
            for k, o in fields:
                v = num(r.get(o))
                if v is not None and not (k.endswith("_dbm") and v <= -127):   # -128 dBm is the controller's "no measurement"
                    d[k] = v
    # DFS: radar detections per channel (seconds since last heard)
    rr, c3 = await _walk(ctx, ["bsnAPIfRadarDetectedChannelNumber", "bsnAPIfRadarSignalLastHeard"], max_rows=50_000)
    radar: dict[str, list] = {}
    for idx, r in rr.items():
        m, rest = _idx_mac(idx)
        if not m or len(rest) < 2:
            continue
        radar.setdefault(f"{m}/{rest[0]}", []).append({"channel": num(r.get("bsnAPIfRadarDetectedChannelNumber")) or rest[1],
                                                       "last_heard_s": num(r.get("bsnAPIfRadarSignalLastHeard"))})
    _report(ctx, "wireless_radio_rf", {**c1, **c2, **c3})
    if not current:
        ctx.outcome.not_configured("wireless_radio_noise_dbm", "radio channels not known yet (radio group has not run)")
    return {"wireless_rf": out, "wireless_radar": radar, "wireless_radar_ok": bool(c3.get("bsnAPIfRadarSignalLastHeard"))}

RADIO_META = ["bsnAPIfPhyChannelAssignment", "bsnAPIfPhyTxPowerControl", "bsnAPIfRegulatoryDomainSupport"]
POWER = ["bsnAPIfDot11NumberSupportedPowerLevels"] + [f"bsnAPIfDot11TxPowerLevel{i}" for i in range(1, 9)]


async def collect_radio_meta(ctx: Ctx) -> dict:
    """Slow-changing radio configuration: assignment mode, regulatory domain, country, RRM recommendation, radio MAC and the
    per-level transmit power table (mW, deprecated in the MIB: used only when the controller answers it)."""
    r1, c1 = await _walk(ctx, RADIO_META)
    r2, c2 = await _walk(ctx, ["bsnAPIfDot11CountryString"])
    r3, c3 = await _walk(ctx, ["bsnAPIfRecommendedChannelNumber", "bsnAPIfRecommendedTxPowerLevel"])
    r4, c4 = await _walk(ctx, POWER)
    r5, c5 = await _walk(ctx, ["cLApDot11RadioMACAddress"])
    radios: dict[tuple, dict] = {}
    for rows in (r1, r2, r3, r4, r5):
        for idx, r in rows.items():
            m, rest = _idx_mac(idx)
            if m and rest:
                radios.setdefault((m, rest[0]), {}).update(r)
    out = {}
    for (m, slot), r in radios.items():
        levels = {i: num(r.get(f"bsnAPIfDot11TxPowerLevel{i}")) for i in range(1, 9)}
        cs = text(r.get("bsnAPIfDot11CountryString"))
        out[f"{m}/{slot}"] = {
            "channel_assignment": enum("bsnAPIfPhyChannelAssignment", r.get("bsnAPIfPhyChannelAssignment")),
            "power_assignment": enum("bsnAPIfPhyTxPowerControl", r.get("bsnAPIfPhyTxPowerControl")),
            "regdomain_supported": None if num(r.get("bsnAPIfRegulatoryDomainSupport")) is None else num(r.get("bsnAPIfRegulatoryDomainSupport")) == 1,
            "country": cs[:2].strip().upper() if cs else "", "environment": {"I": "indoor", "O": "outdoor", "": "all"}.get(cs[2:3].strip().upper(), "") if cs else "",
            "recommended_channel": num(r.get("bsnAPIfRecommendedChannelNumber")), "recommended_power_level": num(r.get("bsnAPIfRecommendedTxPowerLevel")),
            "power_levels_mw": {i: v for i, v in levels.items() if v is not None},
            "radio_mac": mac(r.get("cLApDot11RadioMACAddress")),
        }
    _report(ctx, "wireless_radio_meta", {**c1, **c2, **c3, **c4, **c5})
    return {"wireless_radio_meta": out}


NEIGH = ["bsnAPIfRxNeighborRSSI", "bsnAPIfRxNeighborSlot", "bsnAPIfRxNeighborChannel", "bsnAPIfRxNeighborChannelWidth"]
NEIGH_WIDTH = {"five": 5, "ten": 10, "twenty": 20, "aboveforty": 40, "belowforty": 40}


async def collect_rf_neighbors(ctx: Ctx, max_rows: int = 100_000) -> dict:
    """RRM neighbour list: which other AP radios each radio hears, at what RSSI, on which channel. This is the RF-proximity
    evidence co-/adjacent-channel analysis relies on (sharing a channel number alone is never treated as interference)."""
    rows, counts = await _walk(ctx, NEIGH, max_rows=max_rows)
    out: dict[str, list] = {}
    for idx, r in rows.items():
        m, rest = _idx_mac(idx)
        if not m or len(rest) < 7 or any(p > 255 for p in rest[1:7]):
            continue
        nmac = ":".join(f"{p:02x}" for p in rest[1:7])
        rssi = num(r.get("bsnAPIfRxNeighborRSSI"))
        out.setdefault(f"{m}/{rest[0]}", []).append({
            "mac": nmac, "slot": num(r.get("bsnAPIfRxNeighborSlot")), "rssi_dbm": rssi if rssi is not None and -120 <= rssi <= 0 else None,
            "channel": num(r.get("bsnAPIfRxNeighborChannel")),
            "width_mhz": NEIGH_WIDTH.get(enum("bsnAPIfRxNeighborChannelWidth", r.get("bsnAPIfRxNeighborChannelWidth")))})
    _report(ctx, "wireless_rf_neighbors", counts)
    return {"wireless_rf_neighbors": out, "wireless_rf_neighbors_truncated": max(counts.values() or [0]) >= max_rows}


# ------------------------------------------------------------------ WLANs
WLAN = ["cLWlanProfileName", "cLWlanSsid", "cLWlanRowStatus", "cLWlanMaxClientsAccepted"]
ESS = ["bsnDot11EssSsid", "bsnDot11EssAdminStatus", "bsnDot11EssSecurityAuthType", "bsnDot11EssNumberOfMobileStations"]


async def collect_wlans(ctx: Ctx) -> dict:
    w1, c1 = await _walk(ctx, WLAN)
    w2, c2 = await _walk(ctx, ESS)
    rw, c3 = await _walk(ctx, ["cLApRadioWlanSsid", "cLApRadioWlanBssid"], max_rows=100_000)
    out: dict[int, dict] = {}
    for rows in (w1, w2):
        for idx, r in rows.items():
            try:
                wid = int(idx)
            except ValueError:
                continue
            out.setdefault(wid, {"wlan_id": wid}).update(r)
    wl = {}
    for wid, r in out.items():
        rs = num(r.get("cLWlanRowStatus"))
        adm = num(r.get("bsnDot11EssAdminStatus"))
        wl[wid] = {"wlan_id": wid, "profile": text(r.get("cLWlanProfileName")), "ssid": text(r.get("cLWlanSsid")) or text(r.get("bsnDot11EssSsid")),
                   "enabled": (adm == 1) if adm is not None else ((rs == 1) if rs is not None else None),
                   "security": enum("bsnDot11EssSecurityAuthType", r.get("bsnDot11EssSecurityAuthType")),
                   "max_clients": num(r.get("cLWlanMaxClientsAccepted")), "clients": num(r.get("bsnDot11EssNumberOfMobileStations"))}
    radio_wlans: dict[str, list] = {}
    for idx, r in rw.items():
        m, rest = _idx_mac(idx)
        if not m or len(rest) < 2:
            continue
        b = r.get("cLApRadioWlanBssid")
        radio_wlans.setdefault(f"{m}/{rest[0]}", []).append({"wlan_id": rest[1], "ssid": text(r.get("cLApRadioWlanSsid")),
                                                               "bssid": mac(b) if isinstance(b, bytes) else ""})
    _report(ctx, "wireless_wlan", {**c1, **c2, **c3})
    return {"wireless_wlans": wl, "wireless_radio_wlans": radio_wlans}


# ------------------------------------------------------------------ clients
CLD = ["cldcClientStatus", "cldcClientWlanProfileName", "cldcApMacAddress", "cldcIfType", "cldcClientIPAddress", "cldcClientAccessVLAN",
       "cldcClientUpTime", "cldcClientUsername", "cldcClientSSID", "cldcClientChannel", "cldcClientAuthMode", "cldcClientReasonCode",
       "cldcClientApRoamMacAddress", "cldcClientCurrentTxRate"]
BSN = ["bsnMobileStationIpAddress", "bsnMobileStationAPMacAddr", "bsnMobileStationAPIfSlotId", "bsnMobileStationSsid", "bsnMobileStationStatus",
       "bsnMobileStationReasonCode", "bsnMobileStationProtocol", "bsnMobileStationVlanId", "bsnMobileStationUserName"]
STATS = ["bsnMobileStationRSSI", "bsnMobileStationSnr", "bsnMobileStationBytesReceived", "bsnMobileStationBytesSent",
         "bsnMobileStationPacketsReceived", "bsnMobileStationPacketsSent"]


async def collect_clients(ctx: Ctx, max_rows: int = 20_000) -> dict:
    a, c1 = await _walk(ctx, CLD, max_rows)
    b, c2 = await _walk(ctx, BSN, max_rows)
    s, c3 = await _walk(ctx, STATS, max_rows)
    merged: dict[str, dict] = {}
    for src, rows in (("CISCO-LWAPP-DOT11-CLIENT-MIB", a), (MIB_AIRESPACE, b), (MIB_AIRESPACE, s)):
        for idx, r in rows.items():
            m, _ = _idx_mac(idx)
            if not m:
                continue
            d = merged.setdefault(m, {"_src": set()})
            d["_src"].add(src)
            d.update(r)
    out = {}
    for m, r in merged.items():
        cld_if = enum("cldcIfType", r.get("cldcIfType"))
        proto = enum("bsnMobileStationProtocol", r.get("bsnMobileStationProtocol"))
        apm = r.get("cldcApMacAddress") if isinstance(r.get("cldcApMacAddress"), bytes) else r.get("bsnMobileStationAPMacAddr")
        roam = r.get("cldcClientApRoamMacAddress")
        ip = r.get("cldcClientIPAddress") if isinstance(r.get("cldcClientIPAddress"), str) else r.get("bsnMobileStationIpAddress")
        rssi, snr = num(r.get("bsnMobileStationRSSI")), num(r.get("bsnMobileStationSnr"))
        out[m] = {
            "mac": m, "ip": ip if isinstance(ip, str) and ip != "0.0.0.0" else "", "ap_mac": mac(apm) if isinstance(apm, bytes) else "",
            "slot": num(r.get("bsnMobileStationAPIfSlotId")), "band": BAND_CLD.get(cld_if) or BAND_PROTO.get(proto, ""), "protocol": proto,
            "ssid": text(r.get("cldcClientSSID")) or text(r.get("bsnMobileStationSsid")), "wlan_profile": text(r.get("cldcClientWlanProfileName")),
            "vlan": num(r.get("cldcClientAccessVLAN")) if num(r.get("cldcClientAccessVLAN")) else num(r.get("bsnMobileStationVlanId")),
            "channel": num(r.get("cldcClientChannel")),
            "status": enum("cldcClientStatus", r.get("cldcClientStatus")) or enum("bsnMobileStationStatus", r.get("bsnMobileStationStatus")),
            "auth_mode": enum("cldcClientAuthMode", r.get("cldcClientAuthMode")),
            "reason": enum("cldcClientReasonCode", r.get("cldcClientReasonCode")) or enum("bsnMobileStationReasonCode", r.get("bsnMobileStationReasonCode")),
            "username": text(r.get("cldcClientUsername")) or text(r.get("bsnMobileStationUserName")),
            # RSSI 0 / SNR 0 from a station without RF stats is "not measured", not a 0 dBm signal
            "rssi_dbm": rssi if rssi is not None and rssi < 0 else None, "snr_db": snr if snr is not None and (snr != 0 or rssi) else None,
            "tx_rate_mbps": num(r.get("cldcClientCurrentTxRate")) or None, "session_s": num(r.get("cldcClientUpTime")),
            "rx_bytes": num(r.get("bsnMobileStationBytesReceived")), "tx_bytes": num(r.get("bsnMobileStationBytesSent")),
            "roam_from": mac(roam) if isinstance(roam, bytes) and any(roam) else "", "sources": sorted(r["_src"]),
        }
    counts = {**c1, **c2, **c3}
    _report(ctx, "wireless_client", counts)
    truncated = max(counts.values() or [0]) >= max_rows
    return {"wireless_clients": out, "wireless_client_table_ok": bool(c1.get("cldcClientStatus") or c2.get("bsnMobileStationStatus")),
            "wireless_client_truncated": truncated}


COLLECTORS = {"wireless_ap": collect_aps, "wireless_ap_cdp": collect_ap_cdp, "wireless_radio": collect_radios,
              "wireless_radio_rf": collect_radio_rf, "wireless_wlan": collect_wlans, "wireless_client": collect_clients,
              "wireless_radio_meta": collect_radio_meta, "wireless_rf_neighbors": collect_rf_neighbors}
