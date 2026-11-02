"""Wireless analytics over the controller-reported inventory (PostgreSQL) and history (ClickHouse): overview, RF ranking,
client experience, roaming, AP ↔ switch correlation and the rule-based troubleshooting engine (docs/WIRELESS.md).

Nothing here estimates a value the controller did not report: a missing measurement stays None and is left out of
scores, rankings and averages (with the confidence reduced accordingly)."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import Alert, Switch, SwitchInterface, WirelessAp, WirelessClient, WirelessEvent, WirelessRadio, WirelessWlan

# thresholds (per controller overrides in switches.thresholds["wireless"]; channel utilisation per band)
DEFAULTS = {
    "channel_util_pct": {"2.4": 70, "5": 80, "6": 80, "5/6": 80, "": 80},
    "interference_pct": 30, "noise_dbm": -85, "rssi_poor_dbm": -75, "rssi_good_dbm": -67, "snr_poor_db": 15, "snr_good_db": 25,
    "rate_poor_mbps": 12, "rate_good_mbps": 100, "retry_pct": 20, "ap_clients_max": 40, "ap_cpu_pct": 90, "roams_per_hour": 10,
    "disconnects_per_hour": 5,
    # RF analytics (app/wireless/rf_analytics.py)
    "rf_persistence_minutes": 15, "rf_persistence_fraction": 0.6, "contention_pct": 30, "cochannel_rssi_dbm": -75, "adjacent_rssi_dbm": -70,
    "channel_changes_per_day": 4, "uneven_ratio": 2.5, "uneven_min_clients": 15, "poor_snr_min_clients": 3, "link_changes_per_day": 3,
    # alert hysteresis: an open alert clears only this far below its threshold
    "clear_margin_util_pct": 10, "clear_margin_interference_pct": 5, "clear_margin_noise_db": 3, "clear_margin_retry_pct": 5,
}
SCORE_WEIGHTS = {"rssi": 30, "snr": 30, "rate": 15, "channel_util": 15, "retry": 10}


def thresholds(sw: Switch | None) -> dict:
    t = {**DEFAULTS, "channel_util_pct": dict(DEFAULTS["channel_util_pct"])}
    o = ((sw.thresholds or {}).get("wireless") or {}) if sw else {}
    for k, v in o.items():
        if k == "channel_util_pct" and isinstance(v, dict):
            t[k].update({str(b): float(x) for b, x in v.items()})
        elif k in t and isinstance(v, (int, float)):
            t[k] = v
    return t


def util_limit(t: dict, band: str | None) -> float:
    return float(t["channel_util_pct"].get(band or "", t["channel_util_pct"][""]))


def _lin(v: float, bad: float, good: float) -> float:
    """0 at `bad`, 100 at `good`, linear between (works for either direction)."""
    if good == bad:
        return 100.0
    x = (v - bad) / (good - bad)
    return round(100 * min(1.0, max(0.0, x)), 1)


def client_score(c: WirelessClient, radio: WirelessRadio | None, t: dict) -> dict:
    """Client Experience Score 0-100 = weighted mean of the components that were measured (RSSI 30, SNR 30, data rate
    15, the serving radio's channel utilisation 15 and retry rate 10). Each component scores 100 at its "good" threshold
    and 0 at its "poor" threshold, linear between. Missing components are left out; confidence = measured weight /
    total weight. No measured component → no score."""
    parts = []
    if c.rssi_dbm is not None:
        parts.append(("rssi", "RSSI", c.rssi_dbm, "dBm", _lin(c.rssi_dbm, t["rssi_poor_dbm"] - 5, t["rssi_good_dbm"])))
    if c.snr_db is not None:
        parts.append(("snr", "SNR", c.snr_db, "dB", _lin(c.snr_db, t["snr_poor_db"] - 5, t["snr_good_db"])))
    if c.tx_rate_mbps is not None:
        parts.append(("rate", "Data rate", c.tx_rate_mbps, "Mbit/s", _lin(c.tx_rate_mbps, t["rate_poor_mbps"], t["rate_good_mbps"])))
    if radio is not None and radio.channel_util_pct is not None:
        lim = util_limit(t, radio.band)
        parts.append(("channel_util", "Serving radio channel utilisation", radio.channel_util_pct, "%", _lin(radio.channel_util_pct, lim + 10, lim - 30)))
    if radio is not None and radio.retry_pct is not None:
        parts.append(("retry", "Serving radio retry rate", radio.retry_pct, "%", _lin(radio.retry_pct, t["retry_pct"] + 10, t["retry_pct"] / 2)))
    total = sum(SCORE_WEIGHTS.values())
    have = sum(SCORE_WEIGHTS[p[0]] for p in parts)
    if not parts:
        return {"score": None, "grade": "unknown", "confidence": 0.0, "factors": [], "note": "no RF measurement reported for this client"}
    score = round(sum(SCORE_WEIGHTS[p[0]] * p[4] for p in parts) / have, 1)
    grade = "good" if score >= 75 else "fair" if score >= 50 else "poor"
    return {"score": score, "grade": grade, "confidence": round(have / total, 2),
            "factors": [{"key": k, "label": lbl, "value": v, "unit": u, "points": pts, "weight": SCORE_WEIGHTS[k]} for k, lbl, v, u, pts in parts]}


# ------------------------------------------------------------------ serialisers
def _iso(v):
    if v is None:
        return None
    return (v if v.tzinfo else v.replace(tzinfo=timezone.utc)).isoformat()


def ap_out(a: WirelessAp, wlc: Switch | None = None) -> dict:
    return {"id": a.id, "wlc_id": a.wlc_id, "wlc": wlc.name if wlc else None, "mac": a.mac, "name": a.name or a.mac, "ip": a.ip, "model": a.model,
            "serial": a.serial, "software": a.software, "location": a.location, "site": a.site, "building": a.building, "floor": a.floor,
            "tags": a.tags or {}, "state": a.state, "state_since": _iso(a.state_since), "oper_status": a.oper_status, "admin_enabled": a.admin_enabled,
            "uptime_s": a.uptime_s, "join_uptime_s": a.join_uptime_s, "last_reboot_reason": a.last_reboot_reason, "cpu_pct": a.cpu_pct,
            "mem_pct": a.mem_pct, "clients": a.clients, "radio_count": a.radio_count, "power_status": a.power_status, "uplink": a.uplink or {},
            "switch_id": a.switch_id, "switch_ifindex": a.switch_ifindex, "present": a.present, "last_seen": _iso(a.last_seen),
            "first_seen": _iso(a.first_seen), "sources": (a.counters or {}).get("sources", [])}


def radio_out(r: WirelessRadio, ap: WirelessAp | None, t: dict | None = None) -> dict:
    lim = util_limit(t, r.band) if t else None
    flags = []
    if t:
        if r.channel_util_pct is not None and r.channel_util_pct >= lim:
            flags.append("high_utilization")
        if r.interference_pct is not None and r.interference_pct >= t["interference_pct"]:
            flags.append("wifi_interference")
        if r.noise_dbm is not None and r.noise_dbm >= t["noise_dbm"]:
            flags.append("high_noise")
        if r.retry_pct is not None and r.retry_pct >= t["retry_pct"]:
            flags.append("high_retries")
        if r.state == "down":
            flags.append("down")
    return {"id": r.id, "ap_id": r.ap_id, "ap": ap.name if ap else None, "site": ap.site if ap else "", "wlc_id": r.wlc_id, "slot": r.slot,
            "band": r.band, "radio_type": r.radio_type, "state": r.state, "state_since": _iso(r.state_since), "admin_enabled": r.admin_enabled,
            "channel": r.channel, "channel_width_mhz": r.channel_width_mhz, "tx_power_level": r.tx_power_level, "channel_util_pct": r.channel_util_pct,
            "tx_util_pct": r.tx_util_pct, "rx_util_pct": r.rx_util_pct, "noise_dbm": r.noise_dbm, "interference_pct": r.interference_pct,
            "interference_dbm": r.interference_dbm, "clients": r.clients, "poor_snr_clients": r.poor_snr_clients, "retry_pct": r.retry_pct,
            "wlans": r.wlans or [], "channel_changes": r.channel_changes, "last_seen": _iso(r.last_seen), "util_threshold": lim, "flags": flags,
            "rf_score": rf_problem_score(r, t) if t else None,
            "frequency_mhz": r.frequency_mhz, "center_frequency_mhz": r.center_frequency_mhz, "dfs": r.dfs, "radio_mac": r.radio_mac or "",
            "tx_power_dbm": r.tx_power_dbm, "channel_assignment": r.channel_assignment or "", "power_assignment": r.power_assignment or "",
            "country": r.country or "", "environment": r.environment or "", "regdomain_supported": r.regdomain_supported,
            "recommended_channel": r.recommended_channel, "link_changes": r.link_changes, "last_channel_change_at": _iso(r.last_channel_change_at),
            "rf_collected_at": _iso(r.rf_collected_at), "meta_collected_at": _iso(r.meta_collected_at),
            "neighbors_collected_at": _iso(r.neighbors_collected_at), "neighbor_count": len(r.neighbors or []), "radar": r.radar or []}


def rf_problem_score(r: WirelessRadio, t: dict) -> float | None:
    """Ranking aid (0 = clean): how far each measured RF indicator is past its threshold. None without measurements."""
    parts = []
    if r.channel_util_pct is not None:
        parts.append(max(0.0, r.channel_util_pct - (util_limit(t, r.band) - 20)) / 20)
    if r.interference_pct is not None:
        parts.append(max(0.0, r.interference_pct - (t["interference_pct"] - 15)) / 15)
    if r.noise_dbm is not None:
        parts.append(max(0.0, r.noise_dbm - (t["noise_dbm"] - 5)) / 10)
    if r.retry_pct is not None:
        parts.append(max(0.0, r.retry_pct - t["retry_pct"] / 2) / t["retry_pct"])
    return round(sum(parts), 2) if parts else None


def client_out(c: WirelessClient, ap: WirelessAp | None, radio: WirelessRadio | None, t: dict, show_identity: bool) -> dict:
    return {"id": c.id, "wlc_id": c.wlc_id, "mac": c.mac, "ip": c.ip, "username": c.username if show_identity else ("(hidden)" if c.username else ""),
            "ap_id": c.ap_id, "ap": ap.name if ap else (c.ap_mac or None), "site": ap.site if ap else "", "slot": c.slot, "band": c.band,
            "protocol": c.protocol, "ssid": c.ssid, "wlan_profile": c.wlan_profile, "vlan": c.vlan, "channel": c.channel, "status": c.status,
            "auth_mode": c.auth_mode, "reason": c.reason, "rssi_dbm": c.rssi_dbm, "snr_db": c.snr_db, "tx_rate_mbps": c.tx_rate_mbps,
            "session_s": c.session_s, "rx_bytes": c.rx_bytes, "tx_bytes": c.tx_bytes, "roams": c.roams, "disconnects": c.disconnects,
            "present": c.present, "first_seen": _iso(c.first_seen), "last_seen": _iso(c.last_seen), "sources": c.sources or [],
            "experience": client_score(c, radio, t)}


# ------------------------------------------------------------------ loading helpers
async def controllers(s: AsyncSession) -> list[Switch]:
    return list((await s.execute(select(Switch).where(func.lower(Switch.role) == "wlc").order_by(Switch.name))).scalars())


async def load(s: AsyncSession, wlc_ids: list[int] | None = None, site: str | None = None):
    wlcs = {w.id: w for w in await controllers(s)}
    ids = [i for i in (wlc_ids or list(wlcs)) if i in wlcs]
    aps = {a.id: a for a in (await s.execute(select(WirelessAp).where(WirelessAp.wlc_id.in_(ids)))).scalars()} if ids else {}
    if site:
        aps = {k: a for k, a in aps.items() if a.site == site}
    radios = [r for r in (await s.execute(select(WirelessRadio).where(WirelessRadio.wlc_id.in_(ids)))).scalars() if r.ap_id in aps] if ids else []
    return wlcs, ids, aps, radios


def wlc_out(w: Switch, now: datetime) -> dict:
    h = (w.health or {}).get("wireless") or {}
    from ..switches.poller import intervals_of
    ivs = intervals_of(w)
    gs = w.group_state or {}
    groups = {g: {"interval_seconds": ivs.get(g), "last_run": (gs.get(g) or {}).get("last_run"), "ok": (gs.get(g) or {}).get("ok"),
                  "error": (gs.get(g) or {}).get("error")} for g in ivs if g.startswith("wireless_")}
    stale, failing = [], []
    for g, d in groups.items():
        lr = d["last_run"]
        if d["interval_seconds"] and (lr is None or (now - datetime.fromisoformat(lr)).total_seconds() > 3 * d["interval_seconds"] + 60):
            stale.append(g)
        elif d["ok"] is False:
            failing.append(g)
    return {"id": w.id, "name": w.name, "address": w.address, "vendor": w.vendor, "model": w.model, "firmware": w.firmware, "serial": w.serial,
            "site": w.site, "location": w.location, "state": w.state, "state_since": _iso(w.state_since), "monitoring": w.monitoring,
            "last_success_at": _iso(w.last_success_at), "last_poll_at": _iso(w.last_poll_at), "uptime_s": (w.uptime_ticks or 0) / 100 if w.uptime_ticks else None,
            "cpu_pct": w.cpu_pct, "mem_pct": w.mem_pct, "aps": h.get("aps"), "aps_up": h.get("aps_up"), "aps_down": h.get("aps_down"),
            "aps_degraded": h.get("aps_degraded"), "clients": h.get("clients"), "wlans": h.get("wlans"), "coverage_pct": w.coverage_pct,
            "last_error": w.last_error, "groups": groups, "stale_groups": stale, "failing_groups": failing, "clients_truncated": h.get("clients_truncated", False),
            "ap_table_ok": h.get("ap_table_ok"), "snmp_version": None}


# ------------------------------------------------------------------ overview
async def overview(s: AsyncSession, *, wlc_ids=None, site=None, now=None) -> dict:
    now = now or datetime.now(timezone.utc)
    wlcs, ids, aps, radios = await load(s, wlc_ids, site)
    t_by = {i: thresholds(w) for i, w in wlcs.items()}
    clients = list((await s.execute(select(WirelessClient).where(WirelessClient.wlc_id.in_(ids), WirelessClient.present.is_(True))))
                   .scalars()) if ids else []
    if site:
        clients = [c for c in clients if c.ap_id in aps]
    wl = list((await s.execute(select(WirelessWlan).where(WirelessWlan.wlc_id.in_(ids), WirelessWlan.present.is_(True)))).scalars()) if ids else []
    live_aps = [a for a in aps.values() if a.present or a.state == "down"]
    unhealthy = [r for r in radios if r.present and (r.state == "down" or (r.state == "up" and rf_problem_score(r, t_by[r.wlc_id]) or 0) >= 1)]
    hi_util = [r for r in radios if r.channel_util_pct is not None and r.channel_util_pct >= util_limit(t_by[r.wlc_id], r.band)]
    poor = [c for c in clients if c.rssi_dbm is not None and c.rssi_dbm <= t_by[c.wlc_id]["rssi_poor_dbm"]]
    low_snr = [c for c in clients if c.snr_db is not None and c.snr_db <= t_by[c.wlc_id]["snr_poor_db"]]
    since = now - timedelta(hours=24)
    ev_q = select(WirelessEvent.kind, func.count()).where(WirelessEvent.wlc_id.in_(ids), WirelessEvent.at >= since).group_by(WirelessEvent.kind) if ids else None
    ev_counts = dict((await s.execute(ev_q)).all()) if ev_q is not None else {}
    roam_anom = await roaming(s, wlc_ids=ids, hours=24, now=now, site=site, summary_only=True) if ids else {"anomalies": 0}
    alerts = (await s.execute(select(func.count()).select_from(Alert).where(Alert.rule_key.like("wireless_%"),
                                                                            Alert.status.in_(["new", "investigating"])))).scalar_one()
    assoc_fail = sum((a.counters or {}).get("assoc_fail_delta") or 0 for a in live_aps)
    by_band = Counter(c.band or "unknown" for c in clients)
    by_ssid = Counter(c.ssid or "(none)" for c in clients)
    by_ap = Counter(c.ap_id for c in clients if c.ap_id)
    by_site = Counter((aps[c.ap_id].site if c.ap_id in aps else "") or "(no site)" for c in clients)
    ap_status = defaultdict(Counter)
    for a in live_aps:
        ap_status[a.site or "(no site)"][a.state] += 1
    band_health = defaultdict(lambda: {"radios": 0, "up": 0, "high_util": 0, "util": [], "noise": [], "interference": []})
    for r in radios:
        if not r.present:
            continue
        b = band_health[r.band or "unknown"]
        b["radios"] += 1
        b["up"] += r.state == "up"
        b["high_util"] += r in hi_util
        for k, v in (("util", r.channel_util_pct), ("noise", r.noise_dbm), ("interference", r.interference_pct)):
            if v is not None:
                b[k].append(v)
    avg = lambda xs: round(sum(xs) / len(xs), 1) if xs else None  # noqa: E731
    recent = (await s.execute(select(WirelessEvent).where(WirelessEvent.wlc_id.in_(ids), WirelessEvent.kind.notin_(["client_associated"]))
                              .order_by(WirelessEvent.at.desc()).limit(25))).scalars().all() if ids else []
    return {
        "generated_at": now.isoformat(),
        "cards": {"wlcs": len(wlcs if not wlc_ids else ids), "wlcs_online": sum(1 for i in ids if wlcs[i].state == "up"),
                  "aps": len(live_aps), "aps_online": sum(1 for a in live_aps if a.state in ("up", "degraded")),
                  "aps_offline": sum(1 for a in live_aps if a.state == "down"), "aps_degraded": sum(1 for a in live_aps if a.state == "degraded"),
                  "clients": len(clients), "ssids": sum(1 for w in wl if w.enabled), "unhealthy_radios": len(unhealthy),
                  "high_util_radios": len(hi_util), "poor_signal_clients": len(poor), "low_snr_clients": len(low_snr),
                  "assoc_failures": assoc_fail, "roaming_anomalies": roam_anom["anomalies"], "alerts": alerts,
                  "disconnects_24h": ev_counts.get("client_disconnected", 0), "ap_down_events_24h": ev_counts.get("ap_down", 0)},
        "controllers": [wlc_out(wlcs[i], now) for i in ids],
        "ap_status_by_site": [{"site": k, **v} for k, v in sorted(ap_status.items())],
        "clients_by_ssid": [{"ssid": k, "clients": v} for k, v in by_ssid.most_common(15)],
        "clients_by_band": [{"band": k, "clients": v} for k, v in by_band.most_common()],
        "clients_by_ap": [{"ap_id": k, "ap": aps[k].name if k in aps else str(k), "clients": v} for k, v in by_ap.most_common(10)],
        "clients_by_site": [{"site": k, "clients": v} for k, v in by_site.most_common()],
        "rf_by_band": [{"band": k, "radios": v["radios"], "up": v["up"], "high_util": v["high_util"], "avg_util": avg(v["util"]),
                        "avg_noise_dbm": avg(v["noise"]), "avg_interference_pct": avg(v["interference"])} for k, v in sorted(band_health.items())],
        "worst_radios": [radio_out(r, aps.get(r.ap_id), t_by[r.wlc_id]) for r in sorted(
            [r for r in radios if r.present and rf_problem_score(r, t_by[r.wlc_id])], key=lambda r: -rf_problem_score(r, t_by[r.wlc_id]))[:10]],
        "client_experience": {"poor_rssi": len(poor), "low_snr": len(low_snr),
                              "high_retry_radio_clients": sum(1 for c in clients if any(r.ap_id == c.ap_id and r.slot == c.slot and (r.retry_pct or 0)
                                                                                        >= t_by[c.wlc_id]["retry_pct"] for r in radios)),
                              "repeat_disconnects": sum(1 for c in clients if (c.disconnects or 0) >= 3), "frequent_roamers": roam_anom.get("frequent", 0)},
        "recent_events": [event_out(e, aps) for e in recent],
    }


def event_out(e: WirelessEvent, aps: dict | None = None) -> dict:
    return {"id": e.id, "at": _iso(e.at), "wlc_id": e.wlc_id, "ap_id": e.ap_id, "ap": (aps or {}).get(e.ap_id).name if e.ap_id in (aps or {}) else None,
            "client_mac": e.client_mac, "kind": e.kind, "severity": e.severity, "component": e.component, "detail": e.detail, "data": e.data or {}}


# ------------------------------------------------------------------ roaming
async def roaming(s: AsyncSession, *, wlc_ids=None, hours: int = 24, now=None, site=None, summary_only=False, mac: str | None = None) -> dict:
    """Roams are inferred from consecutive polls (WirelessEvent client_roam). Anomalies: excessive roaming (≥ the
    roams-per-hour threshold over the window), ping-pong (A → B → A within 10 minutes), and disconnect right after a
    roam. Durations are not measured by SNMP and are never reported."""
    now = now or datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)
    q = select(WirelessEvent).where(WirelessEvent.kind.in_(["client_roam", "client_disconnected"]), WirelessEvent.at >= since)
    if wlc_ids:
        q = q.where(WirelessEvent.wlc_id.in_(wlc_ids))
    if mac:
        q = q.where(WirelessEvent.client_mac == mac)
    evs = list((await s.execute(q.order_by(WirelessEvent.at))).scalars())
    by: dict[str, list] = defaultdict(list)
    for e in evs:
        by[e.client_mac].append(e)
    limit = DEFAULTS["roams_per_hour"] * max(1, hours) if hours <= 1 else DEFAULTS["roams_per_hour"] * hours / 4
    rows, anomalies, frequent = [], 0, 0
    for m, lst in by.items():
        roams = [e for e in lst if e.kind == "client_roam"]
        pingpong = 0
        for a, b in zip(roams, roams[1:]):
            if (a.data or {}).get("from_ap") == (b.data or {}).get("to_ap") and (b.at - a.at).total_seconds() <= 600:
                pingpong += 1
        drop_after = sum(1 for a, b in zip(lst, lst[1:]) if a.kind == "client_roam" and b.kind == "client_disconnected" and (b.at - a.at).total_seconds() <= 300)
        flags = []
        if len(roams) >= limit:
            flags.append("excessive_roaming")
            frequent += 1
        if pingpong:
            flags.append("ping_pong")
        if drop_after:
            flags.append("disconnect_after_roam")
        anomalies += bool(flags)
        if not summary_only:
            rows.append({"mac": m, "roams": len(roams), "ping_pong": pingpong, "disconnect_after_roam": drop_after, "flags": flags,
                         "aps": sorted({(e.data or {}).get("to_ap") for e in roams if (e.data or {}).get("to_ap")})[:20],
                         "last": _iso(lst[-1].at)})
    out = {"window_hours": hours, "clients": len(by), "roams": sum(1 for e in evs if e.kind == "client_roam"), "anomalies": anomalies,
           "frequent": frequent, "threshold_roams": round(limit, 1), "measured": False,
           "note": "Roams are inferred from the controller's client→AP mapping in consecutive polls; roam duration is not measured."}
    if not summary_only:
        out["rows"] = sorted(rows, key=lambda r: (-len(r["flags"]), -r["roams"]))[:500]
        out["timeline"] = [event_out(e) for e in evs[-500:]] if mac else []
    return out


# ------------------------------------------------------------------ AP ↔ switch
async def switch_port(s: AsyncSession, a: WirelessAp) -> dict | None:
    """The switch port that cables the AP, only when the controller's CDP cache names it (never inferred from the IP)."""
    if not (a.uplink or {}).get("switch"):
        return None
    out = {"cdp": a.uplink, "switch_id": a.switch_id, "monitored": a.switch_id is not None, "port": None}
    if a.switch_id:
        sw = await s.get(Switch, a.switch_id)
        out["switch"] = {"id": sw.id, "name": sw.name, "state": sw.state, "cpu_pct": sw.cpu_pct, "last_success_at": _iso(sw.last_success_at)} if sw else None
        if a.switch_ifindex is not None:
            i = (await s.execute(select(SwitchInterface).where(SwitchInterface.switch_id == a.switch_id, SwitchInterface.ifindex == a.switch_ifindex))).scalars().first()
            if i:
                out["port"] = {"ifindex": i.ifindex, "name": i.name, "oper": i.oper, "admin": i.admin, "poe": i.poe, "access_vlan": i.access_vlan,
                               "mode": i.mode, "in_errors_delta": i.in_errors_delta, "crc_delta": i.crc_delta,
                               "speed_mbps": i.speed_bps / 1e6 if i.speed_bps else None}
    return out


# ------------------------------------------------------------------ troubleshooting
SCENARIOS = {"poor_performance": "Poor wireless performance", "ap_offline": "AP offline", "client_cannot_connect": "Client cannot connect",
             "frequent_disconnects": "Frequent disconnections", "high_load": "High client load"}


def _ev(kind: str, ok: bool | None, text: str, value=None, threshold=None, source="") -> dict:
    return {"check": kind, "ok": ok, "text": text, "value": value, "threshold": threshold, "source": source}


async def troubleshoot(s: AsyncSession, scenario: str, *, ap_id: int | None = None, mac: str | None = None, ssid: str | None = None,
                       now: datetime | None = None) -> dict:
    """Rule-based checks over what the controller (and switch monitoring) reported. Each finding lists the evidence it
    rests on; probable causes are correlations, not a determined root cause."""
    now = now or datetime.now(timezone.utc)
    if scenario not in SCENARIOS:
        raise ValueError("unknown scenario")
    c = None
    if mac:
        c = (await s.execute(select(WirelessClient).where(WirelessClient.mac == mac.lower()).order_by(WirelessClient.last_seen.desc()))).scalars().first()
        if c and not ap_id:
            ap_id = c.ap_id
    a = await s.get(WirelessAp, ap_id) if ap_id else None
    wlc = await s.get(Switch, a.wlc_id) if a else (await s.get(Switch, c.wlc_id) if c else None)
    t = thresholds(wlc)
    radios = list((await s.execute(select(WirelessRadio).where(WirelessRadio.ap_id == a.id))).scalars()) if a else []
    radio = next((r for r in radios if c and r.slot == c.slot), None)
    ev: list[dict] = []
    causes: list[tuple[str, int]] = []
    if wlc:
        ok = wlc.state == "up"
        ev.append(_ev("controller", ok, f"controller {wlc.name} is {wlc.state}" + ("" if ok else f" since {_iso(wlc.state_since)}"), source="SNMP reachability"))
        stale = wlc_out(wlc, now)["stale_groups"]
        if stale:
            ev.append(_ev("collection", False, f"wireless data is stale for {', '.join(stale)}: findings below may be out of date", source="collector"))
            causes.append(("Monitoring data is stale; confirm on the controller before acting", 1))
        if not ok:
            causes.append(("Controller unreachable from the SIEM: AP and client data cannot be trusted until it answers", 3))
    if scenario == "ap_offline":
        if not a:
            raise ValueError("choose an AP")
        ev.append(_ev("ap_state", a.state not in ("down",), f"AP {a.name} state {a.state} (controller status '{a.oper_status or 'not listed'}')", source="AIRESPACE-WIRELESS-MIB"))
        if a.state == "maintenance":
            causes.append(("The AP is administratively disabled on the controller", 3))
        if a.last_reboot_reason:
            ev.append(_ev("reboot_reason", None, f"last reboot reason reported: {a.last_reboot_reason}", source="CISCO-LWAPP-AP-MIB"))
        last = (await s.execute(select(WirelessEvent).where(WirelessEvent.ap_id == a.id, WirelessEvent.kind.in_(["ap_down", "ap_reboot", "ap_reconnected"]))
                                .order_by(WirelessEvent.at.desc()).limit(5))).scalars().all()
        for e in last:
            ev.append(_ev("ap_event", None, f"{_iso(e.at)} {e.detail}", source="wireless events"))
        sp = await switch_port(s, a)
        if not sp:
            ev.append(_ev("switch_port", None, "the controller's CDP cache does not name this AP's switch port: physical-layer checks unavailable", source="CISCO-LWAPP-CDP-MIB"))
        elif not sp["monitored"]:
            ev.append(_ev("switch_port", None, f"cabled to {sp['cdp'].get('switch')} {sp['cdp'].get('port')} (CDP), which is not a monitored switch", source="CISCO-LWAPP-CDP-MIB"))
        else:
            sw = sp.get("switch") or {}
            ev.append(_ev("switch", sw.get("state") == "up", f"uplink switch {sw.get('name')} is {sw.get('state')}", source="switch monitoring"))
            if sw.get("state") != "up":
                causes.append((f"The uplink switch {sw.get('name')} is not reachable: likely site / switch problem", 3))
            p = sp.get("port")
            if p:
                ev.append(_ev("port", p["oper"] == "up", f"port {p['name']} oper {p['oper']} / admin {p['admin']}", source="switch monitoring (IF-MIB)"))
                if p["oper"] != "up":
                    causes.append((f"Switch port {p['name']} is {p['oper']}: cable, port or power", 3))
                poe = p.get("poe") or {}
                if poe:
                    delivering = poe.get("status") in ("deliveringPower", "delivering") or (poe.get("power_w") or 0) > 0
                    ev.append(_ev("poe", delivering, f"PoE status {poe.get('status') or '?'}, {poe.get('power_w', '?')} W", source="switch monitoring (POWER-ETHERNET-MIB)"))
                    if not delivering:
                        causes.append((f"PoE is not delivering power on {p['name']}", 3))
            else:
                ev.append(_ev("port", None, f"CDP names port {sp['cdp'].get('port')} but it was not found on {sw.get('name')}", source="switch monitoring"))
        if a.state == "down" and not causes:
            causes.append(("The AP left the controller with no switch-side evidence: check the AP's power, cabling and its controller join (CAPWAP) path", 1))
    if scenario in ("poor_performance", "high_load", "frequent_disconnects") or (scenario == "client_cannot_connect" and a):
        for r in radios if not radio else [radio]:
            lim = util_limit(t, r.band)
            tag = f"radio {r.slot} ({r.band or '?'} GHz)"
            if r.channel_util_pct is not None:
                bad = r.channel_util_pct >= lim
                ev.append(_ev("channel_util", not bad, f"{tag} channel utilisation {r.channel_util_pct}%", r.channel_util_pct, lim, "AIRESPACE bsnAPIfLoadParametersTable"))
                if bad:
                    causes.append((f"{tag} channel is busy ({r.channel_util_pct}% ≥ {lim}%): airtime contention", 2))
            if r.interference_pct is not None:
                bad = r.interference_pct >= t["interference_pct"]
                ev.append(_ev("interference", not bad, f"{tag} 802.11 interference {r.interference_pct}% on channel {r.channel}", r.interference_pct, t["interference_pct"],
                              "AIRESPACE bsnAPIfChannelInterferenceInfoTable"))
                if bad:
                    causes.append((f"{tag} other 802.11 networks use channel {r.channel} heavily (co-channel)", 2))
            if r.noise_dbm is not None:
                bad = r.noise_dbm >= t["noise_dbm"]
                ev.append(_ev("noise", not bad, f"{tag} noise floor {r.noise_dbm} dBm", r.noise_dbm, t["noise_dbm"], "AIRESPACE bsnAPIfChannelNoiseInfoTable"))
                if bad:
                    causes.append((f"{tag} raised noise floor ({r.noise_dbm} dBm): possible non-802.11 interference — not identified by SNMP", 1))
            if r.retry_pct is not None:
                bad = r.retry_pct >= t["retry_pct"]
                ev.append(_ev("retries", not bad, f"{tag} retries {r.retry_pct}% of transmitted frames", r.retry_pct, t["retry_pct"], "AIRESPACE bsnAPIfDot11CountersTable"))
                if bad:
                    causes.append((f"{tag} high retry rate: RF contention or weak clients", 2))
            if r.state != "up":
                ev.append(_ev("radio_state", False, f"{tag} is {r.state}", source="AIRESPACE bsnAPIfTable"))
                causes.append((f"{tag} is {r.state}", 3))
        if a and a.clients is not None:
            bad = a.clients >= t["ap_clients_max"]
            ev.append(_ev("ap_clients", not bad, f"AP {a.name} serves {a.clients} clients", a.clients, t["ap_clients_max"], "CISCO-LWAPP-AP-MIB"))
            if bad:
                causes.append((f"AP {a.name} is heavily loaded ({a.clients} clients)", 2 if scenario == "high_load" else 1))
    if c:
        if c.rssi_dbm is not None:
            bad = c.rssi_dbm <= t["rssi_poor_dbm"]
            ev.append(_ev("rssi", not bad, f"client RSSI {c.rssi_dbm} dBm", c.rssi_dbm, t["rssi_poor_dbm"], "AIRESPACE bsnMobileStationStatsTable"))
            if bad:
                causes.append(("Weak client signal: coverage gap, distance or the client sticking to a far AP", 2))
        else:
            ev.append(_ev("rssi", None, "client RSSI not reported by the controller", source="AIRESPACE bsnMobileStationStatsTable"))
        if c.snr_db is not None:
            bad = c.snr_db <= t["snr_poor_db"]
            ev.append(_ev("snr", not bad, f"client SNR {c.snr_db} dB", c.snr_db, t["snr_poor_db"], "AIRESPACE bsnMobileStationStatsTable"))
            if bad:
                causes.append(("Low SNR at the client: noise or weak signal", 2))
        if c.tx_rate_mbps is not None:
            bad = c.tx_rate_mbps <= t["rate_poor_mbps"]
            ev.append(_ev("rate", not bad, f"client data rate {c.tx_rate_mbps} Mbit/s", c.tx_rate_mbps, t["rate_poor_mbps"], "CISCO-LWAPP-DOT11-CLIENT-MIB"))
            if bad:
                causes.append(("Very low negotiated data rate", 1))
        hist = (await s.execute(select(WirelessEvent).where(WirelessEvent.client_mac == c.mac, WirelessEvent.at >= now - timedelta(hours=24)))).scalars().all()
        roams = sum(1 for e in hist if e.kind == "client_roam")
        drops = sum(1 for e in hist if e.kind == "client_disconnected")
        ev.append(_ev("history", drops < 3 and roams < 20, f"last 24 h: {roams} roam(s), {drops} disconnect(s) observed between polls", source="wireless events"))
        if drops >= 3:
            causes.append((f"{drops} disconnections in 24 h" + (" with weak signal" if c.rssi_dbm is not None and c.rssi_dbm <= t["rssi_poor_dbm"] else ""), 2))
        if roams >= 20:
            causes.append((f"Frequent roaming ({roams} in 24 h): overlapping cells or roaming thresholds", 1))
        if scenario == "client_cannot_connect":
            ev.append(_ev("status", c.status in ("associated", "authenticated"), f"controller status '{c.status or '?'}'" + (f", last reason '{c.reason}'" if c.reason else ""),
                          source="CISCO-LWAPP-DOT11-CLIENT-MIB"))
            if c.status in ("aaaPending",):
                causes.append(("Authentication pending at the controller: check RADIUS / 802.1X (details need WLC syslog or RADIUS logs)", 2))
            if c.status in ("excluded", "blacklisted"):
                causes.append(("The controller has excluded this client (repeated failures / policy)", 3))
            ev.append(_ev("vlan", c.vlan is not None, f"VLAN {c.vlan}" if c.vlan is not None else "VLAN not reported", source="controller"))
    if scenario == "client_cannot_connect" and ssid:
        w = (await s.execute(select(WirelessWlan).where(WirelessWlan.ssid == ssid))).scalars().first()
        if not w:
            ev.append(_ev("ssid", False, f"SSID {ssid} is not configured on any monitored controller", source="CISCO-LWAPP-WLAN-MIB"))
            causes.append((f"SSID {ssid} not found on the monitored controllers", 3))
        else:
            ev.append(_ev("ssid", bool(w.enabled), f"SSID {ssid} is {'enabled' if w.enabled else 'disabled'}"
                          + (f" and broadcast by {w.radios} radio(s) on {w.aps} AP(s)" if w.radios is not None else ""), source="CISCO-LWAPP-WLAN-MIB"))
            if not w.enabled:
                causes.append((f"SSID {ssid} is disabled", 3))
            elif w.radios == 0:
                causes.append((f"SSID {ssid} is not broadcast by any radio", 3))
        ev.append(_ev("auth_detail", None, "802.1X / EAP / RADIUS / DHCP failure details are not exposed by these MIBs; use WLC syslog or RADIUS logs", source="limitation"))
    if scenario == "client_cannot_connect" and not (c or ssid or a):
        raise ValueError("choose a client MAC, an SSID or an AP")
    if scenario in ("poor_performance", "frequent_disconnects") and not (a or c):
        raise ValueError("choose an AP or a client MAC")
    causes.sort(key=lambda x: -x[1])
    measured = [e for e in ev if e["ok"] is not None]
    bad = [e for e in measured if e["ok"] is False]
    sev = "high" if any(w >= 3 for _, w in causes) else "medium" if causes else "low"
    confidence = "low" if len(measured) < 3 else "medium" if len(measured) < 6 else "high"
    return {"scenario": scenario, "label": SCENARIOS[scenario], "severity": sev, "confidence": confidence,
            "target": {"wlc": wlc.name if wlc else None, "ap": a.name if a else None, "ap_id": a.id if a else None, "client": c.mac if c else mac, "ssid": ssid},
            "evidence": ev, "probable_causes": [x for x, _ in causes] or (["No measured indicator is outside its threshold"] if measured else ["Not enough data to assess"]),
            "failed_checks": len(bad), "measured_checks": len(measured),
            "next_steps": _steps(scenario), "note": "Probable causes are correlations of the reported measurements, not a determined root cause."}


def _steps(scenario: str) -> list[str]:
    return {
        "poor_performance": ["Compare the radio's channel utilisation and retries with neighbouring APs (RF analytics)",
                             "Check whether the affected clients have weak RSSI / SNR (client list filtered by AP)",
                             "Review the RF profile / DCA channel plan on the controller"],
        "ap_offline": ["Check the switch port and PoE (Switch Monitoring → the uplink switch)", "Check the AP's join path to the controller (CAPWAP, DHCP option 43 / DNS)",
                       "Review the controller's AP join statistics"],
        "client_cannot_connect": ["Check the SSID is enabled and broadcast on the AP the client sees", "Check RADIUS / 802.1X logs for the client",
                                  "Check the client's VLAN / DHCP scope"],
        "frequent_disconnects": ["Check RSSI / SNR history for the client", "Check AP restarts and channel changes at the same times",
                                 "Review roaming between the APs involved"],
        "high_load": ["Compare client counts on neighbouring APs (band steering, load balancing)", "Check per-radio channel utilisation and the 2.4 GHz share"],
    }[scenario]
