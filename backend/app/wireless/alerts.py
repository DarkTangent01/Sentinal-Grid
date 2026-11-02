"""Wireless alert rules (same engine, dedup, cooldown, notifications and auto-resolve as every other rule).

WLC unreachable / CPU / memory are covered by the switch rules (the controller is a monitored device):
switch_unreachable, switch_snmp_auth, switch_cpu_high, switch_memory_high, switch_stale_metrics.
Rules skip paused controllers and APs in maintenance (administratively disabled). Sustained conditions use the
ClickHouse history over the evaluation window, so one bad poll does not alert. Group keys identify the condition
(AP / radio / client), so a continuing problem updates one alert instead of creating one per poll.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from ..db.models import Switch, WirelessAp, WirelessClient, WirelessEvent, WirelessRadio
from ..db.pg import session_factory
from .service import thresholds, util_limit

STEPS = {
    "wireless_ap_down": ["Run Wireless Troubleshooting → AP offline (switch port, PoE, controller join)", "Check the AP's power and cabling"],
    "wireless_radio_down": ["Check whether the radio was disabled on the controller or failed", "Review the AP's events for resets"],
    "wireless_channel_utilization": ["Compare with neighbouring APs on the same channel (RF analytics)", "Review DCA / channel width for the band"],
    "wireless_interference": ["Identify the other 802.11 networks on the channel (controller RF / rogue reports)", "Consider a different channel"],
    "wireless_noise_high": ["Look for non-802.11 sources near the AP (spectrum analysis); SNMP does not identify them"],
    "wireless_retry_high": ["Check client RSSI / SNR on the radio", "Check channel utilisation and interference at the same time"],
    "wireless_poor_rssi": ["Check AP placement / coverage for the area", "Check whether clients stick to a distant AP"],
    "wireless_low_snr": ["Check noise floor and interference on the serving radios"],
    "wireless_ap_overload": ["Check client distribution across neighbouring APs and bands"],
    "wireless_client_disconnects": ["Run Wireless Troubleshooting → Frequent disconnections for an affected client"],
    "wireless_assoc_failures": ["Check RADIUS / 802.1X logs; SNMP gives counts only, not failure reasons"],
    "wireless_excessive_roaming": ["Review the client's roaming timeline (Roaming analysis)", "Check cell overlap and roaming thresholds"],
    "wireless_channel_changes": ["Open Wireless → RF & Frequency → RF events for the change reasons and radar detections",
                                 "Review DCA sensitivity / DFS channel use for the RF profile on the controller"],
    "wireless_stale_metrics": ["Open Wireless → Monitoring health for the controller", "Check the SNMP view includes the wireless MIBs"],
}

DEFAULT_RULES = [
    {"key": "wireless_ap_down", "name": "Wireless: AP disconnected from controller", "severity": "high", "mitre": {},
     "description": "An AP left the controller's AP table (absent from 2 consecutive successful polls).", "params": {"min_down_minutes": 2}},
    {"key": "wireless_radio_down", "name": "Wireless: AP radio down", "severity": "medium", "mitre": {},
     "description": "An administratively enabled AP radio is operationally down.", "params": {"min_down_minutes": 5}},
    {"key": "wireless_channel_utilization", "name": "Wireless: high channel utilisation", "severity": "medium", "mitre": {},
     "description": "A radio's channel utilisation stayed at or above its band threshold for most samples in the window.",
     "params": {"window_minutes": 15, "min_fraction": 0.8, "min_samples": 3}},
    {"key": "wireless_interference", "name": "Wireless: high 802.11 interference", "severity": "low", "mitre": {},
     "description": "Interference from other 802.11 networks on a radio's channel stayed above the threshold.", "params": {"window_minutes": 30, "min_samples": 2}},
    {"key": "wireless_noise_high", "name": "Wireless: high noise floor", "severity": "low", "mitre": {},
     "description": "A radio's noise floor stayed above the threshold.", "params": {"window_minutes": 30, "min_samples": 2}},
    {"key": "wireless_retry_high", "name": "Wireless: high retry rate", "severity": "low", "mitre": {},
     "description": "Retries as a share of transmitted frames stayed above the threshold on a radio.", "params": {"window_minutes": 15, "min_samples": 3}},
    {"key": "wireless_poor_rssi", "name": "Wireless: many clients with poor signal on an AP", "severity": "low", "mitre": {},
     "description": "Several clients of one AP report RSSI at or below the poor-signal threshold.", "params": {"min_clients": 5}},
    {"key": "wireless_low_snr", "name": "Wireless: many clients with low SNR on an AP", "severity": "low", "mitre": {},
     "description": "Several clients of one AP report SNR at or below the threshold.", "params": {"min_clients": 5}},
    {"key": "wireless_ap_overload", "name": "Wireless: AP client overload", "severity": "medium", "mitre": {},
     "description": "An AP serves more clients than the configured maximum.", "params": {}},
    {"key": "wireless_client_disconnects", "name": "Wireless: excessive client disconnections", "severity": "medium", "mitre": {},
     "description": "Many client disconnections at one AP within the window.", "params": {"window_minutes": 60, "min_disconnects": 20}},
    {"key": "wireless_assoc_failures", "name": "Wireless: association failure spike", "severity": "medium", "mitre": {},
     "description": "An AP's failed-association counter increased sharply in the last poll (CISCO-LWAPP-AP-MIB cLApAssocFailTimes).",
     "params": {"min_failures": 20}},
    {"key": "wireless_excessive_roaming", "name": "Wireless: excessive client roaming", "severity": "low", "mitre": {},
     "description": "A client roamed between APs more often than the threshold within the window (roams inferred between polls).",
     "params": {"window_minutes": 60}},
    {"key": "wireless_channel_changes", "name": "Wireless: repeated channel changes", "severity": "low", "mitre": {},
     "description": "A radio changed channel more often than the threshold within the window (DFS radar, DCA or configuration).",
     "params": {"window_hours": 24}},
    {"key": "wireless_stale_metrics", "name": "Wireless: stale or missing wireless metrics", "severity": "medium", "mitre": {},
     "description": "A controller is reachable but a wireless collection group has not succeeded for 3 of its intervals.", "params": {}},
]
AUTO_RESOLVE = {"wireless_channel_changes", "wireless_ap_down", "wireless_radio_down", "wireless_channel_utilization", "wireless_interference", "wireless_noise_high",
                "wireless_retry_high", "wireless_poor_rssi", "wireless_low_snr", "wireless_ap_overload", "wireless_stale_metrics"}


def _aware(v):
    if isinstance(v, str):                     # ClickHouse drivers may return DateTime64 as text
        v = datetime.fromisoformat(v.replace(" ", "T"))
    return v if v is None or v.tzinfo else v.replace(tzinfo=timezone.utc)


def _det(key: str, rule: str, explanation: str, *, first, last, count=1, sites=None, evidence=None):
    from ..alerts.engine import Detection
    return Detection(group_key=key, count=count, first_seen=first, last_seen=last, explanation=explanation, sites=[x for x in (sites or []) if x],
                     evidence={"rule": rule, "investigation": STEPS.get(rule, []), "detected_at": last.isoformat(), **(evidence or {})}, event_filter={})


async def _ctx():
    async with session_factory()() as s:
        wlcs = {w.id: w for w in (await s.execute(select(Switch).where(func.lower(Switch.role) == "wlc"))).scalars() if w.monitoring == "active"}
        aps = {a.id: a for a in (await s.execute(select(WirelessAp).where(WirelessAp.wlc_id.in_(list(wlcs) or [0])))).scalars()}
        radios = list((await s.execute(select(WirelessRadio).where(WirelessRadio.wlc_id.in_(list(wlcs) or [0])))).scalars())
    return wlcs, aps, radios


async def rule_wireless_ap_down(ch, now, p):
    wlcs, aps, _ = await _ctx()
    out = []
    for a in aps.values():
        since = _aware(a.state_since)
        if a.state != "down" or a.wlc_id not in wlcs or wlcs[a.wlc_id].state != "up" or not since:
            continue  # controller down: its APs are unknown, not individually down (switch_unreachable covers it)
        if (now - since).total_seconds() < 60 * float(p.get("min_down_minutes", 2)):
            continue
        out.append(_det(f"{a.id}:{since:%Y%m%d%H%M%S}", "wireless_ap_down", f"AP {a.name} ({a.model or 'model ?'}, {a.mac}) left controller "
                        f"{wlcs[a.wlc_id].name} at {since:%Y-%m-%d %H:%M} UTC" + (f"; uplink {a.uplink.get('switch')} {a.uplink.get('port')}" if (a.uplink or {}).get("switch") else ""),
                        first=since, last=now, sites=[a.site], evidence={"ap_id": a.id, "ap": a.name, "uplink": a.uplink or {}}))
    return out


async def rule_wireless_radio_down(ch, now, p):
    wlcs, aps, radios = await _ctx()
    out = []
    for r in radios:
        a = aps.get(r.ap_id)
        since = _aware(r.state_since)
        if r.state != "down" or not a or a.state in ("down", "maintenance") or not since or r.wlc_id not in wlcs:
            continue
        if (now - since).total_seconds() < 60 * float(p.get("min_down_minutes", 5)):
            continue
        out.append(_det(f"{r.id}", "wireless_radio_down", f"{a.name} radio {r.slot} ({r.band or '?'} GHz) is down while enabled", first=since, last=now,
                        sites=[a.site], evidence={"ap_id": a.id, "radio_id": r.id, "band": r.band}))
    return out


async def _open_groups(rule: str) -> set[str]:
    from ..db.models import Alert
    async with session_factory()() as s:
        return {g for (g,) in (await s.execute(select(Alert.group_key).where(Alert.rule_key == rule, Alert.status.in_(("new", "investigating"))))).all()}


async def _sustained(ch, now, p, metric: str, test, label: str, rule: str, fmt, clear=None):
    """Raise when most samples in the window breach the threshold and the latest does. Hysteresis: an alert already open
    stays open until the latest sample is below the clear level (threshold − margin), so a value hovering at the
    threshold does not flap between raise and resolve."""
    wlcs, aps, radios = await _ctx()
    if not wlcs:
        return []
    still_open = await _open_groups(rule) if clear else set()
    t0 = now - timedelta(minutes=int(p["window_minutes"]))
    rows = await ch.aquery("SELECT wlc_id, ap_id, slot, any(band) AS o_band, count() AS n, groupArray(value) AS vals, min(ts) AS o_first, max(ts) AS o_last "
                           "FROM wireless_metrics WHERE metric = {m:String} AND ts >= {t0:DateTime64(3)} AND wlc_id IN {w:Array(UInt32)} "
                           "GROUP BY wlc_id, ap_id, slot", {"m": metric, "t0": t0, "w": list(wlcs)})
    rmap = {(r.ap_id, r.slot): r for r in radios}
    out = []
    for r in rows:
        a = aps.get(int(r["ap_id"]))
        if not a or a.state in ("down", "maintenance") or int(r["n"]) < int(p.get("min_samples", 2)):
            continue
        t = thresholds(wlcs[int(r["wlc_id"])])
        vals = list(r["vals"])
        bad = [v for v in vals if test(v, t, r["o_band"])]
        held = f"{a.id}:{int(r['slot'])}" in still_open and not clear(vals[-1], t, r["o_band"])
        if held or (len(bad) / len(vals) >= float(p.get("min_fraction", 0.5)) and test(vals[-1], t, r["o_band"])):
            rad = rmap.get((a.id, int(r["slot"])))
            out.append(_det(f"{a.id}:{int(r['slot'])}", rule, f"{a.name} radio {int(r['slot'])} ({r['o_band'] or '?'} GHz): {label} {fmt(vals, t, r['o_band'])} "
                            f"in {len(bad)} of {len(vals)} samples over {p['window_minutes']} min", first=_aware(r["o_first"]), last=_aware(r["o_last"]),
                            count=len(bad), sites=[a.site], evidence={"ap_id": a.id, "radio_id": rad.id if rad else None, "last": vals[-1]}))
    return out


async def rule_wireless_channel_utilization(ch, now, p):
    return await _sustained(ch, now, p, "wireless_radio_channel_utilization_percent", lambda v, t, b: v >= util_limit(t, b), "channel utilisation",
                            "wireless_channel_utilization", lambda vs, t, b: f"≥ {util_limit(t, b):.0f}% (last {vs[-1]:.0f}%)",
                            clear=lambda v, t, b: v < util_limit(t, b) - t["clear_margin_util_pct"])


async def rule_wireless_interference(ch, now, p):
    return await _sustained(ch, now, {**p, "min_fraction": 0.5}, "wireless_radio_interference_percent", lambda v, t, b: v >= t["interference_pct"],
                            "802.11 interference", "wireless_interference", lambda vs, t, b: f"≥ {t['interference_pct']}% (last {vs[-1]:.0f}%)",
                            clear=lambda v, t, b: v < t["interference_pct"] - t["clear_margin_interference_pct"])


async def rule_wireless_noise_high(ch, now, p):
    return await _sustained(ch, now, {**p, "min_fraction": 0.5}, "wireless_radio_noise_dbm", lambda v, t, b: v >= t["noise_dbm"], "noise floor",
                            "wireless_noise_high", lambda vs, t, b: f"≥ {t['noise_dbm']} dBm (last {vs[-1]:.0f} dBm)",
                            clear=lambda v, t, b: v < t["noise_dbm"] - t["clear_margin_noise_db"])


async def rule_wireless_retry_high(ch, now, p):
    return await _sustained(ch, now, {**p, "min_fraction": 0.7}, "wireless_radio_retry_percent", lambda v, t, b: v >= t["retry_pct"], "retries",
                            "wireless_retry_high", lambda vs, t, b: f"≥ {t['retry_pct']}% of frames (last {vs[-1]:.1f}%)",
                            clear=lambda v, t, b: v < t["retry_pct"] - t["clear_margin_retry_pct"])


async def _client_rf(now, p, field: str, key: str, rule: str, label: str):
    wlcs, aps, _ = await _ctx()
    async with session_factory()() as s:
        cl = list((await s.execute(select(WirelessClient).where(WirelessClient.present.is_(True), WirelessClient.wlc_id.in_(list(wlcs) or [0])))).scalars())
    by: dict[int, list] = {}
    for c in cl:
        v = getattr(c, field)
        if v is None or c.ap_id not in aps:
            continue
        if v <= thresholds(wlcs[c.wlc_id])[key]:
            by.setdefault(c.ap_id, []).append(c)
    out = []
    for ap_id, cs in by.items():
        a = aps[ap_id]
        if len(cs) >= int(p["min_clients"]) and a.state not in ("maintenance",):
            out.append(_det(f"{ap_id}", rule, f"{len(cs)} clients of AP {a.name} report {label} ≤ {thresholds(wlcs[a.wlc_id])[key]}", first=now, last=now,
                            count=len(cs), sites=[a.site], evidence={"ap_id": ap_id, "clients": [c.mac for c in cs][:50]}))
    return out


async def rule_wireless_poor_rssi(ch, now, p):
    return await _client_rf(now, p, "rssi_dbm", "rssi_poor_dbm", "wireless_poor_rssi", "RSSI (dBm)")


async def rule_wireless_low_snr(ch, now, p):
    return await _client_rf(now, p, "snr_db", "snr_poor_db", "wireless_low_snr", "SNR (dB)")


async def rule_wireless_ap_overload(ch, now, p):
    wlcs, aps, _ = await _ctx()
    out = []
    for a in aps.values():
        if a.wlc_id in wlcs and a.clients is not None and a.state in ("up", "degraded"):
            lim = thresholds(wlcs[a.wlc_id])["ap_clients_max"]
            if a.clients >= lim:
                out.append(_det(f"{a.id}", "wireless_ap_overload", f"AP {a.name} serves {a.clients} clients (threshold {lim})", first=now, last=now,
                                count=a.clients, sites=[a.site], evidence={"ap_id": a.id, "clients": a.clients}))
    return out


async def rule_wireless_client_disconnects(ch, now, p):
    wlcs, aps, _ = await _ctx()
    t0 = now - timedelta(minutes=int(p["window_minutes"]))
    async with session_factory()() as s:
        rows = (await s.execute(select(WirelessEvent.ap_id, func.count(), func.min(WirelessEvent.at), func.max(WirelessEvent.at))
                                .where(WirelessEvent.kind == "client_disconnected", WirelessEvent.at >= t0, WirelessEvent.wlc_id.in_(list(wlcs) or [0]))
                                .group_by(WirelessEvent.ap_id))).all()
    return [_det(f"{ap}:{t0:%Y%m%d%H}", "wireless_client_disconnects", f"{n} client disconnections at AP {aps[ap].name} in {p['window_minutes']} min",
                 first=_aware(a0), last=_aware(a1), count=n, sites=[aps[ap].site], evidence={"ap_id": ap})
            for ap, n, a0, a1 in rows if ap in aps and n >= int(p["min_disconnects"])]


async def rule_wireless_assoc_failures(ch, now, p):
    wlcs, aps, _ = await _ctx()
    out = []
    for a in aps.values():
        d = (a.counters or {}).get("assoc_fail_delta")
        if a.wlc_id in wlcs and d is not None and d >= int(p["min_failures"]):
            out.append(_det(f"{a.id}:{now:%Y%m%d%H}", "wireless_assoc_failures", f"AP {a.name}: {d} failed client associations since the previous poll "
                            "(SNMP gives the count, not the reasons)", first=now, last=now, count=d, sites=[a.site], evidence={"ap_id": a.id}))
    return out


async def rule_wireless_excessive_roaming(ch, now, p):
    wlcs, aps, _ = await _ctx()
    t0 = now - timedelta(minutes=int(p["window_minutes"]))
    async with session_factory()() as s:
        rows = (await s.execute(select(WirelessEvent.wlc_id, WirelessEvent.client_mac, func.count(), func.min(WirelessEvent.at), func.max(WirelessEvent.at))
                                .where(WirelessEvent.kind == "client_roam", WirelessEvent.at >= t0, WirelessEvent.wlc_id.in_(list(wlcs) or [0]))
                                .group_by(WirelessEvent.wlc_id, WirelessEvent.client_mac))).all()
    out = []
    for w, mac, n, a0, a1 in rows:
        lim = thresholds(wlcs[w])["roams_per_hour"] * int(p["window_minutes"]) / 60
        if n >= lim:
            out.append(_det(f"{mac}:{t0:%Y%m%d%H}", "wireless_excessive_roaming", f"client {mac} roamed {n} times in {p['window_minutes']} min "
                            f"(threshold {lim:.0f}; inferred between polls)", first=_aware(a0), last=_aware(a1), count=n, evidence={"client": mac}))
    return out


async def rule_wireless_channel_changes(ch, now, p):
    wlcs, aps, radios = await _ctx()
    since = now - timedelta(hours=float(p.get("window_hours", 24)))
    async with session_factory()() as s:
        evs = list((await s.execute(select(WirelessEvent).where(WirelessEvent.at >= since, WirelessEvent.kind == "channel_change",
                                                                WirelessEvent.wlc_id.in_(list(wlcs) or [0])))).scalars())
    by: dict[tuple, list] = {}
    for e in evs:
        by.setdefault((e.ap_id, e.component), []).append(e)
    out = []
    for (ap_id, comp), es in by.items():
        a = aps.get(ap_id)
        if not a or a.state == "maintenance":
            continue
        lim = int(thresholds(wlcs[a.wlc_id])["channel_changes_per_day"])
        if len(es) >= lim:
            es.sort(key=lambda e: e.at)
            reasons = sorted({(e.data or {}).get("reason", "not reported") for e in es})
            out.append(_det(f"{comp}", "wireless_channel_changes", f"{comp}: {len(es)} channel changes since {since:%Y-%m-%d %H:%M} UTC "
                            f"(threshold {lim}); reasons: {'; '.join(reasons)[:300]}", first=_aware(es[0].at), last=_aware(es[-1].at), count=len(es),
                            sites=[a.site], evidence={"ap_id": a.id, "channels": [(e.data or {}).get("new") for e in es][-20:]}))
    return out


async def rule_wireless_stale_metrics(ch, now, p):
    from .service import wlc_out
    wlcs, _, _ = await _ctx()
    out = []
    for w in wlcs.values():
        if w.state != "up":
            continue  # unreachable controllers alert through switch_unreachable
        o = wlc_out(w, now)
        stale = o["stale_groups"] + o["failing_groups"]
        if stale:
            out.append(_det(f"{w.id}", "wireless_stale_metrics", f"controller {w.name}: no successful collection for {', '.join(stale)} in 3 intervals",
                            first=now, last=now, count=len(stale), sites=[w.site], evidence={"wlc_id": w.id, "groups": stale}))
    return out


RULES = {d["key"]: globals()[f"rule_{d['key']}"] for d in DEFAULT_RULES}
