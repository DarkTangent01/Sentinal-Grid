"""Seasonal anomaly detection for NMS series (same Detection / dedupe / notification / incident pipeline as the other
NMS rules).

Baseline: the same time of the week (hour-of-week; for wireless clients the same 30-minute slot) in the previous
`weeks` weeks. Expected value = median, spread = 1.4826 × MAD (a robust standard deviation), floored by an absolute and
a relative minimum so that a very stable series does not alert on a change of one client. A point is anomalous when it
is more than `k` spreads away from the median. Nothing is reported while fewer than `min_weeks` weeks have data
(learning), and a week without a reading is left out, never counted as zero. One unusual week in the history (a
holiday) does not move a median.

Rules:
  wireless_ssid_clients_anomaly  concurrent clients on an SSID far below (or above) the usual level for this time
  wireless_ap_zero_clients       an AP that is up but has no client at a time it normally serves several
  switch_if_util_anomaly         an interface's peak utilisation far above its usual level for this hour (and above a floor)
"""
from __future__ import annotations

import statistics
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from ..db.models import SwitchInterface, WirelessAp
from ..db.pg import session_factory

TROUBLE = {
    "wireless_ssid_clients_anomaly": ["Compare with the SSID's hourly chart (WLAN / SSID → hourly clients) for when it started",
                                      "Check RADIUS / DHCP for the SSID's VLAN and the controller's WLAN state",
                                      "A drop on every SSID of a site points at the controller or the uplink, not the WLAN"],
    "wireless_ap_zero_clients": ["Check the AP's radios (Wireless → APs) and whether its WLANs are broadcast",
                                 "Check the switch port / PoE and recent channel changes", "Compare with the neighbouring APs"],
    "switch_if_util_anomaly": ["Open Flow Analytics or the interface's top talkers for the hour",
                               "Check backups / replication jobs scheduled at this time", "Compare with the same hour last week"],
}

DEFAULT_RULES = [
    {"key": "wireless_ssid_clients_anomaly", "name": "Wireless: unusual client count on an SSID", "severity": "medium", "mitre": {},
     "description": "Concurrent clients on an SSID are far below (or above) the usual level for this time of the week "
                    "(median and MAD of the same 30-minute slot in previous weeks).",
     "params": {"weeks": 6, "min_weeks": 3, "k": 4.0, "min_median": 20, "floor_abs": 5, "floor_pct": 0.15, "spikes": False}},
    {"key": "wireless_ap_zero_clients", "name": "Wireless: AP without clients at a busy time", "severity": "low", "mitre": {},
     "description": "An AP is up but has had no client in the last complete half hour, while it usually serves several at this time of the week.",
     "params": {"weeks": 6, "min_weeks": 3, "min_median": 5}},
    {"key": "switch_if_util_anomaly", "name": "Switch: unusual interface utilisation", "severity": "low", "mitre": {},
     "description": "An interface's peak utilisation in the last hour is far above its usual level for this hour of the week and above a floor.",
     "params": {"weeks": 4, "min_weeks": 3, "k": 4.0, "min_util": 60, "floor_abs": 10}},
]
AUTO_RESOLVE = {r["key"] for r in DEFAULT_RULES}


def band(history: list[float], k: float, floor_abs: float = 0.0, floor_pct: float = 0.0) -> tuple[float, float, float]:
    """(median, low, high) of a robust band around the history."""
    med = statistics.median(history)
    mad = statistics.median([abs(x - med) for x in history])
    spread = max(1.4826 * mad, floor_abs, floor_pct * abs(med))
    return med, med - k * spread, med + k * spread


def last_slot(now: datetime, settle_s: int = 600) -> datetime:
    """The newest 30-minute slot the rollup has finished (the aggregation job runs every 5 minutes)."""
    e = int(now.timestamp()) - settle_s
    return datetime.fromtimestamp(e - e % 1800 - 1800, tz=timezone.utc)


def _epochs(ts: list[datetime]) -> list[int]:
    return [int(x.timestamp()) for x in ts]


def _ts(v) -> datetime:
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(str(v).replace(" ", "T")).replace(tzinfo=timezone.utc)


async def _slot_series(ch, slots: list[datetime], dim: str) -> tuple[dict, dict]:
    """{(slot, key): clients summed over the slot's 5-minute readings} and {(slot, wlc_id): readings}."""
    rows = await ch.aquery(f"SELECT slot, {dim} AS k, arraySum((sumMapMerge(conc)).2) AS total FROM wireless_client_slots FINAL "
                           f"WHERE toUnixTimestamp(slot) IN {{s:Array(UInt32)}}{' AND ap_id != 0' if dim == 'ap_id' else ''} GROUP BY slot, k", {"s": _epochs(slots)})
    pol = await ch.aquery("SELECT slot, wlc_id, length((sumMapMerge(conc)).1) AS n FROM wireless_client_slots FINAL "
                          "WHERE toUnixTimestamp(slot) IN {s:Array(UInt32)} GROUP BY slot, wlc_id", {"s": _epochs(slots)})
    return ({(_ts(r["slot"]), r["k"]): float(r["total"]) for r in rows}, {(_ts(r["slot"]), int(r["wlc_id"])): int(r["n"]) for r in pol})


async def rule_wireless_ssid_clients_anomaly(ch, now, p):
    from ..wireless.alerts import _det
    target = last_slot(now)
    weeks = int(p.get("weeks", 6))
    slots = [target - timedelta(days=7 * w) for w in range(weeks + 1)]
    totals, polled = await _slot_series(ch, slots, "ssid")
    readings = {s: sum(n for (s2, _), n in polled.items() if s2 == s) for s in slots}
    if not readings[target]:
        return []                                          # no client table read in the slot: nothing to compare
    avg = lambda s, k: totals.get((s, k), 0.0) / readings[s]  # noqa: E731
    out = []
    for ssid in sorted({k for (_, k) in totals if k}):
        hist = [avg(s, ssid) for s in slots[1:] if readings[s]]
        if len(hist) < int(p.get("min_weeks", 3)):
            continue                                       # learning
        med, low, high = band(hist, float(p.get("k", 4.0)), float(p.get("floor_abs", 5)), float(p.get("floor_pct", 0.15)))
        cur = avg(target, ssid)
        if med >= float(p.get("min_median", 20)) and cur < low:
            way = "below"
        elif p.get("spikes") and cur > high:
            way = "above"
        else:
            continue
        out.append(_det(f"{ssid}:{way}", "wireless_ssid_clients_anomaly",
                        f"SSID {ssid}: {cur:.0f} concurrent clients at {target:%Y-%m-%d %H:%M} UTC, usually {med:.0f} at this time "
                        f"of the week (expected {max(0, low):.0f}–{high:.0f}, {len(hist)} previous weeks)",
                        first=target, last=now, evidence={"ssid": ssid, "slot": target.isoformat(), "observed": round(cur, 1),
                                                          "expected": round(med, 1), "expected_low": round(max(0.0, low), 1),
                                                          "expected_high": round(high, 1), "weeks": len(hist), "direction": way,
                                                          "troubleshooting": TROUBLE["wireless_ssid_clients_anomaly"]}))
    return out


async def rule_wireless_ap_zero_clients(ch, now, p):
    from ..wireless.alerts import _det
    target = last_slot(now)
    weeks = int(p.get("weeks", 6))
    slots = [target - timedelta(days=7 * w) for w in range(weeks + 1)]
    async with session_factory()() as s:
        aps = (await s.execute(select(WirelessAp).where(WirelessAp.present.is_(True), WirelessAp.state == "up"))).scalars().all()
    if not aps:
        return []
    totals, polled = await _slot_series(ch, slots, "ap_id")
    out = []
    for a in aps:
        if not polled.get((target, a.wlc_id)) or totals.get((target, a.id), 0.0) > 0:
            continue
        hist = [totals.get((s, a.id), 0.0) / polled[(s, a.wlc_id)] for s in slots[1:] if polled.get((s, a.wlc_id))]
        if len(hist) < int(p.get("min_weeks", 3)):
            continue
        med = statistics.median(hist)
        if med < float(p.get("min_median", 5)):
            continue
        out.append(_det(f"{a.id}:zero", "wireless_ap_zero_clients",
                        f"AP {a.name} is up but had no client at {target:%Y-%m-%d %H:%M} UTC; it usually serves {med:.0f} at this time of the week",
                        first=target, last=now, sites=[a.site], evidence={"ap_id": a.id, "ap": a.name, "slot": target.isoformat(), "observed": 0,
                                                                          "expected": round(med, 1), "weeks": len(hist),
                                                                          "troubleshooting": TROUBLE["wireless_ap_zero_clients"]}))
    return out


async def rule_switch_if_util_anomaly(ch, now, p):
    from ..switches.alerts import _context, _det
    target = datetime.fromtimestamp(int(now.timestamp()) // 3600 * 3600 - 3600, tz=timezone.utc)
    weeks = int(p.get("weeks", 4))
    hours = [target - timedelta(days=7 * w) for w in range(weeks + 1)]
    rows = await ch.aquery("SELECT hour, switch_id, ifindex, greatest(max(rx_util_max), max(tx_util_max)) AS u FROM switch_if_hourly "
                           "WHERE toUnixTimestamp(hour) IN {h:Array(UInt32)} GROUP BY hour, switch_id, ifindex", {"h": _epochs(hours)})
    series: dict[tuple, dict] = {}
    for r in rows:
        series.setdefault((int(r["switch_id"]), int(r["ifindex"])), {})[_ts(r["hour"])] = float(r["u"])
    cand = []
    for key, vals in series.items():
        cur = vals.get(target)
        if cur is None or cur < float(p.get("min_util", 60)):
            continue
        hist = [vals[h] for h in hours[1:] if h in vals]
        if len(hist) < int(p.get("min_weeks", 3)):
            continue
        med, _, high = band(hist, float(p.get("k", 4.0)), float(p.get("floor_abs", 10)))
        if cur > high:
            cand.append((key, cur, med, high, len(hist)))
    if not cand:
        return []
    sws, bs = await _context()
    by = {x.id: x for x in sws}
    async with session_factory()() as s:
        names = {(r.switch_id, r.ifindex): r.name for r in (await s.execute(select(SwitchInterface).where(
            SwitchInterface.switch_id.in_({k[0] for k, *_ in cand})))).scalars()}
    out = []
    for (sid, ix), cur, med, high, n in cand:
        sw = by.get(sid)
        if sw is None:
            continue
        port = names.get((sid, ix), f"ifIndex {ix}")
        out.append(_det(sw, bs, f"{sid}:{ix}:util_anomaly", "switch_if_util_anomaly",
                        f"{sw.name} {port}: peak utilisation {cur:.0f}% in the hour from {target:%Y-%m-%d %H:00} UTC, usually {med:.0f}% "
                        f"at this hour of the week (expected up to {high:.0f}%, {n} previous weeks)",
                        first=target, last=now, component=port, metric="if_util_max_pct", value=round(cur, 1), threshold=round(high, 1),
                        extra={"ifindex": ix, "expected": round(med, 1), "weeks": n}))
    return out


RULES = {d["key"]: globals()[f"rule_{d['key']}"] for d in DEFAULT_RULES}

