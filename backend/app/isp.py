"""ISP / WAN link analytics from FortiGate SD-WAN health-check logs.

Sources (event logs, subtype sdwan):
    0113022925  Health Check SLA status (periodic): interface, healthcheck, status, latency, jitter, packetloss,
                mosvalue, in/out bandwidth used/available
    0113022931  health-check member changed state, newvalue="dead"
    0113022933  newvalue="alive" (recovery) — the same id is also used for "SLA failed ... [metric]" notifications
    0113022923  member unreachable / service redirect: carries the member's gateway IP

A link is a (firewall, interface). It is DOWN only while every health check that monitors it is dead at the same
time (or every check in its configured `outage_checks`): one failing target (e.g. a SaaS endpoint) is a partial
reachability problem, not a provider outage. Read-only: nothing here talks to a firewall except discovery, which
issues GET requests only.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .db.models import Firewall, IspLink

log = logging.getLogger("isp")
SLA_INFO, DEAD, ALIVE, MEMBER = "0113022925", "0113022931", "0113022933", "0113022923"
LOOKBACK = timedelta(days=7)          # how far back to look for the state a check was in at the window start
STALE = timedelta(hours=6)            # a check silent this long while "dead" is not trusted to still be dead
BASE = "category = 'system' AND event_subtype = 'sdwan'"


def _kv(name: str) -> str:
    return f"extract(raw, '{name}=\"([^\"]*)\"')"


IFACE, HC = _kv("interface"), _kv("healthcheck")


def _bw(expr: str) -> str:
    """'38.84Mbps' → bits per second."""
    num = f"toFloat64OrZero(extract({expr}, '^([0-9.]+)'))"
    unit = f"lower(extract({expr}, '([A-Za-z]+)$'))"
    return f"({num} * multiIf({unit} = 'gbps', 1e9, {unit} = 'mbps', 1e6, {unit} = 'kbps', 1e3, 1))"


def _aware(v) -> datetime:
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(str(v).replace("Z", "")).replace(tzinfo=timezone.utc)


# ------------------------------------------------------------------ interval maths
Interval = tuple[datetime, datetime]


def merge(iv: list[Interval]) -> list[Interval]:
    out: list[Interval] = []
    for a, b in sorted(iv):
        if out and a <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], b))
        else:
            out.append((a, b))
    return out


def intersect(a: list[Interval], b: list[Interval]) -> list[Interval]:
    i = j = 0
    out = []
    while i < len(a) and j < len(b):
        s, e = max(a[i][0], b[j][0]), min(a[i][1], b[j][1])
        if s < e:
            out.append((s, e))
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return out


def subtract(a: list[Interval], b: list[Interval]) -> list[Interval]:
    out = []
    for s, e in a:
        cur = s
        for bs, be in b:
            if be <= cur or bs >= e:
                continue
            if bs > cur:
                out.append((cur, bs))
            cur = max(cur, be)
        if cur < e:
            out.append((cur, e))
    return out


def clip(iv: list[Interval], t0: datetime, t1: datetime) -> list[Interval]:
    return [(max(a, t0), min(b, t1)) for a, b in iv if b > t0 and a < t1]


def down_intervals(transitions: list[tuple[datetime, str]], initial_dead: bool, t0: datetime, t1: datetime,
                   last_seen: datetime | None = None) -> list[Interval]:
    """dead/alive transitions (sorted) → down intervals within [t0, t1]. An open interval ends at t1, unless the check
    has been silent for STALE (check removed or logging stopped), in which case it ends at its last sign of life."""
    out, start = [], (t0 if initial_dead else None)
    for ts, st in transitions:
        if ts < t0:
            continue
        if ts > t1:
            break
        if st == "dead" and start is None:
            start = ts
        elif st == "alive" and start is not None:
            out.append((start, ts))
            start = None
    if start is not None:
        end = t1
        if last_seen and t1 - last_seen > STALE:
            end = max(start, min(t1, last_seen + STALE))
        out.append((start, end))
    return [x for x in out if x[1] > x[0]]


# ------------------------------------------------------------------ data access
@dataclass
class LinkData:
    firewall_id: int
    firewall_name: str
    interface: str
    checks: set[str] = field(default_factory=set)
    transitions: dict[str, list] = field(default_factory=lambda: defaultdict(list))
    initial: dict[str, bool] = field(default_factory=dict)
    last_seen: dict[str, datetime] = field(default_factory=dict)
    perf: dict = field(default_factory=dict)
    breaches: dict[str, int] = field(default_factory=dict)
    gateway: str = ""
    last_sample: datetime | None = None


def _fw_clause(fw_ids: list[int] | None, p: dict) -> str:
    if not fw_ids:
        return ""
    p["fws"] = [int(x) for x in fw_ids]
    return " AND firewall_id IN {fws:Array(UInt32)}"


async def load(ch, t0: datetime, t1: datetime, fw_ids: list[int] | None = None) -> dict[tuple[int, str], LinkData]:
    p = {"t0": t0, "t1": t1, "lb": t0 - LOOKBACK}
    fw = _fw_clause(fw_ids, p)
    links: dict[tuple[int, str], LinkData] = {}

    def link(fid, fname, iface) -> LinkData:
        k = (int(fid), iface)
        if k not in links:
            links[k] = LinkData(int(fid), fname, iface)
        return links[k]

    # state changes inside the window, plus the last state of every check before it
    state_sql = (f"SELECT firewall_id, any(firewall_name) AS fname, {IFACE} AS iface, {HC} AS hc, event_time AS ts, "
                 f"{_kv('newvalue')} AS nv FROM events WHERE {BASE} AND log_id IN ('{DEAD}', '{ALIVE}') "
                 f"AND event_time >= {{t0:DateTime64(3)}} AND event_time < {{t1:DateTime64(3)}}{fw} "
                 f"AND nv IN ('dead', 'alive') AND iface != '' GROUP BY firewall_id, iface, hc, ts, nv ORDER BY ts")
    for r in await ch.aquery(state_sql, p):
        lk = link(r["firewall_id"], r["fname"], r["iface"])
        lk.checks.add(r["hc"])
        lk.transitions[r["hc"]].append((_aware(r["ts"]), r["nv"]))
    before = (f"SELECT firewall_id, any(firewall_name) AS fname, {IFACE} AS iface, {HC} AS hc, "
              f"argMax({_kv('newvalue')}, event_time) AS st, max(event_time) AS at FROM events WHERE {BASE} "
              f"AND log_id IN ('{DEAD}', '{ALIVE}') AND {_kv('newvalue')} IN ('dead', 'alive') "
              f"AND event_time >= {{lb:DateTime64(3)}} AND event_time < {{t0:DateTime64(3)}}{fw} AND iface != '' "
              f"GROUP BY firewall_id, iface, hc")
    for r in await ch.aquery(before, p):
        lk = link(r["firewall_id"], r["fname"], r["iface"])
        lk.checks.add(r["hc"])
        lk.initial[r["hc"]] = r["st"] == "dead" and t0 - _aware(r["at"]) < STALE * 4
    # periodic SLA samples: performance, and the last time each check reported (status up closes stale "dead")
    perf = (f"SELECT firewall_id, any(firewall_name) AS fname, {IFACE} AS iface, {HC} AS hc, count() AS n, "
            f"max(event_time) AS last, maxIf(event_time, {_kv('status')} = 'up') AS last_up, "
            f"avg(toFloat64OrNull({_kv('latency')})) AS lat, quantile(0.95)(toFloat64OrNull({_kv('latency')})) AS lat95, "
            f"avg(toFloat64OrNull({_kv('jitter')})) AS jit, avg(toFloat64OrNull({_kv('packetloss')})) AS loss, "
            f"max(toFloat64OrNull({_kv('packetloss')})) AS loss_max, avg(toFloat64OrNull({_kv('mosvalue')})) AS mos, "
            f"max({_bw(_kv('inbandwidthused'))}) AS in_peak, avg({_bw(_kv('inbandwidthused'))}) AS in_avg, "
            f"max({_bw(_kv('outbandwidthused'))}) AS out_peak, avg({_bw(_kv('outbandwidthused'))}) AS out_avg "
            f"FROM events WHERE {BASE} AND log_id = '{SLA_INFO}' AND event_time >= {{t0:DateTime64(3)}} "
            f"AND event_time < {{t1:DateTime64(3)}}{fw} AND iface != '' GROUP BY firewall_id, iface, hc")
    for r in await ch.aquery(perf, p):
        lk = link(r["firewall_id"], r["fname"], r["iface"])
        lk.checks.add(r["hc"])
        last = _aware(r["last"])
        lk.last_seen[r["hc"]] = max(lk.last_seen.get(r["hc"], last), last)
        lk.last_sample = max(lk.last_sample or last, last)
        # an "up" sample after the last dead transition closes an open down interval
        if r["last_up"] and _aware(r["last_up"]).year > 1971:
            tr = lk.transitions[r["hc"]]
            up = _aware(r["last_up"])
            if (tr and tr[-1][1] == "dead" and up > tr[-1][0]) or (not tr and lk.initial.get(r["hc"])):
                tr.append((up, "alive"))
        lk.perf[r["hc"]] = {k: r[k] for k in ("n", "lat", "lat95", "jit", "loss", "loss_max", "mos", "in_peak", "in_avg", "out_peak", "out_avg")}
    for r in await ch.aquery(
            f"SELECT firewall_id, {IFACE} AS iface, {HC} AS hc, max(event_time) AS last FROM events WHERE {BASE} "
            f"AND log_id IN ('{DEAD}', '{ALIVE}') AND event_time >= {{lb:DateTime64(3)}} AND event_time < {{t1:DateTime64(3)}}{fw} "
            f"AND iface != '' GROUP BY firewall_id, iface, hc", p):
        lk = links.get((int(r["firewall_id"]), r["iface"]))
        if lk:
            last = _aware(r["last"])
            lk.last_seen[r["hc"]] = max(lk.last_seen.get(r["hc"], last), last)
    # SLA threshold breaches by metric, and the member gateway
    for r in await ch.aquery(
            f"SELECT firewall_id, {IFACE} AS iface, {_kv('metric')} AS m, count() AS n FROM events WHERE {BASE} "
            f"AND log_id = '{ALIVE}' AND m != '' AND event_time >= {{t0:DateTime64(3)}} AND event_time < {{t1:DateTime64(3)}}{fw} "
            f"GROUP BY firewall_id, iface, m", p):
        lk = links.get((int(r["firewall_id"]), r["iface"]))
        if lk:
            lk.breaches[r["m"]] = lk.breaches.get(r["m"], 0) + int(r["n"])
    for r in await ch.aquery(
            f"SELECT firewall_id, {IFACE} AS iface, argMax(extract(raw, 'gateway=([0-9a-fA-F.:]+)'), event_time) AS gw FROM events "
            f"WHERE {BASE} AND log_id = '{MEMBER}' AND position(raw, 'gateway=') > 0 AND event_time >= {{lb:DateTime64(3)}} "
            f"AND event_time < {{t1:DateTime64(3)}}{fw} GROUP BY firewall_id, iface", p):
        lk = links.get((int(r["firewall_id"]), r["iface"]))
        if lk:
            lk.gateway = r["gw"]
    return links


# ------------------------------------------------------------------ analysis
def analyze_link(lk: LinkData, cfg: IspLink | None, t0: datetime, t1: datetime, min_outage: int = 60) -> dict:
    wanted = [c for c in (cfg.outage_checks if cfg and cfg.outage_checks else []) if c in lk.checks] or sorted(lk.checks)
    per_check = {hc: down_intervals(lk.transitions.get(hc, []), lk.initial.get(hc, False), t0, t1, lk.last_seen.get(hc))
                 for hc in lk.checks}
    full = None
    for hc in wanted:
        iv = per_check.get(hc, [])
        full = iv if full is None else intersect(full, iv)
    full = merge(full or [])
    any_down = merge([x for iv in per_check.values() for x in iv])
    partial = subtract(any_down, full)
    span = (t1 - t0).total_seconds()
    downtime = sum((b - a).total_seconds() for a, b in full)
    outages = [(a, b) for a, b in full if (b - a).total_seconds() >= min_outage]
    blips = len(full) - len(outages)
    durs = [(b - a).total_seconds() for a, b in outages]
    now_down = bool(full and full[-1][1] >= t1 - timedelta(seconds=1))
    now_partial = bool(partial and partial[-1][1] >= t1 - timedelta(seconds=1))
    up_total = span - downtime
    perf = list(lk.perf.values())
    wsum = sum(x["n"] for x in perf) or 1

    def wavg(k):
        vals = [(x[k], x["n"]) for x in perf if x.get(k) is not None]
        return round(sum(v * n for v, n in vals) / sum(n for _, n in vals), 3) if vals else None

    def wmax(k):
        vals = [x[k] for x in perf if x.get(k) is not None]
        return max(vals) if vals else None
    failing = sorted(((hc, sum((b - a).total_seconds() for a, b in iv), len(iv)) for hc, iv in per_check.items() if iv),
                     key=lambda x: -x[1])
    target = cfg.target_availability if cfg else 99.5
    availability = round(100 * up_total / span, 4) if span else None
    status = "down" if now_down else "degraded" if now_partial else (
        "no_data" if not lk.last_sample or t1 - lk.last_sample > timedelta(minutes=30) else "up")
    return {
        "key": f"{lk.firewall_id}:{lk.interface}", "firewall_id": lk.firewall_id, "firewall_name": lk.firewall_name,
        "interface": lk.interface, "status": status, "checks": sorted(lk.checks), "outage_checks": wanted,
        "availability": availability, "target_availability": target, "sla_met": availability is None or availability >= target,
        "outages": len(outages), "blips": blips, "downtime_s": round(downtime), "longest_s": round(max(durs)) if durs else 0,
        "mttr_s": round(sum(durs) / len(durs)) if durs else 0,
        "mtbf_s": round(up_total / len(outages)) if outages else None,
        "last_outage": outages[-1][0].isoformat() if outages else None,
        "partial_events": len(partial), "partial_s": round(sum((b - a).total_seconds() for a, b in partial)),
        "flaps": sum(1 for tr in lk.transitions.values() for _, st in tr if st == "dead"),
        "failing_checks": [{"check": hc, "down_s": round(s), "events": n} for hc, s, n in failing[:10]],
        "sla_breaches": dict(lk.breaches), "sla_breach_total": sum(lk.breaches.values()),
        "latency_ms": wavg("lat"), "latency_p95_ms": wmax("lat95"), "jitter_ms": wavg("jit"), "packet_loss_pct": wavg("loss"),
        "packet_loss_max_pct": wmax("loss_max"), "mos": wavg("mos"), "samples": int(wsum) if perf else 0,
        "bw_in_peak_bps": wmax("in_peak"), "bw_out_peak_bps": wmax("out_peak"), "bw_in_avg_bps": wavg("in_avg"), "bw_out_avg_bps": wavg("out_avg"),
        "gateway": lk.gateway, "_full": full, "_partial": partial, "_outages": outages,
    }


def daily(intervals: list[Interval], t0: datetime, t1: datetime) -> list[dict]:
    """Per-UTC-day downtime and availability across [t0, t1]."""
    out = []
    d = t0.replace(hour=0, minute=0, second=0, microsecond=0)
    while d < t1:
        a, b = max(d, t0), min(d + timedelta(days=1), t1)
        down = sum((y - x).total_seconds() for x, y in clip(intervals, a, b))
        span = (b - a).total_seconds()
        out.append({"day": d.date().isoformat(), "downtime_s": round(down), "availability": round(100 * (span - down) / span, 3) if span else None,
                    "outages": sum(1 for x, _ in intervals if a <= x < b)})
        d += timedelta(days=1)
    return out


def display_name(cfg: IspLink | None, lk_iface: str) -> str:
    if cfg:
        return cfg.isp_name or cfg.as_org or cfg.alias or cfg.description or lk_iface
    return lk_iface


async def configs(s: AsyncSession) -> dict[tuple[int, str], IspLink]:
    return {(c.firewall_id, c.interface): c for c in (await s.execute(select(IspLink))).scalars()}


async def ensure_links(s: AsyncSession, links: dict[tuple[int, str], LinkData], cfgs: dict[tuple[int, str], IspLink]) -> None:
    """Register newly seen links (so they can be named) and remember their gateway."""
    changed = False
    for (fid, iface), lk in links.items():
        c = cfgs.get((fid, iface))
        if c is None:
            c = IspLink(firewall_id=fid, interface=iface, gateway=lk.gateway or "")
            s.add(c)
            cfgs[(fid, iface)] = c
            changed = True
        elif lk.gateway and c.gateway != lk.gateway:
            c.gateway = lk.gateway
            changed = True
        if c.gateway and not c.as_org:
            org = _asn_org(c.gateway)
            if org:
                c.as_org = org
                changed = True
    if changed:
        try:
            await s.commit()
        except Exception:  # concurrent registration from another request
            await s.rollback()


_geo = None


def _asn_org(ip: str) -> str:
    """Provider name for a gateway address from the GeoIP ASN database (empty when no database is installed)."""
    global _geo
    if _geo is None:
        from .config import get_settings
        from .enrich.geo import GeoResolver
        _geo = GeoResolver(get_settings().geoip_dir)
    return _geo.lookup(ip).get("as_org", "") if _geo.available else ""


async def report(ch, s: AsyncSession, t0: datetime, t1: datetime, fw_ids: list[int] | None = None, min_outage: int = 60,
                 include_hidden: bool = False) -> dict:
    links = await load(ch, t0, t1, fw_ids)
    cfgs = await configs(s)
    await ensure_links(s, links, cfgs)
    rows = []
    for k, lk in links.items():
        c = cfgs.get(k)
        if c and c.hidden and not include_hidden:
            continue
        r = analyze_link(lk, c, t0, t1, min_outage)
        r.update({"isp_name": display_name(c, lk.interface), "named": bool(c and c.isp_name), "circuit_id": c.circuit_id if c else "",
                  "bandwidth_mbps": c.bandwidth_mbps if c else None, "alias": c.alias if c else "", "description": c.description if c else "",
                  "as_org": c.as_org if c else "", "hidden": bool(c and c.hidden), "notes": c.notes if c else "", "id": c.id if c else None,
                  "support_contact": c.support_contact if c else "",
                  "daily": daily(r["_full"], t0, t1)})
        if r["bandwidth_mbps"] and r["bw_in_peak_bps"]:
            r["utilisation_peak_pct"] = round(100 * max(r["bw_in_peak_bps"] or 0, r["bw_out_peak_bps"] or 0) / (r["bandwidth_mbps"] * 1e6), 1)
        rows.append(r)
    rows.sort(key=lambda r: (r["status"] != "down", r["availability"] if r["availability"] is not None else 101, r["firewall_name"], r["interface"]))
    # roll links up to providers; a provider is down only while all of its links are down
    by_isp: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_isp[r["isp_name"]].append(r)
    span = (t1 - t0).total_seconds()
    isps = []
    for name, rs in by_isp.items():
        down = sum(r["downtime_s"] for r in rs)
        outs = sum(r["outages"] for r in rs)
        durs = [(b - a).total_seconds() for r in rs for a, b in r["_outages"]]
        avail = round(100 * (1 - down / (span * len(rs))), 4) if span else None
        target = min(r["target_availability"] for r in rs)
        lat = [r["latency_ms"] for r in rs if r["latency_ms"] is not None]
        isps.append({"isp_name": name, "links": len(rs), "sites": sorted({r["firewall_name"] for r in rs}),
                     "availability": avail, "target_availability": target, "sla_met": avail is None or avail >= target,
                     "outages": outs, "blips": sum(r["blips"] for r in rs), "downtime_s": round(down),
                     "longest_s": round(max(durs)) if durs else 0, "mttr_s": round(sum(durs) / len(durs)) if durs else 0,
                     "latency_ms": round(sum(lat) / len(lat), 2) if lat else None,
                     "jitter_ms": _avg([r["jitter_ms"] for r in rs]), "packet_loss_pct": _avg([r["packet_loss_pct"] for r in rs]),
                     "sla_breach_total": sum(r["sla_breach_total"] for r in rs), "partial_events": sum(r["partial_events"] for r in rs),
                     "down_now": sum(1 for r in rs if r["status"] == "down")})
    isps.sort(key=lambda x: (x["availability"] if x["availability"] is not None else 101))
    timeline = [{"key": r["key"], "isp_name": r["isp_name"], "firewall_id": r["firewall_id"], "firewall_name": r["firewall_name"], "interface": r["interface"],
                 "start": a.isoformat(), "end": b.isoformat(), "duration_s": round((b - a).total_seconds()), "type": "outage"}
                for r in rows for a, b in r["_full"] if (b - a).total_seconds() >= min_outage]
    for r in rows:
        for k in ("_full", "_partial", "_outages"):
            r.pop(k, None)
    return {"window": {"start": t0.isoformat(), "end": t1.isoformat()}, "links": rows, "isps": isps,
            "timeline": sorted(timeline, key=lambda x: x["start"]),
            "totals": {"links": len(rows), "down_now": sum(1 for r in rows if r["status"] == "down"),
                       "degraded_now": sum(1 for r in rows if r["status"] == "degraded"), "outages": sum(r["outages"] for r in rows),
                       "downtime_s": sum(r["downtime_s"] for r in rows),
                       "availability": round(sum(r["availability"] or 0 for r in rows) / len(rows), 4) if rows else None}}


def _avg(v):
    v = [x for x in v if x is not None]
    return round(sum(v) / len(v), 3) if v else None


async def link_detail(ch, s: AsyncSession, fw_id: int, iface: str, t0: datetime, t1: datetime, min_outage: int = 60,
                      bucket: int = 300) -> dict:
    links = await load(ch, t0, t1, [fw_id])
    lk = links.get((fw_id, iface))
    cfgs = await configs(s)
    if lk is None:
        return {"found": False}
    c = cfgs.get((fw_id, iface))
    r = analyze_link(lk, c, t0, t1, min_outage)
    per_check = {hc: down_intervals(lk.transitions.get(hc, []), lk.initial.get(hc, False), t0, t1, lk.last_seen.get(hc)) for hc in lk.checks}
    events = [{"start": a.isoformat(), "end": b.isoformat(), "duration_s": round((b - a).total_seconds()), "type": "outage",
               "checks": r["outage_checks"], "ongoing": b >= t1 - timedelta(seconds=1)} for a, b in r["_full"]]
    for a, b in r["_partial"]:
        hit = sorted(hc for hc, iv in per_check.items() if clip(iv, a, b))
        events.append({"start": a.isoformat(), "end": b.isoformat(), "duration_s": round((b - a).total_seconds()), "type": "partial",
                       "checks": hit, "ongoing": b >= t1 - timedelta(seconds=1)})
    events.sort(key=lambda e: e["start"], reverse=True)
    p = {"t0": t0, "t1": t1, "fw": fw_id, "iface": iface}
    ts = await ch.aquery(
        f"SELECT toStartOfInterval(event_time, INTERVAL {int(bucket)} SECOND) AS t, avg(toFloat64OrNull({_kv('latency')})) AS latency, "
        f"max(toFloat64OrNull({_kv('latency')})) AS latency_max, avg(toFloat64OrNull({_kv('jitter')})) AS jitter, "
        f"avg(toFloat64OrNull({_kv('packetloss')})) AS loss, avg(toFloat64OrNull({_kv('mosvalue')})) AS mos, "
        f"max({_bw(_kv('inbandwidthused'))}) AS bw_in, max({_bw(_kv('outbandwidthused'))}) AS bw_out "
        f"FROM events WHERE {BASE} AND log_id = '{SLA_INFO}' AND firewall_id = {{fw:UInt32}} AND {IFACE} = {{iface:String}} "
        f"AND event_time >= {{t0:DateTime64(3)}} AND event_time < {{t1:DateTime64(3)}} GROUP BY t ORDER BY t", p)
    for row in ts:
        row["t"] = _aware(row["t"]).isoformat()
        for k, v in list(row.items()):
            if isinstance(v, float) and v != v:
                row[k] = None
    by_check = [{"check": hc, **{k: (round(v, 3) if isinstance(v, float) else v) for k, v in lk.perf.get(hc, {}).items()},
                 "down_s": round(sum((b - a).total_seconds() for a, b in per_check.get(hc, []))),
                 "down_events": len(per_check.get(hc, []))} for hc in sorted(lk.checks)]
    for k in ("_full", "_partial", "_outages"):
        r.pop(k, None)
    r.update({"isp_name": display_name(c, iface), "circuit_id": c.circuit_id if c else "", "bandwidth_mbps": c.bandwidth_mbps if c else None,
              "as_org": c.as_org if c else "", "alias": c.alias if c else "", "description": c.description if c else ""})
    return {"found": True, "link": r, "events": events[:500], "timeseries": ts, "bucket_seconds": bucket, "checks": by_check,
            "daily": daily([(datetime.fromisoformat(e["start"]), datetime.fromisoformat(e["end"])) for e in events if e["type"] == "outage"], t0, t1)}


# ------------------------------------------------------------------ discovery (GET only)
async def discover(s: AsyncSession) -> dict:
    """Read interface alias/description and SD-WAN member gateways from each firewall (read-only GET)."""
    from .fortigate.service import build_client
    out = {}
    fws = (await s.execute(select(Firewall).where(Firewall.enabled.is_(True), Firewall.is_demo.is_(False), Firewall.vendor == "fortinet",
                                                  Firewall.token_ciphertext.is_not(None)))).scalars().all()
    cfgs = await configs(s)
    for fw in fws:
        try:
            async with build_client(fw) as c:
                sd = await c.get("/api/v2/cmdb/system/sdwan")
                res = sd.get("results") or {}
                members = res.get("members") or []
                ifaces = {m.get("interface") for m in members if m.get("interface")}
                intf = {}
                for name in ifaces:
                    try:
                        r = await c.get(f"/api/v2/cmdb/system/interface/{name}", vdom=False)
                        x = (r.get("results") or [{}])[0]
                        intf[name] = (x.get("alias") or "", x.get("description") or "")
                    except Exception:
                        intf[name] = ("", "")
            for m in members:
                iface = m.get("interface")
                if not iface:
                    continue
                cfg = cfgs.get((fw.id, iface))
                if cfg is None:
                    cfg = IspLink(firewall_id=fw.id, interface=iface)
                    s.add(cfg)
                    cfgs[(fw.id, iface)] = cfg
                gw = m.get("gateway") or ""
                if gw and gw not in ("0.0.0.0", "::"):
                    cfg.gateway = gw
                    cfg.as_org = cfg.as_org or _asn_org(gw)
                alias, desc = intf.get(iface, ("", ""))
                cfg.alias = alias or cfg.alias
                cfg.description = (desc or m.get("comment") or cfg.description or "")[:255]
                cfg.discovered_at = datetime.now(timezone.utc)
            out[fw.name] = f"{len(members)} SD-WAN member(s)"
        except Exception as e:  # missing permission, SD-WAN disabled, unreachable: logs still drive the analysis
            out[fw.name] = f"skipped: {str(e)[:120]}"
    await s.commit()
    return out
