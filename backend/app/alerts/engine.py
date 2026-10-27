"""Alert evaluation: windowed ClickHouse aggregations -> grouped, deduplicated alerts in PostgreSQL.

Each detection is an indicator that requires investigation, not proof of malicious activity.
"""
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..analytics.filters import table
from ..db.ch import ClickHouse
from ..db.models import Alert, AlertRule, Suppression
from .rules import DEFAULT_RULES, RULE_MITRE

log = logging.getLogger("alerts")
DENIED = "('deny','block')"


@dataclass
class Detection:
    group_key: str
    count: int
    first_seen: datetime
    last_seen: datetime
    explanation: str
    src_ip: str | None = None
    dst_ip: str | None = None
    firewall_ids: list[int] = field(default_factory=list)
    sites: list[str] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)
    event_filter: dict = field(default_factory=dict)
    severity: str | None = None  # overrides the rule default (e.g. by threat-intel category)


def _dt(v) -> datetime:
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(str(v).replace("Z", "")).replace(tzinfo=timezone.utc)


def _window(params: dict, now: datetime) -> tuple[datetime, datetime]:
    return now - timedelta(minutes=int(params.get("window_minutes", 10))), now


COMMON = "min(event_time) AS first_seen, max(event_time) AS last_seen, groupUniqArray(10)(firewall_id) AS fws, groupUniqArray(10)(site) AS sites"


async def _src_rule(ch, now, params, category, metric_sql, having_sql, threshold_key, extra_where="", explain=None,
                    filt=None):
    t0, t1 = _window(params, now)
    sql = f"""SELECT src_ip, {metric_sql} AS metric, count() AS events, {COMMON}
              FROM {table()} WHERE category = '{category}' AND event_time >= {{t0:DateTime64(3)}} AND event_time < {{t1:DateTime64(3)}}
              AND src_ip != '' {extra_where}
              GROUP BY src_ip HAVING {having_sql} >= {{th:Float64}} ORDER BY metric DESC LIMIT 200"""
    rows = await ch.aquery(sql, {"t0": t0, "t1": t1, "th": float(params[threshold_key]), **(params.get("_extra") or {})})
    out = []
    for r in rows:
        out.append(Detection(
            group_key=r["src_ip"], count=int(r["events"]), first_seen=_dt(r["first_seen"]), last_seen=_dt(r["last_seen"]),
            src_ip=r["src_ip"], firewall_ids=[int(x) for x in r["fws"]], sites=[s for s in r["sites"] if s],
            explanation=explain(r, params), evidence={"metric": r["metric"], "window_start": t0.isoformat(), "window_end": t1.isoformat()},
            event_filter={"src_ip": r["src_ip"], "category": [category], **(filt or {})},
        ))
    return out


async def rule_port_scan(ch, now, p):
    return await _src_rule(ch, now, p, "traffic", "uniqExact(dst_port)", "metric", "min_unique_ports",
                           explain=lambda r, p: f"{r['src_ip']} contacted {r['metric']} distinct destination ports in {p['window_minutes']} min (threshold {p['min_unique_ports']}).")


async def rule_denied_burst(ch, now, p):
    return await _src_rule(ch, now, p, "traffic", f"countIf(action IN {DENIED})", "metric", "min_denied",
                           explain=lambda r, p: f"{r['src_ip']} had {r['metric']} denied traffic events in {p['window_minutes']} min (threshold {p['min_denied']}).",
                           filt={"verdict": "denied"})


async def rule_host_sweep(ch, now, p):
    return await _src_rule(ch, now, p, "traffic", "uniqExact(dst_ip)", "metric", "min_unique_dsts",
                           explain=lambda r, p: f"{r['src_ip']} contacted {r['metric']} distinct destination IPs in {p['window_minutes']} min (threshold {p['min_unique_dsts']}).")


async def rule_outbound_volume(ch, now, p):
    p = {**p, "_extra": {"cidrs": p["internal_cidrs"]}}
    extra = ("AND (isIPv4String(dst_ip) OR isIPv6String(dst_ip)) "
             "AND arrayExists(c -> isIPAddressInRange(if(isIPv4String(src_ip) OR isIPv6String(src_ip), src_ip, '::'), c), {cidrs:Array(String)}) "
             "AND NOT arrayExists(c -> isIPAddressInRange(if(isIPv4String(dst_ip) OR isIPv6String(dst_ip), dst_ip, '::'), c), {cidrs:Array(String)})")
    return await _src_rule(ch, now, p, "traffic", "sum(sent_bytes)", "metric", "min_sent_bytes", extra_where=extra,
                           explain=lambda r, p: f"{r['src_ip']} sent {int(r['metric']):,} bytes to external destinations in {p['window_minutes']} min (threshold {int(p['min_sent_bytes']):,}).")


async def rule_nxdomain(ch, now, p):
    return await _src_rule(ch, now, p, "dns", "countIf(dns_rcode='NXDOMAIN')", "metric", "min_nxdomain",
                           explain=lambda r, p: f"{r['src_ip']} received {r['metric']} NXDOMAIN responses in {p['window_minutes']} min (threshold {p['min_nxdomain']}).",
                           filt={"dns_rcode": "NXDOMAIN"})


async def rule_dns_spike(ch, now, p):
    t0, t1 = _window(p, now)
    b0 = t0 - timedelta(hours=int(p["baseline_hours"]))
    win = int(p["window_minutes"])
    buckets = max(1.0, int(p["baseline_hours"]) * 60 / win)
    sql = f"""
    WITH cur AS (SELECT src_ip, count() AS c, {COMMON} FROM {table()} WHERE category='dns' AND src_ip != ''
                 AND event_time >= {{t0:DateTime64(3)}} AND event_time < {{t1:DateTime64(3)}} GROUP BY src_ip),
         base AS (SELECT src_ip, count() / {{nb:Float64}} AS avg_c FROM {table()} WHERE category='dns' AND src_ip != ''
                  AND event_time >= {{b0:DateTime64(3)}} AND event_time < {{t0:DateTime64(3)}} GROUP BY src_ip)
    SELECT cur.src_ip AS src_ip, cur.c AS c, base.avg_c AS avg_c, cur.first_seen AS first_seen, cur.last_seen AS last_seen,
           cur.fws AS fws, cur.sites AS sites
    FROM cur LEFT JOIN base ON cur.src_ip = base.src_ip
    WHERE cur.c >= {{mq:Float64}} AND cur.c >= {{fac:Float64}} * greatest(base.avg_c, 1)
    ORDER BY c DESC LIMIT 100"""
    rows = await ch.aquery(sql, {"t0": t0, "t1": t1, "b0": b0, "nb": buckets, "mq": float(p["min_queries"]), "fac": float(p["factor"])})
    return [Detection(group_key=r["src_ip"], count=int(r["c"]), first_seen=_dt(r["first_seen"]), last_seen=_dt(r["last_seen"]),
                      src_ip=r["src_ip"], firewall_ids=[int(x) for x in r["fws"]], sites=[s for s in r["sites"] if s],
                      explanation=f"{r['src_ip']} made {r['c']} DNS queries in {win} min vs a baseline average of {float(r['avg_c'] or 0):.1f} per {win} min (factor {p['factor']}).",
                      evidence={"current": r["c"], "baseline_avg": r["avg_c"]}, event_filter={"src_ip": r["src_ip"], "category": ["dns"]})
            for r in rows]


async def rule_new_domain(ch, now, p):
    t0, t1 = _window(p, now)
    earliest = await ch.aquery(f"SELECT min(event_time) AS m, count() AS n FROM {table()} WHERE category='dns'")
    if not earliest or not int(earliest[0]["n"]):
        return []
    if _dt(earliest[0]["m"]) > now - timedelta(days=int(p["learning_days"])):
        return []  # still learning: not enough baseline to call anything "new"
    b0 = t0 - timedelta(days=int(p["baseline_days"]))
    sql = f"""
    SELECT cutToFirstSignificantSubdomain(dns_qname) AS domain, count() AS c, groupUniqArray(10)(src_ip) AS clients, {COMMON}
    FROM {table()} WHERE category='dns' AND dns_qname != '' AND event_time >= {{t0:DateTime64(3)}} AND event_time < {{t1:DateTime64(3)}}
      AND domain != '' AND domain NOT IN (
        SELECT DISTINCT cutToFirstSignificantSubdomain(dns_qname) FROM {table()}
        WHERE category='dns' AND event_time >= {{b0:DateTime64(3)}} AND event_time < {{t0:DateTime64(3)}})
    GROUP BY domain ORDER BY c DESC LIMIT {{mx:UInt32}}"""
    rows = await ch.aquery(sql, {"t0": t0, "t1": t1, "b0": b0, "mx": int(p["max_per_run"])})
    return [Detection(group_key=r["domain"], count=int(r["c"]), first_seen=_dt(r["first_seen"]), last_seen=_dt(r["last_seen"]),
                      src_ip=(r["clients"][0] if len(r["clients"]) == 1 else None),
                      firewall_ids=[int(x) for x in r["fws"]], sites=[s for s in r["sites"] if s],
                      explanation=f"Domain {r['domain']} was first observed in this window (not seen in the previous {p['baseline_days']} days); queried by {len(r['clients'])} client(s).",
                      evidence={"clients": r["clients"]}, event_filter={"domain": r["domain"], "category": ["dns"]})
            for r in rows]


async def rule_dns_tunnel(ch, now, p):
    t0, t1 = _window(p, now)
    sql = f"""
    SELECT src_ip, cutToFirstSignificantSubdomain(dns_qname) AS domain, count() AS c, uniqExact(dns_qname) AS names,
           max(dns_qname_len) AS max_len, round(avg(dns_entropy), 2) AS ent, any(dns_qname) AS example, {COMMON}
    FROM {table()} WHERE category='dns' AND event_time >= {{t0:DateTime64(3)}} AND event_time < {{t1:DateTime64(3)}}
      AND (dns_qname_len >= {{lq:UInt16}} OR dns_entropy >= {{me:Float32}})
    GROUP BY src_ip, domain HAVING names >= {{mn:UInt32}} ORDER BY names DESC LIMIT 100"""
    rows = await ch.aquery(sql, {"t0": t0, "t1": t1, "lq": int(p["min_qname_len"]), "me": float(p["min_entropy"]),
                                 "mn": int(p["min_unique_names"])})
    return [Detection(group_key=f"{r['src_ip']}|{r['domain']}", count=int(r["c"]), first_seen=_dt(r["first_seen"]),
                      last_seen=_dt(r["last_seen"]), src_ip=r["src_ip"], firewall_ids=[int(x) for x in r["fws"]],
                      sites=[s for s in r["sites"] if s],
                      explanation=f"{r['src_ip']} queried {r['names']} unique long/high-entropy names under {r['domain']} (max length {r['max_len']}, avg entropy {r['ent']}). Example: {r['example']}",
                      evidence={k: r[k] for k in ("names", "max_len", "ent", "example")},
                      event_filter={"src_ip": r["src_ip"], "domain": r["domain"], "category": ["dns"]})
            for r in rows]


async def rule_admin_login_fail(ch, now, p):
    t0, t1 = _window(p, now)
    sql = f"""
    SELECT firewall_id, src_ip, user, count() AS c, {COMMON} FROM {table()}
    WHERE category='system' AND event_time >= {{t0:DateTime64(3)}} AND event_time < {{t1:DateTime64(3)}}
      AND (positionCaseInsensitive(msg, 'login fail') > 0 OR (orig_action = 'login' AND positionCaseInsensitive(raw, 'status="failed"') > 0)
           OR (orig_action = 'login' AND positionCaseInsensitive(raw, '"status": "failed"') > 0))
    GROUP BY firewall_id, src_ip, user HAVING c >= {{th:UInt32}} ORDER BY c DESC LIMIT 100"""
    rows = await ch.aquery(sql, {"t0": t0, "t1": t1, "th": int(p["min_failures"])})
    return [Detection(group_key=f"{r['firewall_id']}|{r['src_ip']}|{r['user']}", count=int(r["c"]), first_seen=_dt(r["first_seen"]),
                      last_seen=_dt(r["last_seen"]), src_ip=r["src_ip"] or None, firewall_ids=[int(r["firewall_id"])],
                      sites=[s for s in r["sites"] if s],
                      explanation=f"{r['c']} failed admin logins for user '{r['user'] or '?'}' from {r['src_ip'] or 'unknown source'} in {p['window_minutes']} min (threshold {p['min_failures']}).",
                      event_filter={"category": ["system"], "firewall_id": [int(r["firewall_id"])], "q": "login"})
            for r in rows]


async def rule_config_change(ch, now, p):
    t0, t1 = _window(p, now)
    sql = f"""
    SELECT firewall_id, user, count() AS c, groupUniqArray(5)(msg) AS msgs, {COMMON} FROM {table()}
    WHERE category='system' AND event_time >= {{t0:DateTime64(3)}} AND event_time < {{t1:DateTime64(3)}}
      AND log_id IN {{ids:Array(String)}} AND user NOT IN {{ign:Array(String)}}
    GROUP BY firewall_id, user ORDER BY c DESC LIMIT 100"""
    rows = await ch.aquery(sql, {"t0": t0, "t1": t1, "ids": p["log_ids"], "ign": p.get("ignore_users") or ["__siem_no_ignored_user__"]})
    return [Detection(group_key=f"{r['firewall_id']}|{r['user']}", count=int(r["c"]), first_seen=_dt(r["first_seen"]),
                      last_seen=_dt(r["last_seen"]), firewall_ids=[int(r["firewall_id"])], sites=[s for s in r["sites"] if s],
                      explanation=f"{r['c']} configuration change event(s) by '{r['user'] or 'unknown'}'. Verify against approved change requests.",
                      evidence={"messages": r["msgs"]}, event_filter={"category": ["system"], "firewall_id": [int(r["firewall_id"])]})
            for r in rows]


async def rule_multi_site(ch, now, p):
    t0, t1 = _window(p, now)
    sql = f"""
    SELECT src_ip, uniqExact(site) AS n_sites, count() AS c, {COMMON} FROM {table()}
    WHERE category='traffic' AND action IN {DENIED} AND site != '' AND src_ip != ''
      AND event_time >= {{t0:DateTime64(3)}} AND event_time < {{t1:DateTime64(3)}}
    GROUP BY src_ip HAVING n_sites >= {{ms:UInt32}} AND c >= {{md:UInt32}} ORDER BY n_sites DESC, c DESC LIMIT 100"""
    rows = await ch.aquery(sql, {"t0": t0, "t1": t1, "ms": int(p["min_sites"]), "md": int(p["min_denied"])})
    return [Detection(group_key=r["src_ip"], count=int(r["c"]), first_seen=_dt(r["first_seen"]), last_seen=_dt(r["last_seen"]),
                      src_ip=r["src_ip"], firewall_ids=[int(x) for x in r["fws"]], sites=[s for s in r["sites"] if s],
                      explanation=f"{r['src_ip']} was denied {r['c']} times across {r['n_sites']} sites in {p['window_minutes']} min.",
                      event_filter={"src_ip": r["src_ip"], "verdict": "denied", "category": ["traffic"]})
            for r in rows]


# ---------------------------------------------------------------- threat intel + behaviour (UEBA-lite)
def _internal(col: str) -> str:
    return (f"arrayExists(c -> isIPAddressInRange(if(isIPv4String({col}) OR isIPv6String({col}), {col}, '::'), c), "
            "{cidrs:Array(String)})")


def _cidrs() -> list[str]:
    from ..assets import internal_cidrs
    return internal_cidrs()


async def rule_ti_match(ch, now, p):
    t0, t1 = _window(p, now)
    rows = await ch.aquery(f"""
        SELECT src_ip, ti_match, any(ti_source) AS src, any(ti_category) AS cat, any(dst_ip) AS dst, count() AS c,
               groupUniqArray(5)(category) AS cats, {COMMON}
        FROM {table()} WHERE ti_match != '' AND event_time >= {{t0:DateTime64(3)}} AND event_time < {{t1:DateTime64(3)}}
        GROUP BY src_ip, ti_match HAVING c >= {{mn:UInt32}} ORDER BY c DESC LIMIT 200""",
        {"t0": t0, "t1": t1, "mn": int(p.get("min_events", 1))})
    low = set(p.get("low_categories") or [])
    return [Detection(group_key=f"{r['src_ip']}|{r['ti_match']}", count=int(r["c"]), first_seen=_dt(r["first_seen"]),
                      last_seen=_dt(r["last_seen"]), src_ip=r["src_ip"] or None, dst_ip=r["dst"] or None,
                      firewall_ids=[int(x) for x in r["fws"]], sites=[x for x in r["sites"] if x],
                      severity="medium" if r["cat"] in low else None,
                      explanation=f"{r['src_ip'] or 'A host'} had {r['c']} event(s) involving {r['ti_match']}, listed by '{r['src']}' ({r['cat']}).",
                      evidence={"indicator": r["ti_match"], "feed": r["src"], "category": r["cat"], "event_categories": r["cats"]},
                      event_filter={"q": r["ti_match"], "src_ip": r["src_ip"] or None})
            for r in rows]


async def rule_beaconing(ch, now, p):
    t0, t1 = _window(p, now)
    rows = await ch.aquery(f"""
        SELECT src_ip, dst_ip, dst_port, count() AS c,
               arraySlice(arrayDifference(arraySort(groupArray(2000)(toUInt32(toUnixTimestamp(event_time))))), 2) AS gaps,
               arrayAvg(gaps) AS mean_gap,
               sqrt(arrayAvg(arrayMap(x -> (x - mean_gap) * (x - mean_gap), gaps))) AS sd, {COMMON}
        FROM {table()} WHERE category = 'traffic' AND event_time >= {{t0:DateTime64(3)}} AND event_time < {{t1:DateTime64(3)}}
          AND dst_port IS NOT NULL AND dst_port NOT IN {{xp:Array(UInt16)}} AND dst_ip NOT IN {{xd:Array(String)}}
          AND {_internal('src_ip')} AND NOT {_internal('dst_ip')} AND dst_ip != ''
        GROUP BY src_ip, dst_ip, dst_port
        HAVING c >= {{mc:UInt32}} AND mean_gap >= {{mi:Float64}} AND sd / mean_gap <= {{cv:Float64}}
        ORDER BY c DESC LIMIT 100""",
        {"t0": t0, "t1": t1, "cidrs": _cidrs(), "xp": [int(x) for x in p.get("exclude_ports") or [0]],
         "xd": list(p.get("exclude_dsts") or ["__none__"]), "mc": int(p["min_connections"]), "mi": float(p["min_interval_seconds"]),
         "cv": float(p["max_cv"])})
    return [Detection(group_key=f"{r['src_ip']}|{r['dst_ip']}|{r['dst_port']}", count=int(r["c"]), first_seen=_dt(r["first_seen"]),
                      last_seen=_dt(r["last_seen"]), src_ip=r["src_ip"], dst_ip=r["dst_ip"], firewall_ids=[int(x) for x in r["fws"]],
                      sites=[x for x in r["sites"] if x],
                      explanation=(f"{r['src_ip']} connected to {r['dst_ip']}:{r['dst_port']} {r['c']} times every ~{float(r['mean_gap']):.0f}s "
                                   f"(variation {float(r['sd']) / float(r['mean_gap']) * 100:.0f}% of the interval). Regular timing can indicate a C2 heartbeat; "
                                   "update checks and monitoring agents also beacon."),
                      evidence={"mean_interval_s": round(float(r["mean_gap"]), 1), "stddev_s": round(float(r["sd"]), 1), "connections": r["c"]},
                      event_filter={"src_ip": r["src_ip"], "dst_ip": r["dst_ip"], "dst_port": r["dst_port"], "category": ["traffic"]})
            for r in rows]


async def rule_volume_baseline(ch, now, p):
    hour0 = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
    b0 = hour0 - timedelta(days=int(p["baseline_days"]))
    rows = await ch.aquery(f"""
        WITH cur AS (SELECT src_ip, sum(bytes_sent) AS sent, groupUniqArray(firewall_id) AS fws FROM src_hourly
                     WHERE hour = toDateTime({{h:DateTime64(3)}}, 'UTC') AND {_internal('src_ip')} GROUP BY src_ip),
             base AS (SELECT src_ip, sum(bytes_sent) / {{nh:Float64}} AS avg_sent, uniqExact(hour) AS hours FROM src_hourly
                      WHERE hour >= toDateTime({{b0:DateTime64(3)}}, 'UTC') AND hour < toDateTime({{h:DateTime64(3)}}, 'UTC') GROUP BY src_ip)
        SELECT cur.src_ip AS src_ip, cur.sent AS sent, base.avg_sent AS avg_sent, base.hours AS hours, cur.fws AS fws
        FROM cur INNER JOIN base ON cur.src_ip = base.src_ip
        WHERE base.hours >= {{mh:UInt32}} AND cur.sent >= {{mb:Float64}} AND cur.sent >= {{f:Float64}} * greatest(base.avg_sent, 1)
        ORDER BY sent DESC LIMIT 100""",
        {"h": hour0, "b0": b0, "nh": float(int(p["baseline_days"]) * 24), "cidrs": _cidrs(), "mh": int(p["min_history_hours"]),
         "mb": float(p["min_sent_bytes"]), "f": float(p["factor"])})
    return [Detection(group_key=f"{r['src_ip']}|{hour0:%Y%m%d%H}", count=1, first_seen=hour0, last_seen=hour0 + timedelta(hours=1),
                      src_ip=r["src_ip"], firewall_ids=[int(x) for x in r["fws"]],
                      explanation=(f"{r['src_ip']} sent {int(r['sent']):,} bytes between {hour0:%H:%M} and {(hour0 + timedelta(hours=1)):%H:%M} UTC, "
                                   f"{float(r['sent']) / max(float(r['avg_sent']), 1):.0f}× its hourly average over {p['baseline_days']} days."),
                      evidence={"sent_bytes": r["sent"], "baseline_avg_bytes": round(float(r["avg_sent"])), "history_hours": r["hours"]},
                      event_filter={"src_ip": r["src_ip"], "category": ["traffic"], "start": hour0.isoformat(), "end": (hour0 + timedelta(hours=1)).isoformat()})
            for r in rows]


async def _learning_ok(ch, days: int, now) -> bool:
    r = await ch.aquery(f"SELECT min(event_time) AS m, count() AS n FROM {table()} WHERE category='traffic'")
    return bool(r and int(r[0]["n"]) and _dt(r[0]["m"]) <= now - timedelta(days=days))


async def rule_new_country(ch, now, p):
    if not await _learning_ok(ch, int(p["learning_days"]), now):
        return []
    t0, t1 = _window(p, now)
    b0 = t0 - timedelta(days=int(p["baseline_days"]))
    rows = await ch.aquery(f"""
        SELECT dst_country, count() AS c, uniqExact(src_ip) AS hosts, groupUniqArray(5)(src_ip) AS srcs, {COMMON}
        FROM {table()} WHERE category='traffic' AND dst_country != '' AND action IN ('accept','close','timeout','allow')
          AND event_time >= {{t0:DateTime64(3)}} AND event_time < {{t1:DateTime64(3)}}
          AND dst_country NOT IN (SELECT DISTINCT dst_country FROM {table()} WHERE category='traffic'
                                  AND event_time >= {{b0:DateTime64(3)}} AND event_time < {{t0:DateTime64(3)}})
        GROUP BY dst_country ORDER BY c DESC LIMIT {{mx:UInt32}}""", {"t0": t0, "t1": t1, "b0": b0, "mx": int(p["max_per_run"])})
    return [Detection(group_key=r["dst_country"], count=int(r["c"]), first_seen=_dt(r["first_seen"]), last_seen=_dt(r["last_seen"]),
                      src_ip=r["srcs"][0] if len(r["srcs"]) == 1 else None, firewall_ids=[int(x) for x in r["fws"]],
                      sites=[x for x in r["sites"] if x],
                      explanation=f"Allowed traffic to {r['dst_country']} from {r['hosts']} host(s); not seen in the previous {p['baseline_days']} days.",
                      evidence={"hosts": r["srcs"]}, event_filter={"q": r["dst_country"], "category": ["traffic"]})
            for r in rows]


async def rule_new_port(ch, now, p):
    if not await _learning_ok(ch, int(p["learning_days"]), now):
        return []
    t0, t1 = _window(p, now)
    b0 = t0 - timedelta(days=int(p["baseline_days"]))
    rows = await ch.aquery(f"""
        WITH cur AS (SELECT src_ip, dst_port, count() AS c, any(dst_ip) AS dst, {COMMON} FROM {table()}
                     WHERE category='traffic' AND event_time >= {{t0:DateTime64(3)}} AND event_time < {{t1:DateTime64(3)}}
                       AND dst_port IS NOT NULL AND dst_port NOT IN {{ig:Array(UInt16)}} AND action IN ('accept','close','timeout','allow')
                       AND {_internal('src_ip')} AND NOT {_internal('dst_ip')} AND dst_ip != ''
                     GROUP BY src_ip, dst_port HAVING c >= {{me:UInt32}}),
             hist AS (SELECT DISTINCT src_ip FROM src_hourly WHERE hour >= toDateTime({{b0:DateTime64(3)}}, 'UTC') AND hour < toDateTime({{t0:DateTime64(3)}}, 'UTC')),
             base AS (SELECT DISTINCT src_ip, dst_port FROM {table()} WHERE category='traffic'
                      AND event_time >= {{b0:DateTime64(3)}} AND event_time < {{t0:DateTime64(3)}} AND src_ip IN (SELECT src_ip FROM cur))
        SELECT cur.* FROM cur
        WHERE cur.src_ip IN (SELECT src_ip FROM hist) AND (cur.src_ip, cur.dst_port) NOT IN (SELECT src_ip, dst_port FROM base)
        ORDER BY c DESC LIMIT {{mx:UInt32}}""",
        {"t0": t0, "t1": t1, "b0": b0, "cidrs": _cidrs(), "ig": [int(x) for x in p.get("ignore_ports") or [0]],
         "me": int(p["min_events"]), "mx": int(p["max_per_run"])})
    return [Detection(group_key=f"{r['src_ip']}|{r['dst_port']}", count=int(r["c"]), first_seen=_dt(r["first_seen"]),
                      last_seen=_dt(r["last_seen"]), src_ip=r["src_ip"], dst_ip=r["dst"], firewall_ids=[int(x) for x in r["fws"]],
                      sites=[x for x in r["sites"] if x],
                      explanation=f"{r['src_ip']} used external destination port {r['dst_port']} ({r['c']} events) for the first time in {p['baseline_days']} days.",
                      event_filter={"src_ip": r["src_ip"], "dst_port": r["dst_port"], "category": ["traffic"]})
            for r in rows]


VPN_FAIL = "(event_subtype = 'vpn' AND (positionCaseInsensitive(orig_action, 'fail') > 0 OR positionCaseInsensitive(msg, 'fail') > 0))"
VPN_UP = "(event_subtype = 'vpn' AND orig_action IN ('tunnel-up', 'ssl-login', 'ssl-web-login', 'login'))"


async def rule_vpn_bruteforce(ch, now, p):
    t0, t1 = _window(p, now)
    rows = await ch.aquery(f"""
        SELECT src_ip, count() AS c, uniqExact(user) AS users, groupUniqArray(10)(user) AS user_list, any(src_country) AS country, {COMMON}
        FROM {table()} WHERE category='system' AND {VPN_FAIL} AND event_time >= {{t0:DateTime64(3)}} AND event_time < {{t1:DateTime64(3)}}
        GROUP BY src_ip HAVING c >= {{mf:UInt32}} ORDER BY c DESC LIMIT 100""", {"t0": t0, "t1": t1, "mf": int(p["min_failures"])})
    return [Detection(group_key=r["src_ip"] or "unknown", count=int(r["c"]), first_seen=_dt(r["first_seen"]), last_seen=_dt(r["last_seen"]),
                      src_ip=r["src_ip"] or None, firewall_ids=[int(x) for x in r["fws"]], sites=[x for x in r["sites"] if x],
                      explanation=f"{r['c']} failed VPN logins from {r['src_ip'] or 'unknown'}{' (' + r['country'] + ')' if r['country'] else ''} "
                                  f"against {r['users']} user name(s) in {p['window_minutes']} min.",
                      evidence={"users": r["user_list"]}, event_filter={"src_ip": r["src_ip"] or None, "category": ["system"], "event_subtype": "vpn"})
            for r in rows]


async def rule_impossible_travel(ch, now, p):
    from .travel import find_impossible_travel
    t0 = now - timedelta(hours=int(p["window_hours"]))
    rows = await ch.aquery(f"""
        SELECT user, event_time, src_ip, src_country, src_lat, src_lon, firewall_id, site FROM {table()}
        WHERE category='system' AND {VPN_UP} AND user != '' AND event_time >= {{t0:DateTime64(3)}} AND event_time < {{t1:DateTime64(3)}}
        ORDER BY user, event_time LIMIT 200000""", {"t0": t0, "t1": now})
    out = []
    for f in find_impossible_travel(rows, max_kmh=float(p["max_kmh"]), min_km=float(p["min_km"])):
        out.append(Detection(group_key=f"{f['user']}|{f['to']['time']}", count=2, first_seen=_dt(f["from"]["time"]), last_seen=_dt(f["to"]["time"]),
                             src_ip=f["to"]["ip"], firewall_ids=sorted({int(f["from"]["fw"]), int(f["to"]["fw"])}),
                             explanation=(f"User {f['user']} logged in from {f['from']['place']} ({f['from']['ip']}) and {f['minutes']:.0f} min later from "
                                          f"{f['to']['place']} ({f['to']['ip']}): ~{f['km']:.0f} km, {f['kmh']:.0f} km/h"
                                          f"{' (approximate: country centroids)' if f['approximate'] else ''}. Shared VPN exits or proxies can cause false positives."),
                             evidence=f, event_filter={"user": f["user"], "category": ["system"], "event_subtype": "vpn"}))
    return out


async def rule_risky_config_change(ch, now, p):
    return []  # detections are produced by the config-drift collector (app/drift.py)


async def rule_isp_outage(ch, now, p):
    """Full outages on WAN links (see app/isp.py) overlapping the window. Group key = link, so one alert per link
    tracks the current outage; an outage that starts after the alert was resolved opens a new one."""
    from ..db.pg import session_factory
    from ..isp import analyze_link, configs, load
    t0 = now - timedelta(minutes=int(p.get("window_minutes", 15)))
    links = await load(ch, t0 - timedelta(hours=1), now)
    async with session_factory()() as s:
        cfgs = await configs(s)
    out = []
    for key, lk in links.items():
        cfg = cfgs.get(key)
        if cfg and cfg.hidden:
            continue
        r = analyze_link(lk, cfg, t0 - timedelta(hours=1), now, min_outage=int(p.get("min_outage_minutes", 2)) * 60)
        recent = [(a, b) for a, b in r["_outages"] if b >= t0]
        if not recent:
            continue
        a, b = recent[-1]
        ongoing = r["status"] == "down"
        mins = round((b - a).total_seconds() / 60, 1)
        out.append(Detection(
            group_key=r["key"], count=len(recent), first_seen=a, last_seen=b, firewall_ids=[lk.firewall_id],
            explanation=(f"{(cfg.isp_name or cfg.as_org) + ' ' if cfg and (cfg.isp_name or cfg.as_org) else ''}WAN link {lk.interface} on {lk.firewall_name}{f' (gateway {lk.gateway})' if lk.gateway else ''} "
                         f"{'is down' if ongoing else 'was down'} for {mins} min: all {len(r['outage_checks'])} health checks failed "
                         f"({', '.join(r['outage_checks'][:5])})."),
            evidence={"interface": lk.interface, "gateway": lk.gateway, "start": a.isoformat(), "end": b.isoformat(), "ongoing": ongoing,
                      "checks": r["outage_checks"]},
            event_filter={"category": ["system"], "event_subtype": "sdwan", "q": f'interface="{lk.interface}"'}))
    return out


async def rule_peer_anomaly(ch, now, p):
    """Robust outliers within each internal subnet (IPv4 /prefix_len) for bytes sent and connection count."""
    import ipaddress
    from statistics import median
    t0 = now - timedelta(hours=int(p["window_hours"]))
    rows = await ch.aquery(
        "SELECT src_ip, sum(events) AS ev, sum(bytes_sent) AS sent, groupUniqArray(5)(firewall_id) AS fws FROM src_hourly "
        "WHERE hour >= toStartOfHour({t0:DateTime64(3)}) AND isIPv4String(src_ip) AND (isIPAddressInRange(src_ip, '10.0.0.0/8') "
        "OR isIPAddressInRange(src_ip, '172.16.0.0/12') OR isIPAddressInRange(src_ip, '192.168.0.0/16')) GROUP BY src_ip", {"t0": t0})
    groups: dict = {}
    for r in rows:
        net = str(ipaddress.ip_network(f"{r['src_ip']}/{int(p['prefix_len'])}", strict=False))
        groups.setdefault(net, []).append(r)
    out = []
    for net, hosts in groups.items():
        if len(hosts) < int(p["min_peers"]):
            continue
        for metric, floor, label in (("sent", float(p["min_sent_bytes"]), "bytes sent"), ("ev", float(p["min_events"]), "connections")):
            vals = [float(h[metric]) for h in hosts]
            med = median(vals)
            mad = median(abs(v - med) for v in vals) * 1.4826 or 1.0
            for h in hosts:
                v = float(h[metric])
                if v < floor or v < float(p["min_factor"]) * max(med, 1) or (v - med) / mad < float(p["mad_k"]):
                    continue
                out.append(Detection(
                    group_key=f"{h['src_ip']}|{metric}", count=int(h["ev"]), first_seen=t0, last_seen=now, src_ip=h["src_ip"],
                    firewall_ids=[int(x) for x in h["fws"]],
                    explanation=f"{h['src_ip']}: {v:,.0f} {label} in the last {p['window_hours']} h vs a median of {med:,.0f} across "
                                f"{len(hosts)} hosts in {net} ({v / max(med, 1):.0f}× the peer median).",
                    evidence={"metric": v, "peer_median": med, "peer_mad": mad, "peers": len(hosts), "subnet": net, "kind": label},
                    event_filter={"src_ip": h["src_ip"], "category": ["traffic"]}))
    return sorted(out, key=lambda d: -d.evidence["metric"] / max(d.evidence["peer_median"], 1))[:50]


WIN = "category = 'system' AND event_type = 'windows'"
WIN_FAIL = f"{WIN} AND action IN ('logon-fail', 'kerberos-preauth-fail', 'ntlm-fail')"


async def _win_rows(ch, now, p, sql: str, extra: dict | None = None):
    t0 = now - timedelta(minutes=int(p["window_minutes"]))
    return t0, await ch.aquery(sql.replace("{W}", "event_time >= {t0:DateTime64(3)} AND event_time < {t1:DateTime64(3)}"),
                               {"t0": t0, "t1": now, **(extra or {})})


async def rule_win_bruteforce(ch, now, p):
    t0, rows = await _win_rows(ch, now, p,
        f"SELECT if(user != '', user, src_ip) AS k, user, any(src_ip) AS ip, count() AS n, uniqExact(src_ip) AS ips, {COMMON} "
        f"FROM {table()} WHERE {WIN_FAIL} AND {{W}} GROUP BY k, user HAVING n >= {{th:UInt32}} ORDER BY n DESC LIMIT 100",
        {"th": int(p["min_failures"])})
    return [Detection(group_key=r["k"], count=int(r["n"]), first_seen=_dt(r["first_seen"]), last_seen=_dt(r["last_seen"]),
                      src_ip=r["ip"] or None, firewall_ids=[int(x) for x in r["fws"]],
                      explanation=f"{r['n']} failed Windows logons for {r['user'] or 'unknown account'} from {r['ips']} source(s) in {p['window_minutes']} min.",
                      evidence={"metric": int(r["n"]), "user": r["user"]}, event_filter={"category": ["system"], "user": r["user"] or None}) for r in rows]


async def rule_win_password_spray(ch, now, p):
    t0, rows = await _win_rows(ch, now, p,
        f"SELECT src_ip, uniqExact(user) AS users, count() AS n, groupUniqArray(10)(user) AS sample, {COMMON} FROM {table()} "
        f"WHERE {WIN_FAIL} AND src_ip != '' AND {{W}} GROUP BY src_ip HAVING users >= {{th:UInt32}} ORDER BY users DESC LIMIT 50",
        {"th": int(p["min_users"])})
    return [Detection(group_key=r["src_ip"], count=int(r["n"]), first_seen=_dt(r["first_seen"]), last_seen=_dt(r["last_seen"]), src_ip=r["src_ip"],
                      firewall_ids=[int(x) for x in r["fws"]],
                      explanation=f"{r['src_ip']} failed to log on as {r['users']} different accounts in {p['window_minutes']} min (e.g. {', '.join(r['sample'][:5])}).",
                      evidence={"metric": int(r["users"]), "accounts": r["sample"]}, event_filter={"category": ["system"], "src_ip": r["src_ip"]}) for r in rows]


async def _win_simple(ch, now, p, action_sql: str, key: str, explain, extra_where: str = "", extra: dict | None = None):
    t0, rows = await _win_rows(ch, now, p,
        f"SELECT {key} AS k, any(user) AS a_user, any(src_ip) AS ip, any(hostname) AS host, any(app) AS obj, any(msg) AS m, count() AS n, {COMMON} "
        f"FROM {table()} WHERE {WIN} AND {action_sql} {extra_where} AND {{W}} GROUP BY k ORDER BY n DESC LIMIT 100", extra)
    for r in rows:  # aliases differ from column names so they never shadow the grouping key (e.g. key = user)
        r["user"] = r.pop("a_user")
    return [Detection(group_key=str(r["k"]), count=int(r["n"]), first_seen=_dt(r["first_seen"]), last_seen=_dt(r["last_seen"]),
                      src_ip=r["ip"] or None, firewall_ids=[int(x) for x in r["fws"]], explanation=explain(r),
                      evidence={"user": r["user"], "host": r["host"], "object": r["obj"], "message": r["m"]},
                      event_filter={"category": ["system"], "q": str(r["k"])[:200]}) for r in rows]


async def rule_win_lockout(ch, now, p):
    return await _win_simple(ch, now, p, "action = 'lockout'", "user",
                             lambda r: f"Account {r['user']} was locked out {r['n']} time(s) (on {r['host'] or 'a domain controller'}).")


async def rule_win_priv_group(ch, now, p):
    return await _win_simple(ch, now, p, "action = 'group-add'", "concat(app, '|', user)",
                             lambda r: f"{r['user'] or 'A member'} was added to privileged group {r['obj']} (on {r['host'] or 'unknown host'}).",
                             "AND lower(app) IN {groups:Array(String)}", {"groups": [g.lower() for g in p.get("groups", [])]})


async def rule_win_log_cleared(ch, now, p):
    return await _win_simple(ch, now, p, "action = 'log-cleared'", "hostname",
                             lambda r: f"The event log was cleared on {r['host'] or 'a Windows host'} (by {r['user'] or 'unknown'}).")


async def rule_win_new_service(ch, now, p):
    return await _win_simple(ch, now, p, "action = 'service-installed'", "concat(hostname, '|', app)",
                             lambda r: f"Service '{r['obj']}' was installed on {r['host'] or 'a Windows host'}.",
                             "AND lower(app) NOT IN {ign:Array(String)}", {"ign": [x.lower() for x in p.get("ignore_services", [])]})


async def rule_icmp_down(ch, now, p):
    """Targets currently DOWN (state kept by the ICMP prober). One alert per outage: the group key includes the time
    the target went down, so a later outage opens a new alert."""
    from ..db.models import IcmpTarget
    from ..db.pg import session_factory
    async with session_factory()() as s:
        rows = (await s.execute(select(IcmpTarget).where(IcmpTarget.enabled.is_(True), IcmpTarget.state == "down"))).scalars().all()
    out = []
    for t in rows:
        since = _dt(t.state_since) if t.state_since else now
        mins = (now - since).total_seconds() / 60
        if mins < float(p.get("min_down_minutes", 1)):
            continue
        out.append(Detection(group_key=f"{t.id}:{since:%Y%m%d%H%M%S}", count=t.fail_streak, first_seen=since, last_seen=now,
                             dst_ip=t.address if t.address.replace(".", "").replace(":", "").isalnum() else None,
                             explanation=f"{t.name} ({t.address}) has not answered ICMP for {mins:.0f} min "
                                         f"({t.fail_streak} consecutive failed checks of {t.probes} probes).",
                             evidence={"address": t.address, "down_since": since.isoformat(), "failed_checks": t.fail_streak},
                             event_filter={}))
    return out


async def rule_fw_resource_high(ch, now, p):
    from ..fwhealth import perf_samples
    t0 = now - timedelta(minutes=int(p["window_minutes"]))
    by: dict = {}
    for r in await perf_samples(ch, t0, now):
        by.setdefault((r["firewall_id"], r["member"]), []).append(r)
    out = []
    for (fid, member), rs in by.items():
        hot = [r for r in rs if (r["cpu"] or 0) >= float(p["cpu_pct"]) or (r["mem"] or 0) >= float(p["mem_pct"])]
        if len(hot) < int(p["min_samples"]) or rs[-1] not in hot:
            continue
        last = rs[-1]
        out.append(Detection(group_key=f"{fid}:{member}", count=len(hot), first_seen=hot[0]["t"], last_seen=last["t"], firewall_ids=[fid],
                             explanation=f"{member}: CPU {last['cpu'] or 0:.0f}% / memory {last['mem'] or 0:.0f}% ({len(hot)} of {len(rs)} samples over the "
                                         f"threshold in {p['window_minutes']} min; {int(last['sessions'] or 0):,} sessions).",
                             evidence={"cpu": last["cpu"], "mem": last["mem"], "sessions": last["sessions"]},
                             event_filter={"category": ["system"], "q": "Performance statistics"}))
    return out


async def rule_fw_reboot(ch, now, p):
    from ..fwhealth import perf_samples, reboots
    t0 = now - timedelta(minutes=int(p["window_minutes"]))
    out = []
    for b in reboots(await perf_samples(ch, t0 - timedelta(hours=2), now)):
        boot = _dt(b["boot_time"])
        if _dt(b["detected_at"]) < t0:
            continue
        out.append(Detection(group_key=f"{b['firewall_id']}:{b['member']}:{boot:%Y%m%d%H%M}", count=1, first_seen=boot, last_seen=_dt(b["detected_at"]),
                             firewall_ids=[b["firewall_id"]], explanation=f"{b['member']} restarted around {boot:%Y-%m-%d %H:%M} UTC "
                             f"(uptime before restart {b['previous_uptime_s'] // 86400} days).", evidence=b,
                             event_filter={"category": ["system"], "start": boot.isoformat()}))
    return out


async def rule_log_feed_gap(ch, now, p):
    from ..fwhealth import feed_status
    out = []
    for f in await feed_status(ch, now, int(p["silent_minutes"])):
        if not f["gap"]:
            continue
        last = _dt(f["last_event"])
        out.append(Detection(group_key=f"{f['firewall_id']}:{f['category']}", count=1, first_seen=last, last_seen=now, firewall_ids=[f["firewall_id"]],
                             explanation=f"No {f['category']} logs for {f['silent_minutes']:.0f} min from firewall #{f['firewall_id']} "
                                         f"(it sent {f['events_24h']:,} in the last 24 h).", evidence=f,
                             event_filter={"category": [f["category"]], "firewall_id": [f["firewall_id"]]}))
    return out


async def rule_vpn_tunnel_down(ch, now, p):
    from ..vpnmon import tunnels
    t0 = now - timedelta(minutes=int(p["window_minutes"]))
    out = []
    for t in (await tunnels(ch, t0, now))["tunnels"]:
        for d in t["down_periods"]:
            if d["duration_s"] < int(p["min_down_minutes"]) * 60:
                continue
            a = _dt(d["start"])
            ongoing = t["status"] == "down"
            out.append(Detection(group_key=f"{t['firewall_id']}:{t['tunnel']}", count=1, first_seen=a, last_seen=_dt(d["end"]),
                                 firewall_ids=[t["firewall_id"]], dst_ip=t["remote_ip"] or None,
                                 explanation=f"IPsec tunnel {t['tunnel']} on {t['firewall_name']} (peer {t['remote_ip']}) "
                                             f"{'is down' if ongoing else 'was down'} for {d['duration_s'] / 60:.0f} min.",
                                 evidence={**d, "tunnel": t["tunnel"], "peer": t["remote_ip"]},
                                 event_filter={"category": ["system"], "q": f'vpntunnel="{t["tunnel"]}"'}))
    return out


async def rule_identity_auth_failures(ch, now, p):
    from ..identity import auth_events, failures
    evs = await auth_events(ch, now - timedelta(minutes=int(p["window_minutes"])), now)
    out = []
    for u in failures(evs)["by_user"]:
        if u["failures"] < int(p["min_failures"]):
            continue
        out.append(Detection(group_key=u["user"].lower(), count=u["failures"], first_seen=_dt(u["first"]), last_seen=_dt(u["last"]),
                             src_ip=u["sources"][0] if len(u["sources"]) == 1 else None,
                             explanation=f"{u['failures']} failed {'/'.join(u['kinds'])} logins for user '{u['user']}' from {len(u['sources'])} source(s)"
                                         + (f" ({', '.join(u['countries'])})" if u["countries"] else "") + f" in {p['window_minutes']} min"
                                         + (f". Last reason: {u['detail']}" if u["detail"] else "") + ".",
                             evidence={"sources": u["sources"][:50], "kinds": u["kinds"], "countries": u["countries"]},
                             event_filter={"user": u["user"], "category": ["system"]}))
    return out


async def rule_identity_success_after_failures(ch, now, p):
    from ..identity import auth_events, failures
    evs = await auth_events(ch, now - timedelta(minutes=int(p["window_minutes"])) * 2, now)
    t0 = now - timedelta(minutes=int(p["window_minutes"]))
    out = []
    for s in failures(evs, timedelta(minutes=int(p["window_minutes"])))["success_after_failures"]:
        if s["failures"] < int(p["min_failures"]) or _dt(s["t"]) < t0:
            continue
        t = _dt(s["t"])
        out.append(Detection(group_key=f"{s['user'].lower()}|{t:%Y%m%d%H%M}", count=s["failures"] + 1, first_seen=t, last_seen=t,
                             src_ip=s["src_ip"] or None, firewall_ids=[s["firewall_id"]], severity=None if not s["same_source"] else "medium",
                             explanation=f"User '{s['user']}' logged in ({s['kind']}) from {s['src_ip'] or 'unknown'} after {s['failures']} failed attempts"
                                         + ("" if s["same_source"] else f" that came from other sources ({', '.join(s['failed_from'][:5])})") + ".",
                             evidence=s, event_filter={"user": s["user"], "category": ["system"]}))
    return out


async def rule_identity_unusual_login(ch, now, p):
    from ..identity import anomalies, auth_events, baseline
    t0 = now - timedelta(minutes=int(p["window_minutes"]))
    hist = await auth_events(ch, t0 - timedelta(days=int(p["baseline_days"])), t0)
    evs = await auth_events(ch, t0, now)
    out = []
    for a in anomalies(evs, baseline(hist), work_hours=(int(p["work_start_hour"]), int(p["work_end_hour"]))):
        if a["score"] < int(p["min_score"]):
            continue
        t = _dt(a["t"])
        out.append(Detection(group_key=f"{a['user'].lower()}|{t:%Y%m%d%H%M}", count=1, first_seen=t, last_seen=t, src_ip=a["src_ip"] or None,
                             firewall_ids=[a["firewall_id"]], severity="high" if a["score"] >= 60 else None,
                             explanation=f"Unusual {a['kind']} login by '{a['user']}' from {a['src_ip'] or '?'}"
                                         + (f" ({a['country']})" if a["country"] else "") + ": " + "; ".join(r["detail"] for r in a["reasons"]) + ".",
                             evidence=a, event_filter={"user": a["user"], "category": ["system"]}))
    return out


async def rule_admin_account_change(ch, now, p):
    from ..identity import admin_activity
    ign = {x.lower() for x in p.get("ignore_admins") or []}
    out = []
    for c in (await admin_activity(ch, now - timedelta(minutes=int(p["window_minutes"])), now))["account_changes"]:
        if c["admin"].lower() in ign:
            continue
        t = _dt(c["t"])
        what = f"{c['action']} {c['path']} {c['object']}".strip()
        out.append(Detection(group_key=f"{c['firewall_id']}|{c['path']}|{c['object']}|{t:%Y%m%d%H%M}", count=1, first_seen=t, last_seen=t,
                             src_ip=c["src_ip"] or None, firewall_ids=[c["firewall_id"]], severity="high" if c["privilege"] else "medium",
                             explanation=f"{c['admin']} ({c['method'] or '?'} from {c['src_ip'] or '?'}) on {c['firewall_name']}: {what}"
                                         + (f" [{c['attr']}]" if c["attr"] else "") + (". Privilege-related change." if c["privilege"] else "."),
                             evidence=c, event_filter={"category": ["system"], "firewall_id": [c["firewall_id"]], "q": c["object"] or c["path"]}))
    return out


async def rule_admin_off_hours_change(ch, now, p):
    from ..identity import admin_activity
    a, b = int(p["work_start_hour"]), int(p["work_end_hour"])
    groups: dict = {}
    for c in (await admin_activity(ch, now - timedelta(minutes=int(p["window_minutes"])), now))["changes"]:
        off = not (a <= c["local_hour"] < b) or (p.get("weekend", True) and c["local_dow"] >= 5)
        if off and not c.get("cosmetic"):  # an admin rearranging their own dashboard is not a configuration change
            groups.setdefault((c["firewall_id"], c["admin"]), []).append(c)
    out = []
    for (fid, adm), cs in groups.items():
        cs.sort(key=lambda c: c["t"])
        out.append(Detection(group_key=f"{fid}|{adm}|{_dt(cs[0]['t']):%Y%m%d%H}", count=len(cs), first_seen=_dt(cs[0]["t"]), last_seen=_dt(cs[-1]["t"]),
                             src_ip=cs[-1]["src_ip"] or None, firewall_ids=[fid],
                             explanation=f"{adm} made {len(cs)} configuration change(s) on {cs[0]['firewall_name']} at {cs[0]['local_hour']:02d}:00 local"
                                         + (" on a weekend" if cs[0]["local_dow"] >= 5 else "") + ": "
                                         + "; ".join(sorted({f"{c['action']} {c['path']}" for c in cs})[:6]) + ".",
                             evidence={"changes": cs[:20]}, event_filter={"category": ["system"], "firewall_id": [fid]}))
    return out


async def _bgp_report(ch, now, minutes, correlate=False):
    from ..bgp import report
    from ..db.pg import session_factory
    async with session_factory()() as s:
        return await report(ch, s, now - timedelta(minutes=int(minutes)), now, correlate=correlate)


async def _bgp_events(ch, now, minutes, kinds):
    from ..bgp import _window_events
    from ..db.pg import session_factory
    async with session_factory()() as s:
        evs, _ = await _window_events(ch, s, now - timedelta(minutes=int(minutes)), now, None)
    return [e for e in evs if e["kind"] in kinds]


async def rule_bgp_prefix_anomaly(ch, now, p):
    from ..bgp_analysis import is_anomalous
    out = []
    for x in (await _bgp_report(ch, now, 60))["peers"]:
        b = x["baseline"]
        if x["status"] != "up" or not is_anomalous(b, int(p["min_samples"]), float(p["deviation_pct"]), int(p["min_abs"])):
            continue
        out.append(Detection(group_key=f"{x['firewall_id']}:{x['peer']}", count=1, first_seen=now, last_seen=now, firewall_ids=[x["firewall_id"]],
                             dst_ip=x["peer"], explanation=f"BGP neighbor {x['peer']} on {x['firewall_name']} sends {b['current']} prefixes; its 7-day "
                             f"median is {b['median']} ({b['deviation_pct']:+.0f}%). " + ("Partial routing-table loss?" if b["current"] < b["median"]
                                                                                           else "Possible route leak?"),
                             evidence={"peer": x["peer"], **b}, event_filter={"category": ["system"], "q": f'"{x["peer"]}"'}))
    return out


async def rule_bgp_route_leak(ch, now, p):
    out = []
    groups: dict = {}
    for e in await _bgp_events(ch, now, p["window_minutes"], set(p["kinds"])):
        groups.setdefault((e["firewall_id"], e["peer"], e["kind"]), []).append(e)
    for (fid, peer, kind), evs in groups.items():
        sample = ", ".join(sorted({e["prefix"] for e in evs if e["prefix"]})[:8])
        out.append(Detection(group_key=f"{fid}:{peer}:{kind}", count=len(evs), first_seen=evs[0]["t"], last_seen=evs[-1]["t"], firewall_ids=[fid],
                             dst_ip=peer or None, severity="high" if kind in ("leak_suspect", "more_specific") else "medium",
                             explanation=f"BGP {kind.replace('_', ' ')} from neighbor {peer} on {evs[0]['firewall_name']}: {evs[-1]['detail']}"
                                         + (f" Prefixes: {sample}." if sample else ""),
                             evidence={"kind": kind, "peer": peer, "prefixes": sorted({e["prefix"] for e in evs if e["prefix"]})[:50]},
                             event_filter={"category": ["system"], "q": f'"{peer}"'} if peer else {}))
    return out


async def rule_bgp_critical_prefix(ch, now, p):
    from ..bgp import _critical_nets
    from ..bgp_analysis import matches_watchlist
    from ..db.pg import session_factory
    async with session_factory()() as s:
        _, nets = await _critical_nets(s, p["watchlist"])
    if not nets:
        return []
    out = []
    for e in await _bgp_events(ch, now, p["window_minutes"], {"route_withdraw", "path_change", "unreachable"}):
        if not e["prefix"] or not matches_watchlist(e["prefix"], nets):
            continue
        out.append(Detection(group_key=f"{e['firewall_id']}:{e['prefix']}:{e['kind']}", count=1, first_seen=e["t"], last_seen=e["t"],
                             firewall_ids=[e["firewall_id"]], dst_ip=e["peer"] or None,
                             explanation=f"Critical prefix {e['prefix']} on {e['firewall_name']}: {e['kind'].replace('_', ' ')}"
                                         + (f" ({e['detail']})" if e["detail"] else "") + (f" via neighbor {e['peer']}" if e["peer"] else "") + ".",
                             evidence={"prefix": e["prefix"], "kind": e["kind"], "peer": e["peer"], "detail": e["detail"]}))
    return out


async def rule_bgp_peer_down(ch, now, p):
    out = []
    for x in (await _bgp_report(ch, now, p["window_minutes"], correlate=True))["peers"]:
        for d in x["down_periods"]:
            if d["duration_s"] < int(p["min_down_minutes"]) * 60:
                continue
            out.append(Detection(group_key=f"{x['firewall_id']}:{x['peer']}", count=1, first_seen=_dt(d["start"]), last_seen=_dt(d["end"]),
                                 firewall_ids=[x["firewall_id"]], dst_ip=x["peer"],
                                 explanation=f"BGP neighbor {x['peer']}" + (f" (AS {x['remote_as']})" if x["remote_as"] else "") +
                                             f" on {x['firewall_name']} {'is down' if d['ongoing'] else 'was down'} for {d['duration_s'] / 60:.0f} min"
                                             + (f": {x['last_reason']}" if x["last_reason"] else "") + "."
                                             + (f" Likely cause: {d['verdict']}." if d.get("verdict") else ""),
                                 evidence={**d, "peer": x["peer"], "remote_as": x["remote_as"], "reason": x["last_reason"], "tunnel": x["interface"]},
                                 event_filter={"category": ["system"], "q": f'"{x["peer"]}"'}))
    return out


async def rule_bgp_peer_flap(ch, now, p):
    out = []
    for x in (await _bgp_report(ch, now, p["window_minutes"]))["peers"]:
        if x["flaps"] < int(p["min_flaps"]):
            continue
        out.append(Detection(group_key=f"{x['firewall_id']}:{x['peer']}", count=x["flaps"], first_seen=now - timedelta(minutes=int(p["window_minutes"])),
                             last_seen=_dt(x["last_event"]) if x["last_event"] else now, firewall_ids=[x["firewall_id"]], dst_ip=x["peer"],
                             explanation=f"BGP neighbor {x['peer']} on {x['firewall_name']} went down {x['flaps']} times in "
                                         f"{p['window_minutes']} min" + (f" (last: {x['last_reason']})" if x["last_reason"] else "") + ".",
                             evidence={"flaps": x["flaps"], "notifications": x["notifications"], "peer": x["peer"]},
                             event_filter={"category": ["system"], "q": f'"{x["peer"]}"'}))
    return out


async def rule_bgp_route_withdrawals(ch, now, p):
    out = []
    for x in (await _bgp_report(ch, now, p["window_minutes"]))["peers"]:
        if x["routes_withdrawn"] < int(p["min_withdrawals"]):
            continue
        out.append(Detection(group_key=f"{x['firewall_id']}:{x['peer']}", count=x["routes_withdrawn"],
                             first_seen=now - timedelta(minutes=int(p["window_minutes"])), last_seen=_dt(x["last_event"]) if x["last_event"] else now,
                             firewall_ids=[x["firewall_id"]], dst_ip=x["peer"],
                             explanation=f"{x['routes_withdrawn']} BGP route withdrawals for neighbor {x['peer']} on {x['firewall_name']} "
                                         f"in {p['window_minutes']} min ({x['routes_added']} announcements).",
                             evidence={"withdrawn": x["routes_withdrawn"], "added": x["routes_added"], "peer": x["peer"]},
                             event_filter={"category": ["system"], "q": f'"{x["peer"]}"'}))
    return out


RULES = {
    "port_scan": rule_port_scan, "denied_burst": rule_denied_burst, "host_sweep": rule_host_sweep,
    "outbound_volume": rule_outbound_volume, "dns_spike": rule_dns_spike, "nxdomain_burst": rule_nxdomain,
    "new_domain": rule_new_domain, "dns_tunnel": rule_dns_tunnel, "admin_login_fail": rule_admin_login_fail,
    "config_change": rule_config_change, "multi_site": rule_multi_site,
    "ti_match": rule_ti_match, "beaconing": rule_beaconing, "volume_baseline": rule_volume_baseline,
    "new_country": rule_new_country, "new_port": rule_new_port, "vpn_bruteforce": rule_vpn_bruteforce,
    "impossible_travel": rule_impossible_travel, "risky_config_change": rule_risky_config_change,
    "isp_outage": rule_isp_outage, "fw_resource_high": rule_fw_resource_high, "fw_reboot": rule_fw_reboot,
    "log_feed_gap": rule_log_feed_gap, "vpn_tunnel_down": rule_vpn_tunnel_down, "peer_anomaly": rule_peer_anomaly, "icmp_down": rule_icmp_down,
    "bgp_peer_down": rule_bgp_peer_down, "bgp_peer_flap": rule_bgp_peer_flap, "bgp_route_withdrawals": rule_bgp_route_withdrawals,
    "bgp_prefix_anomaly": rule_bgp_prefix_anomaly, "bgp_route_leak": rule_bgp_route_leak, "bgp_critical_prefix": rule_bgp_critical_prefix,
    "identity_auth_failures": rule_identity_auth_failures, "identity_success_after_failures": rule_identity_success_after_failures,
    "identity_unusual_login": rule_identity_unusual_login, "admin_account_change": rule_admin_account_change,
    "admin_off_hours_change": rule_admin_off_hours_change,
    "win_bruteforce": rule_win_bruteforce, "win_password_spray": rule_win_password_spray, "win_lockout": rule_win_lockout,
    "win_priv_group": rule_win_priv_group, "win_log_cleared": rule_win_log_cleared, "win_new_service": rule_win_new_service,
}


async def ensure_default_rules(s: AsyncSession) -> None:
    existing = {r.key: r for r in (await s.execute(select(AlertRule))).scalars()}
    for d in DEFAULT_RULES:
        if d["key"] not in existing:
            s.add(AlertRule(**d))
        else:  # add newly introduced params without overwriting tuned ones; keep catalogue metadata current
            r = existing[d["key"]]
            merged = {**d["params"], **(r.params or {})}
            if merged != r.params:
                r.params = merged
            if r.mitre != d["mitre"]:
                r.mitre = d["mitre"]
            r.description = d["description"]
    await s.commit()


async def upsert_detections(s: AsyncSession, rule: AlertRule, detections: list[Detection], now: datetime,
                            touched: list | None = None) -> dict:
    """touched (optional) receives (alert, created: bool) for correlation and notifications."""
    from ..assets import asset_map, bump
    stats = {"created": 0, "updated": 0, "suppressed": 0}
    sups = (await s.execute(select(Suppression).where(Suppression.rule_key == rule.key))).scalars().all()
    active_sup = {x.group_key for x in sups if x.until is None or _dt(x.until) > now}
    dets = detections[:200]
    assets = await asset_map(s, [x for d in dets for x in (d.src_ip, d.dst_ip) if x])
    order = ["low", "normal", "high", "critical"]
    for d in dets:
        if d.group_key in active_sup or "*" in active_sup:
            stats["suppressed"] += 1
            continue
        crit = max((assets[x].criticality for x in (d.src_ip, d.dst_ip) if x in assets), key=lambda c: order.index(c) if c in order else 1, default="")
        rows = (await s.execute(select(Alert).where(Alert.rule_key == rule.key, Alert.group_key == d.group_key)
                                .order_by(Alert.open_seq.desc()).limit(1))).scalars().all()
        latest = rows[0] if rows else None
        if latest and latest.status != "resolved":
            latest.last_seen = max(_dt(latest.last_seen), d.last_seen)
            latest.event_count = max(int(latest.event_count or 0), d.count)
            latest.explanation = d.explanation
            latest.firewall_ids = sorted(set(latest.firewall_ids or []) | set(d.firewall_ids))
            latest.sites = sorted(set(latest.sites or []) | set(d.sites))
            latest.evidence = json.loads(json.dumps(d.evidence, default=str))
            latest.event_filter = {**d.event_filter, "start": _dt(latest.first_seen).isoformat()}
            if not latest.mitre:
                latest.mitre = rule.mitre or RULE_MITRE.get(rule.key, {})
            stats["updated"] += 1
            if touched is not None:
                touched.append((latest, False))
            continue
        if latest and latest.status == "resolved" and _dt(latest.last_seen) >= d.last_seen:
            continue  # same activity that was already resolved
        sev = d.severity or rule.severity
        a = Alert(rule_key=rule.key, name=rule.name, severity=bump(sev, crit), base_severity=sev, asset_criticality=crit,
                  status="new", group_key=d.group_key, open_seq=(latest.open_seq + 1) if latest else 0, src_ip=d.src_ip,
                  dst_ip=d.dst_ip, firewall_ids=d.firewall_ids, sites=d.sites, first_seen=d.first_seen, last_seen=d.last_seen,
                  event_count=d.count, explanation=d.explanation + (" Severity raised: critical asset involved." if bump(sev, crit) != sev else ""),
                  evidence=json.loads(json.dumps(d.evidence, default=str)), mitre=rule.mitre or RULE_MITRE.get(rule.key, {}),
                  event_filter={**d.event_filter, "start": d.first_seen.isoformat()})
        s.add(a)
        stats["created"] += 1
        if touched is not None:
            touched.append((a, True))
    await s.commit()
    return stats


_LAST_RUN: dict[str, datetime] = {}
CUSTOM_PREFIX = "cq_"


def _custom_runner(s: AsyncSession, rule: AlertRule):
    async def fn(ch, now, params):
        from .custom import evaluate
        dets, _ = await evaluate(ch, s, now, params, name=rule.name)
        return dets
    return fn


async def run_rules(ch: ClickHouse, s: AsyncSession, now: datetime | None = None, correlate: bool = True) -> dict:
    now = now or datetime.now(timezone.utc)
    result = {}
    touched: list = []
    rules = (await s.execute(select(AlertRule).where(AlertRule.enabled.is_(True)))).scalars().all()
    for rule in rules:
        fn = RULES.get(rule.key)
        if fn is None and rule.key.startswith(CUSTOM_PREFIX):
            fn = _custom_runner(s, rule)
        if fn is None:
            continue
        params = dict(rule.params or {})
        every = int(params.get("interval_minutes") or (5 if rule.key.startswith(CUSTOM_PREFIX) else 0))
        if every and rule.key in _LAST_RUN and now - _LAST_RUN[rule.key] < timedelta(minutes=every):
            result[rule.key] = {"skipped": "interval"}
            continue
        try:
            dets = await fn(ch, now, params)
            result[rule.key] = await upsert_detections(s, rule, dets, now, touched)
            _LAST_RUN[rule.key] = now
        except Exception as e:
            await s.rollback()
            log.exception("rule %s failed", rule.key)
            result[rule.key] = {"error": str(e)}
    if correlate and touched:
        from ..incidents import correlate_alerts
        from ..notify import alert_created
        inc_events = []
        try:
            inc_events = await correlate_alerts(s, [a for a, _ in touched], now)
            for a, created in touched:
                if created:
                    await alert_created(s, a)
            await s.commit()
        except Exception:
            await s.rollback()
            log.exception("correlation/notification failed")
        from ..automation import run_for_detections
        try:
            n = await run_for_detections(s, touched, inc_events, ch)
            await s.commit()
            if n:
                result["_automation_runs"] = n
        except Exception:
            await s.rollback()
            log.exception("automation failed")
    return result
