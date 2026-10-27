"""Database-side aggregations for dashboards, top-N pages, web/DNS analytics, explorer and investigations."""
import asyncio
import socket
from datetime import datetime, timedelta, timezone
from functools import lru_cache

from ..db.ch import ClickHouse
from .filters import ALLOWED, DENIED, EventFilter, bucket_seconds, build_where, table

ALLOWED_SQL = "(" + ",".join(f"'{a}'" for a in ALLOWED) + ")"
DENIED_SQL = "(" + ",".join(f"'{a}'" for a in DENIED) + ")"
LIMITS = (10, 25, 50, 100)

EVENT_LIST_COLUMNS = ("event_id, event_time, category, event_type, event_subtype, firewall_id, firewall_name, site, source, "
                      "severity, src_ip, src_port, dst_ip, dst_port, proto_name, action, policy_id, app, service, hostname, "
                      "url, url_is_full, dns_qname, dns_qtype, dns_rcode, sent_bytes, rcvd_bytes, threat, user, msg, "
                      "src_country, dst_country, src_name, ti_match, ti_category")


def _limit(n: int) -> int:
    return n if n in LIMITS else min(LIMITS, key=lambda x: abs(x - n))


def _iso(v):
    if isinstance(v, datetime):
        return v.replace(tzinfo=timezone.utc).isoformat() if v.tzinfo is None else v.astimezone(timezone.utc).isoformat()
    if isinstance(v, str) and len(v) >= 19 and v[4] == "-" and v[10] == " ":
        return v.replace(" ", "T") + "Z"
    return v


def _clean(rows: list[dict]) -> list[dict]:
    return [{k: _iso(v) for k, v in r.items()} for r in rows]


# Zero-fill every bucket of the requested window so charts show real gaps instead of compressing
# sparse buckets onto a category axis (a single bucket used to render as one full-width bar).
FILL = ("ORDER BY t WITH FILL FROM toStartOfInterval(toDateTime({t0:DateTime64(3)}, 'UTC'), toIntervalSecond({b:UInt32})) "
        "TO toDateTime({t1:DateTime64(3)}, 'UTC') STEP toIntervalSecond({b:UInt32})")


# ---------------------------------------------------------------- rollup routing
# events_1m holds per-minute counts/bytes by (category, firewall, site, action, source). Queries whose filters only
# touch those dimensions read whole minutes from the rollup and the partial minutes at both window edges from raw
# events, so results are exact while scanning thousands of rows instead of millions.
ROLLUP_FIELDS = {"start", "end", "range", "firewall_id", "site", "category", "action", "verdict", "source"}  # ql forces raw


def rollup_eligible(f: EventFilter) -> bool:
    for name, value in vars(f).items():
        if name not in ROLLUP_FIELDS and value not in (None, "", [], ()):
            return False
    return True


def _minute_edges(t0: datetime, t1: datetime) -> tuple[datetime, datetime]:
    c0 = t0.replace(second=0, microsecond=0)
    if c0 < t0:
        c0 += timedelta(minutes=1)
    c1 = t1.replace(second=0, microsecond=0)
    return c0, c1


def _rollup_where(f: EventFilter, categories: tuple[str, ...] | None, c0: datetime, c1: datetime) -> tuple[str, dict]:
    p: dict = {"r0": c0, "r1": c1}
    c = ["minute >= toDateTime({r0:DateTime64(3)}, 'UTC')", "minute < toDateTime({r1:DateTime64(3)}, 'UTC')"]
    cats = [x for x in (f.category or categories or []) if not categories or x in categories] or list(categories or [])
    if f.category and categories and not cats:
        cats = ["__none__"]
    if cats:
        p["rcats"] = cats
        c.append("category IN {rcats:Array(String)}")
    if f.firewall_id:
        p["rfw"] = [int(x) for x in f.firewall_id]
        c.append("firewall_id IN {rfw:Array(UInt32)}")
    if f.site:
        p["rsites"] = f.site
        c.append("site IN {rsites:Array(String)}")
    if f.action:
        p["racts"] = f.action
        c.append("action IN {racts:Array(String)}")
    if f.verdict == "allowed":
        c.append(f"action IN {ALLOWED_SQL}")
    elif f.verdict == "denied":
        c.append(f"action IN {DENIED_SQL}")
    if f.source:
        p["rsrc"] = f.source
        c.append("source = {rsrc:String}")
    return " AND ".join(c), p


async def _hybrid(ch: ClickHouse, f: EventFilter, categories: tuple[str, ...] | None, aggs: list[tuple[str, str, str]],
                  bucket: int | None) -> list[dict]:
    """aggs: (alias, rollup_expr, raw_expr). bucket=None returns one totals row; otherwise a zero-filled series."""
    t0, t1 = f.window()
    c0, c1 = _minute_edges(t0, t1)
    raw_where, p = build_where(f, categories=categories)
    use_rollup = c0 < c1
    if use_rollup:
        rw, rp = _rollup_where(f, categories, c0, c1)
        p.update(rp)
        p.update({"c0": c0, "c1": c1})
        raw_where += " AND (event_time < {c0:DateTime64(3)} OR event_time >= {c1:DateTime64(3)})"
    if bucket:
        p["b"] = bucket
        tr = "toStartOfInterval(minute, toIntervalSecond({b:UInt32})) AS t, "
        tw = "toStartOfInterval(toDateTime(event_time, 'UTC'), toIntervalSecond({b:UInt32})) AS t, "
        group = " GROUP BY t"
    else:
        tr = tw = group = ""
    # inner aliases are prefixed so they never shadow source columns (events_1m has a column named `events`)
    raw_sel = f"SELECT {tw}" + ", ".join(f"{raw} AS x_{a}" for a, _, raw in aggs) + f" FROM events WHERE {raw_where}{group}"
    parts = [raw_sel]
    if use_rollup:
        parts.append(f"SELECT {tr}" + ", ".join(f"{r} AS x_{a}" for a, r, _ in aggs) + f" FROM events_1m WHERE {rw}{group}")
    outer = ", ".join(f"sum(x_{a}) AS {a}" for a, _, _ in aggs)
    sql = f"SELECT {'t, ' if bucket else ''}{outer} FROM ({' UNION ALL '.join(parts)})"
    sql += f" GROUP BY t {FILL}" if bucket else ""
    return _clean(await ch.aquery(sql, p))


TRAFFIC_AGGS = [
    ("events", "sum(events)", "count()"),
    ("allowed", f"sumIf(events, action IN {ALLOWED_SQL})", f"countIf(action IN {ALLOWED_SQL})"),
    ("denied", f"sumIf(events, action IN {DENIED_SQL})", f"countIf(action IN {DENIED_SQL})"),
    ("bytes_sent", "sum(bytes_sent)", "sum(sent_bytes)"),
    ("bytes_rcvd", "sum(bytes_rcvd)", "sum(rcvd_bytes)"),
]
ACTION_EXTRAS = {  # extras the rollup can answer (action-based); anything else falls back to raw
    "blocked": (f"sumIf(events, action IN {DENIED_SQL})", f"countIf(action IN {DENIED_SQL})"),
    "allowed": (f"sumIf(events, action IN {ALLOWED_SQL})", f"countIf(action IN {ALLOWED_SQL})"),
}


async def data_start(ch: ClickHouse, categories: tuple[str, ...]) -> str | None:
    """Earliest stored event for the categories (independent of the time filter): buckets before this are
    'not collected yet', not 'zero events'."""
    rows = await ch.aquery(f"SELECT min(event_time) AS m, count() AS n FROM {table()} WHERE category IN {{c:Array(String)}}",
                           {"c": list(categories)})
    if not rows or not int(rows[0]["n"]):
        return None
    return _iso(rows[0]["m"])


async def coverage(ch: ClickHouse) -> dict:
    rows = await ch.aquery(f"SELECT category, min(event_time) AS first_event, max(event_time) AS last_event, "
                           f"max(ingest_time) AS last_ingest, count() AS events, groupUniqArray(source) AS sources "
                           f"FROM {table()} GROUP BY category")
    return {r["category"]: _clean([r])[0] for r in rows}


KPI_COUNT_AGGS = [
    ("traffic_events", "sumIf(events, category='traffic')", "countIf(category='traffic')"),
    ("bytes_total", "sumIf(bytes_sent + bytes_rcvd, category='traffic')", "sumIf(sent_bytes + rcvd_bytes, category='traffic')"),
    ("allowed_events", f"sumIf(events, category='traffic' AND action IN {ALLOWED_SQL})", f"countIf(category='traffic' AND action IN {ALLOWED_SQL})"),
    ("denied_events", f"sumIf(events, category='traffic' AND action IN {DENIED_SQL})", f"countIf(category='traffic' AND action IN {DENIED_SQL})"),
    ("dns_queries", "sumIf(events, category='dns')", "countIf(category='dns')"),
    ("url_blocks", "sumIf(events, category='web' AND action = 'block')", "countIf(category='web' AND action = 'block')"),
    ("security_events", "sumIf(events, category='security')", "countIf(category='security')"),
]


async def kpis(ch: ClickHouse, f: EventFilter) -> dict:
    """Counts come from the rollup when possible (exact); distinct counts scan raw events. Session counts use
    uniqCombined64 (HyperLogLog-style, ~1% error) because exact distinct counting of tens of millions of
    session IDs is too memory-intensive for an interactive dashboard."""
    where, p = build_where(f)
    uniq_sql = f"""
    SELECT
      uniqCombined64If((firewall_id, session_id), category='traffic' AND session_id IS NOT NULL) AS sessions,
      uniqExactIf(src_ip, category='traffic' AND src_ip != '') AS unique_src,
      uniqExactIf(dst_ip, category='traffic' AND dst_ip != '') AS unique_dst,
      uniqCombined64If((firewall_id, session_id), category='traffic' AND session_id IS NOT NULL AND action IN {ALLOWED_SQL}) AS allowed_sessions,
      uniqCombined64If((firewall_id, session_id), category='traffic' AND session_id IS NOT NULL AND action IN {DENIED_SQL}) AS denied_sessions,
      uniqCombined64If(dns_qname, category='dns' AND dns_qname != '') AS unique_domains,
      max(ingest_time) AS last_ingest
    FROM {table()} WHERE {where}"""
    if rollup_eligible(f):
        counts, uniq = await asyncio.gather(_hybrid(ch, f, None, KPI_COUNT_AGGS, None), ch.aquery(uniq_sql, p))
        out = {**(counts[0] if counts else {}), **(_clean(uniq)[0] if uniq else {})}
    else:
        count_sql = "SELECT " + ", ".join(f"{raw} AS {a}" for a, _, raw in KPI_COUNT_AGGS) + f" FROM {table()} WHERE {where}"
        counts, uniq = await asyncio.gather(ch.aquery(count_sql, p), ch.aquery(uniq_sql, p))
        out = {**(_clean(counts)[0] if counts else {}), **(_clean(uniq)[0] if uniq else {})}
    out["approximate"] = ["sessions", "allowed_sessions", "denied_sessions", "unique_domains"]
    return out


async def traffic_timeseries(ch: ClickHouse, f: EventFilter) -> dict:
    start, end = f.window()
    b = bucket_seconds(start, end)
    if b >= 60 and rollup_eligible(f):
        points = await _hybrid(ch, f, ("traffic",), TRAFFIC_AGGS, b)
    else:
        where, p = build_where(f, categories=("traffic",))
        p["b"] = b
        sql = f"""
        SELECT toStartOfInterval(event_time, toIntervalSecond({{b:UInt32}})) AS t,
               count() AS events,
               countIf(action IN {ALLOWED_SQL}) AS allowed,
               countIf(action IN {DENIED_SQL}) AS denied,
               sum(sent_bytes) AS bytes_sent, sum(rcvd_bytes) AS bytes_rcvd
        FROM {table()} WHERE {where} GROUP BY t {FILL}"""
        points = _clean(await ch.aquery(sql, p))
    return {"bucket_seconds": b, "points": points, "data_start": await data_start(ch, ("traffic",))}


async def category_timeseries(ch: ClickHouse, f: EventFilter, category: str, extra_counts: dict[str, str] | None = None) -> dict:
    start, end = f.window()
    b = bucket_seconds(start, end)
    extra_counts = extra_counts or {}
    if b >= 60 and rollup_eligible(f) and all(k in ACTION_EXTRAS for k in extra_counts):
        aggs = [("events", "sum(events)", "count()")] + [(k, *ACTION_EXTRAS[k]) for k in extra_counts]
        points = await _hybrid(ch, f, (category,), aggs, b)
    else:
        where, p = build_where(f, categories=(category,))
        p["b"] = b
        extras = "".join(f", countIf({expr}) AS {name}" for name, expr in extra_counts.items())
        sql = f"""SELECT toStartOfInterval(event_time, toIntervalSecond({{b:UInt32}})) AS t, count() AS events{extras}
                  FROM {table()} WHERE {where} GROUP BY t {FILL}"""
        points = _clean(await ch.aquery(sql, p))
    return {"bucket_seconds": b, "points": points, "data_start": await data_start(ch, (category,))}


DIMENSIONS = {
    "src_ip": ("src_ip", "src_ip != ''"),
    "dst_ip": ("dst_ip", "dst_ip != ''"),
    "dst_port": ("dst_port", "dst_port IS NOT NULL"),
    "proto": ("proto_name", "proto_name != ''"),
    "app": ("app", "app != ''"),
    "service": ("service", "service != ''"),
    "hostname": ("lower(hostname)", "hostname != ''"),
    "dns_qname": ("dns_qname", "dns_qname != ''"),
    "dns_domain": ("cutToFirstSignificantSubdomain(dns_qname)", "dns_qname != ''"),
    "dns_qtype": ("dns_qtype", "dns_qtype != ''"),
    "dns_server": ("dst_ip", "dst_ip != ''"),
    "dns_rcode": ("dns_rcode", "dns_rcode != ''"),
    "url_category": ("url_category", "url_category != ''"),
    "severity": ("severity", "severity != ''"),
    "event_subtype": ("event_subtype", "event_subtype != ''"),
    "threat": ("threat", "threat != ''"),
    "policy_id": ("policy_id", "policy_id IS NOT NULL"),
    "firewall": ("firewall_name", "firewall_name != ''"),
    "action": ("action", "action != ''"),
}
METRICS = {"count": "count()", "bytes": "sum(sent_bytes + rcvd_bytes)", "unique_src": "uniqExact(src_ip)",
           "denied": f"countIf(action IN {DENIED_SQL})"}


async def top(ch: ClickHouse, f: EventFilter, dimension: str, *, category: str | None = None, metric: str = "count",
              limit: int = 10) -> list[dict]:
    if dimension not in DIMENSIONS or metric not in METRICS:
        raise ValueError("invalid dimension or metric")
    expr, nonempty = DIMENSIONS[dimension]
    where, p = build_where(f, extra=[nonempty], categories=(category,) if category else None)
    sql = f"""SELECT {expr} AS key, count() AS events, sum(sent_bytes + rcvd_bytes) AS bytes, {METRICS[metric]} AS value
              FROM {table()} WHERE {where} GROUP BY key ORDER BY value DESC LIMIT {_limit(limit)}"""
    return _clean(await ch.aquery(sql, p))


SORTS = {"count": "events", "bytes": "bytes_total", "unique": "uniq_peer", "denied": "denied"}


async def top_sources(ch: ClickHouse, f: EventFilter, sort: str = "count", limit: int = 25) -> list[dict]:
    where, p = build_where(f, extra=["src_ip != ''"], categories=("traffic",))
    sql = f"""
    SELECT src_ip, count() AS events,
           uniqExactIf(session_id, session_id IS NOT NULL) AS sessions,
           uniqExact(dst_ip) AS uniq_peer, uniqExact(dst_port) AS uniq_dst_ports,
           sum(sent_bytes) AS bytes_sent, sum(rcvd_bytes) AS bytes_rcvd, sum(sent_bytes + rcvd_bytes) AS bytes_total,
           countIf(action IN {DENIED_SQL}) AS denied,
           topK(3)(dst_ip) AS top_destinations,
           groupUniqArray(5)(firewall_name) AS firewalls, groupUniqArray(5)(site) AS sites
    FROM {table()} WHERE {where} GROUP BY src_ip ORDER BY {SORTS.get(sort, 'events')} DESC LIMIT {_limit(limit)}"""
    return _clean(await ch.aquery(sql, p))


@lru_cache(maxsize=4096)
def _ptr(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return None


async def reverse_dns(ips: list[str], timeout: float = 2.0) -> dict[str, str | None]:
    async def one(ip):
        try:
            return ip, await asyncio.wait_for(asyncio.to_thread(_ptr, ip), timeout)
        except asyncio.TimeoutError:
            return ip, None
    return dict(await asyncio.gather(*(one(i) for i in ips)))


async def top_destinations(ch: ClickHouse, f: EventFilter, sort: str = "count", limit: int = 25, rdns: bool = False) -> list[dict]:
    where, p = build_where(f, extra=["dst_ip != ''"], categories=("traffic",))
    sql = f"""
    SELECT dst_ip, count() AS events, uniqExact(src_ip) AS uniq_peer,
           sum(sent_bytes + rcvd_bytes) AS bytes_total, countIf(action IN {DENIED_SQL}) AS denied,
           topKIf(3)(dst_port, dst_port IS NOT NULL) AS top_ports,
           topKIf(3)(app, app != '') AS top_apps,
           groupUniqArray(5)(firewall_name) AS firewalls, groupUniqArray(5)(site) AS sites
    FROM {table()} WHERE {where} GROUP BY dst_ip ORDER BY {SORTS.get(sort, 'events')} DESC LIMIT {_limit(limit)}"""
    rows = _clean(await ch.aquery(sql, p))
    if rdns and rows:
        names = await reverse_dns([r["dst_ip"] for r in rows])
        for r in rows:
            r["ptr"] = names.get(r["dst_ip"])
    return rows


async def top_ports(ch: ClickHouse, f: EventFilter, sort: str = "count", limit: int = 25) -> list[dict]:
    where, p = build_where(f, extra=["dst_port IS NOT NULL"], categories=("traffic",))
    sql = f"""
    SELECT dst_port, proto_name, topKIf(1)(service, service != '') AS top_service,
           count() AS events, uniqExactIf(session_id, session_id IS NOT NULL) AS sessions,
           uniqExact(src_ip) AS uniq_peer, uniqExact(dst_ip) AS uniq_dst,
           sum(sent_bytes + rcvd_bytes) AS bytes_total,
           countIf(action IN {ALLOWED_SQL}) AS allowed, countIf(action IN {DENIED_SQL}) AS denied
    FROM {table()} WHERE {where} GROUP BY dst_port, proto_name ORDER BY {SORTS.get(sort, 'events')} DESC LIMIT {_limit(limit)}"""
    rows = _clean(await ch.aquery(sql, p))
    for r in rows:
        top_service = r.pop("top_service", None)
        r["service"] = top_service[0] if top_service else None  # as logged by FortiGate, never inferred from port
    return rows


# ---------------------------------------------------------------- web
async def web_summary(ch: ClickHouse, f: EventFilter, limit: int = 25) -> dict:
    where, p = build_where(f, categories=("web",))
    lim = _limit(limit)
    q_urls = f"""SELECT lower(hostname) AS hostname, url, url_is_full, count() AS events,
                 countIf(action='block') AS blocked, uniqExact(src_ip) AS clients, any(url_category) AS url_cat
                 FROM {table()} WHERE {where} AND (url != '' OR hostname != '')
                 GROUP BY hostname, url, url_is_full ORDER BY events DESC LIMIT {lim}"""
    q_dom = f"""SELECT cutToFirstSignificantSubdomain(lower(hostname)) AS domain, count() AS events,
                countIf(action='block') AS blocked, uniqExact(src_ip) AS clients
                FROM {table()} WHERE {where} AND hostname != '' GROUP BY domain ORDER BY events DESC LIMIT {lim}"""
    q_src = f"""SELECT src_ip, count() AS events, countIf(action='block') AS blocked, uniqExact(hostname) AS hosts
                FROM {table()} WHERE {where} AND src_ip != '' GROUP BY src_ip ORDER BY events DESC LIMIT {lim}"""
    q_cat = f"""SELECT if(url_category='', '(uncategorized)', url_category) AS cat_name, count() AS events,
                countIf(action='block') AS blocked FROM {table()} WHERE {where} GROUP BY cat_name ORDER BY events DESC LIMIT 30"""
    q_tot = f"""SELECT count() AS events, countIf(action='block') AS blocked, countIf(action IN {ALLOWED_SQL}) AS allowed,
                countIf(url_is_full=1) AS full_urls, countIf(url_is_full=0 AND url != '') AS path_only,
                countIf(url = '' AND hostname != '') AS hostname_only FROM {table()} WHERE {where}"""
    urls, doms, srcs, cats, tot = await asyncio.gather(*(ch.aquery(q, p) for q in (q_urls, q_dom, q_src, q_cat, q_tot)))
    ts = await category_timeseries(ch, f, "web", {"blocked": "action='block'", "allowed": f"action IN {ALLOWED_SQL}"})
    return {"totals": _clean(tot)[0] if tot else {}, "top_urls": _clean(urls), "top_domains": _clean(doms),
            "top_sources": _clean(srcs), "categories": _clean(cats), "timeseries": ts}


# ---------------------------------------------------------------- dns
async def dns_summary(ch: ClickHouse, f: EventFilter, limit: int = 25) -> dict:
    where, p = build_where(f, categories=("dns",))
    lim = _limit(limit)
    qs = {
        "top_domains": f"SELECT dns_qname AS key, count() AS events, uniqExact(src_ip) AS clients FROM {table()} WHERE {where} AND dns_qname != '' GROUP BY key ORDER BY events DESC LIMIT {lim}",
        "top_clients": f"SELECT src_ip AS key, count() AS events, uniqExact(dns_qname) AS domains, countIf(dns_rcode='NXDOMAIN') AS nxdomain FROM {table()} WHERE {where} AND src_ip != '' GROUP BY key ORDER BY events DESC LIMIT {lim}",
        "top_qtypes": f"SELECT dns_qtype AS key, count() AS events FROM {table()} WHERE {where} AND dns_qtype != '' GROUP BY key ORDER BY events DESC LIMIT 20",
        "top_servers": f"SELECT dst_ip AS key, count() AS events, uniqExact(src_ip) AS clients FROM {table()} WHERE {where} AND dst_ip != '' GROUP BY key ORDER BY events DESC LIMIT {lim}",
        "blocked": f"SELECT dns_qname AS key, count() AS events, uniqExact(src_ip) AS clients, any(url_category) AS url_cat FROM {table()} WHERE {where} AND action IN {DENIED_SQL} GROUP BY key ORDER BY events DESC LIMIT {lim}",
        "totals": f"SELECT count() AS queries, uniqExact(dns_qname) AS domains, uniqExact(src_ip) AS clients, countIf(dns_rcode='NXDOMAIN') AS nxdomain, countIf(action IN {DENIED_SQL}) AS blocked, countIf(dns_rcode != '') AS with_rcode FROM {table()} WHERE {where}",
    }
    keys = list(qs)
    res = await asyncio.gather(*(ch.aquery(qs[k], p) for k in keys))
    out = {k: _clean(v) for k, v in zip(keys, res)}
    out["totals"] = out["totals"][0] if out["totals"] else {}
    out["timeseries"] = await category_timeseries(ch, f, "dns", {"nxdomain": "dns_rcode='NXDOMAIN'", "blocked": f"action IN {DENIED_SQL}"})
    return out


async def dns_indicators(ch: ClickHouse, f: EventFilter, *, repeat_threshold: int = 100, long_qname: int = 52,
                         entropy: float = 3.8, z: float = 3.0, limit: int = 25) -> dict:
    """Heuristic indicators. These require analyst investigation; they are not proof of malicious activity."""
    where, p = build_where(f, categories=("dns",))
    lim = _limit(limit)
    p.update({"rt": repeat_threshold, "lq": long_qname, "ent": entropy, "z": z})
    q_repeat = f"""SELECT src_ip, dns_qname, count() AS events FROM {table()} WHERE {where} AND dns_qname != ''
                   GROUP BY src_ip, dns_qname HAVING events >= {{rt:UInt32}} ORDER BY events DESC LIMIT {lim}"""
    q_tunnel = f"""SELECT src_ip, cutToFirstSignificantSubdomain(dns_qname) AS domain, count() AS events,
                   uniqExact(dns_qname) AS unique_names, max(dns_qname_len) AS max_len, round(avg(dns_entropy), 2) AS avg_entropy,
                   any(dns_qname) AS example
                   FROM {table()} WHERE {where} AND (dns_qname_len >= {{lq:UInt16}} OR dns_entropy >= {{ent:Float32}})
                   GROUP BY src_ip, domain ORDER BY unique_names DESC LIMIT {lim}"""
    q_volume = f"""WITH per AS (SELECT src_ip, count() AS c FROM {table()} WHERE {where} AND src_ip != '' GROUP BY src_ip),
                   st AS (SELECT avg(c) AS mu, stddevPop(c) AS sd, count() AS n FROM per)
                   SELECT src_ip, c AS events, round(st.mu, 1) AS mean, round(st.sd, 1) AS stddev,
                          round((c - st.mu) / nullIf(st.sd, 0), 2) AS zscore
                   FROM per CROSS JOIN st WHERE st.n >= 5 AND st.sd > 0 AND (c - st.mu) / st.sd >= {{z:Float32}}
                   ORDER BY events DESC LIMIT {lim}"""
    rep, tun, vol = await asyncio.gather(ch.aquery(q_repeat, p), ch.aquery(q_tunnel, p), ch.aquery(q_volume, p))
    return {"repeated_queries": _clean(rep), "tunneling_indicators": _clean(tun), "unusual_volume": _clean(vol),
            "note": "Indicators require investigation and are not definitive evidence of malicious activity."}


# ---------------------------------------------------------------- security
async def security_summary(ch: ClickHouse, f: EventFilter) -> dict:
    where, p = build_where(f, categories=("security", "system"))
    q1 = f"SELECT severity, event_subtype, count() AS events FROM {table()} WHERE {where} GROUP BY severity, event_subtype ORDER BY events DESC LIMIT 200"
    q2 = f"""SELECT threat, event_subtype, severity, count() AS events, uniqExact(src_ip) AS sources
             FROM {table()} WHERE {where} AND threat != '' GROUP BY threat, event_subtype, severity ORDER BY events DESC LIMIT 25"""
    a, b = await asyncio.gather(ch.aquery(q1, p), ch.aquery(q2, p))
    return {"by_severity_type": _clean(a), "top_threats": _clean(b)}


# ---------------------------------------------------------------- explorer
SORTABLE = {"event_time", "src_ip", "dst_ip", "dst_port", "sent_bytes", "rcvd_bytes", "severity", "action"}


async def list_events(ch: ClickHouse, f: EventFilter, page: int = 1, size: int = 50, sort: str = "event_time",
                      order: str = "desc") -> dict:
    size = max(1, min(size, 500))
    page = max(1, min(page, 10_000))
    where, p = build_where(f)
    col = sort if sort in SORTABLE else "event_time"
    direction = "ASC" if order == "asc" else "DESC"
    p.update({"lim": size, "off": (page - 1) * size})
    rows, total = await asyncio.gather(
        ch.aquery(f"SELECT {EVENT_LIST_COLUMNS} FROM {table()} WHERE {where} ORDER BY {col} {direction}, event_id "
                  f"LIMIT {{lim:UInt32}} OFFSET {{off:UInt32}}", p),
        ch.aquery(f"SELECT count() AS n FROM {table()} WHERE {where}", p),
    )
    return {"items": _clean(rows), "total": int(total[0]["n"]) if total else 0, "page": page, "size": size}


async def get_event(ch: ClickHouse, event_id: str) -> dict | None:
    rows = await ch.aquery(f"SELECT * FROM {table()} WHERE event_id = {{id:String}} LIMIT 1", {"id": event_id})
    return _clean(rows)[0] if rows else None


async def export_rows(ch: ClickHouse, f: EventFilter, max_rows: int = 100_000) -> list[dict]:
    where, p = build_where(f)
    p["lim"] = max_rows
    return _clean(await ch.aquery(f"SELECT {EVENT_LIST_COLUMNS} FROM {table()} WHERE {where} ORDER BY event_time DESC LIMIT {{lim:UInt32}}", p))


async def investigate_ip(ch: ClickHouse, f: EventFilter, ip: str) -> dict:
    f.ip = None
    f.src_ip = ip
    base_traffic = build_where(f, categories=("traffic",))
    where_any, p_any = build_where(EventFilter(start=f.window()[0], end=f.window()[1], ip=ip, firewall_id=f.firewall_id))
    w, p = base_traffic
    wd, pd = build_where(f, categories=("dns",))
    ww, pw = build_where(f, categories=("web",))
    qs = {
        "summary": (f"""SELECT count() AS events, countIf(category='traffic') AS traffic, countIf(category='dns') AS dns,
                        countIf(category='web') AS web, countIf(category IN ('security','system')) AS security,
                        countIf(category='traffic' AND action IN {ALLOWED_SQL}) AS allowed,
                        countIf(category='traffic' AND action IN {DENIED_SQL}) AS denied,
                        sumIf(sent_bytes, src_ip={{anyip:String}}) AS bytes_sent, sumIf(rcvd_bytes, src_ip={{anyip:String}}) AS bytes_rcvd,
                        min(event_time) AS first_seen, max(event_time) AS last_seen,
                        groupUniqArray(10)(firewall_name) AS firewalls, groupUniqArray(10)(site) AS sites
                        FROM {table()} WHERE {where_any}""", p_any),
        "top_destinations": (f"SELECT dst_ip AS key, count() AS events, sum(sent_bytes+rcvd_bytes) AS bytes, countIf(action IN {DENIED_SQL}) AS denied FROM {table()} WHERE {w} AND dst_ip != '' GROUP BY key ORDER BY events DESC LIMIT 25", p),
        "top_ports": (f"SELECT dst_port AS key, proto_name, count() AS events, countIf(action IN {DENIED_SQL}) AS denied FROM {table()} WHERE {w} AND dst_port IS NOT NULL GROUP BY key, proto_name ORDER BY events DESC LIMIT 25", p),
        "dns_history": (f"SELECT dns_qname AS key, any(dns_qtype) AS qtype, count() AS events, max(event_time) AS last_seen, countIf(dns_rcode='NXDOMAIN') AS nxdomain FROM {table()} WHERE {wd} AND dns_qname != '' GROUP BY key ORDER BY events DESC LIMIT 50", pd),
        "url_history": (f"SELECT lower(hostname) AS hostname, url, url_is_full, count() AS events, countIf(action='block') AS blocked, max(event_time) AS last_seen FROM {table()} WHERE {ww} GROUP BY hostname, url, url_is_full ORDER BY events DESC LIMIT 50", pw),
    }
    keys = list(qs)
    res = await asyncio.gather(*(ch.aquery(sql, params) for sql, params in qs.values()))
    out = {k: _clean(v) for k, v in zip(keys, res)}
    out["summary"] = out["summary"][0] if out["summary"] else {}
    out["timeseries"] = await traffic_timeseries(ch, f)
    return out
