"""Network security analytics over Zeek logs (events with category = 'zeek', see ingest/formats.py).

Everything here is an observation with the numbers behind it, never a verdict: a regular connection pattern can be a
software updater, a rare domain a new SaaS tool, a failed certificate check an internal CA Zeek does not know.
Each result says why it is listed so an analyst can judge it. Queries read one bounded time window and are limited.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .assets import internal_cidrs

FAILED_STATES = ("S0", "REJ", "RSTO", "RSTR", "RSTOS0", "RSTRH", "SH", "SHR", "OTH")
STD_PORTS = {"ssh": (22,), "rdp": (3389,), "http": (80, 8080, 8000, 8008, 3128), "ssl": (443, 8443, 993, 995, 465, 636, 853, 5061, 989, 990),
             "dns": (53, 5353, 5355, 853), "smtp": (25, 465, 587), "ftp": (21,), "smb": (445, 139), "ntp": (123,), "dhcp": (67, 68), "krb": (88,),
             "ldap": (389, 636, 3268), "mysql": (3306,), "snmp": (161, 162), "sip": (5060, 5061), "irc": (6667, 6697)}


def _iso(v):
    if isinstance(v, str):
        try:
            v = datetime.fromisoformat(v.replace(" ", "T"))
        except ValueError:
            return v
    if v is None:
        return None
    return (v if v.tzinfo else v.replace(tzinfo=timezone.utc)).isoformat()


def _internal(col: str) -> str:
    return f"((isIPv4String({col}) OR isIPv6String({col})) AND arrayExists(c -> isIPAddressInRange({col}, c), {{cidrs:Array(String)}}))"


def _p(t0: datetime, t1: datetime, **extra) -> dict:
    return {"t0": t0, "t1": t1, "cidrs": internal_cidrs(), **extra}


W = "category = 'zeek' AND event_time >= {t0:DateTime64(3)} AND event_time < {t1:DateTime64(3)}"


async def overview(ch, t0: datetime, t1: datetime) -> dict:
    p = _p(t0, t1)
    logs = await ch.aquery(f"SELECT event_subtype AS log, count() AS n, max(event_time) AS last FROM events WHERE {W} GROUP BY log ORDER BY n DESC", p)
    sensors = await ch.aquery(f"SELECT firewall_name AS sensor, count() AS n, max(event_time) AS last FROM events WHERE {W} GROUP BY sensor ORDER BY n DESC LIMIT 20", p)
    conn = (await ch.aquery(
        f"SELECT count() AS conns, uniqExact(src_ip) AS sources, uniqExact(dst_ip) AS destinations, sum(sent_bytes) AS sent, sum(rcvd_bytes) AS rcvd, "
        f"countIf(action IN {{failed:Array(String)}}) AS failed FROM events WHERE {W} AND event_subtype = 'conn'", {**p, "failed": list(FAILED_STATES)}))[0]
    states = await ch.aquery(f"SELECT action AS state, count() AS n FROM events WHERE {W} AND event_subtype = 'conn' GROUP BY state ORDER BY n DESC LIMIT 15", p)
    services = await ch.aquery(f"SELECT if(service = '', '(not identified)', service) AS service, count() AS n, sum(sent_bytes + rcvd_bytes) AS bytes "
                               f"FROM events WHERE {W} AND event_subtype = 'conn' GROUP BY service ORDER BY n DESC LIMIT 15", p)
    notices = await ch.aquery(f"SELECT threat AS note, count() AS n, uniqExact(src_ip) AS sources, max(event_time) AS last, any(msg) AS sample FROM events "
                              f"WHERE {W} AND event_subtype = 'notice' AND threat != '' GROUP BY note ORDER BY n DESC LIMIT 20", p)
    weird = await ch.aquery(f"SELECT threat AS name, count() AS n, uniqExact(src_ip) AS sources FROM events WHERE {W} AND event_subtype = 'weird' "
                            f"AND threat != '' GROUP BY name ORDER BY n DESC LIMIT 20", p)
    series = await ch.aquery(f"SELECT toStartOfInterval(event_time, toIntervalSecond({{step:UInt32}})) AS t, event_subtype AS log, count() AS n FROM events "
                             f"WHERE {W} GROUP BY t, log ORDER BY t", {**p, "step": max(60, int((t1 - t0).total_seconds() // 48 // 60 * 60) or 60)})
    return {"logs": [{"log": r["log"], "events": int(r["n"]), "last": _iso(r["last"])} for r in logs],
            "sensors": [{"sensor": r["sensor"], "events": int(r["n"]), "last": _iso(r["last"])} for r in sensors],
            "connections": {k: int(conn[k] or 0) for k in ("conns", "sources", "destinations", "sent", "rcvd", "failed")},
            "states": [{"state": r["state"] or "(none)", "count": int(r["n"])} for r in states],
            "services": [{"service": r["service"], "count": int(r["n"]), "bytes": int(r["bytes"])} for r in services],
            "notices": [{"note": r["note"], "count": int(r["n"]), "sources": int(r["sources"]), "last": _iso(r["last"]), "sample": r["sample"]} for r in notices],
            "weird": [{"name": r["name"], "count": int(r["n"]), "sources": int(r["sources"])} for r in weird],
            "timeline": [{"t": _iso(r["t"]), "log": r["log"], "n": int(r["n"])} for r in series],
            "has_data": bool(logs)}


async def scanners(ch, t0: datetime, t1: datetime, min_ports: int = 30, min_hosts: int = 30) -> list[dict]:
    """Sources whose connections mostly failed across many ports or many hosts."""
    rows = await ch.aquery(
        f"SELECT src_ip, {_internal('src_ip')} AS internal, uniqExact(dst_port) AS ports, uniqExact(dst_ip) AS hosts, count() AS attempts, "
        f"countIf(action IN {{failed:Array(String)}}) AS failed, min(event_time) AS first, max(event_time) AS last, "
        f"arraySlice(groupUniqArray(8)(dst_ip), 1, 8) AS sample_hosts FROM events WHERE {W} AND event_subtype = 'conn' AND src_ip != '' "
        f"GROUP BY src_ip HAVING failed >= 0.7 * attempts AND (ports >= {{mp:UInt32}} OR hosts >= {{mh:UInt32}}) ORDER BY failed DESC LIMIT 100",
        {**_p(t0, t1), "failed": list(FAILED_STATES), "mp": min_ports, "mh": min_hosts})
    return [{"src_ip": r["src_ip"], "internal": bool(r["internal"]), "ports": int(r["ports"]), "hosts": int(r["hosts"]), "attempts": int(r["attempts"]),
             "failed": int(r["failed"]), "first": _iso(r["first"]), "last": _iso(r["last"]), "sample_hosts": list(r["sample_hosts"]),
             "kind": "port scan" if int(r["ports"]) >= min_ports and int(r["ports"]) >= int(r["hosts"]) else "host sweep",
             "why": f"{int(r['failed'])} of {int(r['attempts'])} connections were not answered or refused, across {int(r['ports'])} ports and {int(r['hosts'])} hosts"}
            for r in rows]


def beacon_score(intervals_cv: float, size_cv: float, count: int, hours: float) -> int:
    """0-100. Regular timing weighs most (60), then similar sizes (25), then persistence over the window (15)."""
    timing = max(0.0, 1.0 - intervals_cv / 0.5)
    size = max(0.0, 1.0 - size_cv / 0.5)
    persist = min(1.0, count / max(12.0, hours * 2))
    return round(60 * timing + 25 * size + 15 * persist)


async def beacons(ch, t0: datetime, t1: datetime, min_conns: int = 12, max_cv: float = 0.35, limit: int = 100) -> list[dict]:
    """Internal host → external destination pairs that connect at regular intervals. For each: the interval, how
    regular it is (coefficient of variation: 0 = clockwork), how similar the sizes are, and a score built from those."""
    rows = await ch.aquery(
        f"SELECT src_ip, dst_ip, dst_port, any(service) AS service, count() AS n, arraySort(groupArray(toUnixTimestamp(event_time))) AS ts, "
        f"arrayDifference(ts) AS d, arraySlice(d, 2) AS gaps, arrayAvg(gaps) AS mean_gap, "
        f"sqrt(arrayAvg(arrayMap(x -> pow(x - mean_gap, 2), gaps))) AS sd_gap, avg(sent_bytes) AS mean_sent, stddevPop(sent_bytes) AS sd_sent, "
        f"sum(sent_bytes) AS sent, sum(rcvd_bytes) AS rcvd, min(event_time) AS first, max(event_time) AS last "
        f"FROM events WHERE {W} AND event_subtype = 'conn' AND {_internal('src_ip')} AND NOT {_internal('dst_ip')} AND dst_ip != '' "
        f"AND action NOT IN {{failed:Array(String)}} GROUP BY src_ip, dst_ip, dst_port HAVING n BETWEEN {{mn:UInt32}} AND 20000 AND mean_gap >= 20 "
        f"AND sd_gap / mean_gap <= {{cv:Float64}} ORDER BY sd_gap / mean_gap ASC LIMIT {int(limit)}",
        {**_p(t0, t1), "failed": list(FAILED_STATES), "mn": min_conns, "cv": max_cv})
    hours = max(1.0, (t1 - t0).total_seconds() / 3600)
    out = []
    for r in rows:
        mean_gap, cv = float(r["mean_gap"]), float(r["sd_gap"]) / float(r["mean_gap"])
        size_cv = float(r["sd_sent"]) / float(r["mean_sent"]) if float(r["mean_sent"] or 0) > 0 else 1.0
        out.append({"src_ip": r["src_ip"], "dst_ip": r["dst_ip"], "dst_port": int(r["dst_port"] or 0), "service": r["service"], "connections": int(r["n"]),
                    "interval_s": round(mean_gap, 1), "interval_cv": round(cv, 3), "size_cv": round(size_cv, 3), "sent": int(r["sent"]), "rcvd": int(r["rcvd"]),
                    "first": _iso(r["first"]), "last": _iso(r["last"]), "score": beacon_score(cv, size_cv, int(r["n"]), hours),
                    "why": f"{int(r['n'])} connections about every {round(mean_gap)} s (timing variation {round(cv * 100)}%, size variation {round(min(size_cv, 9.99) * 100)}%)"})
    return sorted(out, key=lambda x: -x["score"])


async def dns(ch, t0: datetime, t1: datetime) -> dict:
    p = _p(t0, t1)
    base = f"{W} AND event_subtype = 'dns' AND dns_qname != ''"
    top = await ch.aquery(f"SELECT dns_qname AS name, count() AS n, uniqExact(src_ip) AS clients FROM events WHERE {base} GROUP BY name ORDER BY n DESC LIMIT 25", p)
    # registered domain approximated by the last two labels (three for common two-level suffixes)
    dom = ("if(match(dns_qname, '\\\\.(co|com|org|net|gov|ac|edu)\\\\.[a-z]{2}$'), arrayStringConcat(arraySlice(splitByChar('.', dns_qname), -3), '.'), "
           "arrayStringConcat(arraySlice(splitByChar('.', dns_qname), -2), '.'))")
    rare = await ch.aquery(
        f"SELECT {dom} AS domain, uniqExact(src_ip) AS clients, count() AS n, any(src_ip) AS client, min(event_time) AS first, any(dns_qname) AS sample "
        f"FROM events WHERE {base} AND dns_rcode IN ('NOERROR', '') AND position(dns_qname, '.') > 0 AND NOT endsWith(dns_qname, '.arpa') "
        f"AND NOT endsWith(dns_qname, '.local') GROUP BY domain HAVING clients = 1 AND n <= 20 ORDER BY first DESC LIMIT 50", p)
    nx = await ch.aquery(f"SELECT src_ip, countIf(dns_rcode = 'NXDOMAIN') AS nx, count() AS n, uniqExactIf(dns_qname, dns_rcode = 'NXDOMAIN') AS names FROM events "
                         f"WHERE {base} GROUP BY src_ip HAVING nx >= 20 AND nx >= 0.3 * n ORDER BY nx DESC LIMIT 25", p)
    long_q = await ch.aquery(f"SELECT src_ip, count() AS n, max(dns_qname_len) AS longest, round(avg(dns_entropy), 2) AS entropy, {dom} AS domain FROM events "
                             f"WHERE {base} AND dns_qname_len >= 60 GROUP BY src_ip, domain HAVING n >= 10 ORDER BY n DESC LIMIT 25", p)
    qtypes = await ch.aquery(f"SELECT if(dns_qtype = '', '(none)', dns_qtype) AS qtype, count() AS n FROM events WHERE {base} GROUP BY qtype ORDER BY n DESC LIMIT 12", p)
    return {"top": [{"name": r["name"], "count": int(r["n"]), "clients": int(r["clients"])} for r in top],
            "rare_domains": [{"domain": r["domain"], "client": r["client"], "queries": int(r["n"]), "first": _iso(r["first"]), "sample": r["sample"],
                              "why": "resolved by one host only in this period"} for r in rare],
            "nxdomain": [{"src_ip": r["src_ip"], "nxdomain": int(r["nx"]), "queries": int(r["n"]), "names": int(r["names"]),
                          "why": f"{round(100 * int(r['nx']) / max(1, int(r['n'])))}% of its queries got no such domain"} for r in nx],
            "long_queries": [{"src_ip": r["src_ip"], "domain": r["domain"], "count": int(r["n"]), "longest": int(r["longest"]), "entropy": float(r["entropy"]),
                              "why": "many very long names under one domain (possible data in DNS names; also security / CDN telemetry)"} for r in long_q],
            "qtypes": [{"qtype": r["qtype"], "count": int(r["n"])} for r in qtypes]}


async def tls(ch, t0: datetime, t1: datetime) -> dict:
    p = _p(t0, t1)
    invalid = await ch.aquery(
        f"SELECT hostname AS server_name, dst_ip, threat AS problem, count() AS n, uniqExact(src_ip) AS clients, max(event_time) AS last FROM events "
        f"WHERE {W} AND event_subtype = 'ssl' AND threat != '' GROUP BY server_name, dst_ip, problem ORDER BY n DESC LIMIT 50", p)
    certs = await ch.aquery(f"SELECT threat AS problem, hostname AS name, log_id AS fingerprint, any(msg) AS detail, count() AS n, max(event_time) AS last FROM events "
                            f"WHERE {W} AND event_subtype = 'x509' AND threat != '' GROUP BY problem, name, fingerprint ORDER BY last DESC LIMIT 50", p)
    no_sni = await ch.aquery(f"SELECT src_ip, dst_ip, dst_port, count() AS n FROM events WHERE {W} AND event_subtype = 'ssl' AND hostname = '' "
                             f"AND NOT {_internal('dst_ip')} AND action = 'established' GROUP BY src_ip, dst_ip, dst_port HAVING n >= 5 ORDER BY n DESC LIMIT 25", p)
    top = await ch.aquery(f"SELECT hostname AS server_name, count() AS n, uniqExact(src_ip) AS clients FROM events WHERE {W} AND event_subtype = 'ssl' "
                          f"AND hostname != '' GROUP BY server_name ORDER BY n DESC LIMIT 20", p)
    return {"invalid": [{"server_name": r["server_name"], "dst_ip": r["dst_ip"], "problem": r["problem"], "count": int(r["n"]), "clients": int(r["clients"]),
                         "last": _iso(r["last"])} for r in invalid],
            "certificates": [{"problem": r["problem"], "name": r["name"], "fingerprint": r["fingerprint"], "detail": r["detail"], "count": int(r["n"]),
                              "last": _iso(r["last"])} for r in certs],
            "no_server_name": [{"src_ip": r["src_ip"], "dst_ip": r["dst_ip"], "dst_port": int(r["dst_port"] or 0), "count": int(r["n"]),
                                "why": "TLS to an external address without a server name (direct-to-IP TLS is unusual for browsers)"} for r in no_sni],
            "top": [{"server_name": r["server_name"], "count": int(r["n"]), "clients": int(r["clients"])} for r in top]}


async def unusual_ports(ch, t0: datetime, t1: datetime) -> list[dict]:
    """Protocols Zeek identified by content on ports other than their usual ones (completed connections only)."""
    conds = " OR ".join(f"(service = '{svc}' AND dst_port NOT IN ({', '.join(str(x) for x in ports)}))" for svc, ports in STD_PORTS.items())
    rows = await ch.aquery(
        f"SELECT service, dst_port, {_internal('dst_ip')} AS internal_dst, count() AS n, uniqExact(src_ip) AS sources, uniqExact(dst_ip) AS destinations, "
        f"arraySlice(groupUniqArray(5)(src_ip), 1, 5) AS sample_sources, arraySlice(groupUniqArray(5)(dst_ip), 1, 5) AS sample_destinations FROM events "
        f"WHERE {W} AND event_subtype = 'conn' AND action NOT IN {{failed:Array(String)}} AND ({conds}) GROUP BY service, dst_port, internal_dst "
        f"ORDER BY n DESC LIMIT 50", {**_p(t0, t1), "failed": list(FAILED_STATES)})
    return [{"service": r["service"], "dst_port": int(r["dst_port"] or 0), "direction": "internal" if r["internal_dst"] else "to the internet", "count": int(r["n"]),
             "sources": int(r["sources"]), "destinations": int(r["destinations"]), "sample_sources": list(r["sample_sources"]),
             "sample_destinations": list(r["sample_destinations"])} for r in rows]


async def connection(ch, uid: str, around: datetime | None = None) -> dict:
    """Every Zeek log of one connection (same uid), plus firewall log entries for the same addresses and port within
    five minutes: the sensor's view and the firewall's verdict side by side."""
    now = datetime.now(timezone.utc)
    t0, t1 = ((around - timedelta(days=1), around + timedelta(days=1)) if around else (now - timedelta(days=31), now + timedelta(hours=1)))
    cols = ("event_id, event_time, event_subtype, src_ip, src_port, dst_ip, dst_port, proto_name, service, action, hostname, url, dns_qname, dns_rcode, "
            "threat, sent_bytes, rcvd_bytes, duration, msg, firewall_name, severity")
    logs = await ch.aquery(f"SELECT {cols} FROM events WHERE category = 'zeek' AND event_time >= {{t0:DateTime64(3)}} AND event_time < {{t1:DateTime64(3)}} "
                           f"AND log_id = {{uid:String}} ORDER BY event_time LIMIT 200", {"t0": t0, "t1": t1, "uid": uid})
    for r in logs:
        r["event_time"] = _iso(r["event_time"])
    conn = next((r for r in logs if r["event_subtype"] == "conn"), logs[0] if logs else None)
    fw = []
    if conn and conn["src_ip"] and conn["dst_ip"]:
        ct = datetime.fromisoformat(conn["event_time"])
        fw = await ch.aquery(
            "SELECT event_id, event_time, category, firewall_name, action, policy_id, policy_name, src_ip, src_port, dst_ip, dst_port, app, threat, sent_bytes, "
            "rcvd_bytes, nat_src_ip FROM events WHERE category IN ('traffic', 'security', 'web', 'dns') AND event_time >= {a:DateTime64(3)} AND event_time < {b:DateTime64(3)} "
            "AND src_ip = {s:String} AND dst_ip = {d:String} AND (dst_port = {dp:UInt16} OR {dp:UInt16} = 0) ORDER BY event_time LIMIT 50",
            {"a": ct - timedelta(minutes=5), "b": ct + timedelta(minutes=5), "s": conn["src_ip"], "d": conn["dst_ip"], "dp": int(conn["dst_port"] or 0)})
        for r in fw:
            r["event_time"] = _iso(r["event_time"])
    return {"uid": uid, "logs": logs, "firewall": fw,
            "summary": None if not conn else {"src_ip": conn["src_ip"], "dst_ip": conn["dst_ip"], "dst_port": conn["dst_port"], "service": conn["service"],
                                              "state": conn["action"], "logs": sorted({r["event_subtype"] for r in logs}),
                                              "firewall_verdicts": sorted({r["action"] for r in fw if r["action"]})}}
