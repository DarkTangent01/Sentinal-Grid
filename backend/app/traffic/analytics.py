"""Read models for the Application & Protocol Intelligence API. Every function is bounded (window ≤ 30 days, LIMIT ≤
500, pagination offset ≤ 100 000) and reads raw records only for windows up to six hours (query.RAW_HOURS).

Figures are estimates when the data was sampled: sFlow and sampled NetFlow / IPFIX records are already multiplied by
the sampling rate. Each response says which source answered ("raw records" / "hourly rollups") and how much of the
traffic was sampled.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import Alert, Firewall, Switch, SwitchInterface, SwitchVlan, TrafficVlanPolicy
from . import enrich as E
from . import networks as N
from . import registry as R
from .query import Ctx, Filters, Sql, aggregate, choose, sort_clause
from .settings import load_settings

SOURCE_LABEL = {"raw": "raw records", "conv": "hourly rollups (conversations)", "ifh": "hourly rollups (interfaces)"}
_CACHE: dict = {}
CACHE_SECONDS = 20.0
CACHE_MAX = 256


async def context(s: AsyncSession) -> Ctx:
    st = await load_settings(s)
    ia = _CACHE.get(("ip_apps",))
    if not ia or time.monotonic() - ia[0] > 60:
        ia = (time.monotonic(), await E.ip_apps(s))
        _CACHE[("ip_apps",)] = ia
    return Ctx(reg=await R.load(s), nets=await N.load(s), ip_apps=ia[1], dedup=st.get("dedup") != "none")


async def cached(key: tuple, fn):
    hit = _CACHE.get(key)
    if hit and time.monotonic() - hit[0] < CACHE_SECONDS:
        return hit[1]
    val = await fn()
    if len(_CACHE) > CACHE_MAX:
        for k in sorted(_CACHE, key=lambda k: _CACHE[k][0])[: CACHE_MAX // 4]:
            _CACHE.pop(k, None)
    _CACHE[key] = (time.monotonic(), val)
    return val


def clear_cache() -> None:
    _CACHE.clear()


def _span(f: Filters) -> float:
    t0, t1 = f.window()
    return max(1.0, (t1 - t0).total_seconds())


def trend_bucket(f: Filters, src: str) -> int:
    span = _span(f)
    b = 60 if span <= 3600 else 300 if span <= 6 * 3600 else 1800 if span <= 86400 else 10800 if span <= 7 * 86400 else 21600
    return max(b, 3600) if src != "raw" else b


def _iso(v) -> str | None:
    if v is None:
        return None
    if isinstance(v, datetime):
        return (v if v.tzinfo else v.replace(tzinfo=timezone.utc)).isoformat()
    t = str(v)
    return None if t.startswith("1970") else t.replace(" ", "T") + ("Z" if "+" not in t and "Z" not in t else "")


def _num(r: dict, k: str) -> int:
    try:
        return int(r.get(k) or 0)
    except (TypeError, ValueError):
        return 0


def _meta(f: Filters, src: str) -> dict:
    t0, t1 = f.window()
    return {"start": t0.isoformat(), "end": t1.isoformat(), "source": SOURCE_LABEL[src], "seconds": int(_span(f))}


async def _run(ch, sql: Sql, f: Filters, dims, metrics, **kw) -> list[dict]:
    q, _ = aggregate(sql, f, dims, metrics, **kw)
    return await ch.aquery(q, sql.p)


async def _run_count(ch, sql: Sql, f: Filters, dims, metrics, **kw) -> tuple[list[dict], int]:
    q, cq = aggregate(sql, f, dims, metrics, **kw)
    rows = await ch.aquery(q, sql.p)
    n = await ch.aquery(cq, sql.p)
    return rows, int(n[0]["n"]) if n else 0


# ------------------------------------------------------------------ overview
async def overview(s: AsyncSession, ch, f: Filters) -> dict:
    ctx = await context(s)
    src = choose(f)
    bucket = trend_bucket(f, src)
    span = _span(f)
    tot = (await _run(ch, Sql(ctx, src), f, [], ["bytes", "packets", "flows", "sources", "destinations", "conversations", "peak_bucket_bytes"],
                      bucket_seconds=bucket, order="", limit=1)) or [{}]
    t = tot[0]
    d = Sql(ctx, src)
    by_dir = await _run(ch, d, f, [("direction", d.direction())], ["bytes", "packets", "flows"], limit=10)
    a = Sql(ctx, src)
    apps = await _run(ch, a, f, [("app", a.app())], ["bytes"], limit=500)
    p = Sql(ctx, src)
    protos = await _run(ch, p, f, [("proto", "proto")], ["bytes"], limit=300)
    e = Sql(ctx, src)
    est = await _run(ch, e, f, [("sampled", "toUInt8(sampling > 1)")], ["bytes", "flows"], limit=5) if src != "ifh" else []
    bytes_total = _num(t, "bytes")
    dirs = {r["direction"]: _num(r, "bytes") for r in by_dir}
    unknown = sum(_num(r, "bytes") for r in apps if r["app"] == "Unknown")
    sampled = {int(r["sampled"]): (_num(r, "bytes"), _num(r, "flows")) for r in est}
    t0, t1 = f.window()
    suspicious = (await s.execute(select(func.count(Alert.id)).where(Alert.rule_key.like("traffic\\_%", escape="\\"),
                                                                     Alert.last_seen >= t0, Alert.status != "resolved"))).scalar_one()
    return {**_meta(f, src), "kpis": {
        "bytes": bytes_total, "packets": _num(t, "packets"), "flows": _num(t, "flows"),
        "sources": _num(t, "sources"), "destinations": _num(t, "destinations"), "conversations": _num(t, "conversations"),
        "applications": sum(1 for r in apps if r["app"] != "Unknown"), "protocols": len(protos),
        "avg_bps": round(bytes_total * 8 / span, 1), "peak_bps": round(_num(t, "peak_bucket_bytes") * 8 / bucket, 1), "peak_bucket_seconds": bucket,
        "inbound": dirs.get("inbound", 0), "outbound": dirs.get("outbound", 0), "internal": dirs.get("east_west", 0),
        "external": dirs.get("inbound", 0) + dirs.get("outbound", 0), "transit": dirs.get("transit", 0),
        "unknown": unknown, "suspicious": int(suspicious),
        "sampled_bytes": sampled.get(1, (0, 0))[0], "measured_bytes": sampled.get(0, (0, 0))[0],
    }, "networks_configured": ctx.nets.configured,
        "notes": _notes(ctx, sampled)}


def _notes(ctx: Ctx, sampled: dict) -> list[str]:
    out = []
    if sampled.get(1, (0, 0))[0]:
        out.append("Sampled telemetry (sFlow or sampled NetFlow / IPFIX): bytes and packets are statistical estimates (sample × rate).")
    if not ctx.nets.configured:
        out.append("No network ranges are configured: private address blocks count as internal (Settings → Networks).")
    if not ctx.ip_apps:
        out.append("No enrichment yet: applications are port-based until DNS logs, firewall application control or ASN data are correlated.")
    return out


# ------------------------------------------------------------------ applications / protocols
APP_SORT = {"bytes": "bytes", "packets": "packets", "flows": "flows", "sources": "sources", "destinations": "destinations", "app": "app"}


async def applications(s, ch, f: Filters, sort: str | None, limit: int, offset: int) -> dict:
    ctx = await context(s)
    src = choose(f)
    q = Sql(ctx, src)
    rows, total = await _run_count(ch, q, f, [("app", q.app()), ("category", q.category()), ("confidence", q.confidence())],
                                   ["bytes", "packets", "flows", "sources", "destinations", "conversations", "first", "last", "sampling"],
                                   order=sort_clause(sort, APP_SORT, "bytes DESC"), limit=limit, offset=offset)
    allb = sum(_num(r, "bytes") for r in rows) or 1
    items = []
    for r in rows:
        base = r["app"].split(" · ")[0]
        meta = ctx.reg.by_label.get(base, {})
        items.append({"app": r["app"], "category": r["category"], "confidence": r["confidence"], "bytes": _num(r, "bytes"), "packets": _num(r, "packets"),
                      "flows": _num(r, "flows"), "sources": _num(r, "sources"), "destinations": _num(r, "destinations"),
                      "conversations": _num(r, "conversations"), "first": _iso(r.get("first")), "last": _iso(r.get("last")),
                      "sampled": _num(r, "sampling") > 1, "share": round(100 * _num(r, "bytes") / allb, 2),
                      "encrypted": meta.get("encrypted"), "ambiguous": meta.get("ambiguous", False), "description": meta.get("description", ""),
                      "avg_bps": round(_num(r, "bytes") * 8 / _span(f), 1)})
    return {**_meta(f, src), "items": items, "total": total}


async def protocols(s, ch, f: Filters, limit: int) -> dict:
    ctx = await context(s)
    src = choose(f)
    rows = await _run(ch, Sql(ctx, src), f, [("proto", "proto")], ["bytes", "packets", "flows", "sources", "destinations"], limit=limit)
    q = Sql(ctx, src)
    svc = await _run(ch, q, f, [("proto", "proto"), ("port", q.t["port"]), ("label", q.port_label())], ["bytes", "packets", "flows", "sources"],
                     limit=limit)
    allb = sum(_num(r, "bytes") for r in rows) or 1
    return {**_meta(f, src),
            "protocols": [{"proto": int(r["proto"]), "name": R.PROTOCOLS.get(int(r["proto"]), f"IP {r['proto']}"), "bytes": _num(r, "bytes"),
                           "packets": _num(r, "packets"), "flows": _num(r, "flows"), "sources": _num(r, "sources"),
                           "destinations": _num(r, "destinations"), "share": round(100 * _num(r, "bytes") / allb, 2)} for r in rows],
            "services": [{"proto": int(r["proto"]), "port": int(r["port"]), "name": R.PROTOCOLS.get(int(r["proto"]), str(r["proto"])),
                          "label": r["label"], "bytes": _num(r, "bytes"), "packets": _num(r, "packets"), "flows": _num(r, "flows"),
                          "sources": _num(r, "sources")} for r in svc]}


async def web_protocols(s, ch, f: Filters) -> dict:
    """TCP/443 vs UDP/443 and QUIC evidence. HTTP/2 vs HTTP/1.1 is not visible in flow records (TLS hides ALPN)."""
    ctx = await context(s)
    src = choose(f)
    f443 = Filters(**{**f.__dict__, "port": 443})
    q = Sql(ctx, src)
    series = ("multiIf(proto = 6, 'TCP/443 (HTTPS: HTTP/1.1 or HTTP/2)', proto = 17 AND startsWith(" + q.t["l7"] + ", 'quic'), "
              "'UDP/443 QUIC confirmed (HTTP/3)', proto = 17, 'UDP/443 possible QUIC', 'other')")
    bucket = trend_bucket(f, src)
    trend = await _run(ch, q, f443, [("t", f"toStartOfInterval({q.t['ts']}, INTERVAL {bucket} SECOND)"), ("series", series)], ["bytes", "flows"],
                       order="t", limit=500, bucket_seconds=bucket)
    q2 = Sql(ctx, src)
    totals = await _run(ch, q2, f443, [("series", series.replace(q.t["l7"], q2.t["l7"]))], ["bytes", "packets", "flows", "sources", "destinations"],
                        limit=10)
    q3 = Sql(ctx, src)
    versions = await _run(ch, q3, Filters(**{**f443.__dict__, "proto": 17}), [("version", q3.t["l7"])], ["bytes", "flows"], limit=10) \
        if src != "ifh" else []
    q4 = Sql(ctx, src)
    top_src = await _run(ch, q4, Filters(**{**f443.__dict__, "proto": 17}), [("ip", q4.t["client"])], ["bytes", "flows", "destinations"], limit=10)
    q5 = Sql(ctx, src)
    top_dst = await _run(ch, q5, Filters(**{**f443.__dict__, "proto": 17}), [("ip", q5.t["server"])], ["bytes", "flows", "sources"], limit=10)
    return {**_meta(f, src), "bucket_seconds": bucket,
            "points": [{"t": _iso(r["t"]), "series": r["series"], "bytes": _num(r, "bytes"), "bps": round(_num(r, "bytes") * 8 / bucket, 1),
                        "flows": _num(r, "flows")} for r in trend],
            "totals": [{"series": r["series"], "bytes": _num(r, "bytes"), "packets": _num(r, "packets"), "flows": _num(r, "flows"),
                        "sources": _num(r, "sources"), "destinations": _num(r, "destinations")} for r in totals],
            "quic_versions": [{"version": r["version"] or "no QUIC long header in samples", "bytes": _num(r, "bytes"), "flows": _num(r, "flows")}
                              for r in versions],
            "top_quic_clients": [{"ip": r["ip"], "bytes": _num(r, "bytes"), "flows": _num(r, "flows"), "peers": _num(r, "destinations")} for r in top_src],
            "top_quic_servers": [{"ip": r["ip"], "bytes": _num(r, "bytes"), "flows": _num(r, "flows"), "peers": _num(r, "sources")} for r in top_dst],
            "notes": ["QUIC is confirmed only from sFlow samples whose packet head shows a QUIC long header (handshake packets); "
                      "other UDP/443 traffic is 'possible QUIC'.",
                      "HTTP/2 and HTTP/1.1 cannot be told apart from flow records: TLS hides the negotiated protocol."]}


# ------------------------------------------------------------------ sources / destinations
TALKER_SORT = {"bytes": "bytes", "packets": "packets", "flows": "flows", "peak": "peak_bucket_bytes", "peers": "peers", "last": "last", "first": "first"}


async def _macs(ch, f: Filters, col: str, macol: str, ips: list[str]) -> dict[str, str]:
    """MAC observed with each address in sFlow samples (layer-2 next hop, not necessarily the host when routed)."""
    if not ips:
        return {}
    t0, t1 = f.window()
    try:
        rows = await ch.aquery(f"SELECT {col} AS ip, anyLast({macol}) AS mac FROM flows WHERE ts >= {{t0:DateTime64(3)}} AND ts < {{t1:DateTime64(3)}} "
                               f"AND {col} IN {{ips:Array(String)}} AND {macol} != '' GROUP BY ip", {"t0": t0, "t1": t1, "ips": ips})
    except Exception:
        return {}
    return {r["ip"]: r["mac"] for r in rows}


async def talkers(s, ch, f: Filters, side: str, sort: str | None, limit: int, offset: int, *, sensitive: bool) -> dict:
    ctx = await context(s)
    src = choose(f)
    if src == "ifh":
        src = "conv"
    col, peer = ("src_ip", "destinations") if side == "sources" else ("dst_ip", "sources")
    q = Sql(ctx, src)
    rows, total = await _run_count(ch, q, f, [("ip", col)], ["bytes", "packets", "flows", "peak_bucket_bytes", peer, "first", "last", "sampling"],
                                   order=sort_clause(sort, {**TALKER_SORT, "peers": peer}, "bytes DESC"), limit=limit, offset=offset,
                                   bucket_seconds=trend_bucket(f, src))
    ips = [r["ip"] for r in rows]
    bucket = trend_bucket(f, src)
    # dominant application per address (one more bounded query)
    fa = Filters(**{**f.__dict__})
    qa = Sql(ctx, src)
    qa.p["tops"] = ips or ["-"]
    apps: dict[str, tuple[str, int]] = {}
    if ips:
        q2, _ = aggregate(qa, fa, [("ip", col), ("app", qa.app())], ["bytes"], limit=MAX_APPS_ROWS, having="ip IN {tops:Array(String)}")
        for r in await ch.aquery(q2, qa.p):
            if r["ip"] in ips and _num(r, "bytes") > apps.get(r["ip"], ("", -1))[1]:
                apps[r["ip"]] = (r["app"], _num(r, "bytes"))
    macs = await _macs(ch, f, col, "src_mac" if side == "sources" else "dst_mac", ips) if sensitive else {}
    info = await E.hosts(s, ips, sensitive=sensitive, macs=macs)
    items = []
    for r in rows:
        h = info.get(r["ip"], {})
        items.append({"ip": r["ip"], **h, "bytes": _num(r, "bytes"), "packets": _num(r, "packets"), "flows": _num(r, "flows"),
                      "avg_bps": round(_num(r, "bytes") * 8 / _span(f), 1), "peak_bps": round(_num(r, "peak_bucket_bytes") * 8 / bucket, 1),
                      "peers": _num(r, peer), "first": _iso(r.get("first")), "last": _iso(r.get("last")), "sampled": _num(r, "sampling") > 1,
                      "top_app": apps.get(r["ip"], ("", 0))[0], "direction_class": "internal" if h.get("internal") else "external"})
    return {**_meta(f, src), "items": items, "total": total, "peak_bucket_seconds": bucket}


MAX_APPS_ROWS = 500


# ------------------------------------------------------------------ conversations / raw flows
CONV_SORT = {"bytes": "bytes", "packets": "packets", "flows": "flows", "first": "first", "last": "last", "src": "src_ip", "dst": "dst_ip",
             "port": "port", "app": "app", "peak": "peak_bucket_bytes"}


async def conversations(s, ch, f: Filters, sort: str | None, limit: int, offset: int, *, sensitive: bool) -> dict:
    ctx = await context(s)
    src = choose(f)
    if src == "ifh":
        src = "conv"
    q = Sql(ctx, src)
    bucket = trend_bucket(f, src)
    dims = [("src_ip", "src_ip"), ("dst_ip", "dst_ip"), ("proto", "proto"), ("port", q.t["port"]), ("app", q.app()), ("category", q.category()),
            ("confidence", q.confidence()), ("direction", q.direction()), ("src_vlan", q.src_vlan()), ("dst_vlan", q.dst_vlan())]
    rows, total = await _run_count(ch, q, f, dims, ["bytes", "packets", "flows", "first", "last", "sampling", "peak_bucket_bytes"],
                                   order=sort_clause(sort, CONV_SORT, "bytes DESC"), limit=limit, offset=offset, bucket_seconds=bucket)
    info = await E.hosts(s, {r["src_ip"] for r in rows} | {r["dst_ip"] for r in rows}, sensitive=sensitive)
    span = _span(f)
    items = []
    for r in rows:
        si, di = info.get(r["src_ip"], {}), info.get(r["dst_ip"], {})
        items.append({"src_ip": r["src_ip"], "dst_ip": r["dst_ip"], "proto": int(r["proto"]), "proto_name": R.PROTOCOLS.get(int(r["proto"]), str(r["proto"])),
                      "port": int(r["port"]), "app": r["app"], "category": r["category"], "confidence": r["confidence"], "direction": r["direction"],
                      "src_vlan": int(r["src_vlan"]) or None, "dst_vlan": int(r["dst_vlan"]) or None, "bytes": _num(r, "bytes"),
                      "packets": _num(r, "packets"), "flows": _num(r, "flows"), "avg_bps": round(_num(r, "bytes") * 8 / span, 1),
                      "peak_bps": round(_num(r, "peak_bucket_bytes") * 8 / bucket, 1), "first": _iso(r.get("first")), "last": _iso(r.get("last")),
                      "sampling": _num(r, "sampling"), "sampled": _num(r, "sampling") > 1, "src": _host_brief(si), "dst": _host_brief(di)})
    return {**_meta(f, src), "items": items, "total": total}


def _host_brief(h: dict) -> dict:
    return {k: h.get(k) for k in ("hostname", "kind", "device", "site", "zone", "vlan", "network", "mac", "switch", "port", "ssid", "user",
                                   "as_org", "country", "internal")}


async def flows(s, ch, f: Filters, limit: int, offset: int, *, sensitive: bool) -> dict:
    """Individual flow records (raw), newest first; windows up to 24 hours."""
    t0, t1 = f.window()
    if t1 - t0 > timedelta(hours=24):
        raise ValueError("individual flow records can be listed for windows up to 24 hours; use conversations for longer ones")
    ctx = await context(s)
    q = Sql(ctx, "raw")
    where = q.where(f, t0, t1)
    mac = "src_mac, dst_mac," if sensitive else "'' AS src_mac, '' AS dst_mac,"
    rows = await ch.aquery(
        f"SELECT ts, exporter, version, in_if, out_if, src_ip, dst_ip, src_port, dst_port, proto, bytes, packets, vlan, dst_vlan, sampling, {mac} "
        f"tcp_flags, l7, ({q.app()}) AS app, ({q.confidence()}) AS confidence, ({q.direction()}) AS direction FROM flows WHERE {where} "
        f"ORDER BY ts DESC LIMIT {int(min(limit, 500))} OFFSET {int(min(offset, 100_000))}", q.p)
    names = await device_names(s)
    return {**_meta(f, "raw"), "items": [{
        "ts": _iso(r["ts"]), "exporter": r["exporter"], "device": names.get(r["exporter"], r["exporter"]), "version": r["version"],
        "in_if": int(r["in_if"]), "out_if": int(r["out_if"]), "src_ip": r["src_ip"], "dst_ip": r["dst_ip"], "src_port": int(r["src_port"]),
        "dst_port": int(r["dst_port"]), "proto": int(r["proto"]), "proto_name": R.PROTOCOLS.get(int(r["proto"]), str(r["proto"])),
        "bytes": _num(r, "bytes"), "packets": _num(r, "packets"), "vlan": int(r["vlan"]) or None, "dst_vlan": int(r["dst_vlan"]) or None,
        "sampling": _num(r, "sampling"), "estimated": _num(r, "sampling") > 1 or r["version"] == "sflow5", "src_mac": r["src_mac"], "dst_mac": r["dst_mac"],
        "tcp_flags": int(r["tcp_flags"]), "l7": r["l7"], "app": r["app"], "confidence": r["confidence"], "direction": r["direction"]} for r in rows]}


async def device_names(s: AsyncSession) -> dict[str, str]:
    out = {x.host: x.name for x in (await s.execute(select(Firewall).where(Firewall.is_demo.is_(False)))).scalars()}
    out.update({x.address: x.name for x in (await s.execute(select(Switch))).scalars()})
    return out


# ------------------------------------------------------------------ VLANs
async def _vlan_names(s: AsyncSession, nets: N.Networks) -> dict[int, dict]:
    out: dict[int, dict] = {}
    for v, name in (await s.execute(select(SwitchVlan.vlan_id, SwitchVlan.name).where(SwitchVlan.present.is_(True)))).all():
        out.setdefault(int(v), {"name": name or "", "zone": "", "network": ""})
    for n in nets.nets:
        if n.vlan:
            d = out.setdefault(int(n.vlan), {"name": "", "zone": "", "network": ""})
            d.update(zone=d["zone"] or n.zone, network=d["network"] or n.cidr, name=d["name"] or n.name)
    return out


async def vlans(s, ch, f: Filters, limit: int) -> dict:
    ctx = await context(s)
    src = choose(f)
    if src == "ifh":
        src = "conv"
    q = Sql(ctx, src)
    rows = await _run(ch, q, f, [("vlan", q.src_vlan())], ["bytes", "packets", "flows", "sources", "destinations", "conversations"], limit=limit)
    qd = Sql(ctx, src)
    dirs = await _run(ch, qd, f, [("vlan", qd.src_vlan()), ("direction", qd.direction())], ["bytes"], limit=2000)
    qa = Sql(ctx, src)
    apps = await _run(ch, qa, f, [("vlan", qa.src_vlan()), ("app", qa.app())], ["bytes"], limit=2000)
    names = await _vlan_names(s, ctx.nets)
    by_dir: dict[int, dict] = {}
    for r in dirs:
        by_dir.setdefault(int(r["vlan"]), {})[r["direction"]] = _num(r, "bytes")
    top: dict[int, list] = {}
    for r in apps:
        top.setdefault(int(r["vlan"]), []).append((r["app"], _num(r, "bytes")))
    items = []
    for r in rows:
        v = int(r["vlan"])
        d = by_dir.get(v, {})
        items.append({"vlan": v or None, "label": f"VLAN {v}" if v else "Unknown VLAN", **names.get(v, {"name": "", "zone": "", "network": ""}),
                      "bytes": _num(r, "bytes"), "packets": _num(r, "packets"), "flows": _num(r, "flows"), "sources": _num(r, "sources"),
                      "destinations": _num(r, "destinations"), "conversations": _num(r, "conversations"),
                      "east_west": d.get("east_west", 0), "north_south": d.get("outbound", 0) + d.get("inbound", 0),
                      "top_apps": [a for a, _ in sorted(top.get(v, []), key=lambda x: -x[1])[:5]]})
    return {**_meta(f, src), "items": items, "notes": [
        "A flow's VLAN is the 802.1Q tag or sFlow switch record when the export carries one; otherwise the VLAN the switches' MAC tables "
        "learned for the client's MAC (MACs seen in several VLANs, such as the gateway's, are not used); otherwise the configured range.",
        "Broadcast and multicast are counted with their destination address (255.255.255.255, 224.0.0.0/4, ff00::/8)."]}


async def vlan_matrix(s, ch, f: Filters, limit: int) -> dict:
    ctx = await context(s)
    src = choose(f)
    if src == "ifh":
        src = "conv"
    q = Sql(ctx, src)
    rows = await _run(ch, q, f, [("src_vlan", q.src_vlan()), ("dst_vlan", q.dst_vlan())], ["bytes", "packets", "flows", "conversations", "first", "last"],
                      limit=limit, having="src_vlan != dst_vlan")
    qa = Sql(ctx, src)
    apps = await _run(ch, qa, f, [("src_vlan", qa.src_vlan()), ("dst_vlan", qa.dst_vlan()), ("app", qa.app())], ["bytes"], limit=2000,
                      having="src_vlan != dst_vlan")
    names = await _vlan_names(s, ctx.nets)
    pols = (await s.execute(select(TrafficVlanPolicy).where(TrafficVlanPolicy.enabled.is_(True)))).scalars().all()
    top: dict[tuple, list] = {}
    for r in apps:
        top.setdefault((int(r["src_vlan"]), int(r["dst_vlan"])), []).append((r["app"], _num(r, "bytes")))
    zone_of = {v: d.get("zone", "") for v, d in names.items()}
    items = []
    for r in rows:
        sv, dv = int(r["src_vlan"]), int(r["dst_vlan"])
        verdict = policy_verdict(pols, sv, zone_of.get(sv, ""), True, dv, zone_of.get(dv, ""), True)
        items.append({"src_vlan": sv or None, "dst_vlan": dv or None, "src_name": names.get(sv, {}).get("name", ""), "dst_name": names.get(dv, {}).get("name", ""),
                      "src_zone": zone_of.get(sv, ""), "dst_zone": zone_of.get(dv, ""), "bytes": _num(r, "bytes"), "packets": _num(r, "packets"),
                      "flows": _num(r, "flows"), "conversations": _num(r, "conversations"), "first": _iso(r.get("first")), "last": _iso(r.get("last")),
                      "apps": [a for a, _ in sorted(top.get((sv, dv), []), key=lambda x: -x[1])[:6]], "policy": verdict})
    return {**_meta(f, src), "items": items}


def policy_verdict(pols, sv: int, sz: str, si: bool, dv: int, dz: str, di: bool) -> dict | None:
    """First matching policy (deny before allow); None when no policy covers the pair."""
    hits = [p for p in pols if N.endpoint_matches(p.src, sz, sv, si) and N.endpoint_matches(p.dst, dz, dv, di)]
    if not hits:
        return None
    allow = [p for p in hits if p.action == "allow"]
    deny = [p for p in hits if p.action == "deny"]
    p = allow[0] if allow and not deny else deny[0] if deny else allow[0]
    if allow and deny:   # a specific allow (VLAN-level) beats a zone-level deny
        spec = lambda x: (x.src.startswith("vlan:")) + (x.dst.startswith("vlan:"))   # noqa: E731
        p = max(allow, key=spec) if max(spec(a) for a in allow) > max(spec(d) for d in deny) else deny[0]
    return {"id": p.id, "name": p.name, "action": p.action, "severity": p.severity}


# ------------------------------------------------------------------ interfaces
async def interfaces(s, ch, f: Filters, limit: int, *, lag_mode: str) -> dict:
    """Per device and interface: received (ingress ifIndex) and sent (egress ifIndex) traffic. No deduplication
    across devices; LAG members and the LAG itself are never both counted (lag_mode)."""
    ctx = await context(s)
    src = choose(f, need_if=True)
    rx = await _run(ch, Sql(ctx, src), f, [("exporter", "exporter"), ("ifindex", "in_if")], ["bytes", "packets", "flows", "sampling"],
                    limit=2000, dedup=False)
    tx = await _run(ch, Sql(ctx, src), f, [("exporter", "exporter"), ("ifindex", "out_if")], ["bytes", "packets", "flows"], limit=2000, dedup=False)
    sws = {x.address: x for x in (await s.execute(select(Switch))).scalars()}
    names = await device_names(s)
    ids = {sw.id for sw in sws.values()}
    ifs = {(i.switch_id, i.ifindex): i for i in (await s.execute(select(SwitchInterface).where(SwitchInterface.switch_id.in_(ids or {0})))).scalars()}
    acc: dict[tuple, dict] = {}
    for rows, k in ((rx, "rx"), (tx, "tx")):
        for r in rows:
            key = (r["exporter"], int(r["ifindex"]))
            d = acc.setdefault(key, {"rx_bytes": 0, "tx_bytes": 0, "rx_packets": 0, "tx_packets": 0, "flows": 0, "sampling": 0})
            d[f"{k}_bytes"] += _num(r, "bytes")
            d[f"{k}_packets"] += _num(r, "packets")
            d["flows"] += _num(r, "flows")
            d["sampling"] = max(d["sampling"], _num(r, "sampling"))
    # LAG handling: members → parent
    parent: dict[tuple, int] = {}
    for (sid, idx), i in ifs.items():
        if i.lag_ifindex:
            parent[(sid, idx)] = int(i.lag_ifindex)
    span = _span(f)
    out: dict[tuple, dict] = {}
    for (ex, idx), d in acc.items():
        if idx == 0:
            continue
        sw = sws.get(ex)
        i = ifs.get((sw.id, idx)) if sw else None
        lag = parent.get((sw.id, idx)) if sw else None
        row = {"exporter": ex, "device": names.get(ex, ex), "site": sw.site if sw else "", "ifindex": idx, "name": i.name if i else f"ifIndex {idx}",
               "description": i.alias if i else "", "kind": (i.kind if i else "") or "", "speed_bps": i.speed_bps if i else None,
               "lag_ifindex": lag, **d}
        out[(ex, idx)] = row
    lag_rows = {(ex, idx) for (ex, idx), r in out.items() if r["kind"] == "lag"}
    if lag_mode == "members":
        for key in lag_rows:     # a LAG row is replaced by the sum of its members when members carry traffic
            members = [r for r in out.values() if r["exporter"] == key[0] and r["lag_ifindex"] == key[1]]
            if members:
                out[key]["counted"] = "members"
                for k in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "flows"):
                    out[key][k] = sum(m[k] for m in members)
                for m in members:
                    m["counted"] = "member (included in LAG)"
    else:
        for r in out.values():
            if r["lag_ifindex"] and (r["exporter"], r["lag_ifindex"]) in out:
                r["counted"] = "member (LAG counted as logical)"
    items = []
    for r in out.values():
        b = r["rx_bytes"] + r["tx_bytes"]
        util = None
        if r["speed_bps"]:
            util = round(100 * max(r["rx_bytes"], r["tx_bytes"]) * 8 / span / r["speed_bps"], 2)
        items.append({**r, "bytes": b, "avg_rx_bps": round(r["rx_bytes"] * 8 / span, 1), "avg_tx_bps": round(r["tx_bytes"] * 8 / span, 1),
                      "utilization_pct": util, "sampled": r["sampling"] > 1, "counted": r.get("counted", "")})
    items.sort(key=lambda x: -x["bytes"])
    items = items[:limit]
    # top applications / talkers for the listed interfaces (one bounded query each)
    if items and src == "raw":
        qa = Sql(ctx, "raw")
        apps = await _run(ch, qa, f, [("exporter", "exporter"), ("ifindex", "in_if"), ("app", qa.app())], ["bytes"], limit=2000, dedup=False)
        top: dict[tuple, list] = {}
        for r in apps:
            top.setdefault((r["exporter"], int(r["ifindex"])), []).append((r["app"], _num(r, "bytes")))
        for it in items:
            it["top_apps"] = [a for a, _ in sorted(top.get((it["exporter"], it["ifindex"]), []), key=lambda x: -x[1])[:4]]
    return {**_meta(f, src), "items": items, "lag_mode": lag_mode}


# ------------------------------------------------------------------ trends
SERIES = {"none": None, "app": "app", "direction": "direction", "proto": "proto", "category": "category"}


async def trends(s, ch, f: Filters, by: str, top: int = 6) -> dict:
    ctx = await context(s)
    src = choose(f)
    bucket = trend_bucket(f, src)
    q0 = Sql(ctx, src)
    expr = {"none": None, "app": q0.app, "direction": q0.direction, "category": q0.category, "proto": lambda: "toString(proto)"}[by]
    names: list[str] = []
    if expr:
        lead = await _run(ch, q0, f, [("series", expr())], ["bytes"], limit=top)
        names = [r["series"] for r in lead]
    q = Sql(ctx, src)
    e = {"none": None, "app": q.app, "direction": q.direction, "category": q.category, "proto": lambda: "toString(proto)"}[by]
    dims = [("t", f"toStartOfInterval({q.t['ts']}, INTERVAL {bucket} SECOND)")]
    if e:
        q.p["top_series"] = names or ["-"]
        dims.append(("series", f"if(({e()}) IN {{top_series:Array(String)}}, {e()}, 'Other')"))
    rows = await _run(ch, q, f, dims, ["bytes", "packets", "flows"], order="t", limit=500 * (len(names) + 2), bucket_seconds=bucket)
    if by == "proto":
        for r in rows:
            r["series"] = R.PROTOCOLS.get(int(r["series"]), r["series"]) if str(r.get("series", "")).isdigit() else r.get("series")
    return {**_meta(f, src), "bucket_seconds": bucket, "by": by, "points": [
        {"t": _iso(r["t"]), "series": r.get("series") or "All traffic", "bytes": _num(r, "bytes"), "bps": round(_num(r, "bytes") * 8 / bucket, 1),
         "packets": _num(r, "packets"), "flows": _num(r, "flows")} for r in rows]}


# ------------------------------------------------------------------ DNS / domains
async def domains(s, ch, f: Filters, limit: int, offset: int, q: str | None) -> dict:
    """Domains from collected DNS logs (Zeek, FortiGate DNS, resolver syslog) with the traffic to the addresses they
    resolved to. 'available: false' when no DNS logs were collected in the window."""
    from ..platform.eventquery import table
    t0, t1 = f.window()
    p: dict = {"t0": t0, "t1": t1}
    where = "event_time >= {t0:DateTime64(3)} AND event_time < {t1:DateTime64(3)} AND category = 'dns' AND dns_qname != ''"
    if f.ip:
        where += " AND (src_ip = {ip:String} OR dst_ip = {ip:String})"
        p["ip"] = f.ip
    if q:
        where += " AND positionCaseInsensitive(dns_qname, {q:String}) > 0"
        p["q"] = q
    try:
        have = await ch.aquery(f"SELECT count() AS n FROM {table()} WHERE {where.split(' AND dns_qname')[0]}", p)
    except Exception:
        have = []
    if not have or not int(have[0]["n"]):
        return {"available": False, "reason": "DNS enrichment unavailable: no DNS logs (Zeek, FortiGate DNS, resolver syslog) in this window.",
                "items": [], "total": 0, "start": t0.isoformat(), "end": t1.isoformat()}
    rows = await ch.aquery(
        f"SELECT dns_qname AS domain, count() AS queries, uniqExact(src_ip) AS clients, groupUniqArray(5)(dst_ip) AS servers, "
        f"groupUniqArray(5)(dns_qtype) AS qtypes, groupUniqArray(5)(dns_rcode) AS rcodes, groupUniqArrayArray(20)(dns_resolved) AS resolved, "
        f"min(event_time) AS first, max(event_time) AS last, any(src_ip) AS sample_client FROM {table()} WHERE {where} "
        f"GROUP BY domain ORDER BY queries DESC LIMIT {int(min(limit, 500))} OFFSET {int(min(offset, 100_000))}", p)
    total = await ch.aquery(f"SELECT uniqExact(dns_qname) AS n FROM {table()} WHERE {where}", p)
    ips = sorted({ip for r in rows for ip in r["resolved"] if ip})[:2000]
    traffic: dict[str, int] = {}
    if ips:
        tr = await ch.aquery("SELECT dst_ip AS ip, sum(bytes) AS b FROM flows_conv_hourly WHERE hour >= toStartOfHour({t0:DateTime64(3)}) "
                             "AND hour < {t1:DateTime64(3)} AND dst_ip IN {ips:Array(String)} GROUP BY ip", {"t0": t0, "t1": t1, "ips": ips})
        traffic = {r["ip"]: _num(r, "b") for r in tr}
    shared = {}
    if ips:
        from ..db.models import TrafficIpInfo
        shared = {r.ip: r.domain_count for r in (await s.execute(select(TrafficIpInfo).where(TrafficIpInfo.ip.in_(ips)))).scalars()}
    reg = await R.load(s)
    items = []
    for r in rows:
        res = [x for x in r["resolved"] if x]
        sig = reg.domain_app(r["domain"])
        items.append({"domain": r["domain"], "queries": _num(r, "queries"), "clients": _num(r, "clients"), "servers": r["servers"],
                      "qtypes": [x for x in r["qtypes"] if x], "rcodes": [x for x in r["rcodes"] if x], "resolved": res[:20],
                      "first": _iso(r["first"]), "last": _iso(r["last"]), "traffic_bytes": sum(traffic.get(x, 0) for x in res),
                      "shared_addresses": sum(1 for x in res if shared.get(x, 0) > E.SHARED_DOMAINS),
                      "app": sig[0] if sig else "", "category": sig[1] if sig else ""})
    return {"available": True, "start": t0.isoformat(), "end": t1.isoformat(), "items": items, "total": int(total[0]["n"]) if total else 0,
            "notes": ["Traffic per domain is the traffic to the addresses the domain resolved to; an address shared by many names (CDN) "
                      "is counted for each of them.", "Encrypted DNS (DoT / DoH / DoQ) is not visible in DNS logs; see the DNS over TLS / QUIC "
                      "applications."]}


# ------------------------------------------------------------------ collectors
async def collectors(s, ch) -> dict:
    from .. import selfmon
    proc = [p for p in await selfmon.latest(ch, minutes=10) if p["service"] == "flows"]
    rows = await ch.aquery(
        "SELECT exporter, max(ts) AS last, countIf(ts >= now() - INTERVAL 1 HOUR) AS records_1h, sumIf(bytes, ts >= now() - INTERVAL 1 HOUR) AS bytes_1h, "
        "max(sampling) AS sampling, groupUniqArray(version) AS versions FROM flows WHERE ts >= now() - INTERVAL 1 DAY GROUP BY exporter")
    names = await device_names(s)
    sws = {x.address for x in (await s.execute(select(Switch))).scalars()}
    now = datetime.now(timezone.utc)
    seen = {}
    for r in rows:
        last = r["last"] if isinstance(r["last"], datetime) else datetime.fromisoformat(str(r["last"]))
        last = last if last.tzinfo else last.replace(tzinfo=timezone.utc)
        age = (now - last).total_seconds()
        seen[r["exporter"]] = {"exporter": r["exporter"], "device": names.get(r["exporter"], r["exporter"]), "last": last.isoformat(),
                               "age_seconds": int(age), "status": "ok" if age <= 300 else "stale" if age <= 3600 else "silent",
                               "records_1h": _num(r, "records_1h"), "bytes_1h": _num(r, "bytes_1h"), "sampling": _num(r, "sampling"),
                               "telemetry": sorted(r["versions"]), "estimated": _num(r, "sampling") > 1 or "sflow5" in r["versions"]}
    collector = None
    if proc:
        m = proc[0]["metrics"]
        collector = {"instance": proc[0]["instance"], "last": proc[0]["last"],
                     **{k[6:]: int(v) for k, v in m.items() if k.startswith("flows_") and ":" not in k and k != "flows_last_beat"},
                     "unknown_senders": sorted(({"ip": k.split(":", 1)[1], "datagrams": int(v)} for k, v in m.items() if k.startswith("flows_unknown:")),
                                               key=lambda x: -x["datagrams"])}
    return {"collector": collector, "collector_status": "reporting" if collector else "not reporting",
            "exporters": sorted(seen.values(), key=lambda x: x["age_seconds"]),
            "inventory_without_data": sorted(names[a] for a in sws if a not in seen)[:200],
            "notes": ["The collector accepts flows only from inventory devices (switch / controller management addresses, firewalls); "
                      "other senders are counted and dropped (unknown_senders).",
                      "Ports: NetFlow 2055/udp, IPFIX 4739/udp, sFlow 6343/udp, bound to FLOW_BIND_IP."]}
