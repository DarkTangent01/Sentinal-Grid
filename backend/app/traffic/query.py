"""Filter model and SQL building for traffic analytics (ClickHouse). Every value reaches SQL as a bound parameter;
column names and expressions come only from the fixed tables below, never from the request.

Sources
  raw   flows               every record (30 days): minute detail, ports on both sides, MACs, TCP flags, interfaces
  conv  flows_conv_hourly   per hour, exporter and conversation (source, destination, protocol, service port), 35 days
  ifh   flows_if_hourly     per hour, exporter and interface pair / VLAN / service, 400 days (no addresses)
Windows up to RAW_HOURS read raw records; longer ones read the rollups (whole hours). Interface views read ifh, or raw
when an address filter is also set.

Deduplication (settings "dedup"): one conversation exported by several devices counts once — per conversation and
time bucket the largest exporter's figures are kept — before any grouping. Per-device / per-interface views are not
deduplicated (each device's own view is what they show).

Service port: the lower non-zero port of the two (the server side for almost all services); classification of raw
records looks at both ports first (registry.Registry.port_app has the same rule).
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .networks import Networks
from .registry import Registry

RAW_HOURS = 6
PRESETS = {"5m": 5, "15m": 15, "1h": 60, "6h": 360, "24h": 1440, "7d": 10080, "30d": 43200}
MAX_SPAN = timedelta(days=30)
MAX_LIMIT = 500
MAX_OFFSET = 100_000

TABLES = {
    "raw": {"name": "flows", "ts": "ts", "flows": "count()", "first": "min(ts)", "last": "max(ts)", "syn": "countIf(proto = 6 AND bitAnd(tcp_flags, 18) = 2)",
            "port": "if(src_port != 0 AND (dst_port = 0 OR src_port < dst_port), src_port, dst_port)",
            "server": "if(dst_port = if(src_port != 0 AND (dst_port = 0 OR src_port < dst_port), src_port, dst_port), dst_ip, src_ip)",
            "client": "if(dst_port = if(src_port != 0 AND (dst_port = 0 OR src_port < dst_port), src_port, dst_port), src_ip, dst_ip)",
            "bucket": "toStartOfMinute(ts)", "sampling": "max(sampling)", "ips": True, "ifs": True, "l7": "l7"},
    "conv": {"name": "flows_conv_hourly", "ts": "hour", "flows": "sum(flows)", "first": "min(first)", "last": "max(last)", "syn": "sum(syn_flows)",
             "port": "port", "server": "if(server_is_dst = 1, dst_ip, src_ip)", "client": "if(server_is_dst = 1, src_ip, dst_ip)",
             "bucket": "hour", "sampling": "max(sampling)", "ips": True, "ifs": False, "l7": "l7"},
    "ifh": {"name": "flows_if_hourly", "ts": "hour", "flows": "sum(flows)", "first": "min(hour)", "last": "max(hour)", "syn": "toUInt64(0)",
            "port": "port", "server": "''", "client": "''", "bucket": "hour", "sampling": "toUInt32(0)", "ips": False, "ifs": True, "l7": "''"},
}


def parse_net(v: str) -> str:
    """An IP or CIDR as normalised text (ValueError otherwise)."""
    v = (v or "").strip()
    if "/" in v:
        return str(ipaddress.ip_network(v, strict=False))
    return str(ipaddress.ip_address(v))


@dataclass
class Filters:
    range: str = "1h"
    start: datetime | None = None
    end: datetime | None = None
    exporter: str | None = None
    interface: int | None = None            # ifIndex on `exporter`
    vlan: int | None = None
    app: str | None = None
    category: str | None = None
    proto: int | None = None
    port: int | None = None
    src: str | None = None                  # IP or CIDR
    dst: str | None = None
    ip: str | None = None                   # either side
    direction: str | None = None
    site: str | None = None
    site_exporters: list[str] = field(default_factory=list)
    allowed_exporters: list[str] | None = None   # site-scoped accounts (None: unrestricted)

    def window(self, now: datetime | None = None) -> tuple[datetime, datetime]:
        now = now or datetime.now(timezone.utc)
        if self.start or self.end:
            t1 = min(self.end or now, now)
            t0 = self.start or (t1 - timedelta(hours=1))
            if t0 >= t1:
                raise ValueError("start must be before end")
            if t1 - t0 > MAX_SPAN:
                raise ValueError("the window may be at most 30 days")
            return t0, t1
        return now - timedelta(minutes=PRESETS[self.range]), now

    @property
    def needs_ips(self) -> bool:
        return bool(self.src or self.dst or self.ip)

    def key(self) -> tuple:
        return tuple(sorted((k, str(v)) for k, v in self.__dict__.items()))


@dataclass
class Ctx:
    reg: Registry
    nets: Networks
    ip_apps: dict[str, tuple[str, str, str]] = field(default_factory=dict)   # ip → (app, category, confidence)
    dedup: bool = True


def choose(f: Filters, need_if: bool = False, need_raw: bool = False) -> str:
    t0, t1 = f.window()
    if need_raw or t1 - t0 <= timedelta(hours=RAW_HOURS):
        return "raw"
    if need_if or f.interface is not None:
        return "raw" if f.needs_ips or f.app or f.category or f.direction else "ifh"
    return "conv"


class Sql:
    """Expressions for one source table; parameters accumulate in self.p."""

    def __init__(self, ctx: Ctx, src: str):
        self.ctx, self.src, self.t = ctx, src, TABLES[src]
        self.p: dict = {}
        self._app = None

    def param(self, name: str, value) -> str:
        self.p[name] = value
        return name

    # ------------------------------------------------------------ classification
    def _port_key(self) -> str:
        if self.src == "raw":
            kd, ks = "(toUInt32(proto) * 65536 + toUInt32(dst_port))", "(toUInt32(proto) * 65536 + toUInt32(src_port))"
            return (f"multiIf(has({{pk:Array(UInt32)}}, {kd}) AND has({{pk:Array(UInt32)}}, {ks}) AND dst_port != 0 AND src_port != 0, "
                    f"if(dst_port <= src_port, {kd}, {ks}), has({{pk:Array(UInt32)}}, {kd}) AND dst_port != 0, {kd}, "
                    f"has({{pk:Array(UInt32)}}, {ks}) AND src_port != 0, {ks}, toUInt32(0))")
        return "(toUInt32(proto) * 65536 + toUInt32(port))"

    def _lookups(self):
        r = self.ctx.reg
        self.p.update(pk=r.port_keys or [0], pl=r.port_labels or [""], pc=r.port_cats or [""], pe=r.port_enc or [2],
                      pp=r.proto_keys or [255], ppl=r.proto_labels or [""], ppc=r.proto_cats or [""])
        ips = list(self.ctx.ip_apps.items())[:5000] if self.t["ips"] else []
        self.p.update(ik=[i for i, _ in ips] or [""], ia=[v[0] for _, v in ips] or [""], ic=[v[1] for _, v in ips] or [""],
                      icf=[v[2] for _, v in ips] or ["unknown"])

    def port_label(self) -> str:
        self._lookups()
        k = self._port_key()
        return (f"if(has({{pk:Array(UInt32)}}, {k}), transform({k}, {{pk:Array(UInt32)}}, {{pl:Array(String)}}, ''), "
                f"if(has({{pp:Array(UInt8)}}, proto), transform(proto, {{pp:Array(UInt8)}}, {{ppl:Array(String)}}, 'Unknown'), 'Unknown'))")

    def port_cat(self) -> str:
        k = self._port_key()
        return (f"if(has({{pk:Array(UInt32)}}, {k}), transform({k}, {{pk:Array(UInt32)}}, {{pc:Array(String)}}, 'other'), "
                f"if(has({{pp:Array(UInt8)}}, proto), transform(proto, {{pp:Array(UInt8)}}, {{ppc:Array(String)}}, 'other'), 'other'))")

    def port_enc(self) -> str:
        k = self._port_key()
        return f"transform({k}, {{pk:Array(UInt32)}}, {{pe:Array(UInt8)}}, toUInt8(2))"

    def _ipv(self, arr: str, default: str) -> str:
        return f"transform({self.t['server']}, {{ik:Array(String)}}, {{{arr}:Array(String)}}, '{default}')"

    def app(self) -> str:
        """Final label: enrichment (confirmed / high) > packet evidence (QUIC header, HTTP line, SSH banner) > provider
        (probable, prefixed to the port label) > port signature > Unknown."""
        if self._app:
            return self._app
        pl = self.port_label()
        if not self.t["ips"]:
            self._app = pl
            return pl
        conf, l7 = self._ipv("icf", "unknown"), self.t["l7"]
        ipapp = self._ipv("ia", "")
        self._app = (f"multiIf({conf} IN ('confirmed', 'high'), {ipapp}, startsWith({l7}, 'quic'), 'QUIC', "
                     f"{l7} = 'http' AND ({pl}) IN ('Unknown', 'HTTP Alternate (possible)'), 'HTTP', {l7} = 'ssh' AND ({pl}) = 'Unknown', 'SSH', "
                     f"{l7} = 'tls' AND ({pl}) = 'Unknown', 'TLS', {conf} = 'probable', concat({pl}, ' · ', {ipapp}), {pl})")
        return self._app

    def category(self) -> str:
        pc = self.port_cat()
        if not self.t["ips"]:
            return pc
        conf = self._ipv("icf", "unknown")
        return f"if({conf} IN ('confirmed', 'high'), {self._ipv('ic', 'other')}, {pc})"

    def confidence(self) -> str:
        pl = self.port_label()
        if not self.t["ips"]:
            return f"if(({pl}) = 'Unknown', 'unknown', 'port-based')"
        conf, l7 = self._ipv("icf", "unknown"), self.t["l7"]
        return (f"multiIf({conf} IN ('confirmed', 'high'), {conf}, {l7} IN ('quic-v1', 'quic-v2', 'quic-draft', 'quic-long', 'http', 'ssh', 'tls'), 'confirmed', "
                f"{conf} = 'probable', 'probable', ({pl}) = 'Unknown', 'unknown', 'port-based')")

    # ------------------------------------------------------------ endpoints
    def internal(self, col: str, tag: str) -> str:
        e, p = self.ctx.nets.sql_internal(col, f"in_{tag}")
        self.p.update(p)
        return e

    def net_attr(self, col: str, attr: str, tag: str) -> str:
        e, p = self.ctx.nets.sql_attr(col, attr, f"na_{attr}_{tag}")
        self.p.update(p)
        return e

    def src_vlan(self) -> str:
        if not self.t["ips"]:
            return "vlan"
        return f"if(vlan != 0, vlan, {self.net_attr('src_ip', 'vlan', 's')})"

    def dst_vlan(self) -> str:
        if not self.t["ips"]:
            return "toUInt16(0)"
        base = self.net_attr("dst_ip", "vlan", "d")
        return f"if(dst_vlan != 0, dst_vlan, {base})" if self.src == "raw" else base

    def direction(self) -> str:
        if not self.t["ips"]:
            return "''"
        si, di = self.internal("src_ip", "s"), self.internal("dst_ip", "d")
        return f"multiIf(({si}) AND ({di}), 'east_west', ({si}), 'outbound', ({di}), 'inbound', 'transit')"

    # ------------------------------------------------------------ WHERE
    def where(self, f: Filters, t0: datetime, t1: datetime) -> str:
        ts = self.t["ts"]
        if self.src == "raw":
            parts = [f"{ts} >= {{t0:DateTime64(3)}}", f"{ts} < {{t1:DateTime64(3)}}"]
        else:
            parts = [f"{ts} >= toStartOfHour({{t0:DateTime64(3)}})", f"{ts} < {{t1:DateTime64(3)}}"]
        self.p.update(t0=t0, t1=t1)
        if f.allowed_exporters is not None:
            parts.append("exporter IN {aex:Array(String)}")
            self.p["aex"] = f.allowed_exporters or ["-"]
        if f.exporter:
            parts.append("exporter = {ex:String}")
            self.p["ex"] = f.exporter
        if f.site:
            alts = ["exporter IN {sex:Array(String)}"]
            self.p["sex"] = f.site_exporters or ["-"]
            if self.t["ips"]:
                self.p["site"] = f.site
                alts += [f"({self.net_attr('src_ip', 'site', 'ss')}) = {{site:String}}", f"({self.net_attr('dst_ip', 'site', 'ds')}) = {{site:String}}"]
            parts.append("(" + " OR ".join(alts) + ")")
        if f.interface is not None:
            if not self.t["ifs"]:
                raise ValueError("interface filter needs raw records or the interface rollup")
            parts.append("(in_if = {ifx:UInt32} OR out_if = {ifx:UInt32})")
            self.p["ifx"] = f.interface
        if f.proto is not None:
            parts.append("proto = {proto:UInt8}")
            self.p["proto"] = f.proto
        if f.port is not None:
            parts.append(f"({self.t['port']}) = {{port:UInt16}}")
            self.p["port"] = f.port
        if f.vlan is not None:
            self.p["vlan"] = f.vlan
            parts.append(f"(vlan = {{vlan:UInt16}} OR ({self.src_vlan()}) = {{vlan:UInt16}} OR ({self.dst_vlan()}) = {{vlan:UInt16}})"
                         if self.t["ips"] else "vlan = {vlan:UInt16}")
        for name, col in (("src", "src_ip"), ("dst", "dst_ip")):
            v = getattr(f, name)
            if v:
                if not self.t["ips"]:
                    raise ValueError("address filters need raw records or the conversation rollup")
                parts.append(self._ipmatch(col, v, name))
        if f.ip:
            if not self.t["ips"]:
                raise ValueError("address filters need raw records or the conversation rollup")
            parts.append(f"({self._ipmatch('src_ip', f.ip, 'ip')} OR {self._ipmatch('dst_ip', f.ip, 'ip')})")
        if f.app:
            parts.append(f"({self.app()}) = {{app:String}}")
            self.p["app"] = f.app
        if f.category:
            parts.append(f"({self.category()}) = {{cat:String}}")
            self.p["cat"] = f.category
        if f.direction:
            parts.append(f"({self.direction()}) = {{dirn:String}}")
            self.p["dirn"] = f.direction
        return " AND ".join(parts)

    def _ipmatch(self, col: str, v: str, name: str) -> str:
        self.p["m_" + name] = v
        return f"isIPAddressInRange({col}, {{m_{name}:String}})" if "/" in v else f"{col} = {{m_{name}:String}}"


METRICS = {   # final-level metric expressions (level 3), from the per-bucket level
    "bytes": "sum(bb)", "packets": "sum(pp)", "flows": "sum(ff)", "first": "min(fs)", "last": "max(ls)", "sampling": "max(smp)",
    "syn_flows": "sum(syn)", "peak_bucket_bytes": "max(bb)", "sources": "uniqExactMerge(us)", "destinations": "uniqExactMerge(ud)",
    "conversations": "uniqExactMerge(uc)", "buckets": "count()",
}


def aggregate(sql: Sql, f: Filters, dims: list[tuple[str, str]], metrics: list[str], *, order: str = "bytes DESC", limit: int = 50,
              offset: int = 0, having: str = "", dedup: bool | None = None, bucket_seconds: int | None = None) -> tuple[str, str]:
    """(query, count query). dims: (alias, expression over the source table's columns). The levels:
    1 per exporter, conversation, bucket  2 deduplicated across exporters  3 per dimension and bucket  4 per dimension."""
    t0, t1 = f.window()
    where = sql.where(f, t0, t1)
    t = sql.t
    dedup = sql.ctx.dedup if dedup is None else dedup
    if not t["ips"]:
        dedup = False
    # internal aliases (k_…) never collide with source columns (an alias "vlan" over an expression reading the column
    # vlan would be circular); level 4 renames them back
    d_sel = ", ".join(f"{e} AS k_{a}" for a, e in dims) if dims else ""
    d_names = [f"k_{a}" for a, _ in dims]
    bucket = t["bucket"] if bucket_seconds is None else f"toStartOfInterval({t['ts']}, INTERVAL {int(bucket_seconds)} SECOND)"
    ident = ("src_ip AS s_ip, dst_ip AS d_ip, proto AS pr_, " + f"{t['port']} AS pt_") if t["ips"] else \
        "'' AS s_ip, '' AS d_ip, proto AS pr_, port AS pt_, in_if AS if_i, out_if AS if_o, device_id AS dev_"
    ident_names = ["s_ip", "d_ip", "pr_", "pt_"] + ([] if t["ips"] else ["if_i", "if_o", "dev_"])
    g1 = ", ".join(d_names + ident_names + ["bk", "exporter"])
    l1 = (f"SELECT {d_sel + ', ' if d_sel else ''}{ident}, {bucket} AS bk, exporter, sum(bytes) AS b, sum(packets) AS p, {t['flows']} AS f, "
          f"{t['first']} AS fs, {t['last']} AS ls, {t['sampling']} AS smp, {t['syn']} AS syn FROM {t['name']} WHERE {where} GROUP BY {g1}")
    agg = "max" if dedup else "sum"
    g2 = ", ".join(d_names + ident_names + ["bk"])
    l2 = (f"SELECT {g2}, {agg}(b) AS b, {agg}(p) AS p, {agg}(f) AS f, min(fs) AS fs, max(ls) AS ls, max(smp) AS smp, {agg}(syn) AS syn "
          f"FROM ({l1}) GROUP BY {g2}")
    g3 = ", ".join(d_names + ["bk"])
    l3 = (f"SELECT {g3}, sum(b) AS bb, sum(p) AS pp, sum(f) AS ff, min(fs) AS fs, max(ls) AS ls, max(smp) AS smp, sum(syn) AS syn, "
          f"uniqExactState(s_ip) AS us, uniqExactState(d_ip) AS ud, uniqExactState(tuple(s_ip, d_ip, pr_, pt_)) AS uc FROM ({l2}) GROUP BY {g3}")
    m_sel = ", ".join(f"{METRICS[m]} AS {m}" for m in metrics)
    g4 = ", ".join(d_names)
    rename = ", ".join(f"k_{a} AS {a}" for a, _ in dims)
    l4 = f"SELECT {rename + ', ' if rename else ''}{m_sel} FROM ({l3})" + (f" GROUP BY {g4}" if g4 else "") + (f" HAVING {having}" if having else "")
    q = l4 + (f" ORDER BY {order}" if order else "") + f" LIMIT {int(min(limit, MAX_LIMIT))} OFFSET {int(min(offset, MAX_OFFSET))}"
    cq = f"SELECT count() AS n FROM ({l4})" if g4 else "SELECT 1 AS n"
    return q, cq


def sort_clause(sort: str | None, allowed: dict[str, str], default: str) -> str:
    """'-bytes' → 'bytes DESC'; only keys in `allowed` (key → column alias)."""
    if not sort:
        return default
    desc = sort.startswith("-")
    k = sort.lstrip("-+")
    if k not in allowed:
        raise ValueError(f"cannot sort by {k}")
    return f"{allowed[k]} {'DESC' if desc else 'ASC'}"
