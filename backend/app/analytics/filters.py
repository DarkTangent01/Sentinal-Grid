"""Translate API filter parameters into parameterized ClickHouse WHERE clauses (server-side filtering)."""
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from ..config import get_settings

RANGES = {"5m": timedelta(minutes=5), "15m": timedelta(minutes=15), "1h": timedelta(hours=1),
          "24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}
CATEGORIES = ("traffic", "dns", "web", "security", "system")
ALLOWED = ("accept", "close", "timeout", "reset", "allow", "monitor")
DENIED = ("deny", "block")


@dataclass
class EventFilter:
    start: datetime | None = None
    end: datetime | None = None
    range: str | None = "24h"
    firewall_id: list[int] = field(default_factory=list)
    site: list[str] = field(default_factory=list)
    category: list[str] = field(default_factory=list)
    event_type: str | None = None
    event_subtype: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    ip: str | None = None  # either side
    src_port: int | None = None
    dst_port: int | None = None
    proto: int | None = None
    app: str | None = None
    domain: str | None = None
    dns_query: str | None = None
    dns_qtype: str | None = None
    dns_rcode: str | None = None
    action: list[str] = field(default_factory=list)
    verdict: str | None = None  # allowed | denied
    policy_id: int | None = None
    severity: list[str] = field(default_factory=list)
    url_category: str | None = None
    source: str | None = None
    user: str | None = None
    q: str | None = None
    ql: str | None = None  # SIEM query language (see analytics/ql.py)

    def window(self) -> tuple[datetime, datetime]:
        end = self.end or datetime.now(timezone.utc)
        if self.start:
            start = self.start
        else:
            start = end - RANGES.get(self.range or "24h", RANGES["24h"])
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)
        if start >= end:
            raise ValueError("start must be before end")
        return start, end


def table() -> str:
    return "events FINAL" if get_settings().clickhouse_query_final else "events"


def _ip_clause(col: str, value: str, pname: str, params: dict) -> str:
    value = value.strip()
    if "/" in value:
        net = ipaddress.ip_network(value, strict=False)  # raises ValueError on bad input
        params[pname] = str(net)
        # guard: isIPAddressInRange throws on empty/non-IP strings (e.g. system events without srcip)
        return f"isIPAddressInRange(if(isIPv4String({col}) OR isIPv6String({col}), {col}, '::'), {{{pname}:String}})"
    ipaddress.ip_address(value)
    params[pname] = value
    return f"{col} = {{{pname}:String}}"


def build_where(f: EventFilter, *, extra: list[str] | None = None, categories: tuple[str, ...] | None = None) -> tuple[str, dict]:
    start, end = f.window()
    params: dict = {"t0": start, "t1": end}
    c = ["event_time >= {t0:DateTime64(3)}", "event_time < {t1:DateTime64(3)}"]
    cats = list(f.category) or (list(categories) if categories else [])
    if categories and f.category:
        cats = [x for x in f.category if x in categories]
        if not cats:
            cats = ["__none__"]
    if cats:
        params["cats"] = cats
        c.append("category IN {cats:Array(String)}")
    if f.firewall_id:
        params["fw"] = [int(x) for x in f.firewall_id]
        c.append("firewall_id IN {fw:Array(UInt32)}")
    if f.site:
        params["sites"] = f.site
        c.append("site IN {sites:Array(String)}")
    if f.event_type:
        params["etype"] = f.event_type
        c.append("event_type = {etype:String}")
    if f.event_subtype:
        params["esub"] = f.event_subtype
        c.append("event_subtype = {esub:String}")
    if f.src_ip:
        c.append(_ip_clause("src_ip", f.src_ip, "sip", params))
    if f.dst_ip:
        c.append(_ip_clause("dst_ip", f.dst_ip, "dip", params))
    if f.ip:
        a = _ip_clause("src_ip", f.ip, "anyip", params)
        b = _ip_clause("dst_ip", f.ip, "anyip", params)
        c.append(f"({a} OR {b})")
    for col, val in (("src_port", f.src_port), ("dst_port", f.dst_port)):
        if val is not None:
            params[col] = int(val)
            c.append(f"{col} = {{{col}:UInt16}}")
    if f.proto is not None:
        params["proto"] = int(f.proto)
        c.append("proto = {proto:UInt8}")
    if f.app:
        params["app"] = f.app
        c.append("app = {app:String}")
    if f.domain:
        params["dom"] = f.domain.lower().strip()
        c.append("(lower(hostname) = {dom:String} OR endsWith(lower(hostname), concat('.', {dom:String})) "
                 "OR dns_qname = {dom:String} OR endsWith(dns_qname, concat('.', {dom:String})))")
    if f.dns_query:
        params["qn"] = f.dns_query.lower().strip()
        c.append("positionCaseInsensitive(dns_qname, {qn:String}) > 0")
    if f.dns_qtype:
        params["qt"] = f.dns_qtype.upper()
        c.append("dns_qtype = {qt:String}")
    if f.dns_rcode:
        params["rc"] = f.dns_rcode.upper()
        c.append("dns_rcode = {rc:String}")
    if f.action:
        params["acts"] = f.action
        c.append("action IN {acts:Array(String)}")
    if f.verdict == "allowed":
        c.append(f"action IN {tuple(ALLOWED)!r}")
    elif f.verdict == "denied":
        c.append(f"action IN {tuple(DENIED)!r}")
    if f.policy_id is not None:
        params["pol"] = int(f.policy_id)
        c.append("policy_id = {pol:UInt32}")
    if f.severity:
        params["sev"] = f.severity
        c.append("severity IN {sev:Array(String)}")
    if f.url_category:
        params["ucat"] = f.url_category
        c.append("url_category = {ucat:String}")
    if f.source:
        params["src"] = f.source
        c.append("source = {src:String}")
    if f.user:
        params["usr"] = f.user
        c.append("user = {usr:String}")
    if f.q:
        params["q"] = f.q[:200]
        c.append("positionCaseInsensitive(raw, {q:String}) > 0")
    if f.ql:
        from .ql import compile_ql
        compiled = compile_ql(f.ql)  # raises QLError (ValueError) with a position on bad syntax
        params.update(compiled.params)
        c.append(compiled.sql)
    c.extend(extra or [])
    return " AND ".join(c), params


def bucket_seconds(start: datetime, end: datetime, target_points: int = 120) -> int:
    span = (end - start).total_seconds()
    for b in (10, 30, 60, 300, 600, 900, 1800, 3600, 10800, 21600, 43200, 86400):
        if span / b <= target_points:
            return b
    return 86400
