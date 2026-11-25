"""APIs: Sentinel NMS → Application & Protocol Intelligence (app/traffic, docs/nms/TRAFFIC_INTELLIGENCE.md).

Permissions (app/access/rbac.py): nms.traffic.view for analytics; nms.traffic.detections.view for detections;
nms.traffic.sensitive.view for MACs, domains / DNS, reverse-DNS names and wireless user names (withheld otherwise);
nms.traffic.export for CSV; nms.traffic.rules.manage / enrichment.manage / collector.manage for configuration.
Site-scoped accounts see only the exporters of their sites. Every filter is validated here; no SQL reaches the API.
"""
from __future__ import annotations

import csv
import io
import ipaddress
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..access.rbac import has, require
from ..db.ch import ClickHouse
from ..db.models import Alert, AlertRule, Firewall, Suppression, Switch, TrafficNetwork, TrafficRule, TrafficSignature, TrafficVlanPolicy, User
from ..db.pg import get_session
from ..products import site_allowed
from ..traffic import analytics as A
from ..traffic import networks as N
from ..traffic import registry as R
from ..traffic import settings as S
from ..traffic.detections import DEFAULT_RULES as DETECTION_RULES
from ..traffic.query import PRESETS, Filters, parse_net
from .deps import RateLimiter, audit, ch_dep, csv_safe, iso

router = APIRouter(prefix="/api/nms/traffic", tags=["nms-traffic"])
VIEW, DET, SENS, EXPORT = "nms.traffic.view", "nms.traffic.detections.view", "nms.traffic.sensitive.view", "nms.traffic.export"
RULES_M, ENRICH_M, COLLECT_M = "nms.traffic.rules.manage", "nms.traffic.enrichment.manage", "nms.traffic.collector.manage"
RANGE = "^(" + "|".join(PRESETS) + ")$"
DETECTION_KEYS = {d["key"] for d in DETECTION_RULES}
_limiter = RateLimiter()
# one dependency object per permission, so FastAPI resolves the signed-in user once per request
NEED_VIEW, NEED_DET, NEED_SENS = require(VIEW), require(DET), require(SENS)
NEED_EXPORT, NEED_RULES, NEED_COLLECT = require(EXPORT), require(RULES_M), require(COLLECT_M)


def _bad(e: Exception):
    raise HTTPException(422, str(e))


async def _scope(user: User, s: AsyncSession) -> list[str] | None:
    """Exporters a site-scoped account may see (None: unrestricted)."""
    if user.role == "admin" or not [x for x in (user.sites or []) if x and x.strip()]:
        return None
    sws = (await s.execute(select(Switch.address, Switch.site))).all()
    fws = (await s.execute(select(Firewall.host, Firewall.site).where(Firewall.is_demo.is_(False)))).all()
    return sorted({a for a, site in [*sws, *fws] if a and site_allowed(user, site)})


async def filters(request: Request, range: str = Query("1h", pattern=RANGE), start: datetime | None = None, end: datetime | None = None,
                  exporter: str | None = Query(None, max_length=64), interface: int | None = Query(None, ge=0, le=2**31),
                  vlan: int | None = Query(None, ge=0, le=4095), app: str | None = Query(None, max_length=128),
                  category: str | None = Query(None, max_length=32), proto: int | None = Query(None, ge=0, le=255),
                  port: int | None = Query(None, ge=0, le=65535), src: str | None = Query(None, max_length=64), dst: str | None = Query(None, max_length=64),
                  ip: str | None = Query(None, max_length=64), direction: str | None = Query(None, pattern="^(east_west|outbound|inbound|transit)$"),
                  site: str | None = Query(None, max_length=128), user: User = Depends(NEED_VIEW),
                  s: AsyncSession = Depends(get_session)) -> Filters:
    try:
        nets = {k: parse_net(v) if v else None for k, v in (("src", src), ("dst", dst), ("ip", ip))}
        if exporter:
            exporter = str(ipaddress.ip_address(exporter))
    except ValueError as e:
        raise HTTPException(422, f"not an IP address or network: {e}")
    if interface is not None and not exporter:
        raise HTTPException(422, "an interface filter needs the exporter (device) too")
    for t in (start, end):
        if t is not None and t.tzinfo is None:
            raise HTTPException(422, "start / end need a time zone (ISO 8601 with Z or an offset)")
    f = Filters(range=range, start=start, end=end, exporter=exporter, interface=interface, vlan=vlan, app=app, category=category, proto=proto,
                port=port, direction=direction, site=site, **nets)
    if site:
        sws = (await s.execute(select(Switch.address).where(func.lower(Switch.site) == site.lower()))).scalars().all()
        fws = (await s.execute(select(Firewall.host).where(func.lower(Firewall.site) == site.lower()))).scalars().all()
        f.site_exporters = sorted(set(sws) | set(fws))
    f.allowed_exporters = await _scope(user, s)
    try:
        f.window()
    except ValueError as e:
        _bad(e)
    return f


async def _guard(coro):
    try:
        return await coro
    except ValueError as e:
        _bad(e)


def _sens(user: User) -> bool:
    return has(user, SENS)


# ------------------------------------------------------------------ analytics
@router.get("/overview")
async def overview(f: Filters = Depends(filters), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    return await _guard(A.cached(("ov", f.key()), lambda: A.overview(s, ch, f)))


@router.get("/applications")
async def applications(f: Filters = Depends(filters), sort: str | None = Query(None, max_length=32), limit: int = Query(50, ge=1, le=500),
                       offset: int = Query(0, ge=0, le=100_000), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    return await _guard(A.cached(("apps", f.key(), sort, limit, offset), lambda: A.applications(s, ch, f, sort, limit, offset)))


@router.get("/protocols")
async def protocols(f: Filters = Depends(filters), limit: int = Query(50, ge=1, le=500), s: AsyncSession = Depends(get_session),
                    ch: ClickHouse = Depends(ch_dep)):
    return await _guard(A.cached(("proto", f.key(), limit), lambda: A.protocols(s, ch, f, limit)))


@router.get("/web")
async def web(f: Filters = Depends(filters), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    return await _guard(A.cached(("web", f.key()), lambda: A.web_protocols(s, ch, f)))


@router.get("/top-sources")
async def top_sources(f: Filters = Depends(filters), sort: str | None = Query(None, max_length=32), limit: int = Query(25, ge=1, le=500),
                      offset: int = Query(0, ge=0, le=100_000), user: User = Depends(NEED_VIEW), s: AsyncSession = Depends(get_session),
                      ch: ClickHouse = Depends(ch_dep)):
    sens = _sens(user)
    return await _guard(A.cached(("src", f.key(), sort, limit, offset, sens), lambda: A.talkers(s, ch, f, "sources", sort, limit, offset, sensitive=sens)))


@router.get("/top-destinations")
async def top_destinations(f: Filters = Depends(filters), sort: str | None = Query(None, max_length=32), limit: int = Query(25, ge=1, le=500),
                           offset: int = Query(0, ge=0, le=100_000), user: User = Depends(NEED_VIEW), s: AsyncSession = Depends(get_session),
                           ch: ClickHouse = Depends(ch_dep)):
    sens = _sens(user)
    return await _guard(A.cached(("dst", f.key(), sort, limit, offset, sens),
                                 lambda: A.talkers(s, ch, f, "destinations", sort, limit, offset, sensitive=sens)))


@router.get("/conversations")
async def conversations(f: Filters = Depends(filters), sort: str | None = Query(None, max_length=32), limit: int = Query(50, ge=1, le=500),
                        offset: int = Query(0, ge=0, le=100_000), user: User = Depends(NEED_VIEW), s: AsyncSession = Depends(get_session),
                        ch: ClickHouse = Depends(ch_dep)):
    sens = _sens(user)
    return await _guard(A.cached(("conv", f.key(), sort, limit, offset, sens), lambda: A.conversations(s, ch, f, sort, limit, offset, sensitive=sens)))


@router.get("/flows")
async def flow_records(f: Filters = Depends(filters), limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0, le=100_000),
                       user: User = Depends(NEED_VIEW), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    return await _guard(A.flows(s, ch, f, limit, offset, sensitive=_sens(user)))


@router.get("/vlans")
async def vlans(f: Filters = Depends(filters), limit: int = Query(100, ge=1, le=500), s: AsyncSession = Depends(get_session),
                ch: ClickHouse = Depends(ch_dep)):
    return await _guard(A.cached(("vlans", f.key(), limit), lambda: A.vlans(s, ch, f, limit)))


@router.get("/vlan-matrix")
async def vlan_matrix(f: Filters = Depends(filters), limit: int = Query(200, ge=1, le=500), s: AsyncSession = Depends(get_session),
                      ch: ClickHouse = Depends(ch_dep)):
    return await _guard(A.cached(("vm", f.key(), limit), lambda: A.vlan_matrix(s, ch, f, limit)))


@router.get("/interfaces")
async def interfaces(f: Filters = Depends(filters), limit: int = Query(100, ge=1, le=500), s: AsyncSession = Depends(get_session),
                     ch: ClickHouse = Depends(ch_dep)):
    st = await S.load_settings(s)
    return await _guard(A.cached(("ifs", f.key(), limit), lambda: A.interfaces(s, ch, f, limit, lag_mode=st["lag_mode"])))


@router.get("/trends")
async def trends(f: Filters = Depends(filters), by: str = Query("none", pattern="^(none|app|direction|proto|category)$"),
                 top: int = Query(6, ge=1, le=12), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    return await _guard(A.cached(("tr", f.key(), by, top), lambda: A.trends(s, ch, f, by, top)))


@router.get("/domains")
async def domains(f: Filters = Depends(filters), q: str | None = Query(None, max_length=128), limit: int = Query(50, ge=1, le=500),
                  offset: int = Query(0, ge=0, le=100_000), user: User = Depends(NEED_SENS), s: AsyncSession = Depends(get_session),
                  ch: ClickHouse = Depends(ch_dep)):
    if f.allowed_exporters is not None:
        raise HTTPException(403, "DNS / domain intelligence is not site-scoped and is available to unscoped accounts only")
    return await _guard(A.cached(("dom", f.key(), q, limit, offset), lambda: A.domains(s, ch, f, limit, offset, q)))


@router.get("/collectors")
async def collectors(_: User = Depends(NEED_VIEW), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    return await A.collectors(s, ch)


@router.get("/hosts/{addr}")
async def host(addr: str, f: Filters = Depends(filters), user: User = Depends(NEED_VIEW), s: AsyncSession = Depends(get_session),
               ch: ClickHouse = Depends(ch_dep)):
    """One address: identity (inventory, wireless client, MAC location, enrichment) and its traffic in the window."""
    try:
        ip = str(ipaddress.ip_address(addr))
    except ValueError:
        raise HTTPException(422, "not an IP address")
    from ..db.models import TrafficIpInfo
    from ..traffic.enrich import hosts
    sens = _sens(user)
    info = (await hosts(s, [ip], sensitive=sens)).get(ip, {})
    row = await s.get(TrafficIpInfo, ip)
    fi = Filters(**{**f.__dict__, "ip": ip})
    apps = await _guard(A.applications(s, ch, fi, None, 10, 0))
    peers_out = await _guard(A.talkers(s, ch, Filters(**{**f.__dict__, "src": ip}), "destinations", None, 10, 0, sensitive=sens))
    peers_in = await _guard(A.talkers(s, ch, Filters(**{**f.__dict__, "dst": ip}), "sources", None, 10, 0, sensitive=sens))
    trend = await _guard(A.trends(s, ch, fi, "app", 5))
    enr = None
    if row:
        enr = {"asn": row.asn, "as_org": row.as_org, "country": row.country, "app": row.app, "category": row.category, "confidence": row.confidence,
               "evidence": row.evidence, "fw_app": row.fw_app, "updated_at": iso(row.updated_at),
               "domains": row.domains if sens else [], "rdns": row.rdns if sens else "", "domain_count": row.domain_count}
    return {"ip": ip, "identity": info, "enrichment": enr, "applications": apps["items"], "destinations": peers_out["items"],
            "sources": peers_in["items"], "trend": trend}


@router.get("/baseline/{addr}")
async def baseline(addr: str, hours: int = Query(48, ge=6, le=168), _: User = Depends(NEED_VIEW), ch: ClickHouse = Depends(ch_dep)):
    """One host's hourly upload / download / peers with the expected band (hour-of-day median and upper bound, 14 days)."""
    try:
        ip = str(ipaddress.ip_address(addr))
    except ValueError:
        raise HTTPException(422, "not an IP address")
    from ..traffic.baselines import profile
    return await profile(ch, ip, hours=hours)


@router.get("/options")
async def options(user: User = Depends(NEED_VIEW), s: AsyncSession = Depends(get_session)):
    """Filter choices: devices (exporters), sites, VLANs, zones, applications and categories from the registry."""
    scope = await _scope(user, s)
    devs = [{"exporter": x.address, "name": x.name, "site": x.site, "kind": "switch"} for x in (await s.execute(select(Switch))).scalars()]
    devs += [{"exporter": x.host, "name": x.name, "site": x.site, "kind": "firewall"}
             for x in (await s.execute(select(Firewall).where(Firewall.is_demo.is_(False)))).scalars()]
    if scope is not None:
        devs = [d for d in devs if d["exporter"] in scope]
    reg = await R.load(s)
    nets = await N.load(s)
    return {"devices": sorted(devs, key=lambda d: d["name"].lower()), "sites": sorted({d["site"] for d in devs if d["site"]}),
            "vlans": sorted({n.vlan for n in nets.nets if n.vlan}), "zones": list(N.ZONES), "categories": list(R.CATEGORIES),
            "applications": sorted(set(reg.port_labels) | set(reg.proto_labels) | {a for a, _ in reg.asn.values()} | {d[1] for d in reg.domains}),
            "protocols": [{"proto": k, "name": v} for k, v in sorted(R.PROTOCOLS.items())], "ranges": list(PRESETS),
            "permissions": {k: has(user, p) for k, p in (("detections", DET), ("sensitive", SENS), ("export", EXPORT), ("rules", RULES_M),
                                                          ("enrichment", ENRICH_M), ("collector", COLLECT_M))}}


# ------------------------------------------------------------------ detections
DET_SORT = {"last_seen": Alert.last_seen, "first_seen": Alert.first_seen, "severity": Alert.severity, "count": Alert.event_count}


def _det_out(a: Alert) -> dict:
    ev = a.evidence or {}
    return {"id": a.id, "rule_key": a.rule_key, "name": a.name, "severity": a.severity, "status": a.status, "src_ip": a.src_ip, "dst_ip": a.dst_ip,
            "first_seen": iso(a.first_seen), "last_seen": iso(a.last_seen), "event_count": a.event_count, "explanation": a.explanation,
            "assignee": a.assignee, "notes": a.notes, "incident_id": a.incident_id, "evidence": ev, "filter": (a.event_filter or {}).get("traffic", {}),
            "bytes": ev.get("bytes"), "confidence": ev.get("confidence", ""), "group_key": a.group_key, "category": "traffic"}


@router.get("/detections")
async def detections(status: list[str] = Query(default=[]), severity: list[str] = Query(default=[]), rule: str | None = Query(None, max_length=64),
                     ip: str | None = Query(None, max_length=64), range: str = Query("7d", pattern=RANGE), sort: str = Query("-last_seen", max_length=32),
                     limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0, le=100_000), user: User = Depends(NEED_DET),
                     s: AsyncSession = Depends(get_session)):
    since = datetime.now(timezone.utc) - timedelta(minutes=PRESETS[range])
    q = select(Alert).where(Alert.rule_key.in_(DETECTION_KEYS), Alert.last_seen >= since)
    if status:
        q = q.where(Alert.status.in_(status))
    if severity:
        q = q.where(Alert.severity.in_(severity))
    if rule:
        if rule not in DETECTION_KEYS:
            raise HTTPException(422, "unknown detection rule")
        q = q.where(Alert.rule_key == rule)
    if ip:
        q = q.where((Alert.src_ip == ip) | (Alert.dst_ip == ip))
    k = sort.lstrip("-+")
    if k not in DET_SORT:
        raise HTTPException(422, f"cannot sort by {k}")
    col = DET_SORT[k]
    total = (await s.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
    rows = (await s.execute(q.order_by(col.desc() if sort.startswith("-") else col.asc()).limit(limit).offset(offset))).scalars().all()
    if user.role != "admin" and [x for x in (user.sites or []) if x]:
        rows = [a for a in rows if any(site_allowed(user, x) for x in (a.sites or [""]))]
    counts = dict((await s.execute(select(Alert.severity, func.count()).where(Alert.rule_key.in_(DETECTION_KEYS), Alert.last_seen >= since,
                                                                             Alert.status != "resolved").group_by(Alert.severity))).all())
    return {"items": [_det_out(a) for a in rows], "total": int(total), "open_by_severity": counts}


@router.get("/detections/{did}")
async def detection(did: int, _: User = Depends(NEED_DET), s: AsyncSession = Depends(get_session)):
    a = await s.get(Alert, did)
    if not a or a.rule_key not in DETECTION_KEYS:
        raise HTTPException(404, "not found")
    return _det_out(a)


class DetectionPatch(BaseModel):
    status: str | None = Field(None, pattern=r"^(new|investigating|resolved)$")
    assignee: str | None = Field(None, max_length=64)
    notes: str | None = Field(None, max_length=10_000)


@router.patch("/detections/{did}")
async def update_detection(did: int, body: DetectionPatch, request: Request, user: User = Depends(NEED_DET), s: AsyncSession = Depends(get_session)):
    """Acknowledge (investigating), resolve, assign, or add resolution notes."""
    a = await s.get(Alert, did)
    if not a or a.rule_key not in DETECTION_KEYS:
        raise HTTPException(404, "not found")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(a, k, v)
    await s.commit()
    await audit(s, request, user.username, "traffic_detection_update", str(did), body.model_dump(exclude_none=True))
    return _det_out(a)


class SuppressIn(BaseModel):
    hours: int | None = Field(24, ge=1, le=24 * 365)
    scope: str = Field("group", pattern="^(group|rule)$")
    reason: str = Field("", max_length=1000)


@router.post("/detections/{did}/suppress")
async def suppress_detection(did: int, body: SuppressIn, request: Request, user: User = Depends(NEED_RULES), s: AsyncSession = Depends(get_session)):
    a = await s.get(Alert, did)
    if not a or a.rule_key not in DETECTION_KEYS:
        raise HTTPException(404, "not found")
    until = datetime.now(timezone.utc) + timedelta(hours=body.hours) if body.hours else None
    s.add(Suppression(rule_key=a.rule_key, group_key=a.group_key if body.scope == "group" else "*", until=until, reason=body.reason,
                      created_by=user.username))
    a.status = "suppressed"
    await s.commit()
    await audit(s, request, user.username, "traffic_detection_suppress", str(did), body.model_dump())
    return {"ok": True}


@router.get("/detection-rules")
async def detection_rules(_: User = Depends(NEED_DET), s: AsyncSession = Depends(get_session)):
    rows = {r.key: r for r in (await s.execute(select(AlertRule).where(AlertRule.key.in_(DETECTION_KEYS)))).scalars()}
    out = []
    for d in DETECTION_RULES:
        r = rows.get(d["key"])
        out.append({"key": d["key"], "name": d["name"], "description": d["description"], "enabled": r.enabled if r else True,
                    "severity": r.severity if r else d["severity"], "params": (r.params if r else d["params"]) or {}, "defaults": d["params"]})
    return out


class DetectionRuleIn(BaseModel):
    enabled: bool | None = None
    severity: str | None = Field(None, pattern=r"^(critical|high|medium|low|informational)$")
    params: dict | None = None


@router.put("/detection-rules/{key}")
async def update_detection_rule(key: str, body: DetectionRuleIn, request: Request, user: User = Depends(NEED_RULES),
                                s: AsyncSession = Depends(get_session)):
    """Enable / disable, severity, thresholds, time window, allow lists. Only known parameters, with their default's type."""
    if key not in DETECTION_KEYS:
        raise HTTPException(404, "unknown detection rule")
    r = (await s.execute(select(AlertRule).where(AlertRule.key == key))).scalar_one_or_none()
    if r is None:
        raise HTTPException(409, "rule not seeded yet (run migrations)")
    defaults = next(d["params"] for d in DETECTION_RULES if d["key"] == key)
    if body.params is not None:
        clean = {}
        for k, v in body.params.items():
            if k not in defaults:
                raise HTTPException(422, f"unknown parameter {k}")
            d = defaults[k]
            if isinstance(d, bool):
                ok = isinstance(v, bool)
            elif isinstance(d, int):
                ok = isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 10**12
                if ok and k.endswith("_minutes"):
                    ok = 1 <= v <= 1440
                if ok and k.endswith("_days"):
                    ok = 1 <= v <= 30
            elif isinstance(d, list):
                ok = isinstance(v, list) and len(v) <= 500 and all(isinstance(x, (str, int)) for x in v)
                if ok and k.startswith("allow_"):
                    try:
                        v = sorted({str(ipaddress.ip_network(str(x).strip(), strict=False)) for x in v})
                    except ValueError:
                        raise HTTPException(422, f"{k}: not an IP address or network")
            else:
                ok = isinstance(v, type(d))
            if not ok:
                raise HTTPException(422, f"invalid value for {k}")
            clean[k] = v
        r.params = {**(r.params or {}), **clean}
    if body.enabled is not None:
        r.enabled = body.enabled
    if body.severity:
        r.severity = body.severity
    await s.commit()
    await audit(s, request, user.username, "traffic_rule_update", key, body.model_dump(exclude_none=True))
    return {"key": key, "enabled": r.enabled, "severity": r.severity, "params": r.params}


# ------------------------------------------------------------------ custom watch rules
class WatchRuleIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field("", max_length=2000)
    enabled: bool = True
    severity: str = Field("medium", pattern=r"^(critical|high|medium|low|informational)$")
    proto: int | None = Field(None, ge=0, le=255)
    ports: list[int] = Field(default_factory=list, max_length=100)
    src_cidrs: list[str] = Field(default_factory=list, max_length=100)
    dst_cidrs: list[str] = Field(default_factory=list, max_length=100)
    exclude_cidrs: list[str] = Field(default_factory=list, max_length=100)
    direction: str = Field("any", pattern="^(any|inbound|outbound|east_west|transit)$")
    min_bytes: int = Field(0, ge=0, le=10**13)
    window_minutes: int = Field(15, ge=1, le=1440)

    @field_validator("ports")
    @classmethod
    def _ports(cls, v):
        if any(not 0 <= p <= 65535 for p in v):
            raise ValueError("ports are 0–65535")
        return sorted(set(v))

    @field_validator("src_cidrs", "dst_cidrs", "exclude_cidrs")
    @classmethod
    def _cidrs(cls, v):
        return sorted({str(ipaddress.ip_network(x.strip(), strict=False)) for x in v})


def _rule_out(r: TrafficRule) -> dict:
    return {k: getattr(r, k) for k in ("id", "name", "description", "enabled", "severity", "proto", "ports", "src_cidrs", "dst_cidrs", "exclude_cidrs",
                                       "direction", "min_bytes", "window_minutes", "created_by")} | {"updated_at": iso(r.updated_at)}


@router.get("/rules")
async def list_rules(_: User = Depends(NEED_DET), s: AsyncSession = Depends(get_session)):
    return [_rule_out(r) for r in (await s.execute(select(TrafficRule).order_by(TrafficRule.name))).scalars()]


@router.post("/rules", status_code=201)
async def create_rule(body: WatchRuleIn, request: Request, user: User = Depends(NEED_RULES), s: AsyncSession = Depends(get_session)):
    if (await s.execute(select(TrafficRule).where(TrafficRule.name == body.name))).first():
        raise HTTPException(409, "a rule with this name exists")
    r = TrafficRule(**body.model_dump(), created_by=user.username)
    s.add(r)
    await s.commit()
    await audit(s, request, user.username, "traffic_watch_rule_create", body.name)
    return _rule_out(r)


@router.put("/rules/{rid}")
async def update_rule(rid: int, body: WatchRuleIn, request: Request, user: User = Depends(NEED_RULES), s: AsyncSession = Depends(get_session)):
    r = await s.get(TrafficRule, rid)
    if not r:
        raise HTTPException(404, "not found")
    for k, v in body.model_dump().items():
        setattr(r, k, v)
    await s.commit()
    await audit(s, request, user.username, "traffic_watch_rule_update", body.name)
    return _rule_out(r)


@router.delete("/rules/{rid}")
async def delete_rule(rid: int, request: Request, user: User = Depends(NEED_RULES), s: AsyncSession = Depends(get_session)):
    r = await s.get(TrafficRule, rid)
    if not r:
        raise HTTPException(404, "not found")
    await s.delete(r)
    await s.commit()
    await audit(s, request, user.username, "traffic_watch_rule_delete", r.name)
    return {"ok": True}


# ------------------------------------------------------------------ signatures
class SignatureIn(BaseModel):
    kind: str = Field("port", pattern="^(port|asn|domain)$")
    proto: int | None = Field(None, ge=0, le=255)
    port_from: int | None = Field(None, ge=0, le=65535)
    port_to: int | None = Field(None, ge=0, le=65535)
    match: str = Field("", max_length=255)
    app: str = Field(min_length=1, max_length=64)
    category: str = Field("other", max_length=32)
    encrypted: bool | None = None
    ambiguous: bool = False
    description: str = Field("", max_length=2000)
    enabled: bool = True

    def checked(self) -> dict:
        d = self.model_dump()
        if self.category not in R.CATEGORIES:
            raise HTTPException(422, f"category: one of {', '.join(R.CATEGORIES)}")
        if self.kind == "port":
            if self.proto is None:
                raise HTTPException(422, "a port signature needs the IP protocol")
            if (self.port_from is None) != (self.port_to is None) and self.port_to is not None:
                raise HTTPException(422, "port_to needs port_from")
            if self.port_from is not None:
                d["port_to"] = self.port_to if self.port_to is not None else self.port_from
                if d["port_to"] < self.port_from or d["port_to"] - self.port_from >= R.MAX_RANGE:
                    raise HTTPException(422, f"port range: from ≤ to, at most {R.MAX_RANGE} ports")
            d["match"] = ""
        elif self.kind == "asn":
            if not self.match.strip().isdigit():
                raise HTTPException(422, "an ASN signature matches an AS number")
            d.update(proto=None, port_from=None, port_to=None, match=self.match.strip())
        else:
            m = self.match.strip().lower().lstrip("*.").rstrip(".")
            if not m or " " in m or "." not in m or len(m) > 253:
                raise HTTPException(422, "a domain signature matches a domain suffix such as example.com")
            d.update(proto=None, port_from=None, port_to=None, match=m)
        return d


def _sig_out(r: TrafficSignature) -> dict:
    return {k: getattr(r, k) for k in ("id", "kind", "proto", "port_from", "port_to", "match", "app", "category", "encrypted", "ambiguous",
                                       "description", "builtin_key", "enabled", "updated_by")} | {"updated_at": iso(r.updated_at),
                                                                                                   "label": R.label_of(r.app, r.ambiguous)}


@router.get("/signatures")
async def signatures(kind: str | None = Query(None, pattern="^(port|asn|domain)$"), _: User = Depends(NEED_VIEW), s: AsyncSession = Depends(get_session)):
    q = select(TrafficSignature).order_by(TrafficSignature.kind, TrafficSignature.proto, TrafficSignature.port_from, TrafficSignature.match)
    if kind:
        q = q.where(TrafficSignature.kind == kind)
    return [_sig_out(r) for r in (await s.execute(q)).scalars()]


@router.post("/signatures", status_code=201)
async def create_signature(body: SignatureIn, request: Request, user: User = Depends(NEED_RULES), s: AsyncSession = Depends(get_session)):
    r = TrafficSignature(**body.checked(), updated_by=user.username)
    s.add(r)
    await s.commit()
    R.invalidate()
    A.clear_cache()
    await audit(s, request, user.username, "traffic_signature_create", body.app)
    return _sig_out(r)


@router.put("/signatures/{sid}")
async def update_signature(sid: int, body: SignatureIn, request: Request, user: User = Depends(NEED_RULES), s: AsyncSession = Depends(get_session)):
    r = await s.get(TrafficSignature, sid)
    if not r:
        raise HTTPException(404, "not found")
    for k, v in body.checked().items():
        setattr(r, k, v)
    r.updated_by = user.username
    await s.commit()
    R.invalidate()
    A.clear_cache()
    await audit(s, request, user.username, "traffic_signature_update", body.app)
    return _sig_out(r)


@router.delete("/signatures/{sid}")
async def delete_signature(sid: int, request: Request, user: User = Depends(NEED_RULES), s: AsyncSession = Depends(get_session)):
    r = await s.get(TrafficSignature, sid)
    if not r:
        raise HTTPException(404, "not found")
    await s.delete(r)
    await s.commit()
    R.invalidate()
    A.clear_cache()
    await audit(s, request, user.username, "traffic_signature_delete", r.app)
    return {"ok": True}


# ------------------------------------------------------------------ networks, zones, VLAN policies
class NetworkIn(BaseModel):
    cidr: str = Field(min_length=3, max_length=64)
    name: str = Field("", max_length=128)
    site: str = Field("", max_length=128)
    vlan: int | None = Field(None, ge=1, le=4094)
    zone: str = Field("corporate", max_length=32)
    internal: bool = True
    description: str = Field("", max_length=2000)

    @field_validator("cidr")
    @classmethod
    def _cidr(cls, v):
        return str(ipaddress.ip_network(v.strip(), strict=False))

    @field_validator("zone")
    @classmethod
    def _zone(cls, v):
        if v not in N.ZONES:
            raise ValueError(f"zone: one of {', '.join(N.ZONES)}")
        return v


def _net_out(r: TrafficNetwork) -> dict:
    return {k: getattr(r, k) for k in ("id", "cidr", "name", "site", "vlan", "zone", "internal", "description", "created_by")}


@router.get("/networks")
async def networks(_: User = Depends(NEED_VIEW), s: AsyncSession = Depends(get_session)):
    rows = [_net_out(r) for r in (await s.execute(select(TrafficNetwork).order_by(TrafficNetwork.cidr))).scalars()]
    return {"items": rows, "fallback_internal": N.PRIVATE if not any(r["internal"] for r in rows) else []}


@router.post("/networks", status_code=201)
async def create_network(body: NetworkIn, request: Request, user: User = Depends(NEED_COLLECT), s: AsyncSession = Depends(get_session)):
    if (await s.execute(select(TrafficNetwork).where(TrafficNetwork.cidr == body.cidr))).first():
        raise HTTPException(409, "this network exists")
    r = TrafficNetwork(**body.model_dump(), created_by=user.username)
    s.add(r)
    await s.commit()
    N.invalidate()
    A.clear_cache()
    await audit(s, request, user.username, "traffic_network_create", body.cidr, body.model_dump())
    return _net_out(r)


@router.put("/networks/{nid}")
async def update_network(nid: int, body: NetworkIn, request: Request, user: User = Depends(NEED_COLLECT), s: AsyncSession = Depends(get_session)):
    r = await s.get(TrafficNetwork, nid)
    if not r:
        raise HTTPException(404, "not found")
    dup = (await s.execute(select(TrafficNetwork).where(TrafficNetwork.cidr == body.cidr, TrafficNetwork.id != nid))).first()
    if dup:
        raise HTTPException(409, "this network exists")
    for k, v in body.model_dump().items():
        setattr(r, k, v)
    await s.commit()
    N.invalidate()
    A.clear_cache()
    await audit(s, request, user.username, "traffic_network_update", body.cidr, body.model_dump())
    return _net_out(r)


@router.delete("/networks/{nid}")
async def delete_network(nid: int, request: Request, user: User = Depends(NEED_COLLECT), s: AsyncSession = Depends(get_session)):
    r = await s.get(TrafficNetwork, nid)
    if not r:
        raise HTTPException(404, "not found")
    await s.delete(r)
    await s.commit()
    N.invalidate()
    A.clear_cache()
    await audit(s, request, user.username, "traffic_network_delete", r.cidr)
    return {"ok": True}


class PolicyIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    src: str = Field(min_length=3, max_length=64)
    dst: str = Field(min_length=3, max_length=64)
    action: str = Field("deny", pattern="^(allow|deny)$")
    severity: str = Field("medium", pattern=r"^(critical|high|medium|low|informational)$")
    enabled: bool = True
    description: str = Field("", max_length=2000)

    @field_validator("src", "dst")
    @classmethod
    def _ep(cls, v):
        v = v.strip().lower()
        if not N.valid_endpoint(v):
            raise ValueError("an endpoint is any, internal, external, zone:<zone> or vlan:<1-4094>")
        return v


def _pol_out(r: TrafficVlanPolicy) -> dict:
    return {k: getattr(r, k) for k in ("id", "name", "src", "dst", "action", "severity", "enabled", "description", "builtin_key", "updated_by")}


@router.get("/vlan-policies")
async def vlan_policies(_: User = Depends(NEED_VIEW), s: AsyncSession = Depends(get_session)):
    return [_pol_out(r) for r in (await s.execute(select(TrafficVlanPolicy).order_by(TrafficVlanPolicy.name))).scalars()]


@router.post("/vlan-policies", status_code=201)
async def create_policy(body: PolicyIn, request: Request, user: User = Depends(NEED_RULES), s: AsyncSession = Depends(get_session)):
    r = TrafficVlanPolicy(**body.model_dump(), updated_by=user.username)
    s.add(r)
    await s.commit()
    A.clear_cache()
    await audit(s, request, user.username, "traffic_policy_create", body.name, body.model_dump())
    return _pol_out(r)


@router.put("/vlan-policies/{pid}")
async def update_policy(pid: int, body: PolicyIn, request: Request, user: User = Depends(NEED_RULES), s: AsyncSession = Depends(get_session)):
    r = await s.get(TrafficVlanPolicy, pid)
    if not r:
        raise HTTPException(404, "not found")
    for k, v in body.model_dump().items():
        setattr(r, k, v)
    r.updated_by = user.username
    await s.commit()
    A.clear_cache()
    await audit(s, request, user.username, "traffic_policy_update", body.name, body.model_dump())
    return _pol_out(r)


@router.delete("/vlan-policies/{pid}")
async def delete_policy(pid: int, request: Request, user: User = Depends(NEED_RULES), s: AsyncSession = Depends(get_session)):
    r = await s.get(TrafficVlanPolicy, pid)
    if not r:
        raise HTTPException(404, "not found")
    await s.delete(r)
    await s.commit()
    A.clear_cache()
    await audit(s, request, user.username, "traffic_policy_delete", r.name)
    return {"ok": True}


# ------------------------------------------------------------------ settings
ENRICH_KEYS = {"enrich_dns", "enrich_firewall_apps", "enrich_asn", "enrich_rdns", "rdns_per_run", "enrich_top_n", "enrich_refresh_hours"}


@router.get("/settings")
async def get_settings_(_: User = Depends(NEED_VIEW), s: AsyncSession = Depends(get_session)):
    return S.public(await S.load_settings(s))


@router.put("/settings")
async def put_settings(body: dict, request: Request, user: User = Depends(NEED_VIEW), s: AsyncSession = Depends(get_session)):
    """Enrichment keys need nms.traffic.enrichment.manage; the others nms.traffic.collector.manage."""
    try:
        clean = S.validate(body)
    except ValueError as e:
        _bad(e)
    need = {ENRICH_M if k in ENRICH_KEYS else COLLECT_M for k in clean}
    for p in need:
        if not has(user, p):
            raise HTTPException(403, f"permission {p} required")
    out = await S.save_settings(s, clean, user.username)
    await s.commit()
    A.clear_cache()
    await audit(s, request, user.username, "traffic_settings_update", detail=clean)
    return S.public(out)


# ------------------------------------------------------------------ export
EXPORTS = {
    "applications": (["app", "category", "confidence", "bytes", "packets", "flows", "sources", "destinations", "share", "sampled"], "applications"),
    "top-sources": (["ip", "hostname", "device", "site", "vlan", "zone", "mac", "bytes", "packets", "flows", "avg_bps", "peak_bps", "peers",
                     "top_app", "first", "last", "sampled"], "sources"),
    "top-destinations": (["ip", "hostname", "as_org", "country", "internal", "bytes", "packets", "flows", "peers", "top_app", "first", "last",
                          "sampled"], "destinations"),
    "conversations": (["src_ip", "dst_ip", "proto_name", "port", "app", "category", "confidence", "direction", "src_vlan", "dst_vlan", "bytes",
                       "packets", "flows", "avg_bps", "first", "last", "sampling"], "conversations"),
    "vlans": (["vlan", "name", "zone", "bytes", "packets", "flows", "sources", "destinations", "east_west", "north_south"], "vlans"),
    "vlan-matrix": (["src_vlan", "dst_vlan", "src_zone", "dst_zone", "bytes", "packets", "flows", "conversations", "first", "last"], "vlan_matrix"),
    "interfaces": (["device", "name", "description", "ifindex", "kind", "speed_bps", "rx_bytes", "tx_bytes", "utilization_pct", "flows", "counted"],
                   "interfaces"),
    "detections": (["id", "name", "severity", "status", "src_ip", "dst_ip", "first_seen", "last_seen", "event_count", "bytes", "confidence",
                    "explanation", "assignee"], "detections"),
}
EXPORT_ROWS = 10_000


@router.get("/export/{view}.csv")
async def export(view: str, request: Request, f: Filters = Depends(filters), sort: str | None = Query(None, max_length=32),
                 user: User = Depends(NEED_EXPORT), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    """CSV of one view with the same filters, at most 10 000 rows (500 per page server-side), 10 exports a minute per user."""
    if view not in EXPORTS:
        raise HTTPException(404, "unknown export")
    if not _limiter.check(f"traffic-export:{user.username}", 10):
        raise HTTPException(429, "too many exports, try again in a minute")
    cols, _ = EXPORTS[view]
    sens = _sens(user)
    rows: list[dict] = []
    for off in range(0, EXPORT_ROWS, 500):
        if view == "applications":
            page = (await _guard(A.applications(s, ch, f, sort, 500, off)))["items"]
        elif view == "top-sources":
            page = (await _guard(A.talkers(s, ch, f, "sources", sort, 500, off, sensitive=sens)))["items"]
        elif view == "top-destinations":
            page = (await _guard(A.talkers(s, ch, f, "destinations", sort, 500, off, sensitive=sens)))["items"]
        elif view == "conversations":
            page = (await _guard(A.conversations(s, ch, f, sort, 500, off, sensitive=sens)))["items"]
        elif view == "vlans":
            page = (await _guard(A.vlans(s, ch, f, 500)))["items"] if off == 0 else []
        elif view == "vlan-matrix":
            page = (await _guard(A.vlan_matrix(s, ch, f, 500)))["items"] if off == 0 else []
        elif view == "interfaces":
            st = await S.load_settings(s)
            page = (await _guard(A.interfaces(s, ch, f, 500, lag_mode=st["lag_mode"])))["items"] if off == 0 else []
        else:
            if not has(user, DET):
                raise HTTPException(403, f"permission {DET} required")
            t0, _t1 = f.window()
            q = select(Alert).where(Alert.rule_key.in_(DETECTION_KEYS), Alert.last_seen >= t0).order_by(Alert.last_seen.desc()).limit(500).offset(off)
            page = [_det_out(a) for a in (await s.execute(q)).scalars()]
        rows += page
        if len(page) < 500:
            break
    rows = rows[:EXPORT_ROWS]
    if not sens:
        for r in rows:
            r.pop("mac", None)
            r.pop("user", None)
    await audit(s, request, user.username, "traffic_export", view, {"rows": len(rows), "filters": {k: str(v) for k, v in f.__dict__.items() if v}})
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        w.writerow([csv_safe("" if r.get(c) is None else r.get(c)) for c in cols])
    name = f"traffic-{view}-{datetime.now(timezone.utc):%Y%m%d-%H%M}.csv"
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="{name}"'})
