"""Generic SNMP device monitoring API (Sentinel NMS): onboarding of any SNMP device, monitoring templates, interface
bandwidth history / statistics / thresholds, and interface-history retention.

The device inventory itself is the existing one (app/api/switches.py, table `switches`): every SNMP device lives
there whatever its type; this router adds the generic workflow on top. SNMP secrets live only in credential
profiles (sealed at rest) and are never returned.
"""
from __future__ import annotations

import asyncio
import csv
import io
import socket
import time
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.ch import ClickHouse
from ..db.models import MonitoringTemplate, Switch, SwitchCredential, SwitchInterface, SwitchNetwork, User
from ..db.pg import get_session
from ..products import site_allowed
from ..switches import bandwidth as B
from ..switches import poller as P
from ..switches import templates as T
from ..switches.fingerprints import DEVICE_TYPE_LABELS, DEVICE_TYPES
from ..switches.registry import GROUPS
from ..switches.snmp import SnmpError
from .deps import audit, ch_dep, csv_safe, current_user, iso, require_admin
from .switches import _get, _ifrow, _rate

router = APIRouter(prefix="/api/devices", tags=["devices"])
RANGES = {"15m": 900, "1h": 3600, "6h": 21600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400, "90d": 90 * 86400, "365d": 365 * 86400}
MAX_SPAN = 400 * 86400


def window(range_: str | None, start: datetime | None, end: datetime | None) -> tuple[datetime, datetime]:
    now = datetime.now(timezone.utc)
    if start or end:
        if not (start and end):
            raise HTTPException(422, "a custom range needs both start and end")
        t0, t1 = [x if x.tzinfo else x.replace(tzinfo=timezone.utc) for x in (start, end)]
        t1 = min(t1, now)
        if t1 <= t0:
            raise HTTPException(422, "end must be after start")
        if (t1 - t0).total_seconds() > MAX_SPAN:
            raise HTTPException(422, "a range can be at most 400 days")
        return t0, t1
    sec = RANGES.get(range_ or "24h")
    if sec is None:
        raise HTTPException(422, f"range must be one of {', '.join(RANGES)} or start / end")
    return now - timedelta(seconds=sec), now


# ------------------------------------------------------------------ catalogue
@router.get("/meta")
async def meta(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await T.ensure_builtin(s)
    tmpl = (await s.execute(select(MonitoringTemplate).order_by(MonitoringTemplate.builtin.desc(), MonitoringTemplate.name))).scalars().all()
    return {"device_types": [{"key": k, "label": DEVICE_TYPE_LABELS[k]} for k in DEVICE_TYPES],
            "templates": [{"id": t.id, "name": t.name, "device_type": t.device_type} for t in tmpl],
            "ranges": list(RANGES), "util_defaults": T.UTIL_DEFAULTS}


# ------------------------------------------------------------------ onboarding
class OnboardIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    address: str = Field("", max_length=64)              # management IP; resolved from fqdn when empty
    fqdn: str = Field("", max_length=255)
    port: int = Field(161, ge=1, le=65535)
    credential_id: int
    device_type: str = Field("", max_length=16)          # "" = detect
    template_id: int | None = None                       # None = by detected type
    site: str = Field("", max_length=128)
    building: str = Field("", max_length=128)
    floor: str = Field("", max_length=64)
    rack: str = Field("", max_length=64)
    role: str = Field("", max_length=32)
    tags: list[str] = Field(default_factory=list, max_length=32)
    notes: str = Field("", max_length=2000)
    poll_interval_seconds: int | None = Field(None, ge=30, le=3600)
    icmp_enabled: bool = True
    snmp_enabled: bool = True                             # False = add paused (inventory only)
    timeout_ms: int = Field(3000, ge=500, le=15000)
    retries: int = Field(1, ge=0, le=3)

    @field_validator("device_type")
    @classmethod
    def _dt(cls, v):
        if v and v not in DEVICE_TYPES:
            raise ValueError(f"device type must be one of {', '.join(DEVICE_TYPES)}")
        return v

    @field_validator("tags")
    @classmethod
    def _tags(cls, v):
        return sorted({t.strip()[:48] for t in v if t and t.strip()})


def _step(steps: list, key: str, label: str, ok: bool | None, detail: str = "", **extra) -> None:
    steps.append({"key": key, "label": label, "status": "ok" if ok else "skipped" if ok is None else "failed", "detail": detail, **extra})


async def _resolve(fqdn: str) -> str:
    loop = asyncio.get_running_loop()
    infos = await asyncio.wait_for(loop.getaddrinfo(fqdn, None, type=socket.SOCK_DGRAM), timeout=3)
    for fam, *_rest, sa in infos:
        if fam in (socket.AF_INET, socket.AF_INET6):
            return sa[0]
    raise OSError("no address")


@router.post("/onboard")
async def onboard(body: OnboardIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    """Validate → ICMP → SNMP (sysDescr, sysObjectID, sysName, sysUpTime, sysLocation, sysContact) → identify vendor /
    model / OS / type → capabilities → interfaces → save → monitor. Nothing is saved unless SNMP answered."""
    _rate(user, "onboard", 10)
    steps: list[dict] = []
    t_start = time.monotonic()
    nets = (await s.execute(select(SwitchNetwork))).scalars().all()
    address = body.address.strip()
    if not address and body.fqdn:
        try:
            address = await _resolve(body.fqdn.strip())
            _step(steps, "resolve", f"Resolve {body.fqdn}", True, address)
        except Exception:
            _step(steps, "resolve", f"Resolve {body.fqdn}", False, "the name did not resolve")
            return {"ok": False, "outcome": "invalid", "message": f"{body.fqdn} does not resolve to an address.", "steps": steps}
    try:
        addr = P.validate_address(address, nets)
        _step(steps, "validate", "Validate management address", True, addr)
    except ValueError as e:
        _step(steps, "validate", "Validate management address", False, str(e))
        return {"ok": False, "outcome": "invalid", "message": str(e), "steps": steps}
    for col, val, what in ((Switch.name, body.name.strip(), "name"), (Switch.address, addr, "management address")):
        other = (await s.execute(select(Switch).where(col == val))).scalars().first()
        if other:
            _step(steps, "duplicate", "Check for duplicates", False, f"{other.name} already uses this {what}")
            return {"ok": False, "outcome": "duplicate", "message": f"Device {other.name} already uses this {what}.", "existing_id": other.id,
                    "steps": steps}
    cred = await s.get(SwitchCredential, body.credential_id)
    if cred is None:
        raise HTTPException(422, "SNMP profile not found")
    try:
        P.check_version_allowed(cred.version)
    except SnmpError as e:
        _step(steps, "config", "SNMP profile", False, e.message)
        return {"ok": False, "outcome": "invalid", "message": e.message, "steps": steps}
    _step(steps, "config", "SNMP profile", True, f"{cred.name} (SNMP{cred.version})")

    icmp_ok = None
    if body.icmp_enabled:
        from ..icmp import ping
        try:
            r = await ping(addr, count=2, timeout_ms=1000)
            icmp_ok = r.received > 0 if not r.error_class else None
            _step(steps, "icmp", "ICMP reachability", icmp_ok,
                  f"{r.received}/{r.sent} replies" + (f", {min(r.rtts):.1f} ms" if r.rtts else "") if icmp_ok is not None else f"not tested: {r.error}")
        except Exception as e:  # no ICMP socket in this container: not a device verdict
            _step(steps, "icmp", "ICMP reachability", None, f"not tested ({type(e).__name__})")

    if not body.snmp_enabled:
        sw = await _save(s, body, addr, user, identity={}, paused=True)
        _step(steps, "save", "Save device", True, "added without SNMP monitoring (paused)")
        await audit(s, request, user.username, "device_onboard", sw.name, {"address": addr, "outcome": "inventory_only"})
        return {"ok": True, "outcome": "inventory_only", "id": sw.id, "message": "Added to the inventory; SNMP monitoring is off.", "steps": steps}

    groups = ["system", "inventory", "interfaces", "cpu_memory", "environment", "storage", "lacp", "ups", "printer"]
    pr = await P.probe(addr, cred, port=body.port, timeout=body.timeout_ms / 1000, retries=body.retries, groups=groups)
    if not pr.get("ok"):
        kind = pr.get("kind") or ""
        outcome = {"auth": "auth_failed", "timeout": "unreachable" if icmp_ok is False else "snmp_no_response",
                   "protocol": "unsupported_response"}.get(kind, "snmp_failed")
        msg = {"auth_failed": "SNMP authentication failed: the device rejected the SNMPv3 user or its authentication / privacy settings.",
               "unreachable": "The device is unreachable: no ICMP reply and no SNMP answer.",
               "snmp_no_response": "The device answers ping but not SNMP: SNMP is disabled, UDP 161 is filtered, the agent's access list does not "
                                   "allow this server, or (SNMPv1 / v2c) the community is wrong — agents drop wrong communities silently.",
               "unsupported_response": "The device answered with an SNMP response Sentinel could not use."}.get(outcome, pr.get("error") or "SNMP failed")
        _step(steps, "snmp", "SNMP connectivity", False, pr.get("error") or msg)
        await audit(s, request, user.username, "device_onboard", body.name, {"address": addr, "outcome": outcome}, success=False)
        return {"ok": False, "outcome": outcome, "message": msg, "hint": pr.get("hint"), "steps": steps}
    sysinfo, ident = pr.get("system") or {}, pr.get("identity") or {}
    _step(steps, "snmp", "SNMP connectivity", True, f"answered in {pr.get('duration_ms')} ms")
    _step(steps, "system", "System information", bool(sysinfo.get("sys_descr") or sysinfo.get("sys_object_id")),
          f"{sysinfo.get('sys_name') or '—'} · uptime {int((sysinfo.get('uptime_s') or 0) // 86400)} d", system=sysinfo)
    detected = ident.get("device_type") or "other"
    _step(steps, "identify", "Identify vendor, model, OS and type", True,
          " · ".join(x for x in (ident.get("manufacturer") or ident.get("vendor"), ident.get("model"), ident.get("os"), ident.get("firmware"),
                                 DEVICE_TYPE_LABELS.get(body.device_type or detected, detected)) if x), identity=ident)
    report = pr.get("groups") or {}
    preview = pr.get("preview") or {}
    n_if = int(preview.get("interfaces") or 0)
    if_status = (report.get("interfaces") or {}).get("status")
    if_ok = n_if > 0 and if_status in (None, "ok")
    _step(steps, "interfaces", "Discover interfaces", if_ok,
          f"{n_if} interfaces, {preview.get('interfaces_up', 0)} up, {preview.get('hc_counters', 0)} with 64-bit counters" if n_if
          else "the device returned no IF-MIB interfaces")
    caps = [c for c in (pr.get("capabilities") or []) if c.get("status") in ("healthy", "supported", "ok")]
    _step(steps, "capabilities", "Detect monitoring capabilities", True, f"{len(caps)} metrics supported")
    tmpl = await s.get(MonitoringTemplate, body.template_id) if body.template_id else await T.template_for_type(s, body.device_type or detected)
    sw = await _save(s, body, addr, user, identity={**ident, **{k: sysinfo.get(k) for k in ("sys_name", "sys_descr", "sys_object_id", "location")}},
                     template=tmpl)
    _step(steps, "save", "Save device and start monitoring", True, f"template: {tmpl.name if tmpl else 'none'}; first poll within a minute")
    outcome = "added" if if_ok else "partial"
    await audit(s, request, user.username, "device_onboard", sw.name, {"address": addr, "outcome": outcome, "type": sw.device_type})
    return {"ok": True, "outcome": outcome, "id": sw.id, "steps": steps, "duration_ms": int((time.monotonic() - t_start) * 1000),
            "message": "Device added and monitoring started." if if_ok else
                       "Device added, but interface discovery returned nothing: traffic monitoring will start if the device exposes IF-MIB later.",
            "identity": ident, "preview": preview}


async def _save(s: AsyncSession, body: OnboardIn, addr: str, user: User, *, identity: dict, template: MonitoringTemplate | None = None,
                paused: bool = False) -> Switch:
    sw = Switch(name=body.name.strip(), address=addr, port=body.port, credential_id=body.credential_id, site=body.site, building=body.building,
                floor=body.floor, rack=body.rack, role=body.role or ("wlc" if (body.device_type or identity.get("device_type")) == "wlc" else ""),
                notes=body.notes, fqdn=body.fqdn.strip(), tags=body.tags, device_type_override=body.device_type,
                device_type=(body.device_type or identity.get("device_type") or "")[:16], icmp_enabled=body.icmp_enabled,
                monitoring="paused" if paused else "active", timeout_ms=body.timeout_ms, retries=body.retries,
                vendor=(identity.get("vendor") or "unknown")[:16], model=(identity.get("model") or "")[:64], os=(identity.get("os") or "")[:32],
                firmware=(identity.get("firmware") or "")[:128], sys_descr=identity.get("sys_descr") or "", sys_object_id=(identity.get("sys_object_id") or "")[:128],
                sys_name=(identity.get("sys_name") or "")[:255], location=(identity.get("location") or "")[:255],
                created_by=user.username, state="unknown", capabilities={}, group_state={}, health={})
    await T.apply(s, sw, template)
    sw.poll_interval_seconds = body.poll_interval_seconds or (template.poll_interval_seconds if template else 60)
    s.add(sw)
    await s.commit()
    return sw


# ------------------------------------------------------------------ device classification / template / tags
class DevicePatch(BaseModel):
    device_type: str | None = Field(None, max_length=16)     # "" clears the manual type (detection decides)
    template_id: int | None = None
    clear_template: bool = False
    fqdn: str | None = Field(None, max_length=255)
    tags: list[str] | None = None
    icmp_enabled: bool | None = None


@router.patch("/{sid}")
async def patch_device(sid: int, body: DevicePatch, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    sw = await _get(s, sid, user)
    if body.device_type is not None:
        if body.device_type and body.device_type not in DEVICE_TYPES:
            raise HTTPException(422, "unknown device type")
        sw.device_type_override = body.device_type
        if body.device_type:
            sw.device_type = body.device_type
    if body.clear_template:
        await T.apply(s, sw, None)
    elif body.template_id is not None:
        t = await s.get(MonitoringTemplate, body.template_id)
        if t is None:
            raise HTTPException(404, "template not found")
        await T.apply(s, sw, t)
    if body.fqdn is not None:
        sw.fqdn = body.fqdn.strip()
    if body.tags is not None:
        sw.tags = sorted({t.strip()[:48] for t in body.tags if t and t.strip()})[:32]
    if body.icmp_enabled is not None:
        sw.icmp_enabled = body.icmp_enabled
    await s.commit()
    await audit(s, request, user.username, "device_update", sw.name, body.model_dump(exclude_none=True))
    return {"id": sw.id, "device_type": sw.device_type, "template_id": sw.template_id}


# ------------------------------------------------------------------ monitoring templates
class TemplateIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    device_type: str = Field("", max_length=16)
    description: str = Field("", max_length=2000)
    poll_interval_seconds: int = Field(60, ge=30, le=3600)
    group_intervals: dict[str, int] = Field(default_factory=dict)
    thresholds: dict[str, float] = Field(default_factory=dict)
    interface_rules: dict = Field(default_factory=dict)

    @field_validator("group_intervals")
    @classmethod
    def _gi(cls, v):
        for k, x in v.items():
            if k not in GROUPS or k == "system":
                raise ValueError(f"unknown or fixed metric group '{k}'")
            if x != 0 and not 30 <= x <= 86400:
                raise ValueError("group intervals must be 0 (disabled) or 30-86400 seconds")
        return v

    @field_validator("thresholds")
    @classmethod
    def _th(cls, v):
        allowed = {"cpu_pct", "mem_pct", "storage_pct", "celsius", "pct", "util_warn_pct", "util_high_pct", "util_crit_pct", "min_errors",
                   "min_discards"}
        bad = set(v) - allowed
        if bad:
            raise ValueError(f"unknown thresholds: {', '.join(sorted(bad))}")
        if any(x < 0 for x in v.values()):
            raise ValueError("thresholds must be non-negative")
        return v

    @field_validator("interface_rules")
    @classmethod
    def _ir(cls, v):
        import re
        out = {}
        if v.get("exclude_types"):
            out["exclude_types"] = [int(x) for x in v["exclude_types"]][:64]
        if v.get("exclude_regex"):
            re.compile(str(v["exclude_regex"]))
            out["exclude_regex"] = str(v["exclude_regex"])[:200]
        return out


def _tout(t: MonitoringTemplate, used: int = 0) -> dict:
    return {"id": t.id, "key": t.key, "name": t.name, "device_type": t.device_type, "description": t.description, "builtin": t.builtin,
            "poll_interval_seconds": t.poll_interval_seconds, "group_intervals": t.group_intervals or {}, "thresholds": t.thresholds or {},
            "interface_rules": t.interface_rules or {}, "devices": used, "updated_at": iso(t.updated_at)}


@router.get("/templates")
async def list_templates(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await T.ensure_builtin(s)
    used = dict((await s.execute(select(Switch.template_id, func.count()).where(Switch.template_id.isnot(None)).group_by(Switch.template_id))).all())
    rows = (await s.execute(select(MonitoringTemplate).order_by(MonitoringTemplate.builtin.desc(), MonitoringTemplate.name))).scalars().all()
    return {"items": [_tout(t, used.get(t.id, 0)) for t in rows], "groups": [{"key": k, "label": v["label"], "interval": v["interval"]}
                                                                             for k, v in GROUPS.items() if k != "system" and not v.get("wlc")]}


@router.post("/templates", status_code=201)
async def create_template(body: TemplateIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    if (await s.execute(select(MonitoringTemplate).where(MonitoringTemplate.name == body.name.strip()))).scalars().first():
        raise HTTPException(409, "a template with this name exists")
    t = MonitoringTemplate(**{**body.model_dump(), "name": body.name.strip()}, created_by=user.username)
    s.add(t)
    await s.commit()
    await audit(s, request, user.username, "template_create", t.name)
    return _tout(t)


@router.put("/templates/{tid}")
async def update_template(tid: int, body: TemplateIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    t = await s.get(MonitoringTemplate, tid)
    if t is None:
        raise HTTPException(404, "template not found")
    for k, v in body.model_dump().items():
        setattr(t, k, v.strip() if k == "name" else v)
    t.updated_at = datetime.now(timezone.utc)
    n = await T.propagate(s, t)
    await s.commit()
    await audit(s, request, user.username, "template_update", t.name, {"devices": n})
    return {**_tout(t, n), "devices_updated": n}


@router.delete("/templates/{tid}")
async def delete_template(tid: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    t = await s.get(MonitoringTemplate, tid)
    if t is None:
        raise HTTPException(404, "template not found")
    if t.builtin:
        raise HTTPException(409, "built-in templates can be edited but not deleted")
    for sw in (await s.execute(select(Switch).where(Switch.template_id == tid))).scalars():
        await T.apply(s, sw, None)
    await s.delete(t)
    await s.commit()
    await audit(s, request, user.username, "template_delete", t.name)
    return {"ok": True}


# ------------------------------------------------------------------ interface history retention
class RetentionIn(BaseModel):
    raw_days: int
    five_min_days: int
    hourly_days: int


@router.get("/retention")
async def get_retention(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    return {"value": await B.retention(s), "defaults": B.RETENTION_DEFAULTS, "limits": B.RETENTION_LIMITS}


@router.put("/retention")
async def put_retention(body: RetentionIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session),
                        ch: ClickHouse = Depends(ch_dep)):
    try:
        v = await B.set_retention(s, ch, body.model_dump(), user.username)
    except ValueError as e:
        raise HTTPException(422, str(e))
    await audit(s, request, user.username, "interface_retention", "interfaces", v)
    return {"value": v}


# ------------------------------------------------------------------ interfaces: bandwidth, statistics, thresholds
async def _iface(s: AsyncSession, sid: int, ifx: int) -> SwitchInterface:
    r = (await s.execute(select(SwitchInterface).where(SwitchInterface.switch_id == sid, SwitchInterface.ifindex == ifx))).scalars().first()
    if r is None:
        raise HTTPException(404, "interface not found")
    return r


@router.get("/{sid}/interfaces/{ifx}/bandwidth")
async def bandwidth(sid: int, ifx: int, range: str | None = Query(None, max_length=8), start: datetime | None = None, end: datetime | None = None,
                    compare: str | None = Query(None, pattern=r"^(previous|day|week)$"), user: User = Depends(current_user),
                    s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    """Bandwidth series and statistics for one interface (UTC). compare: the previous period of the same length, the
    same window a day earlier, or a week earlier."""
    sw = await _get(s, sid, user)
    r = await _iface(s, sid, ifx)
    t0, t1 = window(range, start, end)
    ret = await B.retention(s)
    out = {"device": {"id": sw.id, "name": sw.name, "site": sw.site, "state": sw.state, "last_success_at": iso(sw.last_success_at)},
           "interface": _ifrow(r), "series": await B.series(ch, sid, ifx, t0, t1, ret), "stats": await B.stats(ch, sid, ifx, t0, t1, ret),
           "retention": ret}
    if compare:
        c0, c1 = B.compare_window(compare, t0, t1)
        shift = (t0 - c0).total_seconds()
        cs = await B.series(ch, sid, ifx, c0, c1, ret)
        out["compare"] = {"kind": compare, "start": c0.isoformat(), "end": c1.isoformat(), "shift_seconds": shift, "series": cs,
                          "stats": await B.stats(ch, sid, ifx, c0, c1, ret)}
    # last known sample; stale when the device has not been polled successfully for 3 intervals
    age = (datetime.now(timezone.utc) - r.last_sample_at.replace(tzinfo=r.last_sample_at.tzinfo or timezone.utc)).total_seconds() if r.last_sample_at else None
    out["current"] = {"rx_bps": r.rx_bps, "tx_bps": r.tx_bps, "rx_util": r.rx_util, "tx_util": r.tx_util, "at": iso(r.last_sample_at),
                      "stale": age is None or age > 3 * max(60, sw.poll_interval_seconds or 60)}
    return out


class IfacePatch(BaseModel):
    monitored: bool | None = None
    thresholds: dict[str, float] | None = None

    @field_validator("thresholds")
    @classmethod
    def _th(cls, v):
        if v is None:
            return v
        allowed = {"util_warn_pct", "util_high_pct", "util_crit_pct", "min_errors", "min_discards"}
        if set(v) - allowed:
            raise ValueError(f"interface thresholds: {', '.join(sorted(allowed))}")
        if any(not 0 <= x <= 100 for k, x in v.items() if k.startswith("util_")):
            raise ValueError("utilisation thresholds are percentages (0-100)")
        return v


@router.patch("/{sid}/interfaces/{ifx}")
async def patch_interface(sid: int, ifx: int, body: IfacePatch, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    sw = await _get(s, sid, user)
    r = await _iface(s, sid, ifx)
    if body.monitored is not None:
        r.monitored = body.monitored
    if body.thresholds is not None:
        r.thresholds = body.thresholds
    await s.commit()
    await audit(s, request, user.username, "interface_update", f"{sw.name} {r.name}", body.model_dump(exclude_none=True))
    return {"monitored": r.monitored, "thresholds": r.thresholds or {}}


# ------------------------------------------------------------------ global interface view (all devices)
QUICK = r"^(down|high_util|errors|discards|unmonitored|no_data|changed)$"


@router.get("/interfaces")
async def interfaces(q: str | None = Query(None, max_length=128), site: list[str] = Query(default=[]), device_id: list[int] = Query(default=[]),
                     vendor: list[str] = Query(default=[]), device_type: list[str] = Query(default=[]),
                     layer: str | None = Query(None, pattern=r"^(physical|logical)$"), oper: str | None = Query(None, pattern=r"^(up|down)$"),
                     quick: str | None = Query(None, pattern=QUICK), min_util: float | None = Query(None, ge=0, le=100),
                     min_speed_mbps: int | None = Query(None, ge=0), vlan: int | None = Query(None, ge=1, le=4094), lag: bool | None = None,
                     sort: str = Query("util", pattern=r"^(util|errors|discards|name|traffic|speed|device|changed)$"),
                     desc: bool = True, limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0),
                     user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    st, sws = await _iface_query(s, user, q=q, site=site, device_id=device_id, vendor=vendor, device_type=device_type, layer=layer, oper=oper,
                                 quick=quick, min_util=min_util, min_speed_mbps=min_speed_mbps, vlan=vlan, lag=lag)
    I = SwitchInterface  # noqa: E741
    total = (await s.execute(select(func.count()).select_from(st.subquery()))).scalar_one()
    rx, tx = func.coalesce(I.rx_util, 0), func.coalesce(I.tx_util, 0)
    errs = func.coalesce(I.in_errors_delta, 0) + func.coalesce(I.out_errors_delta, 0) + func.coalesce(I.crc_delta, 0)
    key = {"util": case((rx >= tx, rx), else_=tx), "errors": errs, "discards": func.coalesce(I.discards_delta, 0),
           "traffic": func.coalesce(I.rx_bps, 0) + func.coalesce(I.tx_bps, 0), "speed": func.coalesce(I.speed_bps, 0),
           "name": I.name, "device": Switch.name, "changed": func.coalesce(I.last_change_at, datetime(1970, 1, 1, tzinfo=timezone.utc))}[sort]
    st = st.join(Switch, Switch.id == I.switch_id)
    rows = (await s.execute(st.order_by(key.desc() if desc else key.asc(), I.switch_id, I.ifindex).limit(limit).offset(offset))).scalars().all()
    return {"total": total, "items": [{**_ifrow(r, sws[r.switch_id]), "device_type": sws[r.switch_id].device_type, "monitored": r.monitored,
                                       "thresholds": r.thresholds or {}} for r in rows]}


async def _iface_query(s: AsyncSession, user: User, *, q, site, device_id, vendor, device_type, layer, oper, quick, min_util, min_speed_mbps, vlan, lag):
    sws = {x.id: x for x in (await s.execute(select(Switch))).scalars()
           if site_allowed(user, x.site) and (not site or x.site in site) and (not device_id or x.id in device_id)
           and (not vendor or x.vendor in vendor) and (not device_type or x.device_type in device_type)}
    I = SwitchInterface  # noqa: E741
    st = select(I).where(I.switch_id.in_(list(sws) or [0]), I.present.is_(True))
    if layer == "physical":
        st = st.where(I.kind == "physical")
    elif layer == "logical":
        st = st.where(I.kind != "physical")
    if oper == "up":
        st = st.where(I.oper == "up")
    elif oper == "down":
        st = st.where(I.oper != "up")
    if lag is True:
        st = st.where(or_(I.kind == "lag", I.lag_ifindex.isnot(None)))
    if vlan:
        st = st.where(or_(I.access_vlan == vlan, I.native_vlan == vlan))
    if q:
        like = f"%{q}%"
        st = st.where(or_(I.name.ilike(like), I.alias.ilike(like), I.descr.ilike(like)))
    rx, tx = func.coalesce(I.rx_util, 0), func.coalesce(I.tx_util, 0)
    if min_util is not None:
        st = st.where(or_(rx >= min_util, tx >= min_util))
    if min_speed_mbps:
        st = st.where(I.speed_bps >= min_speed_mbps * 1_000_000)
    now = datetime.now(timezone.utc)
    if quick == "down":
        st = st.where(I.admin == "up", I.oper != "up")
    elif quick == "high_util":
        st = st.where(or_(rx >= T.UTIL_DEFAULTS["util_high_pct"], tx >= T.UTIL_DEFAULTS["util_high_pct"]))
    elif quick == "errors":
        st = st.where(func.coalesce(I.in_errors_delta, 0) + func.coalesce(I.out_errors_delta, 0) + func.coalesce(I.crc_delta, 0) > 0)
    elif quick == "discards":
        st = st.where(func.coalesce(I.discards_delta, 0) > 0)
    elif quick == "unmonitored":
        st = st.where(I.monitored.is_(False))
    elif quick == "no_data":
        st = st.where(or_(I.last_sample_at.is_(None), I.last_sample_at < now - timedelta(minutes=15)))
    elif quick == "changed":
        st = st.where(I.last_change_at >= now - timedelta(hours=24))
    return st, sws


@router.get("/interfaces/export.csv")
async def export_interfaces(q: str | None = Query(None, max_length=128), site: list[str] = Query(default=[]), device_id: list[int] = Query(default=[]),
                            vendor: list[str] = Query(default=[]), device_type: list[str] = Query(default=[]),
                            layer: str | None = Query(None, pattern=r"^(physical|logical)$"), oper: str | None = Query(None, pattern=r"^(up|down)$"),
                            quick: str | None = Query(None, pattern=QUICK), min_util: float | None = Query(None, ge=0, le=100),
                            user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    st, sws = await _iface_query(s, user, q=q, site=site, device_id=device_id, vendor=vendor, device_type=device_type, layer=layer, oper=oper,
                                 quick=quick, min_util=min_util, min_speed_mbps=None, vlan=None, lag=None)
    rows = (await s.execute(st.order_by(SwitchInterface.switch_id, SwitchInterface.ifindex).limit(50000))).scalars().all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["device", "site", "interface", "alias", "kind", "admin", "oper", "speed_bps", "rx_bps", "tx_bps", "rx_util_pct", "tx_util_pct",
                "in_errors", "out_errors", "crc", "discards", "last_sample_at"])
    for r in rows:
        sw = sws[r.switch_id]
        w.writerow([csv_safe(x) for x in (sw.name, sw.site, r.name, r.alias, r.kind, r.admin, r.oper, r.speed_bps, r.rx_bps, r.tx_bps, r.rx_util,
                                          r.tx_util, r.in_errors_delta, r.out_errors_delta, r.crc_delta, r.discards_delta, iso(r.last_sample_at))])
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=interfaces.csv"})

