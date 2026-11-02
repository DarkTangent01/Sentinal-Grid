"""APIs: Sentinel NMS → SNMP framework (docs/SNMP.md): vendor overview, polling health, fingerprint registry and
profile overrides, MIB / OID registry and support matrix, OID search and read-only OID test, custom OID profiles with
version history, MIB module import, SNMP traps.

Reads need NMS access and respect the user's site scope; changes need the administrator role and are audited.
Credentials are never returned. The OID test sends GET / GETBULK only, with the device's own credential profile.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import snmp_profiles as SP
from ..db.ch import ClickHouse
from ..db.models import (SnmpCustomOid, SnmpMetricSetting, SnmpMibModule, SnmpProfileVersion, Switch, SwitchCredential, SwitchNetwork, SwitchPollRun,
                         User)
from ..db.pg import get_session
from ..products import site_allowed
from ..switches import fingerprints as FP
from ..switches import poller as P
from ..switches import service as V
from ..switches.registry import GROUPS, METRICS, status_of
from ..switches.snmp import SnmpError
from .deps import audit, ch_dep, current_user, iso, require_admin

router = APIRouter(prefix="/api/snmp", tags=["snmp"])
RANGE = {"1h": 1, "24h": 24, "7d": 168, "30d": 720}
SEVERITIES = ("informational", "low", "medium", "high", "critical")


def _now():
    return datetime.now(timezone.utc)


async def _devices(s: AsyncSession, user: User) -> list[Switch]:
    return [x for x in (await s.execute(select(Switch).order_by(Switch.name))).scalars() if site_allowed(user, x.site)]


async def _device(s: AsyncSession, sid: int, user: User) -> Switch:
    sw = await s.get(Switch, sid)
    if sw is None or not site_allowed(user, sw.site):
        raise HTTPException(404, "device not found")
    return sw


# ------------------------------------------------------------------ vendor / device overview
@router.get("/vendors")
async def vendors(user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    now = _now()
    sws = await _devices(s, user)
    creds = await V.credential_names(s)
    alerts = await V.open_alerts_by_switch(s)
    rows = []
    for x in sws:
        r = V.switch_row(x, now, creds, alerts)
        r.update(product_line=x.product_line, device_type=x.device_type, id_confidence=x.id_confidence, vendor_override=x.vendor_override,
                 family_override=x.family_override, identity=(x.health or {}).get("identity"))
        rows.append(r)
    by_vendor: dict[str, dict] = {}
    for r in rows:
        v = r["vendor"] if r["vendor"] in ("cisco", "fortinet", "juniper", "ruckus") else "other"
        d = by_vendor.setdefault(v, {"vendor": v, "devices": 0, "up": 0, "down": 0, "families": Counter(), "types": Counter()})
        d["devices"] += 1
        d["up"] += r["state"] == "up"
        d["down"] += r["state"] in ("down", "auth_failed")
        d["families"][r["product_line"] or r["family"] or "unidentified"] += 1
        d["types"][r["device_type"] or "unknown"] += 1
    out = []
    for v in ("cisco", "fortinet", "juniper", "ruckus", "other"):
        d = by_vendor.get(v) or {"vendor": v, "devices": 0, "up": 0, "down": 0, "families": Counter(), "types": Counter()}
        out.append({**d, "families": [{"family": k, "count": n} for k, n in d["families"].most_common()],
                    "types": [{"type": k, "count": n} for k, n in d["types"].most_common()]})
    return {"vendors": out, "devices": rows, "total": len(rows)}


class ProfileIn(BaseModel):
    vendor_override: str = Field("", pattern=r"^(|cisco|fortinet|juniper|ruckus|generic)$")
    family_override: str = Field("", max_length=64)


@router.put("/devices/{sid}/profile")
async def set_profile(sid: int, body: ProfileIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    """Manual vendor / product-line override. The next poll re-identifies the device with it and reports a conflict
    when the device's own sysObjectID says otherwise."""
    sw = await _device(s, sid, user)
    known = {r.family for r in FP.DESCR_RULES} | {r.family for r in FP.OID_RULES if r.family}
    if body.family_override and body.family_override not in known:
        raise HTTPException(422, f"unknown product line; choose one of: {', '.join(sorted(known))}")
    before = {"vendor_override": sw.vendor_override, "family_override": sw.family_override}
    sw.vendor_override, sw.family_override = body.vendor_override, body.family_override
    if body.vendor_override:
        sw.vendor = body.vendor_override
    await s.commit()
    await audit(s, request, user.username, "snmp_profile_override", sw.name, {"before": before, "after": body.model_dump()})
    await s.commit()
    return {"id": sw.id, **body.model_dump()}


@router.get("/fingerprints")
async def fingerprints(_: User = Depends(current_user)):
    return FP.catalogue()


@router.get("/identify")
async def identify(sys_object_id: str = Query("", max_length=255), sys_descr: str = Query("", max_length=2000), _: User = Depends(current_user)):
    """Dry-run of the fingerprint registry (no device contacted)."""
    from ..switches.collect import identify as ident
    return ident(sys_object_id, sys_descr)


# ------------------------------------------------------------------ polling health
@router.get("/polling-health")
async def polling_health(range: str = Query("24h", pattern=r"^(1h|24h|7d)$"), user: User = Depends(current_user), s: AsyncSession = Depends(get_session),
                         ch: ClickHouse = Depends(ch_dep)):
    now = _now()
    t0 = now - timedelta(hours=RANGE[range])
    sws = await _devices(s, user)
    ids = [x.id for x in sws] or [0]
    # aggregated in SQL: one row per switch instead of every poll run in the range (~20M rows/week at 2000 switches)
    one = lambda cond: func.sum(case((cond, 1), else_=0))  # noqa: E731
    err = func.coalesce(SwitchPollRun.error, "")
    agg_rows = (await s.execute(select(
        SwitchPollRun.switch_id, func.count().label("polls"), one(SwitchPollRun.ok.is_(True)).label("ok"),
        one(or_(err.like("timeout%"), err.like("%timed out%"))).label("timeouts"), one(err.like("auth%")).label("auth"),
        func.avg(func.coalesce(SwitchPollRun.duration_ms, 0)).label("avg_ms"), func.max(func.coalesce(SwitchPollRun.duration_ms, 0)).label("max_ms"),
    ).where(SwitchPollRun.switch_id.in_(ids), SwitchPollRun.started_at >= t0, SwitchPollRun.kind == "poll")
      .group_by(SwitchPollRun.switch_id))).all()
    agg = {r.switch_id: {"polls": int(r.polls), "ok": int(r.ok or 0), "timeouts": int(r.timeouts or 0), "auth": int(r.auth or 0),
                         "avg_ms": float(r.avg_ms) if r.avg_ms is not None else None, "max_ms": r.max_ms} for r in agg_rows}
    rows = []
    for x in sws:
        a = agg.get(x.id) or {"polls": 0, "ok": 0, "timeouts": 0, "auth": 0, "avg_ms": None, "max_ms": None}
        iv = P.intervals_of(x)
        counts = Counter(status_of(rec, now, iv.get(rec.get("group", ""), 60)) for rec in (x.capabilities or {}).values())
        rows.append({"switch_id": x.id, "name": x.name, "site": x.site, "vendor": x.vendor, "product_line": x.product_line, "state": x.state,
                     "monitoring": x.monitoring, "polls": a["polls"], "success_pct": round(100.0 * a["ok"] / a["polls"], 1) if a["polls"] else None,
                     "failures": a["polls"] - a["ok"], "timeouts": a["timeouts"], "auth_failures": a["auth"],
                     "avg_duration_ms": round(a["avg_ms"]) if a["polls"] else None,
                     "max_duration_ms": a["max_ms"] if a["polls"] else None, "last_success_at": iso(x.last_success_at),
                     "last_poll_at": iso(x.last_poll_at), "last_error": x.last_error, "fail_streak": x.fail_streak, "backoff_until": iso(x.backoff_until),
                     "coverage_pct": x.coverage_pct, "unsupported": counts.get("unsupported", 0), "failed_metrics": counts.get("failed", 0),
                     "stale_metrics": counts.get("stale", 0), "healthy_metrics": counts.get("healthy", 0)})
    total = sum(r["polls"] for r in rows)
    ok = sum(r["polls"] - r["failures"] for r in rows)
    durs = [r["avg_duration_ms"] for r in rows if r["avg_duration_ms"] is not None]
    try:
        tr = await ch.aquery("SELECT count() AS n, uniqExact(switch_id) AS devices FROM snmp_traps WHERE ts >= {t0:DateTime64(3)}", {"t0": t0})
        traps = {"received": int(tr[0]["n"]), "devices": int(tr[0]["devices"])} if tr else {"received": 0, "devices": 0}
    except Exception:
        traps = None
    from ..config import get_settings
    st = get_settings()
    return {"range": range, "summary": {"devices": len(rows), "polls": total, "success_pct": round(100.0 * ok / total, 1) if total else None,
                                        "failures": total - ok, "timeouts": sum(r["timeouts"] for r in rows), "auth_failures": sum(r["auth_failures"] for r in rows),
                                        "avg_duration_ms": round(sum(durs) / len(durs)) if durs else None,
                                        "backing_off": sum(1 for r in rows if r["backoff_until"] and r["backoff_until"] > now.isoformat()),
                                        "unsupported_metrics": sum(r["unsupported"] for r in rows), "inflight": len(P._inflight)},
            "engine": {"max_concurrent_polls": st.switch_max_concurrent_polls, "poll_timeout_s": st.switch_poll_timeout_seconds,
                       "wlc_poll_timeout_s": st.switch_wlc_poll_timeout_seconds, "snmpv2c_allowed": st.switch_allow_snmpv2c,
                       "requests_in_flight_per_device": 1, "backoff": "normal cadence for 2 failures, then doubling up to 15 min (auth: from the 1st)"},
            "traps": traps, "devices": sorted(rows, key=lambda r: (r["success_pct"] is None, r["success_pct"] if r["success_pct"] is not None else 0))}


# ------------------------------------------------------------------ registry and support matrix
@router.get("/registry")
async def registry(vendor: str | None = Query(None, max_length=16), group: str | None = Query(None, max_length=32), q: str | None = Query(None, max_length=128),
                   user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    settings = {r.key: r.enabled for r in (await s.execute(select(SnmpMetricSetting))).scalars()}
    sws = await _devices(s, user)
    observed: dict[tuple, set] = defaultdict(set)
    for x in sws:
        for k, rec in (x.capabilities or {}).items():
            if rec.get("ever_ok"):
                observed[(k, x.vendor)].add(x.id)
    rows = []
    for m in METRICS:
        if vendor and vendor not in m.vendors:
            continue
        if group and m.group != group:
            continue
        if q and q.lower() not in f"{m.key} {m.source} {m.oid}".lower():
            continue
        rows.append({"key": m.key, "group": m.group, "group_label": GROUPS.get(m.group, {}).get("label", m.group), "category": m.category, "source": m.source,
                     "oid": m.oid, "type": m.dtype, "unit": m.unit, "vendors": list(m.vendors), "note": m.note,
                     "interval_seconds": GROUPS.get(m.group, {}).get("interval"), "enabled": settings.get(m.key, True),
                     "observed_devices": {v: len(observed.get((m.key, v), ())) for v in m.vendors}})
    return {"items": rows, "groups": [{"key": k, **v} for k, v in GROUPS.items()]}


class MetricToggle(BaseModel):
    enabled: bool


@router.put("/registry/{key}")
async def toggle_metric(key: str, body: MetricToggle, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    if key not in {m.key for m in METRICS} or key in ("switch_up", "switch_system_info"):
        raise HTTPException(422, "unknown metric, or a metric that cannot be disabled")
    row = await s.get(SnmpMetricSetting, key)
    if row is None:
        row = SnmpMetricSetting(key=key)
        s.add(row)
    row.enabled, row.updated_by = body.enabled, user.username
    await s.commit()
    await audit(s, request, user.username, "snmp_metric_toggle", key, {"enabled": body.enabled})
    await s.commit()
    return {"key": key, "enabled": body.enabled}


@router.get("/support-matrix")
async def support_matrix(user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    """Metric × vendor / product line. "implemented" = the adapter requests it; "observed" = at least one device of that
    product line has returned it (capability registry); "unsupported" = every device of that line that was asked
    answered noSuchObject / empty. Nothing is called validated from MIB definitions alone."""
    sws = await _devices(s, user)
    lines: dict[tuple, list[Switch]] = defaultdict(list)
    for x in sws:
        lines[(x.vendor, x.product_line or x.family or "unidentified")].append(x)
    keys = []
    seen = set()
    for m in METRICS:
        if m.key not in seen and not m.group.startswith("wireless_"):
            seen.add(m.key)
            keys.append(m)
    cols = []
    for (vendor, line), devs in sorted(lines.items()):
        cells = {}
        for m in keys:
            if vendor not in [v for mm in METRICS if mm.key == m.key for v in mm.vendors]:
                cells[m.key] = "not_applicable"
                continue
            recs = [(x.capabilities or {}).get(m.key) for x in devs]
            recs = [r for r in recs if r]
            if any(r.get("ever_ok") for r in recs):
                cells[m.key] = "observed"
            elif recs and all(r.get("last_result") == "missing" for r in recs):
                cells[m.key] = "unsupported"
            elif any(r.get("last_result") == "error" for r in recs):
                cells[m.key] = "failing"
            else:
                cells[m.key] = "implemented"
        cols.append({"vendor": vendor, "product_line": line, "devices": len(devs), "cells": cells})
    adapters = [{"vendor": v, "families": list(getattr(a, "families", ()))} for v, a in _adapters().items()]
    return {"metrics": [{"key": m.key, "group": m.group, "category": m.category} for m in keys], "columns": cols, "adapters": adapters,
            "not_implemented": NOT_IMPLEMENTED}


def _adapters():
    from ..switches import adapters  # noqa: F401  (registers Fortinet / Juniper)
    from ..switches.collect import ADAPTERS
    return ADAPTERS


NOT_IMPLEMENTED = [
    {"area": "Cisco Catalyst 9800", "item": "RESTCONF / model-driven telemetry", "why": "SNMP covers APs, radios, WLANs and clients today (Wireless module); RESTCONF needs a separate read-only API credential"},
    {"area": "Ruckus SmartZone / Ruckus One", "item": "AP, radio and client inventory", "why": "needs the SmartZone public REST API (separate credential); SZ SNMP MIBs are not mapped yet"},
    {"area": "Ruckus standalone / Unleashed APs", "item": "radio and client metrics", "why": "RUCKUS-UNLEASHED / ZD MIBs are not mapped yet; standard MIBs (interfaces, system) work"},
    {"area": "Juniper", "item": "Virtual Chassis members, IPsec (SRX) tunnel state, BGP4-V2 (IPv6 peers)", "why": "not mapped yet; BGP4-MIB (IPv4) peers are collected"},
    {"area": "Juniper", "item": "NETCONF", "why": "out of scope for the SNMP engine; would be a separate optional adapter"},
    {"area": "Fortinet", "item": "FortiGate-managed FortiSwitch through the FortiGate", "why": "poll the FortiSwitch directly; FortiLink telemetry via FortiGate SNMP is not mapped"},
    {"area": "SNMP", "item": "SNMPv1 polling", "why": "polling uses v2c / v3 (v2c off unless enabled); v1 traps are received"},
]


# ------------------------------------------------------------------ OID search and test
@router.get("/oids/search")
async def oid_search(q: str = Query(min_length=2, max_length=128), limit: int = Query(100, ge=1, le=500), _: User = Depends(current_user),
                     s: AsyncSession = Depends(get_session)):
    ql = q.lower().lstrip(".")
    out = []
    for m in METRICS:
        if ql in m.key.lower() or ql in m.source.lower() or (m.oid and m.oid.startswith(ql)):
            out.append({"source": "registry", "name": m.key, "oid": m.oid, "module": m.source.split(" ")[0], "description": m.note or m.source,
                        "vendors": list(m.vendors)})
    from ..snmp_traps import TRAP_NAMES
    for oid, n in TRAP_NAMES.items():
        if ql in n.lower() or oid.startswith(ql):
            out.append({"source": "notification", "name": n, "oid": oid, "module": n.split("::")[0], "description": "notification"})
    for mod in (await s.execute(select(SnmpMibModule).where(SnmpMibModule.enabled.is_(True)))).scalars():
        for name, o in (mod.objects or {}).items():
            if ql in name.lower() or o["oid"].startswith(ql):
                out.append({"source": "mib", "name": f"{mod.name}::{name}", "oid": o["oid"], "module": mod.name, "kind": o["kind"],
                            "syntax": o.get("syntax"), "access": o.get("access"), "description": o.get("description", "")[:300]})
                if len(out) >= limit * 3:
                    break
    return {"items": out[:limit], "total": len(out)}


class OidTestIn(BaseModel):
    switch_id: int
    oid: str = Field(max_length=255)
    method: str = Field("get", pattern=r"^(get|walk)$")


@router.post("/oids/test")
async def oid_test(body: OidTestIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    try:
        oid = SP.validate_oid(body.oid)
    except ValueError as e:
        raise HTTPException(422, str(e))
    sw = await _device(s, body.switch_id, user)
    cred = await s.get(SwitchCredential, sw.credential_id) if sw.credential_id else None
    if cred is None:
        raise HTTPException(422, "the device has no SNMP credential profile")
    try:
        P.validate_address(sw.address, (await s.execute(select(SwitchNetwork))).scalars().all())
        client = P.make_client(sw, cred)
        res = await SP.test_oid(client, oid, body.method)
        await client.close()
    except (SnmpError, ValueError) as e:
        await audit(s, request, user.username, "snmp_oid_test", sw.name, {"oid": oid, "method": body.method, "error": str(e)[:200]}, success=False)
        await s.commit()
        raise HTTPException(502, f"SNMP request failed: {getattr(e, 'message', str(e))}")
    names = await SP.oid_names(s)
    for r in res["rows"]:
        r["name"] = SP.name_oid(r["oid"], names)
    await audit(s, request, user.username, "snmp_oid_test", sw.name, {"oid": oid, "method": body.method, "rows": len(res["rows"])})
    await s.commit()
    return {"device": sw.name, **res}


# ------------------------------------------------------------------ custom OID profiles
class CustomIn(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.\-]{0,63}$")
    oid: str = Field(max_length=255)
    method: str = Field("get", pattern=r"^(get|walk)$")
    value_type: str = Field("gauge", pattern=r"^(gauge|counter|state|info)$")
    unit: str = Field("", max_length=16)
    scale: float = Field(1.0, gt=0, le=1e12)
    vendor: str = Field("", pattern=r"^(|cisco|fortinet|juniper|ruckus|generic)$")
    product_line: str = Field("", max_length=64)
    switch_ids: list[int] = Field(default_factory=list, max_length=2000)
    description: str = Field("", max_length=2000)
    enabled: bool = True


def _snapshot(c: SnmpCustomOid) -> dict:
    return {k: getattr(c, k) for k in ("name", "oid", "method", "value_type", "unit", "scale", "vendor", "product_line", "switch_ids", "description", "enabled")}


@router.get("/custom")
async def list_custom(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    return {"items": [SP.custom_row(c) for c in (await s.execute(select(SnmpCustomOid).order_by(SnmpCustomOid.name))).scalars()]}


@router.post("/custom", status_code=201)
async def create_custom(body: CustomIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    try:
        oid = SP.validate_oid(body.oid)
    except ValueError as e:
        raise HTTPException(422, str(e))
    if (await s.execute(select(SnmpCustomOid).where(SnmpCustomOid.name == body.name))).scalars().first():
        raise HTTPException(409, "a custom OID with this name exists")
    c = SnmpCustomOid(**{**body.model_dump(), "oid": oid}, created_by=user.username, version=1)
    s.add(c)
    await s.flush()
    s.add(SnmpProfileVersion(kind="oid", ref_id=c.id, version=1, data=_snapshot(c), action="create", created_by=user.username))
    await s.commit()
    await audit(s, request, user.username, "snmp_custom_oid_create", c.name, {"oid": c.oid, "method": c.method})
    await s.commit()
    return SP.custom_row(c)


@router.put("/custom/{cid}")
async def update_custom(cid: int, body: CustomIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    c = await s.get(SnmpCustomOid, cid)
    if c is None:
        raise HTTPException(404, "custom OID not found")
    try:
        oid = SP.validate_oid(body.oid)
    except ValueError as e:
        raise HTTPException(422, str(e))
    other = (await s.execute(select(SnmpCustomOid).where(SnmpCustomOid.name == body.name))).scalars().first()
    if other and other.id != cid:
        raise HTTPException(409, "a custom OID with this name exists")
    for k, v in {**body.model_dump(), "oid": oid}.items():
        setattr(c, k, v)
    c.version = (c.version or 1) + 1
    s.add(SnmpProfileVersion(kind="oid", ref_id=c.id, version=c.version, data=_snapshot(c), action="update", created_by=user.username))
    await s.commit()
    await audit(s, request, user.username, "snmp_custom_oid_update", c.name, {"version": c.version})
    await s.commit()
    return SP.custom_row(c)


@router.delete("/custom/{cid}")
async def delete_custom(cid: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    c = await s.get(SnmpCustomOid, cid)
    if c is None:
        raise HTTPException(404, "custom OID not found")
    s.add(SnmpProfileVersion(kind="oid", ref_id=c.id, version=(c.version or 1) + 1, data=_snapshot(c), action="delete", created_by=user.username))
    await s.delete(c)
    await s.commit()
    await audit(s, request, user.username, "snmp_custom_oid_delete", c.name)
    await s.commit()
    return {"ok": True}


@router.get("/custom/{cid}/versions")
async def custom_versions(cid: int, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    rows = (await s.execute(select(SnmpProfileVersion).where(SnmpProfileVersion.kind == "oid", SnmpProfileVersion.ref_id == cid)
                            .order_by(SnmpProfileVersion.version.desc()))).scalars().all()
    return {"items": [{"version": r.version, "action": r.action, "data": r.data, "by": r.created_by, "at": iso(r.created_at)} for r in rows]}


@router.post("/custom/{cid}/rollback/{version}")
async def rollback_custom(cid: int, version: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    c = await s.get(SnmpCustomOid, cid)
    v = (await s.execute(select(SnmpProfileVersion).where(SnmpProfileVersion.kind == "oid", SnmpProfileVersion.ref_id == cid,
                                                          SnmpProfileVersion.version == version))).scalars().first()
    if c is None or v is None:
        raise HTTPException(404, "custom OID or version not found")
    for k, val in v.data.items():
        setattr(c, k, val)
    c.version = (c.version or 1) + 1
    s.add(SnmpProfileVersion(kind="oid", ref_id=c.id, version=c.version, data=_snapshot(c), action=f"rollback:{version}", created_by=user.username))
    await s.commit()
    await audit(s, request, user.username, "snmp_custom_oid_rollback", c.name, {"to": version, "version": c.version})
    await s.commit()
    return SP.custom_row(c)


# ------------------------------------------------------------------ MIB modules
class MibIn(BaseModel):
    filename: str = Field("", max_length=255)
    content: str = Field(min_length=20, max_length=SP.MAX_MIB_BYTES)


def _mib_row(m: SnmpMibModule, full: bool = False) -> dict:
    d = {"id": m.id, "name": m.name, "sha256": m.sha256, "imports": m.imports, "unresolved": m.unresolved, "objects": len(m.objects or {}),
         "enabled": m.enabled, "version": m.version, "imported_by": m.imported_by, "imported_at": iso(m.imported_at)}
    if full:
        d["definitions"] = [{"name": k, **v} for k, v in sorted((m.objects or {}).items(), key=lambda kv: [int(x) for x in kv[1]["oid"].split(".")])]
    return d


@router.get("/mibs")
async def list_mibs(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    return {"items": [_mib_row(m) for m in (await s.execute(select(SnmpMibModule).order_by(SnmpMibModule.name))).scalars()]}


@router.get("/mibs/{mid}")
async def get_mib(mid: int, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    m = await s.get(SnmpMibModule, mid)
    if m is None:
        raise HTTPException(404, "MIB module not found")
    return _mib_row(m, full=True)


@router.post("/mibs", status_code=201)
async def import_mib(body: MibIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    """Parse (never execute) a MIB module and store its definitions; a re-import of the same module is a new version."""
    try:
        head = SP.parse_mib(body.content)   # module name first, so its own earlier version is not used to resolve itself
        parsed = SP.parse_mib(body.content, await SP.known_names(s, exclude=head["module"]))
    except ValueError as e:
        raise HTTPException(422, str(e))
    digest = SP.sha256(body.content)
    m = (await s.execute(select(SnmpMibModule).where(SnmpMibModule.name == parsed["module"]))).scalars().first()
    if m and m.sha256 == digest:
        return {**_mib_row(m), "unchanged": True}
    if m:
        s.add(SnmpProfileVersion(kind="mib", ref_id=m.id, version=m.version, action="replaced", created_by=user.username,
                                 data={"sha256": m.sha256, "imports": m.imports, "unresolved": m.unresolved, "objects": m.objects}))
        m.sha256, m.imports, m.unresolved, m.objects = digest, parsed["imports"], parsed["unresolved"], parsed["objects"]
        m.version, m.imported_by, m.imported_at = (m.version or 1) + 1, user.username, _now()
    else:
        m = SnmpMibModule(name=parsed["module"], sha256=digest, imports=parsed["imports"], unresolved=parsed["unresolved"], objects=parsed["objects"],
                          imported_by=user.username, version=1)
        s.add(m)
    await s.commit()
    await audit(s, request, user.username, "snmp_mib_import", m.name, {"objects": len(m.objects), "unresolved": m.unresolved[:20], "version": m.version,
                                                                       "file": body.filename[:120]})
    await s.commit()
    return _mib_row(m)


class MibToggle(BaseModel):
    enabled: bool


@router.put("/mibs/{mid}")
async def toggle_mib(mid: int, body: MibToggle, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    m = await s.get(SnmpMibModule, mid)
    if m is None:
        raise HTTPException(404, "MIB module not found")
    m.enabled = body.enabled
    await s.commit()
    await audit(s, request, user.username, "snmp_mib_toggle", m.name, {"enabled": body.enabled})
    await s.commit()
    return _mib_row(m)


@router.post("/mibs/{mid}/rollback")
async def rollback_mib(mid: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    m = await s.get(SnmpMibModule, mid)
    prev = (await s.execute(select(SnmpProfileVersion).where(SnmpProfileVersion.kind == "mib", SnmpProfileVersion.ref_id == mid)
                            .order_by(SnmpProfileVersion.version.desc()))).scalars().first() if m else None
    if m is None or prev is None:
        raise HTTPException(404, "no earlier version to roll back to")
    s.add(SnmpProfileVersion(kind="mib", ref_id=m.id, version=m.version, action="rolled_back", created_by=user.username,
                             data={"sha256": m.sha256, "imports": m.imports, "unresolved": m.unresolved, "objects": m.objects}))
    m.sha256, m.imports, m.unresolved, m.objects = prev.data["sha256"], prev.data["imports"], prev.data["unresolved"], prev.data["objects"]
    m.version = (m.version or 1) + 1
    await s.delete(prev)
    await s.commit()
    await audit(s, request, user.username, "snmp_mib_rollback", m.name, {"version": m.version})
    await s.commit()
    return _mib_row(m)


@router.delete("/mibs/{mid}")
async def delete_mib(mid: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    m = await s.get(SnmpMibModule, mid)
    if m is None:
        raise HTTPException(404, "MIB module not found")
    await s.delete(m)
    await s.commit()
    await audit(s, request, user.username, "snmp_mib_delete", m.name)
    await s.commit()
    return {"ok": True}


@router.get("/export")
async def export_profiles(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    """Custom OIDs, metric switches and MIB module list (no device data, no credentials)."""
    return {"exported_at": _now().isoformat(), "format": "sentinel-nms-snmp-profiles/1",
            "custom_oids": [_snapshot(c) for c in (await s.execute(select(SnmpCustomOid).order_by(SnmpCustomOid.name))).scalars()],
            "metric_settings": [{"key": r.key, "enabled": r.enabled} for r in (await s.execute(select(SnmpMetricSetting))).scalars()],
            "mib_modules": [{"name": m.name, "sha256": m.sha256, "version": m.version, "objects": len(m.objects or {})}
                            for m in (await s.execute(select(SnmpMibModule).order_by(SnmpMibModule.name))).scalars()]}


# ------------------------------------------------------------------ traps
@router.get("/traps")
async def traps(range: str = Query("24h", pattern=r"^(1h|24h|7d|30d)$"), switch_id: int | None = None, severity: list[str] = Query(default=[]),
                q: str | None = Query(None, max_length=128), limit: int = Query(200, ge=1, le=1000), user: User = Depends(current_user),
                s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    t0 = _now() - timedelta(hours=RANGE[range])
    devs = {x.id: x for x in await _devices(s, user)}
    ids = [switch_id] if switch_id and switch_id in devs else list(devs) or [0]
    if switch_id and switch_id not in devs:
        raise HTTPException(404, "device not found")
    where = "ts >= {t0:DateTime64(3)} AND switch_id IN {ids:Array(UInt32)}"
    params: dict = {"t0": t0, "ids": ids, "lim": limit}
    sev = [x for x in severity if x in SEVERITIES]
    if sev:
        where += " AND severity IN {sev:Array(String)}"
        params["sev"] = sev
    if q:
        where += " AND (positionCaseInsensitive(trap_name, {q:String}) > 0 OR positionCaseInsensitive(summary, {q:String}) > 0 OR " \
                 "positionCaseInsensitive(component, {q:String}) > 0 OR startsWith(trap_oid, {q:String}))"
        params["q"] = q
    rows = await ch.aquery(f"SELECT ts, switch_id, source_ip, version, vendor, trap_oid, trap_name, severity, component, ifindex, summary, varbinds, repeats "
                           f"FROM snmp_traps WHERE {where} ORDER BY ts DESC LIMIT {{lim:UInt32}}", params)
    summ = await ch.aquery(f"SELECT severity, count() AS n FROM snmp_traps WHERE {where} GROUP BY severity", params)
    top = await ch.aquery(f"SELECT trap_name, count() AS n FROM snmp_traps WHERE {where} GROUP BY trap_name ORDER BY n DESC LIMIT 10", params)
    items = []
    for r in rows:
        try:
            vb = json.loads(r["varbinds"])
        except ValueError:
            vb = []
        sw = devs.get(int(r["switch_id"]))
        items.append({"ts": r["ts"] if isinstance(r["ts"], str) else iso(r["ts"]), "switch_id": int(r["switch_id"]), "switch": sw.name if sw else None,
                      "source_ip": r["source_ip"], "version": r["version"], "vendor": r["vendor"], "trap_oid": r["trap_oid"], "trap_name": r["trap_name"],
                      "severity": r["severity"], "component": r["component"], "ifindex": r["ifindex"], "summary": r["summary"], "varbinds": vb,
                      "repeats": int(r["repeats"] or 0)})
    return {"range": range, "items": items, "by_severity": {x["severity"]: int(x["n"]) for x in summ}, "top": [{"name": x["trap_name"], "count": int(x["n"])} for x in top],
            "receiver": {"port": "162/udp (container 1162)", "accepts": "inventory devices only, with their own credential profile"}}


@router.get("/stats")
async def stats(user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    n = (await s.execute(select(func.count(SnmpCustomOid.id)))).scalar_one()
    m = (await s.execute(select(func.count(SnmpMibModule.id)))).scalar_one()
    return {"devices": len(await _devices(s, user)), "custom_oids": n, "mib_modules": m, "registry_metrics": len({x.key for x in METRICS})}
