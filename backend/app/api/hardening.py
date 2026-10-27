"""Firewall hardening plans: build port/URL/address groups and policies from observed telemetry, render them as
FortiOS CLI for an engineer to review and apply. The SIEM itself stays read-only (GET requests only)."""
import ipaddress
from datetime import datetime, timezone
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..analytics.filters import ALLOWED, DENIED, EventFilter, build_where, table
from ..db.ch import ClickHouse
from ..db.models import Firewall, HardeningPlan, User
from ..db.pg import get_session
from ..fortigate.client import FortiGateAuthError, FortiGateError, FortiGateNotSupported
from ..fortigate.service import build_client
from ..hardening.cli import render_apply, render_rollback
from ..hardening.spec import PlanSpec
from .deps import audit, ch_dep, current_user, event_filter, iso, require_admin

router = APIRouter(prefix="/api/hardening", tags=["hardening"])
A = "(" + ",".join(f"'{x}'" for x in ALLOWED) + ")"
D = "(" + ",".join(f"'{x}'" for x in DENIED) + ")"


def _errors(e: ValidationError) -> list[str]:
    return [f"{'.'.join(str(x) for x in err['loc']) or 'plan'}: {err['msg'].removeprefix('Value error, ')}" for err in e.errors()]


def parse_spec(raw: dict) -> PlanSpec:
    try:
        return PlanSpec.model_validate(raw or {})
    except ValidationError as e:
        raise HTTPException(422, {"errors": _errors(e)})


def plan_out(p: HardeningPlan) -> dict:
    return {"id": p.id, "name": p.name, "description": p.description, "firewall_id": p.firewall_id, "status": p.status,
            "spec": p.spec, "last_check": p.last_check, "created_by": p.created_by, "updated_by": p.updated_by,
            "last_exported_at": iso(p.last_exported_at), "created_at": iso(p.created_at), "updated_at": iso(p.updated_at)}


class PlanIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field("", max_length=4000)
    firewall_id: int | None = None
    status: str = Field("draft", pattern=r"^(draft|ready|exported)$")
    spec: dict = Field(default_factory=dict)


@router.get("/plans")
async def list_plans(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    return [plan_out(p) for p in (await s.execute(select(HardeningPlan).order_by(HardeningPlan.updated_at.desc()))).scalars()]


@router.get("/plans/{plan_id}")
async def get_plan(plan_id: int, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    p = await s.get(HardeningPlan, plan_id)
    if not p:
        raise HTTPException(404, "not found")
    return plan_out(p)


@router.post("/plans", status_code=201)
async def create_plan(body: PlanIn, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    spec = parse_spec(body.spec)
    p = HardeningPlan(name=body.name, description=body.description, firewall_id=body.firewall_id, status=body.status,
                      spec=spec.model_dump(), last_check={}, created_by=admin.username, updated_by=admin.username)
    s.add(p)
    await s.commit()
    await audit(s, request, admin.username, "hardening_plan_create", f"{p.id}:{p.name}")
    return plan_out(p)


@router.put("/plans/{plan_id}")
async def update_plan(plan_id: int, body: PlanIn, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    p = await s.get(HardeningPlan, plan_id)
    if not p:
        raise HTTPException(404, "not found")
    spec = parse_spec(body.spec)
    p.name, p.description, p.firewall_id, p.status = body.name, body.description, body.firewall_id, body.status
    if spec.model_dump() != p.spec:
        p.last_check = {}  # a previous firewall check no longer applies
    p.spec = spec.model_dump()
    p.updated_by = admin.username
    await s.commit()
    await audit(s, request, admin.username, "hardening_plan_update", f"{p.id}:{p.name}")
    return plan_out(p)


@router.delete("/plans/{plan_id}")
async def delete_plan(plan_id: int, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    p = await s.get(HardeningPlan, plan_id)
    if not p:
        raise HTTPException(404, "not found")
    name = p.name
    await s.delete(p)
    await s.commit()
    await audit(s, request, admin.username, "hardening_plan_delete", f"{plan_id}:{name}")
    return {"ok": True}


@router.post("/validate")
async def validate(body: dict, _: User = Depends(current_user)):
    try:
        spec = PlanSpec.model_validate(body or {})
    except ValidationError as e:
        return {"valid": False, "errors": _errors(e)}
    return {"valid": True, "errors": [], "external_references": {k: sorted(v) for k, v in spec.external_references().items()}}


@router.get("/plans/{plan_id}/cli")
async def plan_cli(plan_id: int, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    p = await s.get(HardeningPlan, plan_id)
    if not p:
        raise HTTPException(404, "not found")
    spec = parse_spec(p.spec)
    out = {"apply": render_apply(spec, p.id, p.name), "rollback": render_rollback(spec, p.id),
           "external_references": {k: sorted(v) for k, v in spec.external_references().items()},
           "last_check": p.last_check}
    p.last_exported_at = datetime.now(timezone.utc)
    if p.status == "ready":
        p.status = "exported"
    await s.commit()
    await audit(s, request, user.username, "hardening_plan_export", f"{p.id}:{p.name}")
    return out


# ------------------------------------------------------------- read-only check against the firewall
async def _exists(client, path: str) -> str:
    try:
        body = await client.get(path)
        res = body.get("results")
        return "exists" if (res if not isinstance(res, list) else len(res)) else "absent"
    except FortiGateNotSupported:
        return "absent"
    except FortiGateAuthError as e:
        if e.status == 401:
            raise
        return "forbidden"


@router.post("/plans/{plan_id}/check")
async def check_plan(plan_id: int, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    """GET-only comparison with the live configuration: objects the plan would overwrite, and references that do
    not exist yet (the CLI would fail). Requires fwgrp/utmgrp/netgrp read permission."""
    p = await s.get(HardeningPlan, plan_id)
    if not p:
        raise HTTPException(404, "not found")
    if not p.firewall_id:
        raise HTTPException(400, "select a target firewall for this plan first")
    fw = await s.get(Firewall, p.firewall_id)
    if not fw or fw.is_demo:
        raise HTTPException(400, "target firewall not found or is a demo device")
    spec = parse_spec(p.spec)
    e = lambda n: quote(n, safe="")  # noqa: E731
    defined = ([(a.name, "address", f"/api/v2/cmdb/firewall/address/{e(a.name)}") for a in spec.addresses]
               + [(g.name, "address group", f"/api/v2/cmdb/firewall/addrgrp/{e(g.name)}") for g in spec.address_groups]
               + [(x.name, "service", f"/api/v2/cmdb/firewall.service/custom/{e(x.name)}") for x in spec.services]
               + [(g.name, "service group", f"/api/v2/cmdb/firewall.service/group/{e(g.name)}") for g in spec.service_groups]
               + [(str(u.table_id), "URL filter table", f"/api/v2/cmdb/webfilter/urlfilter/{u.table_id}") for u in spec.url_filters]
               + [(u.profile_name, "web filter profile", f"/api/v2/cmdb/webfilter/profile/{e(u.profile_name)}") for u in spec.url_filters if u.profile_name]
               + [(x.name, "policy", f"/api/v2/cmdb/firewall/policy?filter=name=={e(x.name)}") for x in spec.policies])
    refs = spec.external_references()
    result = {"checked_at": datetime.now(timezone.utc).isoformat(), "firewall": fw.name, "overwrites": [], "missing": [],
              "forbidden": [], "error": None}
    if fw.vendor != "fortinet":
        raise HTTPException(400, "hardening plans generate FortiOS CLI; this firewall is not a FortiGate")
    client = build_client(fw)
    try:
        for name, kind, path in defined:
            st = await _exists(client, path)
            if st == "exists":
                result["overwrites"].append({"kind": kind, "name": name})
            elif st == "forbidden":
                result["forbidden"].append({"kind": kind, "name": name})
        for name in sorted(refs["address"]):
            a = await _exists(client, f"/api/v2/cmdb/firewall/address/{e(name)}")
            g = await _exists(client, f"/api/v2/cmdb/firewall/addrgrp/{e(name)}") if a != "exists" else "n/a"
            if "exists" not in (a, g):
                result["missing"].append({"kind": "address", "name": name})
        for name in sorted(refs["service"]):
            c = await _exists(client, f"/api/v2/cmdb/firewall.service/custom/{e(name)}")
            g = await _exists(client, f"/api/v2/cmdb/firewall.service/group/{e(name)}") if c != "exists" else "n/a"
            if "exists" not in (c, g):
                result["missing"].append({"kind": "service", "name": name})
        for name in sorted(refs["webfilter_profile"]):
            if await _exists(client, f"/api/v2/cmdb/webfilter/profile/{e(name)}") != "exists":
                result["missing"].append({"kind": "web filter profile", "name": name})
        for name in sorted(refs["interface"]):
            i = await _exists(client, f"/api/v2/cmdb/system/interface/{e(name)}")
            z = await _exists(client, f"/api/v2/cmdb/system/zone/{e(name)}") if i != "exists" else "n/a"
            if "exists" not in (i, z):
                result["missing"].append({"kind": "interface/zone", "name": name})
    except FortiGateError as ex:
        result["error"] = str(ex)
    finally:
        await client.close()
    p.last_check = result
    await s.commit()
    await audit(s, request, admin.username, "hardening_plan_check", f"{p.id}:{p.name}",
                {"overwrites": len(result["overwrites"]), "missing": len(result["missing"]), "error": result["error"]})
    return result


# ------------------------------------------------------------- suggestions from observed telemetry
@router.get("/suggest")
async def suggest(limit: int = Query(50, ge=5, le=200), f: EventFilter = Depends(event_filter),
                  _: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep)):
    """Ports and domains actually observed in the selected window, to seed groups. Suggestions only."""
    if f.src_ip:
        try:
            ipaddress.ip_network(f.src_ip, strict=False)
        except ValueError:
            raise HTTPException(422, "invalid source IP/CIDR")
    tw, tp = build_where(f, categories=("traffic",), extra=["dst_port IS NOT NULL"])
    ww, wp = build_where(f, categories=("web",), extra=["hostname != ''"])
    ports_sql = f"""SELECT dst_port AS port, proto_name AS proto, topKIf(1)(service, service != '') AS svc,
        countIf(action IN {A}) AS allowed, countIf(action IN {D}) AS denied, uniqExact(src_ip) AS sources,
        uniqExact(dst_ip) AS destinations, sum(sent_bytes + rcvd_bytes) AS bytes
        FROM {table()} WHERE {tw} AND proto_name IN ('TCP','UDP') GROUP BY port, proto ORDER BY allowed DESC, denied DESC LIMIT {limit}"""
    dom_sql = f"""SELECT cutToFirstSignificantSubdomain(lower(hostname)) AS domain, countIf(action IN {A}) AS allowed,
        countIf(action IN {D}) AS blocked, uniqExact(src_ip) AS clients, any(url_category) AS url_cat
        FROM {table()} WHERE {ww} GROUP BY domain HAVING domain != '' ORDER BY allowed + blocked DESC LIMIT {limit}"""
    ports = await ch.aquery(ports_sql, tp)
    doms = await ch.aquery(dom_sql, wp)
    for r in ports:
        svc = r.pop("svc", None)
        r["service"] = svc[0] if svc else None  # as logged by FortiGate
    t0, t1 = f.window()
    return {"window": {"start": t0.isoformat(), "end": t1.isoformat()}, "ports": ports, "domains": doms,
            "note": "Derived from logged traffic in this window. Review business requirements before restricting access."}
