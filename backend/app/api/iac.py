"""APIs: Infrastructure as Code. Every route is authorised in the backend by IaC role (viewer / editor / approver /
deployer / admin); the UI only mirrors these checks."""
from __future__ import annotations

import io
import zipfile
from datetime import datetime, timedelta, timezone

import yaml
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import (Firewall, IacApproval, IacAudit, IacBackup, IacDevice, IacDrift, IacException, IacJob, IacJobDevice, IacPlan,
                         IacProject, IacRule, IacVersion, User)
from ..db.pg import get_session
from ..iac import service as S
from ..iac.resources import TYPES, capability_matrix, redact
from ..iac.rules import load_ruleset
from ..iac.schema import EXAMPLE, ConfigError, import_yaml, parse
from .deps import client_ip, current_user, iso, limiter

def _request_ip(request: Request) -> None:
    S.CLIENT_IP.set(client_ip(request))  # audit records written deeper in the workflow carry the caller's address


router = APIRouter(prefix="/api/iac", tags=["iac"], dependencies=[Depends(_request_ip)])
ENVS = r"^(development|staging|production)$"


def _err(e: S.IacError):
    raise HTTPException(e.status, e.message)


async def need(user: User, role: str) -> None:
    try:
        S.require(user, role)
    except S.IacError as e:
        _err(e)


def _rate(user: User, what: str, limit: int) -> None:
    if not limiter.check(f"iac:{what}:{user.id}", limit):
        raise HTTPException(429, f"too many {what} requests; try again in a minute")


async def _project(s: AsyncSession, pid: int) -> IacProject:
    p = await s.get(IacProject, pid)
    if p is None:
        raise HTTPException(404, "project not found")
    return p


async def _plan(s: AsyncSession, pid: int) -> IacPlan:
    p = await s.get(IacPlan, pid)
    if p is None:
        raise HTTPException(404, "plan not found")
    return p


# ------------------------------------------------------------------ meta
@router.get("/meta")
async def meta(user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    settings = await S.get_iac_settings(s)
    ok, why = S.writes_effective(settings)
    return {"roles": sorted(S.roles_of(user)) or ["viewer"], "capabilities": capability_matrix(), "example": EXAMPLE,
            "writes_effective": ok, "writes_reason": why, "settings": settings, "username": user.username}


@router.get("/overview")
async def overview(days: int = Query(7, ge=1, le=90), _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    return await S.overview(s, days)


# ------------------------------------------------------------------ projects
class ProjectIn(BaseModel):
    name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._\-]*$")
    description: str = Field("", max_length=2000)
    environment: str = Field("development", pattern=ENVS)


@router.get("/projects")
async def projects(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    rows = (await s.execute(select(IacProject).order_by(IacProject.name))).scalars().all()
    counts = dict((await s.execute(select(IacDevice.project_id, func.count(IacDevice.id)).group_by(IacDevice.project_id))).all())
    latest = dict((await s.execute(select(IacVersion.project_id, func.max(IacVersion.number)).group_by(IacVersion.project_id))).all())
    return [{"id": p.id, "name": p.name, "description": p.description, "environment": p.environment, "archived": p.archived,
             "devices": counts.get(p.id, 0), "latest_version": latest.get(p.id), "approved_version_id": p.approved_version_id,
             "draft_updated_at": iso(p.draft_updated_at), "draft_updated_by": p.draft_updated_by, "created_by": p.created_by} for p in rows]


@router.post("/projects", status_code=201)
async def create_project(body: ProjectIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await need(user, "editor")
    if (await s.execute(select(IacProject.id).where(IacProject.name == body.name))).first():
        raise HTTPException(409, "a project with this name exists")
    p = IacProject(name=body.name, description=body.description, environment=body.environment, created_by=user.username,
                   draft_content=EXAMPLE.replace("branch-baseline", body.name.lower().replace(" ", "-")))
    s.add(p)
    await s.flush()
    await S.audit(s, user.username, "project_create", project_id=p.id, target=p.name, detail={"environment": p.environment}, client_ip=client_ip(request))
    return {"id": p.id}


@router.put("/projects/{pid}")
async def update_project(pid: int, body: ProjectIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await need(user, "admin" if body.environment == "production" else "editor")
    p = await _project(s, pid)
    if p.environment != body.environment:
        await need(user, "admin")
    p.name, p.description, p.environment = body.name, body.description, body.environment
    await S.audit(s, user.username, "project_update", project_id=p.id, target=p.name, detail=body.model_dump(), client_ip=client_ip(request))
    return {"ok": True}


# ------------------------------------------------------------------ devices
class DeviceIn(BaseModel):
    firewall_id: int
    variables: dict[str, str] = Field(default_factory=dict)
    managed: bool = True


@router.get("/devices")
async def devices(project_id: int | None = None, q: str = Query("", max_length=128), site: str = Query("", max_length=128),
                  status: str = Query("", max_length=16), page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=200),
                  _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    """Firewall inventory joined with IaC management (a firewall in no project is listed as unmanaged)."""
    fws = (await s.execute(select(Firewall).where(Firewall.is_demo.is_(False)).order_by(Firewall.name))).scalars().all()
    devs = (await s.execute(select(IacDevice, IacProject).join(IacProject, IacProject.id == IacDevice.project_id))).all()
    by_fw: dict[int, list] = {}
    for d, p in devs:
        if project_id and d.project_id != project_id:
            continue
        by_fw.setdefault(d.firewall_id, []).append((d, p))
    rows = []
    for f in fws:
        links = by_fw.get(f.id, [])
        if project_id and not links:
            continue
        for d, p in links or [(None, None)]:
            r = {"firewall_id": f.id, "name": f.name, "host": f.host, "site": f.site, "vendor": f.vendor, "model": f.model,
                 "firmware": f.fortios_version_detected or f.fortios_version_declared, "api_status": f.api_status,
                 "device_id": d.id if d else None, "project_id": p.id if p else None, "project": p.name if p else "",
                 "environment": p.environment if p else "", "managed": bool(d and d.managed), "integration": d.integration if d else "",
                 "drift_status": d.drift_status if d else "unmanaged", "last_drift_check": iso(d.last_drift_check) if d else None,
                 "last_backup_at": iso(d.last_backup_at) if d else None, "last_deploy_at": iso(d.last_deploy_at) if d else None,
                 "last_deploy_status": d.last_deploy_status if d else "", "observed_at": iso(d.observed_at) if d else None,
                 "capabilities": d.capabilities if d else {}, "variables": d.variables if d else {}}
            if q and q.lower() not in f"{f.name} {f.host} {f.site}".lower():
                continue
            if site and f.site != site:
                continue
            if status and r["drift_status"] != status:
                continue
            rows.append(r)
    return {"total": len(rows), "page": page, "size": size, "items": rows[(page - 1) * size: page * size]}


@router.post("/projects/{pid}/devices", status_code=201)
async def add_device(pid: int, body: DeviceIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await need(user, "admin")
    await _project(s, pid)
    fw = await s.get(Firewall, body.firewall_id)
    if fw is None or fw.is_demo:
        raise HTTPException(404, "firewall not found")
    if fw.vendor != "fortinet":
        raise HTTPException(422, "IaC currently supports FortiGate devices only")
    if (await s.execute(select(IacDevice.id).where(IacDevice.project_id == pid, IacDevice.firewall_id == fw.id))).first():
        raise HTTPException(409, "device already in this project")
    other = (await s.execute(select(IacDevice, IacProject).join(IacProject, IacProject.id == IacDevice.project_id).where(
        IacDevice.firewall_id == fw.id, IacDevice.managed.is_(True)))).first()
    if other:
        raise HTTPException(409, f"device is already managed by project '{other[1].name}' (one owner per device)")
    d = IacDevice(project_id=pid, firewall_id=fw.id, variables=body.variables, managed=body.managed)
    s.add(d)
    await s.flush()
    await S.audit(s, user.username, "device_add", project_id=pid, target=fw.name, detail={"variables": list(body.variables)}, client_ip=client_ip(request))
    return {"id": d.id}


@router.put("/devices/{did}")
async def update_device(did: int, body: DeviceIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await need(user, "editor")
    d = await s.get(IacDevice, did)
    if d is None:
        raise HTTPException(404, "device not found")
    if body.managed != d.managed:
        await need(user, "admin")
    d.variables, d.managed = body.variables, body.managed
    await S.audit(s, user.username, "device_update", project_id=d.project_id, target=str(d.firewall_id),
                  detail={"managed": d.managed, "variables": list(body.variables)}, client_ip=client_ip(request))
    return {"ok": True}


@router.delete("/devices/{did}")
async def remove_device(did: int, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await need(user, "admin")
    d = await s.get(IacDevice, did)
    if d is None:
        raise HTTPException(404, "device not found")
    pid, fid = d.project_id, d.firewall_id
    await s.delete(d)
    await S.audit(s, user.username, "device_remove", project_id=pid, target=str(fid), detail={"note": "configuration on the device is unchanged"},
                  client_ip=client_ip(request))
    return {"ok": True}


@router.post("/devices/{did}/capabilities")
async def device_capabilities(did: int, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    """Detect what the device supports (GET only): readable tables, FortiManager management, write eligibility."""
    await need(user, "editor")
    _rate(user, "device-read", 20)
    d = await s.get(IacDevice, did)
    if d is None:
        raise HTTPException(404, "device not found")
    fw = await s.get(Firewall, d.firewall_id)
    try:
        return await S.refresh_capabilities(s, d, fw)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"cannot read the device: {redact(str(e))[:300]}")


# ------------------------------------------------------------------ studio: draft, validate, versions, import, export
class DraftIn(BaseModel):
    content: str = Field(max_length=1_000_000)


@router.get("/projects/{pid}/draft")
async def get_draft(pid: int, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    p = await _project(s, pid)
    approved = await s.get(IacVersion, p.approved_version_id) if p.approved_version_id else None
    base = await s.get(IacVersion, p.draft_base_version_id) if p.draft_base_version_id else None
    return {"content": p.draft_content, "updated_by": p.draft_updated_by, "updated_at": iso(p.draft_updated_at),
            "base_version": base.number if base else None, "approved": {"number": approved.number, "content": approved.content} if approved else None}


@router.put("/projects/{pid}/draft")
async def save_draft(pid: int, body: DraftIn, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await need(user, "editor")
    p = await _project(s, pid)
    p.draft_content, p.draft_updated_by, p.draft_updated_at = body.content, user.username, S.now()
    await s.commit()
    return {"ok": True, "updated_at": iso(p.draft_updated_at)}


@router.post("/projects/{pid}/validate")
async def validate(pid: int, body: DraftIn, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    """Schema, references, variables and security rules for a draft (no device access)."""
    _rate(user, "validate", 60)
    p = await _project(s, pid)
    rs = await load_ruleset(s, p.id)
    report = S.validate_text(body.content, rs, p.environment)
    if report["valid"]:
        doc = parse(body.content)
        refs = {"addresses": {}, "policies": {}}
        r = doc.resources
        for pol in r.policies:
            for a in pol.srcaddr + pol.dstaddr:
                refs["addresses"].setdefault(a, []).append(pol.id)
            for x in pol.service:
                refs["policies"].setdefault(x, []).append(pol.id)
        report["references"] = {"address_used_by_policies": refs["addresses"], "service_used_by_policies": refs["policies"],
                                "groups": {g.name: g.members for g in r.address_groups + r.service_groups}}
    return report


class CommitIn(BaseModel):
    content: str = Field(max_length=1_000_000)
    message: str = Field(min_length=1, max_length=2000)


@router.post("/projects/{pid}/versions", status_code=201)
async def commit(pid: int, body: CommitIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await need(user, "editor")
    p = await _project(s, pid)
    try:
        v = await S.commit_version(s, p, body.content, body.message, user.username)
    except S.IacError as e:
        _err(e)
    return {"id": v.id, "number": v.number, "valid": v.valid, "validation": v.validation}


@router.get("/projects/{pid}/versions")
async def versions(pid: int, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    p = await _project(s, pid)
    rows = (await s.execute(select(IacVersion).where(IacVersion.project_id == pid).order_by(IacVersion.number.desc()))).scalars().all()
    return [{"id": v.id, "number": v.number, "hash": v.content_hash, "author": v.author, "message": v.message, "valid": v.valid,
             "errors": len(v.validation.get("errors", [])), "findings": len(v.validation.get("findings", [])),
             "approved": v.id == p.approved_version_id, "approved_at": iso(v.approved_at), "created_at": iso(v.created_at)} for v in rows]


@router.get("/versions/{vid}")
async def version(vid: int, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    v = await s.get(IacVersion, vid)
    if v is None:
        raise HTTPException(404, "version not found")
    return {"id": v.id, "project_id": v.project_id, "number": v.number, "content": v.content, "hash": v.content_hash, "author": v.author,
            "message": v.message, "valid": v.valid, "validation": v.validation, "created_at": iso(v.created_at), "approved_at": iso(v.approved_at)}


class ImportIn(BaseModel):
    firewall_id: int
    types: list[str] = Field(default_factory=lambda: ["address", "address_group", "service", "service_group", "policy", "static_route"])


@router.post("/projects/{pid}/import")
async def import_live(pid: int, body: ImportIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    """Read supported resources from a managed firewall (GET only) and return them as desired-state YAML."""
    await need(user, "editor")
    _rate(user, "device-read", 20)
    bad = [t for t in body.types if t not in TYPES]
    if bad:
        raise HTTPException(422, f"unsupported types: {', '.join(bad)}")
    d = (await s.execute(select(IacDevice).where(IacDevice.project_id == pid, IacDevice.firewall_id == body.firewall_id))).scalars().first()
    if d is None:
        raise HTTPException(404, "device is not part of this project")
    fw = await s.get(Firewall, d.firewall_id)
    try:
        obs = await S.observe(s, d, fw)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"cannot read the device: {redact(str(e))[:300]}")
    await S.audit(s, user.username, "import", project_id=pid, target=fw.name, detail={"types": body.types}, client_ip=client_ip(request))
    from ..iac.resources import UNSUPPORTED
    content, skipped = import_yaml(obs["state"], obs["order"], f"{fw.name.lower()}-import", body.types, list(UNSUPPORTED))
    return {"content": content, "skipped": skipped,
            "unreadable": obs.get("errors", {}), "counts": {t: len(obs["state"].get(t) or {}) for t in body.types}}


@router.get("/projects/{pid}/export")
async def export(pid: int, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    """Repository-style archive (iac/…) of the project: no tokens, no device secrets."""
    p = await _project(s, pid)
    vs = (await s.execute(select(IacVersion).where(IacVersion.project_id == pid).order_by(IacVersion.number))).scalars().all()
    devs = (await s.execute(select(IacDevice, Firewall).join(Firewall, Firewall.id == IacDevice.firewall_id).where(IacDevice.project_id == pid))).all()
    rules = (await s.execute(select(IacRule))).scalars().all()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("iac/inventory/devices.yaml", yaml.safe_dump({"devices": [{"name": f.name, "site": f.site, "managed": d.managed,
                                                                             "integration": d.integration, "variables": d.variables} for d, f in devs]}, sort_keys=False))
        z.writestr("iac/inventory/sites.yaml", yaml.safe_dump({"sites": sorted({f.site for _, f in devs if f.site})}))
        if p.draft_content:
            z.writestr(f"iac/environments/{p.environment}/{p.name}.draft.yaml", p.draft_content)
        for v in vs:
            z.writestr(f"iac/environments/{p.environment}/history/{p.name}.v{v.number}.yaml",
                       f"# version {v.number} by {v.author} at {iso(v.created_at)} sha256 {v.content_hash}\n# {v.message}\n" + v.content)
        z.writestr("iac/policies/security_baseline.yaml", yaml.safe_dump({"rules": [{"id": r.rule_id, "family": r.family, "severity": r.severity,
                                                                                     "blocks_deploy": r.blocks_deploy, "enabled": r.enabled,
                                                                                     "params": r.params} for r in rules]}, sort_keys=False))
        z.writestr("iac/README.md", f"# {p.name}\n\nExported from Sentinel Grid IaC ({p.environment}). Versions are immutable; "
                                    "the SIEM database remains the source of truth for plans and approvals.\n")
    await S.audit(s, user.username, "export", project_id=pid, target=p.name, client_ip=client_ip(request))
    buf.seek(0)
    return StreamingResponse(buf, media_type="application/zip", headers={"Content-Disposition": f'attachment; filename="iac-{p.id}.zip"'})


# ------------------------------------------------------------------ plans and approvals
class PlanIn(BaseModel):
    version_id: int
    firewall_ids: list[int] = Field(default_factory=list, max_length=200)


@router.post("/projects/{pid}/plans", status_code=201)
async def make_plan(pid: int, body: PlanIn, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await need(user, "editor")
    _rate(user, "plan", 10)
    p = await _project(s, pid)
    v = await s.get(IacVersion, body.version_id)
    if v is None or v.project_id != pid:
        raise HTTPException(404, "version not found in this project")
    if not v.valid:
        raise HTTPException(422, f"version {v.number} failed validation; fix the errors and commit a new version")
    try:
        plan = await S.create_plan(s, p, user.username, version=v, firewall_ids=body.firewall_ids or None)
    except S.IacError as e:
        _err(e)
    return {"id": plan.id, "status": plan.status}


@router.get("/plans")
async def plans(project_id: int | None = None, status: list[str] = Query(default=[]), page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=200),
                _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    q = select(IacPlan, IacProject.name).join(IacProject, IacProject.id == IacPlan.project_id)
    if project_id:
        q = q.where(IacPlan.project_id == project_id)
    if status:
        q = q.where(IacPlan.status.in_(status))
    total = (await s.execute(select(func.count()).select_from(q.subquery()))).scalar()
    rows = (await s.execute(q.order_by(IacPlan.id.desc()).offset((page - 1) * size).limit(size))).all()
    vers = {v.id: v.number for v in (await s.execute(select(IacVersion).where(IacVersion.id.in_([p.version_id for p, _ in rows if p.version_id])))).scalars()}
    return {"total": total, "items": [{"id": p.id, "project_id": p.project_id, "project": n, "environment": p.environment, "kind": p.kind,
                                       "version": vers.get(p.version_id), "status": p.status, "summary": p.summary, "blocking": p.blocking,
                                       "destructive": p.destructive, "created_by": p.created_by, "created_at": iso(p.created_at),
                                       "targets": p.targets, "stale_reason": p.stale_reason} for p, n in rows]}


@router.get("/plans/{plan_id}")
async def plan_detail(plan_id: int, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    p = await _plan(s, plan_id)
    ch = await S.plan_changes(s, plan_id)
    names = {f.id: f.name for f in (await s.execute(select(Firewall).where(Firewall.id.in_(p.targets or [0])))).scalars()}
    appr = (await s.execute(select(IacApproval).where(IacApproval.plan_id == plan_id).order_by(IacApproval.id))).scalars().all()
    jobs = (await s.execute(select(IacJob).where(IacJob.plan_id == plan_id).order_by(IacJob.id.desc()))).scalars().all()
    v = await s.get(IacVersion, p.version_id) if p.version_id else None
    return {"id": p.id, "project_id": p.project_id, "kind": p.kind, "status": p.status, "environment": p.environment,
            "version": {"id": v.id, "number": v.number, "hash": v.content_hash, "author": v.author} if v else None,
            "recovery_backup_id": p.recovery_backup_id, "plan_hash": p.plan_hash, "targets": [{"id": t, "name": names.get(t, f"#{t}")} for t in p.targets],
            "summary": p.summary, "findings": p.findings, "errors": p.errors, "blocking": p.blocking, "destructive": p.destructive,
            "stale_reason": p.stale_reason, "created_by": p.created_by, "created_at": iso(p.created_at), "observed_hashes": p.observed_hashes,
            "changes": [{"id": c.id, "firewall_id": c.firewall_id, "firewall_name": names.get(c.firewall_id, ""), "seq": c.seq, "type": c.resource_type,
                         "key": c.resource_id, "action": c.action, "current": c.current, "desired": c.desired, "fields": c.fields,
                         "depends_on": c.depends_on, "risk": c.risk, "rule_id": c.rule_id, "impact": c.impact, "disruptive": c.disruptive} for c in ch],
            "approvals": [{"username": a.username, "decision": a.decision, "comment": a.comment, "plan_hash": a.plan_hash,
                           "acknowledged_destructive": a.acknowledged_destructive, "at": iso(a.created_at)} for a in appr],
            "jobs": [{"id": j.id, "kind": j.kind, "status": j.status, "requested_by": j.requested_by, "created_at": iso(j.created_at)} for j in jobs]}


@router.post("/plans/{plan_id}/submit")
async def submit(plan_id: int, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    p = await _plan(s, plan_id)
    try:
        await S.submit(s, p, user)
    except S.IacError as e:
        _err(e)
    return {"status": p.status}


class DecisionIn(BaseModel):
    decision: str = Field(pattern=r"^(approve|reject)$")
    comment: str = Field("", max_length=2000)
    plan_hash: str = Field(min_length=64, max_length=64)
    acknowledge_destructive: bool = False


@router.post("/plans/{plan_id}/decision")
async def decision(plan_id: int, body: DecisionIn, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    p = await _plan(s, plan_id)
    try:
        await S.decide(s, p, user, body.decision, body.comment, body.plan_hash, body.acknowledge_destructive)
    except S.IacError as e:
        _err(e)
    return {"status": p.status}


@router.post("/plans/{plan_id}/refresh")
async def refresh(plan_id: int, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    """Check whether the plan is still current by re-reading its devices (GET only); marks it stale if not."""
    await need(user, "editor")
    _rate(user, "device-read", 20)
    p = await _plan(s, plan_id)
    if p.status in ("succeeded", "failed", "rolled_back", "cancelled", "rejected", "stale", "running", "queued"):
        return {"status": p.status, "stale_reason": p.stale_reason}
    reason = await S.staleness(s, p, read_devices=True)
    if reason:
        await S.mark_stale(s, p, reason, user.username)
    return {"status": p.status, "stale_reason": p.stale_reason}


class JobIn(BaseModel):
    dry_run: bool = False
    acknowledge_destructive: bool = False


@router.post("/plans/{plan_id}/jobs", status_code=201)
async def start_job(plan_id: int, body: JobIn, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    _rate(user, "deploy", 10)
    p = await _plan(s, plan_id)
    try:
        j = await S.queue_job(s, p, user, dry_run=body.dry_run, acknowledge_destructive=body.acknowledge_destructive)
    except S.IacError as e:
        _err(e)
    return {"id": j.id, "status": j.status}


@router.post("/plans/{plan_id}/cancel")
async def cancel_plan(plan_id: int, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await need(user, "editor")
    p = await _plan(s, plan_id)
    if p.status in ("queued", "running", "succeeded", "failed", "rolled_back"):
        raise HTTPException(409, f"plan is {p.status}; cancel its job instead" if p.status in ("queued", "running") else f"plan is {p.status}")
    p.status = "cancelled"
    await S.audit(s, user.username, "plan_cancel", project_id=p.project_id, plan_id=p.id)
    return {"status": p.status}


# ------------------------------------------------------------------ jobs
@router.get("/jobs")
async def jobs(project_id: int | None = None, status: list[str] = Query(default=[]), page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=200),
               _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    q = select(IacJob)
    if project_id:
        q = q.where(IacJob.project_id == project_id)
    if status:
        q = q.where(IacJob.status.in_(status))
    total = (await s.execute(select(func.count()).select_from(q.subquery()))).scalar()
    rows = (await s.execute(q.order_by(IacJob.id.desc()).offset((page - 1) * size).limit(size))).scalars().all()
    return {"total": total, "items": [{"id": j.id, "plan_id": j.plan_id, "project_id": j.project_id, "kind": j.kind, "status": j.status,
                                       "requested_by": j.requested_by, "progress": j.progress, "current_operation": j.current_operation,
                                       "error": j.error, "created_at": iso(j.created_at), "started_at": iso(j.started_at),
                                       "finished_at": iso(j.finished_at), "cancel_requested": j.cancel_requested} for j in rows]}


@router.get("/jobs/{job_id}")
async def job(job_id: int, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    j = await s.get(IacJob, job_id)
    if j is None:
        raise HTTPException(404, "job not found")
    devs = (await s.execute(select(IacJobDevice, Firewall.name).join(Firewall, Firewall.id == IacJobDevice.firewall_id, isouter=True)
                            .where(IacJobDevice.job_id == job_id))).all()
    return {"id": j.id, "plan_id": j.plan_id, "project_id": j.project_id, "kind": j.kind, "status": j.status, "requested_by": j.requested_by,
            "progress": j.progress, "current_operation": j.current_operation, "log": j.log, "error": j.error, "cancel_requested": j.cancel_requested,
            "created_at": iso(j.created_at), "started_at": iso(j.started_at), "finished_at": iso(j.finished_at),
            "devices": [{"firewall_id": d.firewall_id, "firewall_name": n, "status": d.status, "backup_id": d.backup_id, "results": d.results,
                         "verification": d.verification, "health": d.health, "error": d.error, "started_at": iso(d.started_at),
                         "finished_at": iso(d.finished_at)} for d, n in devs]}


@router.post("/jobs/{job_id}/cancel")
async def cancel_job(job_id: int, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    j = await s.get(IacJob, job_id)
    if j is None:
        raise HTTPException(404, "job not found")
    try:
        await S.cancel_job(s, j, user)
    except S.IacError as e:
        _err(e)
    return {"status": j.status, "cancel_requested": j.cancel_requested,
            "note": "" if j.status == "cancelled" else "the job stops before its next change; a change already sent to a device cannot be recalled"}


# ------------------------------------------------------------------ drift
@router.post("/projects/{pid}/drift", status_code=201)
async def run_drift(pid: int, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await need(user, "editor")
    _rate(user, "drift", 10)
    p = await _project(s, pid)
    if not p.approved_version_id:
        raise HTTPException(409, "no approved configuration yet: drift is measured against an approved version")
    j = IacJob(project_id=pid, kind="drift", requested_by=user.username)
    s.add(j)
    await s.flush()
    await S.audit(s, user.username, "drift_queue", project_id=pid, job_id=j.id)
    return {"id": j.id}


@router.get("/drift")
async def drift(project_id: int | None = None, firewall_id: int | None = None, severity: list[str] = Query(default=[]),
                days: int = Query(30, ge=1, le=365), latest: bool = True, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    q = select(IacDrift).where(IacDrift.checked_at >= S.now() - timedelta(days=days))
    if project_id:
        q = q.where(IacDrift.project_id == project_id)
    if firewall_id:
        q = q.where(IacDrift.firewall_id == firewall_id)
    rows = (await s.execute(q.order_by(IacDrift.id.desc()).limit(2000))).scalars().all()
    if latest:
        seen, keep = set(), []
        for r in rows:
            if r.device_id not in seen:
                seen.add(r.device_id)
                keep.append(r)
        rows = keep
    names = {f.id: f.name for f in (await s.execute(select(Firewall))).scalars()}
    out = []
    for r in rows:
        f = [x for x in r.findings if not severity or x["severity"] in severity]
        out.append({"id": r.id, "device_id": r.device_id, "firewall_id": r.firewall_id, "firewall_name": names.get(r.firewall_id, ""),
                    "project_id": r.project_id, "checked_at": iso(r.checked_at), "status": r.status, "counts": r.counts, "error": r.error,
                    "findings": f})
    return out


# ------------------------------------------------------------------ backups and recovery
@router.get("/backups")
async def backups(firewall_id: int | None = None, page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=200),
                  _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    q = select(IacBackup, Firewall.name).join(Firewall, Firewall.id == IacBackup.firewall_id)
    if firewall_id:
        q = q.where(IacBackup.firewall_id == firewall_id)
    rows = (await s.execute(q.order_by(IacBackup.id.desc()).offset((page - 1) * size).limit(size))).all()
    return [{"id": b.id, "firewall_id": b.firewall_id, "firewall_name": n, "job_id": b.job_id, "plan_id": b.plan_id, "kind": b.kind,
             "snapshot_sha256": b.snapshot_sha256, "full_config": bool(b.full_config_ciphertext), "full_config_sha256": b.full_config_sha256,
             "note": b.full_config_note, "validated": b.validated, "created_by": b.created_by, "created_at": iso(b.created_at),
             "objects": {t: len(v) for t, v in (b.snapshot.get("state") or {}).items()}} for b, n in rows]


@router.post("/backups/{bid}/verify")
async def verify_backup(bid: int, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await need(user, "deployer")
    b = await s.get(IacBackup, bid)
    if b is None:
        raise HTTPException(404, "backup not found")
    ok, why = S.validate_backup(b)
    b.validated = ok
    await S.audit(s, user.username, "backup_verify", target=str(bid), detail={"ok": ok, "detail": why})
    return {"ok": ok, "detail": why}


@router.post("/backups/{bid}/recovery-plan", status_code=201)
async def recovery_plan(bid: int, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    """Build a reviewable plan that restores the managed resources captured in this backup. It follows the same
    approval and deployment workflow; nothing is restored automatically."""
    await need(user, "deployer")
    _rate(user, "plan", 10)
    b = await s.get(IacBackup, bid)
    if b is None:
        raise HTTPException(404, "backup not found")
    ok, why = S.validate_backup(b)
    if not ok:
        raise HTTPException(409, f"backup failed validation: {why}")
    dev = (await s.execute(select(IacDevice).where(IacDevice.firewall_id == b.firewall_id, IacDevice.managed.is_(True)))).scalars().first()
    if dev is None:
        raise HTTPException(409, "the device is not managed by any IaC project")
    p = await s.get(IacProject, dev.project_id)
    try:
        plan = await S.create_plan(s, p, user.username, recovery=b)
    except S.IacError as e:
        _err(e)
    return {"id": plan.id, "status": plan.status}


# ------------------------------------------------------------------ rules, exceptions, roles, settings, audit
class RuleIn(BaseModel):
    severity: str = Field(pattern=r"^(info|low|medium|high|critical)$")
    blocks_deploy: bool
    enabled: bool
    params: dict = Field(default_factory=dict)


@router.get("/rules")
async def rules(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    rs = await load_ruleset(s)
    return {"rules": [{"rule_id": r.rule_id, "family": r.family, "title": r.title, "severity": r.severity, "blocks_deploy": r.blocks_deploy,
                       "enabled": r.enabled, "params": r.params, "remediation": r.remediation} for r in sorted(rs["rules"].values(), key=lambda r: r.rule_id)],
            "exceptions": [{"id": e.id, "rule_id": e.rule_id, "project_id": e.project_id, "firewall_id": e.firewall_id, "resource": e.resource,
                            "owner": e.owner, "justification": e.justification, "expires_at": iso(e.expires_at), "created_by": e.created_by}
                           for e in (await s.execute(select(IacException).order_by(IacException.id.desc()))).scalars()]}


@router.put("/rules/{rule_id}")
async def update_rule(rule_id: str, body: RuleIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await need(user, "admin")
    r = await s.get(IacRule, rule_id)
    if r is None:
        raise HTTPException(404, "rule not found")
    r.severity, r.blocks_deploy, r.enabled, r.params = body.severity, body.blocks_deploy, body.enabled, body.params
    await S.audit(s, user.username, "rule_update", target=rule_id, detail=body.model_dump(), client_ip=client_ip(request))
    return {"ok": True}


class ExceptionIn(BaseModel):
    rule_id: str = Field(min_length=3, max_length=32)
    project_id: int | None = None
    firewall_id: int | None = None
    resource: str = Field("*", min_length=1, max_length=255)
    owner: str = Field(min_length=1, max_length=128)
    justification: str = Field(min_length=10, max_length=4000)
    expires_at: datetime


@router.post("/exceptions", status_code=201)
async def add_exception(body: ExceptionIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await need(user, "admin")
    exp = body.expires_at if body.expires_at.tzinfo else body.expires_at.replace(tzinfo=timezone.utc)
    if exp <= S.now() or exp > S.now() + timedelta(days=366):
        raise HTTPException(422, "expiry must be in the future and within one year")
    if await s.get(IacRule, body.rule_id) is None:
        raise HTTPException(404, "rule not found")
    e = IacException(**{**body.model_dump(), "expires_at": exp}, created_by=user.username)
    s.add(e)
    await s.flush()
    await S.audit(s, user.username, "exception_add", target=body.rule_id, detail={**body.model_dump(mode="json")}, client_ip=client_ip(request))
    return {"id": e.id}


@router.delete("/exceptions/{eid}")
async def remove_exception(eid: int, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await need(user, "admin")
    e = await s.get(IacException, eid)
    if e is None:
        raise HTTPException(404, "exception not found")
    await s.delete(e)
    await S.audit(s, user.username, "exception_remove", target=str(eid), client_ip=client_ip(request))
    return {"ok": True}


class RolesIn(BaseModel):
    roles: list[str] = Field(max_length=4)


@router.get("/roles")
async def roles(user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await need(user, "admin")
    return [{"id": u.id, "username": u.username, "siem_role": u.role, "iac_roles": sorted(u.iac_roles or []), "effective": sorted(S.roles_of(u))}
            for u in (await s.execute(select(User).order_by(User.username))).scalars()]


@router.put("/roles/{uid}")
async def set_roles(uid: int, body: RolesIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await need(user, "admin")
    bad = [r for r in body.roles if r not in S.ROLES]
    if bad:
        raise HTTPException(422, f"unknown roles: {', '.join(bad)}")
    u = await s.get(User, uid)
    if u is None:
        raise HTTPException(404, "user not found")
    u.iac_roles = sorted(set(body.roles))
    u.session_version = (u.session_version or 0) + 1  # privilege change: revoke existing sessions
    await S.audit(s, user.username, "roles_update", target=u.username, detail={"roles": u.iac_roles}, client_ip=client_ip(request))
    return {"ok": True}


class SettingsIn(BaseModel):
    writes_enabled: bool | None = None
    sod_production: bool | None = None
    sod_all_environments: bool | None = None
    fail_fast: bool | None = None
    drift_interval_minutes: int | None = Field(None, ge=5, le=10080)
    require_full_backup_production: bool | None = None
    plan_max_age_hours: int | None = Field(None, ge=1, le=168)


@router.put("/settings")
async def put_settings(body: SettingsIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await need(user, "admin")
    data = {k: v for k, v in body.model_dump().items() if v is not None}
    out = await S.put_iac_settings(s, data, user.username)
    await S.audit(s, user.username, "settings_update", detail=data, client_ip=client_ip(request))
    ok, why = S.writes_effective(out)
    return {"settings": out, "writes_effective": ok, "writes_reason": why}


@router.get("/audit")
async def audit_log(project_id: int | None = None, page: int = Query(1, ge=1), size: int = Query(100, ge=1, le=500), verify: bool = False,
                    _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    q = select(IacAudit)
    if project_id:
        q = q.where(IacAudit.project_id == project_id)
    total = (await s.execute(select(func.count()).select_from(q.subquery()))).scalar()
    rows = (await s.execute(q.order_by(IacAudit.id.desc()).offset((page - 1) * size).limit(size))).scalars().all()
    return {"total": total, "chain": await S.verify_audit(s) if verify else None,
            "items": [{"id": a.id, "ts": iso(a.ts), "username": a.username, "action": a.action, "project_id": a.project_id, "plan_id": a.plan_id,
                       "job_id": a.job_id, "target": a.target, "detail": a.detail, "client_ip": a.client_ip, "hash": a.hash[:16]} for a in rows]}


@router.get("/schema-check")
async def schema_check(_: User = Depends(current_user)):
    """The example desired-state document parses (used by the UI's 'insert example')."""
    try:
        parse(EXAMPLE)
        return {"ok": True}
    except ConfigError as e:
        return {"ok": False, "errors": e.errors}
