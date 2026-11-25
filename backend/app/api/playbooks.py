"""APIs: Sentinel NMS → Device Access → Automation (Ansible playbook library and runs; app/playbooks).

Writing or editing a playbook needs nms.automation.execute; every saved version passes the policy check
(app/playbooks/policy.py) and starts as a draft. Approving a version needs nms.configuration.approve and a different
person than its last editor; editing clears the approval. Read-only playbooks and dry runs (--check --diff) of change
playbooks run once requested; a real run of a change playbook needs a second person's approval and
NMS_CONFIG_CHANGES_ENABLED. The runner service executes queued runs.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..access import audit as A
from ..access import rbac
from ..config import get_settings
from ..db.models import NmsPlaybook, NmsPlaybookRun, Switch, User
from ..db.pg import get_session
from ..playbooks.policy import PolicyError, check
from ..playbooks.runner import sha256
from ..products import site_allowed
from .deps import client_ip, iso

router = APIRouter(prefix="/api/nms/access/playbooks", tags=["nms-playbooks"])
P = rbac.require


class PlaybookIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field("", max_length=2000)
    content: str = Field(min_length=10, max_length=200_000)


class ContentIn(BaseModel):
    content: str = Field(min_length=1, max_length=200_000)


class RunIn(BaseModel):
    device_ids: list[int] = Field(min_length=1, max_length=2000)
    mode: str = Field("run", pattern=r"^(run|check)$")


class DecisionIn(BaseModel):
    comment: str = Field("", max_length=2000)


def _pb(p: NmsPlaybook, full: bool = False) -> dict:
    out = {"id": p.id, "name": p.name, "description": p.description, "kind": p.kind, "status": p.status, "sha256": p.sha256,
           "approved": p.status == "approved" and p.approved_sha256 == p.sha256, "created_by": p.created_by, "updated_by": p.updated_by,
           "approved_by": p.approved_by, "approved_at": iso(p.approved_at), "updated_at": iso(p.updated_at), "findings": p.findings}
    if full:
        out["content"] = p.content
    return out


def _run(r: NmsPlaybookRun, name: str = "", full: bool = False) -> dict:
    out = {"id": r.id, "playbook_id": r.playbook_id, "playbook": name, "kind": r.kind, "mode": r.mode, "status": r.status, "devices": len(r.device_ids or []),
           "requested_by": r.requested_by, "approved_by": r.approved_by, "created_at": iso(r.created_at), "started_at": iso(r.started_at),
           "finished_at": iso(r.finished_at), "error": r.error, "hosts": r.hosts}
    if full:
        out.update(output=r.output, backups=r.backups, device_ids=r.device_ids)
    return out


def _check(content: str) -> dict:
    try:
        return check(content)
    except PolicyError as e:
        raise HTTPException(422, f"playbook refused by policy: {e}")


@router.post("/validate")
async def validate(body: ContentIn, _: User = Depends(P("nms.automation.execute"))):
    try:
        return {"ok": True, **check(body.content)}
    except PolicyError as e:
        return {"ok": False, "errors": str(e).split("; ")}


@router.get("")
async def playbooks(_: User = Depends(P("nms.device.access.view")), s: AsyncSession = Depends(get_session)):
    return {"enabled_changes": get_settings().nms_config_changes_enabled,
            "items": [_pb(p) for p in (await s.execute(select(NmsPlaybook).order_by(NmsPlaybook.name))).scalars()]}


@router.get("/runs")
async def runs(_: User = Depends(P("nms.device.access.view")), s: AsyncSession = Depends(get_session)):
    names = dict((await s.execute(select(NmsPlaybook.id, NmsPlaybook.name))).all())
    rows = (await s.execute(select(NmsPlaybookRun).order_by(NmsPlaybookRun.id.desc()).limit(200))).scalars().all()
    return {"items": [_run(r, names.get(r.playbook_id, "")) for r in rows]}


@router.get("/runs/{rid}")
async def run_detail(rid: int, user: User = Depends(P("nms.device.access.view")), s: AsyncSession = Depends(get_session)):
    r = await s.get(NmsPlaybookRun, rid)
    if r is None:
        raise HTTPException(404, "run not found")
    if r.requested_by != user.username and not (rbac.has(user, "nms.device.access.audit.view") or rbac.has(user, "nms.configuration.approve")):
        raise HTTPException(404, "run not found")
    pb = await s.get(NmsPlaybook, r.playbook_id)
    return _run(r, pb.name if pb else "", full=True)


@router.get("/{pid}")
async def playbook(pid: int, _: User = Depends(P("nms.device.access.view")), s: AsyncSession = Depends(get_session)):
    p = await s.get(NmsPlaybook, pid)
    if p is None:
        raise HTTPException(404, "playbook not found")
    return _pb(p, full=True)


@router.post("", status_code=201)
async def create(body: PlaybookIn, request: Request, user: User = Depends(P("nms.automation.execute")), s: AsyncSession = Depends(get_session)):
    res = _check(body.content)
    if (await s.execute(select(NmsPlaybook).where(NmsPlaybook.name == body.name))).scalar_one_or_none():
        raise HTTPException(409, "a playbook with this name exists")
    p = NmsPlaybook(name=body.name, description=body.description, content=body.content, sha256=sha256(body.content), kind=res["kind"],
                    findings=res["findings"], status="draft", created_by=user.username, updated_by=user.username)
    s.add(p)
    await s.commit()
    await A.record(s, user.username, "playbook_create", target=p.name, detail={"kind": p.kind, "sha256": p.sha256, "modules": res["modules"]},
                   client_ip=client_ip(request))
    return _pb(p, full=True)


@router.put("/{pid}")
async def update(pid: int, body: PlaybookIn, request: Request, user: User = Depends(P("nms.automation.execute")), s: AsyncSession = Depends(get_session)):
    p = await s.get(NmsPlaybook, pid)
    if p is None:
        raise HTTPException(404, "playbook not found")
    res = _check(body.content)
    changed = sha256(body.content) != p.sha256
    p.name, p.description = body.name, body.description
    if changed:
        p.content, p.sha256, p.kind, p.findings = body.content, sha256(body.content), res["kind"], res["findings"]
        p.status, p.approved_by, p.approved_sha256, p.approved_at = "draft", "", "", None      # a new version needs a new approval
    p.updated_by = user.username
    await s.commit()
    await A.record(s, user.username, "playbook_update", target=p.name, detail={"kind": p.kind, "sha256": p.sha256, "approval_cleared": changed},
                   client_ip=client_ip(request))
    return _pb(p, full=True)


@router.post("/{pid}/runs", status_code=201)
async def request_run(pid: int, body: RunIn, request: Request, user: User = Depends(P("nms.automation.execute")), s: AsyncSession = Depends(get_session)):
    st = get_settings()
    p = await s.get(NmsPlaybook, pid)
    if p is None:
        raise HTTPException(404, "playbook not found")
    if not (p.status == "approved" and p.approved_sha256 == p.sha256):
        raise HTTPException(409, "only an approved playbook version can run")
    ids = sorted(set(body.device_ids))
    if len(ids) > st.ansible_max_devices:
        raise HTTPException(422, f"at most {st.ansible_max_devices} devices per run")
    rows = (await s.execute(select(Switch.id, Switch.site).where(Switch.id.in_(ids)))).all()
    if len(rows) != len(ids) or not all(site_allowed(user, site) for _, site in rows):
        raise HTTPException(404, "device(s) not found or outside your site scope")
    if p.kind == "change" and body.mode == "run":
        if not st.nms_config_changes_enabled:
            raise HTTPException(409, "configuration changes are disabled (NMS_CONFIG_CHANGES_ENABLED); a dry run (check) is possible")
        if not rbac.has(user, "nms.device.access.configuration"):
            raise HTTPException(403, "permission nms.device.access.configuration required for a change run")
    active = (await s.execute(select(func.count()).select_from(NmsPlaybookRun).where(NmsPlaybookRun.requested_by == user.username,
                                                                                       NmsPlaybookRun.status.in_(("queued", "running", "pending_approval"))))).scalar() or 0
    if active >= 3:
        raise HTTPException(429, "you already have 3 runs waiting or running")
    r = NmsPlaybookRun(playbook_id=p.id, playbook_sha256=p.sha256, kind=p.kind, mode=body.mode, device_ids=ids, requested_by=user.username,
                       status="pending_approval" if (p.kind == "change" and body.mode == "run") else "queued")
    s.add(r)
    await s.commit()
    await A.record(s, user.username, "playbook_run_request", target=p.name, detail={"run_id": r.id, "mode": r.mode, "kind": r.kind, "devices": len(ids)},
                   client_ip=client_ip(request))
    return _run(r, p.name)


@router.post("/{pid}/{action}")
async def decide_playbook(pid: int, action: str, body: DecisionIn, request: Request, user: User = Depends(P("nms.device.access.view")),
                          s: AsyncSession = Depends(get_session)):
    if action not in ("approve", "retire"):
        raise HTTPException(404, "unknown action")
    p = await s.get(NmsPlaybook, pid)
    if p is None:
        raise HTTPException(404, "playbook not found")
    if not rbac.has(user, "nms.configuration.approve"):
        raise HTTPException(403, "permission nms.configuration.approve required")
    if action == "approve":
        if user.username == (p.updated_by or p.created_by):
            raise HTTPException(403, "the last editor cannot approve their own playbook version")
        _check(p.content)
        p.status, p.approved_by, p.approved_sha256, p.approved_at = "approved", user.username, p.sha256, datetime.now(timezone.utc)
    else:
        p.status = "retired"
    await s.commit()
    await A.record(s, user.username, f"playbook_{action}", target=p.name, detail={"sha256": p.sha256, "comment": body.comment[:300]},
                   client_ip=client_ip(request))
    return _pb(p)


@router.post("/runs/{rid}/{action}")
async def decide_run(rid: int, action: str, body: DecisionIn, request: Request, user: User = Depends(P("nms.device.access.view")),
                     s: AsyncSession = Depends(get_session)):
    if action not in ("approve", "reject", "cancel"):
        raise HTTPException(404, "unknown action")
    r = await s.get(NmsPlaybookRun, rid)
    if r is None:
        raise HTTPException(404, "run not found")
    if action == "cancel":
        if r.requested_by != user.username and not rbac.has(user, "nms.device.access.session.terminate"):
            raise HTTPException(403, "only the requester or a session administrator can cancel")
        if r.status in ("pending_approval", "queued"):
            r.status = "cancelled"
        elif r.status == "running":
            r.cancel_requested = True
        else:
            raise HTTPException(409, f"a {r.status} run cannot be cancelled")
    else:
        if r.status != "pending_approval":
            raise HTTPException(409, f"the run is {r.status}, not waiting for approval")
        if not rbac.has(user, "nms.configuration.approve"):
            raise HTTPException(403, "permission nms.configuration.approve required")
        if user.username == r.requested_by:
            raise HTTPException(403, "the requester cannot approve their own change run")
        r.status = "queued" if action == "approve" else "rejected"
        r.approved_by, r.approved_at = user.username, datetime.now(timezone.utc)
    await s.commit()
    await A.record(s, user.username, f"playbook_run_{action}", detail={"run_id": rid, "comment": body.comment[:300]}, client_ip=client_ip(request))
    return _run(r)
