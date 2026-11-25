"""APIs: Sentinel NMS → Device Access (served by the access gateway service; see app/access/__init__.py).

Every route checks an nms.* permission (app/access/rbac.py) and, where a device is involved, the user's site scope.
No route takes a host, a port or a command text for a device: devices are addressed by id, commands by template id.
"""
from __future__ import annotations

import csv
import io
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..access import audit as A
from ..access import changes as C
from ..access import diagnostics as DG
from ..access import rbac, terminal, vault
from ..access.commands import LEVELS, PLATFORMS, SIMULATED, TEMPLATES, classify, platform_of, templates_for
from ..access.gateway import ACTIVE_STATES, PORTS, AccessError, check_limits, expire_pending, resolve, tcp_probe
from ..config import get_settings
from ..db.models import (ConsolePort, ConsoleServer, DeviceSshCredential, NmsAccessAudit, NmsAccessCommand, NmsAccessRecording, NmsAccessSession, NmsChangeRequest,
                         NmsCredentialAssignment, NmsDiagJob, NmsDiagResult, Switch, User)
from ..db.pg import get_session, session_factory
from ..products import site_allowed
from .deps import client_ip, csv_safe, iso, require_admin

router = APIRouter(prefix="/api/nms/access", tags=["nms-access"])
P = rbac.require


def _err(e: AccessError) -> HTTPException:
    return HTTPException(e.status, e.message)


async def _device(s: AsyncSession, user: User, sid: int) -> Switch:
    sw = await s.get(Switch, sid)
    if sw is None or not site_allowed(user, sw.site):
        raise HTTPException(404, "device not found")
    return sw


# ------------------------------------------------------------------ identity, library
@router.get("/me")
async def me(user: User = Depends(P("nms.device.access.view"))):
    st = get_settings()
    return {"username": user.username, "roles": rbac.roles_of(user), "permissions": sorted(rbac.permissions_of(user)),
            "terminal_enabled": st.access_terminal_enabled, "changes_enabled": st.nms_config_changes_enabled, "recording": st.access_recording,
            "limits": {"sessions": st.access_max_sessions, "per_user": st.access_max_sessions_per_user, "per_device": st.access_max_sessions_per_device,
                       "idle_seconds": st.access_idle_timeout_seconds, "max_seconds": st.access_max_session_seconds}}


@router.get("/library")
async def library(_: User = Depends(P("nms.device.access.view"))):
    return {"levels": LEVELS,
            "platforms": [{"id": k, **v, "simulated_tests": k in SIMULATED, "lab_validated": False} for k, v in PLATFORMS.items()],
            "templates": [{"id": t.id, "platform": t.platform, "title": t.title, "category": t.category, "commands": list(t.commands),
                           "risk": max((classify(c)[0] for c in t.commands), key=LEVELS.index), "note": t.note} for t in TEMPLATES]}


class ClassifyIn(BaseModel):
    command: str = Field(max_length=1000)


@router.post("/classify")
async def classify_command(body: ClassifyIn, _: User = Depends(P("nms.device.access.view"))):
    """What the gateway would decide for a command (no device is contacted)."""
    r, why = classify(body.command)
    return {"risk": r, "reason": why}


# ------------------------------------------------------------------ devices
def _dev_row(sw: Switch, sessions: int, last: datetime | None) -> dict:
    plat = platform_of(sw)
    return {"id": sw.id, "name": sw.name, "address": sw.address, "vendor": sw.vendor_override or sw.vendor, "model": sw.model,
            "family": sw.family_override or sw.family or sw.product_line, "os": sw.os, "firmware": sw.firmware, "site": sw.site,
            "role": sw.role, "device_type": sw.device_type, "state": sw.state, "platform": plat,
            "platform_label": PLATFORMS[plat]["label"] if plat else None, "platform_override": sw.access_platform or "",
            "ssh_credential": bool(sw.ssh_credential_id), "host_key_pinned": bool(sw.ssh_host_key),
            "active_sessions": sessions, "last_access": iso(last)}


@router.get("/devices")
async def devices(q: str | None = Query(None, max_length=100), site: str | None = Query(None, max_length=128),
                  vendor: str | None = Query(None, max_length=16), limit: int = Query(200, ge=1, le=2000), offset: int = Query(0, ge=0),
                  user: User = Depends(P("nms.device.access.view")), s: AsyncSession = Depends(get_session)):
    stmt = select(Switch).order_by(Switch.name)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(Switch.name.ilike(like), Switch.address.ilike(like), Switch.model.ilike(like)))
    if site:
        stmt = stmt.where(Switch.site == site)
    if vendor:
        stmt = stmt.where(or_(Switch.vendor == vendor, Switch.vendor_override == vendor))
    sws = [x for x in (await s.execute(stmt)).scalars() if site_allowed(user, x.site)]
    total = len(sws)
    sws = sws[offset:offset + limit]
    ids = [x.id for x in sws]
    act = dict((await s.execute(select(NmsAccessSession.switch_id, func.count()).where(NmsAccessSession.state.in_(ACTIVE_STATES),
                                NmsAccessSession.switch_id.in_(ids)).group_by(NmsAccessSession.switch_id))).all()) if ids else {}
    last = dict((await s.execute(select(NmsAccessSession.switch_id, func.max(NmsAccessSession.connected_at)).where(
        NmsAccessSession.switch_id.in_(ids)).group_by(NmsAccessSession.switch_id))).all()) if ids else {}
    return {"total": total, "items": [_dev_row(x, act.get(x.id, 0), last.get(x.id)) for x in sws]}


@router.get("/devices/{sid}")
async def device(sid: int, user: User = Depends(P("nms.device.access.view")), s: AsyncSession = Depends(get_session)):
    sw = await _device(s, user, sid)
    act = (await s.execute(select(NmsAccessSession).where(NmsAccessSession.switch_id == sid, NmsAccessSession.state.in_(ACTIVE_STATES))
                           .order_by(NmsAccessSession.started_at.desc()))).scalars().all()
    hist = (await s.execute(select(NmsAccessSession).where(NmsAccessSession.switch_id == sid).order_by(NmsAccessSession.started_at.desc()).limit(20))).scalars().all()
    ok = (await s.execute(select(NmsAccessSession).where(NmsAccessSession.switch_id == sid, NmsAccessSession.connected_at.is_not(None))
                          .order_by(NmsAccessSession.connected_at.desc()).limit(1))).scalar_one_or_none()
    cred, how = await vault.resolve(s, sw, "ssh")
    https_cred, https_how = await vault.resolve(s, sw, "https")
    perms = rbac.permissions_of(user)
    plat = platform_of(sw)
    actions = {
        "ssh": "nms.device.access.ssh" in perms and get_settings().access_terminal_enabled and cred is not None,
        "https": "nms.device.access.https" in perms,
        "diagnostics": "nms.device.access.diagnostics" in perms and plat is not None and cred is not None,
        "test": "nms.device.access.diagnostics" in perms,
        "history": True,
        "credentials": "nms.device.access.credential.manage" in perms,
        "change": "nms.device.access.configuration" in perms and plat in C.PROCEDURES,
        "telnet": "nms.device.access.ssh" in perms and get_settings().access_telnet_enabled and sw.access_telnet and cred is not None,
        "netconf": "nms.device.access.diagnostics" in perms,
        "restconf": "nms.device.access.diagnostics" in perms,
    }
    ports = (await s.execute(select(ConsolePort).where(ConsolePort.switch_id == sid))).scalars().all()
    servers = {x.id: x for x in (await s.execute(select(ConsoleServer).where(ConsoleServer.id.in_([p.server_id for p in ports] or [0])))).scalars()}
    consoles = [{"id": p.id, "server": servers[p.server_id].name, "kind": servers[p.server_id].kind, "method": servers[p.server_id].method,
                 "port": p.port, "label": p.label, "usable": "nms.device.access.ssh" in perms and (servers[p.server_id].method == "ssh" or get_settings().access_telnet_enabled)}
                for p in ports if p.server_id in servers]
    return {**_dev_row(sw, len(act), ok.connected_at if ok else None),
            "protocols": {"ssh": True, "https": True, "netconf": plat == "junos" or plat == "cisco_ios", "snmp": bool(sw.credential_id)},
            "snmp": {"state": sw.state, "last_success_at": iso(sw.last_success_at), "error": sw.last_error[:300] if sw.state != "up" else ""},
            "credential": {"ssh": {"id": cred.id, "name": cred.name, "username": cred.username, "via": how} if cred else None,
                           "https": {"id": https_cred.id, "name": https_cred.name, "via": https_how} if https_cred else None},
            "last_latency_ms": ok.latency_ms if ok else None,
            "actions": actions, "consoles": consoles, "telnet_enabled_device": sw.access_telnet, "https_cert_pinned": bool(sw.https_cert_sha256),
            "templates": [{"id": t.id, "title": t.title, "category": t.category} for t in templates_for(plat)],
            "sessions": [_sess(x) for x in act], "history": [_sess(x) for x in hist]}


@router.post("/devices/{sid}/test")
async def test_connectivity(sid: int, request: Request, user: User = Depends(P("nms.device.access.diagnostics")),
                            s: AsyncSession = Depends(get_session)):
    """TCP reachability of the management services (fixed ports) plus the SNMP state from the latest poll."""
    try:
        t = await resolve(s, user, sid, "ssh")
    except AccessError as e:
        raise _err(e)
    import asyncio
    names = ("ssh", "https", "netconf")
    res = await asyncio.gather(*(tcp_probe(t.host, PORTS[p], 3.0) for p in names))
    out = {p: r for p, r in zip(names, res)}
    out["snmp"] = {"ok": t.switch.state == "up", "state": t.switch.state, "last_success_at": iso(t.switch.last_success_at)}
    await A.record(s, user.username, "connectivity_test", switch_id=sid, target=t.switch.name,
                   detail={k: v.get("ok") for k, v in out.items()}, client_ip=client_ip(request))
    return out


class SessionIn(BaseModel):
    mode: str = Field("read_only", pattern=r"^(read_only|change)$")
    change_id: int | None = None
    protocol: str = Field("ssh", pattern=r"^(ssh|telnet|console)$")
    console_port_id: int | None = None
    cols: int = Field(120, ge=20, le=400)
    rows: int = Field(32, ge=5, le=200)


@router.post("/devices/{sid}/sessions", status_code=201)
async def open_session(sid: int, body: SessionIn, request: Request, user: User = Depends(P("nms.device.access.ssh")),
                       s: AsyncSession = Depends(get_session)):
    st = get_settings()
    if not st.access_terminal_enabled:
        raise HTTPException(409, "the browser terminal is disabled on this installation")
    try:
        t = await resolve(s, user, sid, "ssh")
        await check_limits(s, user, sid)
    except AccessError as e:
        await A.record(s, user.username, "terminal_open", switch_id=sid, detail={"refused": e.message}, client_ip=client_ip(request), success=False)
        raise _err(e)
    if body.mode == "change":
        if not st.nms_config_changes_enabled:
            raise HTTPException(409, "configuration changes are disabled on this installation (NMS_CONFIG_CHANGES_ENABLED)")
        if not rbac.has(user, "nms.device.access.configuration"):
            raise HTTPException(403, "permission nms.device.access.configuration required for a change session")
        cr = await s.get(NmsChangeRequest, body.change_id) if body.change_id else None
        if cr is None or cr.switch_id != sid or cr.status != "approved":
            raise HTTPException(409, "a change session needs an approved change request for this device")
        n = datetime.now(timezone.utc)
        if (cr.window_start and n < C._aware(cr.window_start)) or (cr.window_end and n > C._aware(cr.window_end)):
            raise HTTPException(409, "outside the approved change window")
    cred = None
    if body.protocol == "console":
        cp = await s.get(ConsolePort, body.console_port_id) if body.console_port_id else None
        srv = await s.get(ConsoleServer, cp.server_id) if cp else None
        if cp is None or cp.switch_id != sid or srv is None:
            raise HTTPException(404, "console port not found for this device")
        if srv.credential_id is None:
            raise HTTPException(409, "the console server has no credential")
        if srv.method == "telnet" and not st.access_telnet_enabled:
            raise HTTPException(409, "Telnet is disabled on this installation (ACCESS_TELNET_ENABLED)")
    else:
        if body.protocol == "telnet" and not (st.access_telnet_enabled and t.switch.access_telnet):
            raise HTTPException(409, "Telnet is not enabled for this device (ACCESS_TELNET_ENABLED and the device's Telnet switch)")
        cred, _ = await vault.resolve(s, t.switch, "ssh")
        if cred is None:
            raise HTTPException(409, "no SSH credential is assigned to this device (Credential Vault)")
    ticket = secrets.token_urlsafe(32)
    row = NmsAccessSession(id=str(uuid.uuid4()), user_id=user.id, username=user.username, switch_id=sid, device_name=t.switch.name,
                           device_address=t.host, protocol=body.protocol, mode=body.mode, change_id=body.change_id if body.mode == "change" else None,
                           credential_id=cred.id if cred else None, console_port_id=body.console_port_id if body.protocol == "console" else None, client_ip=client_ip(request), ticket_hash=terminal.ticket_hash(ticket),
                           ticket_expires_at=datetime.now(timezone.utc) + timedelta(seconds=st.access_ticket_seconds), state="pending",
                           recording=st.access_recording if st.access_recording in ("off", "commands", "full") else "commands")
    s.add(row)
    await s.commit()
    await A.record(s, user.username, "terminal_open", switch_id=sid, session_id=row.id, target=t.switch.name,
                   detail={"mode": body.mode, "change_id": row.change_id, "protocol": body.protocol, "console_port_id": row.console_port_id},
                   client_ip=client_ip(request))
    return {"session_id": row.id, "ticket": ticket, "ws_path": "/api/nms/access/ws", "expires_in": st.access_ticket_seconds,
            "recording": row.recording}


@router.websocket("/ws")
async def ws(websocket: WebSocket):
    await terminal.handle(websocket)


@router.post("/devices/{sid}/web")
async def open_web(sid: int, request: Request, user: User = Depends(P("nms.device.access.https")), s: AsyncSession = Depends(get_session)):
    """Web management: audited, returns the device's HTTPS address. The browser connects itself (no proxy; the user
    signs in to the device), so this works only where the engineer's workstation can reach the management network."""
    try:
        t = await resolve(s, user, sid, "https")
    except AccessError as e:
        raise _err(e)
    host = f"[{t.host}]" if ":" in t.host else t.host
    await A.record(s, user.username, "web_open", switch_id=sid, target=t.switch.name, detail={"url": f"https://{host}/"}, client_ip=client_ip(request))
    return {"url": f"https://{host}/", "note": "opens directly from your browser; Sentinel does not proxy or sign in to the web UI"}


class PlatformIn(BaseModel):
    platform: str = Field("", max_length=24)


@router.put("/devices/{sid}/platform")
async def set_platform(sid: int, body: PlatformIn, request: Request, user: User = Depends(P("nms.device.manage")), s: AsyncSession = Depends(get_session)):
    sw = await _device(s, user, sid)
    if body.platform and body.platform not in PLATFORMS:
        raise HTTPException(422, f"unknown platform; one of {', '.join(PLATFORMS)}")
    sw.access_platform = body.platform
    await s.commit()
    await A.record(s, user.username, "device_platform", switch_id=sid, target=sw.name, detail={"platform": body.platform or "auto"}, client_ip=client_ip(request))
    return {"platform": platform_of(sw)}


class DeviceCredIn(BaseModel):
    ssh_credential_id: int | None = None


@router.put("/devices/{sid}/credential")
async def set_device_credential(sid: int, body: DeviceCredIn, request: Request, user: User = Depends(P("nms.device.access.credential.manage")),
                                s: AsyncSession = Depends(get_session)):
    sw = await _device(s, user, sid)
    if body.ssh_credential_id is not None:
        c = await s.get(DeviceSshCredential, body.ssh_credential_id)
        if c is None or (c.kind or "ssh") != "ssh":
            raise HTTPException(404, "SSH credential not found")
    sw.ssh_credential_id = body.ssh_credential_id
    await s.commit()
    await A.record(s, user.username, "device_credential", switch_id=sid, target=sw.name, detail={"ssh_credential_id": body.ssh_credential_id},
                   client_ip=client_ip(request))
    return {"ok": True}


# ------------------------------------------------------------------ sessions
def _sess(r: NmsAccessSession) -> dict:
    return {"id": r.id, "username": r.username, "switch_id": r.switch_id, "device": r.device_name, "address": r.device_address,
            "protocol": r.protocol, "mode": r.mode, "change_id": r.change_id, "client_ip": r.client_ip, "state": r.state, "result": r.result,
            "termination_reason": r.termination_reason, "latency_ms": r.latency_ms, "bytes_in": r.bytes_in, "bytes_out": r.bytes_out,
            "commands": r.commands, "blocked": r.blocked, "recording": r.recording, "started_at": iso(r.started_at),
            "connected_at": iso(r.connected_at), "ended_at": iso(r.ended_at), "last_activity_at": iso(r.last_activity_at)}


@router.get("/sessions")
async def sessions(state: str | None = Query(None, pattern=r"^(active|ended)$"), switch_id: int | None = None,
                   username: str | None = Query(None, max_length=64), limit: int = Query(100, ge=1, le=1000),
                   user: User = Depends(P("nms.device.access.view")), s: AsyncSession = Depends(get_session)):
    """Everyone sees their own sessions; auditors and session administrators see all (within their site scope)."""
    await expire_pending(s)
    stmt = select(NmsAccessSession).order_by(NmsAccessSession.started_at.desc()).limit(limit)
    see_all = rbac.has(user, "nms.device.access.audit.view") or rbac.has(user, "nms.device.access.session.terminate")
    if not see_all:
        stmt = stmt.where(NmsAccessSession.user_id == user.id)
    elif username:
        stmt = stmt.where(NmsAccessSession.username == username)
    if state == "active":
        stmt = stmt.where(NmsAccessSession.state.in_(ACTIVE_STATES))
    elif state == "ended":
        stmt = stmt.where(NmsAccessSession.state.not_in(ACTIVE_STATES))
    if switch_id:
        stmt = stmt.where(NmsAccessSession.switch_id == switch_id)
    rows = (await s.execute(stmt)).scalars().all()
    sites = dict((await s.execute(select(Switch.id, Switch.site).where(Switch.id.in_({r.switch_id for r in rows if r.switch_id})))).all()) if rows else {}
    return {"items": [_sess(r) for r in rows if r.user_id == user.id or site_allowed(user, sites.get(r.switch_id))]}


async def _visible_session(s: AsyncSession, user: User, sid: str) -> NmsAccessSession:
    r = await s.get(NmsAccessSession, sid)
    if r is None:
        raise HTTPException(404, "session not found")
    if r.user_id != user.id:
        sw = await s.get(Switch, r.switch_id) if r.switch_id else None
        if not rbac.has(user, "nms.device.access.audit.view") or not site_allowed(user, sw.site if sw else None):
            raise HTTPException(404, "session not found")
    return r


@router.get("/sessions/{sid}")
async def session_detail(sid: str, user: User = Depends(P("nms.device.access.view")), s: AsyncSession = Depends(get_session)):
    r = await _visible_session(s, user, sid)
    cmds = (await s.execute(select(NmsAccessCommand).where(NmsAccessCommand.session_id == sid).order_by(NmsAccessCommand.id).limit(5000))).scalars().all()
    rec = await s.get(NmsAccessRecording, sid)
    return {**_sess(r), "has_recording": rec is not None,
            "command_log": [{"ts": iso(c.ts), "command": c.command, "risk": c.risk, "allowed": c.allowed, "reason": c.reason} for c in cmds]}


@router.get("/sessions/{sid}/recording")
async def session_recording(sid: str, request: Request, user: User = Depends(P("nms.device.access.audit.view")), s: AsyncSession = Depends(get_session)):
    r = await _visible_session(s, user, sid)
    rec = await s.get(NmsAccessRecording, sid)
    if rec is None:
        raise HTTPException(404, "no recording for this session")
    await A.record(s, user.username, "recording_view", switch_id=r.switch_id, session_id=sid, target=r.device_name, client_ip=client_ip(request))
    return PlainTextResponse(rec.text, headers={"Content-Disposition": f'attachment; filename="session-{sid}.txt"'})


@router.post("/sessions/{sid}/terminate")
async def terminate(sid: str, request: Request, user: User = Depends(P("nms.device.access.view")), s: AsyncSession = Depends(get_session)):
    r = await s.get(NmsAccessSession, sid)
    if r is None:
        raise HTTPException(404, "session not found")
    if r.user_id != user.id:
        sw = await s.get(Switch, r.switch_id) if r.switch_id else None
        if not rbac.has(user, "nms.device.access.session.terminate") or not site_allowed(user, sw.site if sw else None):
            raise HTTPException(403, "permission nms.device.access.session.terminate required")
    if r.state not in ACTIVE_STATES:
        return {"ok": True, "state": r.state}
    r.terminate_requested_by = user.username
    if r.state == "pending":
        r.state, r.ended_at, r.termination_reason, r.ticket_hash = "terminated", datetime.now(timezone.utc), f"terminated by {user.username}"[:64], ""
    await s.commit()
    terminal.stop_local(sid, f"terminated by {user.username}")
    await A.record(s, user.username, "terminal_terminate", switch_id=r.switch_id, session_id=sid, target=r.device_name,
                   detail={"owner": r.username}, client_ip=client_ip(request))
    return {"ok": True, "state": "terminating"}


# ------------------------------------------------------------------ diagnostics
class DiagIn(BaseModel):
    templates: list[str] = Field(default_factory=list, max_length=50)
    categories: list[str] = Field(default_factory=list, max_length=10)


def _job(j: NmsDiagJob) -> dict:
    return {"id": j.id, "username": j.username, "kind": j.kind, "templates": j.templates, "status": j.status, "total": j.total,
            "completed": j.completed, "failed": j.failed, "concurrency": j.concurrency, "timeout_seconds": j.timeout_seconds,
            "cancel_requested": j.cancel_requested, "created_at": iso(j.created_at), "started_at": iso(j.started_at), "finished_at": iso(j.finished_at)}


def _result(r: NmsDiagResult, full: bool = True) -> dict:
    outs = r.outputs or []
    if not full:
        outs = [{k: v for k, v in o.items() if k != "output"} | {"lines": (o.get("output") or "").count("\n") + 1} for o in outs]
    return {"switch_id": r.switch_id, "device": r.device_name, "status": r.status, "error": r.error, "outputs": outs,
            "duration_ms": r.duration_ms, "finished_at": iso(r.finished_at)}


@router.post("/devices/{sid}/diagnostics")
async def run_diagnostics(sid: int, body: DiagIn, request: Request, user: User = Depends(P("nms.device.access.diagnostics")),
                          s: AsyncSession = Depends(get_session)):
    await _device(s, user, sid)
    try:
        DG.validate_request(body.templates, body.categories)
    except AccessError as e:
        raise _err(e)
    job_id = await DG.create_job(user, [sid], body.templates, body.categories, kind="single")
    async with session_factory()() as s2:
        j = await s2.get(NmsDiagJob, job_id)
        j.status, j.started_at = "running", datetime.now(timezone.utc)
        await s2.commit()
    r = await DG.run_device(user, sid, body.templates, body.categories, job_id, float(get_settings().access_command_timeout_seconds) * 4,
                            client_ip=client_ip(request))
    s.expire_all()
    j = await s.get(NmsDiagJob, job_id)
    j.status, j.completed, j.failed, j.finished_at = "done", 1, int(r["status"] == "failed"), datetime.now(timezone.utc)
    await s.commit()
    res = (await s.execute(select(NmsDiagResult).where(NmsDiagResult.job_id == job_id))).scalar_one()
    return {"job": _job(j), "result": _result(res)}


class BulkIn(DiagIn):
    device_ids: list[int] = Field(min_length=1, max_length=2000)
    concurrency: int | None = Field(None, ge=1, le=50)
    timeout_seconds: int | None = Field(None, ge=10, le=900)


@router.post("/bulk", status_code=202)
async def bulk(body: BulkIn, request: Request, user: User = Depends(P("nms.device.access.diagnostics")), s: AsyncSession = Depends(get_session)):
    if not rbac.has(user, "nms.automation.execute"):
        raise HTTPException(403, "permission nms.automation.execute required for bulk diagnostics")
    st = get_settings()
    ids = sorted(set(body.device_ids))
    if len(ids) > st.access_bulk_max_devices:
        raise HTTPException(422, f"at most {st.access_bulk_max_devices} devices per bulk job")
    try:
        DG.validate_request(body.templates, body.categories)
    except AccessError as e:
        raise _err(e)
    rows = (await s.execute(select(Switch.id, Switch.site).where(Switch.id.in_(ids)))).all()
    allowed = [i for i, site in rows if site_allowed(user, site)]
    if len(allowed) != len(ids):
        raise HTTPException(404, f"{len(ids) - len(allowed)} device(s) not found or outside your site scope")
    running = (await s.execute(select(func.count()).select_from(NmsDiagJob).where(NmsDiagJob.username == user.username,
                                                                                    NmsDiagJob.status.in_(("queued", "running")), NmsDiagJob.kind == "bulk"))).scalar() or 0
    if running >= 3:
        raise HTTPException(429, "you already have 3 bulk jobs running")
    job_id = await DG.create_job(user, ids, body.templates, body.categories, kind="bulk", concurrency=body.concurrency, timeout=body.timeout_seconds)
    await A.record(s, user.username, "bulk_diagnostics", target=f"{len(ids)} devices",
                   detail={"job_id": job_id, "templates": body.templates, "categories": body.categories}, client_ip=client_ip(request))
    DG.start_job(job_id, user, body.templates, body.categories, client_ip=client_ip(request))
    return {"job_id": job_id}


@router.get("/jobs")
async def jobs(kind: str | None = Query(None, pattern=r"^(single|bulk)$"), limit: int = Query(50, ge=1, le=500),
               user: User = Depends(P("nms.device.access.diagnostics")), s: AsyncSession = Depends(get_session)):
    stmt = select(NmsDiagJob).order_by(NmsDiagJob.id.desc()).limit(limit)
    if not rbac.has(user, "nms.device.access.audit.view"):
        stmt = stmt.where(NmsDiagJob.username == user.username)
    if kind:
        stmt = stmt.where(NmsDiagJob.kind == kind)
    return {"items": [_job(j) for j in (await s.execute(stmt)).scalars()]}


async def _visible_job(s: AsyncSession, user: User, jid: int) -> NmsDiagJob:
    j = await s.get(NmsDiagJob, jid)
    if j is None or (j.username != user.username and not rbac.has(user, "nms.device.access.audit.view")):
        raise HTTPException(404, "job not found")
    return j


@router.get("/jobs/{jid}")
async def job(jid: int, full: bool = False, user: User = Depends(P("nms.device.access.diagnostics")), s: AsyncSession = Depends(get_session)):
    j = await _visible_job(s, user, jid)
    res = (await s.execute(select(NmsDiagResult).where(NmsDiagResult.job_id == jid).order_by(NmsDiagResult.device_name))).scalars().all()
    return {"job": _job(j), "results": [_result(r, full) for r in res]}


@router.get("/jobs/{jid}/results/{switch_id}")
async def job_result(jid: int, switch_id: int, user: User = Depends(P("nms.device.access.diagnostics")), s: AsyncSession = Depends(get_session)):
    await _visible_job(s, user, jid)
    r = (await s.execute(select(NmsDiagResult).where(NmsDiagResult.job_id == jid, NmsDiagResult.switch_id == switch_id))).scalar_one_or_none()
    if r is None:
        raise HTTPException(404, "result not found")
    return _result(r)


@router.post("/jobs/{jid}/cancel")
async def cancel(jid: int, request: Request, user: User = Depends(P("nms.device.access.diagnostics")), s: AsyncSession = Depends(get_session)):
    j = await _visible_job(s, user, jid)
    if j.username != user.username and not rbac.has(user, "nms.device.access.session.terminate"):
        raise HTTPException(403, "only the job's owner or a session administrator can cancel it")
    ok = await DG.cancel_job(jid)
    await A.record(s, user.username, "bulk_cancel", detail={"job_id": jid, "was_running": ok}, client_ip=client_ip(request))
    return {"ok": ok}


@router.get("/jobs/{jid}/export")
async def export_job(jid: int, user: User = Depends(P("nms.device.access.diagnostics")), s: AsyncSession = Depends(get_session)):
    j = await _visible_job(s, user, jid)
    res = (await s.execute(select(NmsDiagResult).where(NmsDiagResult.job_id == jid).order_by(NmsDiagResult.device_name))).scalars().all()
    parts = [f"# Sentinel NMS diagnostics job {j.id} by {j.username}, {iso(j.created_at)}, status {j.status}\n"]
    for r in res:
        parts.append(f"\n===== {r.device_name} (#{r.switch_id}): {r.status} {r.error}\n")
        for o in r.outputs or []:
            parts.append(f"\n--- {o['command']} [{o['status']}, {o['ms']} ms]\n{o.get('output', '')}\n")
    return PlainTextResponse("".join(parts), headers={"Content-Disposition": f'attachment; filename="diagnostics-{jid}.txt"'})


# ------------------------------------------------------------------ credential vault
class VaultIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    kind: str = Field("ssh", pattern=r"^(ssh|https|api_token|netconf)$")
    username: str = Field("", max_length=64)
    password: str = Field("", max_length=256)
    private_key: str = Field("", max_length=16384)
    token: str = Field("", max_length=4096)
    client_id: str = Field("", max_length=256)
    client_secret: str = Field("", max_length=1024)
    refresh_token: str = Field("", max_length=4096)
    description: str = Field("", max_length=1000)
    owner: str = Field("", max_length=64)


class AssignIn(BaseModel):
    kind: str = Field("ssh", pattern=r"^(ssh|https|api_token|netconf)$")
    site: str = Field("", max_length=128)
    role: str = Field("", max_length=32)
    vendor: str = Field("", max_length=16)


def _secret_values(body: VaultIn) -> dict:
    if body.private_key:
        import asyncssh
        try:
            asyncssh.import_private_key(body.private_key)
        except Exception:
            raise HTTPException(422, "the private key could not be read (OpenSSH or PEM, without a passphrase)")
    return {"password": body.password, "private_key": body.private_key, "token": body.token, "client_id": body.client_id,
            "client_secret": body.client_secret, "refresh_token": body.refresh_token}


@router.get("/vault")
async def vault_list(user: User = Depends(P("nms.device.access.credential.manage")), s: AsyncSession = Depends(get_session)):
    used = dict((await s.execute(select(Switch.ssh_credential_id, func.count()).where(Switch.ssh_credential_id.is_not(None)).group_by(Switch.ssh_credential_id))).all())
    asg = (await s.execute(select(NmsCredentialAssignment).order_by(NmsCredentialAssignment.id))).scalars().all()
    groups: dict[int, int] = {}
    for a in asg:
        groups[a.credential_id] = groups.get(a.credential_id, 0) + 1
    creds = (await s.execute(select(DeviceSshCredential).order_by(DeviceSshCredential.name))).scalars().all()
    return {"kinds": vault.KINDS, "items": [vault.describe(c, used.get(c.id, 0), groups.get(c.id, 0)) for c in creds],
            "assignments": [{"id": a.id, "credential_id": a.credential_id, "kind": a.kind, "site": a.site, "role": a.role, "vendor": a.vendor,
                             "created_by": a.created_by, "created_at": iso(a.created_at)} for a in asg]}


@router.post("/vault", status_code=201)
async def vault_create(body: VaultIn, request: Request, user: User = Depends(P("nms.device.access.credential.manage")), s: AsyncSession = Depends(get_session)):
    vals = _secret_values(body)
    if not any(vals[f] for f in vault.FIELDS[body.kind][:1 if body.kind == "api_token" else None]) and not (body.kind == "api_token" and vals["refresh_token"]):
        raise HTTPException(422, f"a {body.kind} credential needs: {' or '.join(vault.FIELDS[body.kind])}")
    if body.kind in ("ssh", "https", "netconf") and not body.username:
        raise HTTPException(422, "a username is required")
    if (await s.execute(select(DeviceSshCredential).where(DeviceSshCredential.name == body.name))).scalar_one_or_none():
        raise HTTPException(409, "a credential with this name exists")
    c = DeviceSshCredential(name=body.name, kind=body.kind, username=body.username, secret_ciphertext=vault.seal(body.kind, vals),
                            description=body.description, owner=body.owner or user.username, created_by=user.username,
                            rotated_at=datetime.now(timezone.utc))
    s.add(c)
    await s.commit()
    await A.record(s, user.username, "vault_create", target=c.name, detail={"kind": c.kind}, client_ip=client_ip(request))
    return vault.describe(c)


@router.put("/vault/{cid}")
async def vault_update(cid: int, body: VaultIn, request: Request, user: User = Depends(P("nms.device.access.credential.manage")), s: AsyncSession = Depends(get_session)):
    c = await s.get(DeviceSshCredential, cid)
    if c is None:
        raise HTTPException(404, "credential not found")
    if body.kind != (c.kind or "ssh"):
        raise HTTPException(422, "the kind of a credential cannot change; create a new one")
    vals = _secret_values(body)
    c.name, c.username, c.description, c.owner = body.name, body.username, body.description, body.owner or c.owner
    rotated = any(vals[f] for f in vault.FIELDS[c.kind or "ssh"])
    if rotated:                     # empty secret fields keep the stored secret
        c.secret_ciphertext = vault.seal(c.kind or "ssh", vals)
        vault.rotated(c)
    await s.commit()
    await A.record(s, user.username, "vault_rotate" if rotated else "vault_update", target=c.name, detail={"kind": c.kind}, client_ip=client_ip(request))
    return vault.describe(c)


@router.delete("/vault/{cid}")
async def vault_delete(cid: int, request: Request, user: User = Depends(P("nms.device.access.credential.manage")), s: AsyncSession = Depends(get_session)):
    c = await s.get(DeviceSshCredential, cid)
    if c is None:
        raise HTTPException(404, "credential not found")
    n = (await s.execute(select(func.count()).select_from(Switch).where(Switch.ssh_credential_id == cid))).scalar() or 0
    if n:
        raise HTTPException(409, f"{n} device(s) use this credential; reassign them first")
    await s.delete(c)
    await s.commit()
    await A.record(s, user.username, "vault_delete", target=c.name, client_ip=client_ip(request))
    return {"ok": True}


@router.post("/vault/{cid}/assignments", status_code=201)
async def vault_assign(cid: int, body: AssignIn, request: Request, user: User = Depends(P("nms.device.access.credential.manage")), s: AsyncSession = Depends(get_session)):
    c = await s.get(DeviceSshCredential, cid)
    if c is None:
        raise HTTPException(404, "credential not found")
    if (c.kind or "ssh") != body.kind:
        raise HTTPException(422, f"this is a {c.kind} credential")
    a = NmsCredentialAssignment(credential_id=cid, kind=body.kind, site=body.site.strip(), role=body.role.strip(), vendor=body.vendor.strip().lower(),
                                created_by=user.username)
    s.add(a)
    await s.commit()
    await A.record(s, user.username, "vault_assign", target=c.name, detail={"kind": a.kind, "site": a.site, "role": a.role, "vendor": a.vendor},
                   client_ip=client_ip(request))
    return {"id": a.id}


@router.delete("/vault/assignments/{aid}")
async def vault_unassign(aid: int, request: Request, user: User = Depends(P("nms.device.access.credential.manage")), s: AsyncSession = Depends(get_session)):
    a = await s.get(NmsCredentialAssignment, aid)
    if a is None:
        raise HTTPException(404, "assignment not found")
    await s.delete(a)
    await s.commit()
    await A.record(s, user.username, "vault_unassign", detail={"assignment": aid}, client_ip=client_ip(request))
    return {"ok": True}


# ------------------------------------------------------------------ roles
class RolesIn(BaseModel):
    roles: list[str] = Field(max_length=7)


@router.get("/roles")
async def roles(_: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    users = (await s.execute(select(User).order_by(User.username))).scalars().all()
    return {"roles": [{"id": k, "label": v["label"], "permissions": sorted(v["permissions"])} for k, v in rbac.ROLES.items()],
            "permissions": list(rbac.PERMISSIONS),
            "users": [{"id": u.id, "username": u.username, "role": u.role, "products": u.products or [], "sites": u.sites or [],
                       "nms_roles": rbac.roles_of(u), "permissions": sorted(rbac.permissions_of(u))} for u in users]}


@router.put("/roles/{uid}")
async def set_roles(uid: int, body: RolesIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    try:
        new = rbac.validate_roles(body.roles)
    except ValueError as e:
        raise HTTPException(422, str(e))
    u = await s.get(User, uid)
    if u is None:
        raise HTTPException(404, "user not found")
    old = sorted(u.nms_roles or [])
    u.nms_roles = new
    u.session_version = (u.session_version or 0) + 1      # privilege change: revoke the user's sessions (and open terminals)
    await s.commit()
    await A.record(s, user.username, "roles_update", target=u.username, detail={"before": old, "after": new}, client_ip=client_ip(request))
    return {"ok": True, "roles": new}


# ------------------------------------------------------------------ change requests
class ChangeIn(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    reason: str = Field("", max_length=4000)
    lines: list[str] = Field(min_length=1, max_length=500)
    rollback_lines: list[str] = Field(default_factory=list, max_length=500)
    save_config: bool = False
    window_start: datetime | None = None
    window_end: datetime | None = None


class DecisionIn(BaseModel):
    comment: str = Field("", max_length=2000)


def _change(cr: NmsChangeRequest, full: bool = False) -> dict:
    out = {"id": cr.id, "switch_id": cr.switch_id, "device": cr.device_name, "title": cr.title, "risk": cr.risk, "status": cr.status,
           "requested_by": cr.requested_by, "approved_by": cr.approved_by, "approved_at": iso(cr.approved_at), "executed_by": cr.executed_by,
           "executed_at": iso(cr.executed_at), "window_start": iso(cr.window_start), "window_end": iso(cr.window_end),
           "created_at": iso(cr.created_at), "lines": len(cr.lines or [])}
    if full:
        out.update(reason=cr.reason, line_text=cr.lines, rollback_lines=cr.rollback_lines, save_config=cr.save_config, preview=cr.preview,
                   output=cr.output, result={k: v for k, v in (cr.result or {}).items()}, log=cr.log, decision_comment=cr.decision_comment,
                   pre_snapshot_id=cr.pre_snapshot_id, post_snapshot_id=cr.post_snapshot_id)
    return out


async def _visible_change(s: AsyncSession, user: User, cid: int) -> NmsChangeRequest:
    cr = await s.get(NmsChangeRequest, cid)
    sw = await s.get(Switch, cr.switch_id) if cr and cr.switch_id else None
    if cr is None or not site_allowed(user, sw.site if sw else None):
        raise HTTPException(404, "change request not found")
    return cr


@router.get("/changes")
async def changes(status: str | None = Query(None, max_length=20), switch_id: int | None = None, limit: int = Query(100, ge=1, le=500),
                  user: User = Depends(P("nms.device.access.view")), s: AsyncSession = Depends(get_session)):
    stmt = select(NmsChangeRequest).order_by(NmsChangeRequest.id.desc()).limit(limit)
    if status:
        stmt = stmt.where(NmsChangeRequest.status == status)
    if switch_id:
        stmt = stmt.where(NmsChangeRequest.switch_id == switch_id)
    rows = (await s.execute(stmt)).scalars().all()
    sites = dict((await s.execute(select(Switch.id, Switch.site).where(Switch.id.in_({r.switch_id for r in rows if r.switch_id})))).all()) if rows else {}
    return {"enabled": get_settings().nms_config_changes_enabled, "items": [_change(r) for r in rows if site_allowed(user, sites.get(r.switch_id))]}


@router.get("/changes/{cid}")
async def change(cid: int, user: User = Depends(P("nms.device.access.view")), s: AsyncSession = Depends(get_session)):
    return _change(await _visible_change(s, user, cid), full=True)


@router.post("/devices/{sid}/changes", status_code=201)
async def create_change(sid: int, body: ChangeIn, request: Request, user: User = Depends(P("nms.device.access.configuration")),
                        s: AsyncSession = Depends(get_session)):
    try:
        cr = await C.create(s, user, sid, title=body.title, reason=body.reason, lines=body.lines, rollback_lines=body.rollback_lines,
                            save_config=body.save_config, window_start=body.window_start, window_end=body.window_end)
    except AccessError as e:
        raise _err(e)
    await A.record(s, user.username, "change_request", switch_id=sid, target=cr.device_name, detail={"change_id": cr.id, "risk": cr.risk, "lines": len(cr.lines)},
                   client_ip=client_ip(request))
    return _change(cr, full=True)


@router.post("/changes/{cid}/{decision}")
async def decide(cid: int, decision: str, body: DecisionIn, request: Request, user: User = Depends(P("nms.device.access.view")),
                 s: AsyncSession = Depends(get_session)):
    if decision not in ("approve", "reject", "execute", "rollback", "cancel"):
        raise HTTPException(404, "unknown action")
    cr = await _visible_change(s, user, cid)
    try:
        if decision in ("approve", "reject"):
            cr = await C.decide(s, user, cr, decision == "approve", body.comment)
            await A.record(s, user.username, f"change_{decision}", switch_id=cr.switch_id, target=cr.device_name, detail={"change_id": cid},
                           client_ip=client_ip(request))
        elif decision == "cancel":
            if cr.requested_by != user.username and not rbac.has(user, "nms.configuration.approve"):
                raise HTTPException(403, "only the requester or an approver can cancel")
            if cr.status not in ("pending_approval", "approved"):
                raise HTTPException(409, f"a {cr.status} change cannot be cancelled")
            cr.status = "cancelled"
            C.log_event(cr, user.username, "cancelled", body.comment)
            await s.commit()
            await A.record(s, user.username, "change_cancel", switch_id=cr.switch_id, target=cr.device_name, detail={"change_id": cid}, client_ip=client_ip(request))
        elif decision == "execute":
            cr = await C.execute(s, user, cr, client_ip=client_ip(request))
        else:
            cr = await C.rollback(s, user, cr, client_ip=client_ip(request))
    except AccessError as e:
        raise _err(e)
    return _change(cr, full=True)


# ------------------------------------------------------------------ access audit
@router.get("/audit")
async def audit_log(action: str | None = Query(None, max_length=64), username: str | None = Query(None, max_length=64),
                    switch_id: int | None = None, success: bool | None = None, start: datetime | None = None, end: datetime | None = None,
                    limit: int = Query(200, ge=1, le=2000), offset: int = Query(0, ge=0),
                    user: User = Depends(P("nms.device.access.audit.view")), s: AsyncSession = Depends(get_session)):
    stmt = select(NmsAccessAudit)
    if action:
        stmt = stmt.where(NmsAccessAudit.action == action)
    if username:
        stmt = stmt.where(NmsAccessAudit.username == username)
    if switch_id:
        stmt = stmt.where(NmsAccessAudit.switch_id == switch_id)
    if success is not None:
        stmt = stmt.where(NmsAccessAudit.success == success)
    if start:
        stmt = stmt.where(NmsAccessAudit.ts >= start)
    if end:
        stmt = stmt.where(NmsAccessAudit.ts < end)
    total = (await s.execute(select(func.count()).select_from(stmt.subquery()))).scalar() or 0
    rows = (await s.execute(stmt.order_by(NmsAccessAudit.id.desc()).offset(offset).limit(limit))).scalars().all()
    sites = dict((await s.execute(select(Switch.id, Switch.site).where(Switch.id.in_({r.switch_id for r in rows if r.switch_id})))).all()) if rows else {}
    return {"total": total, "items": [{"id": r.id, "ts": iso(r.ts), "username": r.username, "action": r.action, "switch_id": r.switch_id,
                                       "session_id": r.session_id, "target": r.target, "detail": r.detail, "client_ip": r.client_ip, "success": r.success}
                                      for r in rows if r.switch_id is None or site_allowed(user, sites.get(r.switch_id))]}


@router.get("/audit/verify")
async def audit_verify(_: User = Depends(P("nms.device.access.audit.view")), s: AsyncSession = Depends(get_session)):
    return await A.verify(s)


@router.get("/audit/export.csv")
async def audit_export(request: Request, user: User = Depends(P("nms.device.access.audit.view")), s: AsyncSession = Depends(get_session)):
    rows = (await s.execute(select(NmsAccessAudit).order_by(NmsAccessAudit.id.desc()).limit(100_000))).scalars().all()
    sites = dict((await s.execute(select(Switch.id, Switch.site))).all())
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "ts", "username", "action", "switch_id", "session_id", "target", "success", "client_ip", "detail", "hash"])
    for r in rows:
        if r.switch_id is None or site_allowed(user, sites.get(r.switch_id)):
            w.writerow([csv_safe(x) for x in (r.id, iso(r.ts), r.username, r.action, r.switch_id, r.session_id, r.target, r.success, r.client_ip, str(r.detail), r.hash)])
    await A.record(s, user.username, "audit_export", client_ip=client_ip(request))
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="nms-access-audit.csv"'})


@router.get("/health")
async def health():
    return {"status": "ok"}


# ------------------------------------------------------------------ Telnet opt-in, NETCONF / RESTCONF
class TelnetIn(BaseModel):
    enabled: bool


@router.put("/devices/{sid}/telnet")
async def set_telnet(sid: int, body: TelnetIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    """Per-device Telnet opt-in (administrators). Telnet also needs ACCESS_TELNET_ENABLED on the installation."""
    sw = await _device(s, user, sid)
    sw.access_telnet = body.enabled
    await s.commit()
    await A.record(s, user.username, "device_telnet", switch_id=sid, target=sw.name, detail={"enabled": body.enabled, "cleartext": True},
                   client_ip=client_ip(request))
    return {"ok": True, "installation_enabled": get_settings().access_telnet_enabled}


@router.get("/protocol-ops")
async def protocol_ops(_: User = Depends(P("nms.device.access.view"))):
    from ..access.netconf import NETCONF_OPS, RESTCONF_OPS
    return {"netconf": [{"id": k, "title": v["title"], "platform": v.get("platform")} for k, v in NETCONF_OPS.items()],
            "restconf": [{"id": k, "title": v["title"], "path": v["path"], "platform": v.get("platform")} for k, v in RESTCONF_OPS.items()]}


class OpIn(BaseModel):
    operation: str = Field(max_length=64)


async def _protocol_job(s: AsyncSession, user: User, sid: int, name: str, result: dict) -> int:
    job = NmsDiagJob(username=user.username, kind="single", templates=[name], device_ids=[sid], status="done", total=1, completed=1,
                     failed=int(result.get("status") != "ok"), created_at=datetime.now(timezone.utc), finished_at=datetime.now(timezone.utc))
    s.add(job)
    await s.flush()
    sw = await s.get(Switch, sid)
    s.add(NmsDiagResult(job_id=job.id, switch_id=sid, device_name=sw.name if sw else "", status="ok" if result.get("status") == "ok" else "failed",
                        error="" if result.get("status") == "ok" else result.get("status", ""),
                        outputs=[{"template": name, "command": result.get("path") or name, "status": result.get("status"), "ms": result.get("ms"),
                                  "output": (result.get("output") or "")[:262144], "truncated": len(result.get("output") or "") > 262144}],
                        duration_ms=result.get("ms"), finished_at=datetime.now(timezone.utc)))
    await s.commit()
    return job.id


@router.post("/devices/{sid}/netconf")
async def run_netconf(sid: int, body: OpIn, request: Request, user: User = Depends(P("nms.device.access.diagnostics")), s: AsyncSession = Depends(get_session)):
    from ..access.gateway import connect
    from ..access.netconf import NETCONF_OPS, netconf
    if body.operation not in NETCONF_OPS:
        raise HTTPException(422, f"unknown NETCONF operation; one of {', '.join(NETCONF_OPS)}")
    try:
        t = await resolve(s, user, sid, "netconf")
        cred, _ = await vault.resolve(s, t.switch, "netconf")
        if cred is None:
            cred, _ = await vault.resolve(s, t.switch, "ssh")
        conn, server_key, _ = await connect(t, cred)
        try:
            if not t.switch.ssh_host_key and server_key:
                t.switch.ssh_host_key = server_key
            res = await netconf(conn, body.operation, float(get_settings().access_command_timeout_seconds))
        finally:
            conn.close()
    except AccessError as e:
        await A.record(s, user.username, "netconf_run", switch_id=sid, detail={"operation": body.operation, "error": e.message[:300]},
                       client_ip=client_ip(request), success=False)
        raise _err(e)
    await s.commit()
    job_id = await _protocol_job(s, user, sid, f"netconf:{body.operation}", res)
    await A.record(s, user.username, "netconf_run", switch_id=sid, target=t.switch.name, detail={"operation": body.operation, "status": res["status"], "job_id": job_id},
                   client_ip=client_ip(request), success=res["status"] == "ok")
    return {**res, "job_id": job_id}


@router.post("/devices/{sid}/restconf")
async def run_restconf(sid: int, body: OpIn, request: Request, user: User = Depends(P("nms.device.access.diagnostics")), s: AsyncSession = Depends(get_session)):
    from ..access.netconf import RESTCONF_OPS, restconf
    if body.operation not in RESTCONF_OPS:
        raise HTTPException(422, f"unknown RESTCONF operation; one of {', '.join(RESTCONF_OPS)}")
    try:
        t = await resolve(s, user, sid, "https")
        cred, _ = await vault.resolve(s, t.switch, "https")
        if cred is None:
            cred, _ = await vault.resolve(s, t.switch, "ssh")
        if cred is None:
            raise AccessError(409, "no https (or ssh) credential for this device", "config")
        res, fp = await restconf(t, vault.unseal(cred), cred.username, body.operation, pinned=t.switch.https_cert_sha256 or "",
                                 timeout=float(get_settings().restconf_timeout_seconds), transport=_RESTCONF_TRANSPORT.get("t"))
    except AccessError as e:
        await A.record(s, user.username, "restconf_run", switch_id=sid, detail={"operation": body.operation, "error": e.message[:300]},
                       client_ip=client_ip(request), success=False)
        raise _err(e)
    if not t.switch.https_cert_sha256 and fp:
        t.switch.https_cert_sha256 = fp                  # pinned on first use
    await s.commit()
    job_id = await _protocol_job(s, user, sid, f"restconf:{body.operation}", res)
    await A.record(s, user.username, "restconf_run", switch_id=sid, target=t.switch.name,
                   detail={"operation": body.operation, "status": res["status"], "http_status": res["http_status"], "job_id": job_id},
                   client_ip=client_ip(request), success=res["status"] == "ok")
    return {**res, "job_id": job_id}


_RESTCONF_TRANSPORT: dict = {}     # tests only: an httpx transport standing in for the device


@router.post("/devices/{sid}/https-cert/accept")
async def accept_https_cert(sid: int, request: Request, user: User = Depends(P("nms.device.access.credential.manage")), s: AsyncSession = Depends(get_session)):
    """Forget the pinned HTTPS certificate; the next RESTCONF call pins the certificate the device presents then."""
    sw = await _device(s, user, sid)
    old = sw.https_cert_sha256
    sw.https_cert_sha256 = ""
    await s.commit()
    await A.record(s, user.username, "https_cert_reset", switch_id=sid, target=sw.name, detail={"previous": old}, client_ip=client_ip(request))
    return {"ok": True}


# ------------------------------------------------------------------ console servers
class ConsoleServerIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    address: str = Field(min_length=2, max_length=64)
    kind: str = Field("opengear", pattern=r"^(opengear|cisco)$")
    method: str = Field("ssh", pattern=r"^(ssh|telnet)$")
    credential_id: int | None = None
    site: str = Field("", max_length=128)
    notes: str = Field("", max_length=2000)


class ConsolePortIn(BaseModel):
    port: int = Field(ge=1, le=9999)
    switch_id: int | None = None
    label: str = Field("", max_length=128)


def _cs_out(c: ConsoleServer, ports: list[ConsolePort], names: dict) -> dict:
    return {"id": c.id, "name": c.name, "address": c.address, "kind": c.kind, "method": c.method, "credential_id": c.credential_id, "site": c.site,
            "notes": c.notes, "host_key_pinned": bool(c.ssh_host_key),
            "ports": [{"id": p.id, "port": p.port, "switch_id": p.switch_id, "device": names.get(p.switch_id, ""), "label": p.label} for p in sorted(ports, key=lambda x: x.port)]}


@router.get("/console-servers")
async def console_servers(user: User = Depends(P("nms.device.access.view")), s: AsyncSession = Depends(get_session)):
    srv = (await s.execute(select(ConsoleServer).order_by(ConsoleServer.name))).scalars().all()
    ports = (await s.execute(select(ConsolePort))).scalars().all()
    names = dict((await s.execute(select(Switch.id, Switch.name))).all())
    return {"telnet_enabled": get_settings().access_telnet_enabled,
            "items": [_cs_out(c, [p for p in ports if p.server_id == c.id], names) for c in srv if site_allowed(user, c.site)]}


async def _validate_cs(s: AsyncSession, body: ConsoleServerIn) -> None:
    from ..switches.poller import validate_address
    from ..db.models import SwitchNetwork
    try:
        validate_address(body.address, (await s.execute(select(SwitchNetwork))).scalars().all())
    except ValueError as e:
        raise HTTPException(422, str(e))
    if body.credential_id is not None:
        c = await s.get(DeviceSshCredential, body.credential_id)
        if c is None or (c.kind or "ssh") != "ssh":
            raise HTTPException(422, "the credential must be an SSH credential from the vault")


@router.post("/console-servers", status_code=201)
async def create_console_server(body: ConsoleServerIn, request: Request, user: User = Depends(P("nms.device.manage")), s: AsyncSession = Depends(get_session)):
    await _validate_cs(s, body)
    if (await s.execute(select(ConsoleServer).where(ConsoleServer.name == body.name))).scalar_one_or_none():
        raise HTTPException(409, "a console server with this name exists")
    c = ConsoleServer(**body.model_dump(), created_by=user.username)
    s.add(c)
    await s.commit()
    await A.record(s, user.username, "console_server_create", target=c.name, detail={"kind": c.kind, "method": c.method, "address": c.address},
                   client_ip=client_ip(request))
    return {"id": c.id}


@router.put("/console-servers/{cid}")
async def update_console_server(cid: int, body: ConsoleServerIn, request: Request, user: User = Depends(P("nms.device.manage")), s: AsyncSession = Depends(get_session)):
    c = await s.get(ConsoleServer, cid)
    if c is None:
        raise HTTPException(404, "console server not found")
    await _validate_cs(s, body)
    if body.address != c.address:
        c.ssh_host_key = ""                           # a different host: its key is pinned again on first use
    for k, v in body.model_dump().items():
        setattr(c, k, v)
    await s.commit()
    await A.record(s, user.username, "console_server_update", target=c.name, detail={"kind": c.kind, "method": c.method}, client_ip=client_ip(request))
    return {"ok": True}


@router.delete("/console-servers/{cid}")
async def delete_console_server(cid: int, request: Request, user: User = Depends(P("nms.device.manage")), s: AsyncSession = Depends(get_session)):
    c = await s.get(ConsoleServer, cid)
    if c is None:
        raise HTTPException(404, "console server not found")
    await s.delete(c)
    await s.commit()
    await A.record(s, user.username, "console_server_delete", target=c.name, client_ip=client_ip(request))
    return {"ok": True}


@router.post("/console-servers/{cid}/accept-host-key")
async def console_accept_key(cid: int, request: Request, user: User = Depends(P("nms.device.access.credential.manage")), s: AsyncSession = Depends(get_session)):
    c = await s.get(ConsoleServer, cid)
    if c is None:
        raise HTTPException(404, "console server not found")
    c.ssh_host_key = ""
    await s.commit()
    await A.record(s, user.username, "console_host_key_reset", target=c.name, client_ip=client_ip(request))
    return {"ok": True}


@router.post("/console-servers/{cid}/ports", status_code=201)
async def add_console_port(cid: int, body: ConsolePortIn, request: Request, user: User = Depends(P("nms.device.manage")), s: AsyncSession = Depends(get_session)):
    c = await s.get(ConsoleServer, cid)
    if c is None:
        raise HTTPException(404, "console server not found")
    if body.switch_id is not None and await s.get(Switch, body.switch_id) is None:
        raise HTTPException(422, "device not found")
    if (await s.execute(select(ConsolePort).where(ConsolePort.server_id == cid, ConsolePort.port == body.port))).scalar_one_or_none():
        raise HTTPException(409, "this port is already mapped")
    p = ConsolePort(server_id=cid, **body.model_dump())
    s.add(p)
    await s.commit()
    await A.record(s, user.username, "console_port_map", switch_id=body.switch_id, target=c.name, detail={"port": body.port}, client_ip=client_ip(request))
    return {"id": p.id}


@router.delete("/console-ports/{pid}")
async def delete_console_port(pid: int, request: Request, user: User = Depends(P("nms.device.manage")), s: AsyncSession = Depends(get_session)):
    p = await s.get(ConsolePort, pid)
    if p is None:
        raise HTTPException(404, "console port not found")
    await s.delete(p)
    await s.commit()
    await A.record(s, user.username, "console_port_unmap", switch_id=p.switch_id, detail={"port": p.port}, client_ip=client_ip(request))
    return {"ok": True}
