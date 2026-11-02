"""APIs: TACACS+ AAA (tac_plus-ng). Backend RBAC: TACACS+ roles (auditor / operator / policy_admin / approver; SIEM admins
hold all) on top of the SIEM session. Overview counts are visible to every signed-in user; command history, sessions,
raw records and exports need the auditor role. Shared secrets are write-only: shown once at creation or rotation."""
from __future__ import annotations

import csv
import io
import ipaddress
import re
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db.ch import ClickHouse
from ..db.models import (AuditLog, TacAuthPolicy, TacClient, TacCommandRule, TacConfigVersion, TacDeployJob, TacHealthCheck, TacIdentitySource, TacRole,
                         TacRoleMapping, TacServer, TacTestRun, TacUser, User)
from ..db.pg import get_session
from ..netguard import DestinationError, check_host_static
from ..tacacs import client as TC
from ..tacacs import queries as Q
from ..tacacs import render as RND
from ..tacacs import service as S
from ..tacacs.policy import (PolicyError, conflicts, evaluate_command, evaluate_exec, explain, validate_name, validate_pattern, validate_window)
from ..tacacs.templates import template
from ..tacacs.vendors import CAPABILITIES, CATEGORIES, ROLE_TEMPLATES
from .deps import audit, ch_dep, client_ip, csv_safe, current_user, iso, limiter

router = APIRouter(prefix="/api/tacacs", tags=["tacacs"])
RANGE = r"^(1h|6h|24h|7d|30d)$"
VENDOR = r"^(fortinet|cisco|ruckus|other)$"


async def _need(s: AsyncSession, request: Request, user: User, role: str, action: str, target: str = "") -> None:
    try:
        S.require(user, role)
    except S.TacError as e:
        s.add(AuditLog(username=user.username, action=f"tacacs_{action}", target=target[:255], detail={"refused": e.message},
                       client_ip=client_ip(request), success=False))
        await s.commit()
        raise HTTPException(403, e.message)


def _rate(user: User, key: str, n: int):
    if not limiter.check(f"tac:{key}:{user.id}", n):
        raise HTTPException(429, f"too many {key} requests; wait a minute")


def _err(e: Exception):
    if isinstance(e, S.TacError):
        raise HTTPException(e.status, e.message)
    if isinstance(e, PolicyError):
        raise HTTPException(422, str(e))
    raise e


async def _get(s, model, oid: int, what: str):
    x = await s.get(model, oid)
    if x is None:
        raise HTTPException(404, f"{what} not found")
    return x


def _f(range_, start=None, **kw) -> dict:
    t0, t1 = Q.window(range_)
    return {"t0": t0, "t1": t1, **{k: v for k, v in kw.items() if v not in (None, "")}}


# ------------------------------------------------------------------ meta / overview
@router.get("/meta")
async def meta(user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    cfg = await S.settings(s)
    return {"my_roles": sorted(S.roles_of(user)), "roles": S.ROLE_HELP, "vendors": CAPABILITIES, "categories": CATEGORIES, "role_templates": ROLE_TEMPLATES,
            "settings": {k: v for k, v in cfg.items() if not k.endswith("ciphertext")}, "tester_configured": bool(cfg.get("tester_address") and cfg.get("tester_secret_ciphertext")),
            "event_types": sorted({e for e, _ in __import__("app.tacacs.parse", fromlist=["EVENT"]).EVENT.values()} | {"conn_probe"}), "is_siem_admin": user.role == "admin"}


@router.get("/overview")
async def overview(range: str = Query("24h", pattern=RANGE), user_: str | None = Query(None, alias="user", max_length=64),
                   device: str | None = Query(None, max_length=64), site: str | None = Query(None, max_length=128), result: str | None = Query(None, max_length=32),
                   event_type: str | None = Query(None, max_length=32), severity: str | None = Query(None, pattern=r"^(informational|low|medium|high)$"),
                   _: User = Depends(current_user), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    return await Q.overview(s, ch, _f(range, user=user_, device=device, site=site, result=result, event_type=event_type, severity=severity))


@router.get("/timeline")
async def timeline(range: str = Query("24h", pattern=RANGE), user_: str | None = Query(None, alias="user", max_length=64),
                   device: str | None = Query(None, max_length=64), _: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep)):
    return await Q.timeline(ch, _f(range, user=user_, device=device))


# ------------------------------------------------------------------ servers
class ServerIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    kind: str = Field("managed", pattern=r"^(managed|external)$")
    management_address: str = Field(min_length=1, max_length=255)
    client_address: str = Field("", max_length=255)
    port: int = Field(49, ge=1, le=65535)
    site: str = Field("", max_length=128)
    environment: str = Field("production", pattern=r"^(production|staging|lab)$")
    role: str = Field("primary", pattern=r"^(primary|secondary)$")
    monitoring: bool = True
    notes: str = Field("", max_length=2000)


def _server_out(x: TacServer) -> dict:
    return {"id": x.id, "name": x.name, "kind": x.kind, "management_address": x.management_address, "client_address": x.client_address, "port": x.port,
            "site": x.site, "environment": x.environment, "role": x.role, "implementation": x.implementation, "version": x.version, "monitoring": x.monitoring,
            "status": x.status, "status_since": iso(x.status_since), "last_check_at": iso(x.last_check_at), "last_ok_at": iso(x.last_ok_at),
            "last_error": x.last_error, "agent": x.agent or {}, "deployed_version_id": x.deployed_version_id, "deployed_sha256": x.deployed_sha256,
            "last_deploy_at": iso(x.last_deploy_at), "last_accounting_at": iso(x.last_accounting_at), "last_authentication_at": iso(x.last_authentication_at),
            "ingestion": x.ingestion or {}, "notes": x.notes, "created_at": iso(x.created_at)}


def _check_server_addr(addr: str):
    try:
        check_host_static(addr)
    except DestinationError as e:
        raise HTTPException(422, str(e))


@router.get("/servers")
async def servers(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    return {"items": [_server_out(x) for x in (await s.execute(select(TacServer).order_by(TacServer.role, TacServer.name))).scalars()]}


@router.post("/servers", status_code=201)
async def server_create(body: ServerIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "operator", "server_create", body.name)
    _check_server_addr(body.management_address)
    if (await s.execute(select(TacServer).where(TacServer.name == body.name))).scalars().first():
        raise HTTPException(409, "a server with this name exists")
    if body.kind == "managed" and (await s.execute(select(TacServer).where(TacServer.kind == "managed"))).scalars().first():
        raise HTTPException(409, "one managed server per SIEM (it shares the agent volume); add other servers as external")
    x = TacServer(**body.model_dump(), created_by=user.username)
    s.add(x)
    await s.commit()
    await audit(s, request, user.username, "tacacs_server_create", x.name, {"kind": x.kind, "address": x.management_address})
    return _server_out(x)


@router.put("/servers/{sid}")
async def server_update(sid: int, body: ServerIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "operator", "server_update", str(sid))
    x = await _get(s, TacServer, sid, "server")
    _check_server_addr(body.management_address)
    if body.kind != x.kind:
        raise HTTPException(422, "the server kind cannot change; add a new server instead")
    for k, v in body.model_dump().items():
        setattr(x, k, v)
    await s.commit()
    await audit(s, request, user.username, "tacacs_server_update", x.name, {"monitoring": x.monitoring})
    return _server_out(x)


@router.delete("/servers/{sid}")
async def server_delete(sid: int, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "operator", "server_delete", str(sid))
    x = await _get(s, TacServer, sid, "server")
    used = (await s.execute(select(func.count()).select_from(TacClient).where(or_(TacClient.primary_server_id == sid, TacClient.secondary_server_id == sid)))).scalar_one()
    if used:
        raise HTTPException(409, f"{used} client(s) are assigned to this server; reassign them first")
    await s.delete(x)
    await s.commit()
    await audit(s, request, user.username, "tacacs_server_delete", x.name)
    return {"ok": True}


@router.post("/servers/{sid}/check")
async def server_check(sid: int, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "operator", "server_check", str(sid))
    _rate(user, "check", 20)
    from ..tacacs.jobs import health
    x = await _get(s, TacServer, sid, "server")
    hc = await health(s, x)
    return {"status": hc.status, "tcp_ok": hc.tcp_ok, "latency_ms": hc.latency_ms, "agent_ok": hc.agent_ok, "detail": hc.detail, "server": _server_out(x)}


@router.get("/servers/{sid}/health")
async def server_health(sid: int, limit: int = Query(200, ge=1, le=2000), _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _get(s, TacServer, sid, "server")
    rows = (await s.execute(select(TacHealthCheck).where(TacHealthCheck.server_id == sid).order_by(TacHealthCheck.at.desc()).limit(limit))).scalars().all()
    ok = sum(1 for r in rows if r.status == "up")
    return {"availability_pct": round(100 * ok / len(rows), 2) if rows else None,
            "items": [{"at": iso(r.at), "status": r.status, "tcp_ok": r.tcp_ok, "latency_ms": r.latency_ms, "agent_ok": r.agent_ok, "detail": r.detail} for r in rows]}


# ------------------------------------------------------------------ clients
class ClientIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    address: str = Field(min_length=1, max_length=64)
    vendor: str = Field(pattern=VENDOR)
    model: str = Field("", max_length=64)
    firmware: str = Field("", max_length=64)
    site: str = Field("", max_length=128)
    device_group: str = Field("", max_length=64)
    role: str = Field("", max_length=32)
    primary_server_id: int | None = None
    secondary_server_id: int | None = None
    enabled: bool = True
    notes: str = Field("", max_length=2000)
    wide_cidr_justification: str = Field("", max_length=1000)


def _client_out(c: TacClient, names: dict | None = None) -> dict:
    return {"id": c.id, "name": c.name, "address": c.address, "vendor": c.vendor, "model": c.model, "firmware": c.firmware, "site": c.site,
            "device_group": c.device_group, "role": c.role, "primary_server_id": c.primary_server_id, "secondary_server_id": c.secondary_server_id,
            "primary_server": (names or {}).get(c.primary_server_id), "secondary_server": (names or {}).get(c.secondary_server_id), "enabled": c.enabled,
            "has_secret": bool(c.secret_ciphertext), "secret_version": c.secret_version, "secret_rotated_at": iso(c.secret_rotated_at),
            "rotation_state": c.rotation_state, "wide_cidr": "/" in c.address, "wide_cidr_approved_by": c.wide_cidr_approved_by,
            "wide_cidr_justification": c.wide_cidr_justification, "sync_status": c.sync_status, "last_auth_test_at": iso(c.last_auth_test_at),
            "last_auth_test_ok": c.last_auth_test_ok, "last_accounting_at": iso(c.last_accounting_at), "last_authentication_at": iso(c.last_authentication_at),
            "capabilities": CAPABILITIES.get(c.vendor), "notes": c.notes, "created_by": c.created_by, "created_at": iso(c.created_at), "updated_at": iso(c.updated_at)}


@router.get("/clients")
async def clients(q: str | None = Query(None, max_length=64), vendor: str | None = Query(None, pattern=VENDOR), site: str | None = Query(None, max_length=128),
                  sort: str = Query("name", pattern=r"^(name|vendor|site|last_accounting|sync)$"), limit: int = Query(100, ge=1, le=1000),
                  offset: int = Query(0, ge=0), _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    st = select(TacClient)
    if q:
        st = st.where(or_(TacClient.name.ilike(f"%{q}%"), TacClient.address.ilike(f"%{q}%"), TacClient.model.ilike(f"%{q}%")))
    if vendor:
        st = st.where(TacClient.vendor == vendor)
    if site:
        st = st.where(TacClient.site == site)
    order = {"name": TacClient.name, "vendor": TacClient.vendor, "site": TacClient.site, "last_accounting": TacClient.last_accounting_at.desc(),
             "sync": TacClient.sync_status}[sort]
    total = (await s.execute(select(func.count()).select_from(st.subquery()))).scalar_one()
    rows = (await s.execute(st.order_by(order).offset(offset).limit(limit))).scalars().all()
    names = {x.id: x.name for x in (await s.execute(select(TacServer))).scalars()}
    return {"total": total, "items": [_client_out(c, names) for c in rows]}


async def _client_validate(s, body: ClientIn, cid: int | None):
    try:
        validate_name(body.name, "device name")
    except PolicyError as e:
        raise HTTPException(422, str(e))
    if (await s.execute(select(TacClient).where(TacClient.name == body.name, TacClient.id != (cid or 0)))).scalars().first():
        raise HTTPException(409, "a client with this name exists")
    for sid in (body.primary_server_id, body.secondary_server_id):
        if sid and not await s.get(TacServer, sid):
            raise HTTPException(422, "assigned server not found")
    if body.primary_server_id and body.primary_server_id == body.secondary_server_id:
        raise HTTPException(422, "primary and secondary server must differ")
    existing = (await s.execute(select(TacClient))).scalars().all()
    try:
        return S.validate_client_address(body.address, await S.settings(s), existing=existing, self_id=cid, wide_justification=body.wide_cidr_justification)
    except S.TacError as e:
        _err(e)


@router.post("/clients", status_code=201)
async def client_create(body: ClientIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "operator", "client_create", body.name)
    addr, wide = await _client_validate(s, body, None)
    secret = S.generate_secret()
    c = TacClient(**{k: v for k, v in body.model_dump().items() if k not in ("address", "wide_cidr_justification")}, address=addr, secret_ciphertext=S.seal(secret),
                  wide_cidr_approved_by=user.username if wide else "", wide_cidr_justification=body.wide_cidr_justification if wide else "",
                  sync_status="pending", created_by=user.username, secret_rotated_at=S.now())
    s.add(c)
    await s.commit()
    await audit(s, request, user.username, "tacacs_client_create", c.name, {"address": c.address, "vendor": c.vendor, "wide_cidr": wide})
    return {**_client_out(c), "shared_secret": secret, "secret_notice": "Shown once. Configure it on the device; it cannot be displayed again."}


@router.put("/clients/{cid}")
async def client_update(cid: int, body: ClientIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "operator", "client_update", str(cid))
    c = await _get(s, TacClient, cid, "client")
    addr, wide = await _client_validate(s, body, cid)
    before = _client_out(c)
    for k, v in body.model_dump().items():
        if k not in ("address", "wide_cidr_justification"):
            setattr(c, k, v)
    if addr != c.address:
        c.address = addr
        c.wide_cidr_approved_by = user.username if wide else ""
        c.wide_cidr_justification = body.wide_cidr_justification if wide else ""
    c.sync_status = "pending"
    await s.commit()
    changed = {k: [before[k], _client_out(c)[k]] for k in ("name", "address", "vendor", "site", "device_group", "enabled", "primary_server_id",
                                                           "secondary_server_id") if before[k] != _client_out(c)[k]}
    await audit(s, request, user.username, "tacacs_client_update", c.name, {"changes": changed})
    return _client_out(c)


@router.delete("/clients/{cid}")
async def client_delete(cid: int, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "operator", "client_delete", str(cid))
    c = await _get(s, TacClient, cid, "client")
    await s.delete(c)
    await s.commit()
    await audit(s, request, user.username, "tacacs_client_delete", c.name, {"address": c.address})
    return {"ok": True, "note": "the device stays configured on the server until the next deployed version"}


@router.post("/clients/{cid}/rotate")
async def client_rotate(cid: int, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    """Step 1: generate a new secret. Both keys are accepted by the server once a version with it is deployed, so the
    device can be switched without an outage. Step 2 (complete) removes the old key."""
    await _need(s, request, user, "operator", "client_rotate", str(cid))
    c = await _get(s, TacClient, cid, "client")
    if c.rotation_state == "pending":
        raise HTTPException(409, "a rotation is already pending; complete or cancel it first")
    secret = S.generate_secret()
    c.pending_secret_ciphertext, c.rotation_state, c.sync_status = S.seal(secret), "pending", "pending"
    await s.commit()
    await audit(s, request, user.username, "tacacs_client_rotate_start", c.name, {"secret_version": c.secret_version + 1})
    return {"shared_secret": secret, "secret_notice": "Shown once. Deploy a configuration version (both keys accepted), change the key on the device, "
            "verify a login, then complete the rotation."}


@router.post("/clients/{cid}/rotate/{action}")
async def client_rotate_finish(cid: int, action: str, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "operator", f"client_rotate_{action}", str(cid))
    if action not in ("complete", "cancel"):
        raise HTTPException(404, "unknown action")
    c = await _get(s, TacClient, cid, "client")
    if c.rotation_state != "pending":
        raise HTTPException(409, "no rotation pending")
    if action == "complete":
        c.secret_ciphertext, c.secret_version, c.secret_rotated_at = c.pending_secret_ciphertext, c.secret_version + 1, S.now()
    c.pending_secret_ciphertext, c.rotation_state, c.sync_status = "", "completed" if action == "complete" else "", "pending"
    await s.commit()
    await audit(s, request, user.username, f"tacacs_client_rotate_{action}", c.name, {"secret_version": c.secret_version})
    return _client_out(c)


@router.get("/clients/{cid}/template")
async def client_template(cid: int, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    c = await _get(s, TacClient, cid, "client")
    srv = {x.id: x for x in (await s.execute(select(TacServer))).scalars()}
    p, sec = srv.get(c.primary_server_id), srv.get(c.secondary_server_id)
    if p is None:
        raise HTTPException(422, "assign a primary server first")
    addr = lambda x: (x.client_address or x.management_address) if x else None  # noqa: E731
    return template(_client_out(c), addr(p), addr(sec))


@router.get("/clients/{cid}/history")
async def client_history(cid: int, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    c = await _get(s, TacClient, cid, "client")
    rows = (await s.execute(select(AuditLog).where(AuditLog.action.like("tacacs_client_%"), AuditLog.target.in_([c.name, str(cid)]))
                            .order_by(AuditLog.ts.desc()).limit(200))).scalars().all()
    return {"items": [{"ts": iso(a.ts), "user": a.username, "action": a.action, "detail": a.detail, "success": a.success} for a in rows]}


# ------------------------------------------------------------------ identity sources and users
class SourceIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    kind: str = Field(pattern=r"^(local|ldap|ad|pam)$")
    enabled: bool = True
    hosts: list[str] = Field(default_factory=list, max_length=6)
    base: str = Field("", max_length=255)
    group_base: str = Field("", max_length=255)
    filter: str = Field("", max_length=255)
    memberof_regex: str = Field("", max_length=255)
    bind_dn: str = Field("", max_length=255)
    bind_password: str | None = Field(None, max_length=256)       # write-only
    starttls: bool = False
    nested_group_depth: int | None = Field(None, ge=0, le=10)
    pam_service: str = Field("", max_length=32)


def _source_out(x: TacIdentitySource) -> dict:
    return {"id": x.id, "name": x.name, "kind": x.kind, "enabled": x.enabled, "settings": x.settings or {}, "has_bind_password": bool(x.bind_secret_ciphertext),
            "last_test_at": iso(x.last_test_at), "last_test_ok": x.last_test_ok, "last_test_detail": x.last_test_detail, "created_at": iso(x.created_at)}


def _validate_source(body: SourceIn) -> dict:
    try:
        validate_name(body.name, "identity source name")
    except PolicyError as e:
        raise HTTPException(422, str(e))
    if body.kind in ("ldap", "ad"):
        if not body.hosts:
            raise HTTPException(422, "at least one LDAP host (ldaps://host:636 or host with StartTLS)")
        for h in body.hosts:
            if not re.fullmatch(r"(ldaps?://)?[A-Za-z0-9.-]{1,253}(:\d{1,5})?/?", h):
                raise HTTPException(422, f"invalid LDAP host {h}")
            if h.lower().startswith("ldap://") and not body.starttls:
                raise HTTPException(422, "clear-text LDAP is refused: use ldaps:// or enable StartTLS")
            try:
                check_host_static(h.split("://")[-1].split(":")[0].rstrip("/"))
            except DestinationError as e:
                raise HTTPException(422, str(e))
        if body.memberof_regex:
            try:
                re.compile(body.memberof_regex)
            except re.error:
                raise HTTPException(422, "memberOf regex is not valid")
    if body.kind == "pam" and body.pam_service:
        try:
            validate_name(body.pam_service, "PAM service")
        except PolicyError as e:
            raise HTTPException(422, str(e))
    return {k: v for k, v in body.model_dump().items() if k not in ("name", "kind", "enabled", "bind_password") and v not in (None, "", [])}


@router.get("/identity-sources")
async def sources(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    return {"items": [_source_out(x) for x in (await s.execute(select(TacIdentitySource).order_by(TacIdentitySource.name))).scalars()]}


@router.post("/identity-sources", status_code=201)
async def source_create(body: SourceIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "policy_admin", "identity_source_create", body.name)
    st = _validate_source(body)
    if (await s.execute(select(TacIdentitySource).where(TacIdentitySource.name == body.name))).scalars().first():
        raise HTTPException(409, "an identity source with this name exists")
    x = TacIdentitySource(name=body.name, kind=body.kind, enabled=body.enabled, settings=st, bind_secret_ciphertext=S.seal(body.bind_password or ""),
                          created_by=user.username)
    s.add(x)
    await s.commit()
    await audit(s, request, user.username, "tacacs_identity_source_create", x.name, {"kind": x.kind, "hosts": st.get("hosts")})
    return _source_out(x)


@router.put("/identity-sources/{xid}")
async def source_update(xid: int, body: SourceIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "policy_admin", "identity_source_update", str(xid))
    x = await _get(s, TacIdentitySource, xid, "identity source")
    st = _validate_source(body)
    x.name, x.enabled, x.settings = body.name, body.enabled, st
    if body.bind_password:
        x.bind_secret_ciphertext = S.seal(body.bind_password)
    await s.commit()
    await audit(s, request, user.username, "tacacs_identity_source_update", x.name, {"bind_password_changed": bool(body.bind_password)})
    return _source_out(x)


@router.delete("/identity-sources/{xid}")
async def source_delete(xid: int, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "policy_admin", "identity_source_delete", str(xid))
    x = await _get(s, TacIdentitySource, xid, "identity source")
    await s.delete(x)
    await s.commit()
    await audit(s, request, user.username, "tacacs_identity_source_delete", x.name)
    return {"ok": True}


class UserIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    source_id: int
    display_name: str = Field("", max_length=128)
    enabled: bool = True
    emergency: bool = False
    groups: list[str] = Field(default_factory=list, max_length=20)
    valid_until: datetime | None = None
    disabled_reason: str = Field("", max_length=500)
    password: str | None = Field(None, max_length=128)            # local only; write-only


async def _user_out(s, u: TacUser, ch=None, srcs: dict | None = None) -> dict:
    return {"id": u.id, "username": u.username, "source_id": u.source_id, "source": (srcs or {}).get(u.source_id), "display_name": u.display_name,
            "enabled": u.enabled, "emergency": u.emergency, "groups": u.groups or [], "valid_until": iso(u.valid_until), "disabled_reason": u.disabled_reason,
            "has_password": bool(u.password_hash), "password_set_at": iso(u.password_set_at), "created_at": iso(u.created_at)}


@router.get("/users")
async def users(q: str | None = Query(None, max_length=64), limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0),
                _: User = Depends(current_user), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    st = select(TacUser)
    if q:
        st = st.where(TacUser.username.ilike(f"%{q}%"))
    total = (await s.execute(select(func.count()).select_from(st.subquery()))).scalar_one()
    rows = (await s.execute(st.order_by(TacUser.username).offset(offset).limit(limit))).scalars().all()
    srcs = {x.id: {"name": x.name, "kind": x.kind} for x in (await s.execute(select(TacIdentitySource))).scalars()}
    names = [u.username for u in rows]
    last = {r["username"]: r for r in await ch.aquery(
        "SELECT username, maxIf(ts, event_type = 'auth_success') AS ok, maxIf(ts, event_type = 'auth_failure') AS fail, countIf(event_type = 'auth_failure') AS fails "
        "FROM tacacs_events FINAL WHERE username IN {u:Array(String)} AND ts >= now() - INTERVAL 90 DAY GROUP BY username", {"u": names or [""]})}
    roles = {r.id: r.name for r in (await s.execute(select(TacRole))).scalars()}
    maps = (await s.execute(select(TacRoleMapping))).scalars().all()
    out = []
    for u in rows:
        d = await _user_out(s, u, srcs=srcs)
        lr = last.get(u.username) or {}
        d["last_login"] = Q._iso(lr.get("ok")) if lr.get("ok") and not str(lr.get("ok")).startswith("1970") else None
        d["last_failure"] = Q._iso(lr.get("fail")) if lr.get("fail") and not str(lr.get("fail")).startswith("1970") else None
        d["roles"] = sorted({roles[m.role_id] for m in maps if m.enabled and m.role_id in roles and
                             ((m.principal_type == "user" and m.principal == u.username) or (m.principal_type == "group" and m.principal in (u.groups or [])))})
        out.append(d)
    return {"total": total, "items": out}


@router.post("/users", status_code=201)
async def user_create(body: UserIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "policy_admin", "user_create", body.username)
    src = await _get(s, TacIdentitySource, body.source_id, "identity source")
    try:
        validate_name(body.username, "user name")
        for g in body.groups:
            validate_name(g, "group name")
    except PolicyError as e:
        raise HTTPException(422, str(e))
    if (await s.execute(select(TacUser).where(TacUser.username == body.username))).scalars().first():
        raise HTTPException(409, "this user exists (user names must be unique across sources)")
    if src.kind != "local" and body.password:
        raise HTTPException(422, "passwords are only stored for local users; directory users authenticate against their directory")
    try:
        h = S.hash_password(body.password) if (src.kind == "local" and body.password) else ""
    except S.TacError as e:
        _err(e)
    u = TacUser(**{k: v for k, v in body.model_dump().items() if k != "password"}, password_hash=h, password_set_at=S.now() if h else None,
                created_by=user.username)
    s.add(u)
    await s.commit()
    await audit(s, request, user.username, "tacacs_user_create", u.username, {"source": src.name, "emergency": u.emergency, "groups": u.groups})
    return await _user_out(s, u)


@router.put("/users/{uid}")
async def user_update(uid: int, body: UserIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "policy_admin", "user_update", str(uid))
    u = await _get(s, TacUser, uid, "user")
    src = await _get(s, TacIdentitySource, u.source_id, "identity source")
    before = {"enabled": u.enabled, "emergency": u.emergency, "groups": list(u.groups or [])}
    for k in ("display_name", "enabled", "emergency", "groups", "valid_until", "disabled_reason"):
        setattr(u, k, getattr(body, k))
    if body.password:
        if src.kind != "local":
            raise HTTPException(422, "directory users have no stored password")
        try:
            u.password_hash, u.password_set_at = S.hash_password(body.password), S.now()
        except S.TacError as e:
            _err(e)
    await s.commit()
    await audit(s, request, user.username, "tacacs_user_update", u.username,
                {"before": before, "after": {"enabled": u.enabled, "emergency": u.emergency, "groups": u.groups}, "password_changed": bool(body.password)})
    return await _user_out(s, u)


@router.delete("/users/{uid}")
async def user_delete(uid: int, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "policy_admin", "user_delete", str(uid))
    u = await _get(s, TacUser, uid, "user")
    await s.delete(u)
    await s.commit()
    await audit(s, request, user.username, "tacacs_user_delete", u.username)
    return {"ok": True}


# ------------------------------------------------------------------ roles, mappings, command rules, policies
class RoleIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    description: str = Field("", max_length=1000)
    privileged: bool = False
    vendor_profiles: dict[str, dict] = Field(default_factory=dict)
    default_command_action: str = Field("deny", pattern=r"^(permit|deny)$")
    command_categories: list[str] = Field(default_factory=list)


def _role_out(r: TacRole) -> dict:
    return {"id": r.id, "name": r.name, "description": r.description, "privileged": r.privileged, "vendor_profiles": r.vendor_profiles or {},
            "default_command_action": r.default_command_action, "command_categories": r.command_categories or [], "created_at": iso(r.created_at)}


def _check_role(body: RoleIn) -> dict:
    try:
        validate_name(body.name, "role name")
        vp = S.validate_vendor_profiles(body.vendor_profiles)
    except (PolicyError, S.TacError) as e:
        _err(e)
    bad = set(body.command_categories) - set(CATEGORIES)
    if bad:
        raise HTTPException(422, f"unknown categories: {', '.join(sorted(bad))}")
    return vp


@router.get("/roles")
async def roles(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    snap, _sec = await S.snapshot(s, with_secrets=False)
    rows = (await s.execute(select(TacRole).order_by(TacRole.name))).scalars().all()
    return {"items": [{**_role_out(r), "explain": explain(snap, r.id)} for r in rows]}


@router.post("/roles", status_code=201)
async def role_create(body: RoleIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "policy_admin", "role_create", body.name)
    vp = _check_role(body)
    if (await s.execute(select(TacRole).where(TacRole.name == body.name))).scalars().first():
        raise HTTPException(409, "a role with this name exists")
    r = TacRole(**{**body.model_dump(), "vendor_profiles": vp}, created_by=user.username)
    s.add(r)
    await s.commit()
    await audit(s, request, user.username, "tacacs_role_create", r.name, {"privileged": r.privileged})
    return _role_out(r)


@router.post("/roles/templates", status_code=201)
async def role_templates(request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "policy_admin", "role_templates")
    have = {r.name for r in (await s.execute(select(TacRole))).scalars()}
    added = [r for r in S.seed_roles() if r.name not in have]
    s.add_all(added)
    await s.commit()
    await audit(s, request, user.username, "tacacs_role_templates", "", {"added": [r.name for r in added]})
    return {"added": [r.name for r in added]}


@router.put("/roles/{rid}")
async def role_update(rid: int, body: RoleIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "policy_admin", "role_update", str(rid))
    r = await _get(s, TacRole, rid, "role")
    vp = _check_role(body)
    for k, v in {**body.model_dump(), "vendor_profiles": vp}.items():
        setattr(r, k, v)
    await s.commit()
    await audit(s, request, user.username, "tacacs_role_update", r.name, {"privileged": r.privileged, "categories": r.command_categories})
    return _role_out(r)


@router.delete("/roles/{rid}")
async def role_delete(rid: int, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "policy_admin", "role_delete", str(rid))
    r = await _get(s, TacRole, rid, "role")
    await s.delete(r)
    await s.commit()
    await audit(s, request, user.username, "tacacs_role_delete", r.name)
    return {"ok": True}


class MappingIn(BaseModel):
    principal_type: str = Field(pattern=r"^(user|group)$")
    principal: str = Field(min_length=1, max_length=128)
    role_id: int
    scope_sites: list[str] = Field(default_factory=list)
    scope_device_groups: list[str] = Field(default_factory=list)
    scope_vendors: list[str] = Field(default_factory=list)
    scope_clients: list[str] = Field(default_factory=list)
    time_window: str = Field("", max_length=128)
    priority: int = Field(100, ge=0, le=10000)
    justification: str = Field("", max_length=1000)
    expires_at: datetime | None = None
    enabled: bool = True


def _mapping_out(m: TacRoleMapping, roles: dict | None = None) -> dict:
    return {"id": m.id, "principal_type": m.principal_type, "principal": m.principal, "role_id": m.role_id, "role": (roles or {}).get(m.role_id),
            "scope_sites": m.scope_sites or [], "scope_device_groups": m.scope_device_groups or [], "scope_vendors": m.scope_vendors or [],
            "scope_clients": m.scope_clients or [], "time_window": m.time_window, "priority": m.priority, "justification": m.justification,
            "expires_at": iso(m.expires_at), "enabled": m.enabled, "created_by": m.created_by, "created_at": iso(m.created_at)}


async def _check_mapping(s, body: MappingIn):
    try:
        validate_name(body.principal, "user / group name")
        validate_window(body.time_window)
    except PolicyError as e:
        raise HTTPException(422, str(e))
    role = await _get(s, TacRole, body.role_id, "role")
    if set(body.scope_vendors) - set(CAPABILITIES):
        raise HTTPException(422, "unknown vendor in scope")
    if role.privileged and len(body.justification.strip()) < 10:
        raise HTTPException(422, "privileged role mappings need a justification")
    return role


@router.get("/mappings")
async def mappings(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    roles = {r.id: r.name for r in (await s.execute(select(TacRole))).scalars()}
    return {"items": [_mapping_out(m, roles) for m in (await s.execute(select(TacRoleMapping).order_by(TacRoleMapping.priority, TacRoleMapping.id))).scalars()]}


@router.post("/mappings", status_code=201)
async def mapping_create(body: MappingIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "policy_admin", "mapping_create", body.principal)
    role = await _check_mapping(s, body)
    m = TacRoleMapping(**body.model_dump(), created_by=user.username)
    s.add(m)
    await s.commit()
    await audit(s, request, user.username, "tacacs_mapping_create", f"{body.principal_type}:{body.principal}",
                {"role": role.name, "privileged": role.privileged, "justification": body.justification, "expires_at": iso(body.expires_at)})
    return _mapping_out(m)


@router.put("/mappings/{mid}")
async def mapping_update(mid: int, body: MappingIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "policy_admin", "mapping_update", str(mid))
    m = await _get(s, TacRoleMapping, mid, "mapping")
    role = await _check_mapping(s, body)
    for k, v in body.model_dump().items():
        setattr(m, k, v)
    await s.commit()
    await audit(s, request, user.username, "tacacs_mapping_update", f"{m.principal_type}:{m.principal}", {"role": role.name})
    return _mapping_out(m)


@router.delete("/mappings/{mid}")
async def mapping_delete(mid: int, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "policy_admin", "mapping_delete", str(mid))
    m = await _get(s, TacRoleMapping, mid, "mapping")
    await s.delete(m)
    await s.commit()
    await audit(s, request, user.username, "tacacs_mapping_delete", f"{m.principal_type}:{m.principal}")
    return {"ok": True}


class RuleIn(BaseModel):
    role_id: int
    vendor: str = Field(pattern=r"^(cisco|ruckus|other|any)$")
    action: str = Field(pattern=r"^(permit|deny)$")
    match: str = Field("regex", pattern=r"^(regex|category)$")
    pattern: str = Field("", max_length=256)
    category: str = Field("", max_length=32)
    priority: int = Field(100, ge=0, le=10000)
    exception: bool = False
    owner: str = Field("", max_length=64)
    justification: str = Field("", max_length=1000)
    expires_at: datetime | None = None
    enabled: bool = True
    description: str = Field("", max_length=1000)


def _rule_out(r: TacCommandRule) -> dict:
    return {"id": r.id, "role_id": r.role_id, "vendor": r.vendor, "action": r.action, "match": r.match, "pattern": r.pattern, "category": r.category,
            "priority": r.priority, "exception": r.exception, "owner": r.owner, "justification": r.justification, "expires_at": iso(r.expires_at),
            "enabled": r.enabled, "description": r.description, "created_by": r.created_by, "created_at": iso(r.created_at),
            "expired": bool(r.expires_at and (r.expires_at if r.expires_at.tzinfo else r.expires_at.replace(tzinfo=timezone.utc)) <= S.now())}


async def _check_rule(s, body: RuleIn):
    await _get(s, TacRole, body.role_id, "role")
    try:
        if body.match == "regex":
            validate_pattern(body.pattern)
        elif body.category not in CATEGORIES:
            raise PolicyError("unknown command category")
    except PolicyError as e:
        raise HTTPException(422, str(e))
    if body.exception and (not body.owner or not body.expires_at or len(body.justification.strip()) < 10):
        raise HTTPException(422, "exceptions need an owner, a justification and an expiry")


@router.get("/command-rules")
async def rules(role_id: int | None = None, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    st = select(TacCommandRule)
    if role_id:
        st = st.where(TacCommandRule.role_id == role_id)
    return {"items": [_rule_out(r) for r in (await s.execute(st.order_by(TacCommandRule.role_id, TacCommandRule.priority, TacCommandRule.id))).scalars()]}


@router.post("/command-rules", status_code=201)
async def rule_create(body: RuleIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "policy_admin", "command_rule_create", str(body.role_id))
    await _check_rule(s, body)
    r = TacCommandRule(**body.model_dump(), created_by=user.username)
    s.add(r)
    await s.commit()
    await audit(s, request, user.username, "tacacs_command_rule_create", str(r.id), {"role_id": r.role_id, "action": r.action, "match": r.match,
                                                                                        "pattern": r.pattern, "category": r.category, "exception": r.exception})
    return _rule_out(r)


@router.put("/command-rules/{rid}")
async def rule_update(rid: int, body: RuleIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "policy_admin", "command_rule_update", str(rid))
    r = await _get(s, TacCommandRule, rid, "rule")
    await _check_rule(s, body)
    for k, v in body.model_dump().items():
        setattr(r, k, v)
    await s.commit()
    await audit(s, request, user.username, "tacacs_command_rule_update", str(r.id), {"action": r.action, "pattern": r.pattern, "category": r.category})
    return _rule_out(r)


@router.delete("/command-rules/{rid}")
async def rule_delete(rid: int, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "policy_admin", "command_rule_delete", str(rid))
    r = await _get(s, TacCommandRule, rid, "rule")
    await s.delete(r)
    await s.commit()
    await audit(s, request, user.username, "tacacs_command_rule_delete", str(rid))
    return {"ok": True}


class PolicyIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    device_groups: list[str] = Field(default_factory=list)
    allowed_sources: list[str] = Field(default_factory=lambda: ["local", "directory"])
    allow_local_users: bool = True
    require_group_mapping: bool = True
    allow_emergency: bool = True
    failure_alert_threshold: int = Field(5, ge=1, le=1000)
    priority: int = Field(100, ge=0, le=10000)
    enabled: bool = True
    description: str = Field("", max_length=1000)


def _policy_out(p: TacAuthPolicy) -> dict:
    return {k: getattr(p, k) for k in ("id", "name", "device_groups", "allowed_sources", "allow_local_users", "require_group_mapping", "allow_emergency",
                                       "failure_alert_threshold", "priority", "enabled", "description", "created_by")} | {"created_at": iso(p.created_at)}


def _check_policy(body: PolicyIn):
    try:
        validate_name(body.name, "policy name")
    except PolicyError as e:
        raise HTTPException(422, str(e))
    if not set(body.allowed_sources) <= {"local", "directory"} or not body.allowed_sources:
        raise HTTPException(422, "allowed sources: one or both of local, directory")
    if not body.require_group_mapping:
        raise HTTPException(422, "default-deny is fixed: users without a role mapping are always denied")


@router.get("/auth-policies")
async def policies(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    return {"items": [_policy_out(p) for p in (await s.execute(select(TacAuthPolicy).order_by(TacAuthPolicy.priority))).scalars()]}


@router.post("/auth-policies", status_code=201)
async def policy_create(body: PolicyIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "policy_admin", "auth_policy_create", body.name)
    _check_policy(body)
    if not body.allow_local_users and "local" in body.allowed_sources:
        body.allowed_sources = [x for x in body.allowed_sources if x != "local"]
    p = TacAuthPolicy(**body.model_dump(), created_by=user.username)
    s.add(p)
    await s.commit()
    await audit(s, request, user.username, "tacacs_auth_policy_create", p.name, body.model_dump())
    return _policy_out(p)


@router.put("/auth-policies/{pid}")
async def policy_update(pid: int, body: PolicyIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "policy_admin", "auth_policy_update", str(pid))
    p = await _get(s, TacAuthPolicy, pid, "policy")
    _check_policy(body)
    for k, v in body.model_dump().items():
        setattr(p, k, v)
    await s.commit()
    await audit(s, request, user.username, "tacacs_auth_policy_update", p.name, body.model_dump())
    return _policy_out(p)


@router.delete("/auth-policies/{pid}")
async def policy_delete(pid: int, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "policy_admin", "auth_policy_delete", str(pid))
    p = await _get(s, TacAuthPolicy, pid, "policy")
    await s.delete(p)
    await s.commit()
    await audit(s, request, user.username, "tacacs_auth_policy_delete", p.name)
    return {"ok": True}


# ------------------------------------------------------------------ policy simulation
class SimIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    groups: list[str] = Field(default_factory=list, max_length=50)
    client_id: int
    commands: list[str] = Field(default_factory=list, max_length=50)
    at: datetime | None = None


@router.post("/policy/simulate")
async def simulate(body: SimIn, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    c = await _get(s, TacClient, body.client_id, "client")
    snap, _sec = await S.snapshot(s, with_secrets=False)
    u = next((x for x in snap["users"] if x["username"] == body.username), None)
    groups = sorted(set(body.groups) | set((u or {}).get("groups") or []))
    client = next(x for x in snap["clients"] if x["id"] == c.id)
    at = body.at or S.now()
    return {"user": body.username, "groups": groups, "client": client["name"], "vendor": client["vendor"], "at": at.isoformat(),
            "known_user": u is not None, "exec": evaluate_exec(snap, body.username, groups, client, at),
            "commands": [evaluate_command(snap, body.username, groups, client, cmd, at) for cmd in body.commands],
            "note": "Simulation of the policy that would be rendered now (draft); deploy a version for the server to enforce it."}


@router.get("/policy/conflicts")
async def policy_conflicts(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    snap, _sec = await S.snapshot(s, with_secrets=False)
    return {"items": conflicts(snap), "validation": S.validation(snap)}


# ------------------------------------------------------------------ configuration studio
@router.get("/config/preview")
async def config_preview(request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "policy_admin", "config_preview")
    snap, sec = await S.snapshot(s, with_secrets=False)
    v = S.validation(snap)
    try:
        red = RND.render(snap, sec, redact=True)
    except PolicyError as e:
        return {"content": "", "validation": {**v, "ok": False, "errors": v["errors"] + [str(e)]}, "diff": ""}
    deployed = (await s.execute(select(TacServer).where(TacServer.kind == "managed"))).scalars().first()
    base = await s.get(TacConfigVersion, deployed.deployed_version_id) if deployed and deployed.deployed_version_id else None
    return {"content": red, "validation": v, "diff": RND.diff(base.content_redacted if base else "", red, f"v{base.number}" if base else "nothing deployed", "draft"),
            "base_version": base.number if base else None}


class VersionIn(BaseModel):
    message: str = Field(min_length=3, max_length=2000)


@router.post("/config/versions", status_code=201)
async def version_create(body: VersionIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "policy_admin", "version_create")
    try:
        v = await S.commit_version(s, user.username, body.message)
    except (S.TacError, PolicyError) as e:
        _err(e)
    await s.commit()
    await audit(s, request, user.username, "tacacs_version_create", f"v{v.number}", {"sha256": v.sha256, "warnings": len(v.validation.get("warnings", []))})
    return {"id": v.id, "number": v.number, "sha256": v.sha256, "validation": v.validation}


@router.get("/config/versions")
async def versions(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    return {"items": await Q.version_list(s)}


@router.get("/config/versions/{vid}")
async def version_detail(vid: int, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "policy_admin", "version_view", str(vid))
    v = await _get(s, TacConfigVersion, vid, "version")
    return {"id": v.id, "number": v.number, "message": v.message, "sha256": v.sha256, "content": v.content_redacted, "validation": v.validation,
            "created_by": v.created_by, "created_at": iso(v.created_at)}


@router.get("/config/diff")
async def version_diff(a: int, b: int, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "policy_admin", "version_diff")
    va, vb = await _get(s, TacConfigVersion, a, "version"), await _get(s, TacConfigVersion, b, "version")
    return {"diff": RND.diff(va.content_redacted, vb.content_redacted, f"v{va.number}", f"v{vb.number}")}


class DeployIn(BaseModel):
    server_id: int
    action: str = Field("deploy", pattern=r"^(deploy|validate)$")
    comment: str = Field("", max_length=2000)


def _job_out(j: TacDeployJob, ver: dict | None = None) -> dict:
    return {"id": j.id, "version_id": j.version_id, "version": (ver or {}).get(j.version_id), "server_id": j.server_id, "action": j.action, "status": j.status,
            "requested_by": j.requested_by, "approved_by": j.approved_by, "approval_hash": j.approval_hash, "comment": j.comment, "result": j.result,
            "created_at": iso(j.created_at), "decided_at": iso(j.decided_at), "started_at": iso(j.started_at), "finished_at": iso(j.finished_at)}


@router.post("/config/versions/{vid}/deploy", status_code=201)
async def version_deploy(vid: int, body: DeployIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "policy_admin", f"{body.action}_request", f"v{vid}")
    _rate(user, "deploy", 10)
    v = await _get(s, TacConfigVersion, vid, "version")
    srv = await _get(s, TacServer, body.server_id, "server")
    if (await s.execute(select(TacDeployJob).where(TacDeployJob.server_id == srv.id, TacDeployJob.status.in_(["queued", "running"])))).scalars().first():
        raise HTTPException(409, "another job for this server is queued or running")
    try:
        j = await S.request_deploy(s, v, srv, user, body.comment, body.action)
    except S.TacError as e:
        _err(e)
    await s.commit()
    await audit(s, request, user.username, f"tacacs_{body.action}_request", f"v{v.number}→{srv.name}", {"job": j.id, "status": j.status})
    return _job_out(j)


@router.get("/deployments")
async def deployments(limit: int = Query(100, ge=1, le=500), _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    ver = {v.id: v.number for v in (await s.execute(select(TacConfigVersion))).scalars()}
    return {"items": [_job_out(j, ver) for j in (await s.execute(select(TacDeployJob).order_by(TacDeployJob.id.desc()).limit(limit))).scalars()]}


class DecisionIn(BaseModel):
    decision: str = Field(pattern=r"^(approve|reject)$")
    approval_hash: str = Field(min_length=64, max_length=64)
    comment: str = Field("", max_length=2000)


@router.post("/deployments/{jid}/decision")
async def deployment_decision(jid: int, body: DecisionIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    j = await _get(s, TacDeployJob, jid, "deployment")
    try:
        await S.decide(s, j, user, body.decision, body.approval_hash, body.comment)
    except S.TacError as e:
        await s.commit()  # persists a cancellation of a stale request
        s.add(AuditLog(username=user.username, action="tacacs_deploy_decision", target=str(jid), detail={"refused": e.message, "decision": body.decision},
                       client_ip=client_ip(request), success=False))
        await s.commit()
        _err(e)
    await s.commit()
    await audit(s, request, user.username, f"tacacs_deploy_{body.decision}", str(jid), {"version_id": j.version_id, "server_id": j.server_id})
    return _job_out(j)


@router.post("/deployments/{jid}/cancel")
async def deployment_cancel(jid: int, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "policy_admin", "deploy_cancel", str(jid))
    j = await _get(s, TacDeployJob, jid, "deployment")
    if j.status not in ("pending_approval", "queued"):
        raise HTTPException(409, f"job is {j.status}")
    j.status, j.finished_at = "cancelled", S.now()
    await s.commit()
    await audit(s, request, user.username, "tacacs_deploy_cancel", str(jid))
    return _job_out(j)


# ------------------------------------------------------------------ accounting explorer / sessions (auditor)
def _ev_filter(range_, user_, device, vendor, site, q, category, result, event_type, task_id, priv_lvl, server_id, severity, log_):
    return _f(range_, user=user_, device=device, vendor=vendor, site=site, q=q, category=category, result=result, event_type=event_type, task_id=task_id,
              priv_lvl=priv_lvl, server_id=server_id, severity=severity, log=log_)


EVQ = dict(range=Query("24h", pattern=RANGE), user_=Query(None, alias="user", max_length=64), device=Query(None, max_length=64),
           vendor=Query(None, pattern=VENDOR), site=Query(None, max_length=128), q=Query(None, max_length=128), category=Query(None, max_length=32),
           result=Query(None, max_length=32), event_type=Query(None, max_length=32), task_id=Query(None, max_length=64), priv_lvl=Query(None, ge=0, le=15),
           server_id=Query(None, ge=1), severity=Query(None, pattern=r"^(informational|low|medium|high)$"), log_=Query(None, alias="log", pattern=r"^(authc|authz|acct|conn)$"))


@router.get("/events")
async def events(request: Request, range: str = EVQ["range"], user_: str | None = EVQ["user_"], device: str | None = EVQ["device"],
                 vendor: str | None = EVQ["vendor"], site: str | None = EVQ["site"], q: str | None = EVQ["q"], category: str | None = EVQ["category"],
                 result: str | None = EVQ["result"], event_type: str | None = EVQ["event_type"], task_id: str | None = EVQ["task_id"],
                 priv_lvl: int | None = EVQ["priv_lvl"], server_id: int | None = EVQ["server_id"], severity: str | None = EVQ["severity"],
                 log_: str | None = EVQ["log_"], raw: bool = False, limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0),
                 user: User = Depends(current_user), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    await _need(s, request, user, "auditor", "events_view")
    return await Q.events(ch, _ev_filter(range, user_, device, vendor, site, q, category, result, event_type, task_id, priv_lvl, server_id, severity, log_),
                          limit, offset, raw)


@router.get("/events/export.csv")
async def events_export(request: Request, range: str = EVQ["range"], user_: str | None = EVQ["user_"], device: str | None = EVQ["device"],
                        vendor: str | None = EVQ["vendor"], site: str | None = EVQ["site"], q: str | None = EVQ["q"], category: str | None = EVQ["category"],
                        result: str | None = EVQ["result"], event_type: str | None = EVQ["event_type"], task_id: str | None = EVQ["task_id"],
                        priv_lvl: int | None = EVQ["priv_lvl"], server_id: int | None = EVQ["server_id"], severity: str | None = EVQ["severity"],
                        log_: str | None = EVQ["log_"], user: User = Depends(current_user), s: AsyncSession = Depends(get_session),
                        ch: ClickHouse = Depends(ch_dep)):
    await _need(s, request, user, "auditor", "events_export")
    data = await Q.events(ch, _ev_filter(range, user_, device, vendor, site, q, category, result, event_type, task_id, priv_lvl, server_id, severity, log_), 50000, 0, False)
    cols = ["ts", "event_type", "result", "msgid", "username", "device_address", "device_name", "vendor", "site", "port", "remote_addr", "service", "priv_lvl",
            "profile", "rule", "cmd", "cmd_category", "task_id", "severity"]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in data["items"]:
        w.writerow([csv_safe(r.get(c)) for c in cols])
    await audit(s, request, user.username, "tacacs_events_export", "", {"rows": len(data["items"]), "range": range})
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=tacacs-events.csv"})


@router.get("/sessions")
async def sessions(request: Request, range: str = EVQ["range"], user_: str | None = EVQ["user_"], device: str | None = EVQ["device"],
                   site: str | None = EVQ["site"], limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0), user: User = Depends(current_user),
                   s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    await _need(s, request, user, "auditor", "sessions_view")
    return await Q.sessions(ch, _f(range, user=user_, device=device, site=site), limit, offset)


# ------------------------------------------------------------------ testing center
class TestIn(BaseModel):
    server_id: int | None = None
    client_id: int | None = None
    source_id: int | None = None
    username: str = Field("", max_length=64)
    password: str = Field("", max_length=256)  # used once, never stored or logged


async def _record(s, kind, target, steps, user, server_id=None, client_id=None) -> dict:
    ok = all(x["ok"] for x in steps) if steps else False
    cat = next((x["category"] for x in steps if not x["ok"]), "")
    t = TacTestRun(kind=kind, target=target[:255], server_id=server_id, client_id=client_id, status="passed" if ok else "failed", category=cat,
                   detail="; ".join(f"{x['name']}: {x['detail']}" for x in steps)[:2000], steps=steps, requested_by=user.username,
                   started_at=datetime.fromisoformat(steps[0]["started_at"]) if steps else S.now(), finished_at=S.now())
    s.add(t)
    await s.commit()
    return {"id": t.id, "kind": kind, "target": target, "status": t.status, "category": cat, "steps": steps, "started_at": iso(t.started_at),
            "finished_at": iso(t.finished_at), "help": TC.CATEGORY_HELP.get(cat, "")}


@router.post("/tests/{kind}")
async def run_test(kind: str, body: TestIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session),
                   ch: ClickHouse = Depends(ch_dep)):
    if kind not in ("tcp", "auth", "accounting", "identity", "validate", "failover"):
        raise HTTPException(404, "unknown test")
    await _need(s, request, user, "operator", f"test_{kind}")
    _rate(user, "test", 10 if kind != "auth" else 5)
    to = get_settings().tacacs_test_timeout_seconds
    cfg = await S.settings(s)
    tester_key = S.unseal(cfg.get("tester_secret_ciphertext") or "")
    if kind == "identity":
        x = await _get(s, TacIdentitySource, body.source_id or 0, "identity source")
        if x.kind not in ("ldap", "ad"):
            raise HTTPException(422, "bind tests apply to LDAP / AD sources")
        steps = await TC.ldap_bind(x.settings or {}, S.unseal(x.bind_secret_ciphertext), to)
        x.last_test_at, x.last_test_ok = S.now(), bool(steps) and all(st["ok"] for st in steps)
        x.last_test_detail = "; ".join(f"{st['name']}: {st['detail']}" for st in steps)[:2000]
        return await _record(s, kind, x.name, steps, user)
    if kind == "failover":
        c = await _get(s, TacClient, body.client_id or 0, "client")
        steps = []
        for label, sid in (("primary", c.primary_server_id), ("secondary", c.secondary_server_id)):
            srv = await s.get(TacServer, sid) if sid else None
            if srv is None:
                steps.append({**TC._step(f"{label} server", False, datetime.now().timestamp(), "not assigned", "not_configured")})
                continue
            st = await TC.tcp(srv.management_address, srv.port, to)
            st["name"] = f"{label} {srv.name}: {st['name']}"
            steps.append(st)
        return await _record(s, kind, c.name, steps, user, client_id=c.id)
    srv = await _get(s, TacServer, body.server_id or 0, "server")
    if kind == "tcp":
        return await _record(s, kind, srv.name, [await TC.tcp(srv.management_address, srv.port, to)], user, server_id=srv.id)
    if kind == "validate":
        v = (await s.execute(select(TacConfigVersion).order_by(TacConfigVersion.number.desc()).limit(1))).scalars().first()
        if v is None:
            raise HTTPException(422, "commit a configuration version first")
        j = await S.request_deploy(s, v, srv, user, "validation from the testing center", "validate")
        await s.commit()
        return {"queued_job": j.id, "status": j.status, "note": "the deploy agent parses the version with tac_plus-ng -P; see Deployments for the result"}
    if not (cfg.get("tester_address") and tester_key):
        st = TC._step(kind, False, datetime.now().timestamp(), "tester device not configured", "not_configured")
        return await _record(s, kind, srv.name, [st], user, server_id=srv.id)
    if kind == "auth":
        if not body.username or not body.password:
            raise HTTPException(422, "username and password are required (used once, never stored)")
        since = S.now()
        step = await TC.authenticate(srv.management_address, srv.port, tester_key, body.username, body.password, to)
        steps = [step]
        if srv.kind == "managed":
            corr = await TC.correlate_auth(ch, srv.id, body.username, since)
            if corr:
                cat = {"auth_success": "", "auth_failure": "auth_reject", "auth_backend_error": "backend_unavailable",
                       "auth_policy_deny": "policy_deny"}.get(corr["event_type"], step["category"])
                steps.append({**TC._step("server log", step["ok"], since.timestamp(), f"{corr['msgid']} {corr.get('rule') or ''}".strip(), cat or "")})
            else:
                steps.append(TC._step("server log", False, since.timestamp(), "no matching authentication log line within 12 s", "not_ingested"))
        return await _record(s, kind, f"{body.username}@{srv.name}", steps, user, server_id=srv.id)
    task = f"sgtest-{int(S.now().timestamp())}"
    st = await TC.account(srv.management_address, srv.port, tester_key, "sentinel-grid-test", task, to)
    steps = [st]
    if st["ok"] and srv.kind == "managed":
        ok = await TC.wait_ingested(ch, srv.id, task)
        steps.append(TC._step("ingestion", ok, S.now().timestamp(), "record visible in the Accounting Explorer" if ok else "not ingested within 15 s",
                              "" if ok else "not_ingested"))
    return await _record(s, kind, srv.name, steps, user, server_id=srv.id)


@router.get("/tests")
async def tests(limit: int = Query(100, ge=1, le=500), _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    rows = (await s.execute(select(TacTestRun).order_by(TacTestRun.id.desc()).limit(limit))).scalars().all()
    return {"items": [{"id": t.id, "kind": t.kind, "target": t.target, "status": t.status, "category": t.category, "detail": t.detail, "steps": t.steps,
                       "requested_by": t.requested_by, "started_at": iso(t.started_at), "finished_at": iso(t.finished_at),
                       "help": TC.CATEGORY_HELP.get(t.category, "")} for t in rows]}


# ------------------------------------------------------------------ settings / roles / audit
class SettingsIn(BaseModel):
    client_networks: list[str] = Field(default_factory=list, max_length=100)
    max_prefix_without_approval: int = Field(32, ge=16, le=32)
    redaction_rules: list[str] = Field(default_factory=list, max_length=50)
    require_approval: bool = True
    tester_address: str = Field("", max_length=64)
    accounting_gap_hours: int = Field(24, ge=1, le=720)
    rotate_tester_secret: bool = False


@router.get("/settings")
async def get_settings_(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    cfg = await S.settings(s)
    return {k: v for k, v in cfg.items() if not k.endswith("ciphertext")} | {"tester_secret_set": bool(cfg.get("tester_secret_ciphertext"))}


@router.put("/settings")
async def put_settings(body: SettingsIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _need(s, request, user, "policy_admin", "settings_update")
    nets = []
    for n in body.client_networks:
        try:
            net = ipaddress.ip_network(n.strip(), strict=False)
        except ValueError:
            raise HTTPException(422, f"invalid network {n}")
        if net.prefixlen < (8 if net.version == 4 else 32) or net.is_loopback or net.is_link_local or net.is_multicast:
            raise HTTPException(422, f"{net} cannot be a client network")
        nets.append(str(net))
    for r in body.redaction_rules:
        try:
            re.compile(r)
        except re.error:
            raise HTTPException(422, f"invalid redaction regex: {r}")
    if body.tester_address:
        try:
            ip = ipaddress.ip_address(body.tester_address)
        except ValueError:
            raise HTTPException(422, "tester address must be the SIEM worker's source IP as the TACACS+ server sees it")
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
            raise HTTPException(422, "tester address cannot be loopback / unspecified / multicast")
    row = await S.get_settings_row(s)
    data = {**S.DEFAULT_SETTINGS, **(row.data or {}), **body.model_dump(exclude={"rotate_tester_secret"}), "client_networks": nets}
    shown = None
    if body.tester_address and (body.rotate_tester_secret or not data.get("tester_secret_ciphertext")):
        shown = "generated"
        data["tester_secret_ciphertext"] = S.seal(S.generate_secret())
    row.data, row.updated_by = data, user.username
    await s.commit()
    await audit(s, request, user.username, "tacacs_settings_update", "", {"client_networks": nets, "require_approval": body.require_approval,
                                                                           "tester_address": body.tester_address, "tester_secret": shown or "unchanged"})
    return {k: v for k, v in data.items() if not k.endswith("ciphertext")} | {"tester_secret_set": bool(data.get("tester_secret_ciphertext"))}


@router.get("/rbac")
async def rbac(request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    if user.role != "admin":
        raise HTTPException(403, "SIEM administrator role required")
    return {"roles": S.ROLE_HELP, "users": [{"id": u.id, "username": u.username, "siem_role": u.role, "tacacs_roles": sorted(S.roles_of(u))}
                                            for u in (await s.execute(select(User).order_by(User.username))).scalars()]}


class RbacIn(BaseModel):
    tacacs_roles: list[str] = Field(default_factory=list)


@router.put("/rbac/{uid}")
async def rbac_set(uid: int, body: RbacIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    if user.role != "admin":
        s.add(AuditLog(username=user.username, action="tacacs_rbac_update", target=str(uid), detail={"refused": "not a SIEM administrator"},
                       client_ip=client_ip(request), success=False))
        await s.commit()
        raise HTTPException(403, "SIEM administrator role required")
    if set(body.tacacs_roles) - set(S.ROLES):
        raise HTTPException(422, "unknown TACACS+ role")
    u = await _get(s, User, uid, "user")
    u.tacacs_roles = sorted(set(body.tacacs_roles))
    u.session_version = (u.session_version or 0) + 1  # role change revokes the user's sessions
    await s.commit()
    await audit(s, request, user.username, "tacacs_rbac_update", u.username, {"tacacs_roles": u.tacacs_roles})
    return {"id": u.id, "tacacs_roles": u.tacacs_roles}


@router.get("/audit")
async def tac_audit(q: str | None = Query(None, max_length=128), limit: int = Query(200, ge=1, le=1000), offset: int = Query(0, ge=0),
                    request: Request = None, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    if not ({"auditor", "policy_admin", "approver"} & S.roles_of(user)):
        raise HTTPException(403, "TACACS+ auditor, policy_admin or approver role required")
    st = select(AuditLog).where(AuditLog.action.like("tacacs_%"))
    if q:
        st = st.where(or_(AuditLog.action.ilike(f"%{q}%"), AuditLog.target.ilike(f"%{q}%"), AuditLog.username.ilike(f"%{q}%")))
    total = (await s.execute(select(func.count()).select_from(st.subquery()))).scalar_one()
    rows = (await s.execute(st.order_by(AuditLog.ts.desc()).offset(offset).limit(limit))).scalars().all()
    return {"total": total, "items": [{"ts": iso(a.ts), "user": a.username, "action": a.action, "target": a.target, "detail": a.detail, "client_ip": a.client_ip,
                                       "success": a.success} for a in rows]}


@router.get("/health")
async def health_summary(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    servers = (await s.execute(select(TacServer))).scalars().all()
    clients = (await s.execute(select(TacClient))).scalars().all()
    since = S.now() - timedelta(hours=24)
    # one aggregate for all servers (was one query per server loading every 24 h health row)
    avail = {sid: (n, up) for sid, n, up in (await s.execute(
        select(TacHealthCheck.server_id, func.count(), func.sum(case((TacHealthCheck.status == "up", 1), else_=0)))
        .where(TacHealthCheck.at >= since).group_by(TacHealthCheck.server_id))).all()}
    out = []
    for x in servers:
        n, up = avail.get(x.id, (0, 0))
        out.append({**_server_out(x), "availability_24h": round(100 * (up or 0) / n, 2) if n else None,
                    "clients_primary": sum(1 for c in clients if c.primary_server_id == x.id), "clients_secondary": sum(1 for c in clients if c.secondary_server_id == x.id)})
    no_secondary = [c.name for c in clients if c.enabled and not c.secondary_server_id]
    return {"servers": out, "clients_without_secondary": no_secondary,
            "notes": ["Device failover behaviour differs by vendor: Cisco tries servers in group order per request; FortiGate uses secondary-server when the "
                      "primary times out; FastIron tries hosts in configured order.", "Only the managed server receives configuration from the SIEM; keep "
                      "external servers' configuration in step with your own process."]}
