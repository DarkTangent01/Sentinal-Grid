"""TACACS+ AAA workflow: RBAC, settings, client and secret management, snapshots, configuration versions and the
approval-gated deployment workflow. Network devices are never changed by this module; only the TACACS+ server's
configuration is, and only through an approved job executed by the deploy agent."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import secrets as pysecrets
from datetime import datetime, timezone

from passlib.hash import sha512_crypt
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import (TacAuthPolicy, TacClient, TacCommandRule, TacConfigVersion, TacDeployJob, TacIdentitySource, TacRole,
                         TacRoleMapping, TacServer, TacSetting, TacUser, User)
from ..netguard import DestinationError, check_ip
from ..security import TokenCipher
from . import render as R
from .policy import conflicts, validate_name
from .vendors import CAPABILITIES, ROLE_TEMPLATES

ROLES = ("auditor", "operator", "policy_admin", "approver")
ROLE_HELP = {"auditor": "read accounting, command history and raw records; export", "operator": "servers and clients metadata, tests",
             "policy_admin": "identities, roles, policies, command rules, configuration versions, deploy requests",
             "approver": "approve or reject deployments (never their own)"}
TESTER = "sentinel_grid_tester"
DEFAULT_SETTINGS = {"client_networks": [], "max_prefix_without_approval": 32, "redaction_rules": [], "require_approval": True,
                    "tester_address": "", "accounting_gap_hours": 24}


class TacError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def now() -> datetime:
    return datetime.now(timezone.utc)


def aware(v):
    if v is None:
        return None
    return v if v.tzinfo else v.replace(tzinfo=timezone.utc)


def roles_of(user: User) -> set[str]:
    r = set(user.tacacs_roles or [])
    if user.role == "admin":
        r |= set(ROLES)
    return r


def require(user: User, role: str) -> None:
    if role not in roles_of(user):
        raise TacError(403, f"TACACS+ '{role}' role required")


def seal(v: str) -> str:
    return TokenCipher().encrypt(v) if v else ""


def unseal(v: str) -> str:
    return TokenCipher().decrypt(v) if v else ""


async def get_settings_row(s: AsyncSession) -> TacSetting:
    row = (await s.execute(select(TacSetting).order_by(TacSetting.id))).scalars().first()
    if row is None:
        row = TacSetting(data=dict(DEFAULT_SETTINGS))
        s.add(row)
        await s.flush()
    return row


async def settings(s: AsyncSession) -> dict:
    return {**DEFAULT_SETTINGS, **((await get_settings_row(s)).data or {})}


def generate_secret() -> str:
    """32 characters from [A-Za-z0-9_-]: accepted by FortiOS, IOS and FastIron key fields without quoting."""
    return pysecrets.token_urlsafe(24)


def hash_password(pw: str) -> str:
    if not pw or len(pw) < 12 or len(pw) > 128:
        raise TacError(422, "local TACACS+ passwords must be 12-128 characters")
    return sha512_crypt.using(rounds=656000).hash(pw)


# ------------------------------------------------------------------ client address validation
def validate_client_address(addr: str, cfg: dict, *, existing: list[TacClient], self_id: int | None = None,
                            wide_justification: str = "") -> tuple[str, bool]:
    """→ (normalised address, needs wide-CIDR approval). Refuses addresses outside the authorised client networks,
    overlaps with other clients, loopback / link-local / multicast and anything wider than /16."""
    try:
        net = ipaddress.ip_network(addr.strip(), strict=False)
    except ValueError:
        raise TacError(422, "client address must be an IP address or CIDR")
    try:
        check_ip(net.network_address)
    except DestinationError as e:
        raise TacError(422, str(e))
    if net.prefixlen < (16 if net.version == 4 else 48):
        raise TacError(422, "client ranges wider than /16 (IPv4) or /48 (IPv6) are not accepted")
    nets = [ipaddress.ip_network(n, strict=False) for n in cfg.get("client_networks") or []]
    if not any(net.subnet_of(n) for n in nets if n.version == net.version):
        raise TacError(422, f"{net} is not inside an authorised client network (TACACS+ → Settings → client networks)")
    for c in existing:
        if c.id == self_id:
            continue
        other = ipaddress.ip_network(c.address, strict=False)
        if other.version == net.version and net.overlaps(other):
            raise TacError(409, f"{net} overlaps the client {c.name} ({c.address})")
    single = net.prefixlen == net.max_prefixlen
    wide = not single and net.prefixlen < int(cfg.get("max_prefix_without_approval", 32))
    if wide and len(wide_justification.strip()) < 10:
        raise TacError(422, f"{net} covers {net.num_addresses} addresses: a justification is required and the range is recorded as an approved exception")
    return (str(net.network_address) if single else str(net)), wide


# ------------------------------------------------------------------ snapshot
async def snapshot(s: AsyncSession, *, with_secrets: bool) -> tuple[dict, dict]:
    clients = (await s.execute(select(TacClient).order_by(TacClient.name))).scalars().all()
    sources = (await s.execute(select(TacIdentitySource).order_by(TacIdentitySource.id))).scalars().all()
    src_kind = {x.id: x.kind for x in sources}
    users = (await s.execute(select(TacUser).order_by(TacUser.username))).scalars().all()
    roles = (await s.execute(select(TacRole))).scalars().all()
    maps = (await s.execute(select(TacRoleMapping))).scalars().all()
    rules = (await s.execute(select(TacCommandRule))).scalars().all()
    pols = (await s.execute(select(TacAuthPolicy))).scalars().all()
    cfg = await settings(s)
    iso = lambda d: d.isoformat() if d else None  # noqa: E731
    snap = {
        "clients": [{"id": c.id, "name": c.name, "address": c.address, "vendor": c.vendor, "site": c.site, "device_group": c.device_group,
                     "enabled": c.enabled, "rotation": c.rotation_state, "secret_version": c.secret_version} for c in clients],
        "sources": [{"id": x.id, "name": x.name, "kind": x.kind, "enabled": x.enabled,
                     "settings": {k: v for k, v in (x.settings or {}).items() if k != "bind_password"}} for x in sources],
        "users": [{"username": u.username, "source_kind": "local" if src_kind.get(u.source_id) == "local" else "directory", "enabled": u.enabled,
                   "emergency": u.emergency, "groups": u.groups or [], "valid_until": iso(u.valid_until),
                   "password_hash": u.password_hash if with_secrets else ("set" if u.password_hash else "")} for u in users],
        "roles": {r.id: {"id": r.id, "name": r.name, "privileged": r.privileged, "vendor_profiles": r.vendor_profiles or {},
                         "default_command_action": r.default_command_action, "command_categories": r.command_categories or []} for r in roles},
        "mappings": [{"id": m.id, "principal_type": m.principal_type, "principal": m.principal, "role_id": m.role_id, "scope_sites": m.scope_sites or [],
                      "scope_device_groups": m.scope_device_groups or [], "scope_vendors": m.scope_vendors or [], "scope_clients": m.scope_clients or [],
                      "time_window": m.time_window or "", "priority": m.priority, "expires_at": iso(m.expires_at), "enabled": m.enabled} for m in maps],
        "rules": [{"id": r.id, "role_id": r.role_id, "vendor": r.vendor, "action": r.action, "match": r.match, "pattern": r.pattern, "category": r.category,
                   "priority": r.priority, "exception": r.exception, "owner": r.owner, "expires_at": iso(r.expires_at), "enabled": r.enabled} for r in rules],
        "policies": [{"name": p.name, "device_groups": p.device_groups or [], "allowed_sources": p.allowed_sources or ["local", "directory"],
                      "allow_emergency": p.allow_emergency, "priority": p.priority, "enabled": p.enabled} for p in pols],
    }
    sec: dict = {"clients": {}, "sources": {}}
    for c in clients:
        keys = []
        if c.secret_ciphertext:
            keys.append(unseal(c.secret_ciphertext) if with_secrets else "x")
        if c.pending_secret_ciphertext:
            keys.append(unseal(c.pending_secret_ciphertext) if with_secrets else "x")
        sec["clients"][c.name] = keys
    for x in sources:
        if x.bind_secret_ciphertext:
            sec["sources"][x.name] = unseal(x.bind_secret_ciphertext) if with_secrets else "x"
    tk = cfg.get("tester_secret_ciphertext") or ""
    if cfg.get("tester_address") and tk:
        sec["tester"] = {"address": cfg["tester_address"], "key": unseal(tk) if with_secrets else "x"}
    return snap, sec


def validation(snap: dict) -> dict:
    """Errors block a version; warnings are shown with it."""
    errors, warnings = [], []
    vendors = {c["vendor"] for c in snap["clients"] if c.get("enabled", True)}
    for r in snap["roles"].values():
        for v in vendors:
            if not (r.get("vendor_profiles") or {}).get(v):
                warnings.append(f"role {r['name']} has no {CAPABILITIES[v]['label']} profile: exec authorization returns no privilege on those devices")
    if "fortinet" in vendors and any(r["vendor"] in ("fortinet", "any") for r in snap["rules"]):
        warnings.append("command rules do not apply to FortiGates (no per-command authorization in FortiOS)")
    if not any(u.get("emergency") and u.get("enabled", True) for u in snap["users"]):
        warnings.append("no emergency account defined: keep device-local emergency access configured")
    if not snap["mappings"]:
        warnings.append("no role mappings: every authentication will be denied by the default-deny ruleset")
    for c in conflicts(snap):
        (errors if c["type"] == "exception_incomplete" else warnings).append(f"{c['type']}: {c['detail']} ({c['role']})")
    return {"errors": errors, "warnings": warnings, "ok": not errors}


async def commit_version(s: AsyncSession, user: str, message: str) -> TacConfigVersion:
    snap, sec = await snapshot(s, with_secrets=True)
    v = validation(snap)
    if not v["ok"]:
        raise TacError(422, "configuration is not valid: " + "; ".join(v["errors"]))
    full = R.render(snap, sec, redact=False)
    red = R.render(snap, sec, redact=True)
    snap_public = json.loads(json.dumps({**snap, "users": [{**u, "password_hash": "set" if u.get("password_hash") else ""} for u in snap["users"]]},
                                        default=str))
    last = (await s.execute(select(func.max(TacConfigVersion.number)))).scalar() or 0
    ver = TacConfigVersion(number=last + 1, message=message[:2000], content_redacted=red, content_ciphertext=seal(full), sha256=R.sha256(full),
                           model=snap_public, validation=v, created_by=user)
    s.add(ver)
    await s.flush()
    return ver


def approval_hash(ver: TacConfigVersion, server: TacServer, base: str) -> str:
    return hashlib.sha256(f"{ver.sha256}|{server.id}|{base}".encode()).hexdigest()


async def request_deploy(s: AsyncSession, ver: TacConfigVersion, server: TacServer, user: User, comment: str, action: str = "deploy") -> TacDeployJob:
    if server.kind != "managed":
        raise TacError(422, "only managed (tac_plus-ng + agent) servers can receive configuration")
    cfg = await settings(s)
    need = action == "deploy" and (cfg.get("require_approval", True) or server.environment == "production")
    job = TacDeployJob(version_id=ver.id, server_id=server.id, action=action, status="pending_approval" if need else "queued", requested_by=user.username,
                       base_sha256=server.deployed_sha256 or (server.agent or {}).get("active_sha256") or "", comment=comment[:2000])
    job.approval_hash = approval_hash(ver, server, job.base_sha256)
    s.add(job)
    await s.flush()
    return job


async def decide(s: AsyncSession, job: TacDeployJob, user: User, decision: str, plan_hash: str, comment: str) -> TacDeployJob:
    require(user, "approver")
    if job.status != "pending_approval":
        raise TacError(409, f"job is {job.status}")
    if job.requested_by == user.username:
        raise TacError(403, "separation of duties: you cannot approve your own deployment request")
    ver = await s.get(TacConfigVersion, job.version_id)
    server = await s.get(TacServer, job.server_id)
    current = server.deployed_sha256 or (server.agent or {}).get("active_sha256") or ""
    if plan_hash != job.approval_hash:
        raise TacError(409, "the approval does not match this request (stale page or replayed approval)")
    if current != job.base_sha256 or approval_hash(ver, server, current) != job.approval_hash:
        job.status, job.decided_at = "cancelled", now()
        job.result = {"reason": "the server's active configuration changed after the request; request again"}
        raise TacError(409, job.result["reason"])
    job.status = "queued" if decision == "approve" else "rejected"
    job.approved_by, job.decided_at = user.username, now()
    job.comment = (job.comment + f"\n[{user.username}] {comment}").strip()[:4000]
    return job


def seed_roles() -> list[TacRole]:
    return [TacRole(name=t["name"], description=t["description"], privileged=t["privileged"], vendor_profiles=t["vendor_profiles"],
                    command_categories=t["command_categories"], default_command_action="deny", created_by="system") for t in ROLE_TEMPLATES]


def validate_vendor_profiles(vp: dict) -> dict:
    out = {}
    for v, p in (vp or {}).items():
        if v not in CAPABILITIES:
            raise TacError(422, f"unknown vendor {v}")
        if v in ("cisco", "other"):
            lvl = int(p.get("priv_lvl", 1))
            if not 0 <= lvl <= 15:
                raise TacError(422, "Cisco priv-lvl must be 0-15")
            out[v] = {"priv_lvl": lvl}
        elif v == "ruckus":
            lvl = int(p.get("priv_lvl", 5))
            if lvl not in (0, 4, 5):
                raise TacError(422, "Ruckus foundry-privlvl must be 0 (super-user), 4 (port-config) or 5 (read-only)")
            out[v] = {"priv_lvl": lvl}
        elif v == "fortinet":
            out[v] = {"admin_profile": validate_name(str(p.get("admin_profile") or ""), "FortiGate admin profile")}
    return out
