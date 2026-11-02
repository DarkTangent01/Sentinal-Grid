"""IaC workflow: settings, roles, hash-chained audit, versions, device observation, plans, approvals, deployment
queueing, drift detection, backups and recovery plans. Device execution lives in executor.py (worker)."""
from __future__ import annotations

import asyncio
import hashlib
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db.models import (Firewall, IacApproval, IacAudit, IacBackup, IacDevice, IacDrift, IacJob, IacJobDevice, IacLock, IacPlan,
                         IacPlanChange, IacProject, IacSetting, IacVersion, User)
from . import adapters
from .diff import SEV, classify, compute, counts
from .resources import TYPES, canonical_hash, redact
from .rules import evaluate, load_ruleset, plan_findings, worst
from .schema import ConfigError, declared_types, parse, render, variables_for

ROLES = ("editor", "approver", "deployer", "admin")
CLIENT_IP: ContextVar[str] = ContextVar("iac_client_ip", default="")  # set per API request
ACTIVE_JOB = ("queued", "running")
DEFAULT_SETTINGS = {"writes_enabled": False, "sod_production": True, "sod_all_environments": False, "fail_fast": True,
                    "drift_interval_minutes": 60, "require_full_backup_production": False, "plan_max_age_hours": 24}


class IacError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def now() -> datetime:
    return datetime.now(timezone.utc)


def aware(dt):
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ------------------------------------------------------------------ settings and roles
async def get_iac_settings(s: AsyncSession) -> dict:
    row = await s.get(IacSetting, 1)
    return {**DEFAULT_SETTINGS, **((row.data if row else None) or {})}


async def put_iac_settings(s: AsyncSession, data: dict, user: str) -> dict:
    row = await s.get(IacSetting, 1)
    if row is None:
        row = IacSetting(id=1, data={})
        s.add(row)
    row.data = {**DEFAULT_SETTINGS, **(row.data or {}), **{k: v for k, v in data.items() if k in DEFAULT_SETTINGS}}
    row.updated_by = user
    await s.commit()
    return row.data


def writes_effective(settings: dict) -> tuple[bool, str]:
    if not get_settings().iac_device_writes:
        return False, "IAC_DEVICE_WRITES is not enabled on the server (environment); deployments can only run as dry runs"
    if not settings.get("writes_enabled"):
        return False, "device writes are disabled in the IaC settings; an IaC administrator must enable them"
    return True, ""


def roles_of(user: User) -> set[str]:
    r = set(user.iac_roles or [])
    if user.role == "admin":
        r |= set(ROLES)
    return r


def require(user: User, role: str) -> None:
    if role != "viewer" and role not in roles_of(user):
        raise IacError(403, f"IaC '{role}' role required")


# ------------------------------------------------------------------ tamper-evident audit
async def audit(s: AsyncSession, user: str, action: str, *, project_id=None, plan_id=None, job_id=None, target: str = "",
                detail: dict | None = None, client_ip: str = "", commit: bool = True) -> IacAudit:
    if s.bind.dialect.name == "postgresql":
        await s.execute(text("SELECT pg_advisory_xact_lock(724519)"))  # serialise the chain across API and worker
    last = (await s.execute(select(IacAudit.hash).order_by(IacAudit.id.desc()).limit(1))).scalar() or ""
    ts = now()
    body = {"ts": ts.isoformat(), "username": user, "action": action, "project_id": project_id, "plan_id": plan_id, "job_id": job_id,
            "target": target[:255], "detail": redact(detail or {}), "client_ip": client_ip or CLIENT_IP.get()}
    row = IacAudit(ts=ts, username=user, action=action, project_id=project_id, plan_id=plan_id, job_id=job_id, target=target[:255],
                   detail=body["detail"], client_ip=body["client_ip"], prev_hash=last, hash=hashlib.sha256((last + canonical_hash(body)).encode()).hexdigest())
    s.add(row)
    if commit:
        await s.commit()
    return row


async def verify_audit(s: AsyncSession) -> dict:
    prev, n = "", 0
    for r in (await s.execute(select(IacAudit).order_by(IacAudit.id))).scalars():
        body = {"ts": aware(r.ts).isoformat(), "username": r.username, "action": r.action, "project_id": r.project_id, "plan_id": r.plan_id,
                "job_id": r.job_id, "target": r.target, "detail": r.detail, "client_ip": r.client_ip}
        if r.prev_hash != prev or r.hash != hashlib.sha256((prev + canonical_hash(body)).encode()).hexdigest():
            return {"ok": False, "checked": n, "broken_at": r.id}
        prev, n = r.hash, n + 1
    return {"ok": True, "checked": n, "broken_at": None}


# ------------------------------------------------------------------ versions
def validate_text(content: str, rs: dict, environment: str) -> dict:
    """Schema + render with default variables + security rules (no device). Returns a validation report."""
    try:
        doc = parse(content)
    except ConfigError as e:
        return {"valid": False, "errors": e.errors, "findings": [], "declared": []}
    desired, order, errs = render(doc, variables_for(doc, "", ""))
    findings = evaluate(rs, desired, order, environment) if not errs else []
    return {"valid": not errs, "errors": errs, "findings": findings, "declared": sorted(declared_types(doc)),
            "counts": {t: len(v) for t, v in desired.items() if v}}


async def commit_version(s: AsyncSession, project: IacProject, content: str, message: str, user: str) -> IacVersion:
    rs = await load_ruleset(s, project.id)
    report = validate_text(content, rs, project.environment)
    last = (await s.execute(select(IacVersion).where(IacVersion.project_id == project.id).order_by(IacVersion.number.desc()).limit(1))).scalars().first()
    if last and last.content_hash == hashlib.sha256(content.encode()).hexdigest():
        raise IacError(409, f"no changes since version {last.number}")
    v = IacVersion(project_id=project.id, number=(last.number + 1) if last else 1, content=content,
                   content_hash=hashlib.sha256(content.encode()).hexdigest(), message=message[:2000], author=user,
                   parent_id=last.id if last else None, valid=report["valid"], validation=report)
    s.add(v)
    project.draft_content, project.draft_base_version_id = content, None
    await s.flush()
    project.draft_base_version_id = v.id
    await audit(s, user, "version_commit", project_id=project.id, target=f"v{v.number}",
                detail={"hash": v.content_hash, "valid": v.valid, "message": message[:200]}, commit=False)
    await s.commit()
    return v


# ------------------------------------------------------------------ device observation
async def observe(s: AsyncSession, dev: IacDevice, fw: Firewall) -> dict:
    """Read the device's managed tables (GET only) and store the normalised state."""
    ad = adapters.make_adapter(fw, integration=dev.integration)
    try:
        snap = await ad.read_state(list(TYPES))
    finally:
        await ad.close()
    h = canonical_hash({"state": snap["state"], "order": snap["order"]})
    dev.observed = {"state": snap["state"], "order": snap["order"], "refs": snap["refs"], "errors": snap["errors"]}
    dev.observed_hash, dev.observed_at = h, now()
    return dev.observed


async def refresh_capabilities(s: AsyncSession, dev: IacDevice, fw: Firewall) -> dict:
    ad = adapters.make_adapter(fw, integration=dev.integration)
    try:
        caps = await ad.capabilities()
    finally:
        await ad.close()
    caps["checked_at"] = now().isoformat()
    if caps.get("fortimanager"):
        dev.integration = "fortimanager"
    dev.capabilities = caps
    await s.commit()
    return caps


async def _project_devices(s: AsyncSession, project_id: int, firewall_ids: list[int] | None = None) -> list[tuple[IacDevice, Firewall]]:
    q = select(IacDevice, Firewall).join(Firewall, Firewall.id == IacDevice.firewall_id).where(IacDevice.project_id == project_id,
                                                                                               IacDevice.managed.is_(True))
    if firewall_ids:
        q = q.where(IacDevice.firewall_id.in_(firewall_ids))
    return list((await s.execute(q)).all())


# ------------------------------------------------------------------ plans
def _plan_hash(version_hash: str, targets: list[int], observed: dict, ruleset_hash: str, changes: list[dict]) -> str:
    return canonical_hash({"version": version_hash, "targets": sorted(targets), "observed": {str(k): v for k, v in sorted(observed.items())},
                           "ruleset": ruleset_hash,
                           "changes": [(c["firewall_id"], c["type"], c["key"], c["action"], c.get("desired"), c.get("current")) for c in changes]})


async def create_plan(s: AsyncSession, project: IacProject, user: str, *, version: IacVersion | None = None,
                      firewall_ids: list[int] | None = None, recovery: IacBackup | None = None) -> IacPlan:
    """Read every target device (GET), render the desired state per device, diff, classify, validate and persist an
    immutable plan whose hash binds the version, targets, observed device state, rule set and every change."""
    rs = await load_ruleset(s, project.id)
    devs = await _project_devices(s, project.id, [recovery.firewall_id] if recovery else firewall_ids)
    if not devs:
        raise IacError(422, "no managed devices selected for this project")
    if len(devs) > get_settings().iac_max_plan_devices:
        raise IacError(422, f"a plan may target at most {get_settings().iac_max_plan_devices} devices")
    doc = None
    if recovery is None:
        if version is None:
            raise IacError(422, "version required")
        try:
            doc = parse(version.content)
        except ConfigError as e:
            raise IacError(422, f"version {version.number} is not valid: {e}")
    settings = await get_iac_settings(s)
    all_changes, findings, errors, observed_hashes = [], [], [], {}
    sem = asyncio.Semaphore(4)

    async def read(dev, fw):
        async with sem:
            try:
                await observe(s, dev, fw)
            except Exception as e:  # noqa: BLE001 - recorded as plan error, never hidden
                errors.append({"firewall_id": fw.id, "firewall_name": fw.name, "message": f"cannot read device: {redact(str(e))[:300]}"})
    await asyncio.gather(*(read(d, f) for d, f in devs))
    for dev, fw in devs:
        if dev.observed is None or any(e["firewall_id"] == fw.id for e in errors):
            continue
        obs = dev.observed
        observed_hashes[str(fw.id)] = dev.observed_hash
        if recovery is not None:
            snap = recovery.snapshot
            desired, order = snap.get("state", {}), snap.get("order", [])
            created = {}
            job_dev = (await s.execute(select(IacJobDevice).where(IacJobDevice.job_id == recovery.job_id,
                                                                   IacJobDevice.firewall_id == fw.id))).scalars().first() if recovery.job_id else None
            touched = set()
            for r in (job_dev.results if job_dev else []):
                touched.add(r["type"])
                if r.get("action") == "create" and r.get("ok"):
                    created.setdefault(r["type"], []).append(r["key"])
            managed = (touched or set(desired)) & set(TYPES)
            prune, prev = set(), created
        else:
            desired, order, rerr = render(doc, variables_for(doc, fw.name, fw.site or "", dev.variables))
            for e in rerr:
                errors.append({**e, "firewall_id": fw.id, "firewall_name": fw.name})
            if rerr:
                continue
            prune = set(doc.manage.prune)
            prev = dev.managed_keys or {}
            managed = declared_types(doc) | prune | {t for t, ks in prev.items() if ks}
            findings += evaluate(rs, desired, order, project.environment, observed=obs["state"], refs=obs["refs"],
                                 firewall_id=fw.id, firewall_name=fw.name)
        unreadable = [t for t in managed if t in obs.get("errors", {})]
        if unreadable:
            errors.append({"firewall_id": fw.id, "firewall_name": fw.name,
                           "message": f"cannot read {', '.join(unreadable)} on the device; the plan would be incomplete"})
            continue
        ch = compute(desired, obs["state"], managed_types=managed, prune_types=prune, previously_managed=prev,
                     desired_order=order, observed_order=obs["order"], ignored=doc.manage.ignored() if doc else None)
        for c in ch:
            c["firewall_id"], c["firewall_name"] = fw.id, fw.name
            c.update(classify(c, rs["overrides"]))
        findings += plan_findings(rs, ch, obs["state"], project.environment, fw.id, fw.name, dev.drift_status)
        all_changes += ch
    targets = [f.id for _, f in devs]
    vhash = version.content_hash if version else recovery.snapshot_sha256
    blocking = bool(errors) or any(f["blocks"] for f in findings)
    plan = IacPlan(project_id=project.id, version_id=version.id if version else None, version_hash=vhash,
                   kind="recovery" if recovery else "change", recovery_backup_id=recovery.id if recovery else None,
                   environment=project.environment, targets=targets, observed_hashes=observed_hashes, ruleset_hash=rs["hash"],
                   findings=findings, errors=errors, blocking=blocking, created_by=user,
                   destructive=any(c["action"] == "delete" or c["disruptive"] for c in all_changes))
    plan.summary = {
        "create": sum(c["action"] == "create" for c in all_changes), "update": sum(c["action"] == "update" for c in all_changes),
        "delete": sum(c["action"] == "delete" for c in all_changes), "move": sum(c["action"] == "move" for c in all_changes),
        "devices": len(targets), "devices_with_changes": len({c["firewall_id"] for c in all_changes}),
        "no_op_devices": [f.name for _, f in devs if f.id not in {c["firewall_id"] for c in all_changes} and str(f.id) in observed_hashes],
        "risk": counts(all_changes), "finding_severity": counts(findings, "severity"), "worst_finding": worst(findings),
        "disruptive": sum(c["disruptive"] for c in all_changes), "blocking_findings": sum(f["blocks"] for f in findings),
        "writes_effective": writes_effective(settings)[0]}
    plan.plan_hash = _plan_hash(vhash, targets, observed_hashes, rs["hash"], all_changes)
    plan.status = "validation_failed" if blocking else ("ready_for_review" if all_changes else "ready_for_review")
    s.add(plan)
    await s.flush()
    for i, c in enumerate(all_changes):
        s.add(IacPlanChange(plan_id=plan.id, firewall_id=c["firewall_id"], seq=i, resource_type=c["type"], resource_id=c["key"],
                            action=c["action"], current=c.get("current"), desired=c.get("desired"), fields=c.get("fields", []),
                            depends_on=c.get("depends_on", []), risk=c["risk"], rule_id=c["rule_id"], impact=c["impact"],
                            disruptive=c["disruptive"]))
    await audit(s, user, "plan_create", project_id=project.id, plan_id=plan.id, target=f"plan {plan.id}",
                detail={"version": version.number if version else None, "recovery_backup": recovery.id if recovery else None,
                        "hash": plan.plan_hash, "summary": {k: plan.summary[k] for k in ("create", "update", "delete", "move")},
                        "status": plan.status}, commit=False)
    await s.commit()
    return plan


async def plan_changes(s: AsyncSession, plan_id: int) -> list[IacPlanChange]:
    return list((await s.execute(select(IacPlanChange).where(IacPlanChange.plan_id == plan_id).order_by(IacPlanChange.seq))).scalars())


async def mark_stale(s: AsyncSession, plan: IacPlan, reason: str, user: str = "system") -> None:
    plan.status, plan.stale_reason = "stale", reason
    await audit(s, user, "plan_stale", project_id=plan.project_id, plan_id=plan.id, detail={"reason": reason}, commit=False)
    await s.commit()


async def staleness(s: AsyncSession, plan: IacPlan, *, read_devices: bool) -> str:
    """Reason the plan no longer reflects reality ('' if fresh). Reading devices is GET-only."""
    settings = await get_iac_settings(s)
    if now() - aware(plan.created_at) > timedelta(hours=float(settings["plan_max_age_hours"])):
        return f"plan is older than {settings['plan_max_age_hours']} hours"
    if plan.version_id:
        v = await s.get(IacVersion, plan.version_id)
        if v is None or v.content_hash != plan.version_hash:
            return "the configuration version changed"
    rs = await load_ruleset(s, plan.project_id)
    if rs["hash"] != plan.ruleset_hash:
        return "validation rules or exceptions changed since planning"
    devs = await _project_devices(s, plan.project_id, plan.targets)
    if {f.id for _, f in devs} != set(plan.targets):
        return "the set of managed target devices changed"
    if read_devices:
        for dev, fw in devs:
            try:
                await observe(s, dev, fw)
            except Exception as e:  # noqa: BLE001
                return f"cannot re-read {fw.name}: {redact(str(e))[:200]}"
            if dev.observed_hash != plan.observed_hashes.get(str(fw.id)):
                await s.commit()
                return f"{fw.name}'s live configuration changed since planning"
        await s.commit()
    return ""


async def submit(s: AsyncSession, plan: IacPlan, user: User) -> IacPlan:
    require(user, "editor")
    if plan.status != "ready_for_review":
        raise IacError(409, f"plan is {plan.status}; only plans ready for review can be submitted")
    plan.status = "pending_approval"
    await audit(s, user.username, "plan_submit", project_id=plan.project_id, plan_id=plan.id, detail={"hash": plan.plan_hash}, commit=False)
    await s.commit()
    return plan


async def decide(s: AsyncSession, plan: IacPlan, user: User, decision: str, comment: str, plan_hash: str, acknowledge_destructive: bool) -> IacPlan:
    require(user, "approver")
    if plan.status != "pending_approval":
        raise IacError(409, f"plan is {plan.status}; only plans pending approval can be decided")
    if plan_hash != plan.plan_hash:
        raise IacError(409, "the plan changed since you reviewed it (hash mismatch); reload and review again")
    settings = await get_iac_settings(s)
    sod = settings["sod_all_environments"] or (settings["sod_production"] and plan.environment == "production")
    if sod and decision == "approve":
        authors = {plan.created_by}
        if plan.version_id:
            v = await s.get(IacVersion, plan.version_id)
            if v:
                authors.add(v.author)
        if user.username in authors:
            raise IacError(403, "separation of duties: you created this plan or its configuration version; another approver must decide")
    if decision == "approve":
        if plan.blocking:
            raise IacError(409, "plan has blocking validation findings or errors")
        reason = await staleness(s, plan, read_devices=False)
        if reason:
            await mark_stale(s, plan, reason, user.username)
            raise IacError(409, f"plan is stale: {reason}; generate a new plan")
        if plan.destructive and not acknowledge_destructive:
            raise IacError(422, "this plan deletes or disrupts configuration; acknowledge the destructive changes to approve")
    s.add(IacApproval(plan_id=plan.id, username=user.username, decision=decision, comment=comment[:2000], plan_hash=plan.plan_hash,
                      acknowledged_destructive=acknowledge_destructive))
    plan.status = "approved" if decision == "approve" else "rejected"
    if decision == "approve" and plan.version_id:
        v = await s.get(IacVersion, plan.version_id)
        project = await s.get(IacProject, plan.project_id)
        if v and project:
            v.approved_at = v.approved_at or now()
            project.approved_version_id = v.id
    await audit(s, user.username, f"plan_{decision}", project_id=plan.project_id, plan_id=plan.id,
                detail={"hash": plan.plan_hash, "comment": comment[:200], "ack_destructive": acknowledge_destructive}, commit=False)
    await s.commit()
    return plan


async def queue_job(s: AsyncSession, plan: IacPlan, user: User, *, dry_run: bool, acknowledge_destructive: bool) -> IacJob:
    """Deploy (approved plans only) or dry-run (any non-failed plan; never writes). Locks are taken by the worker;
    here we refuse a second active job for the same devices."""
    if dry_run:
        require(user, "editor")
        if plan.status in ("validation_failed", "rejected", "cancelled", "stale"):
            raise IacError(409, f"plan is {plan.status}")
    else:
        require(user, "deployer")
        if plan.status != "approved":
            raise IacError(409, f"plan is {plan.status}; only approved plans can be deployed")
        appr = (await s.execute(select(IacApproval).where(IacApproval.plan_id == plan.id, IacApproval.decision == "approve")
                                .order_by(IacApproval.id.desc()))).scalars().first()
        if appr is None or appr.plan_hash != plan.plan_hash:
            raise IacError(409, "approval is not bound to this exact plan; approve again")
        if plan.destructive and not acknowledge_destructive:
            raise IacError(422, "acknowledge the destructive changes to deploy")
        settings = await get_iac_settings(s)
        ok, why = writes_effective(settings)
        if not ok:
            raise IacError(409, why)
        reason = await staleness(s, plan, read_devices=False)
        if reason:
            await mark_stale(s, plan, reason, user.username)
            raise IacError(409, f"plan is stale: {reason}; generate a new plan")
    busy = (await s.execute(select(IacJob).join(IacPlan, IacPlan.id == IacJob.plan_id).where(
        IacJob.status.in_(ACTIVE_JOB), IacJob.kind == "deploy"))).scalars().all()
    for j in busy:
        p = await s.get(IacPlan, j.plan_id)
        if p and set(p.targets) & set(plan.targets) and not dry_run:
            raise IacError(409, f"job {j.id} is already deploying to one of these devices")
    job = IacJob(plan_id=plan.id, project_id=plan.project_id, kind="dry_run" if dry_run else "deploy", plan_hash=plan.plan_hash,
                 requested_by=user.username, progress={"devices": len(plan.targets), "done": 0})
    s.add(job)
    await s.flush()
    for fid in plan.targets:
        s.add(IacJobDevice(job_id=job.id, firewall_id=fid))
    if not dry_run:
        plan.status = "queued"
    await audit(s, user.username, "job_queue", project_id=plan.project_id, plan_id=plan.id, job_id=job.id,
                detail={"kind": job.kind, "hash": plan.plan_hash}, commit=False)
    await s.commit()
    return job


async def cancel_job(s: AsyncSession, job: IacJob, user: User) -> IacJob:
    require(user, "deployer")
    if job.status == "queued":
        job.status, job.finished_at, job.error = "cancelled", now(), f"cancelled by {user.username} before it started"
        if job.plan_id and job.kind == "deploy":
            p = await s.get(IacPlan, job.plan_id)
            if p and p.status == "queued":
                p.status = "approved"
    elif job.status == "running":
        job.cancel_requested = True  # honoured between changes; a request already sent to a device cannot be recalled
    else:
        raise IacError(409, f"job is {job.status}")
    await audit(s, user.username, "job_cancel", project_id=job.project_id, plan_id=job.plan_id, job_id=job.id, detail={"status": job.status}, commit=False)
    await s.commit()
    return job


# ------------------------------------------------------------------ locks
async def acquire_locks(firewall_ids: list[int], job_id: int, ttl_seconds: int) -> bool:
    """All-or-nothing device locks (own session, so a conflict cannot expire the caller's objects)."""
    from ..db.pg import session_factory
    t = now()
    async with session_factory()() as ls:
        await ls.execute(delete(IacLock).where(IacLock.firewall_id.in_(firewall_ids), IacLock.expires_at < t))
        await ls.commit()
        try:
            for fid in firewall_ids:
                ls.add(IacLock(firewall_id=fid, job_id=job_id, acquired_at=t, expires_at=t + timedelta(seconds=ttl_seconds)))
            await ls.commit()
            return True
        except Exception:  # IntegrityError: another job holds one of the devices
            await ls.rollback()
            return False


async def release_locks(job_id: int) -> None:
    from ..db.pg import session_factory
    async with session_factory()() as ls:
        await ls.execute(delete(IacLock).where(IacLock.job_id == job_id))
        await ls.commit()


# ------------------------------------------------------------------ backups
def snapshot_hash(snap: dict) -> str:
    return canonical_hash(snap)


async def store_backup(s: AsyncSession, fw: Firewall, snap: dict, full_text: str | None, note: str, *, job_id=None, plan_id=None,
                       kind="pre_change", user="system") -> IacBackup:
    from ..security import TokenCipher
    b = IacBackup(firewall_id=fw.id, job_id=job_id, plan_id=plan_id, kind=kind, snapshot=snap, snapshot_sha256=snapshot_hash(snap),
                  full_config_note=note, created_by=user)
    if full_text:
        b.full_config_sha256 = hashlib.sha256(full_text.encode()).hexdigest()
        b.full_config_ciphertext = TokenCipher().encrypt(full_text)
    s.add(b)
    await s.flush()
    b.validated, _ = validate_backup(b)
    await s.commit()
    return b


def validate_backup(b: IacBackup) -> tuple[bool, str]:
    if snapshot_hash(b.snapshot) != b.snapshot_sha256:
        return False, "resource snapshot checksum mismatch"
    if not (b.snapshot or {}).get("state"):
        return False, "resource snapshot is empty"
    if b.full_config_ciphertext:
        from ..security import TokenCipher
        try:
            txt = TokenCipher().decrypt(b.full_config_ciphertext)
        except RuntimeError:
            return False, "full configuration cannot be decrypted with the current key"
        if hashlib.sha256(txt.encode()).hexdigest() != b.full_config_sha256:
            return False, "full configuration checksum mismatch"
    return True, "checksums verified"


# ------------------------------------------------------------------ drift
def drift_findings(desired: dict, order: list[str], obs: dict, managed: set[str], prune: set[str], prev: dict, overrides: dict,
                   baseline: dict | None = None, ignored: dict[str, set[str]] | None = None) -> list[dict]:
    """Differences between the device and the desired state, described from the device's point of view."""
    ignored = ignored or {}
    ch = compute(desired, obs["state"], managed_types=managed, prune_types=prune, previously_managed=prev,
                 desired_order=order, observed_order=obs["order"], ignored=ignored)
    inv_action = {"create": "delete", "delete": "create", "update": "update", "move": "move"}
    out = []
    for c in ch:
        inv = {"type": c["type"], "key": c["key"], "action": inv_action[c["action"]], "current": c.get("desired"), "desired": c.get("current"),
               "fields": [{**f, "current": f.get("desired"), "desired": f.get("current"), "added": f.get("removed"), "removed": f.get("added")}
                          for f in c.get("fields", [])]}
        k = classify(inv, overrides)
        what = {"create": "present on the device but not in the approved configuration", "delete": "missing from the device",
                "update": "differs from the approved configuration", "move": "is in a different position on the device"}[inv["action"]]
        out.append({"type": c["type"], "key": c["key"], "change": inv["action"], "desired": c.get("desired"), "live": c.get("current"),
                    "fields": inv["fields"], "severity": k["risk"], "rule_id": k["rule_id"], "explanation": f"{c['type']} '{c['key'] or c['type']}' {what}: {k['impact']}"})
    # declared types: undeclared policies / routes on the device are unexpected (other undeclared objects are fine)
    for t in ("policy", "static_route"):
        if t not in managed or t in prune:
            continue
        for k, o in (obs["state"].get(t) or {}).items():
            if k in (desired.get(t) or {}) or k in set(prev.get(t) or []) or k in set((baseline or {}).get(t) or []) \
                    or k in (ignored.get(t) or set()):
                continue
            inv = {"type": t, "key": k, "action": "create", "current": None, "desired": o, "fields": []}
            c = classify(inv, overrides)
            out.append({"type": t, "key": k, "change": "unmanaged", "desired": None, "live": o, "fields": [], "severity": c["risk"],
                        "rule_id": c["rule_id"], "explanation": f"unexpected {t} {k} on the device (not declared): {c['impact']}"})
    out.sort(key=lambda x: -SEV.index(x["severity"]))
    return out


async def drift_check(s: AsyncSession, dev: IacDevice, user: str = "system") -> IacDrift:
    fw = await s.get(Firewall, dev.firewall_id)
    project = await s.get(IacProject, dev.project_id)
    rs = await load_ruleset(s, project.id)
    vid = project.approved_version_id
    v = await s.get(IacVersion, vid) if vid else None
    rec = IacDrift(device_id=dev.id, firewall_id=fw.id, project_id=project.id, status="error", version_id=v.id if v else None)
    try:
        if v is None:
            raise ValueError("no approved configuration version yet (approve a plan first)")
        doc = parse(v.content)
        desired, order, rerr = render(doc, variables_for(doc, fw.name, fw.site or "", dev.variables))
        if rerr:
            raise ValueError("; ".join(e["message"] for e in rerr))
        obs = await observe(s, dev, fw)
        prune, prev = set(doc.manage.prune), dev.managed_keys or {}
        managed = declared_types(doc) | prune | {t for t, ks in prev.items() if ks}
        f = drift_findings(desired, order, obs, managed, prune, prev, rs["overrides"], dev.baseline_unmanaged, doc.manage.ignored())
        rec.findings, rec.counts, rec.observed_hash = f, counts(f, "severity"), dev.observed_hash
        rec.status = "drift" if f else "in_sync"
    except Exception as e:  # noqa: BLE001 - stored for the operator
        rec.error = redact(str(e))[:500]
    dev.drift_status, dev.last_drift_check = rec.status, now()
    s.add(rec)
    await audit(s, user, "drift_check", project_id=project.id, target=fw.name,
                detail={"status": rec.status, "counts": rec.counts, "error": rec.error}, commit=False)
    await s.commit()
    return rec


async def drift_due(s: AsyncSession) -> list[IacDevice]:
    settings = await get_iac_settings(s)
    every = timedelta(minutes=max(5, int(settings["drift_interval_minutes"])))
    devs = (await s.execute(select(IacDevice).join(IacProject, IacProject.id == IacDevice.project_id).where(
        IacDevice.managed.is_(True), IacProject.archived.is_(False), IacProject.approved_version_id.is_not(None)))).scalars().all()
    return [d for d in devs if d.last_drift_check is None or now() - aware(d.last_drift_check) >= every]


# ------------------------------------------------------------------ overview
async def overview(s: AsyncSession, days: int = 7) -> dict:
    t0 = now() - timedelta(days=days)
    devs = (await s.execute(select(IacDevice, Firewall, IacProject).join(Firewall, Firewall.id == IacDevice.firewall_id)
                            .join(IacProject, IacProject.id == IacDevice.project_id).where(IacProject.archived.is_(False)))).all()
    managed = [d for d in devs if d[0].managed]
    pending = (await s.execute(select(func.count(IacPlan.id)).where(IacPlan.status == "pending_approval"))).scalar()
    failed_validation = {p for (p,) in (await s.execute(select(IacPlan.project_id).where(IacPlan.status == "validation_failed",
                                                                                          IacPlan.created_at >= t0))).all()}
    jobs = (await s.execute(select(IacJob).where(IacJob.created_at >= t0, IacJob.kind == "deploy").order_by(IacJob.id.desc()).limit(50))).scalars().all()
    latest_drift = {}
    for r in (await s.execute(select(IacDrift).where(IacDrift.checked_at >= t0).order_by(IacDrift.id))).scalars():
        latest_drift[r.device_id] = r
    findings = []
    for r in latest_drift.values():
        for f in r.findings[:50]:
            findings.append({**f, "firewall_id": r.firewall_id, "project_id": r.project_id, "checked_at": aware(r.checked_at).isoformat(), "source": "drift"})
    for p in (await s.execute(select(IacPlan).where(IacPlan.created_at >= t0).order_by(IacPlan.id.desc()).limit(20))).scalars():
        for f in p.findings[:50]:
            findings.append({**f, "plan_id": p.id, "project_id": p.project_id, "source": "validation"})
    versions = (await s.execute(select(IacVersion, IacProject.name).join(IacProject, IacProject.id == IacVersion.project_id)
                                .order_by(IacVersion.id.desc()).limit(10))).all()
    last_sync = max((aware(d[0].last_drift_check) for d in managed if d[0].drift_status == "in_sync" and d[0].last_drift_check), default=None)
    return {
        "totals": {"managed": len(managed), "in_sync": sum(d[0].drift_status == "in_sync" for d in managed),
                   "drift": sum(d[0].drift_status == "drift" for d in managed), "unknown": sum(d[0].drift_status in ("unknown", "error") for d in managed),
                   "failed_validation": sum(1 for d in managed if d[2].id in failed_validation), "pending_approvals": pending,
                   "deployments": len(jobs), "failed_deployments": sum(j.status == "failed" for j in jobs),
                   "last_sync": last_sync.isoformat() if last_sync else None},
        "devices": [{"device_id": d.id, "firewall_id": f.id, "firewall_name": f.name, "site": f.site, "project_id": p.id, "project": p.name,
                     "environment": p.environment, "drift_status": d.drift_status, "last_drift_check": aware(d.last_drift_check).isoformat() if d.last_drift_check else None,
                     "last_deploy_at": aware(d.last_deploy_at).isoformat() if d.last_deploy_at else None, "last_deploy_status": d.last_deploy_status,
                     "integration": d.integration, "managed": d.managed, "validation_failed": p.id in failed_validation} for d, f, p in devs],
        "jobs": [{"id": j.id, "plan_id": j.plan_id, "project_id": j.project_id, "status": j.status, "requested_by": j.requested_by,
                  "created_at": aware(j.created_at).isoformat(), "finished_at": aware(j.finished_at).isoformat() if j.finished_at else None, "error": j.error[:200]}
                 for j in jobs[:20]],
        "versions": [{"project": n, "project_id": v.project_id, "number": v.number, "author": v.author, "message": v.message[:200], "valid": v.valid,
                      "created_at": aware(v.created_at).isoformat()} for v, n in versions],
        "findings": sorted(findings, key=lambda f: -SEV.index(f.get("severity", "info")))[:300],
    }
