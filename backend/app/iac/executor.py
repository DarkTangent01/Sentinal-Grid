"""Background execution of IaC jobs (worker process only; never inside an HTTP request).

deploy:   locks → pre-flight on every device (reachable, not FortiManager-managed, live state unchanged since planning)
          → per device (fail-fast by default): pre-change backup (checksummed, encrypted full config when the device
          allows it) → changes in dependency order, cancellation checked between changes → re-read and verify the
          resulting configuration → health check → record actual state. Nothing is rolled back automatically: a failure
          is reported as it is, and recovery is a separate, reviewed plan built from the backup.
dry_run:  the same pre-flight, then the exact requests each change would send. No backup, no lock, no writes.
drift:    drift check for every managed device of a project.
Multiple firewalls are never treated as one transaction.
"""
from __future__ import annotations

import asyncio
import logging

from sqlalchemy import select, update

from ..config import get_settings
from ..db.models import Firewall, IacDevice, IacJob, IacJobDevice, IacPlan, IacProject
from ..db.pg import session_factory
from . import adapters, service as S
from .diff import field_diff
from .resources import SINGLETONS, canonical_hash, redact

log = logging.getLogger("iac.executor")


def _log(job: IacJob, msg: str) -> None:
    job.log = (job.log or []) + [{"t": S.now().isoformat(), "msg": redact(msg)[:1000]}]
    job.current_operation = redact(msg)[:500]


async def claim_next() -> int | None:
    async with session_factory()() as s:
        ids = [j for (j,) in (await s.execute(select(IacJob.id).where(IacJob.status == "queued").order_by(IacJob.id).limit(5))).all()]
        for jid in ids:
            res = await s.execute(update(IacJob).where(IacJob.id == jid, IacJob.status == "queued").values(status="running", started_at=S.now()))
            await s.commit()
            if res.rowcount == 1:
                return jid
    return None


async def run(job_id: int) -> None:
    timeout = get_settings().iac_job_timeout_seconds
    try:
        await asyncio.wait_for(_run(job_id), timeout=timeout)
    except asyncio.TimeoutError:
        async with session_factory()() as s:
            job = await s.get(IacJob, job_id)
            job.status, job.finished_at = "failed", S.now()
            job.error = f"job exceeded the {timeout}s limit; device state was re-read where possible — check per-device results"
            _log(job, job.error)
            await S.release_locks(job_id)
            if job.plan_id and job.kind == "deploy":
                p = await s.get(IacPlan, job.plan_id)
                p.status = "failed"
            await S.audit(s, "system", "job_timeout", project_id=job.project_id, plan_id=job.plan_id, job_id=job.id, commit=False)
            await s.commit()
    except Exception as e:  # noqa: BLE001 - a job must always end in a terminal state
        log.exception("iac job %s crashed", job_id)
        async with session_factory()() as s:
            job = await s.get(IacJob, job_id)
            if job.status == "running":
                job.status, job.finished_at, job.error = "failed", S.now(), f"internal error: {redact(str(e))[:300]}"
                await S.release_locks(job_id)
                await s.commit()


async def _run(job_id: int) -> None:
    async with session_factory()() as s:
        job = await s.get(IacJob, job_id)
        if job.kind == "drift":
            await _drift(s, job)
            return
        plan = await s.get(IacPlan, job.plan_id)
        if plan is None or plan.plan_hash != job.plan_hash:
            return await _finish(s, job, plan, "failed", "plan missing or changed after the job was queued")
        if job.kind == "deploy":
            if plan.status != "queued":
                return await _finish(s, job, plan, "failed", f"plan is {plan.status}, expected queued")
            ok, why = S.writes_effective(await S.get_iac_settings(s))
            if not ok:
                return await _finish(s, job, plan, "failed", why)
            reason = await S.staleness(s, plan, read_devices=False)
            if reason:
                await S.mark_stale(s, plan, reason)
                return await _finish(s, job, plan, "failed", f"plan is stale: {reason}", plan_status="stale")
            if not await S.acquire_locks(plan.targets, job.id, get_settings().iac_job_timeout_seconds + 300):
                return await _finish(s, job, plan, "failed", "another deployment holds a lock on one of the target devices", plan_status="approved")
            plan.status = "running"
            await s.commit()
        try:
            await _execute(s, job, plan)
        finally:
            if job.kind == "deploy":
                await S.release_locks(job.id)


async def _finish(s, job: IacJob, plan: IacPlan | None, status: str, error: str = "", plan_status: str | None = None) -> None:
    job.status, job.finished_at, job.error = status, S.now(), redact(error)[:2000]
    if error:
        _log(job, error)
    if plan is not None and job.kind == "deploy":
        plan.status = plan_status or {"succeeded": "succeeded", "failed": "failed", "cancelled": "cancelled"}.get(status, plan.status)
    await S.audit(s, job.requested_by, f"job_{status}", project_id=job.project_id, plan_id=job.plan_id, job_id=job.id,
                  detail={"kind": job.kind, "error": error[:300]}, commit=False)
    await s.commit()


async def _execute(s, job: IacJob, plan: IacPlan) -> None:
    deploy = job.kind == "deploy"
    settings = await S.get_iac_settings(s)
    changes = await S.plan_changes(s, plan.id)
    devrows = {d.firewall_id: d for d in (await s.execute(select(IacJobDevice).where(IacJobDevice.job_id == job.id))).scalars()}
    project = await s.get(IacProject, plan.project_id)
    targets = [(await s.get(Firewall, fid), (await s.execute(select(IacDevice).where(IacDevice.project_id == plan.project_id,
                                                                                    IacDevice.firewall_id == fid))).scalars().first())
               for fid in plan.targets]
    # ---------------- pre-flight on all devices before the first write
    pre: dict[int, dict] = {}
    for fw, dev in targets:
        jd = devrows[fw.id]
        jd.started_at = S.now()
        _log(job, f"pre-flight {fw.name}")
        await s.commit()
        if dev is None:
            jd.status, jd.error = "failed", "device is no longer managed by this project"
            return await _finish(s, job, plan, "failed", f"{fw.name}: {jd.error}")
        if dev.integration == "fortimanager" or (dev.capabilities or {}).get("fortimanager"):
            jd.status, jd.error = "failed", "managed by FortiManager: direct deployment blocked"
            if deploy:
                return await _finish(s, job, plan, "failed", f"{fw.name}: {jd.error}")
        ad = adapters.make_adapter(fw, integration=dev.integration)
        try:
            snap = await ad.read_state(list(S.TYPES))
            health = await ad.health()
        except Exception as e:  # noqa: BLE001
            jd.status, jd.error = "failed", f"unreachable: {redact(str(e))[:300]}"
            await ad.close()
            return await _finish(s, job, plan, "failed", f"{fw.name}: {jd.error}")
        await ad.close()
        h = canonical_hash({"state": snap["state"], "order": snap["order"]})
        if h != plan.observed_hashes.get(str(fw.id)):
            jd.status, jd.error = "failed", "live configuration changed since planning"
            if deploy:
                await S.mark_stale(s, plan, f"{fw.name}'s live configuration changed since planning")
                return await _finish(s, job, plan, "failed", f"{fw.name}: {jd.error}; re-plan", plan_status="stale")
        if not health.get("reachable"):
            jd.status, jd.error = "failed", f"health check failed: {health.get('error', '')}"
            return await _finish(s, job, plan, "failed", f"{fw.name}: {jd.error}")
        jd.health = {"before": health}
        pre[fw.id] = snap
    await s.commit()
    if not deploy:  # ---------------- dry run: requests only
        for fw, dev in targets:
            jd = devrows[fw.id]
            ad = adapters.make_adapter(fw, integration=dev.integration, writes_allowed=False)
            try:
                jd.results = [{"type": c.resource_type, "key": c.resource_id, "action": c.action, "request": ad.describe(_cd(c)), "ok": None,
                               "dry_run": True} for c in changes if c.firewall_id == fw.id]
            finally:
                await ad.close()
            jd.status, jd.finished_at = "dry_run_ok" if jd.status == "pending" else jd.status, S.now()
        job.progress = {"devices": len(targets), "done": len(targets)}
        return await _finish(s, job, plan, "succeeded" if all(d.status == "dry_run_ok" for d in devrows.values()) else "failed",
                             "" if all(d.status == "dry_run_ok" for d in devrows.values()) else "one or more devices failed pre-flight")
    # ---------------- deployment
    failed = cancelled = False
    for i, (fw, dev) in enumerate(targets):
        jd = devrows[fw.id]
        if failed and settings["fail_fast"]:
            jd.status, jd.error = "skipped", "skipped after an earlier device failed (fail-fast)"
            continue
        if job.cancel_requested or (await s.get(IacJob, job.id)).cancel_requested:
            jd.status, jd.error, cancelled = "cancelled", "cancelled before this device started", True
            continue
        # backup
        _log(job, f"{fw.name}: capturing pre-change backup")
        await s.commit()
        ad = adapters.make_adapter(fw, integration=dev.integration, writes_allowed=True)
        after = None
        try:
            full, note = await ad.backup_full()
            b = await S.store_backup(s, fw, {"state": pre[fw.id]["state"], "order": pre[fw.id]["order"]}, full, note, job_id=job.id,
                                     plan_id=plan.id, user=job.requested_by)
            jd.backup_id = b.id
            dev.last_backup_at = S.now()
            if not b.validated or (project.environment == "production" and settings["require_full_backup_production"] and not full):
                jd.status, jd.error = "failed", f"backup not usable ({note if not full else 'validation failed'}); no change was sent"
                failed = True
                await s.commit()
                continue
            _log(job, f"{fw.name}: backup {b.id} stored ({'full config + ' if full else ''}resource snapshot)")
            results = []
            for c in [c for c in changes if c.firewall_id == fw.id]:
                if (await _cancel(s, job)):
                    cancelled = True
                    _log(job, f"{fw.name}: cancellation requested — stopping before {c.action} {c.resource_type} {c.resource_id}")
                    break
                _log(job, f"{fw.name}: {c.action} {c.resource_type} {c.resource_id or ''}")
                await s.commit()
                try:
                    r = await ad.apply(_cd(c))
                except Exception as e:  # noqa: BLE001
                    r = {"ok": False, "device_error": redact(str(e))[:500]}
                results.append({"type": c.resource_type, "key": c.resource_id, "action": c.action, **r})
                if not r["ok"]:
                    failed = True
                    jd.error = f"{c.action} {c.resource_type} {c.resource_id} failed: {r.get('device_error') or r.get('http_status')}"
                    _log(job, f"{fw.name}: {jd.error}; stopping this device")
                    break
            jd.results = results
            # verify: re-read what the device now has
            _log(job, f"{fw.name}: verifying resulting configuration")
            await s.commit()
            after = await ad.read_state(list(S.TYPES))
            jd.verification = _verify([c for c in changes if c.firewall_id == fw.id], after, results)
            jd.health = {**(jd.health or {}), "after": await ad.health()}
        except Exception as e:  # noqa: BLE001 - e.g. the device stopped answering mid-deployment
            failed = True
            jd.error = jd.error or f"deployment interrupted: {redact(str(e))[:300]}; actual device state unknown — re-read before acting"
            jd.verification = {"ok": False, "checked": 0, "mismatches": [], "note": "could not verify"}
        finally:
            await ad.close()
        if after is not None:
            dev.observed = {"state": after["state"], "order": after["order"], "refs": after["refs"], "errors": after["errors"]}
            dev.observed_hash, dev.observed_at = canonical_hash({"state": after["state"], "order": after["order"]}), S.now()
        dev.last_deploy_at = S.now()
        ok = not failed and not cancelled and jd.verification.get("ok") and (jd.health.get("after") or {}).get("reachable")
        jd.status = "succeeded" if ok else ("cancelled" if cancelled and not failed else "failed")
        if not ok and not jd.error:
            jd.error = "verification failed: the device does not match the plan" if not jd.verification.get("ok") else "post-change health check failed"
            failed = failed or not cancelled
        dev.last_deploy_status = jd.status
        if ok:
            if plan.kind == "change" and plan.version_id:
                dev.last_deployed_version_id = plan.version_id
            mk = {t: sorted(set((dev.managed_keys or {}).get(t, [])) | {r["key"] for r in results if r["type"] == t and r["action"] in ("create", "update")}
                            - {r["key"] for r in results if r["type"] == t and r["action"] == "delete"}) for t in S.TYPES if t not in SINGLETONS}
            dev.managed_keys = {t: v for t, v in mk.items() if v}
            if after is not None:  # what else was already on the device: known, not "unexpected" drift
                dev.baseline_unmanaged = {t: sorted(k for k in (after["state"].get(t) or {}) if k not in set(dev.managed_keys.get(t, [])))
                                          for t in ("policy", "static_route")}
        jd.finished_at = S.now()
        job.progress = {"devices": len(targets), "done": i + 1}
        await s.commit()
    status = "succeeded" if not failed and not cancelled else ("cancelled" if cancelled and not failed else "failed")
    if status == "succeeded" and plan.kind == "recovery" and plan.recovery_backup_id:
        b = await s.get(S.IacBackup, plan.recovery_backup_id)
        if b and b.plan_id:
            orig = await s.get(IacPlan, b.plan_id)
            if orig and orig.status in ("failed", "succeeded"):
                orig.status = "rolled_back"
    await _finish(s, job, plan, status, "" if status == "succeeded" else
                  "deployment did not complete; per-device results show what was changed. No automatic rollback was performed.")


def _cd(c) -> dict:
    return {"type": c.resource_type, "key": c.resource_id, "action": c.action, "desired": c.desired, "current": c.current}


async def _cancel(s, job: IacJob) -> bool:
    await s.refresh(job, ["cancel_requested"])
    return bool(job.cancel_requested)


def _verify(changes, after: dict, results: list[dict]) -> dict:
    """Does the device now hold what the applied changes intended? (Only changes that were sent are checked.)"""
    sent = {(r["type"], r["key"], r["action"]) for r in results if r.get("ok")}
    mismatches = []
    for c in changes:
        if (c.resource_type, c.resource_id, c.action) not in sent:
            continue
        live = (after["state"].get(c.resource_type) or {}).get(c.resource_id)
        if c.action == "delete":
            if live is not None:
                mismatches.append({"resource": f"{c.resource_type}:{c.resource_id}", "problem": "still present after delete"})
        elif c.action in ("create", "update"):
            if live is None:
                mismatches.append({"resource": f"{c.resource_type}:{c.resource_id}", "problem": "missing after change"})
                continue
            fd = field_diff({k: live.get(k) for k in c.desired}, c.desired, list(c.desired))
            if fd:
                mismatches.append({"resource": f"{c.resource_type}:{c.resource_id}", "problem": "differs from desired", "fields": fd})
        elif c.action == "move":
            order = after["order"]
            ref = (c.desired or {}).get("after")
            if ref and (c.resource_id not in order or ref not in order or order.index(c.resource_id) < order.index(ref)):
                mismatches.append({"resource": f"policy:{c.resource_id}", "problem": f"not after policy {ref}"})
    return {"ok": not mismatches and len(sent) == len([r for r in results]), "checked": len(sent), "mismatches": mismatches}


async def _drift(s, job: IacJob) -> None:
    devs = (await s.execute(select(IacDevice).where(IacDevice.project_id == job.project_id, IacDevice.managed.is_(True)))).scalars().all()
    out = []
    for i, d in enumerate(devs):
        r = await S.drift_check(s, d, job.requested_by)
        out.append({"device_id": d.id, "status": r.status, "findings": len(r.findings), "error": r.error})
        job.progress = {"devices": len(devs), "done": i + 1}
    job.progress["results"] = out
    await _finish(s, job, None, "succeeded" if all(o["status"] != "error" for o in out) else "failed",
                  "" if all(o["status"] != "error" for o in out) else "drift check failed for some devices")


async def loop(stop: asyncio.Event) -> None:
    """Worker loop: run queued jobs (bounded concurrency) and enqueue scheduled drift checks."""
    running: set[asyncio.Task] = set()
    last_drift = 0.0
    while not stop.is_set():
        try:
            running = {t for t in running if not t.done()}
            while len(running) < get_settings().iac_max_concurrent_jobs:
                jid = await claim_next()
                if jid is None:
                    break
                running.add(asyncio.create_task(run(jid)))
            if asyncio.get_running_loop().time() - last_drift > 60:
                last_drift = asyncio.get_running_loop().time()
                async with session_factory()() as s:
                    for d in await S.drift_due(s):
                        await S.drift_check(s, d)
        except Exception:
            log.exception("iac loop error")
        try:
            await asyncio.wait_for(stop.wait(), timeout=3)
        except asyncio.TimeoutError:
            pass
