"""Diagnostics: run approved command-library templates on one device or many.

Only template ids (or template categories) are accepted; the commands come from commands.TEMPLATES, each checked at
import to be READ_ONLY or LOW_RISK. A template runs only on its own platform. Bulk jobs run with bounded concurrency
(NMS_BULK / ACCESS_BULK_CONCURRENCY) and a per-device timeout; one slow or failing device never blocks the others;
cancellation stops devices that have not started and cancels running ones.
"""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone

from sqlalchemy import select

from ..config import get_settings
from ..configs.backup import mask
from ..db.models import NmsAccessCommand, NmsDiagJob, NmsDiagResult, Switch, User
from ..db.pg import session_factory
from . import audit, vault
from .commands import BY_ID, TEMPLATES, classify
from .gateway import AccessError, connect, resolve, run_read_only

log = logging.getLogger("access.diagnostics")
MAX_OUTPUT = 256 * 1024
_TASKS: dict[int, asyncio.Task] = {}      # bulk jobs running in this gateway process


def now() -> datetime:
    return datetime.now(timezone.utc)


def select_templates(platform: str | None, template_ids: list[str], categories: list[str]) -> list:
    out = [BY_ID[t] for t in template_ids if t in BY_ID and BY_ID[t].platform == platform]
    out += [t for t in TEMPLATES if t.platform == platform and t.category in categories and t not in out]
    return out


def validate_request(template_ids: list[str], categories: list[str]) -> None:
    unknown = [t for t in template_ids if t not in BY_ID]
    if unknown:
        raise AccessError(422, f"unknown template(s): {', '.join(unknown[:10])}")
    cats = {t.category for t in TEMPLATES}
    bad = [c for c in categories if c not in cats]
    if bad:
        raise AccessError(422, f"unknown categories: {', '.join(bad)}")
    if not template_ids and not categories:
        raise AccessError(422, "choose at least one template or category")


async def run_device(user: User, switch_id: int, template_ids: list[str], categories: list[str], job_id: int,
                     timeout: float, *, client_ip: str = "") -> dict:
    """Run on one device; persists the result row (job_id, switch_id) and the command records."""
    t0 = time.perf_counter()
    async with session_factory()() as s:
        res = (await s.execute(select(NmsDiagResult).where(NmsDiagResult.job_id == job_id, NmsDiagResult.switch_id == switch_id))).scalar_one_or_none()
        if res is None:
            res = NmsDiagResult(job_id=job_id, switch_id=switch_id)
            s.add(res)
        res.status = "running"
        await s.commit()
        outputs, err, status = [], "", "ok"
        try:
            t = await resolve(s, user, switch_id, "ssh")
            res.device_name = t.switch.name
            tpls = select_templates(t.platform, template_ids, categories)
            if t.platform is None:
                raise AccessError(409, "no command library for this device's platform (set the access platform)", "unsupported")
            if not tpls:
                raise AccessError(409, f"none of the chosen templates applies to {t.platform}", "skipped")
            cmds = [c for tp in tpls for c in tp.commands]
            for c in cmds:      # defence in depth: never send anything above LOW_RISK
                if classify(c)[0] not in ("READ_ONLY", "LOW_RISK"):
                    raise AccessError(500, f"refused non-read-only template command {c}")
            cred, _ = await vault.resolve(s, t.switch, "ssh")
            conn, server_key, _ = await connect(t, cred)
            try:
                if not t.switch.ssh_host_key and server_key:
                    t.switch.ssh_host_key = server_key
                results = await asyncio.wait_for(run_read_only(conn, t.platform, cmds, float(get_settings().access_command_timeout_seconds)), timeout)
            finally:
                conn.close()
            by_cmd = {}
            for tp in tpls:
                for c in tp.commands:
                    by_cmd.setdefault(c, tp.id)
            for r in results:
                text = mask(r["output"])
                outputs.append({"template": by_cmd.get(r["command"], ""), "command": r["command"], "status": r["status"], "ms": r["ms"],
                                "output": text[:MAX_OUTPUT], "truncated": len(text) > MAX_OUTPUT})
                s.add(NmsAccessCommand(job_id=job_id, switch_id=switch_id, username=user.username, command=r["command"],
                                       risk=classify(r["command"])[0], allowed=True, reason="diagnostic template"))
            if any(o["status"] != "ok" for o in outputs):
                status = "ok" if any(o["status"] == "ok" for o in outputs) else "failed"
                if status == "failed":
                    err = "; ".join(sorted({o["status"] for o in outputs}))
        except AccessError as e:
            status = "skipped" if e.kind in ("skipped", "unsupported") else "failed"
            err = e.message
        except asyncio.TimeoutError:
            status, err = "failed", f"device timeout ({timeout:g} s)"
        except asyncio.CancelledError:
            status, err = "cancelled", "cancelled"
            res.status, res.error, res.finished_at = status, err, now()
            await s.commit()
            raise
        res.status, res.error, res.outputs = status, err[:2000], outputs
        res.duration_ms, res.finished_at = round((time.perf_counter() - t0) * 1000), now()
        await s.commit()
        await audit.record(s, user.username, "diagnostics_run", switch_id=switch_id, target=res.device_name,
                           detail={"job_id": job_id, "templates": template_ids, "categories": categories, "status": status, "error": err[:300]},
                           client_ip=client_ip, success=status == "ok")
        return {"switch_id": switch_id, "status": status, "error": err}


async def create_job(user: User, device_ids: list[int], template_ids: list[str], categories: list[str], *, kind: str,
                     concurrency: int | None = None, timeout: int | None = None) -> int:
    st = get_settings()
    async with session_factory()() as s:
        names = dict((await s.execute(select(Switch.id, Switch.name).where(Switch.id.in_(device_ids)))).all())
        job = NmsDiagJob(username=user.username, kind=kind, templates=template_ids + [f"category:{c}" for c in categories],
                         device_ids=device_ids, status="queued", total=len(device_ids),
                         concurrency=max(1, min(concurrency or st.access_bulk_concurrency, 50)),
                         timeout_seconds=max(10, min(timeout or 120, 900)))
        s.add(job)
        await s.flush()
        for d in device_ids:
            s.add(NmsDiagResult(job_id=job.id, switch_id=d, device_name=names.get(d, f"#{d}"), status="pending"))
        await s.commit()
        return job.id


async def run_job(job_id: int, user: User, template_ids: list[str], categories: list[str], *, client_ip: str = "") -> None:
    async with session_factory()() as s:
        job = await s.get(NmsDiagJob, job_id)
        job.status, job.started_at = "running", now()
        await s.commit()
        ids, conc, timeout = list(job.device_ids), job.concurrency, float(job.timeout_seconds)
    sem = asyncio.Semaphore(conc)

    async def one(sid: int):
        async with sem:
            async with session_factory()() as s:
                if (await s.get(NmsDiagJob, job_id)).cancel_requested:
                    r = (await s.execute(select(NmsDiagResult).where(NmsDiagResult.job_id == job_id, NmsDiagResult.switch_id == sid))).scalar_one()
                    r.status, r.error, r.finished_at = "cancelled", "cancelled before it started", now()
                    await s.commit()
                    return {"status": "cancelled"}
            try:
                return await run_device(user, sid, template_ids, categories, job_id, timeout, client_ip=client_ip)
            except asyncio.CancelledError:
                return {"status": "cancelled"}
            except Exception as e:      # one device's unexpected error must not stop the job
                log.exception("diagnostics on device %s failed", sid)
                async with session_factory()() as s:
                    r = (await s.execute(select(NmsDiagResult).where(NmsDiagResult.job_id == job_id, NmsDiagResult.switch_id == sid))).scalar_one()
                    r.status, r.error, r.finished_at = "failed", f"internal error: {type(e).__name__}", now()
                    await s.commit()
                return {"status": "failed"}
            finally:
                async with session_factory()() as s:
                    j = await s.get(NmsDiagJob, job_id)
                    done = (await s.execute(select(NmsDiagResult.status).where(NmsDiagResult.job_id == job_id))).scalars().all()
                    j.completed = sum(1 for x in done if x not in ("pending", "running"))
                    j.failed = sum(1 for x in done if x == "failed")
                    await s.commit()

    try:
        await asyncio.gather(*(one(i) for i in ids))
        final = None
    except asyncio.CancelledError:
        final = "cancelled"
    async with session_factory()() as s:
        j = await s.get(NmsDiagJob, job_id)
        for r in (await s.execute(select(NmsDiagResult).where(NmsDiagResult.job_id == job_id, NmsDiagResult.status.in_(("pending", "running"))))).scalars():
            r.status, r.error, r.finished_at = "cancelled", "cancelled", now()
        j.status = final or ("cancelled" if j.cancel_requested else "done")
        j.finished_at = now()
        done = (await s.execute(select(NmsDiagResult.status).where(NmsDiagResult.job_id == job_id))).scalars().all()
        j.completed = sum(1 for x in done if x not in ("pending", "running"))
        j.failed = sum(1 for x in done if x == "failed")
        await s.commit()


def start_job(job_id: int, user: User, template_ids: list[str], categories: list[str], **kw) -> asyncio.Task:
    task = asyncio.create_task(run_job(job_id, user, template_ids, categories, **kw))
    _TASKS[job_id] = task
    task.add_done_callback(lambda _t: _TASKS.pop(job_id, None))
    return task


async def cancel_job(job_id: int) -> bool:
    async with session_factory()() as s:
        j = await s.get(NmsDiagJob, job_id)
        if j is None or j.status not in ("queued", "running"):
            return False
        j.cancel_requested = True
        await s.commit()
    task = _TASKS.get(job_id)
    if task is not None:
        task.cancel()
    return True


async def mark_orphans() -> int:
    """Gateway start: jobs that were running in a previous process cannot finish; mark them failed."""
    async with session_factory()() as s:
        n = 0
        for j in (await s.execute(select(NmsDiagJob).where(NmsDiagJob.status.in_(("queued", "running"))))).scalars():
            j.status, j.finished_at, n = "failed", now(), n + 1
            for r in (await s.execute(select(NmsDiagResult).where(NmsDiagResult.job_id == j.id, NmsDiagResult.status.in_(("pending", "running"))))).scalars():
                r.status, r.error = "failed", "the gateway restarted while this job ran"
        await s.commit()
        return n
