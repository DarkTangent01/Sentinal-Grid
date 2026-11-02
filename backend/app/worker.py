"""Background worker: API health polling, optional API log pulls, alert evaluation, retention, demo feed.

Horizontal scaling: run N workers with WORKER_SHARDS=N and WORKER_SHARD=0..N-1; firewalls are assigned
by id modulo N. Alerting/retention run only on shard 0.
"""
import asyncio
import logging
import os
import signal
import time
from datetime import datetime, timezone

from sqlalchemy import select

from .alerts.engine import run_rules
from .config import get_settings
from .db.ch import get_ch
from .db.models import Firewall
from .db.pg import init_engine, session_factory
from .switches.poller import backoff_seconds
from .fortigate.service import poll_health, pull_logs
from .ingest.pipeline import DeviceRegistry, EventSink
from .logging_setup import setup_logging
from .retention import run_retention

log = logging.getLogger("worker")
SHARD = int(os.environ.get("WORKER_SHARD", "0"))
SHARDS = max(1, int(os.environ.get("WORKER_SHARDS", "1")))
CONCURRENCY = int(os.environ.get("WORKER_POLL_CONCURRENCY", "20"))


def firewall_backoff(prev_fails: int, api_status: str | None, interval: int) -> tuple[int, int]:
    """(fail streak, seconds before the next poll). An unreachable firewall costs every retry x timeout per cycle and
    holds up the cycle for all firewalls, so it backs off like a switch: normal cadence for 2 failures, then doubling up
    to 15 minutes; wrong credentials back off from the first failure. Any other status resets the streak."""
    kind = {"unreachable": "timeout", "auth_error": "auth"}.get(api_status or "")
    if not kind:
        return 0, 0
    fails = prev_fails + 1
    return fails, backoff_seconds(fails, interval, kind)


def worker_pool_need(s) -> int:
    """Firewall and switch polls each hold a session for their whole network round trip; plus one per other loop."""
    return CONCURRENCY + s.switch_max_concurrent_polls + 6


async def poll_loop(stop: asyncio.Event):
    ch = get_ch()
    registry = DeviceRegistry()
    from .enrich.enricher import Enricher
    enricher = Enricher()
    sink = EventSink(ch, registry, enricher=enricher)
    last_run: dict[int, float] = {}
    not_before: dict[int, float] = {}  # failing firewall -> monotonic time of its next poll
    fails: dict[int, int] = {}
    sem = asyncio.Semaphore(CONCURRENCY)

    async def one(fw_id: int):
        async with sem:
            async with session_factory()() as s:
                fw = await s.get(Firewall, fw_id)
                if fw is None:
                    return
                if fw.vendor == "paloalto":
                    from .paloalto import poll_health as pan_poll_health
                    await pan_poll_health(fw, ch)
                else:
                    await poll_health(fw, ch)
                if fw.api_status == "ok":
                    from . import bgp
                    try:
                        await bgp.poll(fw, s, ch)
                    except Exception:
                        log.exception("bgp poll failed for %s", fw.name)
                if fw.vendor == "fortinet" and fw.api_log_pull and fw.api_status == "ok":
                    await enricher.refresh_ti()
                    n = await pull_logs(fw, sink)
                    await sink.flush()
                    log.info("api log pull %s: %d new events", fw.name, n)
                await s.commit()
                fails[fw_id], delay = firewall_backoff(fails.get(fw_id, 0), fw.api_status, fw.poll_interval_seconds)
                not_before[fw_id] = time.monotonic() + delay
                if delay:
                    log.info("firewall %s %s (%d in a row): next poll in %ds", fw.name, fw.api_status, fails[fw_id], delay)

    while not stop.is_set():
        try:
            async with session_factory()() as s:
                fws = (await s.execute(select(Firewall).where(Firewall.enabled.is_(True), Firewall.is_demo.is_(False),
                                                              Firewall.token_ciphertext.is_not(None)))).scalars().all()
            now = time.monotonic()
            due = [f.id for f in fws if f.id % SHARDS == SHARD and now - last_run.get(f.id, 0) >= f.poll_interval_seconds
                   and now >= not_before.get(f.id, 0)]
            for fid in due:
                last_run[fid] = now
            if due:
                await asyncio.gather(*(one(fid) for fid in due), return_exceptions=True)
        except Exception:
            log.exception("poll loop error")
        try:
            with open("/tmp/worker.heartbeat", "w") as hb:
                hb.write(str(time.time()))
        except OSError:
            pass
        try:
            await asyncio.wait_for(stop.wait(), timeout=5)
        except asyncio.TimeoutError:
            pass


async def policy_loop(stop: asyncio.Event):
    """Collect policy configuration, objects and hit counters (GET only), then run shadow analysis."""
    from .policy.collector import sync_firewall
    interval = get_settings().policy_sync_interval_seconds
    while not stop.is_set():
        try:
            async with session_factory()() as s:
                fws = (await s.execute(select(Firewall).where(Firewall.enabled.is_(True), Firewall.is_demo.is_(False),
                                                              Firewall.token_ciphertext.is_not(None),
                                                              Firewall.vendor == "fortinet"))).scalars().all()
                for fw in fws:
                    if fw.id % SHARDS != SHARD or stop.is_set():
                        continue
                    st = await sync_firewall(s, get_ch(), fw)
                    log.info("policy sync %s: %s (%d policies, counters=%s)", fw.name, st.status, st.policies, st.counters_supported)
        except Exception:
            log.exception("policy loop error")
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass


async def ngen_jobs(stop: asyncio.Event):
    """Threat-intel feed refresh, asset learning, saved searches, reports and notification delivery."""
    from .assets import learn_recent
    from .enrich.feeds import refresh_due_feeds
    from .notify import process_outbox
    from .reports import run_due as reports_due
    from .isp import discover as isp_discover
    from .wan import sync_sdwan as wan_sync_sdwan
    from .searches import run_due as searches_due
    st = get_settings()
    last: dict[str, float] = {}
    jobs = [  # name, interval seconds, coroutine factory
        ("notifications", 15, lambda s: process_outbox(s)),
        ("ti_feeds", 900, lambda s: refresh_due_feeds(s)),
        ("assets", st.asset_learn_interval_seconds, lambda s: learn_recent(s, get_ch(), minutes=st.asset_learn_interval_seconds // 60 + 5)),
        ("saved_searches", 300, lambda s: searches_due(s, get_ch())),
        ("reports", 600, lambda s: reports_due(s, get_ch())),
        ("isp_discovery", 3600, lambda s: isp_discover(s)),
        ("wan_sdwan_outages", 300, lambda s: wan_sync_sdwan(s, get_ch())),  # SD-WAN link outages → WAN outages / incidents
    ]
    while not stop.is_set():
        now = time.monotonic()
        for name, every, fn in jobs:
            if now - last.get(name, 0) < every:
                continue
            last[name] = now
            try:
                async with session_factory()() as s:
                    res = await fn(s)
                if res:
                    log.info("%s: %s", name, res)
            except Exception:
                log.exception("%s job failed", name)
        try:
            await asyncio.wait_for(stop.wait(), timeout=5)
        except asyncio.TimeoutError:
            pass


async def icmp_loop(stop: asyncio.Event):
    """ICMP reachability probes (app/icmp.py); each target keeps its own interval."""
    from .icmp import run_due
    while not stop.is_set():
        try:
            async with session_factory()() as s:
                res = await run_due(s, get_ch())
            if res.get("changes"):
                log.info("icmp: %s", res)
        except Exception:
            log.exception("icmp probing failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=5)
        except asyncio.TimeoutError:
            pass


async def switch_loop(stop: asyncio.Event):
    """Switch SNMP polling (app/switches): due switches every few seconds, queued discovery runs, hourly housekeeping."""
    from .switches.discovery import run_queued
    from .switches.poller import housekeeping, run_due
    last_hk = 0.0
    while not stop.is_set():
        try:
            res = await run_due(get_ch(), session_factory())
            if res.get("failed"):
                log.info("switch polls: %s", res)
            await run_queued(session_factory())
            if time.monotonic() - last_hk > 3600:
                async with session_factory()() as s:
                    await housekeeping(s)
                last_hk = time.monotonic()
        except Exception:
            log.exception("switch polling failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=5)
        except asyncio.TimeoutError:
            pass


async def service_loop(stop: asyncio.Event):
    """NMS service checks (app/nms/services.py): TCP / HTTP / DNS / TLS checks, each on its own interval."""
    from .nms.services import run_due
    while not stop.is_set():
        try:
            async with session_factory()() as s:
                res = await run_due(get_ch(), s)
            if res.get("changes"):
                log.info("service checks: %s", res)
        except Exception:
            log.exception("service checks failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=10)
        except asyncio.TimeoutError:
            pass


async def tacacs_loop(stop: asyncio.Event):
    """TACACS+ AAA (app/tacacs): health checks, accounting / AAA log ingestion, approved deployment jobs."""
    from .tacacs.jobs import housekeeping, tick
    last_hk = 0.0
    while not stop.is_set():
        try:
            await tick(get_ch(), session_factory())
            if time.monotonic() - last_hk > 3600:
                async with session_factory()() as s:
                    await housekeeping(s)
                last_hk = time.monotonic()
        except Exception:
            log.exception("tacacs jobs failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=5)
        except asyncio.TimeoutError:
            pass


async def periodic(stop: asyncio.Event, interval: int, fn, name: str):
    while not stop.is_set():
        started = time.monotonic()
        try:
            async with session_factory()() as s:
                res = await fn(get_ch(), s)
            log.info("%s finished in %.1fs: %s", name, time.monotonic() - started, res)
        except Exception:
            log.exception("%s failed", name)
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass


async def main():
    s = get_settings()
    setup_logging(s.log_level)
    init_engine(pool_size=10, max_overflow=max(s.db_max_overflow, worker_pool_need(s) - 10))
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    tasks = [asyncio.create_task(poll_loop(stop)), asyncio.create_task(policy_loop(stop))]
    if SHARD == 0:
        tasks.append(asyncio.create_task(periodic(stop, s.alert_interval_seconds, run_rules, "alert evaluation")))
        tasks.append(asyncio.create_task(periodic(stop, s.retention_interval_seconds, run_retention, "retention")))
        tasks.append(asyncio.create_task(ngen_jobs(stop)))
        tasks.append(asyncio.create_task(icmp_loop(stop)))
        tasks.append(asyncio.create_task(switch_loop(stop)))
        tasks.append(asyncio.create_task(tacacs_loop(stop)))
        tasks.append(asyncio.create_task(service_loop(stop)))
        from .iac.executor import loop as iac_loop
        tasks.append(asyncio.create_task(iac_loop(stop)))
        if s.demo_mode:
            from . import demo
            log.warning("DEMO_MODE enabled: generating synthetic demo events tagged source='demo'")
            tasks.append(asyncio.create_task(demo.run(backfill_hours=float(os.environ.get("DEMO_BACKFILL_HOURS", "6")),
                                                      live=True, step_seconds=5)))
    log.info("worker started shard %d/%d at %s", SHARD, SHARDS, datetime.now(timezone.utc).isoformat())
    await stop.wait()
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    log.info("worker stopped")


if __name__ == "__main__":
    asyncio.run(main())
