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
from .db.pg import session_factory
from .fortigate.service import poll_health, pull_logs
from .ingest.pipeline import DeviceRegistry, EventSink
from .logging_setup import setup_logging
from .retention import run_retention

log = logging.getLogger("worker")
SHARD = int(os.environ.get("WORKER_SHARD", "0"))
SHARDS = max(1, int(os.environ.get("WORKER_SHARDS", "1")))
CONCURRENCY = int(os.environ.get("WORKER_POLL_CONCURRENCY", "20"))


async def poll_loop(stop: asyncio.Event):
    ch = get_ch()
    registry = DeviceRegistry()
    from .enrich.enricher import Enricher
    enricher = Enricher()
    sink = EventSink(ch, registry, enricher=enricher)
    last_run: dict[int, float] = {}
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

    while not stop.is_set():
        try:
            async with session_factory()() as s:
                fws = (await s.execute(select(Firewall).where(Firewall.enabled.is_(True), Firewall.is_demo.is_(False),
                                                              Firewall.token_ciphertext.is_not(None)))).scalars().all()
            now = time.monotonic()
            due = [f.id for f in fws if f.id % SHARDS == SHARD and now - last_run.get(f.id, 0) >= f.poll_interval_seconds]
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
