"""Background worker: API health polling, optional API log pulls, alert evaluation, retention, demo feed, SNMP polling.

Roles (WORKER_ROLES, docs/performance/REMEDIATION_PLAN.md): `all` (default) runs every loop in this process; `core`
runs everything except SNMP switch / WLC polling; `snmp` runs only that polling. SNMP decoding is pure-Python CPU work
(pyasn1): in a shared event loop it took 75% of the worker's only core and delayed alert evaluation 10-20x, so
production runs it in its own process (`poller` service). Several `snmp` processes may run: each switch is claimed
with a database lease, so no device is polled twice.

Horizontal scaling of the core role: run N workers with WORKER_SHARDS=N and WORKER_SHARD=0..N-1; firewalls are
assigned by id modulo N. Alerting/retention run only on shard 0.

Products (PRODUCT, docs/architecture/MIGRATION_PLAN.md phase 4): empty (default) runs both products' loops, as today;
`grid` or `nms` runs only that product's loops (LOOP_PRODUCT) and alert rules. The singleton jobs that still share one
database table across products (notification delivery, retention) run only where WORKER_SHARED_JOBS is on: by default
in the combined worker; with separate product workers, set it on exactly one of them until each product has its own
database (phase 6).
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
ROLES = ("all", "core", "snmp")
HEARTBEAT = "/tmp/worker.heartbeat"  # the container health check reads its age
# loop -> product ("shared": singleton job over shared tables; "any": every product process runs its own copy)
LOOP_PRODUCT = {
    "loop_monitor": "any", "alert_evaluation": "any", "ngen_jobs": "any", "retention": "shared",
    "switch_polling": "nms", "firewall_polling": "nms", "policy_sync": "nms", "icmp": "nms", "tacacs": "nms",
    "service_checks": "nms", "iac": "nms", "wireless_analytics": "nms", "config_backup": "nms", "network_compliance": "nms",
    "wireless_integrations": "nms", "traffic_enrichment": "nms", "identity_index": "any",
}
# ngen_jobs entries -> product, same meaning
JOB_PRODUCT = {"notifications": "shared", "reports": "any", "ti_feeds": "grid", "assets": "grid", "saved_searches": "grid",
               "isp_discovery": "nms", "wan_sdwan_outages": "nms"}


def worker_product(value: str | None) -> str | None:
    """PRODUCT: "grid", "nms" or empty (both)."""
    v = (value or "").strip().lower() or None
    if v not in (None, "grid", "nms"):
        raise SystemExit(f"PRODUCT: unknown product {value!r} (use grid or nms, or leave it empty for both)")
    return v


def shared_jobs(product: str | None, value: str | None) -> bool:
    """WORKER_SHARED_JOBS: on by default for the combined worker only."""
    if value is None or value.strip() == "":
        return product is None
    return value.strip().lower() in ("1", "true", "yes", "on")


def runs(owner: str, product: str | None, shared: bool) -> bool:
    if owner == "shared":
        return shared
    return owner == "any" or product is None or owner == product


def worker_roles(value: str | None) -> set[str]:
    """Parse WORKER_ROLES ("all", "core", "snmp" or "core,snmp"); unknown names are an error, not silently ignored."""
    roles = {r.strip().lower() for r in (value or "all").split(",") if r.strip()} or {"all"}
    bad = roles - set(ROLES)
    if bad:
        raise SystemExit(f"WORKER_ROLES: unknown role(s) {', '.join(sorted(bad))} (use {', '.join(ROLES)})")
    return {"core", "snmp"} if "all" in roles else roles


def beat() -> None:
    try:
        with open(HEARTBEAT, "w") as hb:
            hb.write(str(time.time()))
    except OSError:
        pass


async def loop_monitor(stop: asyncio.Event, interval: float = 1.0, report_every: int = 60, warn_lag: float = 0.5) -> None:
    """Event-loop lag: how late a 1 s sleep wakes up. A busy loop (CPU-bound work in a coroutine) shows up here long
    before it shows up as stale polls or slow alerting. Logged every minute; a warning when the worst lag is high."""
    lags: list[float] = []
    while not stop.is_set():
        t0 = time.monotonic()
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
            return
        except asyncio.TimeoutError:
            pass
        lags.append(max(0.0, time.monotonic() - t0 - interval))
        if len(lags) >= report_every:
            lags.sort()
            p95, worst = lags[max(0, int(len(lags) * 0.95) - 1)], lags[-1]
            (log.warning if worst >= warn_lag else log.info)("event loop lag p95 %.3fs max %.3fs over %ds", p95, worst, len(lags))
            lags.clear()
            from . import selfmon   # this process's own health → nms_self_metrics (Monitoring Health page, /api/metrics)
            selfmon.put("loop_lag_p95_s", p95)
            selfmon.put("loop_lag_max_s", worst)
            try:
                await selfmon.flush(get_ch())
            except Exception:
                log.warning("writing self-monitoring metrics failed", exc_info=True)


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
        beat()
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
                ids = [(i, n) for i, n in (await s.execute(select(Firewall.id, Firewall.name).where(
                    Firewall.enabled.is_(True), Firewall.is_demo.is_(False), Firewall.token_ciphertext.is_not(None),
                    Firewall.vendor == "fortinet"))).all() if i % SHARDS == SHARD]
        except Exception:
            log.exception("policy loop error")
            ids = []
        for fw_id, name in ids:  # one session and one error boundary per firewall: a failure never skips the others
            if stop.is_set():
                break
            try:
                async with session_factory()() as s:
                    fw = await s.get(Firewall, fw_id)
                    if fw is None:
                        continue
                    st = await sync_firewall(s, get_ch(), fw)
                    log.info("policy sync %s: %s (%d policies, counters=%s)", name, st.status, st.policies or 0, st.counters_supported)
            except Exception:
                log.exception("policy sync loop error for %s", name)
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass


async def ngen_jobs(stop: asyncio.Event, product: str | None = None, shared: bool = True):
    """Threat-intel feed refresh, asset learning, saved searches, reports and notification delivery (the entries of
    this process's product, JOB_PRODUCT)."""
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
        ("reports", 600, lambda s: reports_due(s, get_ch(), product=product)),
        ("isp_discovery", 3600, lambda s: isp_discover(s)),
        ("wan_sdwan_outages", 300, lambda s: wan_sync_sdwan(s, get_ch())),  # SD-WAN link outages → WAN outages / incidents
    ]
    jobs = [j for j in jobs if runs(JOB_PRODUCT[j[0]], product, shared)]
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
        beat()  # the poller's liveness (in the default role the firewall loop beats as well)
        try:  # polls run in the background (a refilling pool): a short tick refills free slots promptly
            await asyncio.wait_for(stop.wait(), timeout=2)
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
        from . import selfmon
        try:
            async with session_factory()() as s:
                res = await fn(get_ch(), s)
            log.info("%s finished in %.1fs: %s", name, time.monotonic() - started, res)
            selfmon.put(f"loop_seconds:{name}", time.monotonic() - started)
            selfmon.put(f"loop_last_run:{name}", time.time())
        except Exception:
            log.exception("%s failed", name)
            selfmon.add(f"loop_errors:{name}")
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass


def loop_plan(roles: set[str], shard: int, product: str | None = None, shared: bool = True) -> list[str]:
    """The loops this process runs. SNMP polling never shares a process with the core loops unless both roles are
    asked for (the default `all`, kept for single-container installs); a dedicated `snmp` process polls on any shard.
    product / shared narrow the plan to one product's loops (LOOP_PRODUCT)."""
    plan = ["loop_monitor"]
    if "snmp" in roles and (shard == 0 or roles == {"snmp"}):
        plan.append("switch_polling")
    if "core" in roles:
        plan += ["firewall_polling", "policy_sync"]
        if shard == 0:
            plan += ["alert_evaluation", "retention", "ngen_jobs", "icmp", "tacacs", "service_checks", "iac", "wireless_analytics",
                     "config_backup", "network_compliance", "wireless_integrations", "traffic_enrichment", "identity_index"]
    return [x for x in plan if runs(LOOP_PRODUCT[x], product, shared)]


async def main():
    s = get_settings()
    setup_logging(s.log_level)
    init_engine(pool_size=10, max_overflow=max(s.db_max_overflow, worker_pool_need(s) - 10))
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    roles = worker_roles(os.environ.get("WORKER_ROLES"))
    product = worker_product(os.environ.get("PRODUCT"))
    shared = shared_jobs(product, os.environ.get("WORKER_SHARED_JOBS"))
    from .composition import load
    load(product)   # registrations of this process's product(s): alert rules, report sections
    from .iac.executor import loop as iac_loop
    from .wireless.history import run_aggregation as wireless_rollup
    from .configs.alerts import loop_body as config_backup
    from .netcompliance.engine import loop_body as network_compliance
    from .wireless.integrations import run_due as wireless_integrations
    from .traffic.enrich import run_enrichment as traffic_enrichment
    from .platform.identity import run_identity as identity_index
    from .composition import LOADED
    factories = {
        "loop_monitor": lambda: loop_monitor(stop), "switch_polling": lambda: switch_loop(stop), "firewall_polling": lambda: poll_loop(stop),
        "policy_sync": lambda: policy_loop(stop), "alert_evaluation": lambda: periodic(stop, s.alert_interval_seconds, lambda ch, db: run_rules(ch, db, product=product), "alert evaluation"),
        "retention": lambda: periodic(stop, s.retention_interval_seconds, run_retention, "retention"), "ngen_jobs": lambda: ngen_jobs(stop, product, shared),
        "icmp": lambda: icmp_loop(stop), "tacacs": lambda: tacacs_loop(stop), "service_checks": lambda: service_loop(stop),
        "iac": lambda: iac_loop(stop),
        # client history rollup (app/wireless/history.py): the analytics pages read rollups, never raw snapshots per request
        "wireless_analytics": lambda: periodic(stop, s.wireless_analytics_interval_seconds, wireless_rollup, "wireless client rollup"),
        # read-only SSH configuration backup (app/configs): checks every 10 minutes which devices are due
        "config_backup": lambda: periodic(stop, 600, config_backup, "configuration backup"),
        # network compliance (app/netcompliance): hourly check, evaluates daily or when a backup / snapshot changed
        "network_compliance": lambda: periodic(stop, 3600, network_compliance, "network compliance"),
        # SmartZone / Ruckus One / Mist / Aruba Central (app/wireless/integrations.py): each on its own interval
        "wireless_integrations": lambda: periodic(stop, 60, wireless_integrations, "wireless integrations"),
        # application & protocol intelligence (app/traffic/enrich.py): DNS / firewall-app / ASN enrichment of busy destinations
        "traffic_enrichment": lambda: periodic(stop, 300, traffic_enrichment, "traffic enrichment"),
        # shared identity index (app/platform/identity.py): each product's contributors, every 5 minutes
        "identity_index": lambda: periodic(stop, 300, lambda ch, db: identity_index(ch, db, products=set(LOADED) or None), "identity index")}
    tasks = [asyncio.create_task(factories[name](), name=name) for name in loop_plan(roles, SHARD, product, shared)]
    if "core" in roles and SHARD == 0 and shared:
        if s.demo_mode:
            from . import demo
            log.warning("DEMO_MODE enabled: generating synthetic demo events tagged source='demo'")
            tasks.append(asyncio.create_task(demo.run(backfill_hours=float(os.environ.get("DEMO_BACKFILL_HOURS", "6")),
                                                      live=True, step_seconds=5)))
    log.info("worker started: product %s, roles %s, shard %d/%d, shared jobs %s, at %s", product or "both", ",".join(sorted(roles)), SHARD, SHARDS,
             "on" if shared else "off", datetime.now(timezone.utc).isoformat())
    await stop.wait()
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    if "switch_polling" in loop_plan(roles, SHARD, product, shared):
        from .switches.poller import release_on_shutdown
        released = await release_on_shutdown(session_factory())
        if released:
            log.info("released %d in-flight switch leases: %s", len(released), released)
    log.info("worker stopped")


if __name__ == "__main__":
    asyncio.run(main())
