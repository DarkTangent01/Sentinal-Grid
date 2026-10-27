"""Single-process development server (NOT for production).

Runs API + syslog receiver + alert engine + retention (+ demo feed if DEMO_MODE) in one process so the embedded
ClickHouse engine (chdb, single-process) and SQLite can be used without Docker. Usage:
    CLICKHOUSE_MODE=embedded DATABASE_URL=sqlite+aiosqlite:///./dev.db ... python -m app.devserver
"""
import asyncio
import logging
import os

import uvicorn

from .alerts.engine import run_rules
from .config import get_settings
from .db.ch import get_ch
from .ingest.pipeline import DeviceRegistry, EventSink
from .main import create_app
from .migrate import main as migrate_main
from .retention import run_retention
from .syslog_server import UDPProtocol, handle_tcp
from .worker import periodic, policy_loop, poll_loop

log = logging.getLogger("devserver")


async def main():
    s = get_settings()
    await asyncio.to_thread(migrate_main)  # alembic env uses asyncio.run, so run it off the event loop
    stop = asyncio.Event()
    registry = DeviceRegistry()
    await registry.refresh()
    from .enrich.enricher import Enricher
    from .worker import icmp_loop, ngen_jobs
    enricher = Enricher()
    await enricher.refresh_ti(force=True)
    sink = EventSink(get_ch(), registry, enricher=enricher)
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(lambda: UDPProtocol(sink), local_addr=("127.0.0.1", s.syslog_udp_port))
    await asyncio.start_server(lambda r, w: handle_tcp(r, w, sink), "127.0.0.1", s.syslog_tcp_port)

    async def flusher():
        while True:
            await asyncio.sleep(s.syslog_flush_seconds)
            await sink.flush()
            await registry.refresh()
            await enricher.refresh_ti()

    tasks = [flusher(), poll_loop(stop), policy_loop(stop), ngen_jobs(stop), icmp_loop(stop), periodic(stop, s.alert_interval_seconds, run_rules, "alerts"),
             periodic(stop, s.retention_interval_seconds, run_retention, "retention")]
    if s.demo_mode:
        from . import demo
        tasks.append(demo.run(backfill_hours=float(os.environ.get("DEMO_BACKFILL_HOURS", "2")), live=True, step_seconds=5))
    server = uvicorn.Server(uvicorn.Config(create_app(), host="127.0.0.1", port=int(os.environ.get("PORT", "8000")), log_level="warning"))
    await asyncio.gather(server.serve(), *tasks)


if __name__ == "__main__":
    asyncio.run(main())
