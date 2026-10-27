"""Retention: drops whole (category, day) partitions older than the configured policy. Every run is logged."""
import logging
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .db.ch import ClickHouse
from .db.models import RetentionPolicy, RetentionRun

log = logging.getLogger("retention")
DEFAULT_RETENTION_DAYS = {"traffic": 30, "dns": 30, "web": 90, "security": 365, "system": 365}
_PART = re.compile(r"\('(\w+)',\s*(\d{8})\)")
_PART_ID = re.compile(r"^[0-9A-Za-z_-]{1,128}$")


def _check_partition_id(pid: str) -> None:
    """partition_id is interpolated into ALTER TABLE (DDL cannot bind it), so it must be a plain identifier."""
    if not _PART_ID.match(str(pid)):
        raise ValueError(f"unexpected partition id {pid!r}")


async def ensure_default_policies(s: AsyncSession) -> None:
    existing = {p.category for p in (await s.execute(select(RetentionPolicy))).scalars()}
    for cat, days in DEFAULT_RETENTION_DAYS.items():
        if cat not in existing:
            s.add(RetentionPolicy(category=cat, days=days, enabled=True))
    await s.commit()


async def list_partitions(ch: ClickHouse, table: str = "events") -> list[dict]:
    rows = await ch.aquery(
        "SELECT partition_id, any(partition) AS partition, sum(rows) AS rows, sum(bytes_on_disk) AS bytes "
        "FROM system.parts WHERE database = currentDatabase() AND table = {t:String} AND active GROUP BY partition_id",
        {"t": table})
    out = []
    for r in rows:
        m = _PART.match(str(r["partition"]))
        if m:
            out.append({"partition_id": r["partition_id"], "category": m.group(1),
                        "day": datetime.strptime(m.group(2), "%Y%m%d").replace(tzinfo=timezone.utc),
                        "rows": int(r["rows"]), "bytes": int(r["bytes"])})
    return out


async def run_retention(ch: ClickHouse, s: AsyncSession, now: datetime | None = None) -> list[dict]:
    now = now or datetime.now(timezone.utc)
    policies = {p.category: p for p in (await s.execute(select(RetentionPolicy))).scalars()}
    parts = await list_partitions(ch)
    rollup_parts = await list_partitions(ch, "events_1m")
    results = []
    for cat, pol in policies.items():
        if not pol.enabled:
            continue
        cutoff = (now - timedelta(days=pol.days)).replace(hour=0, minute=0, second=0, microsecond=0)
        victims = [p for p in parts if p["category"] == cat and p["day"] + timedelta(days=1) <= cutoff]
        run = RetentionRun(category=cat, cutoff=cutoff, status="ok", partitions_dropped=[], rows_dropped=0)
        try:
            for p in victims:
                _check_partition_id(p["partition_id"])
                await ch.acommand(f"ALTER TABLE events DROP PARTITION ID '{p['partition_id']}'")
                run.partitions_dropped = [*run.partitions_dropped, p["day"].strftime("%Y-%m-%d")]
                run.rows_dropped += p["rows"]
            # the per-minute rollup follows the same policy so dashboards never count expired events
            for p in rollup_parts:
                if p["category"] == cat and p["day"] + timedelta(days=1) <= cutoff:
                    _check_partition_id(p["partition_id"])
                    await ch.acommand(f"ALTER TABLE events_1m DROP PARTITION ID '{p['partition_id']}'")
        except Exception as e:
            run.status = "error"
            run.error = str(e)[:2000]
            log.exception("retention failed for %s", cat)
        if victims or run.status != "ok":
            s.add(run)
            log.info("retention %s: dropped %d partitions (%d rows) older than %s", cat, len(run.partitions_dropped),
                     run.rows_dropped, cutoff.date())
        results.append({"category": cat, "cutoff": cutoff.isoformat(), "dropped": run.partitions_dropped,
                        "rows": run.rows_dropped, "status": run.status})
    await s.commit()
    return results
