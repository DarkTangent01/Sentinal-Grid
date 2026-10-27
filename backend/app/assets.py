"""Asset inventory learned from traffic (FortiGate device identification + user fields) plus manual context."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .analytics.filters import table
from .config import get_settings
from .db.ch import ClickHouse
from .db.models import Asset

CRITICALITY = ["low", "normal", "high", "critical"]


def internal_cidrs() -> list[str]:
    return [c.strip() for c in get_settings().internal_cidrs.split(",") if c.strip()]


async def learn_assets(s: AsyncSession, ch: ClickHouse, since: datetime) -> int:
    """Upsert internal source hosts seen since `since`. Manual fields (criticality, tags, owner, notes) are kept."""
    rows = await ch.aquery(f"""
        SELECT src_ip, argMaxIf(src_name, event_time, src_name != '') AS name, argMaxIf(src_mac, event_time, src_mac != '') AS mac,
               argMaxIf(src_os, event_time, src_os != '') AS os, argMaxIf(user, event_time, user != '') AS last_user,
               groupUniqArrayIf(10)(user, user != '') AS users, groupUniqArray(10)(firewall_id) AS fws,
               min(event_time) AS first, max(event_time) AS last
        FROM {table()} WHERE event_time >= {{t0:DateTime64(3)}} AND src_ip != '' AND category IN ('traffic', 'web', 'dns')
          AND arrayExists(c -> isIPAddressInRange(if(isIPv4String(src_ip) OR isIPv6String(src_ip), src_ip, '::'), c), {{cidrs:Array(String)}})
        GROUP BY src_ip LIMIT 100000""", {"t0": since, "cidrs": internal_cidrs()})
    if not rows:
        return 0
    from .policy.store import to_utc
    existing = {a.ip: a for a in (await s.execute(select(Asset).where(Asset.ip.in_([r["src_ip"] for r in rows])))).scalars()}
    for r in rows:
        a = existing.get(r["src_ip"])
        if a is None:
            a = Asset(ip=r["src_ip"], first_seen=to_utc(r["first"]), users=[], firewall_ids=[], tags=[], source="observed")
            s.add(a)
        a.hostname = r["name"] or a.hostname
        a.mac = r["mac"] or a.mac
        a.os = r["os"] or a.os
        a.last_user = r["last_user"] or a.last_user
        a.users = sorted(set(a.users or []) | set(r["users"] or []))[:25]
        a.firewall_ids = sorted(set(a.firewall_ids or []) | {int(x) for x in r["fws"]})
        a.last_seen = max(filter(None, [to_utc(r["last"]), a.last_seen if a.last_seen is None or a.last_seen.tzinfo else a.last_seen.replace(tzinfo=timezone.utc)]))
    await s.commit()
    return len(rows)


async def asset_map(s: AsyncSession, ips: list[str]) -> dict[str, Asset]:
    ips = [i for i in set(ips) if i]
    if not ips:
        return {}
    return {a.ip: a for a in (await s.execute(select(Asset).where(Asset.ip.in_(ips)))).scalars()}


def bump(severity: str, criticality: str) -> str:
    """Raise alert severity one level for critical assets (high-value targets), never above critical."""
    order = ["informational", "low", "medium", "high", "critical"]
    if criticality != "critical" or severity not in order:
        return severity
    return order[min(len(order) - 1, order.index(severity) + 1)]


async def learn_recent(s: AsyncSession, ch: ClickHouse, minutes: int = 15) -> int:
    return await learn_assets(s, ch, datetime.now(timezone.utc) - timedelta(minutes=minutes))
