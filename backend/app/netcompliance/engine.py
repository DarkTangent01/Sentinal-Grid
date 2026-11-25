"""Network compliance runs: assemble each device's evidence, evaluate the checks, store the results, score frameworks.

Reads PostgreSQL only (configuration backups, FortiGate snapshots, BGP audit, polling state, TACACS+ clients, syslog
sources). It never contacts a device, so it is safe to run from the API as well as from the worker.
"""
from __future__ import annotations

import logging
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import (BgpRouter, ConfigSnapshot, DeviceConfigSnapshot, Firewall, IngestStat, LogSource, NetComplianceException,
                         NetComplianceResult, NetComplianceRun, Switch, SwitchCredential, TacClient)
from .checks import BY_ID, CATALOG_VERSION, CHECKS, Ctx, address_in, evaluate
from .frameworks import FRAMEWORKS

log = logging.getLogger("netcompliance")
SKIP_TYPES = {"ap", "server"}                   # access points are assessed through their controller; servers are out of scope
KEEP_DAYS = 400                                 # runs kept for audit trend (one a day ≈ 400 rows plus results)
STATUSES = ("pass", "fail", "not_evaluated")


def aware(v: datetime | None) -> datetime | None:
    return v.replace(tzinfo=timezone.utc) if v and not v.tzinfo else v


async def contexts(s: AsyncSession, now: datetime) -> list[Ctx]:
    sws = [x for x in (await s.execute(select(Switch))).scalars() if (x.device_type or "") not in SKIP_TYPES]
    creds = {c.id: c for c in (await s.execute(select(SwitchCredential))).scalars()}
    tac_by_switch, tac_by_fw, tac_by_addr = {}, {}, {}
    for t in (await s.execute(select(TacClient))).scalars():
        d = {"enabled": t.enabled, "last_auth": aware(t.last_authentication_at), "last_accounting": aware(t.last_accounting_at), "name": t.name}
        if t.switch_id:
            tac_by_switch[t.switch_id] = d
        if t.firewall_id:
            tac_by_fw[t.firewall_id] = d
        tac_by_addr[t.address] = d
    sources = [x for x in (await s.execute(select(LogSource).where(LogSource.enabled.is_(True)))).scalars() if x.kind in ("netdev", "syslog")]
    # latest configuration text per switch (one row per change: the newest is the current configuration)
    latest = select(DeviceConfigSnapshot.switch_id, func.max(DeviceConfigSnapshot.taken_at).label("t")).group_by(DeviceConfigSnapshot.switch_id).subquery()
    cfg = {r.switch_id: r.text for r in (await s.execute(select(DeviceConfigSnapshot).join(
        latest, (DeviceConfigSnapshot.switch_id == latest.c.switch_id) & (DeviceConfigSnapshot.taken_at == latest.c.t)))).scalars()}
    fleet: dict[tuple, Counter] = defaultdict(Counter)
    for x in sws:
        if x.model and x.firmware:
            fleet[("switch", x.model)][x.firmware] += 1

    out: list[Ctx] = []
    for x in sws:
        cred = creds.get(x.credential_id) if x.credential_id else None
        tac = tac_by_switch.get(x.id) or tac_by_addr.get(x.address)
        # syslog: exact only when a log source lists this one address (a source covering many devices proves nothing per device)
        exact = [src for src in sources if [str(a) for a in (src.source_ips or [])] == [x.address]]
        covering = [src for src in sources if address_in(x.address, src.source_ips)]
        if exact:
            syslog_at, note = aware(exact[0].last_event_at), f"log source '{exact[0].name}'"
        else:
            syslog_at, note = None, (f"covered by shared log source '{covering[0].name}' (not attributable per device)" if covering else "")
        vendor = (x.vendor_override or x.vendor or "").lower()
        out.append(Ctx(
            kind="switch", id=x.id, name=x.name, now=now, vendor=vendor, device_type=x.device_type or "", role=(x.role or "").lower(),
            site=x.site or "", address=x.address, model=x.model or "", firmware=x.firmware or "",
            fleet_firmware=dict(fleet.get(("switch", x.model), {})),
            config=cfg.get(x.id), config_at=aware(x.config_backup_at), backup_assigned=bool(x.ssh_credential_id),
            backup_error=x.config_backup_error or "", monitoring=x.monitoring, last_success_at=aware(x.last_success_at),
            snmp_version=(cred.version if cred else None), snmp_priv=(bool(cred.priv_protocol) and cred.priv_protocol != "none") if cred else None,
            tacacs=tac, syslog_at=syslog_at, syslog_note=note))

    fws = [f for f in (await s.execute(select(Firewall).where(Firewall.is_demo.is_(False)))).scalars()]
    snaps: dict[int, ConfigSnapshot] = {}
    for sn in (await s.execute(select(ConfigSnapshot).order_by(ConfigSnapshot.collected_at.desc()))).scalars():
        snaps.setdefault(sn.firewall_id, sn)          # newest per firewall (the firewall's own VDOM collection)
    bgp = {b.firewall_id: b for b in (await s.execute(select(BgpRouter))).scalars()}
    syslog = {i.firewall_id: aware(i.last_ingest_time) for i in (await s.execute(select(IngestStat).where(IngestStat.source == "syslog"))).scalars()}
    fw_fleet: dict[str, Counter] = defaultdict(Counter)
    for f in fws:
        ver = f.fortios_version_detected or f.fortios_version_declared
        if f.model and ver:
            fw_fleet[f.model][ver] += 1
    for f in fws:
        sn = snaps.get(f.id)
        b = bgp.get(f.id)
        out.append(Ctx(
            kind="firewall", id=f.id, name=f.name, now=now, vendor="fortinet", device_type="firewall", site=f.site or "", address=f.host,
            model=f.model or "", firmware=f.fortios_version_detected or f.fortios_version_declared or "",
            fleet_firmware=dict(fw_fleet.get(f.model or "", {})), monitoring="active" if f.enabled else "paused",
            last_success_at=aware(f.api_last_success), tacacs=tac_by_fw.get(f.id), syslog_at=syslog.get(f.id),
            fg=sn.data if sn else None, fg_errors=(sn.errors or {}) if sn else {}, fg_at=aware(sn.collected_at) if sn else None,
            bgp_audit=(b.audit or []) if b and b.config is not None else None))
    return out


def evaluate_ctx(ctx: Ctx) -> list[dict]:
    res = evaluate(ctx)
    if ctx.kind == "switch" and ctx.device_type == "firewall":
        # a firewall in the SNMP inventory: its configuration is assessed in the firewall scope (FortiGate snapshot)
        res = [r for r in res if BY_ID[r["check"]].source not in ("config",)]
    return res


def score(counts: dict) -> dict:
    p, f, n = counts.get("pass", 0), counts.get("fail", 0), counts.get("not_evaluated", 0)
    ex = counts.get("excepted", 0)
    return {"pass": p, "fail": f, "not_evaluated": n, "excepted": ex,
            "score": round(100.0 * p / (p + f), 1) if p + f else None,                     # met share of what could be evaluated
            "coverage": round(100.0 * (p + f + ex) / (p + f + n + ex), 1) if p + f + n + ex else None}  # share with evidence


def framework_summary(rows: list[tuple[str, int, list[dict]]], active_exc: list[NetComplianceException] | None = None) -> dict:
    """{framework: score dict + per-control counts}. Excepted results count neither as pass nor as fail."""
    out = {}
    for fk, fw in FRAMEWORKS.items():
        tot: Counter = Counter()
        per: dict[str, Counter] = defaultdict(Counter)
        for kind, dev_id, results in rows:
            for r in results:
                c = BY_ID.get(r["check"])
                if not c or fk not in c.refs:
                    continue
                st = status_with_exceptions(r, kind, dev_id, active_exc)
                tot[st] += 1
                for ctl in c.refs[fk]:
                    per[ctl][st] += 1
        out[fk] = {**score(tot), "controls": {k: score(v) for k, v in per.items()}}
    return out


def status_with_exceptions(r: dict, kind: str, dev_id: int, active: list[NetComplianceException] | None) -> str:
    if r["status"] in ("fail", "not_evaluated") and active:
        for e in active:
            if e.check_id == r["check"] and e.device_kind == kind and (e.device_id is None or e.device_id == dev_id):
                return "excepted"
    return r["status"]


async def active_exceptions(s: AsyncSession, now: datetime | None = None) -> list[NetComplianceException]:
    now = now or datetime.now(timezone.utc)
    return list((await s.execute(select(NetComplianceException).where(NetComplianceException.expires_at > now))).scalars())


async def run(s: AsyncSession, *, trigger: str = "schedule", user: str = "", now: datetime | None = None) -> NetComplianceRun:
    now = now or datetime.now(timezone.utc)
    r = NetComplianceRun(started_at=now, trigger=trigger, triggered_by=user, catalog_version=CATALOG_VERSION)
    s.add(r)
    await s.flush()
    rows, totals = [], Counter()
    for ctx in await contexts(s, now):
        res = evaluate_ctx(ctx)
        totals.update(x["status"] for x in res)
        s.add(NetComplianceResult(run_id=r.id, device_kind=ctx.kind, device_id=ctx.id, device_name=ctx.name[:128], device_type=ctx.device_type[:16],
                                  vendor=ctx.vendor[:16], site=ctx.site[:128], results=res))
        rows.append((ctx.kind, ctx.id, res))
    r.devices = len(rows)
    r.totals = dict(totals)
    # stored without exceptions: the trend shows what the devices are; exceptions are applied when read
    r.summary = {k: {x: v[x] for x in ("pass", "fail", "not_evaluated", "score", "coverage")} for k, v in framework_summary(rows).items()}
    r.finished_at = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=KEEP_DAYS)
    await s.execute(delete(NetComplianceRun).where(NetComplianceRun.started_at < cutoff))
    await s.commit()
    log.info("network compliance run %s: %d devices, %s", r.id, r.devices, dict(totals))
    return r


async def latest_run(s: AsyncSession) -> NetComplianceRun | None:
    return (await s.execute(select(NetComplianceRun).where(NetComplianceRun.finished_at.is_not(None))
                            .order_by(NetComplianceRun.started_at.desc()).limit(1))).scalars().first()


async def due(s: AsyncSession, now: datetime) -> str | None:
    """Daily, and sooner when the evidence changed: a new configuration backup or FortiGate snapshot since the last run."""
    last = await latest_run(s)
    if last is None:
        return "first"
    t = aware(last.started_at)
    if now - t >= timedelta(hours=24):
        return "schedule"
    newer = (await s.execute(select(func.max(DeviceConfigSnapshot.taken_at)))).scalar()
    newer_fw = (await s.execute(select(func.max(ConfigSnapshot.collected_at)))).scalar()
    if any(v and aware(v) > t for v in (newer, newer_fw)):
        return "data"
    return None


async def loop_body(ch, s: AsyncSession) -> dict:
    """Worker loop step (hourly): run when due."""
    now = datetime.now(timezone.utc)
    why = await due(s, now)
    if not why:
        return {"ran": False}
    r = await run(s, trigger="schedule" if why in ("first", "schedule") else "data", now=now)
    return {"ran": True, "run_id": r.id, "devices": r.devices, "trigger": r.trigger}


__all__ = ["contexts", "run", "latest_run", "due", "loop_body", "framework_summary", "active_exceptions", "status_with_exceptions",
           "score", "CHECKS", "STATUSES"]
