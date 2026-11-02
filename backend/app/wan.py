"""WAN observability: outage records, WAN incidents, correlation and settings (docs/WAN.md).

One source of truth
    `wan_outages` holds every confirmed outage (and degradation episode) of an ICMP target or SD-WAN link. Outage
    counts, downtime, availability and the ISP incident analytics all read it, so the live monitoring page and the
    incident dashboard cannot disagree. ISP incidents are rows of the existing `incidents` table with category "wan":
    the same case workflow (status, owner, comments, evidence) as security incidents, plus site / ISP / circuit and
    root-cause fields.

Timing convention
    started_at  first failed observation of the streak that crossed the failure threshold
    last_ok_at  last healthy observation before it (the physical failure happened between the two)
    detected_at when the threshold was met (started_at + (down_after - 1) intervals)
    recovered_at first healthy observation of the streak that crossed the recovery threshold
    recovery_detected_at when the recovery threshold was met
    duration = recovered_at - started_at; time to detect = detected_at - started_at.

Incident correlation (setting "correlation")
    target   one incident per monitored target
    circuit  (default) targets of the same circuit join one incident while their outages overlap
    site     every circuit of a site joins one incident while outages overlap
    An outage joins an open incident only while that incident still has an outage in progress (or one that recovered
    less than merge_gap_seconds ago, default 0): distinct outages are never merged just because they were close.

Root cause
    Categories are classification options a person confirms. The system only records the detected symptom and an
    evidence-based *probable* cause (investigate()); ICMP failure alone is never reported as an ISP root cause.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import or_, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from .db.models import (Firewall, IcmpTarget, Incident, IncidentComment, IspLink, WanCollector, WanMaintenance, WanOutage,
                        WanSetting)

log = logging.getLogger("wan")
WAN_OPEN = ("open", "in_progress", "monitoring")
STATUSES = ("open", "in_progress", "monitoring", "resolved", "closed")
STATUS_LABEL = {"open": "Open", "in_progress": "Investigating", "monitoring": "Monitoring", "resolved": "Resolved", "closed": "Closed"}
ROOT_CAUSES = [
    {"key": "isp_outage", "label": "ISP outage"}, {"key": "isp_packet_loss", "label": "ISP packet loss"},
    {"key": "isp_latency", "label": "ISP latency degradation"}, {"key": "last_mile", "label": "Last-mile circuit issue"},
    {"key": "power", "label": "Power failure"}, {"key": "firewall_wan", "label": "Firewall or WAN interface failure"},
    {"key": "upstream_routing", "label": "Upstream routing issue"}, {"key": "dns", "label": "DNS issue"},
    {"key": "probe_failure", "label": "Monitoring probe failure"}, {"key": "local_lan", "label": "Local LAN issue"},
    {"key": "planned_maintenance", "label": "Planned maintenance"}, {"key": "unknown", "label": "Unknown / under investigation"},
]
DEFAULT_SETTINGS = {
    "correlation": "circuit",          # target | circuit | site
    "merge_gap_seconds": 0,
    "recovery_action": "resolve",      # resolve | monitoring | none: what recovery does to an incident nobody is working on
    "severity_primary": "high",
    "severity_backup": "medium",
    "degraded_incidents": False,       # open incidents for degradation episodes too
    "stale_after_seconds": 180,        # collector heartbeat older than this: monitoring is stale
    "gap_factor": 3,                   # a pause between checks longer than gap_factor x interval is an unobserved gap
    "root_cause_categories": ROOT_CAUSES,
}
WAN_TASKS = ["Confirm the outage scope (one target, circuit, ISP, site) from the investigation panel",
             "Check the firewall WAN interface and SD-WAN health checks for the circuit",
             "Raise a ticket with the provider if the circuit itself failed (record the ticket number)",
             "Record the confirmed root cause and resolution notes"]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def aware(v):
    if v is None:
        return None
    if isinstance(v, str):
        v = datetime.fromisoformat(v.replace("Z", "+00:00").replace(" ", "T", 1))
    return v if v.tzinfo else v.replace(tzinfo=timezone.utc)


# ------------------------------------------------------------------ settings
async def _settings_row(s: AsyncSession) -> WanSetting:
    row = (await s.execute(select(WanSetting).order_by(WanSetting.id).limit(1))).scalars().first()
    if row is None:
        row = WanSetting(data={})
        s.add(row)
        await s.flush()
    return row


async def settings(s: AsyncSession) -> dict:
    row = (await s.execute(select(WanSetting).order_by(WanSetting.id).limit(1))).scalars().first()
    return {**DEFAULT_SETTINGS, **((row.data if row else None) or {})}


def validate_settings(data: dict) -> dict:
    out = {}
    if "correlation" in data:
        if data["correlation"] not in ("target", "circuit", "site"):
            raise ValueError("correlation must be target, circuit or site")
        out["correlation"] = data["correlation"]
    if "recovery_action" in data:
        if data["recovery_action"] not in ("resolve", "monitoring", "none"):
            raise ValueError("recovery_action must be resolve, monitoring or none")
        out["recovery_action"] = data["recovery_action"]
    for k in ("severity_primary", "severity_backup"):
        if k in data:
            if data[k] not in ("low", "medium", "high", "critical"):
                raise ValueError(f"{k} must be low, medium, high or critical")
            out[k] = data[k]
    for k, lo, hi in (("merge_gap_seconds", 0, 86400), ("stale_after_seconds", 30, 86400), ("gap_factor", 2, 20)):
        if k in data:
            v = int(data[k])
            if not lo <= v <= hi:
                raise ValueError(f"{k} must be between {lo} and {hi}")
            out[k] = v
    if "degraded_incidents" in data:
        out["degraded_incidents"] = bool(data["degraded_incidents"])
    if "root_cause_categories" in data:
        cats, seen = [], set()
        for c in data["root_cause_categories"] or []:
            key, label = str(c.get("key", "")).strip().lower(), str(c.get("label", "")).strip()
            if not key or not label or len(key) > 48 or len(label) > 128 or not all(ch.isalnum() or ch in "_-" for ch in key):
                raise ValueError("each root-cause category needs a key (letters, digits, _ or -, up to 48) and a label")
            if key not in seen:
                seen.add(key)
                cats.append({"key": key, "label": label})
        if not cats:
            raise ValueError("keep at least one root-cause category")
        out["root_cause_categories"] = cats
    return out


async def save_settings(s: AsyncSession, data: dict, user: str) -> dict:
    row = await _settings_row(s)
    row.data = {**(row.data or {}), **validate_settings(data)}
    row.updated_by = user
    await s.commit()
    return await settings(s)


# ------------------------------------------------------------------ inventory labels
class Ctx:
    """Circuit / ISP / site context of a target, resolved once per poll cycle."""

    def __init__(self, links: dict[int, IspLink], fws: dict[int, Firewall]):
        self.links, self.fws = links, fws

    @classmethod
    async def load(cls, s: AsyncSession) -> "Ctx":
        return cls({x.id: x for x in (await s.execute(select(IspLink))).scalars()},
                   {x.id: x for x in (await s.execute(select(Firewall))).scalars()})

    def link(self, t: IcmpTarget) -> IspLink | None:
        return self.links.get(t.isp_link_id) if t.isp_link_id else None

    def isp(self, t: IcmpTarget) -> str:
        lk = self.link(t)
        if lk:
            return lk.isp_name or lk.as_org or lk.alias or lk.interface or t.isp_name or "(no provider)"
        return t.isp_name or "(no provider)"

    def link_site(self, lk: IspLink | None) -> str:
        if not lk:
            return ""
        fw = self.fws.get(lk.firewall_id) if lk.firewall_id else None
        return lk.site or (fw.site if fw else "") or (fw.name if fw else "")

    def site(self, t: IcmpTarget) -> str:
        return t.site or self.link_site(self.link(t)) or "(no site)"

    def circuit_key(self, t: IcmpTarget) -> str:
        return f"circuit:{t.isp_link_id}" if t.isp_link_id else f"target:{t.id}"

    def circuit_name(self, t: IcmpTarget) -> str:
        lk = self.link(t)
        return circuit_label(lk, self.fws) if lk else t.name

    def firewall_id(self, t: IcmpTarget) -> int | None:
        lk = self.link(t)
        return lk.firewall_id if lk else None


def circuit_label(lk: IspLink, fws: dict[int, Firewall] | None = None) -> str:
    fw = (fws or {}).get(lk.firewall_id) if lk.firewall_id else None
    base = lk.name or " ".join(x for x in (lk.isp_name or lk.as_org or lk.alias, lk.circuit_id) if x) or lk.interface or f"circuit {lk.id}"
    return f"{base} ({fw.name}/{lk.interface})" if fw and not lk.name else base


# ------------------------------------------------------------------ maintenance
def maintenance_matches(m: WanMaintenance, *, site: str, isp: str, link_id: int | None, target_id: int | None) -> bool:
    v = (m.scope_value or "").strip().lower()
    return (m.scope == "all" or (m.scope == "site" and v == site.lower()) or (m.scope == "isp" and v == isp.lower())
            or (m.scope == "circuit" and link_id is not None and v == str(link_id))
            or (m.scope == "target" and target_id is not None and v == str(target_id)))


async def active_maintenance(s: AsyncSession, at: datetime, **scope) -> WanMaintenance | None:
    for m in (await s.execute(select(WanMaintenance).where(WanMaintenance.starts_at <= at, WanMaintenance.ends_at > at))).scalars():
        if maintenance_matches(m, **scope):
            return m
    return None


# ------------------------------------------------------------------ outages (called by the prober on state changes)
async def _lock(s: AsyncSession, key: str) -> None:
    """Serialise incident correlation per key across workers (PostgreSQL advisory lock; no-op on SQLite)."""
    if s.bind.dialect.name == "postgresql":
        h = int.from_bytes(hashlib.sha1(key.encode()).digest()[:8], "big", signed=True)
        await s.execute(text("SELECT pg_advisory_xact_lock(:h)"), {"h": h})


async def open_outage(s: AsyncSession, t: IcmpTarget, ctx: Ctx, *, kind: str, started_at: datetime, detected_at: datetime,
                      last_ok_at: datetime | None, failed_checks: int, evidence: dict, cfg: dict | None = None) -> WanOutage:
    """Idempotent: an open outage of the same kind for the target is returned as is (worker restart, duplicate job)."""
    cur = (await s.execute(select(WanOutage).where(WanOutage.target_id == t.id, WanOutage.source == "icmp", WanOutage.kind == kind,
                                                   WanOutage.recovered_at.is_(None)))).scalars().first()
    if cur:
        return cur
    cfg = cfg or await settings(s)
    lk = ctx.link(t)
    site, isp = ctx.site(t), ctx.isp(t)
    m = await active_maintenance(s, started_at, site=site, isp=isp, link_id=t.isp_link_id, target_id=t.id)
    o = WanOutage(source="icmp", kind=kind, target_id=t.id, isp_link_id=t.isp_link_id, firewall_id=lk.firewall_id if lk else None,
                  target_name=t.name, address=t.address, isp_name=isp, site=site, circuit_name=ctx.circuit_name(t),
                  last_ok_at=last_ok_at, started_at=started_at, detected_at=detected_at, failed_checks=failed_checks,
                  evidence=evidence, maintenance_id=m.id if m else None, created_at=_now())
    try:
        async with s.begin_nested():
            s.add(o)
    except IntegrityError:  # another worker opened it first (unique open-outage index)
        return (await s.execute(select(WanOutage).where(WanOutage.target_id == t.id, WanOutage.source == "icmp", WanOutage.kind == kind,
                                                        WanOutage.recovered_at.is_(None)))).scalars().one()
    if m is None and (kind == "down" or cfg.get("degraded_incidents")):
        role = lk.role if lk else "primary"
        await attach_incident(s, o, cfg, key=_corr_key(cfg, ctx, t), entity=_corr_entity(cfg, ctx, t), role=role)
        await notify_outage(s, o)
    return o


async def close_outage(s: AsyncSession, t: IcmpTarget, *, kind: str, recovered_at: datetime, detected_at: datetime,
                       evidence: dict, cfg: dict | None = None) -> WanOutage | None:
    o = (await s.execute(select(WanOutage).where(WanOutage.target_id == t.id, WanOutage.source == "icmp", WanOutage.kind == kind,
                                                 WanOutage.recovered_at.is_(None)))).scalars().first()
    if o is None:
        return None
    await finish_outage(s, o, recovered_at, detected_at, evidence, cfg)
    return o


async def finish_outage(s: AsyncSession, o: WanOutage, recovered_at: datetime, detected_at: datetime, evidence: dict,
                        cfg: dict | None = None) -> None:
    recovered_at = max(recovered_at, aware(o.started_at))
    o.recovered_at, o.recovery_detected_at = recovered_at, detected_at
    o.duration_s = int((recovered_at - aware(o.started_at)).total_seconds())
    o.evidence = {**(o.evidence or {}), "recovery": evidence}
    if o.incident_id:
        await on_outage_closed(s, o, cfg or await settings(s))
        await notify_recovery(s, o)


def _corr_key(cfg: dict, ctx: Ctx, t: IcmpTarget) -> str:
    mode = cfg.get("correlation", "circuit")
    if mode == "target":
        return f"target:{t.id}"
    if mode == "site":
        return f"site:{ctx.site(t).lower()}"
    return ctx.circuit_key(t)


def _corr_entity(cfg: dict, ctx: Ctx, t: IcmpTarget) -> tuple[str, str]:
    mode = cfg.get("correlation", "circuit")
    if mode == "target":
        return "target", f"{t.name} ({t.address})"
    if mode == "site":
        return "site", ctx.site(t)
    return ("circuit", ctx.circuit_name(t)) if t.isp_link_id else ("target", f"{t.name} ({t.address})")


async def attach_incident(s: AsyncSession, o: WanOutage, cfg: dict, *, key: str, entity: tuple[str, str], role: str = "primary") -> Incident:
    from .incidents import SLA
    await _lock(s, key)
    now = _now()
    gap = timedelta(seconds=int(cfg.get("merge_gap_seconds") or 0))
    for inc in (await s.execute(select(Incident).where(Incident.category == "wan", Incident.correlation_key == key,
                                                       Incident.status.in_(WAN_OPEN)).order_by(Incident.id.desc()))).scalars():
        outs = (await s.execute(select(WanOutage).where(WanOutage.incident_id == inc.id))).scalars().all()
        live = [x for x in outs if x.recovered_at is None or aware(x.recovered_at) >= aware(o.started_at) - gap]
        if live:
            o.incident_id = inc.id
            inc.last_seen = max(aware(inc.last_seen), aware(o.detected_at))
            inc.title = _title(inc, len(outs) + 1)
            s.add(IncidentComment(incident_id=inc.id, author="system", kind="system",
                                  body=f"Outage #{o.id or 'new'} of {o.target_name} ({o.address}) joined: it overlaps an outage already in this "
                                       f"incident ({cfg.get('correlation', 'circuit')} correlation)."))
            if inc.status == "monitoring":  # it failed again while being watched
                inc.status = "open"
                s.add(IncidentComment(incident_id=inc.id, author="system", kind="status", body="Status monitoring → open (new outage)"))
            return inc
    sev = cfg.get("severity_backup", "medium") if role == "backup" else cfg.get("severity_primary", "high")
    ack, res = SLA.get(sev, SLA["medium"])
    from secrets import token_hex
    inc = Incident(category="wan", title="", entity_type=entity[0], entity=entity[1][:255], status="open", severity=sev,
                   site=o.site, isp_name=o.isp_name, isp_link_id=o.isp_link_id, correlation_key=key, first_seen=aware(o.started_at),
                   last_seen=aware(o.detected_at), created_at=now, sla_ack_due=now + ack, sla_resolve_due=now + res,
                   summary=(f"Detected symptom: {o.target_name}{f' ({o.address})' if o.address else ''} stopped answering ICMP — "
                            f"{o.failed_checks} consecutive failed checks." if o.source == "icmp" else
                            f"Detected symptom: every SD-WAN health check on {o.circuit_name or o.target_name} failed at the same time "
                            f"({', '.join((o.evidence or {}).get('checks', [])) or 'all checks'}) for at least the minimum outage duration."),
                   rule_keys=["wan_outage"], evidence=[], linked=[],
                   tasks=[{"id": token_hex(4), "text": x, "done": False, "added_by": "system"} for x in WAN_TASKS])
    inc.title = _title(inc, 1)
    s.add(inc)
    await s.flush()
    o.incident_id = inc.id
    await s.flush()
    try:
        inv = await investigate(s, at=aware(o.detected_at), target_id=o.target_id, link_id=o.isp_link_id, site=o.site)
        inc.probable_cause = f"{inv['label']}: {inv['explanation']}"
    except Exception:  # investigation is advisory; never block incident creation
        log.exception("wan investigation failed")
    s.add(IncidentComment(incident_id=inc.id, author="system", kind="system",
                          body=f"Incident opened by confirmed outage #{o.id} of {o.target_name} ({o.address}); "
                               f"last healthy check {aware(o.last_ok_at).isoformat() if o.last_ok_at else 'never'}, "
                               f"first failed check {aware(o.started_at).isoformat()}, confirmed {aware(o.detected_at).isoformat()}."))
    return inc


def _title(inc: Incident, outages: int) -> str:
    who = " ".join(x for x in (inc.isp_name, inc.site) if x and not x.startswith("("))
    return f"{who + ': ' if who else ''}{inc.entity} down" + (f" ({outages} outages)" if outages > 1 else "")


async def on_outage_closed(s: AsyncSession, o: WanOutage, cfg: dict) -> None:
    inc = await s.get(Incident, o.incident_id)
    if inc is None:
        return
    s.add(IncidentComment(incident_id=inc.id, author="system", kind="system",
                          body=f"Outage #{o.id} of {o.target_name} recovered at {aware(o.recovered_at).isoformat()} after {fmt_dur(o.duration_s)} "
                               f"(recovery confirmed {aware(o.recovery_detected_at).isoformat()})."))
    inc.last_seen = max(aware(inc.last_seen), aware(o.recovery_detected_at))
    still = (await s.execute(select(WanOutage.id).where(WanOutage.incident_id == inc.id, WanOutage.recovered_at.is_(None),
                                                        WanOutage.id != o.id))).first()
    if still or inc.status not in WAN_OPEN:
        return
    action = cfg.get("recovery_action", "resolve")
    if action == "none":
        return
    if inc.status == "open" and action == "resolve":
        inc.status = "resolved"
        inc.resolved_at = aware(o.recovered_at)
        s.add(IncidentComment(incident_id=inc.id, author="system", kind="status",
                              body="Status open → resolved (every outage recovered; root cause still to be recorded)"))
    elif inc.status in ("open", "in_progress"):
        # someone is investigating (or the policy says so): keep the case, watch for recurrence
        old, inc.status = inc.status, "monitoring"
        s.add(IncidentComment(incident_id=inc.id, author="system", kind="status", body=f"Status {old} → monitoring (service recovered)"))


def fmt_dur(sec: int | float | None) -> str:
    if sec is None:
        return "—"
    sec = int(sec)
    d, r = divmod(sec, 86400)
    h, r = divmod(r, 3600)
    m, s_ = divmod(r, 60)
    return " ".join(x for x in (f"{d}d" if d else "", f"{h}h" if h else "", f"{m}m" if m else "", f"{s_}s" if s_ and not d else "") if x) or "0s"


# ------------------------------------------------------------------ notifications (existing outbox, rules and channels)
async def notify_outage(s: AsyncSession, o: WanOutage) -> None:
    from .notify import _link, enqueue
    inc = await s.get(Incident, o.incident_id) if o.incident_id else None
    await enqueue(s, "wan.outage", {
        "title": f"[OUTAGE] {o.isp_name} {o.site}: {o.target_name} down",
        "text": f"{o.target_name} ({o.address}) is down since {aware(o.started_at):%Y-%m-%d %H:%M:%S} UTC (first failed check; "
                f"confirmed after {o.failed_checks} consecutive failures).",
        "fields": {"ISP": o.isp_name, "Site": o.site, "Circuit": o.circuit_name or "—", "Incident": f"#{inc.id}" if inc else "—",
                   "Probable cause": (inc.probable_cause if inc else "") or "—"},
        "url": _link(f"/isp?tab=incidents&id={inc.id}" if inc else "/isp?tab=live")},
        severity=inc.severity if inc else "medium", dedupe_key=f"wan:outage:{o.id}", rule_key="wan_outage")


async def notify_recovery(s: AsyncSession, o: WanOutage) -> None:
    from .notify import _link, enqueue
    inc = await s.get(Incident, o.incident_id) if o.incident_id else None
    await enqueue(s, "wan.recovered", {
        "title": f"[RECOVERED] {o.isp_name} {o.site}: {o.target_name} up after {fmt_dur(o.duration_s)}",
        "text": f"{o.target_name} ({o.address}) answered again at {aware(o.recovered_at):%Y-%m-%d %H:%M:%S} UTC. "
                f"Outage duration {fmt_dur(o.duration_s)} (first failed check to first good check).",
        "fields": {"ISP": o.isp_name, "Site": o.site, "Duration": fmt_dur(o.duration_s), "Incident": f"#{inc.id} ({inc.status})" if inc else "—"},
        "url": _link(f"/isp?tab=incidents&id={inc.id}" if inc else "/isp?tab=live")},
        severity=inc.severity if inc else "medium", dedupe_key=f"wan:recovered:{o.id}", rule_key="wan_outage")


# ------------------------------------------------------------------ collector health
async def collector(s: AsyncSession) -> WanCollector:
    row = await s.get(WanCollector, 1)
    if row is None:
        row = WanCollector(id=1)
        s.add(row)
    return row


def collector_status(row: WanCollector | None, now: datetime, stale_after: int) -> dict:
    if row is None or row.heartbeat_at is None:
        return {"status": "never_ran", "heartbeat_at": None, "last_success_at": None, "detail": "the ICMP collector has not run yet"}
    hb, ok = aware(row.heartbeat_at), aware(row.last_success_at)
    age = (now - hb).total_seconds()
    status = "stale" if age > stale_after else ("degraded" if row.last_errors or row.backlog else "ok")
    detail = (f"no heartbeat for {fmt_dur(age)}: target states are frozen at their last known value" if status == "stale" else
              f"{row.last_errors} probe error(s), {row.backlog} target(s) left for the next cycle" if status == "degraded" else "collecting")
    return {"status": status, "heartbeat_at": hb.isoformat(), "last_success_at": ok.isoformat() if ok else None, "age_s": round(age),
            "last_duration_ms": row.last_duration_ms, "last_checked": row.last_checked, "last_errors": row.last_errors,
            "backlog": row.backlog, "last_error": row.last_error, "worker": row.worker, "detail": detail}


# ------------------------------------------------------------------ correlation / investigation
CLASS_LABEL = {"monitoring_system": "Monitoring system problem", "site_wide": "Site-wide outage (power, firewall, LAN or site uplinks)",
               "firewall_or_local": "Firewall or local network problem", "isp_wide": "ISP-wide problem", "circuit": "Single circuit failure",
               "single_target": "Single target unreachable", "none": "No outage in progress", "insufficient": "Insufficient evidence"}


async def investigate(s: AsyncSession, *, at: datetime | None = None, target_id: int | None = None, link_id: int | None = None,
                      site: str | None = None) -> dict:
    """Explainable classification of an outage at `at` from overlapping outage records of related targets / links and the
    collector heartbeat. Every conclusion lists the evidence it rests on; it is a probable cause, not a root cause."""
    at = at or _now()
    cfg = await settings(s)
    ctx = await Ctx.load(s)
    targets = (await s.execute(select(IcmpTarget))).scalars().all()
    tmap = {t.id: t for t in targets}
    focus = tmap.get(target_id) if target_id else None
    if focus is not None:
        link_id = link_id or focus.isp_link_id
        site = site or ctx.site(focus)
    lk = ctx.links.get(link_id) if link_id else None
    site = site or ctx.link_site(lk) or ""
    if site.startswith("("):  # "(no site)" placeholder groups unrelated targets: not evidence
        site = ""
    outs = (await s.execute(select(WanOutage).where(WanOutage.kind == "down", WanOutage.started_at <= at,
                                                    or_(WanOutage.recovered_at.is_(None), WanOutage.recovered_at > at)))).scalars().all()
    down_t = {o.target_id for o in outs if o.source == "icmp" and o.target_id}
    down_links = {o.isp_link_id for o in outs if o.source == "sdwan" and o.isp_link_id}
    ev: list[dict] = []
    row = await s.get(WanCollector, 1)
    if row and row.heartbeat_at and at - aware(row.heartbeat_at) > timedelta(seconds=int(cfg["stale_after_seconds"])) and at > aware(row.heartbeat_at):
        ev.append({"kind": "collector", "ok": False, "text": f"ICMP collector silent since {aware(row.heartbeat_at).isoformat()}"})
        return _verdict("monitoring_system", ev, "The SIEM's own prober stopped; target states are not trustworthy until it runs again.")
    if row and row.last_errors and focus is not None and focus.last_error:
        ev.append({"kind": "collector", "ok": False, "text": f"local probe errors on the SIEM ({focus.last_error[:120]})"})
    if focus is not None and focus.id not in down_t and not (lk and lk.id in down_links):
        return _verdict("none", ev, f"{focus.name} had no confirmed outage at that time.")
    active = [t for t in targets if t.enabled]
    site_t = [t for t in active if site and ctx.site(t).lower() == site.lower()]
    circ_t = [t for t in active if link_id and t.isp_link_id == link_id]
    isp = (ctx.isp(focus) if focus else (lk.isp_name if lk else "")) or ""
    isp_t = [t for t in active if isp and ctx.isp(t).lower() == isp.lower()]

    def share(ts):
        return sum(1 for t in ts if t.id in down_t), len(ts)
    if focus is None and not circ_t and not site_t:
        if lk and lk.id in down_links:
            ev.append({"kind": "sdwan", "ok": False, "text": "every SD-WAN health check on the link failed together (the firewall's own measurement)"})
            return _verdict("circuit", ev, "The firewall lost every SD-WAN health-check target on this link at once. Add an ICMP target for the "
                                           "circuit's gateway to confirm from a second vantage point.")
        return _verdict("insufficient", ev, "No monitored targets match the selection.")
    c_down, c_n = share(circ_t)
    s_down, s_n = share(site_t)
    i_down, i_n = share(isp_t)
    if circ_t:
        ev.append({"kind": "circuit", "ok": c_down == 0, "text": f"{c_down} of {c_n} target(s) on circuit {circuit_label(lk, ctx.fws) if lk else ''} down"})
    if site_t:
        ev.append({"kind": "site", "ok": s_down == 0, "text": f"{s_down} of {s_n} target(s) at site {site} down"})
    isp_sites = {ctx.site(t) for t in isp_t if t.id in down_t}
    if isp_t:
        ev.append({"kind": "isp", "ok": i_down == 0, "text": f"{i_down} of {i_n} {isp} target(s) down across {len(isp_sites)} site(s)"})
    if lk and lk.firewall_id:
        if lk.id in down_links:
            ev.append({"kind": "sdwan", "ok": False, "text": "the firewall's SD-WAN health checks also report this link down"})
        else:
            ev.append({"kind": "sdwan", "ok": True, "text": "no SD-WAN outage recorded for this link at that time (checks healthy or not logged)"})
        fw_links = [x for x in ctx.links.values() if x.firewall_id == lk.firewall_id and not x.hidden]
        fw_t = [t for t in active if t.isp_link_id in {x.id for x in fw_links}]
        f_down, f_n = share(fw_t)
        if f_n > c_n:
            ev.append({"kind": "firewall", "ok": f_down < f_n, "text": f"{f_down} of {f_n} target(s) behind firewall {ctx.fws[lk.firewall_id].name if lk.firewall_id in ctx.fws else lk.firewall_id} down"})
    if s_n >= 2 and s_down == s_n and len({t.isp_link_id for t in site_t}) >= 2:
        return _verdict("site_wide", ev, f"Every monitored target at {site} failed together across circuits of different providers: "
                                         "more likely power, firewall, LAN or the site's uplinks than one ISP.")
    if lk and lk.firewall_id and any(e["kind"] == "firewall" and not e["ok"] for e in ev):
        return _verdict("firewall_or_local", ev, "All circuits behind the same firewall are down: check the firewall and local network first.")
    if i_down >= 2 and len(isp_sites) >= 2:
        return _verdict("isp_wide", ev, f"{isp} targets are down at {len(isp_sites)} sites at the same time.")
    if circ_t and c_down == c_n and c_n >= 1 and (c_n >= 2 or (lk and lk.id in down_links) or s_n > c_n):
        why = "every target on the circuit is down" + (" and the firewall's SD-WAN checks agree" if lk and lk.id in down_links else "") + \
              (" while other circuits at the site are up" if s_n > c_n and s_down < s_n else "")
        return _verdict("circuit", ev, why[0].upper() + why[1:] + ".")
    if focus is not None and focus.id in down_t:
        if circ_t and c_down < c_n:
            return _verdict("single_target", ev, "Other targets on the same circuit still answer: the path to this address (or the host) "
                                                 "is affected, not the whole circuit.")
        return _verdict("single_target" if not circ_t else "circuit", ev,
                        "Only this target is monitored for the circuit: add the gateway or a second target to tell a host problem from a circuit failure.")
    if not down_t and not down_links:
        return _verdict("none", ev, "No outage overlaps the selected time.")
    return _verdict("insufficient", ev, "The overlapping outages do not match a single pattern.")


def _verdict(cls: str, ev: list[dict], explanation: str) -> dict:
    return {"classification": cls, "label": CLASS_LABEL[cls], "explanation": explanation, "evidence": ev,
            "note": "Probable cause from correlated monitoring evidence; confirm before recording a root cause."}


# ------------------------------------------------------------------ SD-WAN link outages → outage records / incidents
async def sync_sdwan(s: AsyncSession, ch, now: datetime | None = None, hours: int = 48, min_outage: int = 120) -> dict:
    """Mirror full SD-WAN link outages (app/isp.py: every health check on the link dead) into wan_outages so they count in
    the same analytics and incidents as ICMP outages. Idempotent: matched on (link, start); a clipped start (outage began
    before the window) matches the link's open outage."""
    from . import isp
    now = now or _now()
    t0 = now - timedelta(hours=hours)
    links = await isp.load(ch, t0, now)
    cfgs = await isp.configs(s)
    await isp.ensure_links(s, links, cfgs)  # newly seen links are registered (as the SD-WAN report does)
    cfg = await settings(s)
    ctx = await Ctx.load(s)
    made = closed = 0
    for key, ld in links.items():
        c = cfgs.get(key)
        if c is None or c.hidden or not c.enabled:
            continue
        r = isp.analyze_link(ld, c, t0, now, min_outage)
        for a, b in r["_outages"]:
            ongoing = b >= now - timedelta(seconds=1)
            q = select(WanOutage).where(WanOutage.source == "sdwan", WanOutage.isp_link_id == c.id)
            q = q.where(WanOutage.recovered_at.is_(None)) if a <= t0 + timedelta(seconds=1) else \
                q.where(WanOutage.started_at >= a - timedelta(seconds=1), WanOutage.started_at <= a + timedelta(seconds=1))
            o = (await s.execute(q.limit(1))).scalars().first()
            if o is None:
                if a <= t0 + timedelta(seconds=1):
                    continue  # began before the window and was never recorded: not invented now
                isp_name = isp.display_name(c, c.interface)
                site = ctx.link_site(c) or "(no site)"
                m = await active_maintenance(s, a, site=site, isp=isp_name, link_id=c.id, target_id=None)
                o = WanOutage(source="sdwan", kind="down", isp_link_id=c.id, firewall_id=c.firewall_id, target_name=f"SD-WAN {ld.interface}",
                              address=ld.gateway or "", isp_name=isp_name, site=site, circuit_name=circuit_label(c, ctx.fws),
                              started_at=a, detected_at=a + timedelta(seconds=min_outage), failed_checks=len(r["outage_checks"]),
                              evidence={"checks": r["outage_checks"], "firewall": ld.firewall_name, "interface": ld.interface},
                              maintenance_id=m.id if m else None, created_at=now)
                s.add(o)
                await s.flush()
                made += 1
                if m is None:
                    await attach_incident(s, o, cfg, key=f"circuit:{c.id}" if cfg["correlation"] != "site" else f"site:{site.lower()}",
                                          entity=("circuit", circuit_label(c, ctx.fws)) if cfg["correlation"] != "site" else ("site", site),
                                          role=c.role)
                    await notify_outage(s, o)
            if not ongoing and o.recovered_at is None:
                await finish_outage(s, o, b, b, {"source": "sdwan", "alive_at": b.isoformat()}, cfg)
                closed += 1
    await s.commit()
    return {"opened": made, "closed": closed} if made or closed else {}
