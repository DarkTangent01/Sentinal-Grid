"""Automation rules (SOAR-style playbooks): trigger + conditions → ordered actions.

Every action acts on SIEM data only (assignment, status, comments, notifications, watchlists, enrichment).
`suggest_block` only *generates* FortiOS CLI for an analyst to review; the SIEM never writes to a firewall."""
from __future__ import annotations

import ipaddress
import logging
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from .db.models import (Alert, Asset, AutomationRule, AutomationRun, Incident, IncidentComment, NotificationChannel,
                        TiFeed, TiIndicator, User, Watchlist)
from .incidents import OPEN, SEV, set_status

log = logging.getLogger("automation")
TRIGGERS = ("alert.created", "incident.created", "incident.escalated")
ACTIONS = ("assign", "set_status", "set_severity", "comment", "notify", "enrich", "add_to_watchlist", "suggest_block", "run_query")
SAFE_ENTITY = re.compile(r"^[A-Za-z0-9_.:@\-/]{1,255}$")


def _now():
    return datetime.now(timezone.utc)


# ------------------------------------------------------------------ target abstraction
def facts(target) -> dict:
    """Uniform view of an alert or incident used by conditions and templates."""
    if isinstance(target, Incident):
        return {"type": "incident", "id": target.id, "title": target.title, "severity": target.severity,
                "entity_type": target.entity_type, "entity": target.entity, "rule_keys": target.rule_keys or [],
                "tactics": target.tactics or [], "sites": [], "asset_criticality": target.asset_criticality or "",
                "status": target.status}
    m = target.mitre or {}
    etype, ent = ("ip", target.src_ip) if target.src_ip else ("other", target.group_key)
    return {"type": "alert", "id": target.id, "title": target.name, "severity": target.severity, "entity_type": etype,
            "entity": ent or "", "rule_keys": [target.rule_key], "tactics": [m["tactic"]] if m.get("tactic") else [],
            "sites": target.sites or [], "asset_criticality": target.asset_criticality or "", "status": target.status}


def matches(cond: dict, f: dict) -> tuple[bool, str]:
    cond = cond or {}
    sev = cond.get("min_severity")
    if sev and SEV.index(f["severity"] if f["severity"] in SEV else "low") < SEV.index(sev if sev in SEV else "low"):
        return False, f"severity {f['severity']} below {sev}"
    if cond.get("rule_keys") and not set(cond["rule_keys"]) & set(f["rule_keys"]):
        return False, "rule not in list"
    if cond.get("tactics") and not set(cond["tactics"]) & set(f["tactics"]):
        return False, "tactic not in list"
    if cond.get("entity_types") and f["entity_type"] not in cond["entity_types"]:
        return False, f"entity type {f['entity_type']} not in list"
    if cond.get("sites") and not set(cond["sites"]) & set(f["sites"]):
        return False, "site not in list"
    if cond.get("asset_criticality") and f["asset_criticality"] not in cond["asset_criticality"]:
        return False, "asset criticality not in list"
    tc = (cond.get("title_contains") or "").strip().lower()
    if tc and tc not in (f["title"] or "").lower():
        return False, "title does not contain text"
    return True, "matched"


def _fmt(text: str, f: dict) -> str:
    return re.sub(r"\{(title|severity|entity|entity_type|id|type)\}", lambda m: str(f.get(m.group(1), "")), text or "")[:4000]


async def _note(s: AsyncSession, target, body: str, author: str = "automation") -> None:
    if isinstance(target, Incident):
        s.add(IncidentComment(incident_id=target.id, author=author, kind="system", body=body))
    else:
        stamp = _now().strftime("%Y-%m-%d %H:%M UTC")
        target.notes = ((target.notes or "") + f"\n[{stamp} {author}] {body}").strip()[-20000:]


# ------------------------------------------------------------------ actions
async def act_assign(s, target, a, f, ch, dry):
    user = (a.get("user") or "").strip()
    if not user or not (await s.execute(select(User.id).where(User.username == user))).first():
        return False, f"unknown user '{user}'"
    if not dry:
        target.assignee = user
    return True, f"assigned to {user}"


async def act_set_status(s, target, a, f, ch, dry):
    st = a.get("status", "")
    if isinstance(target, Incident):
        if st not in ("open", "in_progress", "resolved", "closed"):
            return False, f"invalid incident status '{st}'"
        if not dry:
            await set_status(s, target, st, "automation", a.get("closure_reason"))
    else:
        if st not in ("new", "investigating", "resolved", "suppressed"):
            return False, f"invalid alert status '{st}'"
        if not dry:
            target.status = st
    return True, f"status → {st}"


async def act_set_severity(s, target, a, f, ch, dry):
    sev = a.get("severity", "")
    if sev not in SEV:
        return False, f"invalid severity '{sev}'"
    if not dry:
        target.severity = sev
    return True, f"severity → {sev}"


async def act_comment(s, target, a, f, ch, dry):
    text = _fmt(a.get("text", ""), f).strip()
    if not text:
        return False, "empty comment"
    if not dry:
        await _note(s, target, text)
    return True, "comment added"


async def act_notify(s, target, a, f, ch, dry):
    from .notify import _link, enqueue
    cid = a.get("channel_id")
    chan = await s.get(NotificationChannel, int(cid)) if cid else None
    if not chan:
        return False, "unknown notification channel"
    if not dry:
        path = f"/incidents/{f['id']}" if f["type"] == "incident" else "/alerts"
        await enqueue(s, f"{f['type']}.automation", {
            "title": _fmt(a.get("title") or "[{severity}] {title}", f),
            "text": _fmt(a.get("text") or "Automation rule matched {type} #{id} ({entity}).", f),
            "fields": {"Severity": f["severity"], "Entity": f["entity"]}, "url": _link(path)},
            severity=f["severity"], dedupe_key=f"auto:{f['type']}:{f['id']}:{cid}", channel_ids=[chan.id])
    return True, f"notification queued to {chan.name}"


async def entity_context(s: AsyncSession, ch, f: dict) -> list[str]:
    """Plain-text enrichment lines for an entity (asset, threat intel, recent activity, related alerts)."""
    ent, lines = f["entity"], []
    is_ip = False
    try:
        ipaddress.ip_address(ent)
        is_ip = True
    except ValueError:
        pass
    if is_ip:
        a = (await s.execute(select(Asset).where(Asset.ip == ent))).scalars().first()
        if a:
            lines.append(f"Asset: {a.hostname or '-'} · criticality {a.criticality} · owner {a.owner or '-'} · OS {a.os or '-'} · last user {a.last_user or '-'}")
        else:
            lines.append("Asset: not in inventory")
        ti = (await s.execute(select(TiFeed.name, TiFeed.category, TiIndicator.note).join(TiFeed, TiFeed.id == TiIndicator.feed_id)
                              .where(TiIndicator.indicator == ent).limit(5))).all()
        lines.append("Threat intel: " + ("; ".join(f"{n} ({c}{', ' + note if note else ''})" for n, c, note in ti) if ti else "no indicator match"))
        if ch is not None:
            try:
                r = await ch.aquery(
                    "SELECT count() AS events, uniqExact(dst_ip) AS dsts, countIf(action IN ('deny','block')) AS denied, "
                    "sum(sent_bytes) AS sent, topK(5)(dst_port) AS ports, anyIf(src_country, src_country != '') AS sc, "
                    "topK(3)(dst_country) AS dc FROM events WHERE event_time >= now64(3) - INTERVAL 24 HOUR AND "
                    "(src_ip = {ip:String} OR dst_ip = {ip:String})", {"ip": ent})
                if r:
                    x = r[0]
                    lines.append(f"Last 24h: {int(x['events']):,} events, {int(x['dsts']):,} distinct destinations, "
                                 f"{int(x['denied']):,} denied, {int(x['sent'] or 0):,} bytes sent; top ports {', '.join(str(p) for p in x['ports'] if p is not None)}; "
                                 f"countries {', '.join(c for c in x['dc'] if c) or '-'}")
            except Exception as e:  # enrichment must never break the playbook
                lines.append(f"Recent activity unavailable: {e}")
    since = _now() - timedelta(days=7)
    n = (await s.execute(select(func.count(Alert.id)).where(or_(Alert.src_ip == ent, Alert.dst_ip == ent, Alert.group_key == ent),
                                                             Alert.last_seen >= since))).scalar_one()
    lines.append(f"Alerts for this entity in 7 days: {n}")
    return lines


async def act_enrich(s, target, a, f, ch, dry):
    lines = await entity_context(s, ch, f)
    if not dry:
        await _note(s, target, "Enrichment for " + f["entity"] + ":\n" + "\n".join(f"• {l}" for l in lines))
    return True, f"{len(lines)} enrichment line(s)"


async def act_add_to_watchlist(s, target, a, f, ch, dry):
    from .watchlists import add_item
    w = await s.get(Watchlist, int(a.get("watchlist_id") or 0))
    if not w:
        return False, "unknown watchlist"
    ttl = int(a.get("ttl_hours") or 0)
    if dry:
        return True, f"would add {f['entity']} to {w.name}"
    try:
        created = await add_item(s, w, f["entity"], _fmt(a.get("label") or "{type} #{id}: {title}", f)[:255], "automation",
                                 _now() + timedelta(hours=ttl) if ttl else None)
    except ValueError as e:
        return False, f"entity does not fit watchlist '{w.name}' ({w.kind}): {e}"
    return True, f"{'added to' if created else 'already in'} {w.name}"


def block_cli(ip: str, ref: str) -> str:
    net = ipaddress.ip_network(ip, strict=False)
    name = f"SIEM-BLK-{str(net.network_address).replace(':', '_')}"
    if net.version == 4:
        return (f"config firewall address\n    edit \"{name}\"\n        set subnet {net.network_address} {net.netmask}\n"
                f"        set comment \"{ref}\"\n    next\nend\nconfig firewall addrgrp\n    edit \"SIEM-BLOCKLIST\"\n"
                f"        append member \"{name}\"\n    next\nend")
    return (f"config firewall address6\n    edit \"{name}\"\n        set ip6 {net}\n        set comment \"{ref}\"\n    next\nend\n"
            f"config firewall addrgrp6\n    edit \"SIEM-BLOCKLIST6\"\n        append member \"{name}\"\n    next\nend")


async def act_suggest_block(s, target, a, f, ch, dry):
    try:
        ipaddress.ip_address(f["entity"])
    except ValueError:
        return False, "entity is not an IP address"
    cli = block_cli(f["entity"], f"SIEM {f['type']} #{f['id']}")
    if not dry:
        await _note(s, target, "Suggested containment (NOT applied — the SIEM is read-only toward firewalls). Review, then run on "
                    "the FortiGate; SIEM-BLOCKLIST must be referenced by a deny policy:\n" + cli)
    return True, "block CLI generated"


async def act_run_query(s, target, a, f, ch, dry):
    from .analytics.filters import EventFilter
    from .analytics.pipeline import run_pipeline, watchlist_names
    from .watchlists import load_watchlists
    if ch is None:
        return False, "query engine unavailable"
    q = a.get("query") or ""
    if "$entity$" in q:
        if not SAFE_ENTITY.match(f["entity"] or ""):
            return False, "entity contains characters that cannot be substituted safely"
        q = q.replace("$entity$", f["entity"])
    if dry:
        return True, "query would run"
    wl = await load_watchlists(s, watchlist_names(q))
    res = await run_pipeline(ch, q, EventFilter(range=a.get("range") or "24h"), wl, max_rows=10)
    cols = res["columns"][:6]
    table = "\n".join(" | ".join(str(r.get(c, "")) for c in cols) for r in res["rows"][:10])
    await _note(s, target, f"Query: {q}\n{' | '.join(cols)}\n{table or '(no results)'}")
    return True, f"{len(res['rows'])} row(s)"


HANDLERS = {"assign": act_assign, "set_status": act_set_status, "set_severity": act_set_severity, "comment": act_comment,
            "notify": act_notify, "enrich": act_enrich, "add_to_watchlist": act_add_to_watchlist,
            "suggest_block": act_suggest_block, "run_query": act_run_query}


def validate_actions(actions: list) -> None:
    if not isinstance(actions, list) or not actions or len(actions) > 20:
        raise ValueError("between 1 and 20 actions are required")
    for a in actions:
        if not isinstance(a, dict) or a.get("type") not in HANDLERS:
            raise ValueError(f"unknown action {a.get('type') if isinstance(a, dict) else a!r}")
        if a["type"] == "run_query":
            from .analytics.pipeline import compile_pipeline, watchlist_names
            q = a.get("query") or ""
            compile_pipeline(q.replace("$entity$", "0.0.0.0"), {n: {"kind": "string", "values": []} for n in watchlist_names(q)})


async def execute(s: AsyncSession, rule: AutomationRule, trigger: str, target, ch=None, dry: bool = False) -> AutomationRun:
    f = facts(target)
    results = []
    for a in rule.actions or []:
        fn = HANDLERS.get(a.get("type"))
        try:
            ok, detail = await fn(s, target, a, f, ch, dry) if fn else (False, "unknown action")
        except Exception as e:  # one failing action never blocks the others
            log.exception("automation action %s failed", a.get("type"))
            ok, detail = False, str(e)[:300]
        results.append({"action": a.get("type"), "ok": ok, "detail": detail})
        f = facts(target)  # actions may change severity/status for later ones
    status = "dry_run" if dry else ("ok" if all(r["ok"] for r in results) else ("error" if not any(r["ok"] for r in results) else "partial"))
    run = AutomationRun(rule_id=rule.id, rule_name=rule.name, trigger=trigger, target_type=f["type"], target_id=f["id"],
                        status=status, results=results)
    if not dry:
        s.add(run)
        rule.run_count = (rule.run_count or 0) + 1
        rule.last_run = _now()
    return run


async def run_automation(s: AsyncSession, trigger: str, target, ch=None) -> list[AutomationRun]:
    rules = (await s.execute(select(AutomationRule).where(AutomationRule.enabled.is_(True), AutomationRule.trigger == trigger)
                             .order_by(AutomationRule.priority, AutomationRule.id))).scalars().all()
    runs = []
    for rule in rules:
        ok, _ = matches(rule.conditions, facts(target))
        if not ok:
            continue
        runs.append(await execute(s, rule, trigger, target, ch))
        if rule.stop_processing:
            break
    return runs


async def run_for_detections(s: AsyncSession, touched: list, incident_events: list, ch=None) -> int:
    """Called by the alert engine after correlation. Returns the number of playbook runs."""
    n = 0
    for a, created in touched:
        if created:
            n += len(await run_automation(s, "alert.created", a, ch))
    for inc, kind in incident_events or []:
        if kind in ("created", "escalated") and inc.status in OPEN:
            n += len(await run_automation(s, f"incident.{kind}", inc, ch))
    return n
