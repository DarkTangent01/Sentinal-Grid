"""Notification routing (rules, quiet hours, de-duplication) and delivery via a persistent outbox."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import smtplib
import ssl
from datetime import datetime, time, timedelta, timezone
from email.message import EmailMessage
from zoneinfo import ZoneInfo

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import get_settings
from .db.models import Alert, Incident, NotificationChannel, NotificationOutbox, NotificationRule
from .netguard import acheck_host, request_guard
from .security import TokenCipher

log = logging.getLogger("notify")
SEV = ["informational", "low", "medium", "high", "critical"]
COLOR = {"critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04", "low": "#0284c7", "informational": "#64748b"}
EVENT_TYPES = ("alert.created", "incident.created", "incident.escalated", "report.ready", "search.threshold")
BACKOFF = [60, 300, 900, 3600]


def _now():
    return datetime.now(timezone.utc)


def secrets_of(ch: NotificationChannel) -> dict:
    if not ch.secret_ciphertext:
        return {}
    return json.loads(TokenCipher().decrypt(ch.secret_ciphertext))


def seal(secret: dict) -> str | None:
    secret = {k: v for k, v in secret.items() if v}
    return TokenCipher().encrypt(json.dumps(secret)) if secret else None


def in_quiet_hours(rule: NotificationRule, now: datetime) -> bool:
    if not rule.quiet_start or not rule.quiet_end:
        return False
    try:
        local = now.astimezone(ZoneInfo(rule.quiet_tz or "UTC")).time()
        a, b = time.fromisoformat(rule.quiet_start), time.fromisoformat(rule.quiet_end)
    except (ValueError, KeyError):
        return False
    return (a <= local < b) if a < b else (local >= a or local < b)  # window may wrap midnight


def _link(path: str) -> str:
    base = get_settings().public_base_url.rstrip("/")
    return f"{base}{path}" if base else path


async def enqueue(s: AsyncSession, event_type: str, payload: dict, *, severity: str, dedupe_key: str, rule_key: str | None = None,
                  now: datetime | None = None, channel_ids: list[int] | None = None) -> int:
    """Create outbox rows for every matching rule. channel_ids bypasses rules (reports, test messages)."""
    now = now or _now()
    payload = {**payload, "severity": severity, "event_type": event_type}
    n = 0
    if channel_ids is not None:
        for cid in channel_ids:
            s.add(NotificationOutbox(channel_id=cid, event_type=event_type, dedupe_key=dedupe_key, payload=payload, next_attempt=now))
            n += 1
        return n
    rules = (await s.execute(select(NotificationRule).where(NotificationRule.enabled.is_(True)))).scalars().all()
    for r in rules:
        if event_type not in (r.event_types or []):
            continue
        if SEV.index(severity if severity in SEV else "low") < SEV.index(r.min_severity if r.min_severity in SEV else "high"):
            continue
        if r.rule_keys and rule_key and rule_key not in r.rule_keys:
            continue
        status = "pending"
        if in_quiet_hours(r, now) and severity != "critical":
            status = "suppressed"
        elif r.dedupe_minutes:
            dup = (await s.execute(select(NotificationOutbox.id).where(
                NotificationOutbox.rule_id == r.id, NotificationOutbox.dedupe_key == dedupe_key,
                NotificationOutbox.status.in_(["pending", "sent"]),
                NotificationOutbox.created_at >= now - timedelta(minutes=r.dedupe_minutes)).limit(1))).first()
            if dup:
                status = "suppressed"
        s.add(NotificationOutbox(rule_id=r.id, channel_id=r.channel_id, event_type=event_type, dedupe_key=dedupe_key,
                                 payload=payload, status=status, next_attempt=now, created_at=now,
                                 error="quiet hours" if status == "suppressed" and in_quiet_hours(r, now) else
                                 ("duplicate within de-dup window" if status == "suppressed" else None)))
        n += status == "pending"
    return n


async def alert_created(s: AsyncSession, a: Alert) -> None:
    await enqueue(s, "alert.created", {
        "title": f"[{a.severity.upper()}] {a.name}", "text": a.explanation,
        "fields": {"Source": a.src_ip or "—", "Sites": ", ".join(a.sites or []) or "—",
                   "MITRE": f"{(a.mitre or {}).get('tactic_name', '')} {' '.join((a.mitre or {}).get('techniques', []))}".strip() or "—"},
        "url": _link(f"/alerts?id={a.id}")}, severity=a.severity, dedupe_key=f"alert:{a.rule_key}:{a.group_key}", rule_key=a.rule_key)


async def incident_event(s: AsyncSession, inc: Incident, kind: str) -> None:
    await enqueue(s, f"incident.{kind}", {
        "title": f"[{inc.severity.upper()}] Incident #{inc.id} {kind}: {inc.title}",
        "text": f"{inc.alert_count} alert(s) for {inc.entity_type} {inc.entity}. Tactics: {', '.join(inc.tactics) or '—'}.",
        "fields": {"Entity": inc.entity, "Severity": inc.severity, "Alerts": str(inc.alert_count),
                   "Techniques": ", ".join(inc.techniques) or "—"},
        "url": _link(f"/incidents/{inc.id}")}, severity=inc.severity, dedupe_key=f"incident:{inc.id}:{kind}:{inc.severity}")


# ---------------------------------------------------------------- delivery
def _text(p: dict) -> str:
    fields = "\n".join(f"{k}: {v}" for k, v in (p.get("fields") or {}).items())
    return f"{p.get('title', '')}\n{p.get('text', '')}\n{fields}\n{p.get('url', '')}".strip()


def build_request(ch: NotificationChannel, p: dict, secret: dict) -> dict:
    """Returns {'method': 'http', 'url', 'json'|'content', 'headers'} or {'method': 'smtp', 'message'}."""
    if ch.type == "slack":
        fields = "\n".join(f"*{k}:* {v}" for k, v in (p.get("fields") or {}).items())
        text = f"*{p.get('title', '')}*\n{p.get('text', '')}\n{fields}" + (f"\n<{p['url']}|Open in SIEM>" if p.get("url", "").startswith("http") else "")
        return {"method": "http", "url": secret.get("url", ""), "json": {"text": text}}
    if ch.type == "teams":  # Teams Workflows "When a Teams webhook request is received" (adaptive card)
        facts = [{"title": k, "value": str(v)} for k, v in (p.get("fields") or {}).items()]
        body = [{"type": "TextBlock", "size": "Medium", "weight": "Bolder", "text": p.get("title", ""), "wrap": True},
                {"type": "TextBlock", "text": p.get("text", ""), "wrap": True}, {"type": "FactSet", "facts": facts}]
        card = {"type": "AdaptiveCard", "version": "1.4", "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "body": body}
        if p.get("url", "").startswith("http"):
            card["actions"] = [{"type": "Action.OpenUrl", "title": "Open in SIEM", "url": p["url"]}]
        return {"method": "http", "url": secret.get("url", ""),
                "json": {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]}}
    if ch.type == "webhook":
        content = json.dumps(p, default=str).encode()
        headers = {"Content-Type": "application/json"}
        if secret.get("hmac_secret"):
            headers["X-SIEM-Signature"] = "sha256=" + hmac.new(secret["hmac_secret"].encode(), content, hashlib.sha256).hexdigest()
        return {"method": "http", "url": secret.get("url", ""), "content": content, "headers": headers}
    if ch.type == "email":
        cfg = ch.config or {}
        msg = EmailMessage()
        msg["Subject"] = p.get("subject") or p.get("title", "Sentinel Grid notification")
        msg["From"] = cfg.get("from_addr", "siem@localhost")
        msg["To"] = ", ".join(cfg.get("to", []))
        msg.set_content(_text(p))
        html = p.get("html") or (f"<h3 style='color:{COLOR.get(p.get('severity', ''), '#111')}'>{_esc(p.get('title', ''))}</h3>"
                                 f"<p>{_esc(p.get('text', ''))}</p><table>" +
                                 "".join(f"<tr><td><b>{_esc(k)}</b></td><td>{_esc(str(v))}</td></tr>" for k, v in (p.get("fields") or {}).items()) +
                                 "</table>" + (f"<p><a href='{_esc(p['url'])}'>Open in SIEM</a></p>" if p.get("url", "").startswith("http") else ""))
        msg.add_alternative(html, subtype="html")
        return {"method": "smtp", "message": msg}
    raise ValueError(f"unknown channel type {ch.type}")


def _esc(x: str) -> str:
    return x.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("'", "&#39;").replace('"', "&quot;")


def _smtp_send(cfg: dict, password: str | None, msg: EmailMessage) -> None:
    host, port, mode = cfg.get("host"), int(cfg.get("port", 587)), cfg.get("security", "starttls")
    ctx = ssl.create_default_context()
    if mode == "ssl":
        server = smtplib.SMTP_SSL(host, port, context=ctx, timeout=20)
    else:
        server = smtplib.SMTP(host, port, timeout=20)
        if mode == "starttls":
            server.starttls(context=ctx)
    try:
        if cfg.get("username"):
            server.login(cfg["username"], password or "")
        server.send_message(msg)
    finally:
        server.quit()


async def deliver(ch: NotificationChannel, payload: dict, transport: httpx.AsyncBaseTransport | None = None) -> None:
    req = build_request(ch, payload, secrets_of(ch))
    if req["method"] == "smtp":
        cfg = ch.config or {}
        await acheck_host(str(cfg.get("host", "")), int(cfg.get("port", 587)))
        await asyncio.to_thread(_smtp_send, cfg, secrets_of(ch).get("password"), req["message"])
        return
    if not req["url"].lower().startswith(("https://", "http://")):
        raise ValueError("channel has no valid URL")
    async with httpx.AsyncClient(timeout=15, transport=transport, follow_redirects=False,
                                 event_hooks={"request": [request_guard(("https", "http"))]}) as c:
        r = await c.post(req["url"], json=req.get("json"), content=req.get("content"), headers=req.get("headers"))
        if r.status_code >= 300:
            raise RuntimeError(f"HTTP {r.status_code}: {r.text[:200]}")


async def process_outbox(s: AsyncSession, transport: httpx.AsyncBaseTransport | None = None, limit: int = 50) -> dict:
    now = _now()
    rows = (await s.execute(select(NotificationOutbox).where(NotificationOutbox.status == "pending",
            NotificationOutbox.next_attempt <= now).order_by(NotificationOutbox.id).limit(limit))).scalars().all()
    stats = {"sent": 0, "failed": 0, "retry": 0}
    for o in rows:
        ch = await s.get(NotificationChannel, o.channel_id)
        if not ch or not ch.enabled:
            o.status, o.error = "failed", "channel missing or disabled"
            stats["failed"] += 1
            continue
        try:
            await deliver(ch, o.payload, transport)
            o.status, o.sent_at, o.error = "sent", _now(), None
            stats["sent"] += 1
        except Exception as e:
            o.attempts += 1
            o.error = f"{type(e).__name__}: {e}"[:500]
            if o.attempts > len(BACKOFF):
                o.status = "failed"
                stats["failed"] += 1
            else:
                o.next_attempt = _now() + timedelta(seconds=BACKOFF[o.attempts - 1])
                stats["retry"] += 1
    await s.commit()
    return stats
