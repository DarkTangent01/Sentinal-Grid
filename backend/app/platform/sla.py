"""Acknowledge / resolve service-level timers for cases (security incidents in the SIEM, network incidents in NMS)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


def _aware(v):
    return v if v is None or v.tzinfo else v.replace(tzinfo=timezone.utc)


SLA = {  # (acknowledge, resolve)
    "critical": (timedelta(minutes=15), timedelta(hours=4)),
    "high": (timedelta(hours=1), timedelta(hours=24)),
    "medium": (timedelta(hours=4), timedelta(days=3)),
    "low": (timedelta(hours=24), timedelta(days=7)),
    "informational": (timedelta(days=3), timedelta(days=14)),
}


def sla_state(inc, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    ack_due, res_due = _aware(inc.sla_ack_due), _aware(inc.sla_resolve_due)
    acked, resolved = _aware(inc.acknowledged_at), _aware(inc.resolved_at)
    return {
        "ack_due": ack_due.isoformat() if ack_due else None, "resolve_due": res_due.isoformat() if res_due else None,
        "ack_breached": bool(ack_due and ((acked or now) > ack_due)),
        "resolve_breached": bool(res_due and ((resolved or now) > res_due)),
    }

