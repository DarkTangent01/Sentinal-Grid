"""Seed data shared by migrations and tests: bootstrap admin, default rules, retention policies."""
import logging

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .alerts.engine import ensure_default_rules
from .enrich.feeds import ensure_default_feeds
from .config import get_settings
from .db.models import User
from .retention import ensure_default_policies
from .security import hash_password, validate_password_strength

log = logging.getLogger("bootstrap")


async def backfill_alert_mitre(s: AsyncSession) -> int:
    """Alerts created before ATT&CK mapping existed get their rule's mapping (idempotent)."""
    from .alerts.rules import RULE_MITRE
    from .db.models import Alert
    n = 0
    for a in (await s.execute(select(Alert))).scalars():
        if not a.mitre and a.rule_key in RULE_MITRE:
            a.mitre = RULE_MITRE[a.rule_key]
            n += 1
    if n:  # refresh tactics/severity of open incidents that contain back-filled alerts
        from .db.models import Incident
        from .incidents import OPEN, compute
        for inc in (await s.execute(select(Incident).where(Incident.status.in_(OPEN)))).scalars().all():
            members = (await s.execute(select(Alert).where(Alert.incident_id == inc.id))).scalars().all()
            if members:
                compute(inc, members)
    await s.commit()
    return n


async def seed(s: AsyncSession) -> None:
    await ensure_default_rules(s)
    await ensure_default_policies(s)
    await ensure_default_feeds(s)
    await backfill_alert_mitre(s)
    from .content import ensure_content
    await ensure_content(s)
    if (await s.execute(select(func.count(User.id)))).scalar_one() == 0:
        st = get_settings()
        if not st.bootstrap_admin_password:
            log.warning("no users exist and BOOTSTRAP_ADMIN_PASSWORD is unset; no admin created")
            return
        validate_password_strength(st.bootstrap_admin_password)
        s.add(User(username=st.bootstrap_admin_username, password_hash=hash_password(st.bootstrap_admin_password), role="admin"))
        await s.commit()
        log.info("created bootstrap admin user %s", st.bootstrap_admin_username)
