"""Alert framework: runs registered detection rules and stores their results as grouped, deduplicated alerts in
PostgreSQL. It holds no product rules. Sentinel Grid registers its detections in alerts/siem.py and Sentinel NMS its
rules in alerts/nms.py, each with optional hooks:

- runners: rule-key prefix -> factory(session, rule) building a runner for stored rules (custom / YAML);
- severity_context: async (session, detections) -> (context_of(detection), bump(severity, context));
- admission: async (session, now) -> predicate(detection) that holds back new alerts (maintenance windows);
- auto_resolve / resolver: rules whose open alerts resolve themselves once their condition clears;
- after_run: async (session, ch, touched, now, result) after a pass (correlation, notifications, automation).

Each detection is an indicator that requires investigation, not proof of malicious activity.
"""
import json
import logging
import time
from dataclasses import dataclass, field
from functools import cached_property
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.ch import ClickHouse
from ..db.models import Alert, AlertRule, Suppression

log = logging.getLogger("alerts")

TACTICS = {  # MITRE ATT&CK Enterprise tactics, kill-chain order (alert rows carry an optional mapping)
    "TA0043": "Reconnaissance", "TA0042": "Resource Development", "TA0001": "Initial Access", "TA0002": "Execution",
    "TA0003": "Persistence", "TA0004": "Privilege Escalation", "TA0005": "Defense Evasion", "TA0006": "Credential Access",
    "TA0007": "Discovery", "TA0008": "Lateral Movement", "TA0009": "Collection", "TA0011": "Command and Control",
    "TA0010": "Exfiltration", "TA0040": "Impact",
}


def M(tactic: str, *techniques: str) -> dict:
    return {"tactic": tactic, "tactic_name": TACTICS[tactic], "techniques": list(techniques)}


@dataclass
class Detection:
    group_key: str
    count: int
    first_seen: datetime
    last_seen: datetime
    explanation: str
    src_ip: str | None = None
    dst_ip: str | None = None
    firewall_ids: list[int] = field(default_factory=list)
    sites: list[str] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)
    event_filter: dict = field(default_factory=dict)
    severity: str | None = None  # overrides the rule default (e.g. by threat-intel category)


def _dt(v) -> datetime:
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(str(v).replace("Z", "")).replace(tzinfo=timezone.utc)


def _window(params: dict, now: datetime) -> tuple[datetime, datetime]:
    return now - timedelta(minutes=int(params.get("window_minutes", 10))), now


@dataclass
class Product:
    name: str
    rules: dict
    defaults: list
    runners: dict = field(default_factory=dict)
    default_interval: dict = field(default_factory=dict)
    catalogue_prefixes: tuple = ()
    auto_resolve: set = field(default_factory=set)
    resolver: object = None
    severity_context: object = None
    admission: object = None
    after_run: object = None

    @cached_property
    def mitre(self) -> dict:
        return {r["key"]: r["mitre"] for r in self.defaults}

    def owns(self, key: str) -> bool:
        return key in self.rules or key in self.mitre or key.startswith(tuple(self.runners))


PRODUCTS: dict[str, Product] = {}
# The combined deployment (both products in one process, alerts/combined.py) may route a whole pass to one after-run
# step, which keeps its single correlation / notification behaviour; separated products leave it unset.
COMBINED_AFTER_RUN = None


def register(name: str, *, rules: dict, defaults: list, **hooks) -> Product:
    p = Product(name, rules, defaults, **hooks)
    PRODUCTS[name] = p
    return p


def _products(product: str | None) -> list[Product]:
    if not PRODUCTS:
        raise RuntimeError("no alert rules are registered: import alerts.siem and/or alerts.nms (or alerts.combined)")
    return [PRODUCTS[product]] if product else list(PRODUCTS.values())


def product_of(key: str) -> Product | None:
    for p in PRODUCTS.values():
        if p.owns(key):
            return p
    return None


def rule_mitre(key: str) -> dict:
    p = product_of(key)
    return p.mitre.get(key, {}) if p else {}


async def ensure_default_rules(s: AsyncSession, product: str | None = None) -> None:
    existing = {r.key: r for r in (await s.execute(select(AlertRule))).scalars()}
    for prod in _products(product):
        for d in prod.defaults:
            if d["key"] not in existing:
                s.add(AlertRule(**d))
            else:  # add newly introduced params without overwriting tuned ones; keep catalogue metadata current
                r = existing[d["key"]]
                merged = {**d["params"], **(r.params or {})}
                if d["key"].startswith(prod.catalogue_prefixes):   # catalogue metadata follows the shipped file, tuning stays
                    merged.update(rule_version=d["params"]["rule_version"], rule_sha256=d["params"]["rule_sha256"])
                if merged != r.params:
                    r.params = merged
                if r.mitre != d["mitre"]:
                    r.mitre = d["mitre"]
                r.description = d["description"]
    await s.commit()


async def _latest_alerts(s: AsyncSession, rule_key: str, group_keys: set[str]) -> dict[str, Alert]:
    """Latest alert (highest open_seq) per group for one rule."""
    if not group_keys:
        return {}
    top = (select(Alert.group_key, func.max(Alert.open_seq).label("seq"))
           .where(Alert.rule_key == rule_key, Alert.group_key.in_(group_keys)).group_by(Alert.group_key).subquery())
    rows = (await s.execute(select(Alert).join(top, and_(Alert.group_key == top.c.group_key, Alert.open_seq == top.c.seq))
                            .where(Alert.rule_key == rule_key))).scalars().all()
    return {a.group_key: a for a in rows}


async def upsert_detections(s: AsyncSession, rule: AlertRule, detections: list[Detection], now: datetime,
                            touched: list | None = None) -> dict:
    """touched (optional) receives (alert, created: bool) for correlation and notifications."""
    prod = product_of(rule.key)
    stats = {"created": 0, "updated": 0, "suppressed": 0}
    sups = (await s.execute(select(Suppression).where(Suppression.rule_key == rule.key))).scalars().all()
    in_maintenance = await prod.admission(s, now) if prod and prod.admission else None
    active_sup = {x.group_key for x in sups if x.until is None or _dt(x.until) > now}
    dets = detections[:200]
    context_of, bump = (await prod.severity_context(s, dets)) if prod and prod.severity_context else (lambda d: "", lambda sev, c: sev)
    mitre_default = prod.mitre.get(rule.key, {}) if prod else {}
    latest_by = await _latest_alerts(s, rule.key, {d.group_key for d in dets})  # one query, not one per detection
    for d in dets:
        if d.group_key in active_sup or "*" in active_sup:
            stats["suppressed"] += 1
            continue
        if in_maintenance and in_maintenance(d):
            stats["maintenance"] = stats.get("maintenance", 0) + 1
            continue
        crit = context_of(d)
        latest = latest_by.get(d.group_key)
        if latest and latest.status != "resolved":
            latest.last_seen = max(_dt(latest.last_seen), d.last_seen)
            latest.event_count = max(int(latest.event_count or 0), d.count)
            latest.explanation = d.explanation
            latest.firewall_ids = sorted(set(latest.firewall_ids or []) | set(d.firewall_ids))
            latest.sites = sorted(set(latest.sites or []) | set(d.sites))
            latest.evidence = json.loads(json.dumps(d.evidence, default=str))
            latest.event_filter = {**d.event_filter, "start": _dt(latest.first_seen).isoformat()}
            if not latest.mitre:
                latest.mitre = rule.mitre or mitre_default
            stats["updated"] += 1
            if touched is not None:
                touched.append((latest, False))
            continue
        if latest and latest.status == "resolved" and _dt(latest.last_seen) >= d.last_seen:
            continue  # same activity that was already resolved
        sev = d.severity or rule.severity
        a = Alert(rule_key=rule.key, name=rule.name, severity=bump(sev, crit), base_severity=sev, asset_criticality=crit,
                  status="new", group_key=d.group_key, open_seq=(latest.open_seq + 1) if latest else 0, src_ip=d.src_ip,
                  dst_ip=d.dst_ip, firewall_ids=d.firewall_ids, sites=d.sites, first_seen=d.first_seen, last_seen=d.last_seen,
                  event_count=d.count, explanation=d.explanation + (" Severity raised: critical asset involved." if bump(sev, crit) != sev else ""),
                  evidence=json.loads(json.dumps(d.evidence, default=str)), mitre=rule.mitre or mitre_default,
                  event_filter={**d.event_filter, "start": d.first_seen.isoformat()})
        s.add(a)
        latest_by[d.group_key] = a  # a later detection of the same group in this run must see (and update) this alert
        stats["created"] += 1
        if touched is not None:
            touched.append((a, True))
    await s.commit()
    return stats


_LAST_RUN: dict[str, datetime] = {}


def _runner(prod: Product, s: AsyncSession, rule: AlertRule):
    fn = prod.rules.get(rule.key)
    if fn is None:
        for prefix, factory in prod.runners.items():
            if rule.key.startswith(prefix):
                return factory(s, rule)
    return fn


async def run_rules(ch: ClickHouse, s: AsyncSession, now: datetime | None = None, correlate: bool = True,
                    product: str | None = None) -> dict:
    """One evaluation pass over the enabled rules of one product (or of every registered product).
    correlate=False skips the products' after-run steps (correlation, notifications, automation)."""
    now = now or datetime.now(timezone.utc)
    result = {}
    timings: dict[str, float] = {}
    prods = _products(product)
    touched: dict[str, list] = {p.name: [] for p in prods}
    rules = (await s.execute(select(AlertRule).where(AlertRule.enabled.is_(True)))).scalars().all()
    for rule in rules:
        prod = next((p for p in prods if p.owns(rule.key)), None)
        fn = _runner(prod, s, rule) if prod else None
        if fn is None:
            continue
        params = dict(rule.params or {})
        dflt = next((v for k, v in prod.default_interval.items() if rule.key.startswith(k)), 0)
        every = int(params.get("interval_minutes") or dflt)
        if every and rule.key in _LAST_RUN and now - _LAST_RUN[rule.key] < timedelta(minutes=every):
            result[rule.key] = {"skipped": "interval"}
            continue
        started = time.monotonic()
        try:
            dets = await fn(ch, now, params)
            result[rule.key] = await upsert_detections(s, rule, dets, now, touched[prod.name])
            _LAST_RUN[rule.key] = now
            timings[rule.key] = time.monotonic() - started
            if rule.key in prod.auto_resolve and prod.resolver:  # stateful conditions resolve themselves
                n = len(await prod.resolver(s, rule.key, {d.group_key for d in dets}, now))
                if n:
                    result[rule.key]["resolved"] = result[rule.key].get("resolved", 0) + n
                await s.commit()
        except Exception as e:
            timings[rule.key] = time.monotonic() - started
            stats = (rule.params or {}).get("_stats") if rule.key.startswith(prod.catalogue_prefixes) else None
            await s.rollback()
            log.exception("rule %s failed", rule.key)
            result[rule.key] = {"error": str(e)}
            if stats:   # keep the failure visible on the rule (the rollback discarded the in-memory change)
                try:
                    r2 = await s.get(AlertRule, rule.id)
                    r2.params = {**(r2.params or {}), "_stats": stats}
                    await s.commit()
                except Exception:
                    await s.rollback()
    # the five slowest rules of this pass, in the pass's log line: a rule that starts scanning raw history shows up here
    result["_slowest"] = [f"{k} {t:.1f}s" for k, t in sorted(timings.items(), key=lambda x: -x[1])[:5]]
    if correlate:
        if COMBINED_AFTER_RUN and product is None:
            everything = [x for p in prods for x in touched[p.name]]
            if everything:
                await COMBINED_AFTER_RUN(s, ch, everything, now, result)
        else:
            for p in prods:
                if p.after_run and touched[p.name]:
                    await p.after_run(s, ch, touched[p.name], now, result)
    return result
