"""Detection tuning suggestions from analyst verdicts (alert dispositions).

Suggestion types:
    suppress_entity   an entity produced ≥ N false-positive / benign alerts for a rule and never a true positive
    raise_threshold   for threshold rules, every false positive scored below every true positive (or there are
                      many false positives and no true positives): propose a threshold just above the false positives
    noisy_untriaged   many alerts, almost none triaged — the rule is probably ignored
    review_rule       very high false-positive rate overall
Applying a suggestion goes through the same suppression / rule-parameter paths as manual tuning (audited)."""
from __future__ import annotations

import math
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .db.models import Alert, AlertRule, Suppression

THRESHOLD_PARAM = {"port_scan": "min_unique_ports", "denied_burst": "min_denied", "host_sweep": "min_unique_dsts",
                   "outbound_volume": "min_sent_bytes", "nxdomain_burst": "min_nxdomain", "admin_login_fail": "min_failures",
                   "vpn_bruteforce": "min_failures", "multi_site": "min_denied", "dns_tunnel": "min_unique_names"}
FALSE = ("false_positive", "benign")


def _metric(a: Alert) -> float | None:
    v = (a.evidence or {}).get("metric")
    try:
        return float(v) if v is not None else float(a.event_count or 0)
    except (TypeError, ValueError):
        return None


async def suggestions(s: AsyncSession, days: int = 90, min_fp: int = 3) -> list[dict]:
    since = datetime.now(timezone.utc) - timedelta(days=days)
    alerts = (await s.execute(select(Alert).where(Alert.created_at >= since))).scalars().all()
    rules = {r.key: r for r in (await s.execute(select(AlertRule))).scalars()}
    sups = {(x.rule_key, x.group_key) for x in (await s.execute(select(Suppression))).scalars()
            if x.until is None or (x.until if x.until.tzinfo else x.until.replace(tzinfo=timezone.utc)) > datetime.now(timezone.utc)}
    by_rule: dict[str, list[Alert]] = defaultdict(list)
    for a in alerts:
        by_rule[a.rule_key].append(a)
    out = []
    for key, rs in by_rule.items():
        rule = rules.get(key)
        name = rule.name if rule else key
        fp = [a for a in rs if a.disposition in FALSE]
        tp = [a for a in rs if a.disposition == "true_positive"]
        decided = len(fp) + len(tp)
        # 1. entities that only ever produce false positives
        by_entity: dict[str, list[Alert]] = defaultdict(list)
        for a in rs:
            by_entity[a.group_key].append(a)
        for g, ga in by_entity.items():
            f = sum(1 for a in ga if a.disposition in FALSE)
            t = sum(1 for a in ga if a.disposition == "true_positive")
            if f >= min_fp and t == 0 and (key, g) not in sups:
                out.append({"type": "suppress_entity", "rule_key": key, "rule": name, "group_key": g, "false_positives": f,
                            "alerts": len(ga), "impact": f"stops ~{len(ga)} alert(s) like these",
                            "reason": f"{g} produced {f} false-positive/benign verdicts and no true positive in {days} days."})
        # 2. threshold separable by verdict
        param = THRESHOLD_PARAM.get(key)
        if param and rule and param in (rule.params or {}) and len(fp) >= min_fp:
            fpm = [m for m in (_metric(a) for a in fp) if m is not None]
            tpm = [m for m in (_metric(a) for a in tp) if m is not None]
            cur = float(rule.params[param])
            if fpm and (not tpm or max(fpm) < min(tpm)):
                proposed = max(cur + 1, math.ceil(max(fpm) * 1.1))
                if tpm:
                    proposed = min(proposed, math.floor(min(tpm)))
                if proposed > cur:
                    kept = sum(1 for m in tpm if m >= proposed)
                    out.append({"type": "raise_threshold", "rule_key": key, "rule": name, "param": param, "current": cur, "proposed": proposed,
                                "false_positives": len(fp), "true_positives": len(tp),
                                "impact": f"removes {sum(1 for m in fpm if m < proposed)} of {len(fpm)} past false positives, keeps {kept} of {len(tpm)} true positives",
                                "reason": f"Every false positive scored ≤ {max(fpm):g}" + (f"; true positives started at {min(tpm):g}." if tpm else "; no true positives yet.")})
        # 3. ignored rule
        triaged = sum(1 for a in rs if a.status != "new" or a.disposition)
        if len(rs) >= 50 and triaged / len(rs) < 0.1:
            out.append({"type": "noisy_untriaged", "rule_key": key, "rule": name, "alerts": len(rs), "triaged": triaged,
                        "impact": "analyst time / alert fatigue", "reason": f"{len(rs)} alerts in {days} days, only {triaged} triaged."})
        # 4. mostly wrong
        if decided >= 10 and len(fp) / decided >= 0.8:
            out.append({"type": "review_rule", "rule_key": key, "rule": name, "false_positive_rate": round(len(fp) / decided, 2),
                        "decided": decided, "impact": "precision", "reason": f"{len(fp)} of {decided} decided alerts were false positive or benign."})
    order = {"raise_threshold": 0, "suppress_entity": 1, "review_rule": 2, "noisy_untriaged": 3}
    return sorted(out, key=lambda x: (order[x["type"]], -x.get("false_positives", x.get("alerts", 0))))
