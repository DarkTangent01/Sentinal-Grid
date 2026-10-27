"""Compliance evidence mapping. Statuses are computed from live configuration and data; this supports audits but
is not a certification. Controls the SIEM cannot verify are marked 'manual'."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .db.models import (AlertRule, Asset, BgpRouter, ConfigSnapshot, Firewall, Incident, IngestStat, NotificationRule, PolicyAnalysisRun,
                        ReportDefinition, RetentionPolicy, TiFeed)


async def facts(s: AsyncSession) -> dict:
    now = datetime.now(timezone.utc)
    ret = {p.category: (p.days if p.enabled else None) for p in (await s.execute(select(RetentionPolicy))).scalars()}
    ingest = (await s.execute(select(func.max(IngestStat.last_ingest_time)))).scalar()
    ingest = ingest.replace(tzinfo=timezone.utc) if ingest and not ingest.tzinfo else ingest
    rules = {r.key: r.enabled for r in (await s.execute(select(AlertRule))).scalars()}
    feeds_ok = (await s.execute(select(func.count(TiFeed.id)).where(TiFeed.enabled.is_(True), TiFeed.last_success.is_not(None)))).scalar()
    last_review = (await s.execute(select(func.max(PolicyAnalysisRun.started_at)).where(PolicyAnalysisRun.status == "ok"))).scalar()
    last_review = last_review.replace(tzinfo=timezone.utc) if last_review and not last_review.tzinfo else last_review
    return {
        "now": now, "retention": ret, "min_retention": min([d for d in ret.values() if d] or [0]),
        "ingest_recent": bool(ingest and ingest > now - timedelta(hours=1)), "last_ingest": ingest,
        "firewalls": (await s.execute(select(func.count(Firewall.id)).where(Firewall.is_demo.is_(False)))).scalar(),
        "rules": rules, "ti_feeds_ok": feeds_ok,
        "incidents": (await s.execute(select(func.count(Incident.id)))).scalar(),
        "assets": (await s.execute(select(func.count(Asset.id)))).scalar(),
        "critical_assets": (await s.execute(select(func.count(Asset.id)).where(Asset.criticality == "critical"))).scalar(),
        "snapshots": (await s.execute(select(func.count(ConfigSnapshot.id)))).scalar(),
        "last_policy_review": last_review,
        "daily_report": bool((await s.execute(select(func.count(ReportDefinition.id)).where(ReportDefinition.enabled.is_(True),
                                                                                             ReportDefinition.period == "daily"))).scalar()),
        "notify_rules": (await s.execute(select(func.count(NotificationRule.id)).where(NotificationRule.enabled.is_(True)))).scalar(),
        "bgp_audit": [f for r in (await s.execute(select(BgpRouter).where(BgpRouter.config.is_not(None)))).scalars() for f in (r.audit or [])],
        "bgp_audited": (await s.execute(select(func.count(BgpRouter.firewall_id)).where(BgpRouter.config.is_not(None)))).scalar(),
    }


def _c(cid, title, status, evidence, how=""):
    return {"id": cid, "title": title, "status": status, "evidence": evidence, "how": how}


def _bgp_control(cid: str, f: dict) -> dict:
    """Routing-protocol hardening from the BGP configuration audit (authentication, prefix limits, filters, BFD)."""
    if not f.get("bgp_audited"):
        return _c(cid, "Routing protocol sessions are protected", "manual", "No BGP configuration read from the firewalls.",
                  "Grant the API profile read access to router configuration, or verify BGP neighbor settings manually.")
    findings = f["bgp_audit"]
    med = sum(1 for x in findings if x["severity"] in ("high", "medium"))
    by = {}
    for x in findings:
        by[x["check"]] = by.get(x["check"], 0) + 1
    ev = ", ".join(f"{v}× {k}" for k, v in sorted(by.items(), key=lambda kv: -kv[1])) or "no findings"
    return _c(cid, "Routing protocol sessions are protected (BGP authentication, prefix limits, route filters)",
              "met" if not med else "partial", f"BGP audit on {f['bgp_audited']} firewall(s): {ev}.",
              "Fix the findings on the BGP page → Configuration audit (CLI is generated for review).")


def evaluate(f: dict) -> list[dict]:
    r, mr = f["retention"], f["min_retention"]
    review_ok = bool(f["last_policy_review"] and f["last_policy_review"] > f["now"] - timedelta(days=7))
    ingest = "met" if f["ingest_recent"] else ("partial" if f["last_ingest"] else "not_met")
    ret_txt = ", ".join(f"{k} {v or 'off'} d" for k, v in sorted(r.items()))
    detect = sum(1 for v in f["rules"].values() if v)
    return [
        {"framework": "CERT-In Directions (Apr 2022)", "controls": [
            _c("CERT-In 4(iv)", "Maintain logs of ICT systems for a rolling 180 days within India", "met" if mr >= 180 else "not_met",
               f"Retention: {ret_txt}.", "Set every category to ≥180 days in Settings → Retention; host the SIEM in India."),
            _c("CERT-In 4(i)", "Synchronise clocks to NTP (NIC/NPL)", "manual", "Event timestamps are stored in UTC as logged by each FortiGate.",
               "Verify 'config system ntp' on each FortiGate and NTP on the SIEM host."),
            _c("CERT-In 4(ii)", "Report cyber incidents within 6 hours", "met" if f["incidents"] is not None and f["notify_rules"] else "partial",
               f"Incident correlation with SLA timers; {f['notify_rules']} notification rule(s) enabled.", "Configure a notification rule for incident.created."),
            _c("CERT-In logging", "Collect firewall logs continuously", ingest, f"Last ingestion: {f['last_ingest'] or 'never'}."),
        ]},
        {"framework": "ISO/IEC 27001:2022 Annex A", "controls": [
            _c("A.8.15", "Logging", ingest if mr >= 90 else "partial", f"Firewall logs ingested; retention {ret_txt}."),
            _c("A.8.16", "Monitoring activities", "met" if detect >= 10 else "partial", f"{detect} detection rules enabled, alerting and incidents."),
            _c("A.5.7", "Threat intelligence", "met" if f["ti_feeds_ok"] else "not_met", f"{f['ti_feeds_ok']} feed(s) fetched successfully.",
               "Enable feeds in Threat Intel and confirm the SIEM can reach them."),
            _c("A.5.25 / A.5.26", "Assessment of and response to security events", "met" if f["incidents"] else "partial",
               f"{f['incidents']} incident(s) tracked with assignee, SLA, comments and closure reason."),
            _c("A.8.9", "Configuration management", "met" if f["snapshots"] else "not_met", f"{f['snapshots']} configuration snapshot(s) with drift detection."),
            _c("A.8.20", "Network security", "met" if review_ok else "partial",
               f"Policy usage/shadow analysis last run: {f['last_policy_review'] or 'never'}."),
            _bgp_control("A.8.20 (routing)", f),
            _c("A.5.9 / A.8.1", "Inventory of assets", "met" if f["assets"] else "not_met", f"{f['assets']} assets ({f['critical_assets']} critical)."),
            _c("A.8.17", "Clock synchronisation", "manual", "", "Verify NTP on firewalls and the SIEM host."),
            _c("A.8.5", "Secure authentication (SIEM)", "partial", "Argon2 passwords, lockout, RBAC; MFA/SSO not yet available in this SIEM."),
        ]},
        {"framework": "PCI DSS v4.0", "controls": [
            _c("10.2", "Audit logs capture security events", ingest, "Traffic, UTM and admin events are collected via syslog."),
            _c("10.4.1", "Review security event logs at least daily", "met" if f["daily_report"] else "partial",
               "Alerts run every minute" + ("; daily report scheduled." if f["daily_report"] else "; schedule a daily report for review evidence.")),
            _c("10.5.1", "Retain audit logs ≥12 months (3 months immediately available)", "met" if mr >= 365 else ("partial" if mr >= 90 else "not_met"),
               f"Retention: {ret_txt}."),
            _c("10.7.2", "Detect failures of critical security controls", "met" if f["ingest_recent"] else "partial",
               "Per-firewall API and log-ingestion health with lag."),
            _c("1.2.7", "Review firewall rule sets at least every six months", "met" if review_ok else "partial",
               "Policy analytics: usage, shadowed and redundant rules."),
            _c("12.10", "Incident response", "met" if f["incidents"] else "partial", "Incident and case management with SLA tracking."),
        ]},
        {"framework": "NIST CSF 2.0", "controls": [
            _c("DE.CM-01", "Networks are monitored", ingest, f"{f['firewalls']} firewall(s) registered."),
            _c("DE.AE-02", "Adverse events are analyzed", "met" if detect else "not_met", f"{detect} detections incl. behaviour baselines."),
            _c("DE.AE-07", "Threat intelligence integrated", "met" if f["ti_feeds_ok"] else "not_met", f"{f['ti_feeds_ok']} active feed(s)."),
            _c("RS.MA-01", "Incident management", "met" if f["incidents"] else "partial", "Correlated incidents with case workflow."),
            _c("ID.AM-01/02", "Asset inventory", "met" if f["assets"] else "not_met", f"{f['assets']} assets learned/maintained."),
            _c("PR.PS-01", "Configuration management", "met" if f["snapshots"] else "not_met", "Configuration drift snapshots."),
            _c("PR.PS-04", "Log records generated and available", "met" if mr >= 90 else "partial", f"Retention: {ret_txt}."),
            _bgp_control("PR.IR-01", f),
        ]},
    ]


async def compliance_status(s: AsyncSession) -> dict:
    f = await facts(s)
    fw = evaluate(f)
    counts = {k: sum(1 for x in fw for c in x["controls"] if c["status"] == k) for k in ("met", "partial", "not_met", "manual")}
    return {"generated_at": f["now"].isoformat(), "frameworks": fw, "counts": counts,
            "disclaimer": "Evidence support only: statuses reflect SIEM configuration and data, not an audit or certification."}
