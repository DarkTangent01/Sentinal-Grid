"""Policy analytics API (v1). Read-only: collection uses GET requests; nothing here modifies a firewall."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..analytics.filters import table
from ..db.ch import ClickHouse
from ..db.models import (Firewall, FirewallPolicy, PolicyAnalysisRun, PolicyAssessmentChange, PolicyConfigChange,
                         PolicyObjectSet, PolicySync, ShadowFinding, User)
from ..db.pg import get_session
from ..policy.collector import sync_firewall
from ..policy.store import to_utc, usage_for
from ..policy.usage import CounterPoint, counter_deltas
from .deps import audit, ch_dep, current_user, iso, require_admin

router = APIRouter(prefix="/api/v1/policies", tags=["policies"])
WINDOWS = (7, 30, 60, 90)
METRIC_SOURCES = {
    "firewall_hits": "FortiGate per-policy hit counter (/monitor/firewall/policy), summed as deltas between SIEM snapshots",
    "siem_matches": "Traffic logs ingested by this SIEM whose policyid (and poluuid when logged) match the policy",
    "last_seen": "Latest of firewall last-used timestamp and latest matching log",
}


def _win(window_days: int) -> int:
    if window_days not in WINDOWS:
        raise HTTPException(422, f"window_days must be one of {WINDOWS}")
    return window_days


async def _scopes(s: AsyncSession, firewall_id: int | None, vdom: str | None):
    q = select(PolicySync)
    if firewall_id:
        q = q.where(PolicySync.firewall_id == firewall_id)
    if vdom:
        q = q.where(PolicySync.vdom == vdom)
    syncs = (await s.execute(q)).scalars().all()
    fws = {f.id: f for f in (await s.execute(select(Firewall))).scalars()}
    return [(st, fws[st.firewall_id]) for st in syncs if st.firewall_id in fws]


def _row(p: FirewallPolicy, fw: Firewall, u: dict, st: PolicySync) -> dict:
    c, m, a = u.get("counters"), u.get("siem") or {}, u["assessment"]
    cfg = p.config or {}
    last_candidates = [x for x in [(c or {}).get("last_used"), to_utc(m.get("last_seen"))] if x]
    return {
        "firewall_id": fw.id, "firewall": fw.name, "site": fw.site, "vdom": p.vdom, "policyid": p.policyid, "uuid": p.uuid,
        "name": p.name, "seq": p.seq, "srcintf": cfg.get("srcintf", []), "dstintf": cfg.get("dstintf", []),
        "srcaddr": cfg.get("srcaddr", []), "dstaddr": cfg.get("dstaddr", []), "service": cfg.get("service", []),
        "schedule": cfg.get("schedule"), "action": p.action, "status": p.status, "nat": cfg.get("nat"), "logtraffic": p.logtraffic,
        "profiles": cfg.get("profiles", {}), "source": p.source,
        # explicit None = "Not available" (never shown as zero)
        "firewall_hits": c["hits"] if c else None, "firewall_bytes": c["bytes"] if c else None,
        "firewall_counter_total": c["current_hits"] if c else None, "counter_resets": c["resets"] if c else None,
        "counters_supported": st.counters_supported,
        "siem_matches": m.get("matches", 0) if u.get("log_coverage_since") else None, "siem_bytes": m.get("bytes"),
        "siem_denied": m.get("denied"), "last_seen": max(last_candidates).isoformat() if last_candidates else None,
        "assessment": a, "analysis": p.analysis or {}, "last_changed_at": iso(p.last_changed_at),
        "first_seen_at": iso(p.first_seen_at), "log_coverage_since": u.get("log_coverage_since"),
    }


async def _rows(s, ch, window_days, firewall_id=None, vdom=None) -> list[dict]:
    rows = []
    for st, fw in await _scopes(s, firewall_id, vdom):
        pols, usage = await usage_for(s, ch, fw.id, st.vdom, window_days, st.counters_supported)
        rows += [_row(p, fw, usage[p.policyid], st) for p in pols]
    return rows


def _match(r: dict, f: dict) -> bool:
    def has(field, needle):
        return any(needle.lower() in str(x).lower() for x in r[field])
    if f.get("q") and not (f["q"].lower() in r["name"].lower() or f["q"] == str(r["policyid"]) or f["q"].lower() in (r["uuid"] or "")):
        return False
    for key in ("srcintf", "dstintf", "service"):
        if f.get(key) and not has(key, f[key]):
            return False
    if f.get("addr") and not (has("srcaddr", f["addr"]) or has("dstaddr", f["addr"])):
        return False
    if f.get("action") and r["action"] != f["action"]:
        return False
    if f.get("status") and r["status"] != f["status"]:
        return False
    if f.get("logging") and r["logtraffic"] != f["logging"]:
        return False
    if f.get("assessment") and r["assessment"]["state"] != f["assessment"]:
        return False
    if f.get("shadow") == "any" and not r["analysis"].get("findings"):
        return False
    if f.get("shadow") and f["shadow"] not in ("any",) and r["analysis"].get("worst") != f["shadow"]:
        return False
    if f.get("site") and r["site"] != f["site"]:
        return False
    return True


@router.get("/scopes")
async def scopes(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    out = []
    for st, fw in await _scopes(s, None, None):
        out.append({"firewall_id": fw.id, "firewall": fw.name, "site": fw.site, "vdom": st.vdom, "status": st.status,
                    "last_success": iso(st.last_success), "last_attempt": iso(st.last_attempt), "error": st.error,
                    "counters_supported": st.counters_supported, "policies": st.policies, "is_demo": fw.is_demo,
                    "details": st.details})
    return out


@router.get("/summary")
async def summary(window_days: int = 30, firewall_id: int | None = None, vdom: str | None = None,
                  _: User = Depends(current_user), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    rows = await _rows(s, ch, _win(window_days), firewall_id, vdom)
    since = datetime.now(timezone.utc) - timedelta(days=window_days)
    st = lambda x: sum(1 for r in rows if r["assessment"]["state"] == x)  # noqa: E731
    return {
        "window_days": window_days, "total": len(rows),
        "enabled": sum(r["status"] == "enable" for r in rows), "disabled": sum(r["status"] != "enable" for r in rows),
        "in_use": st("in_use"), "no_observed_hits": st("no_observed_hits") + st("potentially_unused"),
        "potentially_unused": st("potentially_unused"), "unknown": st("unknown"),
        "zero_counter": sum(1 for r in rows if r["firewall_hits"] == 0 and r["status"] == "enable"),
        "counters_available": any(r["counters_supported"] for r in rows),
        "no_logging": sum(1 for r in rows if r["logtraffic"] == "disable"),
        "shadowed": sum(1 for r in rows if r["analysis"].get("worst") in ("full_shadow", "redundant")),
        "with_findings": sum(1 for r in rows if r["analysis"].get("findings")),
        "changed": sum(1 for r in rows if r["last_changed_at"] and r["last_changed_at"] >= since.isoformat()
                       and r["first_seen_at"] < r["last_changed_at"]),
        "top_by_events": sorted(({"policyid": r["policyid"], "firewall_id": r["firewall_id"], "vdom": r["vdom"], "name": r["name"],
                                  "firewall": r["firewall"], "value": r["siem_matches"]} for r in rows if r["siem_matches"]),
                                key=lambda x: -x["value"])[:10],
        "top_by_bytes": sorted(({"policyid": r["policyid"], "firewall_id": r["firewall_id"], "vdom": r["vdom"], "name": r["name"],
                                 "firewall": r["firewall"], "value": r["firewall_bytes"] if r["firewall_bytes"] is not None else r["siem_bytes"],
                                 "source": "firewall counter" if r["firewall_bytes"] is not None else "SIEM logs"}
                                for r in rows if (r["firewall_bytes"] or r["siem_bytes"])), key=lambda x: -x["value"])[:10],
        "metric_sources": METRIC_SOURCES,
    }


@router.get("")
async def inventory(window_days: int = 30, firewall_id: int | None = None, vdom: str | None = None, site: str | None = None,
                    q: str | None = Query(None, max_length=128), srcintf: str | None = None, dstintf: str | None = None,
                    addr: str | None = None, service: str | None = None, action: str | None = Query(None, pattern="^(accept|deny|ipsec)$"),
                    status: str | None = Query(None, pattern="^(enable|disable)$"), logging: str | None = Query(None, pattern="^(all|utm|disable)$"),
                    assessment: str | None = None, shadow: str | None = None,
                    sort: str = Query("seq", pattern="^(seq|policyid|name|siem_matches|firewall_hits|last_seen|firewall)$"),
                    order: str = Query("asc", pattern="^(asc|desc)$"), page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=500),
                    _: User = Depends(current_user), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    rows = await _rows(s, ch, _win(window_days), firewall_id, vdom)
    f = dict(q=q, srcintf=srcintf, dstintf=dstintf, addr=addr, service=service, action=action, status=status, logging=logging,
             assessment=assessment, shadow=shadow, site=site)
    rows = [r for r in rows if _match(r, f)]
    rows.sort(key=lambda r: (r["firewall"], r["vdom"], r["seq"]) if sort == "seq" else
              ((r[sort] is None), r[sort] if r[sort] is not None else 0), reverse=(order == "desc" and sort != "seq"))
    return {"items": rows[(page - 1) * size: page * size], "total": len(rows), "page": page, "size": size,
            "window_days": window_days, "metric_sources": METRIC_SOURCES}


@router.get("/shadow")
async def shadow(firewall_id: int | None = None, vdom: str | None = None, classification: str | None = None,
                 severity: str | None = None, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    qy = select(ShadowFinding)
    if firewall_id:
        qy = qy.where(ShadowFinding.firewall_id == firewall_id)
    if vdom:
        qy = qy.where(ShadowFinding.vdom == vdom)
    if classification:
        qy = qy.where(ShadowFinding.classification == classification)
    if severity:
        qy = qy.where(ShadowFinding.severity == severity)
    fws = {f.id: f for f in (await s.execute(select(Firewall))).scalars()}
    items = [{"id": x.id, "run_id": x.run_id, "firewall_id": x.firewall_id, "firewall": fws.get(x.firewall_id).name if x.firewall_id in fws else "?",
              "vdom": x.vdom, "earlier_policyid": x.earlier_policyid, "later_policyid": x.later_policyid,
              "classification": x.classification, "severity": x.severity, "confidence": x.confidence, "explanation": x.explanation, **x.data}
             for x in (await s.execute(qy.order_by(ShadowFinding.firewall_id, ShadowFinding.later_policyid))).scalars()]
    runs = (await s.execute(select(PolicyAnalysisRun).order_by(PolicyAnalysisRun.started_at.desc()).limit(20))).scalars()
    order = ["high", "medium", "low"]
    return {"items": sorted(items, key=lambda i: (order.index(i["severity"]) if i["severity"] in order else 9, i["firewall"], i["later_seq"])),
            "by_severity": {sv: sum(1 for i in items if i["severity"] == sv) for sv in order},
            "by_classification": {c: sum(1 for i in items if i["classification"] == c) for c in ("full_shadow", "redundant", "partial_shadow", "overlap")},
            "runs": [{"id": r.id, "firewall_id": r.firewall_id, "vdom": r.vdom, "started_at": iso(r.started_at), "status": r.status,
                      "policies": r.policies, "findings": r.findings, "error": r.error} for r in runs]}


@router.get("/{firewall_id}/{vdom}/{policyid}")
async def detail(firewall_id: int, vdom: str, policyid: int, window_days: int = 30, _: User = Depends(current_user),
                 s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    window_days = _win(window_days)
    p = (await s.execute(select(FirewallPolicy).where(FirewallPolicy.firewall_id == firewall_id, FirewallPolicy.vdom == vdom,
                                                      FirewallPolicy.policyid == policyid))).scalar_one_or_none()
    fw = await s.get(Firewall, firewall_id)
    st = await s.get(PolicySync, (firewall_id, vdom))
    if not p or not fw or not st:
        raise HTTPException(404, "policy not found")
    pols, usage = await usage_for(s, ch, firewall_id, vdom, window_days, st.counters_supported)
    row = _row(p, fw, usage.get(policyid) or {"assessment": {"state": "unknown", "method": "-", "confidence": "-",
                                                                "reasons": ["policy deleted from firewall"]}}, st)
    t1 = datetime.now(timezone.utc)
    t0 = t1 - timedelta(days=window_days)
    b = 3600 if window_days <= 7 else 21600 if window_days <= 30 else 86400
    pw = {"fw": firewall_id, "pid": policyid, "t0": t0, "t1": t1, "b": b, "vd": vdom}
    where = ("firewall_id = {fw:UInt32} AND policy_id = {pid:UInt32} AND (vdom = {vd:String} OR vdom = '') "
             "AND event_time >= {t0:DateTime64(3)} AND event_time < {t1:DateTime64(3)}")
    if p.uuid:
        where += " AND (policy_uuid = '' OR policy_uuid = {puuid:String})"  # uuid comes from the device: bind it
        pw["puuid"] = p.uuid
    ts = await ch.aquery(f"""SELECT toStartOfInterval(event_time, toIntervalSecond({{b:UInt32}})) AS t, count() AS events,
        countIf(action IN ('deny','block')) AS denied, sum(sent_bytes + rcvd_bytes) AS bytes
        FROM {table()} WHERE category='traffic' AND {where} GROUP BY t
        ORDER BY t WITH FILL FROM toStartOfInterval(toDateTime({{t0:DateTime64(3)}}, 'UTC'), toIntervalSecond({{b:UInt32}}))
        TO toDateTime({{t1:DateTime64(3)}}, 'UTC') STEP toIntervalSecond({{b:UInt32}})""", pw)

    async def top(expr, cat="traffic", nonempty="1"):
        return await ch.aquery(f"""SELECT {expr} AS key, count() AS events, sum(sent_bytes + rcvd_bytes) AS bytes,
            countIf(action IN ('deny','block')) AS denied FROM {table()} WHERE category='{cat}' AND {where} AND {nonempty}
            GROUP BY key ORDER BY events DESC LIMIT 10""", pw)
    related = await ch.aquery(f"SELECT category, count() AS events FROM {table()} WHERE category != 'traffic' AND {where} GROUP BY category", pw)
    snaps = await ch.aquery("""SELECT ts, uuid, hit_count, bytes, packets, last_used FROM policy_counters FINAL
        WHERE firewall_id={fw:UInt32} AND vdom={vd:String} AND policyid={pid:UInt32} AND ts >= {t0:DateTime64(3)} ORDER BY ts""", pw)

    pts = [CounterPoint(to_utc(r["ts"]), r["uuid"], r["hit_count"], r["bytes"], r["packets"]) for r in snaps]
    counter_series = []
    for prev, cur in zip(pts, pts[1:]):
        d = counter_deltas([prev, cur])
        counter_series.append({"t": cur.ts.isoformat(), "hits": d["hits"] if cur.hit_count is not None else None,
                               "bytes": d["bytes"] if cur.bytes is not None else None, "total": cur.hit_count, "reset": d["resets"] > 0})
    changes = (await s.execute(select(PolicyConfigChange).where(PolicyConfigChange.firewall_id == firewall_id, PolicyConfigChange.vdom == vdom,
               PolicyConfigChange.policyid == policyid).order_by(PolicyConfigChange.observed_at.desc()).limit(50))).scalars()
    hist = (await s.execute(select(PolicyAssessmentChange).where(PolicyAssessmentChange.firewall_id == firewall_id, PolicyAssessmentChange.vdom == vdom,
            PolicyAssessmentChange.policyid == policyid).order_by(PolicyAssessmentChange.observed_at.desc()).limit(50))).scalars()
    rel = (await s.execute(select(ShadowFinding).where(ShadowFinding.firewall_id == firewall_id, ShadowFinding.vdom == vdom,
           (ShadowFinding.later_policyid == policyid) | (ShadowFinding.earlier_policyid == policyid)))).scalars()
    neighbours = {x.policyid: x for x in pols}
    objs = await s.get(PolicyObjectSet, (firewall_id, vdom))

    def clean(rows):
        return [{k: (to_utc(v).isoformat() if isinstance(v, datetime) else v) for k, v in r.items()} for r in rows]
    return {
        "policy": row, "config": p.config, "sync": {"status": st.status, "last_success": iso(st.last_success), "error": st.error,
                                                    "counters_supported": st.counters_supported,
                                                    "objects_collected_at": iso(objs.collected_at) if objs else None,
                                                    "object_errors": objs.errors if objs else {}},
        "deleted_at": iso(p.deleted_at), "uuid_history": p.uuid_history,
        "timeseries": {"bucket_seconds": b, "points": clean(ts)}, "counter_series": counter_series,
        "top_sources": clean(await top("src_ip", nonempty="src_ip != ''")), "top_destinations": clean(await top("dst_ip", nonempty="dst_ip != ''")),
        "top_ports": clean(await top("concat(proto_name, '/', toString(dst_port))", nonempty="dst_port IS NOT NULL")),
        "top_apps": clean(await top("app", nonempty="app != ''")),
        "related_events": clean(related),
        "changes": [{"observed_at": iso(c.observed_at), "change_type": c.change_type, "changed_fields": c.changed_fields,
                     "old": {k: c.old_config.get(k) for k in c.changed_fields} if c.changed_fields else {},
                     "new": {k: c.new_config.get(k) for k in c.changed_fields} if c.changed_fields else {}} for c in changes],
        "assessment_history": [{"observed_at": iso(h.observed_at), "state": h.state, "method": h.method, "confidence": h.confidence,
                                "window_days": h.window_days} for h in hist],
        "shadow": [{"id": x.id, "role": "later" if x.later_policyid == policyid else "earlier",
                    "other_policyid": x.earlier_policyid if x.later_policyid == policyid else x.later_policyid,
                    "other_name": (neighbours.get(x.earlier_policyid if x.later_policyid == policyid else x.later_policyid).name
                                   if (x.earlier_policyid if x.later_policyid == policyid else x.later_policyid) in neighbours else ""),
                    "classification": x.classification, "severity": x.severity, "confidence": x.confidence,
                    "explanation": x.explanation, **x.data} for x in rel],
        "window_days": window_days, "metric_sources": METRIC_SOURCES,
    }


@router.post("/sync/{firewall_id}")
async def sync_now(firewall_id: int, request: Request, admin: User = Depends(require_admin),
                   s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    fw = await s.get(Firewall, firewall_id)
    if not fw:
        raise HTTPException(404, "firewall not found")
    if fw.is_demo:
        raise HTTPException(400, "demo firewalls have no API; demo policies are synthetic")
    if fw.vendor != "fortinet":
        raise HTTPException(400, "policy analytics currently supports FortiGate only")
    st = await sync_firewall(s, ch, fw)
    await audit(s, request, admin.username, "policy_sync", fw.name, {"status": st.status, "policies": st.policies})
    return {"status": st.status, "error": st.error, "policies": st.policies, "counters_supported": st.counters_supported, "details": st.details}
