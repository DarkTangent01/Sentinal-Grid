"""Persist policy configuration, objects, counters, analysis runs and assessments."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..analytics.filters import table
from ..db.ch import ClickHouse
from ..db.models import (FirewallPolicy, PolicyAnalysisRun, PolicyAssessmentChange, PolicyConfigChange,
                         PolicyObjectSet, ShadowFinding)
from .model import config_hash
from .shadow import analyze
from .usage import assess

log = logging.getLogger("policy")
ASSESS_FIELDS = ("status", "action", "logtraffic", "type")


def _now():
    return datetime.now(timezone.utc)


def to_utc(v) -> datetime | None:
    """Normalize ClickHouse timestamps to aware UTC. The embedded engine returns strings; clickhouse-connect (server
    mode) returns datetime objects that may be timezone-naive. Comparing naive and aware datetimes raises TypeError."""
    if v in (None, ""):
        return None
    if isinstance(v, datetime):
        dt = v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    else:
        text = str(v).strip().replace(" ", "T").replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
        dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return None if dt.year <= 1970 else dt


async def store_policies(s: AsyncSession, firewall_id: int, vdom: str, policies: list[dict], source: str = "api") -> dict:
    now = _now()
    existing = {p.policyid: p for p in (await s.execute(select(FirewallPolicy).where(
        FirewallPolicy.firewall_id == firewall_id, FirewallPolicy.vdom == vdom))).scalars()}
    seen, summary = set(), {"created": 0, "modified": 0, "reordered": 0, "deleted": 0, "reused": 0}
    for p in policies:
        pid = p["policyid"]
        seen.add(pid)
        h = config_hash(p)
        row = existing.get(pid)
        if row is None or row.deleted_at is not None:
            if row is None:
                row = FirewallPolicy(firewall_id=firewall_id, vdom=vdom, policyid=pid, first_seen_at=now, uuid_history=[], analysis={}, assessment={})
                s.add(row)
            change = "created"
            row.deleted_at = None
            row.uuid_history = [*(row.uuid_history or []), {"uuid": p["uuid"], "first_seen": now.isoformat()}]
            s.add(PolicyConfigChange(firewall_id=firewall_id, vdom=vdom, policyid=pid, uuid=p["uuid"], observed_at=now,
                                     change_type=change, changed_fields=[], old_config={}, new_config=p))
            summary[change] += 1
            row.last_changed_at = now
        else:
            old = row.config or {}
            if row.uuid and p["uuid"] and row.uuid != p["uuid"]:
                # same policy ID, different object: the ID was deleted and reused
                row.uuid_history = [*(row.uuid_history or []), {"uuid": p["uuid"], "first_seen": now.isoformat()}]
                s.add(PolicyConfigChange(firewall_id=firewall_id, vdom=vdom, policyid=pid, uuid=p["uuid"], observed_at=now,
                                         change_type="reused", changed_fields=["uuid"], old_config=old, new_config=p))
                summary["reused"] += 1
                row.last_changed_at = now
            elif row.config_hash != h:
                fields = sorted(k for k in set(old) | set(p) if k != "seq" and old.get(k) != p.get(k))
                s.add(PolicyConfigChange(firewall_id=firewall_id, vdom=vdom, policyid=pid, uuid=p["uuid"], observed_at=now,
                                         change_type="modified", changed_fields=fields, old_config=old, new_config=p))
                summary["modified"] += 1
                row.last_changed_at = now
            elif row.seq != p["seq"]:
                s.add(PolicyConfigChange(firewall_id=firewall_id, vdom=vdom, policyid=pid, uuid=p["uuid"], observed_at=now,
                                         change_type="reordered", changed_fields=["seq"], old_config={"seq": row.seq}, new_config={"seq": p["seq"]}))
                summary["reordered"] += 1
        row.uuid, row.seq, row.name = p["uuid"], p["seq"], p["name"]
        row.status, row.action, row.logtraffic = p["status"], p["action"], p["logtraffic"]
        row.config, row.config_hash, row.source, row.last_seen_at = p, h, source, now
    for pid, row in existing.items():
        if pid not in seen and row.deleted_at is None:
            row.deleted_at = now
            s.add(PolicyConfigChange(firewall_id=firewall_id, vdom=vdom, policyid=pid, uuid=row.uuid, observed_at=now,
                                     change_type="deleted", changed_fields=[], old_config=row.config or {}, new_config={}))
            summary["deleted"] += 1
    await s.commit()
    return summary


async def store_objects(s: AsyncSession, firewall_id: int, vdom: str, objects: dict, errors: dict) -> None:
    row = await s.get(PolicyObjectSet, (firewall_id, vdom))
    if row is None:
        row = PolicyObjectSet(firewall_id=firewall_id, vdom=vdom)
        s.add(row)
    row.objects, row.errors, row.collected_at = objects, errors, _now()
    await s.commit()


COUNTER_COLS = ["ts", "firewall_id", "vdom", "policyid", "uuid", "hit_count", "bytes", "packets", "active_sessions",
                "first_used", "last_used", "source"]


def _int(v):
    try:
        return int(v) if v not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _epoch(v):
    n = _int(v)
    return datetime.fromtimestamp(n, tz=timezone.utc).replace(microsecond=0) if n and n > 0 else None


def parse_counters(results: list) -> list[dict]:
    """Parse /api/v2/monitor/firewall/policy results. Missing fields stay None ("Not available"), never 0."""
    out = []
    for r in results or []:
        if not isinstance(r, dict) or _int(r.get("policyid")) is None:
            continue
        out.append({"policyid": _int(r["policyid"]), "uuid": r.get("uuid") or "", "hit_count": _int(r.get("hit_count")),
                    "bytes": _int(r.get("bytes")), "packets": _int(r.get("packets")),
                    "active_sessions": _int(r.get("active_sessions")),
                    "first_used": _epoch(r.get("first_used")), "last_used": _epoch(r.get("last_used"))})
    return out


async def store_counters(ch: ClickHouse, firewall_id: int, vdom: str, counters: list[dict], source: str = "api") -> int:
    ts = _now().replace(microsecond=0)
    rows = [{**c, "ts": ts, "firewall_id": firewall_id, "vdom": vdom, "source": source} for c in counters]
    await ch.ainsert("policy_counters", rows, COUNTER_COLS)
    return len(rows)


async def run_analysis(s: AsyncSession, firewall_id: int, vdom: str) -> PolicyAnalysisRun:
    pols = (await s.execute(select(FirewallPolicy).where(FirewallPolicy.firewall_id == firewall_id, FirewallPolicy.vdom == vdom,
                                                         FirewallPolicy.deleted_at.is_(None)))).scalars().all()
    objs = await s.get(PolicyObjectSet, (firewall_id, vdom))
    run = PolicyAnalysisRun(firewall_id=firewall_id, vdom=vdom, started_at=_now(), status="running")
    s.add(run)
    await s.flush()
    try:
        configs = [p.config for p in pols]
        result = analyze(configs, (objs.objects if objs else {}) or {})
        await s.execute(delete(ShadowFinding).where(ShadowFinding.firewall_id == firewall_id, ShadowFinding.vdom == vdom))
        for f in result["findings"]:
            s.add(ShadowFinding(run_id=run.id, firewall_id=firewall_id, vdom=vdom, earlier_policyid=f["earlier_policyid"],
                                later_policyid=f["later_policyid"], classification=f["classification"], severity=f["severity"],
                                confidence=f["confidence"], explanation=f["explanation"],
                                data={k: v for k, v in f.items() if k not in ("classification", "severity", "confidence", "explanation")}))
        by_id = {p.policyid: p for p in pols}
        for pid, st in result["policy_status"].items():
            if pid in by_id:
                rel = [f for f in result["findings"] if f["later_policyid"] == pid]
                by_id[pid].analysis = {**st, "findings": len(rel),
                                       "worst": max((f["classification"] for f in rel), key=lambda c: ["overlap", "partial_shadow", "redundant", "full_shadow"].index(c), default=None)}
        if not objs:
            run.error = "address/service objects not collected; analysis limited to predefined services"
        run.status, run.policies, run.findings = "ok", result["policies_analyzed"], len(result["findings"])
    except Exception as e:  # keep the previous findings visible if analysis fails
        log.exception("policy analysis failed for firewall %s/%s", firewall_id, vdom)
        run.status, run.error = "error", str(e)[:2000]
    run.finished_at = _now()
    await s.commit()
    return run


# ---------------------------------------------------------------- usage data (ClickHouse)
COUNTER_DELTA_SQL = """
SELECT policyid,
       sum(d_hits) AS hits, sum(d_bytes) AS bytes, sum(d_packets) AS packets,
       min(ts) AS first, max(ts) AS last, count() - 1 AS intervals, sum(reset) AS resets,
       max(last_used) AS last_used, argMax(hit_count, ts) AS current_hits, countIf(hit_count IS NULL) AS null_hits
FROM (
    SELECT policyid, ts, last_used, hit_count,
           row_number() OVER w AS rn,
           lagInFrame(hit_count) OVER w AS ph, lagInFrame(uuid) OVER w AS pu,
           lagInFrame(bytes) OVER w AS pb, lagInFrame(packets) OVER w AS pp,
           if(rn = 1 OR hit_count IS NULL OR ph IS NULL, 0,
              if(hit_count < ph OR (uuid != pu AND uuid != '' AND pu != ''), toInt64(assumeNotNull(hit_count)), toInt64(assumeNotNull(hit_count)) - toInt64(assumeNotNull(ph)))) AS d_hits,
           if(rn = 1 OR bytes IS NULL OR pb IS NULL, 0, if(bytes < pb OR (uuid != pu AND uuid != '' AND pu != ''), toInt64(assumeNotNull(bytes)), toInt64(assumeNotNull(bytes)) - toInt64(assumeNotNull(pb)))) AS d_bytes,
           if(rn = 1 OR packets IS NULL OR pp IS NULL, 0, if(packets < pp OR (uuid != pu AND uuid != '' AND pu != ''), toInt64(assumeNotNull(packets)), toInt64(assumeNotNull(packets)) - toInt64(assumeNotNull(pp)))) AS d_packets,
           if(rn > 1 AND hit_count IS NOT NULL AND ph IS NOT NULL AND (hit_count < ph OR (uuid != pu AND uuid != '' AND pu != '')), 1, 0) AS reset
    FROM (SELECT * FROM policy_counters FINAL
          WHERE firewall_id = {fw:UInt32} AND vdom = {vd:String} AND ts >= {t0:DateTime64(3)} AND ts <= {t1:DateTime64(3)})
    WINDOW w AS (PARTITION BY policyid ORDER BY ts ROWS BETWEEN 1 PRECEDING AND CURRENT ROW)
)
GROUP BY policyid
"""


async def counter_deltas_window(ch: ClickHouse, fw: int, vdom: str, t0, t1) -> dict[int, dict]:
    rows = await ch.aquery(COUNTER_DELTA_SQL, {"fw": fw, "vd": vdom, "t0": t0, "t1": t1})
    out = {}
    for r in rows:
        dt = to_utc
        out[int(r["policyid"])] = {"hits": int(r["hits"] or 0), "bytes": int(r["bytes"] or 0), "packets": int(r["packets"] or 0),
                                   "first": dt(r["first"]), "last": dt(r["last"]), "intervals": int(r["intervals"]),
                                   "resets": int(r["resets"]), "last_used": dt(r["last_used"]),
                                   "current_hits": r["current_hits"], "all_null": int(r["null_hits"]) == int(r["intervals"]) + 1}
    return out


async def siem_matches(ch: ClickHouse, fw: int, vdom: str, t0, t1, policies: list[FirewallPolicy]) -> dict[int, dict]:
    """Traffic log matches per policy. Logs carry policyid (+ poluuid on FortiOS 6.2+). When a policy ID was reused
    (UUID history > 1), logs without a UUID are only attributed after the current UUID was first observed."""
    rows = await ch.aquery(
        f"""SELECT policy_id, policy_uuid, count() AS n, max(event_time) AS last, min(event_time) AS first,
                   sum(sent_bytes + rcvd_bytes) AS bytes, countIf(action IN ('deny','block')) AS denied
            FROM {table()} WHERE category = 'traffic' AND firewall_id = {{fw:UInt32}} AND (vdom = {{vd:String}} OR vdom = '')
              AND event_time >= {{t0:DateTime64(3)}} AND event_time < {{t1:DateTime64(3)}} AND policy_id IS NOT NULL
            GROUP BY policy_id, policy_uuid""", {"fw": fw, "vd": vdom, "t0": t0, "t1": t1})
    by_id: dict[int, list] = {}
    for r in rows:
        by_id.setdefault(int(r["policy_id"]), []).append(r)
    out = {}
    for p in policies:
        reused = len(p.uuid_history or []) > 1
        total = {"matches": 0, "bytes": 0, "denied": 0, "last_seen": None, "time_cut": None}
        for r in by_id.get(p.policyid, []):
            if r["policy_uuid"] and p.uuid and r["policy_uuid"] != p.uuid:
                continue  # belongs to a previous policy that used this ID
            if not r["policy_uuid"] and reused:
                total["time_cut"] = (p.uuid_history or [{}])[-1].get("first_seen")
                continue  # counted below with a time cut
            total["matches"] += int(r["n"])
            total["bytes"] += int(r["bytes"])
            total["denied"] += int(r["denied"])
            last = to_utc(r["last"])
            total["last_seen"] = max(filter(None, [total["last_seen"], last]))
        if total["time_cut"]:
            cut = to_utc(total["time_cut"])
            extra = await ch.aquery(
                f"""SELECT count() AS n, max(event_time) AS last, sum(sent_bytes + rcvd_bytes) AS bytes FROM {table()}
                    WHERE category='traffic' AND firewall_id={{fw:UInt32}} AND policy_id={{pid:UInt32}} AND policy_uuid=''
                      AND event_time >= {{c:DateTime64(3)}} AND event_time < {{t1:DateTime64(3)}}""",
                {"fw": fw, "pid": p.policyid, "c": max(cut, t0), "t1": t1})
            if extra and int(extra[0]["n"]):
                total["matches"] += int(extra[0]["n"])
                total["bytes"] += int(extra[0]["bytes"])
                total["last_seen"] = max(filter(None, [total["last_seen"], to_utc(extra[0]["last"])]))
        out[p.policyid] = total
    return out


async def ingest_since(ch: ClickHouse, fw: int) -> datetime | None:
    r = await ch.aquery(f"SELECT min(event_time) AS m, count() AS n FROM {table()} WHERE category='traffic' AND firewall_id={{fw:UInt32}}", {"fw": fw})
    if not r or not int(r[0]["n"]):
        return None
    return to_utc(r[0]["m"])


async def usage_for(s: AsyncSession, ch: ClickHouse, fw: int, vdom: str, window_days: int, counters_supported: bool | None,
                    min_days: int = 30) -> tuple[list[FirewallPolicy], dict[int, dict]]:
    t1 = _now()
    t0 = t1 - timedelta(days=window_days)
    pols = (await s.execute(select(FirewallPolicy).where(FirewallPolicy.firewall_id == fw, FirewallPolicy.vdom == vdom,
                                                         FirewallPolicy.deleted_at.is_(None)).order_by(FirewallPolicy.seq))).scalars().all()
    counters = await counter_deltas_window(ch, fw, vdom, t0, t1) if counters_supported else {}
    matches = await siem_matches(ch, fw, vdom, t0, t1, pols)
    since = await ingest_since(ch, fw)
    out = {}
    for p in pols:
        c = counters.get(p.policyid)
        if c and c["all_null"]:
            c = None
        m = matches.get(p.policyid, {})
        a = assess(policy=p.config, window_start=t0, window_end=t1, counters=c, counter_last_used=c["last_used"] if c else None,
                   siem_matches=m.get("matches", 0),
                   siem_last_seen=m.get("last_seen"),
                   ingest_since=since, min_days=min_days)
        m = {**m, "last_seen": m["last_seen"].isoformat() if m.get("last_seen") else None}
        out[p.policyid] = {"assessment": a, "counters": c, "siem": m, "window_days": window_days,
                           "log_coverage_since": since.isoformat() if since else None}
    return pols, out


async def refresh_assessments(s: AsyncSession, ch: ClickHouse, fw: int, vdom: str, counters_supported: bool | None, window_days: int = 30) -> None:
    pols, usage = await usage_for(s, ch, fw, vdom, window_days, counters_supported)
    now = _now()
    for p in pols:
        a = usage[p.policyid]["assessment"]
        prev = (p.assessment or {}).get("state")
        p.assessment = {**a, "window_days": window_days, "assessed_at": now.isoformat()}
        if prev != a["state"]:
            s.add(PolicyAssessmentChange(firewall_id=fw, vdom=vdom, policyid=p.policyid, observed_at=now, state=a["state"],
                                         method=a["method"], confidence=a["confidence"], window_days=window_days))
    await s.commit()
