"""APIs: Sentinel NMS → Network Compliance (app/netcompliance).

Everyone with NMS access sees the results, scores and evidence summaries. Configuration lines quoted as evidence
(already secret-masked by the backup) are returned to administrators only, like the configuration text itself.
Running an evaluation reads stored data only (no device is contacted). Exceptions are administrator actions and
are audited.
"""
import csv
import io
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import NetComplianceException, NetComplianceResult, NetComplianceRun, User
from ..db.pg import get_session
from ..netcompliance import engine
from ..netcompliance.checks import BY_ID, CATALOG_VERSION, CHECKS
from ..netcompliance.frameworks import FRAMEWORKS
from .deps import audit, csv_safe, current_user, require_admin

router = APIRouter(prefix="/api/nms/compliance", tags=["nms-compliance"])
KINDS = ("switch", "firewall")
SEV_ORDER = {"high": 0, "medium": 1, "low": 2}


def _iso(v):
    return (v if v.tzinfo else v.replace(tzinfo=timezone.utc)).isoformat() if v else None


def _check_out(c) -> dict:
    return {"id": c.id, "title": c.title, "severity": c.severity, "kinds": list(c.kinds), "category": c.category, "rationale": c.rationale,
            "refs": c.refs, "source": c.source, "vendors_with_fix": sorted(c.fix)}


def _run_out(r: NetComplianceRun | None) -> dict | None:
    if not r:
        return None
    return {"id": r.id, "started_at": _iso(r.started_at), "finished_at": _iso(r.finished_at), "trigger": r.trigger,
            "triggered_by": r.triggered_by, "devices": r.devices, "totals": r.totals, "catalog_version": r.catalog_version}


def _fw(framework: str | None) -> str | None:
    if framework and framework not in FRAMEWORKS:
        raise HTTPException(422, f"unknown framework (one of {', '.join(FRAMEWORKS)})")
    return framework


async def _latest_rows(s: AsyncSession) -> tuple[NetComplianceRun | None, list[NetComplianceResult]]:
    run = await engine.latest_run(s)
    if not run:
        return None, []
    rows = list((await s.execute(select(NetComplianceResult).where(NetComplianceResult.run_id == run.id))).scalars())
    return run, rows


def _in_fw(check_id: str, framework: str | None) -> bool:
    c = BY_ID.get(check_id)
    return bool(c) and (framework is None or framework in c.refs)


@router.get("/catalog")
async def catalog(_: User = Depends(current_user)):
    return {"version": CATALOG_VERSION, "checks": [_check_out(c) for c in CHECKS],
            "frameworks": {k: {"name": v["name"], "short": v["short"], "note": v["note"], "controls": v["controls"]} for k, v in FRAMEWORKS.items()}}


@router.get("/summary")
async def summary(framework: str | None = None, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    framework = _fw(framework)
    run, rows = await _latest_rows(s)
    exc = await engine.active_exceptions(s)
    data = [(r.device_kind, r.device_id, r.results) for r in rows]
    fws = engine.framework_summary(data, exc)
    by_check: dict[str, Counter] = defaultdict(Counter)
    by_sev: dict[str, Counter] = defaultdict(Counter)
    by_kind: dict[str, Counter] = defaultdict(Counter)
    devices = []
    for r in rows:
        dc = Counter()
        for x in r.results:
            if not _in_fw(x["check"], framework):
                continue
            st = engine.status_with_exceptions(x, r.device_kind, r.device_id, exc)
            by_check[x["check"]][st] += 1
            by_sev[BY_ID[x["check"]].severity][st] += 1
            by_kind[r.device_kind][st] += 1
            dc[st] += 1
            if st == "fail":
                dc[f"fail_{BY_ID[x['check']].severity}"] += 1
        devices.append({"kind": r.device_kind, "id": r.device_id, "name": r.device_name, "site": r.site, "vendor": r.vendor,
                        "device_type": r.device_type, **engine.score(dc), "fail_high": dc.get("fail_high", 0)})
    trend_runs = list((await s.execute(select(NetComplianceRun).where(NetComplianceRun.finished_at.is_not(None))
                                       .order_by(NetComplianceRun.started_at.desc()).limit(60))).scalars())[::-1]
    overall = engine.score(sum(by_kind.values(), Counter()))
    return {
        "run": _run_out(run), "framework": framework, "overall": overall,
        "frameworks": {k: {kk: vv for kk, vv in v.items() if kk != "controls"} | {"name": FRAMEWORKS[k]["name"], "short": FRAMEWORKS[k]["short"]}
                       for k, v in fws.items()},
        "by_kind": {k: engine.score(v) for k, v in by_kind.items()},
        "by_severity": {k: engine.score(by_sev.get(k, Counter())) for k in ("high", "medium", "low")},
        "checks": sorted(({**_check_out(BY_ID[k]), **engine.score(v)} for k, v in by_check.items()),
                         key=lambda c: (-c["fail"], SEV_ORDER[c["severity"]], c["id"])),
        "worst_devices": sorted((d for d in devices if d["fail"]), key=lambda d: (-d["fail_high"], -d["fail"], d["name"]))[:15],
        "trend": [{"run_id": t.id, "at": _iso(t.started_at), "score": ((t.summary or {}).get(framework) or {}).get("score") if framework
                   else engine.score(Counter({k: v for k, v in (t.totals or {}).items() if k in engine.STATUSES}))["score"],
                   "coverage": ((t.summary or {}).get(framework) or {}).get("coverage") if framework
                   else engine.score(Counter({k: v for k, v in (t.totals or {}).items() if k in engine.STATUSES}))["coverage"]}
                  for t in trend_runs],
        "exceptions_active": len(exc),
        "devices_by_kind": dict(Counter(r.device_kind for r in rows)),
    }


@router.get("/controls")
async def controls(framework: str = Query("cis"), _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    framework = _fw(framework)
    run, rows = await _latest_rows(s)
    exc = await engine.active_exceptions(s)
    fs = engine.framework_summary([(r.device_kind, r.device_id, r.results) for r in rows], exc)[framework]
    per_check: dict[str, Counter] = defaultdict(Counter)
    for r in rows:
        for x in r.results:
            per_check[x["check"]][engine.status_with_exceptions(x, r.device_kind, r.device_id, exc)] += 1
    items = []
    for cid, title in FRAMEWORKS[framework]["controls"].items():
        checks = [c for c in CHECKS if cid in c.refs.get(framework, [])]
        if not checks:
            continue
        sc = fs["controls"].get(cid) or engine.score(Counter())
        items.append({"control": cid, "title": title, **sc,
                      "status": "no_evidence" if sc["pass"] + sc["fail"] == 0 else "met" if sc["fail"] == 0 else "partial" if sc["pass"] else "not_met",
                      "checks": [{"id": c.id, "title": c.title, "severity": c.severity, **engine.score(per_check.get(c.id, Counter()))} for c in checks]})
    return {"run": _run_out(run), "framework": framework, "name": FRAMEWORKS[framework]["name"], "note": FRAMEWORKS[framework]["note"],
            **{k: v for k, v in fs.items() if k != "controls"}, "items": items}


@router.get("/devices")
async def devices(framework: str | None = None, kind: str | None = None, site: str | None = None, vendor: str | None = None,
                  q: str | None = None, status: str | None = Query(None, pattern="^(failing|passing|no_evidence)$"),
                  _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    framework = _fw(framework)
    run, rows = await _latest_rows(s)
    exc = await engine.active_exceptions(s)
    out = []
    for r in rows:
        if (kind and r.device_kind != kind) or (site and r.site != site) or (vendor and r.vendor != vendor) or \
                (q and q.lower() not in r.device_name.lower()):
            continue
        dc = Counter()
        for x in r.results:
            if _in_fw(x["check"], framework):
                st = engine.status_with_exceptions(x, r.device_kind, r.device_id, exc)
                dc[st] += 1
                if st == "fail":
                    dc[f"fail_{BY_ID[x['check']].severity}"] += 1
        sc = engine.score(dc)
        if status == "failing" and not sc["fail"] or status == "passing" and (sc["fail"] or not sc["pass"]) or \
                status == "no_evidence" and (sc["pass"] or sc["fail"]):
            continue
        out.append({"kind": r.device_kind, "id": r.device_id, "name": r.device_name, "site": r.site, "vendor": r.vendor,
                    "device_type": r.device_type, **sc, "fail_high": dc.get("fail_high", 0), "fail_medium": dc.get("fail_medium", 0),
                    "fail_low": dc.get("fail_low", 0)})
    out.sort(key=lambda d: (-d["fail_high"], -d["fail"], d["name"].lower()))
    return {"run": _run_out(run), "items": out, "sites": sorted({r.site for r in rows if r.site}), "vendors": sorted({r.vendor for r in rows if r.vendor})}


@router.get("/devices/{kind}/{device_id}")
async def device(kind: str, device_id: int, framework: str | None = None, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    framework = _fw(framework)
    if kind not in KINDS:
        raise HTTPException(404, "unknown device kind")
    run = await engine.latest_run(s)
    if not run:
        raise HTTPException(404, "no compliance run yet")
    r = (await s.execute(select(NetComplianceResult).where(NetComplianceResult.run_id == run.id, NetComplianceResult.device_kind == kind,
                                                           NetComplianceResult.device_id == device_id))).scalars().first()
    if not r:
        raise HTTPException(404, "device not in the latest run")
    exc = await engine.active_exceptions(s)
    admin = user.role == "admin"
    findings = []
    for x in r.results:
        if not _in_fw(x["check"], framework):
            continue
        c = BY_ID[x["check"]]
        e = next((e for e in exc if e.check_id == c.id and e.device_kind == kind and (e.device_id is None or e.device_id == device_id)), None)
        vendor = "fortinet" if kind == "firewall" else r.vendor
        findings.append({**_check_out(c), "status": engine.status_with_exceptions(x, kind, device_id, exc), "raw_status": x["status"],
                         "evidence": x["evidence"], "lines": x.get("lines", []) if admin else [], "lines_hidden": bool(x.get("lines")) and not admin,
                         "fix": c.fix.get(vendor, "") if x["status"] == "fail" else "",
                         "exception": {"id": e.id, "reason": e.reason, "expires_at": _iso(e.expires_at), "created_by": e.created_by,
                                       "scope": "device" if e.device_id else "all"} if e else None})
    findings.sort(key=lambda f: ({"fail": 0, "not_evaluated": 1, "excepted": 2, "pass": 3}[f["status"]], SEV_ORDER[f["severity"]], f["id"]))
    return {"run": _run_out(run), "kind": kind, "id": device_id, "name": r.device_name, "site": r.site, "vendor": r.vendor,
            "device_type": r.device_type, **engine.score(Counter(f["status"] for f in findings)), "findings": findings}


@router.get("/checks/{check_id}")
async def check(check_id: str, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    c = BY_ID.get(check_id)
    if not c:
        raise HTTPException(404, "unknown check")
    run, rows = await _latest_rows(s)
    exc = await engine.active_exceptions(s)
    items = []
    for r in rows:
        x = next((x for x in r.results if x["check"] == check_id), None)
        if x:
            items.append({"kind": r.device_kind, "id": r.device_id, "name": r.device_name, "site": r.site, "vendor": r.vendor,
                          "status": engine.status_with_exceptions(x, r.device_kind, r.device_id, exc), "evidence": x["evidence"]})
    items.sort(key=lambda i: ({"fail": 0, "not_evaluated": 1, "excepted": 2, "pass": 3}[i["status"]], i["name"].lower()))
    return {"run": _run_out(run), **_check_out(c), "fix": c.fix, **engine.score(Counter(i["status"] for i in items)), "items": items}


@router.get("/runs")
async def runs(limit: int = Query(30, ge=1, le=200), _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    rs = (await s.execute(select(NetComplianceRun).order_by(NetComplianceRun.started_at.desc()).limit(limit))).scalars()
    return {"items": [{**_run_out(r), "summary": r.summary} for r in rs]}


@router.post("/run")
async def run_now(request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    r = await engine.run(s, trigger="manual", user=user.username)
    await audit(s, request, user.username, "network_compliance_run", str(r.id), {"devices": r.devices})
    return _run_out(r)


class ExceptionIn(BaseModel):
    check_id: str = Field(min_length=1, max_length=16)
    device_kind: str = Field(pattern="^(switch|firewall)$")
    device_id: int | None = None
    reason: str = Field(min_length=10, max_length=2000)
    days: int = Field(90, ge=1, le=365)


@router.get("/exceptions")
async def exceptions(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    now = datetime.now(timezone.utc)
    names = {}
    run, rows = await _latest_rows(s)
    for r in rows:
        names[(r.device_kind, r.device_id)] = r.device_name
    items = (await s.execute(select(NetComplianceException).order_by(NetComplianceException.expires_at))).scalars()
    return {"items": [{"id": e.id, "check_id": e.check_id, "check_title": BY_ID[e.check_id].title if e.check_id in BY_ID else e.check_id,
                       "device_kind": e.device_kind, "device_id": e.device_id,
                       "device_name": names.get((e.device_kind, e.device_id), f"#{e.device_id}") if e.device_id else "all devices",
                       "reason": e.reason, "expires_at": _iso(e.expires_at), "expired": engine.aware(e.expires_at) <= now,
                       "created_by": e.created_by, "created_at": _iso(e.created_at)} for e in items]}


@router.post("/exceptions")
async def add_exception(body: ExceptionIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    c = BY_ID.get(body.check_id)
    if not c:
        raise HTTPException(422, "unknown check")
    if body.device_kind not in c.kinds:
        raise HTTPException(422, f"check {c.id} does not apply to {body.device_kind} devices")
    e = NetComplianceException(check_id=c.id, device_kind=body.device_kind, device_id=body.device_id, reason=body.reason.strip(),
                               expires_at=datetime.now(timezone.utc) + timedelta(days=body.days), created_by=user.username)
    s.add(e)
    await s.flush()
    await audit(s, request, user.username, "network_compliance_exception_add", f"{c.id}:{body.device_kind}:{body.device_id or 'all'}",
                {"reason": e.reason, "days": body.days})
    return {"id": e.id}


@router.delete("/exceptions/{exc_id}")
async def delete_exception(exc_id: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    e = await s.get(NetComplianceException, exc_id)
    if not e:
        raise HTTPException(404, "not found")
    target = f"{e.check_id}:{e.device_kind}:{e.device_id or 'all'}"
    await s.delete(e)
    await audit(s, request, user.username, "network_compliance_exception_delete", target)
    return {"ok": True}


@router.get("/export.csv")
async def export(framework: str | None = None, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    framework = _fw(framework)
    run, rows = await _latest_rows(s)
    exc = await engine.active_exceptions(s)
    buf = io.StringIO()
    w = csv.writer(buf)
    fws = [framework] if framework else list(FRAMEWORKS)
    w.writerow(["run", "evaluated_at", "device", "kind", "site", "vendor", "check", "title", "severity", "status", "evidence",
                *[FRAMEWORKS[f]["short"] for f in fws]])
    for r in rows:
        for x in r.results:
            if not _in_fw(x["check"], framework):
                continue
            c = BY_ID[x["check"]]
            w.writerow([csv_safe(v) for v in (run.id, _iso(run.started_at), r.device_name, r.device_kind, r.site, r.vendor, c.id, c.title, c.severity,
                                              engine.status_with_exceptions(x, r.device_kind, r.device_id, exc), x["evidence"],
                                              *[" ".join(c.refs.get(f, [])) for f in fws])])
    name = f"network-compliance-{framework or 'all'}-{datetime.now(timezone.utc):%Y%m%d}.csv"
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="{name}"'})
