"""APIs: YAML detection rules (Sentinel Grid → Detections → Rule pack). docs/DETECTION_RULES.md.

Reads, validation, embedded tests and historical dry runs are open to every Grid user. None of them writes alerts, and
tests only touch the rule's own inline test rows. Creating, changing and deleting custom rules needs the administrator
role and is audited. Enable / disable, severity and threshold use the existing /api/alert-rules/{key}.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..assets import internal_cidrs
from ..db.ch import ClickHouse
from ..db.models import AlertRule, User
from ..db.pg import get_session
from ..detection.compiler import compile_rule
from ..detection.loader import MAX_YAML_BYTES, RuleError, builtin, parse_rule, rule_for, sha256
from ..detection.runner import dry_run, run_tests
from ..detection.schema import Rule, rule_key
from .deps import audit, ch_dep, current_user, require_admin

router = APIRouter(prefix="/api/detections/yaml", tags=["detection-rules"])
HISTORY = 20


class YamlIn(BaseModel):
    yaml: str = Field(min_length=10, max_length=MAX_YAML_BYTES)


def _row(r: Rule, text: str, origin: str, ar: AlertRule | None, full: bool = False) -> dict:
    params = (ar.params if ar else {}) or {}
    c = r.detection.condition
    out = {"key": r.key, "id": r.id, "name": r.name, "description": r.description, "version": r.version, "origin": origin, "status": r.status,
           "enabled": ar.enabled if ar else False, "severity": ar.severity if ar else r.severity, "default_severity": r.severity,
           "category": r.category, "log_source": r.log_source.model_dump(exclude_none=True), "data_sources": r.data_sources,
           "falsepositives": r.falsepositives, "investigation": r.investigation, "mitre": r.mitre_dict(), "tags": r.tags,
           "tests": len(r.tests), "threshold": params.get("threshold", c.threshold), "default_threshold": c.threshold, "timeframe_s": c.timeframe,
           "group_by": c.group_by, "sha256": sha256(text)[:16], "stats": params.get("_stats"), "installed": ar is not None}
    if full:
        out["yaml"] = text
        out["history"] = [{k: v for k, v in h.items() if k != "yaml"} for h in params.get("history", [])]
    return out


async def _rows(s: AsyncSession) -> dict[str, AlertRule]:
    return {r.key: r for r in (await s.execute(select(AlertRule).where(AlertRule.key.like("yml\\_%", escape="\\")))).scalars()}


def _errors(e: RuleError) -> HTTPException:
    return HTTPException(422, {"message": "rule is invalid", "errors": e.errors})


@router.get("")
async def list_rules(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    rows = await _rows(s)
    out = [_row(r, text, "builtin", rows.get(k)) for k, (r, text) in builtin().items()]
    for k, ar in rows.items():
        if k in builtin():
            continue
        try:
            r, text, origin = rule_for(k, ar.params)  # type: ignore[misc]
            out.append(_row(r, text, origin, ar))
        except (RuleError, TypeError):
            out.append({"key": k, "id": k, "name": ar.name, "origin": "custom", "invalid": True, "enabled": ar.enabled})
    return {"items": sorted(out, key=lambda x: x["id"])}


@router.get("/{key}")
async def get_rule(key: str, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    ar = (await _rows(s)).get(key)
    found = rule_for(key, ar.params if ar else None)
    if not found:
        raise HTTPException(404, "rule not found")
    r, text, origin = found
    return _row(r, text, origin, ar, full=True)


@router.post("/validate")
async def validate(body: YamlIn, _: User = Depends(current_user)):
    """Validate YAML and show the compiled query (values appear as bound parameters, never inline)."""
    try:
        r = parse_rule(body.yaml)
    except RuleError as e:
        return {"valid": False, "errors": e.errors}
    now = datetime.now(timezone.utc)
    q = compile_rule(r, t0=now, t1=now, cidrs=["<INTERNAL_CIDRS>"])
    return {"valid": True, "errors": [], "key": r.key, "id": r.id, "version": r.version, "tests": len(r.tests), "sql": q.sql,
            "parameters": {k: (v if not isinstance(v, datetime) else v.isoformat()) for k, v in q.params.items()}}


@router.post("/test")
async def test_yaml(body: YamlIn, _: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep)):
    """Run the embedded test cases of unsaved YAML (rule editor)."""
    try:
        r = parse_rule(body.yaml)
    except RuleError as e:
        raise _errors(e)
    res = await run_tests(ch, r)
    return {"id": r.id, "passed": all(x["passed"] for x in res), "results": res}


@router.post("/{key}/test")
async def test_rule(key: str, _: User = Depends(current_user), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    ar = (await _rows(s)).get(key)
    found = rule_for(key, ar.params if ar else None)
    if not found:
        raise HTTPException(404, "rule not found")
    res = await run_tests(ch, found[0])
    return {"id": found[0].id, "passed": all(x["passed"] for x in res), "results": res}


@router.post("/{key}/dry-run")
async def dry_run_rule(key: str, hours: int = Query(24, ge=1, le=168), _: User = Depends(current_user), s: AsyncSession = Depends(get_session),
                       ch: ClickHouse = Depends(ch_dep)):
    """Historical replay over real events: which groups would have alerted. Read-only; no alerts are created."""
    ar = (await _rows(s)).get(key)
    found = rule_for(key, ar.params if ar else None)
    if not found:
        raise HTTPException(404, "rule not found")
    thr = (ar.params or {}).get("threshold") if ar else None
    return await dry_run(ch, found[0], datetime.now(timezone.utc), hours, internal_cidrs(), thr)


@router.post("", status_code=201)
async def save_custom(body: YamlIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session),
                      ch: ClickHouse = Depends(ch_dep)):
    """Create or update a custom rule. Its embedded tests must pass, and `version` must be higher than the stored one."""
    try:
        r = parse_rule(body.yaml)
    except RuleError as e:
        raise _errors(e)
    key = rule_key(r.id)
    if key in builtin():
        raise HTTPException(409, f"{r.id} is a built-in rule; copy it under a new id to customise it (or tune its threshold)")
    res = await run_tests(ch, r)
    failed = [x for x in res if not x["passed"]]
    if failed:
        raise HTTPException(422, {"message": "embedded tests failed", "results": res})
    ar = (await _rows(s)).get(key)
    now = datetime.now(timezone.utc)
    entry = {"version": r.version, "sha256": sha256(body.yaml)[:16], "by": user.username, "at": now.isoformat(), "yaml": body.yaml}
    if ar is None:
        ar = AlertRule(key=key, name=f"{r.id} {r.name}", description=r.description.strip(), severity=r.severity, enabled=r.status == "enabled",
                       mitre=r.mitre_dict(), params={"yaml": body.yaml, "threshold": r.detection.condition.threshold,
                                                     "interval_minutes": max(1, min(60, r.detection.condition.timeframe // 60)), "history": [entry]})
        s.add(ar)
        action = "yaml_rule_create"
    else:
        old = parse_rule(ar.params["yaml"]).version if ar.params.get("yaml") else 0
        if r.version <= old:
            raise HTTPException(409, f"version must be higher than the stored version {old}")
        ar.name, ar.description, ar.mitre = f"{r.id} {r.name}", r.description.strip(), r.mitre_dict()
        ar.params = {**ar.params, "yaml": body.yaml, "threshold": r.detection.condition.threshold,
                     "history": ([entry] + list(ar.params.get("history", [])))[:HISTORY]}
        action = "yaml_rule_update"
    await s.commit()
    await audit(s, request, user.username, action, key, {"version": r.version, "sha256": entry["sha256"]})
    await s.commit()
    return _row(r, body.yaml, "custom", ar, full=True)


@router.post("/{key}/rollback/{version}")
async def rollback(key: str, version: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    """Restore an earlier version of a custom rule as a new (higher) version."""
    ar = (await _rows(s)).get(key)
    if ar is None or key in builtin():
        raise HTTPException(404, "custom rule not found")
    hist = ar.params.get("history", [])
    target = next((h for h in hist if h["version"] == version), None)
    if target is None:
        raise HTTPException(404, "version not found")
    current = max(h["version"] for h in hist)
    text = target["yaml"]
    import re
    text = re.sub(r"(?m)^version:\s*\d+\s*$", f"version: {current + 1}", text, count=1)
    r = parse_rule(text)
    entry = {"version": r.version, "sha256": sha256(text)[:16], "by": user.username, "at": datetime.now(timezone.utc).isoformat(), "yaml": text,
             "rolled_back_to": version}
    ar.params = {**ar.params, "yaml": text, "history": ([entry] + hist)[:HISTORY]}
    await s.commit()
    await audit(s, request, user.username, "yaml_rule_rollback", key, {"to": version, "version": r.version})
    await s.commit()
    return _row(r, text, "custom", ar, full=True)


@router.delete("/{key}")
async def delete_custom(key: str, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    if key in builtin():
        raise HTTPException(409, "built-in rules cannot be deleted; disable them instead")
    ar = (await _rows(s)).get(key)
    if ar is None:
        raise HTTPException(404, "custom rule not found")
    await s.delete(ar)
    await s.commit()
    await audit(s, request, user.username, "yaml_rule_delete", key)
    await s.commit()
    return {"ok": True}
