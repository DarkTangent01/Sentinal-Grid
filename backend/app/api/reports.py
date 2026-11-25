"""Scheduled reports (shared service: each product app mounts it and offers the sections its product registered)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.ch import ClickHouse
from ..db.models import ReportDefinition, ReportRun, User
from ..db.pg import get_session
from ..reports import SECTIONS, run_definition
from .deps import audit, ch_dep, current_user, iso, require_admin

router = APIRouter(prefix="/api", tags=["reports"])


class ReportIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    period: str = Field("daily", pattern=r"^(daily|weekly|monthly)$")
    sections: list[str] = Field(default_factory=lambda: list(SECTIONS))
    channel_ids: list[int] = Field(default_factory=list)
    enabled: bool = True
    send_hour: int = Field(7, ge=0, le=23)
    tz: str = Field("UTC", max_length=64)


def rd_out(d: ReportDefinition) -> dict:
    return {"id": d.id, "name": d.name, "period": d.period, "sections": d.sections, "channel_ids": d.channel_ids, "enabled": d.enabled,
            "send_hour": d.send_hour, "tz": d.tz, "last_run": iso(d.last_run), "created_by": d.created_by}


@router.get("/reports")
async def list_reports(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    defs = (await s.execute(select(ReportDefinition).order_by(ReportDefinition.name))).scalars()
    runs = (await s.execute(select(ReportRun.id, ReportRun.name, ReportRun.generated_at, ReportRun.period_start, ReportRun.period_end,
                                   ReportRun.summary, ReportRun.pdf.is_not(None).label("has_pdf"))
                            .order_by(ReportRun.generated_at.desc()).limit(50))).all()
    return {"definitions": [rd_out(d) for d in defs], "sections": SECTIONS,
            "runs": [{"id": r.id, "name": r.name, "generated_at": iso(r.generated_at), "period_start": iso(r.period_start),
                      "period_end": iso(r.period_end), "summary": r.summary, "has_pdf": bool(r.has_pdf)} for r in runs]}


async def _save_def(d: ReportDefinition, body: ReportIn):
    bad = set(body.sections) - set(SECTIONS)
    if bad:
        raise HTTPException(422, f"unknown sections {sorted(bad)}")
    for k, v in body.model_dump().items():
        setattr(d, k, v)


@router.post("/reports", status_code=201)
async def create_report(body: ReportIn, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    d = ReportDefinition(created_by=admin.username)
    await _save_def(d, body)
    s.add(d)
    await s.commit()
    await audit(s, request, admin.username, "report_create", body.name)
    return rd_out(d)


@router.put("/reports/{rid}")
async def update_report(rid: int, body: ReportIn, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    d = await s.get(ReportDefinition, rid)
    if not d:
        raise HTTPException(404, "not found")
    await _save_def(d, body)
    await s.commit()
    await audit(s, request, admin.username, "report_update", body.name)
    return rd_out(d)


@router.delete("/reports/{rid}")
async def delete_report(rid: int, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    d = await s.get(ReportDefinition, rid)
    if not d:
        raise HTTPException(404, "not found")
    await s.delete(d)
    await s.commit()
    await audit(s, request, admin.username, "report_delete", d.name)
    return {"ok": True}


@router.post("/reports/{rid}/run")
async def run_report(rid: int, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session),
                     ch: ClickHouse = Depends(ch_dep)):
    d = await s.get(ReportDefinition, rid)
    if not d:
        raise HTTPException(404, "not found")
    run = await run_definition(s, ch, d)
    await audit(s, request, admin.username, "report_run", d.name)
    return {"id": run.id}


@router.get("/reports/runs/{run_id}.pdf")
async def report_pdf(run_id: int, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    from fastapi.responses import Response
    r = await s.get(ReportRun, run_id)
    if not r or not r.pdf:
        raise HTTPException(404, "no PDF for this report run")
    return Response(r.pdf, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="report-{run_id}.pdf"'})


@router.get("/reports/runs/{run_id}.html", response_class=HTMLResponse)
async def report_html(run_id: int, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    r = await s.get(ReportRun, run_id)
    if not r:
        raise HTTPException(404, "not found")
    # static document: no scripts allowed
    return HTMLResponse(r.html, headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})
