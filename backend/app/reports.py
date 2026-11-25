"""Scheduled HTML reports (printable; emailed through notification channels).

Report framework: renders the sections the products register (analytics/report_sections.py for Sentinel Grid,
nms/report_sections.py for Sentinel NMS); it holds no product sections itself."""
from __future__ import annotations

import html as h
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .db.ch import ClickHouse
from .db.models import ReportDefinition, ReportRun

SECTIONS: list[str] = []   # filled by the products' registrations, in registration order
RENDERERS: dict = {}       # section key -> async (s, ch, start, end, sections, summary) -> list of HTML parts
PRODUCT_OF: dict[str, str] = {}
PDF_MAX_BYTES = 8 * 1024 * 1024


def register(product: str, renderers: dict) -> None:
    for key, fn in renderers.items():
        if key not in RENDERERS:
            SECTIONS.append(key)
        RENDERERS[key] = fn
        PRODUCT_OF[key] = product


def _no_fetch(url: str, *a, **k):
    """WeasyPrint URL fetcher: reports are self-contained; nothing (images, fonts, stylesheets) is fetched from anywhere."""
    raise ValueError(f"external resource refused: {url[:80]}")


def pdf_of(doc: str) -> bytes | None:
    """The report as PDF (WeasyPrint), or None when the PDF engine is unavailable; the HTML report is never blocked by it."""
    try:
        from weasyprint import HTML
        return HTML(string=doc, url_fetcher=_no_fetch).write_pdf()
    except Exception:
        import logging
        logging.getLogger("reports").warning("PDF rendering failed; the report is kept as HTML only", exc_info=True)
        return None


def _fmt(n) -> str:
    try:
        return f"{int(n):,}"
    except (TypeError, ValueError):
        return str(n)


def _table(headers: list[str], rows: list[list]) -> str:
    if not rows:
        return "<p class='muted'>No data for this period.</p>"
    head = "".join(f"<th>{h.escape(x)}</th>" for x in headers)
    body = "".join("<tr>" + "".join(f"<td>{h.escape(str(c))}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


async def generate(s: AsyncSession, ch: ClickHouse, name: str, start: datetime, end: datetime, sections: list[str]) -> tuple[str, dict]:
    parts, summary, done = [], {}, set()
    for key in SECTIONS:   # registration order; a renderer shared by several keys runs once
        fn = RENDERERS[key]
        if key in sections and fn not in done:
            done.add(fn)
            parts += await fn(s, ch, start, end, sections, summary)
    doc = f"""<!doctype html><html><head><meta charset="utf-8"><title>{h.escape(name)}</title><style>
body{{font:13px/1.45 -apple-system,Segoe UI,Roboto,sans-serif;color:#0f172a;margin:24px;max-width:1000px}}
h1{{font-size:20px;margin:0}} h2{{font-size:15px;margin:22px 0 6px;border-bottom:1px solid #e2e8f0;padding-bottom:4px}}
table{{border-collapse:collapse;width:100%}} th,td{{text-align:left;padding:4px 8px;border-bottom:1px solid #eef2f6;vertical-align:top}}
th{{font-size:11px;text-transform:uppercase;color:#475569}} .muted{{color:#64748b}} @media print{{body{{margin:0}}}}
</style></head><body><h1>{h.escape(name)}</h1><p class="muted">Sentinel Grid report · {start:%Y-%m-%d %H:%M} – {end:%Y-%m-%d %H:%M} UTC ·
generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC</p>{''.join(parts)}</body></html>"""
    return doc, summary


async def run_definition(s: AsyncSession, ch: ClickHouse, d: ReportDefinition, now: datetime | None = None) -> ReportRun:
    now = now or datetime.now(timezone.utc)
    start, end = period_window(d.period, now)
    html_doc, summary = await generate(s, ch, d.name, start, end, d.sections or SECTIONS)
    pdf = pdf_of(html_doc)
    run = ReportRun(definition_id=d.id, name=d.name, generated_at=now, period_start=start, period_end=end, html=html_doc, summary=summary, pdf=pdf)
    s.add(run)
    d.last_run = now
    await s.flush()
    if d.channel_ids:
        from .notify import _link, enqueue
        await enqueue(s, "report.ready", {"title": f"Report: {d.name}", "subject": f"Sentinel Grid report: {d.name}",
                                          "text": f"{d.period.title()} report generated.", "html": html_doc,
                                          "url": _link(f"/api/reports/runs/{run.id}.html"),
                                          **({"attachments": [{"filename": f"{d.name}-{now:%Y%m%d}.pdf".replace("/", "_"), "mime": "application/pdf",
                                                               "content_b64": __import__("base64").b64encode(pdf).decode()}]}
                                             if pdf and len(pdf) <= PDF_MAX_BYTES else {})},
                      severity="informational", dedupe_key=f"report:{run.id}", channel_ids=list(d.channel_ids))
    await s.commit()
    return run


def period_window(period: str, now: datetime) -> tuple[datetime, datetime]:
    """daily / weekly: the trailing 1 or 7 days. monthly: the previous calendar month (UTC), as SLA reports need."""
    if period == "monthly":
        end = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        start = (end - timedelta(days=1)).replace(day=1)
        return start, end
    return now - timedelta(days=7 if period == "weekly" else 1), now


def is_due(d: ReportDefinition, now: datetime) -> bool:
    try:
        local = now.astimezone(ZoneInfo(d.tz or "UTC"))
    except (KeyError, ValueError):
        local = now
    if local.hour != d.send_hour or (d.period == "monthly" and local.day != 1):
        return False
    last = d.last_run if d.last_run is None or d.last_run.tzinfo else d.last_run.replace(tzinfo=timezone.utc)
    gap = timedelta(days={"weekly": 7, "monthly": 27}.get(d.period, 1)) - timedelta(hours=1)
    return last is None or now - last >= gap


def runs_here(d: ReportDefinition, product: str) -> bool:
    """Which product process runs a definition when the products run apart (until definitions are split per product,
    phase 6): Sentinel NMS runs definitions made only of NMS sections; Sentinel Grid runs every other definition (with a
    mix, the NMS sections are left out of the Grid report). A process only knows its own product's sections, so each
    side decides from the sections it registered."""
    secs = d.sections or []
    if product == "nms":
        return bool(secs) and all(PRODUCT_OF.get(x) == "nms" for x in secs)
    return not secs or any(PRODUCT_OF.get(x) == "grid" for x in secs)


async def run_due(s: AsyncSession, ch: ClickHouse, now: datetime | None = None, product: str | None = None) -> dict:
    """product: run only that product's definitions (runs_here); None runs all (combined deployment)."""
    now = now or datetime.now(timezone.utc)
    out = {}
    for d in (await s.execute(select(ReportDefinition).where(ReportDefinition.enabled.is_(True)))).scalars().all():
        if product and not runs_here(d, product):
            continue
        if is_due(d, now):
            out[d.name] = (await run_definition(s, ch, d, now)).id
    return out
