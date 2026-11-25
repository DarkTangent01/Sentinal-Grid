"""Scheduled reports: NMS sections, PDF output (WeasyPrint, no remote fetch) and the PDF as an email attachment."""
from datetime import datetime, timedelta, timezone

import pytest

from app import reports as R
from app.nms.report_sections import NMS_SECTIONS
from app.db.models import (Alert, DeviceConfigSnapshot, NotificationChannel, ReportDefinition, ReportRun, Switch, WirelessRogue)
from app.notify import build_request

from .test_api import api  # noqa: F401  (fixture)


def _pdf_ok() -> bool:
    return (R.pdf_of("<p>x</p>") or b"").startswith(b"%PDF")


async def _data(db):
    now = datetime.now(timezone.utc)
    sw = Switch(name="ACC1", address="192.0.2.1", monitoring="active", state="up", capabilities={}, group_state={}, health={}, thresholds={})
    wlc = Switch(name="WLC", address="192.0.2.9", role="wlc", vendor="cisco", monitoring="active", state="up", capabilities={}, group_state={},
                 health={}, thresholds={})
    db.add_all([sw, wlc])
    await db.flush()
    db.add_all([DeviceConfigSnapshot(switch_id=sw.id, taken_at=now - timedelta(hours=3), config_hash="a", text="x", added=3, removed=1, trigger="trap"),
                WirelessRogue(wlc_id=wlc.id, mac="00:de:ad:00:00:01", ssid="CORP", spoofs_ssid=True, rssi_dbm=-60, present=True,
                              first_seen=now - timedelta(hours=5), last_seen=now),
                Alert(rule_key="switch_port_down", name="Switch port down", severity="medium", status="new", group_key="1:5",
                      first_seen=now - timedelta(hours=2), last_seen=now, event_count=1, explanation="x", evidence={}, event_filter={})])
    await db.commit()
    return now


async def test_nms_sections_render(db, ch):
    now = await _data(db)
    doc, summary = await R.generate(db, ch, "Weekly NMS", now - timedelta(days=7), now, NMS_SECTIONS)
    for title in ("Network availability", "Capacity risks", "Network alerts (1)", "Configuration changes (1)", "Rogue access points (1 flagged of 1 heard)"):
        assert title in doc, title
    assert summary["config_changes"] == 1 and summary["rogue_aps"] == {"heard": 1, "flagged": 1} and summary["nms_alerts"] == 1
    assert "spoofs our SSID" in doc


def test_pdf_never_fetches_remote_resources(monkeypatch):
    if not _pdf_ok():
        pytest.skip("WeasyPrint's system libraries (pango) are not available here")
    asked = []
    real = R._no_fetch

    def spy(url, *a, **k):
        asked.append(url)
        return real(url, *a, **k)
    monkeypatch.setattr(R, "_no_fetch", spy)
    pdf = R.pdf_of('<h1>Report</h1><img src="http://198.51.100.7/beacon.png"><link rel="stylesheet" href="https://example.com/x.css">')
    assert pdf.startswith(b"%PDF") and asked                      # asked for, refused, and the report still rendered


async def test_run_stores_pdf_and_emails_it(api, db, ch):  # noqa: F811
    from .test_iac import As
    await _data(db)
    chan = NotificationChannel(name="ops", type="email", config={"to": ["noc@example.com"], "from_addr": "siem@example.com", "host": "smtp.example.com"},
                               enabled=True)
    db.add(chan)
    await db.flush()
    d = ReportDefinition(name="Weekly NMS", period="weekly", sections=NMS_SECTIONS, channel_ids=[chan.id], enabled=True, send_hour=8, tz="UTC", created_by="admin1")
    db.add(d)
    await db.commit()
    run = await R.run_definition(db, ch, d)
    from sqlalchemy import select

    from app.db.models import NotificationOutbox
    out = (await db.execute(select(NotificationOutbox))).scalars().one()
    if _pdf_ok():
        assert run.pdf.startswith(b"%PDF")
        msg = build_request(chan, out.payload, {})["message"]
        (att,) = list(msg.iter_attachments())
        assert att.get_content_type() == "application/pdf" and att.get_filename().endswith(".pdf")
        A = await As.login(api, "admin1")
        r = await A.get(f"/api/reports/runs/{run.id}.pdf")
        assert r.status_code == 200 and r.content.startswith(b"%PDF")
    else:
        assert run.pdf is None and "attachments" not in out.payload        # HTML report still delivered
    assert (await db.get(ReportRun, run.id)).html.startswith("<!doctype html>")
