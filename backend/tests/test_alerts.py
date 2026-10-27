from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.alerts.engine import ensure_default_rules, run_rules
from app.db.models import Alert, AlertRule, Suppression

from .test_storage_analytics import _load, traffic


async def _enable_only(db, key, **params):
    await ensure_default_rules(db)
    for r in (await db.execute(select(AlertRule))).scalars():
        r.enabled = r.key == key
        if r.key == key and params:
            r.params = {**r.params, **params}
    await db.commit()


async def test_port_scan_detection_and_grouping(clean_ch, db):
    await _enable_only(db, "port_scan", min_unique_ports=20)
    await _load(clean_ch, [traffic(i, src="10.9.9.9", dport=1000 + i, action="deny") for i in range(25)]
                + [traffic(500 + i, src="10.0.0.5", dport=443) for i in range(25)])
    res = await run_rules(clean_ch, db)
    assert res["port_scan"]["created"] == 1
    a = (await db.execute(select(Alert))).scalar_one()
    assert a.src_ip == "10.9.9.9" and a.status == "new" and "25 distinct destination ports" in a.explanation
    assert a.event_filter["src_ip"] == "10.9.9.9" and a.firewall_ids == [1] and a.sites == ["Lab"]
    # second evaluation updates the same grouped alert instead of flooding
    res = await run_rules(clean_ch, db)
    assert res["port_scan"] == {"created": 0, "updated": 1, "suppressed": 0}


async def test_below_threshold_no_alert(clean_ch, db):
    await _enable_only(db, "port_scan", min_unique_ports=50)
    await _load(clean_ch, [traffic(i, src="10.9.9.9", dport=1000 + i) for i in range(10)])
    assert (await run_rules(clean_ch, db))["port_scan"]["created"] == 0


async def test_suppression(clean_ch, db):
    await _enable_only(db, "denied_burst", min_denied=5)
    db.add(Suppression(rule_key="denied_burst", group_key="10.2.2.2", until=datetime.now(timezone.utc) + timedelta(hours=1),
                       created_by="test"))
    await db.commit()
    await _load(clean_ch, [traffic(i, src="10.2.2.2", action="deny") for i in range(10)])
    res = await run_rules(clean_ch, db)
    assert res["denied_burst"] == {"created": 0, "updated": 0, "suppressed": 1}


async def test_resolved_alert_reopens_as_new(clean_ch, db):
    await _enable_only(db, "denied_burst", min_denied=5)
    await _load(clean_ch, [traffic(i, src="10.3.3.3", action="deny") for i in range(10)])
    await run_rules(clean_ch, db)
    a = (await db.execute(select(Alert))).scalar_one()
    a.status = "resolved"
    await db.commit()
    assert (await run_rules(clean_ch, db))["denied_burst"]["created"] == 0  # same activity already resolved
    later = datetime.now(timezone.utc) - timedelta(seconds=5)
    await _load(clean_ch, [traffic(900 + i, src="10.3.3.3", action="deny", ts=later) for i in range(10)])
    assert (await run_rules(clean_ch, db))["denied_burst"]["created"] == 1


async def test_dns_tunnel_and_nxdomain(clean_ch, db):
    await _enable_only(db, "dns_tunnel", min_unique_names=5)
    from app.ingest.normalize import normalize
    from app.db.ch_schema import EVENT_COLUMNS
    now = datetime.now(timezone.utc) - timedelta(minutes=1)
    recs = [{"type": "utm", "subtype": "dns", "srcip": "10.4.4.4", "eventtime": str(int(now.timestamp() * 1e9) + i),
             "qname": f"{'x' * 10}{i}abcdefghijklmnopqrstuvwxyz0123456789qwertyuiopasdfghjkl.t.tunnel.example.net"} for i in range(8)]
    clean_ch.insert("events", [normalize(r, source="syslog", firewall={"id": 1, "name": "f", "site": "s"}) for r in recs], EVENT_COLUMNS)
    res = await run_rules(clean_ch, db)
    assert res["dns_tunnel"]["created"] == 1
    a = (await db.execute(select(Alert))).scalar_one()
    assert a.group_key == "10.4.4.4|example.net" or a.group_key.startswith("10.4.4.4|")


async def test_admin_login_fail_rule(clean_ch, db):
    await _enable_only(db, "admin_login_fail", min_failures=3)
    from app.ingest.pipeline import DeviceRegistry, EventSink
    from .conftest import fixture_lines
    reg = DeviceRegistry()
    reg.load([{"id": 1, "name": "FGT-TEST-01", "site": "Lab", "serial": "FGTEST0000000001"}])
    sink = EventSink(clean_ch, reg)
    base = fixture_lines()[4]
    now_ns = int((datetime.now(timezone.utc) - timedelta(minutes=1)).timestamp() * 1e9)
    for i in range(4):
        sink.add_line(base.replace("eventtime=1792577734000000000", f"eventtime={now_ns + i}"), source="syslog")
    await sink.flush()
    res = await run_rules(clean_ch, db)
    assert res["admin_login_fail"]["created"] == 1
