"""Next-gen features end to end (embedded ClickHouse + SQLite + mocked HTTP). SYNTHETIC TEST FIXTURES."""
from datetime import datetime, timedelta, timezone

import httpx
import pytest_asyncio
import respx
from sqlalchemy import select

from app.alerts.engine import ensure_default_rules, run_rules
from app.analytics import queries as Q
from app.analytics.filters import EventFilter
from app.config import get_settings
from app.db.models import (Alert, AlertRule, Asset, Firewall, Incident, NotificationChannel, NotificationOutbox, NotificationRule,
                           TiFeed, TiIndicator, User)
from app.enrich.enricher import Enricher
from app.enrich.feeds import ensure_default_feeds, fetch_feed
from app.enrich.geo import GeoResolver
from app.ingest.normalize import normalize
from app.ingest.pipeline import DeviceRegistry, EventSink
from app.main import create_app
from app.notify import process_outbox, seal
from app.security import hash_password

from .test_storage_analytics import FW, _load, traffic

NOW = lambda: datetime.now(timezone.utc)  # noqa: E731


async def only(db, *keys, **params):
    await ensure_default_rules(db)
    for r in (await db.execute(select(AlertRule))).scalars():
        r.enabled = r.key in keys
        if r.key in params:
            r.params = {**r.params, **params[r.key]}
    await db.commit()


def ev(rec, fw=FW):
    return normalize(rec, source="syslog", firewall=fw)


# ------------------------------------------------------------------ query language on real data
async def test_ql_filters_events(clean_ch):
    await _load(clean_ch, [traffic(1, src="10.0.0.1", dport=445, action="deny"), traffic(2, src="10.0.0.2", dport=445),
                           traffic(3, src="192.168.1.5", dport=22, action="deny"), traffic(4, src="10.0.0.3", dport=80, sent=5000)])
    async def n(q):
        return (await Q.list_events(clean_ch, EventFilter(range="1h", ql=q)))["total"]
    assert await n("src_ip:10.0.0.0/8 AND action:deny AND dst_port:445") == 1
    assert await n("dst_port:445 OR dst_port:22") == 3
    assert await n("NOT src:10.0.0.0/8") == 1
    assert await n("port:1-100 bytes>=5000") == 1  # only the port-80 record (5000 sent + 200 rcvd)
    assert await n("-action:deny dst_port:445") == 1


# ------------------------------------------------------------------ threat intel → alert → incident → notification
async def test_threat_intel_end_to_end(db, clean_ch):
    await ensure_default_feeds(db)
    manual = (await db.execute(select(TiFeed).where(TiFeed.name == "Manual IOCs"))).scalar_one()
    db.add(TiIndicator(feed_id=manual.id, indicator="198.51.100.66", type="ip"))
    ch_ = NotificationChannel(name="soc-slack", type="slack", config={}, secret_ciphertext=seal({"url": "https://hooks.slack.test/x"}))
    db.add(ch_)
    await db.commit()
    db.add(NotificationRule(name="high+", channel_id=ch_.id, event_types=["alert.created", "incident.created"], min_severity="high"))
    await db.commit()
    enr = Enricher(geo=GeoResolver(None))
    await enr.refresh_ti(force=True)
    reg = DeviceRegistry()
    reg.load([FW])
    sink = EventSink(clean_ch, reg, enricher=enr)
    ts = int((NOW() - timedelta(minutes=2)).timestamp() * 1e9)
    for i in range(3):
        sink.add_fields({"type": "traffic", "subtype": "forward", "devid": FW["serial"], "eventtime": str(ts + i), "logid": "13",
                         "srcip": "10.0.0.9", "dstip": "198.51.100.66", "dstport": "8443", "proto": "6", "action": "close",
                         "sessionid": str(70 + i)}, source="syslog", raw=None)
    await sink.flush()
    assert clean_ch.query("SELECT count() AS n FROM events WHERE ti_match = '198.51.100.66'")[0]["n"] == 3
    await only(db, "ti_match")
    res = await run_rules(clean_ch, db)
    assert res["ti_match"]["created"] == 1
    a = (await db.execute(select(Alert))).scalar_one()
    assert a.severity == "high" and a.mitre["tactic"] == "TA0011" and a.incident_id
    inc = await db.get(Incident, a.incident_id)
    assert inc.entity == "10.0.0.9" and inc.status == "open" and inc.sla_ack_due is not None
    outbox = (await db.execute(select(NotificationOutbox))).scalars().all()
    assert {o.event_type for o in outbox} == {"alert.created", "incident.created"}
    with respx.mock:
        route = respx.post("https://hooks.slack.test/x").mock(return_value=httpx.Response(200, text="ok"))
        stats = await process_outbox(db)
    assert stats["sent"] == 2 and route.call_count == 2
    s = await Q.list_events(clean_ch, EventFilter(range="1h", ql="ti:*"))
    assert s["total"] == 3


# ------------------------------------------------------------------ behaviour rules
async def test_beaconing_detected_and_irregular_ignored(db, clean_ch):
    await only(db, "beaconing", beaconing={"min_connections": 20, "exclude_ports": [53]})
    base = NOW() - timedelta(hours=2)
    regular = [traffic(i, src="10.0.0.7", dst="1.0.0.50", dport=8443, ts=base + timedelta(seconds=60 * i)) for i in range(40)]
    import random
    rnd = random.Random(3)
    irregular = [traffic(500 + i, src="10.0.0.8", dst="1.0.0.51", dport=8443, ts=base + timedelta(seconds=rnd.randint(0, 6000))) for i in range(40)]
    await _load(clean_ch, regular + irregular)
    res = await run_rules(clean_ch, db, correlate=False)
    assert res["beaconing"]["created"] == 1
    a = (await db.execute(select(Alert))).scalar_one()
    assert a.src_ip == "10.0.0.7" and abs(a.evidence["mean_interval_s"] - 60) < 1


async def test_volume_baseline_uses_hourly_rollup(db, clean_ch):
    await only(db, "volume_baseline", volume_baseline={"min_history_hours": 3, "min_sent_bytes": 1000, "factor": 5})
    hour0 = NOW().replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
    hist = [traffic(i, src="10.0.0.20", dst="1.0.0.9", sent=100, ts=hour0 - timedelta(hours=h + 1, minutes=5)) for i, h in enumerate(range(10))]
    spike = [traffic(100 + i, src="10.0.0.20", dst="1.0.0.9", sent=10_000, ts=hour0 + timedelta(minutes=10 + i)) for i in range(3)]
    await _load(clean_ch, hist + spike)
    assert clean_ch.query("SELECT count() AS n FROM src_hourly")[0]["n"] >= 10  # populated by the materialized view
    res = await run_rules(clean_ch, db, correlate=False)
    assert res["volume_baseline"]["created"] == 1


async def test_vpn_bruteforce_and_impossible_travel(db, clean_ch):
    await only(db, "vpn_bruteforce", "impossible_travel", vpn_bruteforce={"min_failures": 5})
    reg = DeviceRegistry()
    reg.load([FW])
    sink = EventSink(clean_ch, reg)
    t = NOW() - timedelta(minutes=14)  # failures land inside the 15-minute brute-force window

    def line(i, action, user, ip, country, minutes):
        ns = int((t + timedelta(minutes=minutes)).timestamp() * 1e9) + i
        return (f'date=2026-10-23 time=10:00:00 devname="FGT-TEST-01" devid="{FW["serial"]}" eventtime={ns} logid="0101039426" '
                f'type="event" subtype="vpn" level="notice" vd="root" action="{action}" tunneltype="ssl-tunnel" remip={ip} '
                f'srccountry="{country}" user="{user}" msg="vpn"')
    for i in range(6):
        sink.add_line(line(i, "ssl-login-fail", f"u{i}", "1.0.0.200", "Netherlands", 1), source="syslog")
    sink.add_line(line(20, "tunnel-up", "rahul", "1.0.0.10", "India", 2), source="syslog")
    sink.add_line(line(21, "tunnel-up", "rahul", "1.0.0.20", "Netherlands", 12), source="syslog")
    await sink.flush()
    res = await run_rules(clean_ch, db, correlate=False)
    assert res["vpn_bruteforce"]["created"] == 1 and res["impossible_travel"]["created"] == 1
    travel = (await db.execute(select(Alert).where(Alert.rule_key == "impossible_travel"))).scalar_one()
    assert "rahul" in travel.explanation and "approximate" in travel.explanation


# ------------------------------------------------------------------ assets + criticality + correlation
async def test_assets_learned_and_criticality_raises_severity(db, clean_ch):
    await _load(clean_ch, [{**traffic(1, src="10.0.0.30"), "srcname": "fin-db-01", "srcmac": "AA:BB:CC:00:11:22", "osname": "Linux", "user": "svc"}])
    from app.assets import learn_assets
    assert await learn_assets(db, clean_ch, NOW() - timedelta(hours=1)) == 1
    a = (await db.execute(select(Asset))).scalar_one()
    assert a.hostname == "fin-db-01" and a.mac == "aa:bb:cc:00:11:22" and a.last_user == "svc"
    a.criticality = "critical"
    await db.commit()
    await only(db, "port_scan", port_scan={"min_unique_ports": 5})
    await _load(clean_ch, [traffic(10 + i, src="10.0.0.30", dport=1000 + i, action="deny") for i in range(6)])
    await run_rules(clean_ch, db, correlate=False)
    al = (await db.execute(select(Alert))).scalar_one()
    assert al.base_severity == "high" and al.severity == "critical" and al.asset_criticality == "critical"


async def test_multi_tactic_correlation_escalates_and_closure_feeds_fp_rate(db, clean_ch):
    await only(db, "port_scan", "denied_burst", "host_sweep", port_scan={"min_unique_ports": 5}, denied_burst={"min_denied": 5},
               host_sweep={"min_unique_dsts": 5})
    recs = [traffic(i, src="10.0.0.40", dst=f"1.0.1.{i}", dport=2000 + i, action="deny") for i in range(8)]
    await _load(clean_ch, recs)
    await run_rules(clean_ch, db)
    incs = (await db.execute(select(Incident))).scalars().all()
    assert len(incs) == 1  # three alerts, one entity → one incident
    inc = incs[0]
    assert inc.alert_count == 3 and set(inc.tactics) == {"TA0007", "TA0043"} and inc.severity == "critical"  # high + 2 tactics
    from app.incidents import set_status
    await set_status(db, inc, "closed", "analyst1", "false_positive")
    await db.commit()
    assert all(a.disposition == "false_positive" for a in (await db.execute(select(Alert))).scalars())


async def test_single_low_alert_stays_standalone(db, clean_ch):
    await only(db, "nxdomain_burst", nxdomain_burst={"min_nxdomain": 2})
    t = NOW() - timedelta(minutes=2)
    await _load(clean_ch, [{"type": "utm", "subtype": "dns", "srcip": "10.0.0.50", "rcode": "NXDOMAIN", "qname": f"x{i}.example.test",
                            "eventtime": str(int(t.timestamp() * 1e9) + i)} for i in range(3)])
    await run_rules(clean_ch, db)
    assert (await db.execute(select(Incident))).scalars().all() == []


# ------------------------------------------------------------------ notifications delivery
async def test_outbox_retry_quiet_hours_and_dedupe(db):
    from app.notify import enqueue
    c = NotificationChannel(name="hook", type="webhook", config={}, secret_ciphertext=seal({"url": "https://hook.test/in", "hmac_secret": "s"}))
    db.add(c)
    await db.commit()
    r = NotificationRule(name="all", channel_id=c.id, event_types=["alert.created"], min_severity="low", dedupe_minutes=30,
                         quiet_start="00:00", quiet_end="23:59", quiet_tz="UTC")
    db.add(r)
    await db.commit()
    await enqueue(db, "alert.created", {"title": "t"}, severity="high", dedupe_key="k1")      # quiet hours → suppressed
    await enqueue(db, "alert.created", {"title": "t"}, severity="critical", dedupe_key="k2")  # critical bypasses quiet hours
    await enqueue(db, "alert.created", {"title": "t"}, severity="critical", dedupe_key="k2")  # duplicate → suppressed
    await db.commit()
    rows = (await db.execute(select(NotificationOutbox).order_by(NotificationOutbox.id))).scalars().all()
    assert [o.status for o in rows] == ["suppressed", "pending", "suppressed"]
    with respx.mock:
        route = respx.post("https://hook.test/in").mock(return_value=httpx.Response(500))
        stats = await process_outbox(db)
    assert stats["retry"] == 1 and route.calls[0].request.headers["X-SIEM-Signature"].startswith("sha256=")
    o = rows[1]
    await db.refresh(o)
    nxt = o.next_attempt if o.next_attempt.tzinfo else o.next_attempt.replace(tzinfo=timezone.utc)  # SQLite returns naive
    assert o.status == "pending" and o.attempts == 1 and nxt > NOW()


# ------------------------------------------------------------------ feeds
async def test_feed_fetch_https_only_and_keeps_old_on_failure(db):
    f = TiFeed(name="t", url="https://feed.test/list.txt", kind="ip", category="c2", enabled=True)
    db.add(f)
    await db.commit()
    ok = httpx.MockTransport(lambda req: httpx.Response(200, text="# list\n1.0.0.7\n1.0.0.8\n"))
    assert (await fetch_feed(db, f, ok)).startswith("ok: 2")
    bad = httpx.MockTransport(lambda req: httpx.Response(503))
    assert (await fetch_feed(db, f, bad)).startswith("error")
    assert f.indicator_count == 2 and len((await db.execute(select(TiIndicator))).scalars().all()) == 2  # previous list kept
    f.url = "http://insecure.test/list"
    assert "only https" in await fetch_feed(db, f, ok)


# ------------------------------------------------------------------ drift
class FakeClient:
    def __init__(self, data):
        self.data = data

    async def get(self, path, params=None):
        from app.fortigate.client import FortiGateNotSupported
        for k, v in self.data.items():
            if path.endswith(k):
                return {"results": v}
        raise FortiGateNotSupported(path)


async def test_drift_snapshots_alert_only_on_risky_change(db, clean_ch):
    from app.drift import snapshot_firewall
    from app.db.models import ConfigSnapshot
    await only(db, "risky_config_change")
    fw = Firewall(name="fw-d", host="10.9.9.9", tags=[], syslog_source_ips=[], capabilities={}, health={}, api_log_cursor={})
    db.add(fw)
    await db.commit()
    data = {"system/interface": [{"name": "wan1", "role": "wan", "allowaccess": "ping"}], "system/admin": [{"name": "admin", "accprofile": "super_admin",
            "trusthost1": "10.0.0.0 255.0.0.0", "two-factor": "fortitoken"}], "system/global": {"strong-crypto": "enable"}}
    assert (await snapshot_firewall(db, FakeClient(data), fw, "root")) is not None
    assert (await snapshot_firewall(db, FakeClient(data), fw, "root")) is None  # unchanged → no new snapshot
    data["system/interface"] = [{"name": "wan1", "role": "wan", "allowaccess": "ping https ssh"}]
    snap = await snapshot_firewall(db, FakeClient(data), fw, "root")
    assert snap.changes and any("WAN interface wan1" in r["title"] for r in snap.risks)
    alerts = (await db.execute(select(Alert).where(Alert.rule_key == "risky_config_change"))).scalars().all()
    assert len(alerts) == 1 and alerts[0].severity == "high"
    assert len((await db.execute(select(ConfigSnapshot))).scalars().all()) == 2


# ------------------------------------------------------------------ API
PW = "correct-horse-battery-staple"


@pytest_asyncio.fixture
async def api(db, clean_ch):
    get_settings.cache_clear()
    db.add_all([User(username="admin1", password_hash=hash_password(PW), role="admin"),
                User(username="analyst1", password_hash=hash_password(PW), role="analyst")])
    await db.commit()
    from app.bootstrap import seed
    await seed(db)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app()), base_url="http://test") as c:
        yield c


async def login(c, u):
    return {"X-CSRF-Token": (await c.post("/api/auth/login", json={"username": u, "password": PW})).json()["csrf_token"]}


async def test_api_rbac_secrets_and_validation(api, db, clean_ch):
    h = await login(api, "analyst1")
    assert (await api.post("/api/notifications/channels", json={"name": "x", "type": "slack", "url": "https://h/x"}, headers=h)).status_code == 403
    assert (await api.post("/api/ti/manual", json={"indicators": "1.0.0.1"}, headers=h)).status_code == 403
    assert (await api.post("/api/searches", json={"name": "s", "query": "foo:1"}, headers=h)).status_code == 422
    assert (await api.post("/api/searches", json={"name": "s", "query": "action:deny", "schedule": "hourly"}, headers=h)).status_code == 403
    r = await api.post("/api/searches", json={"name": "denies", "query": "action:deny"}, headers=h)
    assert r.status_code == 201
    assert (await api.post("/api/ql/validate", json={"query": "src_ip:1.2.3"}, headers=h)).json()["valid"] is False
    h = await login(api, "admin1")
    r = await api.post("/api/notifications/channels", json={"name": "slack", "type": "slack", "url": "https://hooks.slack.test/secret-path"}, headers=h)
    assert r.status_code == 201 and "secret-path" not in r.text and r.json()["has_secret"] is True
    assert "secret-path" not in (await api.get("/api/notifications/channels")).text
    r = await api.post("/api/ti/manual", json={"indicators": "1.0.0.1, evil.example.org 1.0.2.0/24 nonsense", "note": "case 7"}, headers=h)
    assert r.json()["added"] == 3
    assert {x["type"] for x in (await api.get("/api/ti/manual")).json()} == {"ip", "domain", "cidr"}
    assert (await api.put("/api/assets/10.0.0.77", json={"criticality": "critical", "owner": "finance"}, headers=h)).json()["source"] == "manual"
    comp = (await api.get("/api/compliance")).json()
    assert comp["counts"]["manual"] >= 2 and "not an audit" in comp["disclaimer"]
    assert (await api.get("/api/compliance/export.csv")).text.startswith("framework,control")
    inc = Incident(title="t", entity_type="ip", entity="10.0.0.1", status="open", created_at=datetime.now(timezone.utc), evidence=[])
    db.add(inc)
    await db.commit()
    assert (await api.patch(f"/api/incidents/{inc.id}", json={"status": "closed"}, headers=h)).status_code == 422  # needs a reason
    r = await api.patch(f"/api/incidents/{inc.id}", json={"status": "closed", "closure_reason": "benign"}, headers=h)
    assert r.status_code == 200 and r.json()["status"] == "closed"
    d = (await api.get(f"/api/incidents/{inc.id}")).json()
    assert any("closed" in t["title"] for t in d["timeline"])
    rep = await api.post("/api/reports", json={"name": "Daily SOC", "period": "daily"}, headers=h)
    run = await api.post(f"/api/reports/{rep.json()['id']}/run", headers=h)
    html_r = await api.get(f"/api/reports/runs/{run.json()['id']}.html")
    assert html_r.status_code == 200 and "<h2>Summary</h2>" in html_r.text and "Compliance evidence" in html_r.text
    assert html_r.headers["content-security-policy"].startswith("default-src 'none'")
    assert (await api.get("/api/events?range=1h&ql=src_ip:999")).status_code == 422


async def test_retired_builtin_feed_is_disabled(db):
    db.add(TiFeed(name="abuse.ch URLhaus (malware hosts)", url="https://urlhaus.abuse.ch/downloads/hostfile/", kind="domain",
                  category="malware", enabled=True, builtin=True))
    await db.commit()
    await ensure_default_feeds(db)
    f = (await db.execute(select(TiFeed).where(TiFeed.name == "abuse.ch URLhaus (malware hosts)"))).scalar_one()
    assert f.enabled is False and "410" in f.last_status
    names = {x.name for x in (await db.execute(select(TiFeed))).scalars()}
    assert "CERT Polska malicious domains" in names and "IPsum level 3 (aggregated malicious IPs)" in names


async def test_large_feed_bulk_insert(db):
    f = TiFeed(name="big", url="https://feed.test/big", kind="domain", category="c", enabled=True)
    db.add(f)
    await db.commit()
    body = "\n".join(f"host{i}.bad-example.org" for i in range(20000))
    assert (await fetch_feed(db, f, httpx.MockTransport(lambda r: httpx.Response(200, text=body)))).startswith("ok: 20000")
