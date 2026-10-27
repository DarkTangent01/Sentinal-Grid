"""ISP / WAN link analytics from synthetic SD-WAN health-check syslog (real ingest path)."""
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.alerts.engine import ensure_default_rules, run_rules
from app.db.models import Alert, AlertRule, IspLink
from app.ingest.pipeline import EventSink
from app.isp import down_intervals, intersect, merge, report, subtract

from .test_api import api, login  # noqa: F401
from .test_storage_analytics import registry

NOW = datetime.now(timezone.utc).replace(microsecond=0)


_seq = iter(range(1, 10**9))


def line(ts: datetime, logid: str, body: str, level="notice") -> str:
    ns = int(ts.timestamp() * 1e9) + next(_seq)  # FortiGate eventtime is unique to the nanosecond
    return (f'<189>date={ts:%Y-%m-%d} time={ts:%H:%M:%S} devname="FGT-TEST-01" devid="FGTEST0000000001" eventtime={ns} tz="+0000" '
            f'logid="{logid}" type="event" subtype="sdwan" level="{level}" vd="root" {body}')


def sla(ts, iface, hc, lat=5.0, status="up"):
    return line(ts, "0113022925", f'logdesc="SDWAN SLA information" eventtype="SLA" healthcheck="{hc}" slatargetid=1 interface="{iface}" '
                f'status="{status}" latency="{lat}" jitter="0.5" packetloss="0.000" moscodec="g711" mosvalue="4.4" '
                f'inbandwidthused="40.00Mbps" outbandwidthused="2.50Mbps" slamap="0x1" msg="Health Check SLA status."', "information")


def state(ts, iface, hc, new):
    lid = "0113022931" if new == "dead" else "0113022933"
    old = "alive" if new == "dead" else "dead"
    return line(ts, lid, f'eventtype="Health Check" healthcheck="{hc}" interface="{iface}" probeproto="ping" oldvalue="{old}" '
                f'newvalue="{new}" msg="SD-WAN health-check member changed state."', "warning")


async def _ingest(ch):
    sink = EventSink(ch, registry())
    lines = []
    for m in range(0, 120, 2):  # SLA samples every 2 minutes for two hours
        t = NOW - timedelta(minutes=120 - m)
        lines += [sla(t, "port1", "DNS"), sla(t, "port1", "Web"),
                  sla(t, "port2", "DNS", lat=12.0, status="down" if t >= NOW - timedelta(minutes=5) else "up")]
    o = NOW - timedelta(minutes=90)  # full outage: both checks dead for 10 minutes
    lines += [state(o, "port1", "DNS", "dead"), state(o + timedelta(seconds=3), "port1", "Web", "dead"),
              state(o + timedelta(minutes=10), "port1", "DNS", "alive"), state(o + timedelta(minutes=10, seconds=2), "port1", "Web", "alive")]
    p = NOW - timedelta(minutes=60)  # partial: only the Web target fails
    lines += [state(p, "port1", "Web", "dead"), state(p + timedelta(minutes=5), "port1", "Web", "alive")]
    b = NOW - timedelta(minutes=30)  # blip: 20 seconds
    lines += [state(b, "port1", "DNS", "dead"), state(b, "port1", "Web", "dead"),
              state(b + timedelta(seconds=20), "port1", "DNS", "alive"), state(b + timedelta(seconds=20), "port1", "Web", "alive")]
    d = NOW - timedelta(minutes=5)  # port2 goes down and stays down
    lines += [state(d, "port2", "DNS", "dead")]
    lines += [line(NOW - timedelta(minutes=40), "0113022933", 'eventtype="SLA" healthcheck="DNS" interface="port1" status="up" latency="95.0" '
                   'metric="latency" msg="Health Check SLA status. SLA failed due to being over the performance metric threshold[latency]."'),
              line(NOW - timedelta(minutes=7), "0113022923", 'eventtype="Service" interface="port2" member="2" serviceid=3 service="x" '
                   'gateway=203.0.113.1 metric="latency" msg="Member link is unreachable or miss threshold. Stop forwarding traffic. "')]
    for ln in lines:
        assert sink.add_line(ln, source="syslog", peer_ip="10.1.0.1") is not None, ln
    await sink.flush()


def test_interval_maths():
    t = lambda m: NOW + timedelta(minutes=m)  # noqa: E731
    assert intersect([(t(0), t(10))], [(t(5), t(20))]) == [(t(5), t(10))]
    assert merge([(t(0), t(5)), (t(3), t(8)), (t(10), t(11))]) == [(t(0), t(8)), (t(10), t(11))]
    assert subtract([(t(0), t(10))], [(t(2), t(4))]) == [(t(0), t(2)), (t(4), t(10))]
    # an interval left open by a check that went silent is not counted forever
    iv = down_intervals([(t(0), "dead")], False, t(-10), t(24 * 60), last_seen=t(0))
    assert iv == [(t(0), t(6 * 60))]


async def test_isp_report(clean_ch, db):
    await _ingest(clean_ch)
    db.add(IspLink(firewall_id=1, interface="port1", isp_name="Acme Telecom", target_availability=99.9, outage_checks=[]))
    await db.commit()
    rep = await report(clean_ch, db, NOW - timedelta(hours=2), NOW + timedelta(seconds=1))
    links = {l["interface"]: l for l in rep["links"]}
    p1, p2 = links["port1"], links["port2"]
    assert p1["isp_name"] == "Acme Telecom" and p1["status"] == "up"
    assert p1["outages"] == 1 and p1["blips"] == 1
    assert 595 <= p1["longest_s"] <= 600            # both checks dead from +3s to +10m (intersection)
    assert 610 <= p1["downtime_s"] <= 620           # outage + 20 s blip
    assert p1["partial_events"] >= 1 and p1["partial_s"] >= 300
    assert p1["sla_breaches"] == {"latency": 1}
    assert p1["latency_ms"] == 5.0 and p1["mos"] == 4.4 and p1["bw_in_peak_bps"] == 40e6
    assert p1["availability"] < 99.9 and p1["sla_met"] is False
    assert p2["status"] == "down" and p2["gateway"] == "203.0.113.1"
    assert rep["totals"]["down_now"] == 1
    assert {i["isp_name"] for i in rep["isps"]} == {"Acme Telecom", "port2"}
    # links seen in logs are registered for naming
    assert {c.interface for c in (await db.execute(select(IspLink))).scalars()} == {"port1", "port2"}


async def test_isp_outage_alert(clean_ch, db):
    await _ingest(clean_ch)
    await ensure_default_rules(db)
    for r in (await db.execute(select(AlertRule))).scalars():
        r.enabled = r.key == "isp_outage"
    await db.commit()
    res = await run_rules(clean_ch, db)
    assert res["isp_outage"]["created"] == 1
    a = (await db.execute(select(Alert))).scalars().one()
    assert a.group_key == "1:port2" and "is down" in a.explanation and a.firewall_ids == [1]


async def test_isp_api(api, clean_ch, db):
    await _ingest(clean_ch)
    h = await login(api, "analyst1")
    r = await api.get("/api/isp/overview", params={"range": "24h"}, headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["totals"]["links"] == 2
    r = await api.get("/api/isp/links/1/port1", params={"range": "24h"}, headers=h)
    assert r.status_code == 200, r.text
    d = r.json()
    assert {e["type"] for e in d["events"]} == {"outage", "partial"} and d["timeseries"] and len(d["checks"]) == 2
    r = await api.get("/api/isp/outages.csv", params={"range": "24h"}, headers=h)
    assert r.status_code == 200 and "port1" in r.text
    link_id = (await db.execute(select(IspLink).where(IspLink.interface == "port2"))).scalars().one().id
    assert (await api.put(f"/api/isp/config/{link_id}", json={"isp_name": "x"}, headers=h)).status_code == 403
    ha = await login(api, "admin1")
    assert (await api.put(f"/api/isp/config/{link_id}", json={"isp_name": "Beta Fiber", "bandwidth_mbps": 100}, headers=ha)).status_code == 200
    r = await api.get("/api/isp/overview", params={"range": "24h"}, headers=h)
    assert "Beta Fiber" in {i["isp_name"] for i in r.json()["isps"]}
