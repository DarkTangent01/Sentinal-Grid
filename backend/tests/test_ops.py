"""Firewall health (resources, reboots, FortiAnalyzer) and IPsec tunnel monitoring from real-format event logs."""
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app import fwhealth, vpnmon
from app.alerts.engine import ensure_default_rules, run_rules
from app.db.models import Alert, AlertRule
from app.ingest.pipeline import EventSink
from app.reports import generate, period_window

from .test_storage_analytics import registry

NOW = datetime.now(timezone.utc).replace(microsecond=0)
_seq = iter(range(1, 10**9))


def line(ts, logid, sub, body, level="notice"):
    ns = int(ts.timestamp() * 1e9) + next(_seq)
    return (f'<189>date={ts:%Y-%m-%d} time={ts:%H:%M:%S} devname="FGT-TEST-01" devid="FGTEST0000000001" eventtime={ns} tz="+0000" '
            f'logid="{logid}" type="event" subtype="{sub}" level="{level}" vd="root" {body}')


def perf(ts, cpu, mem, uptime):
    return line(ts, "0100040704", "system", f'logdesc="System performance statistics" action="perf-stats" cpu={cpu} mem={mem} totalsession=5000 '
                f'disk=0 bandwidth="1000/2000" setuprate=40 sysuptime={uptime} msg="Performance statistics: average CPU: {cpu}"')


def vpn(ts, logid, tunnel, body):
    return line(ts, logid, "vpn", f'remip=198.51.100.9 locip=203.0.113.2 remport=500 locport=500 outintf="wan1" user="N/A" '
                f'xauthuser="N/A" vpntunnel="{tunnel}" {body}')


async def _ingest(ch):
    sink = EventSink(ch, registry())
    lines = []
    up = 900_000
    for i in range(12):  # samples every 5 min for the last hour; reboot 25 min ago; CPU hot for the last 3 samples
        t = NOW - timedelta(minutes=60 - 5 * i)
        if t >= NOW - timedelta(minutes=25) and up > 10_000:
            up = 300
        lines.append(perf(t, 95 if i >= 9 else 20, 40, up))
        up += 300
    lines += [line(NOW - timedelta(minutes=50), "0100022902", "system", 'action="disconnect" reason="connection close" msg="Disconnected from FortiAnalyzer 192.0.2.50"'),
              line(NOW - timedelta(minutes=49), "0100022901", "system", 'action="connect" msg="Connected to FortiAnalyzer 192.0.2.50"')]
    sent = rcvd = 0
    for i in range(6):  # tunnel statistics every 10 min
        sent, rcvd = sent + 60_000_000, rcvd + 120_000_000
        lines.append(vpn(NOW - timedelta(minutes=60 - 10 * i), "0101037141", "hq-tun", f'action="tunnel-stats" duration={600 * i} sentbyte={sent} rcvdbyte={rcvd} nextstat=600'))
    lines += [vpn(NOW - timedelta(minutes=30), "0101037138", "hq-tun", 'action="tunnel-down"'),
              vpn(NOW - timedelta(minutes=20), "0101037138", "hq-tun", 'action="tunnel-up"'),
              vpn(NOW - timedelta(minutes=8), "0101037138", "branch-tun", 'action="tunnel-down"')]
    lines += [line(NOW - timedelta(minutes=m), "0101037124", "vpn", 'remip=192.0.2.200 locip=203.0.113.2 outintf="wan1" vpntunnel="N/A" '
                   'status="negotiate_error" reason="peer SA proposal not match local policy" xauthuser="N/A"', "error") for m in range(1, 6)]
    lines += [line(NOW - timedelta(minutes=10), "0101037138", "vpn", 'remip=100.64.1.1 outintf="wan1" xauthuser="alice" vpntunnel="Remote_0" action="tunnel-up"')]
    for ln in lines:
        assert sink.add_line(ln, source="syslog", peer_ip="10.1.0.1") is not None, ln
    await sink.flush()


async def test_firewall_health(clean_ch, db):
    await _ingest(clean_ch)
    o = await fwhealth.overview(clean_ch, db, NOW - timedelta(hours=2), NOW + timedelta(seconds=1))
    f = o["firewalls"][0]
    m = f["members"][0]
    assert m["member"] == "FGT-TEST-01" and m["cpu"] == 95 and m["sessions"] == 5000 and m["cpu_stats"]["max"] == 95
    assert len(f["reboots"]) == 1 and f["reboots"][0]["previous_uptime_s"] > 10_000
    assert f["faz"]["disconnects"] == 1 and f["faz"]["connected"] is True


async def test_vpn_tunnels(clean_ch):
    await _ingest(clean_ch)
    o = await vpnmon.overview(clean_ch, NOW - timedelta(hours=2), NOW + timedelta(seconds=1))
    t = {x["tunnel"]: x for x in o["tunnels"]}
    assert set(t) == {"hq-tun", "branch-tun"}  # the dial-up session is not a site-to-site tunnel
    assert t["hq-tun"]["status"] == "up" and t["hq-tun"]["downs"] == 1 and 590 <= t["hq-tun"]["downtime_s"] <= 610
    assert t["hq-tun"]["avg_in_bps"] == 1_600_000  # 120 MB per 600 s
    assert t["branch-tun"]["status"] == "down"
    assert o["phase1_failures"][0]["count"] == 5 and o["dialup"][0]["user"] == "alice"


async def test_ops_alert_rules(clean_ch, db):
    await _ingest(clean_ch)
    await ensure_default_rules(db)
    for r in (await db.execute(select(AlertRule))).scalars():
        r.enabled = r.key in ("fw_resource_high", "fw_reboot", "vpn_tunnel_down")
        if r.key == "vpn_tunnel_down":
            r.params = {**r.params, "min_down_minutes": 5}
    await db.commit()
    res = await run_rules(clean_ch, db)
    assert res["fw_resource_high"]["created"] == 1 and res["fw_reboot"]["created"] == 1
    assert res["vpn_tunnel_down"]["created"] == 2  # hq-tun (10 min, recovered) and branch-tun (ongoing 8 min)
    names = {a.rule_key for a in (await db.execute(select(Alert))).scalars()}
    assert names == {"fw_resource_high", "fw_reboot", "vpn_tunnel_down"}


async def test_monthly_report_sections(clean_ch, db):
    await _ingest(clean_ch)
    s, e = period_window("monthly", datetime(2026, 11, 1, 7, tzinfo=timezone.utc))
    assert (s, e) == (datetime(2026, 10, 1, tzinfo=timezone.utc), datetime(2026, 11, 1, tzinfo=timezone.utc))
    html, _ = await generate(db, clean_ch, "Ops", NOW - timedelta(hours=2), NOW, ["isp_sla", "firewall_health", "vpn_tunnels"])
    assert "Firewall health" in html and "hq-tun" in html and "ISP availability" in html
