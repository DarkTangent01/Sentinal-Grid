"""Palo Alto PAN-OS: syslog CSV ingest (fields, time zone, source checks, detections) and the read-only XML API."""
import re
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from sqlalchemy import select

from app import paloalto
from app.alerts.engine import ensure_default_rules, run_rules
from app.db.models import Alert, AlertRule, Firewall
from app.ingest.panos import detect, parse
from app.ingest.pipeline import DeviceRegistry, EventSink

PA = {"id": 7, "name": "PA-HQ-01", "site": "HQ", "serial": "013201001234", "host": "10.50.0.1", "vendor": "paloalto",
      "log_tz": "Asia/Kolkata"}
H = "<14>Oct 26 12:00:00 PA-HQ-01 "
TRAFFIC = (H + "1,2026/10/26 12:00:00,013201001234,TRAFFIC,end,2561,2026/10/26 12:00:00,10.1.1.5,93.184.216.34,203.0.113.10,"
           "93.184.216.34,Allow-Web,corp\\alice,,ssl,vsys1,trust,untrust,ethernet1/2,ethernet1/1,Forward,,123456,1,51515,443,40001,"
           "443,0x400000,tcp,allow,6200,1200,5000,20,2026/10/26 11:59:50,10,computer-and-internet-info,0,7311,0x0,"
           "10.0.0.0-10.255.255.255,United States,0,10,10,tcp-fin")
URL = (H + '1,2026/10/26 12:00:01,013201001234,THREAT,url,2561,2026/10/26 12:00:01,10.1.1.5,198.51.100.7,0.0.0.0,0.0.0.0,'
       'Allow-Web,,,web-browsing,vsys1,trust,untrust,ethernet1/2,ethernet1/1,Forward,,123457,1,51516,80,0,0,0x0,tcp,block-url,'
       '"bad.example.com/login.php",(9999),phishing,informational,client-to-server,7312,0x0,10.0.0.0-10.255.255.255,Netherlands')


def auth_fail(i):
    return (H + f"1,2026/10/26 12:00:{i:02d},013201001234,SYSTEM,auth,2561,2026/10/26 12:00:{i:02d},,auth-fail,,0,0,general,medium,"
            f"\"failed authentication for user 'admin'. Reason: Invalid username/password. From: 10.9.9.8.\",{7400 + i}")


def config(i):
    return (H + f"1,2026/10/26 12:01:{i:02d},013201001234,CONFIG,0,2561,2026/10/26 12:01:{i:02d},10.9.9.9,vsys1,edit,admin,Web,"
            f"Succeeded, vsys  vsys1 rulebase security rules Rule{i},{7500 + i}")


def test_detect_and_parse_rfc5424_header():
    host, f = detect("<14>1 2026-10-26T12:00:01+05:30 PA-HQ-01 - - - - " + URL[len(H):])
    assert host == "PA-HQ-01"
    d = parse(host, f)
    assert (d["type"], d["subtype"], d["hostname"], d["action"], d["catdesc"]) == ("utm", "webfilter", "bad.example.com", "blocked", "phishing")
    assert detect('date=2026-10-26 time=12:00:00 devid="FGT" logid="0000000013" type="traffic"') is None


async def test_ingest_time_zone_and_source_check(clean_ch):
    reg = DeviceRegistry()
    reg.load([PA])
    sink = EventSink(clean_ch, reg)
    ev = sink.add_line(TRAFFIC, peer_ip="10.50.0.1")
    assert ev is not None and ev["firewall_id"] == 7 and ev["category"] == "traffic"
    assert ev["event_time"] == datetime(2026, 10, 26, 6, 30, tzinfo=timezone.utc)  # 12:00 IST
    assert (ev["src_ip"], ev["dst_ip"], ev["dst_port"], ev["action"], ev["sent_bytes"], ev["rcvd_bytes"], ev["policy_name"]) == \
        ("10.1.1.5", "93.184.216.34", 443, "accept", 1200, 5000, "Allow-Web")
    assert ev["parser_version"].startswith("panos")
    assert sink.add_line(TRAFFIC, peer_ip="10.50.0.1") is None and sink.counters["duplicates"] == 1
    assert sink.add_line(URL, peer_ip="192.0.2.66") is None and sink.counters["source_mismatch"] == 1  # serial spoofed from elsewhere


async def test_builtin_detections_cover_panos(clean_ch, db):
    db.add(Firewall(id=7, name="PA-HQ-01", host="10.50.0.1", serial="013201001234", vendor="paloalto", log_tz="UTC",
                    syslog_source_ips=[], capabilities={}, health={}, api_log_cursor={}, tags=[]))
    await db.commit()
    reg = DeviceRegistry()
    reg.load([{**PA, "log_tz": "UTC"}])
    sink = EventSink(clean_ch, reg)
    recent = (datetime.now(timezone.utc) - timedelta(seconds=30)).strftime("%Y/%m/%d %H:%M")
    stamp = lambda line: re.sub(r"2026/10/26 12:0\d", recent, line)  # noqa: E731  inside every rule window
    for i in range(6):
        assert sink.add_line(stamp(auth_fail(i)), peer_ip="10.50.0.1") is not None
    assert sink.add_line(stamp(config(1)), peer_ip="10.50.0.1") is not None
    await sink.flush()
    await ensure_default_rules(db)
    for r in (await db.execute(select(AlertRule))).scalars():
        r.enabled = r.key in ("admin_login_fail", "config_change")
    await db.commit()
    res = await run_rules(clean_ch, db, now=datetime.now(timezone.utc) + timedelta(seconds=60))
    assert res["admin_login_fail"]["created"] == 1 and res["config_change"]["created"] == 1
    assert {a.rule_key for a in (await db.execute(select(Alert))).scalars()} == {"admin_login_fail", "config_change"}


# ------------------------------------------------------------------ XML API (mocked PAN-OS)
SYSINFO = ("<response status='success'><result><system><hostname>PA-HQ-01</hostname><serial>013201001234</serial>"
           "<model>PA-3220</model><sw-version>11.1.2</sw-version><uptime>12 days, 3:04:05</uptime><app-version>8800-1</app-version>"
           "</system></result></response>")
RES = ("<response status='success'><result><![CDATA[top - 12:00:00 up 12 days\n%Cpu(s):  3.0 us,  1.0 sy,  0.0 ni, 95.5 id\n"
       "MiB Mem :  32000.0 total,  8000.0 free,  16000.0 used,  8000.0 buff/cache\n]]></result></response>")
SESS = "<response status='success'><result><num-active>12345</num-active><cps>210</cps><kbps>98000</kbps></result></response>"
HA = ("<response status='success'><result><enabled>yes</enabled><group><mode>Active-Passive</mode><local-info><state>active</state>"
      "</local-info><peer-info><state>passive</state></peer-info></group></result></response>")
IFS = "<response status='success'><result><hw><entry><name>ethernet1/1</name><state>up</state><speed>10000</speed></entry></hw></result></response>"
RULES = ("<response status='success'><result><rules><entry name='Allow-Web'><action>allow</action></entry>"
         "<entry name='Deny-All'><action>deny</action><disabled>no</disabled></entry></rules></result></response>")


def mock_pan(seen: list):
    def handler(req: httpx.Request):
        seen.append(req)
        assert req.headers["X-PAN-KEY"] == "pan-key-1234567890" and "key" not in req.url.params  # key never in the URL
        p = req.url.params
        if p["type"] == "config":
            assert p["action"] == "get"
            return httpx.Response(200, text=RULES)
        cmd = p["cmd"]
        body = {paloalto.SYSTEM_INFO: SYSINFO, paloalto.RESOURCES: RES, paloalto.SESSION_INFO: SESS, paloalto.HA_STATE: HA,
                paloalto.INTERFACES: IFS}.get(cmd)
        return httpx.Response(200, text=body or "<response status='error' code='17'><msg>unknown</msg></response>")
    return httpx.MockTransport(handler)


async def test_pan_api_poll_and_readonly_guard(monkeypatch):
    seen: list = []
    monkeypatch.setattr(paloalto, "client_for", lambda fw, key=None: paloalto.PanClient("10.50.0.1", 443, "pan-key-1234567890", None,
                                                                                         transport=mock_pan(seen)))
    fw = Firewall(id=7, name="PA-HQ-01", host="10.50.0.1", https_port=443, vendor="paloalto", vdom="vsys1", capabilities={}, health={})
    rep = await paloalto.run_connection_test(fw)
    assert rep["ok"] and rep["identity"]["version"] == "11.1.2" and rep["endpoints"]["policies"] == "supported"
    paloalto.apply_test_report(fw, rep)
    assert (fw.serial, fw.model, fw.api_status) == ("013201001234", "PA-3220", "ok")
    await paloalto.poll_health(fw)
    r = fw.health["resources"]
    assert (r["cpu"], r["mem"], r["sessions"], r["cps"]) == (4.5, 50.0, 12345, 210)
    assert fw.health["ha"]["local_state"] == "active" and fw.health["uptime_s"] == 12 * 86400 + 3 * 3600 + 4 * 60 + 5
    assert set(fw.health["policies"]) == {"Allow-Web", "Deny-All"}
    assert all(q.method == "GET" for q in seen)
    c = paloalto.PanClient("10.50.0.1", 443, "k", None, transport=mock_pan([]))
    with pytest.raises(ValueError, match="read-only"):
        await c.op("<request><restart><system></system></restart></request>")
    await c.close()


async def test_pan_api_auth_error():
    def handler(req):
        return httpx.Response(200, text="<response status='error' code='403'><result><msg>Invalid Credential</msg></result></response>")
    c = paloalto.PanClient("10.50.0.1", 443, "bad", None, transport=httpx.MockTransport(handler))
    from app.fortigate.client import FortiGateAuthError
    with pytest.raises(FortiGateAuthError):
        await paloalto.system_info(c)
    await c.close()
