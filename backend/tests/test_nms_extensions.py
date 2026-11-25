"""ICMP / TCP / ARP discovery, the L3 / WAN topology layer, NETCONF / RESTCONF read operations, Telnet and serial
console access, wireless controller / cloud integrations, and the Ansible playbook policy, API and runner.

Device and vendor behaviour is simulated (asyncssh / asyncio servers on loopback, httpx mock transports built from the
vendors' documented response shapes); none of it is a real device, controller or cloud tenant."""
import asyncio
import json
import os
import stat
import sys
from datetime import datetime, timezone

import asyncssh
import httpx
import pytest
from sqlalchemy import select

from app.access import channels as CH
from app.access import gateway as G
from app.access import terminal, vault
from app.access.netconf import EOM, mask_xml
from app.config import get_settings
from app.db.models import (BgpPeer, ConsolePort, ConsoleServer, DeviceSshCredential, Firewall, IspLink, NmsAccessAudit, NmsPlaybook,
                           NmsPlaybookRun, Switch, SwitchCredential, SwitchDiscoveryRun, SwitchNetwork, User, WanOutage, WirelessAp,
                           WirelessClient, WirelessIntegration)
from app.icmp import ProbeResult
from app.playbooks import policy, runner
from app.security import TokenCipher, hash_password
from app.switches import discovery, l3topology
from app.wireless import integrations as W

from .snmp_sim import FakeClient
from .test_api import PW, api, login  # noqa: F401  (fixture)
from .test_device_access import FakeWS, _Srv, _wait


async def _base(db, *, telnet=False):
    db.add(SwitchNetwork(cidr="192.0.2.0/24", site="HQ", allow_discovery=True))
    cred = DeviceSshCredential(name="netops", kind="ssh", username="netops", secret_ciphertext=vault.seal("ssh", {"password": "pw-123456"}))
    db.add(cred)
    await db.flush()
    sw = Switch(name="R1", address="192.0.2.10", vendor="cisco", family="Catalyst", os="IOS-XE", site="HQ", monitoring="active", state="up",
                ssh_credential_id=cred.id, access_telnet=telnet, capabilities={}, group_state={}, health={}, thresholds={})
    db.add(sw)
    db.add_all([User(username="eng1", password_hash=hash_password(PW), role="analyst", products=["nms"], nms_roles=["network_engineer"]),
                User(username="appr1", password_hash=hash_password(PW), role="analyst", products=["nms"], nms_roles=["nms_admin"])])
    await db.commit()
    return sw, cred


# ------------------------------------------------------------------ discovery
async def test_discovery_icmp_tcp_arp(db):
    net = SwitchNetwork(cidr="192.0.2.0/29", allow_discovery=True)
    snmpc = SwitchCredential(name="c", version="v3", username="u")
    db.add_all([net, snmpc])
    await db.flush()
    router = Switch(name="CORE", address="192.0.2.1", vendor="cisco", monitoring="active", state="up", credential_id=snmpc.id,
                    capabilities={}, group_state={}, health={}, thresholds={})
    db.add(router)
    await db.flush()
    run = SwitchDiscoveryRun(network_id=net.id, cidr=net.cidr, credential_id=None, methods=["icmp", "tcp", "arp"], status="queued")
    db.add(run)
    await db.commit()

    async def pinger(ip, count=1, timeout_ms=800):
        return ProbeResult(1, 1, [1.5]) if ip in ("192.0.2.2", "192.0.2.3") else ProbeResult(1, 0, [])

    async def prober(ip):
        return [22, 443] if ip == "192.0.2.3" else []
    arp = FakeClient({"1.3.6.1.2.1.4.22.1.2.5.192.0.2.4": b"\x00\x11\x22\x33\x44\x55", "1.3.6.1.2.1.4.22.1.2.5.198.51.100.9": b"\x00\x11\x22\x33\x44\x66",
                      "1.3.6.1.2.1.4.22.1.2.5.192.0.2.3": b"\xaa\xbb\xcc\xdd\xee\xff"})
    r = await discovery.run(db, run, pinger=pinger, prober=prober, arp_client_factory=lambda sw: arp)
    assert r.status == "done", r.error
    res = {x["address"]: x for x in r.results}
    assert res["192.0.2.2"]["methods"] == ["icmp"] and res["192.0.2.2"]["status"] == "alive"
    assert res["192.0.2.3"]["services"] == ["ssh", "https"] and res["192.0.2.3"]["mac"] == "aa:bb:cc:dd:ee:ff" and res["192.0.2.3"]["learned_from"] == "CORE"
    assert res["192.0.2.4"]["status"] == "arp_only" and res["192.0.2.4"]["mac"] == "00:11:22:33:44:55"
    assert "198.51.100.9" not in res                                       # outside the network being discovered
    # SNMP still needs a credential
    run2 = SwitchDiscoveryRun(network_id=net.id, cidr=net.cidr, credential_id=None, methods=["snmp"], status="queued")
    db.add(run2)
    await db.commit()
    assert (await discovery.run(db, run2)).status == "failed"


async def test_discovery_api_methods(api, db):  # noqa: F811  (pytest fixture)
    db.add(SwitchNetwork(cidr="192.0.2.0/29", allow_discovery=True))
    await db.commit()
    h = await login(api, "admin1")
    nid = (await db.execute(select(SwitchNetwork.id))).scalar()
    assert (await api.post("/api/switches/admin/discovery", headers=h, json={"network_id": nid, "methods": ["snmp"]})).status_code == 422
    assert (await api.post("/api/switches/admin/discovery", headers=h, json={"network_id": nid, "methods": ["nmap"]})).status_code == 422
    r = await api.post("/api/switches/admin/discovery", headers=h, json={"network_id": nid, "methods": ["icmp", "tcp"]})
    assert r.status_code == 202 and r.json()["hosts"] == 6


# ------------------------------------------------------------------ L3 / WAN topology
async def test_l3_topology(db):
    a = Switch(name="CORE1", address="192.0.2.1", vendor="cisco", site="HQ", state="up", capabilities={}, group_state={}, thresholds={},
               health={"routing": {"ip_interfaces": [{"ip": "10.0.0.1"}], "ospf": [{"neighbor": "10.0.0.2", "router_id": "2.2.2.2", "state": "full"},
                                                                                      {"neighbor": "10.9.9.9", "router_id": "9.9.9.9", "state": "init"}],
                                    "bgp": [{"peer": "203.0.113.1", "remote_as": 64500, "state": "established"}]}})
    b = Switch(name="CORE2", address="192.0.2.2", vendor="cisco", site="HQ", state="up", capabilities={}, group_state={}, thresholds={},
               health={"routing": {"ip_interfaces": [{"ip": "10.0.0.2"}], "ospf": [{"neighbor": "10.0.0.1", "router_id": "1.1.1.1", "state": "full"}]}})
    fw = Firewall(name="FW1", host="198.51.100.1", site="HQ")
    db.add_all([a, b, fw])
    await db.flush()
    db.add(BgpPeer(firewall_id=fw.id, peer_ip="203.0.113.5", remote_as=64501, state="Active", local_ip="203.0.113.6"))
    link = IspLink(firewall_id=fw.id, interface="wan1", isp_name="ACME", name="HQ-ACME", site="HQ")
    db.add(link)
    await db.flush()
    db.add(WanOutage(isp_link_id=link.id, firewall_id=fw.id, started_at=datetime.now(timezone.utc), detected_at=datetime.now(timezone.utc)))
    await db.commit()
    g = await l3topology.build(db, tunnels=[{"firewall_id": fw.id, "tunnel": "to-DC", "remote_ip": "192.0.2.2", "status": "up"},
                                            {"firewall_id": fw.id, "tunnel": "to-partner", "remote_ip": "198.18.0.9", "status": "down"}])
    by = {(e["protocol"], e["detail"]): e for e in g["edges"]}
    ospf = [e for e in g["edges"] if e["protocol"] == "ospf" and {e["a"], e["b"]} == {f"sw:{a.id}", f"sw:{b.id}"}]
    assert len(ospf) == 1 and ospf[0]["state"] == "up" and ospf[0]["matched_by"].startswith("interface address")   # seen from both ends: one edge
    assert by[("ospf", "10.9.9.9")]["state"] == "down" and by[("ospf", "10.9.9.9")]["matched_by"] == "not in inventory"
    assert by[("bgp", "203.0.113.1")]["b"] == "as:AS64500" and by[("bgp", "203.0.113.1")]["source"] == "SNMP BGP4-MIB"
    assert by[("bgp", "203.0.113.5")]["state"] == "down" and by[("bgp", "203.0.113.5")]["source"] == "FortiGate BGP API"
    assert by[("ipsec", "to-DC")]["b"] == f"sw:{b.id}" and by[("ipsec", "to-partner")]["state"] == "down"
    assert by[("isp", "wan1")]["state"] == "down" and by[("isp", "wan1")]["layer"] == "wan" and by[("isp", "wan1")]["matched_by"] == "configured"
    assert g["summary"]["ospf"]["total"] == 2


# ------------------------------------------------------------------ NETCONF / RESTCONF
@pytest.fixture
async def netconf_server(monkeypatch):
    seen = []

    async def handle(proc):
        if proc.subsystem != "netconf":
            proc.exit(1)
            return
        buf = ""
        proc.stdout.write('<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability>'
                          '<capability>urn:ietf:params:netconf:capability:candidate:1.0</capability></capabilities></hello>' + EOM)
        while True:
            chunk = await proc.stdin.read(4096)
            if not chunk:
                break
            buf += chunk
            while EOM in buf:
                msg, buf = buf.split(EOM, 1)
                seen.append(msg)
                if "<get-config>" in msg:
                    proc.stdout.write('<rpc-reply message-id="101"><data><system><password>Sup3rSecret</password><host-name>R1</host-name></system>'
                                      '</data></rpc-reply>' + EOM)
                elif "<close-session/>" in msg:
                    proc.stdout.write('<rpc-reply message-id="102"><ok/></rpc-reply>' + EOM)
                    proc.exit(0)
                    return
    key = asyncssh.generate_private_key("ssh-ed25519")
    srv = await asyncssh.create_server(_Srv, "127.0.0.1", 0, server_host_keys=[key], process_factory=handle)
    port = srv.sockets[0].getsockname()[1]
    dialled = []

    async def dial(host, p, host_key, **kw):
        dialled.append((host, p))
        known = asyncssh.import_known_hosts(f"127.0.0.1 {host_key}\n") if host_key else None
        return await asyncssh.connect("127.0.0.1", port=port, known_hosts=known, **kw)
    monkeypatch.setattr(G, "_dial", dial)
    yield {"seen": seen, "dialled": dialled}
    srv.close()


async def test_netconf_read_operations(api, db, netconf_server):  # noqa: F811  (pytest fixture)
    sw, _ = await _base(db)
    h = await login(api, "eng1")
    r = await api.post(f"/api/nms/access/devices/{sw.id}/netconf", headers=h, json={"operation": "capabilities"})
    assert r.status_code == 200, r.text
    assert "candidate:1.0" in r.json()["output"] and netconf_server["dialled"] == [("192.0.2.10", 830)]
    r = await api.post(f"/api/nms/access/devices/{sw.id}/netconf", headers=h, json={"operation": "running_config"})
    assert r.json()["status"] == "ok" and "Sup3rSecret" not in r.json()["output"] and "&lt;masked&gt;" in r.json()["output"]
    assert any("<get-config>" in m for m in netconf_server["seen"]) and not any("edit-config" in m for m in netconf_server["seen"])
    assert (await api.post(f"/api/nms/access/devices/{sw.id}/netconf", headers=h, json={"operation": "edit-config"})).status_code == 422
    ro = await api.get("/api/nms/access/protocol-ops", headers=h)
    assert {o["id"] for o in ro.json()["netconf"]} >= {"capabilities", "running_config", "junos_interfaces"}


async def test_restconf_read_operations(api, db):  # noqa: F811  (pytest fixture)
    from app.api import access as AA
    sw, _ = await _base(db)
    calls = []

    def handler(req: httpx.Request):
        calls.append((req.url.path, req.headers.get("authorization", "")))
        if req.url.path == "/.well-known/host-meta":
            return httpx.Response(200, text="<XRD/>")
        if req.url.path.endswith("ietf-interfaces:interfaces"):
            return httpx.Response(200, json={"ietf-interfaces:interfaces": {"interface": [{"name": "Gi1", "password": "x"}]}})
        return httpx.Response(404)
    AA._RESTCONF_TRANSPORT["t"] = httpx.MockTransport(handler)
    try:
        h = await login(api, "eng1")
        r = await api.post(f"/api/nms/access/devices/{sw.id}/restconf", headers=h, json={"operation": "interfaces"})
        assert r.status_code == 200 and r.json()["status"] == "ok" and '"<masked>"' in r.json()["output"]
        assert calls[0] == ("/.well-known/host-meta", "") and calls[1][1].startswith("Basic ")   # no credentials before the probe
        r = await api.post(f"/api/nms/access/devices/{sw.id}/restconf", headers=h, json={"operation": "iosxe_version"})
        assert r.json()["status"] == "unsupported"
        assert (await api.post(f"/api/nms/access/devices/{sw.id}/restconf", headers=h, json={"operation": "/restconf/data/x"})).status_code == 422
    finally:
        AA._RESTCONF_TRANSPORT.clear()


def test_xml_masking():
    t = mask_xml('<x><snmp-community>public</snmp-community><encrypted-password>$6$a</encrypted-password><name>ok</name></x>')
    assert "public" not in t and "$6$a" not in t and "<name>ok</name>" in t


# ------------------------------------------------------------------ Telnet
@pytest.fixture
async def telnet_device():
    seen = []

    async def handle(r, w):
        w.write(bytes([255, 253, 31, 255, 251, 1, 255, 251, 3]) + b"\r\nUser Access Verification\r\n\r\nUsername: ")
        stage, buf = "user", b""
        while True:
            data = await r.read(1024)
            if not data:
                break
            data = data.replace(bytes([255, 251, 31]), b"").replace(bytes([255, 253, 1]), b"").replace(bytes([255, 253, 3]), b"")
            if b"\xff\xfa" in data:
                data = data[:data.index(b"\xff\xfa")] + data[data.index(b"\xff\xf0") + 2:]
            buf += data
            while b"\r" in buf:
                line, buf = buf.split(b"\r", 1)
                line = line.strip(b"\n").decode()
                seen.append(f"{stage}:{line}")
                if stage == "user":
                    stage = "pw"
                    w.write(b"\r\nPassword: ")
                elif stage == "pw":
                    if line != "pw-123456":
                        w.write(b"\r\n% Login invalid\r\n")
                        w.close()
                        return
                    stage = "cli"
                    w.write(b"\r\nR1>")
                elif line == "exit":
                    w.close()
                    return
                else:
                    w.write(f"\r\n{'Cisco IOS Software' if line.startswith('show') else ''}\r\nR1>".encode())
            await w.drain()
    srv = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    yield {"port": port, "seen": seen}
    srv.close()


async def test_telnet_disabled_by_default_then_guarded(api, db, telnet_device, monkeypatch):  # noqa: F811  (pytest fixture)
    sw, _ = await _base(db, telnet=True)
    h = await login(api, "eng1")
    r = await api.post(f"/api/nms/access/devices/{sw.id}/sessions", headers=h, json={"protocol": "telnet"})
    assert r.status_code == 409 and "Telnet" in r.json()["detail"]
    monkeypatch.setenv("ACCESS_TELNET_ENABLED", "true")
    get_settings.cache_clear()
    real_open = CH.TelnetChannel.open

    async def to_sim(host, port, timeout, cols=120, rows=32):
        assert (host, port) == ("192.0.2.10", 23)
        return await real_open("127.0.0.1", telnet_device["port"], timeout, cols, rows)
    monkeypatch.setattr(CH.TelnetChannel, "open", to_sim)
    try:
        r = await api.post(f"/api/nms/access/devices/{sw.id}/sessions", headers=h, json={"protocol": "telnet"})
        assert r.status_code == 201, r.text
        ws = FakeWS({"siem_session": api.cookies.get("siem_session")})
        await ws.inbox.put({"t": "auth", "session": r.json()["session_id"], "ticket": r.json()["ticket"]})
        task = asyncio.create_task(terminal.handle(ws))
        await _wait(lambda: any(m.get("t") == "status" for m in ws.sent))
        st = next(m for m in ws.sent if m.get("t") == "status")
        assert st["protocol"] == "telnet" and st["cleartext"] is True
        assert telnet_device["seen"][:2] == ["user:netops", "pw:pw-123456"]
        await ws.inbox.put({"t": "i", "d": "show version\r"})
        await _wait(lambda: "cli:show version" in telnet_device["seen"])
        await ws.inbox.put({"t": "i", "d": "conf t\r"})
        await _wait(lambda: any(m.get("t") == "blocked" for m in ws.sent))
        await ws.inbox.put({"t": "close"})
        await asyncio.wait_for(task, 10)
        assert not any("conf t" in x for x in telnet_device["seen"])
        a = (await db.execute(select(NmsAccessAudit).where(NmsAccessAudit.action == "terminal_connect"))).scalars().all()
        assert a[-1].detail.get("cleartext") is True and a[-1].detail.get("protocol") == "telnet"
    finally:
        get_settings.cache_clear()


# ------------------------------------------------------------------ serial console
def test_console_login_forms():
    assert CH.console_login("opengear", "ssh", "netops", 5) == ("netops:port05", 22)
    assert CH.console_login("cisco", "ssh", "netops", 33) == ("netops:33", 22)
    assert CH.console_login("cisco", "telnet", "netops", 33) == ("", 2033)


async def test_console_session_through_opengear(api, db, monkeypatch):  # noqa: F811  (pytest fixture)
    sw, cred = await _base(db)
    logins = []

    class OgSrv(asyncssh.SSHServer):
        def begin_auth(self, username):
            logins.append(username)
            return True

        def password_auth_supported(self):
            return True

        def validate_password(self, username, password):
            return username == "og:port05" and password == "og-pass"

    async def handle(proc):
        proc.stdout.write("\r\nR1 console\r\nR1>")
        while True:
            try:
                line = await proc.stdin.readline()
            except (asyncssh.BreakReceived, asyncssh.SignalReceived):
                proc.stdout.write("^C\r\nR1>")
                continue
            except asyncssh.TerminalSizeChanged:
                continue
            except Exception:
                break
            if not line:
                break
            proc.stdout.write("\r\nR1>")
        proc.exit(0)
    key = asyncssh.generate_private_key("ssh-ed25519")
    srv = await asyncssh.create_server(OgSrv, "127.0.0.1", 0, server_host_keys=[key], process_factory=handle)
    port = srv.sockets[0].getsockname()[1]

    async def dial(host, p, host_key, **kw):
        assert (host, p) == ("192.0.2.200", 22)
        known = asyncssh.import_known_hosts(f"127.0.0.1 {host_key}\n") if host_key else None
        return await asyncssh.connect("127.0.0.1", port=port, known_hosts=known, **kw)
    monkeypatch.setattr(CH, "_dial", dial)
    ogc = DeviceSshCredential(name="og", kind="ssh", username="og", secret_ciphertext=vault.seal("ssh", {"password": "og-pass"}))
    db.add(ogc)
    await db.commit()
    ha = await login(api, "admin1")
    assert (await api.post("/api/nms/access/console-servers", headers=ha, json={"name": "OG", "address": "203.0.113.200", "kind": "opengear",
                                                                                 "credential_id": ogc.id})).status_code == 422   # outside every network
    r = await api.post("/api/nms/access/console-servers", headers=ha, json={"name": "OG", "address": "192.0.2.200", "kind": "opengear", "credential_id": ogc.id})
    cs = r.json()["id"]
    pid = (await api.post(f"/api/nms/access/console-servers/{cs}/ports", headers=ha, json={"port": 5, "switch_id": sw.id, "label": "R1 con"})).json()["id"]
    h = await login(api, "eng1")
    dev = await api.get(f"/api/nms/access/devices/{sw.id}", headers=h)
    assert dev.json()["consoles"][0]["port"] == 5
    r = await api.post(f"/api/nms/access/devices/{sw.id}/sessions", headers=h, json={"protocol": "console", "console_port_id": pid})
    assert r.status_code == 201, r.text
    ws = FakeWS({"siem_session": api.cookies.get("siem_session")})
    await ws.inbox.put({"t": "auth", "session": r.json()["session_id"], "ticket": r.json()["ticket"]})
    task = asyncio.create_task(terminal.handle(ws))
    await _wait(lambda: "R1 console" in ws.out())
    await ws.inbox.put({"t": "i", "d": "reload\r"})
    await _wait(lambda: any(m.get("t") == "blocked" for m in ws.sent))
    await ws.inbox.put({"t": "close"})
    await asyncio.wait_for(task, 10)
    srv.close()
    assert logins == ["og:port05"]
    key = (await db.execute(select(ConsoleServer.ssh_host_key).where(ConsoleServer.id == cs))).scalar()
    assert key.startswith("ssh-ed25519")                                                # pinned on first use
    assert (await db.execute(select(ConsolePort.switch_id).where(ConsolePort.id == pid))).scalar() == sw.id


# ------------------------------------------------------------------ wireless integrations
def test_integration_url_allowlist():
    nets = [SwitchNetwork(cidr="192.0.2.0/24")]
    assert W.validate_base_url("mist", "https://api.eu.mist.com", nets) == "https://api.eu.mist.com"
    assert W.validate_base_url("smartzone", "https://192.0.2.50:8443", nets) == "https://192.0.2.50:8443"
    for kind, url in (("mist", "https://evil.example.com"), ("mist", "https://api.mist.com.evil.io"), ("mist", "http://api.mist.com"),
                      ("mist", "https://10.0.0.1"), ("ruckus_one", "https://api.ruckus.cloud/x"), ("smartzone", "https://198.51.100.5:8443"),
                      ("smartzone", "https://192.0.2.50:22"), ("aruba_central", "https://user:pw@apigw-uswest4.central.arubanetworks.com")):
        with pytest.raises(W.IntegrationError):
            W.validate_base_url(kind, url, nets)


MIST_AP = {"mac": "5c5b35000001", "name": "AP-1F-01", "ip": "192.0.2.61", "model": "AP43", "serial": "A1", "version": "0.14", "status": "connected",
           "uptime": 3600, "num_clients": 2, "radio_stat": {"band_24": {"channel": 6, "bandwidth": 20, "util_all": 31, "num_clients": 1, "noise_floor": -92},
                                                             "band_5": {"channel": 36, "bandwidth": 80, "util_all": 12, "num_clients": 1}}}


def _mist(req: httpx.Request):
    assert req.headers["authorization"] == "Token mist-token-1"
    p = req.url.path
    if p == "/api/v1/orgs/org-1/sites":
        return httpx.Response(200, json=[{"id": "s1", "name": "HQ"}, {"id": "s2", "name": "Lab"}])
    if p == "/api/v1/sites/s1/stats/devices":
        return httpx.Response(200, json=[MIST_AP, {**MIST_AP, "mac": "5c5b35000002", "name": "AP-off", "status": "disconnected"}])
    if p == "/api/v1/sites/s1/stats/clients":
        return httpx.Response(200, json=[{"mac": "aabbccddee01", "ip": "10.1.1.5", "ap_mac": "5c5b35000001", "ssid": "Corp", "vlan_id": 10, "band": "5",
                                          "channel": 36, "rssi": -55, "snr": 35, "rx_bytes": 100, "tx_bytes": 200, "uptime": 60, "username": "alice"}])
    return httpx.Response(404)


async def test_mist_integration_feeds_the_wireless_pipeline(db, ch):
    db.add(SwitchNetwork(cidr="192.0.2.0/24"))
    cred = DeviceSshCredential(name="mist", kind="api_token", username="", secret_ciphertext=vault.seal("api_token", {"token": "mist-token-1"}))
    db.add(cred)
    await db.flush()
    i = WirelessIntegration(name="Mist HQ", kind="mist", base_url="https://api.mist.com", org_id="org-1", site_filter=["HQ"], credential_id=cred.id)
    db.add(i)
    await db.commit()
    res = await W.sync(db, ch, i, transport=httpx.MockTransport(_mist))
    assert res["ok"], res
    ctl = await db.get(Switch, i.switch_id)
    assert ctl.monitoring == "external" and ctl.role == "wlc" and ctl.state == "up" and ctl.address == f"integration:mist:{i.id}"
    aps = (await db.execute(select(WirelessAp).where(WirelessAp.wlc_id == ctl.id))).scalars().all()
    assert [a.name for a in aps] == ["AP-1F-01"] and aps[0].model == "AP43"                    # offline AP not listed as joined
    cl = (await db.execute(select(WirelessClient).where(WirelessClient.wlc_id == ctl.id))).scalars().all()
    assert cl[0].mac == "aa:bb:cc:dd:ee:01" and cl[0].ssid == "Corp" and cl[0].band == "5" and cl[0].rssi_dbm == -55 and cl[0].ap_id == aps[0].id
    # the access gateway refuses the virtual controller
    with pytest.raises(G.AccessError):
        await G.resolve(db, User(username="a", role="admin"), ctl.id)
    # a rejected token is recorded, the controller marked down
    i.credential_id = cred.id
    res = await W.sync(db, ch, i, transport=httpx.MockTransport(lambda r: httpx.Response(401)))
    assert not res["ok"] and "rejected the credential" in res["error"]


async def test_smartzone_ruckus_one_aruba(db, ch):
    db.add(SwitchNetwork(cidr="192.0.2.0/24"))
    sz_c = DeviceSshCredential(name="sz", kind="https", username="api", secret_ciphertext=vault.seal("https", {"password": "szpw"}))
    r1_c = DeviceSshCredential(name="r1", kind="api_token", username="client-1", secret_ciphertext=vault.seal("api_token", {"token": "client-secret"}))
    ar_c = DeviceSshCredential(name="ar", kind="api_token", username="", secret_ciphertext=vault.seal(
        "api_token", {"token": "old-access", "client_id": "cid", "client_secret": "csec", "refresh_token": "rt-1"}))
    db.add_all([sz_c, r1_c, ar_c])
    await db.flush()

    def sz(req):
        p = req.url.path
        if p.endswith("/serviceTicket"):
            assert json.loads(req.content) == {"username": "api", "password": "szpw"}
            return httpx.Response(200, json={"serviceTicket": "ST-1"})
        assert req.url.params["serviceTicket"] == "ST-1"
        if p.endswith("/query/ap"):
            return httpx.Response(200, json={"list": [{"apMac": "00:33:58:00:00:01", "deviceName": "SZ-AP1", "ip": "192.0.2.71", "model": "R750",
                                                       "status": "Online", "numClients": 1, "channel24G": "11 (20MHz)", "airtime24G": 40}], "hasMore": False})
        if p.endswith("/query/client"):
            return httpx.Response(200, json={"list": [{"clientMac": "AA:BB:CC:00:00:01", "apMac": "00:33:58:00:00:01", "ssid": "Guest",
                                                       "radioType": "11ng", "rssi": -60, "vlan": 20}], "hasMore": False})
        return httpx.Response(404)

    def r1(req):
        p = req.url.path
        if p == "/oauth2/token/tenant-9":
            return httpx.Response(200, json={"access_token": "r1-at"})
        assert req.headers["authorization"] == "Bearer r1-at"
        if p == "/venues/aps/query":
            return httpx.Response(200, json={"data": [{"apMac": "00:11:22:33:44:01", "name": "R1-AP", "model": "R650", "status": "2_00_Operational",
                                                       "radios": [{"band": "5", "channel": 44}]}], "totalCount": 1})
        if p == "/venues/aps/clients/query":
            return httpx.Response(200, json={"data": [{"clientMac": "aa:bb:cc:00:00:02", "apMac": "00:11:22:33:44:01", "ssid": "Corp", "radioBand": "5"}],
                                             "totalCount": 1})
        return httpx.Response(404)
    seen_tokens = []

    def aruba(req):
        p = req.url.path
        if p == "/oauth2/token":
            assert req.url.params["refresh_token"] == "rt-1"
            return httpx.Response(200, json={"access_token": "new-access", "refresh_token": "rt-2"})
        seen_tokens.append(req.headers["authorization"])
        if req.headers["authorization"] == "Bearer old-access":
            return httpx.Response(401)
        if p == "/monitoring/v2/aps":
            return httpx.Response(200, json={"aps": [{"macaddr": "20:4c:03:00:00:01", "name": "AR-AP", "status": "Up", "site": "HQ",
                                                      "radios": [{"index": 0, "band": 1, "channel": "36E", "status": "Up"}]}], "total": 1})
        if p == "/monitoring/v1/clients/wireless":
            return httpx.Response(200, json={"clients": [{"macaddr": "aa:bb:cc:00:00:03", "associated_device_mac": "20:4c:03:00:00:01",
                                                          "network": "Corp", "band": 5, "signal_db": -48, "site": "HQ"}], "total": 1})
        return httpx.Response(404)
    for name, kind, url, org, cred, handler in (("SZ", "smartzone", "https://192.0.2.50:8443", "", sz_c, sz),
                                                ("R1", "ruckus_one", "https://api.eu.ruckus.cloud", "tenant-9", r1_c, r1),
                                                ("AR", "aruba_central", "https://apigw-eucentral3.central.arubanetworks.com", "", ar_c, aruba)):
        i = WirelessIntegration(name=name, kind=kind, base_url=url, org_id=org, credential_id=cred.id)
        db.add(i)
        await db.commit()
        res = await W.sync(db, ch, i, transport=httpx.MockTransport(handler))
        assert res["ok"] and res["aps"] == 1 and res["clients"] == 1, (name, res)
    assert seen_tokens[:2] == ["Bearer old-access", "Bearer new-access"]
    ar_id = ar_c.id
    db.expire_all()
    stored = json.loads(TokenCipher().decrypt((await db.execute(select(DeviceSshCredential.secret_ciphertext).where(DeviceSshCredential.id == ar_id))).scalar()))
    assert stored["refresh_token"] == "rt-2" and stored["access_token"] == "new-access"          # rotated token kept, encrypted


async def test_integration_api_admin_only(api, db):  # noqa: F811  (pytest fixture)
    await _base(db)
    h = await login(api, "eng1")
    assert (await api.post("/api/wireless/integrations", headers=h, json={"name": "x", "kind": "mist", "base_url": "https://api.mist.com",
                                                                          "org_id": "o"})).status_code == 403
    ha = await login(api, "admin1")
    r = await api.post("/api/wireless/integrations", headers=ha, json={"name": "x", "kind": "mist", "base_url": "https://169.254.169.254", "org_id": "o"})
    assert r.status_code == 422
    r = await api.post("/api/wireless/integrations", headers=ha, json={"name": "x", "kind": "mist", "base_url": "https://api.mist.com/", "org_id": "o"})
    assert r.status_code == 201 and r.json()["base_url"] == "https://api.mist.com"
    assert (await api.get("/api/wireless/integrations", headers=h)).status_code == 200


# ------------------------------------------------------------------ Ansible policy, API, runner
READ_PB = """
- name: facts
  hosts: targets
  gather_facts: false
  connection: ansible.netcommon.network_cli
  tasks:
    - name: version
      cisco.ios.ios_command:
        commands: [show version, show ip interface brief]
      register: out
    - debug: {var: out.stdout_lines}
"""
CHANGE_PB = """
- hosts: targets
  gather_facts: false
  tasks:
    - cisco.ios.ios_config:
        lines: [description uplink]
        parents: [interface Gi1/0/1]
"""


@pytest.mark.parametrize("text,needle", [
    ("- hosts: targets\n  tasks:\n    - shell: id\n", "not allowed"),
    ("- hosts: targets\n  tasks:\n    - ansible.builtin.command: id\n", "not allowed"),
    ("- hosts: localhost\n  tasks:\n    - debug: {msg: x}\n", "hosts must be"),
    ("- hosts: targets\n  tasks:\n    - debug: {msg: \"{{ lookup('file', '/etc/passwd') }}\"}\n", "forbidden Jinja"),
    ("- hosts: targets\n  tasks:\n    - debug: {msg: x}\n      delegate_to: localhost\n", "exactly one module"),
    ("- hosts: targets\n  roles: [x]\n  tasks:\n    - debug: {msg: x}\n", "keys not allowed"),
    ("- hosts: targets\n  tasks:\n    - cisco.ios.ios_command: {commands: [conf t]}\n", "read-only commands"),
    ("- hosts: targets\n  tasks:\n    - cisco.ios.ios_command: {commands: [\"{{ x }}\"]}\n", "literal text"),
    ("- hosts: targets\n  tasks:\n    - cisco.ios.ios_config: {src: /tmp/x.cfg}\n", "src"),
    ("- hosts: targets\n  tasks:\n    - cisco.ios.ios_config: {lines: [reload]}\n", "destructive"),
    ("- hosts: targets\n  become: true\n  become_method: sudo\n  tasks:\n    - debug: {msg: x}\n", "become_method"),
])
def test_playbook_policy_refuses(text, needle):
    with pytest.raises(policy.PolicyError) as e:
        policy.check(text)
    assert needle in str(e.value)


def test_playbook_policy_classifies():
    assert policy.check(READ_PB)["kind"] == "read_only"
    r = policy.check(CHANGE_PB)
    assert r["kind"] == "change" and r["modules"] == ["cisco.ios.ios_config"]


async def test_playbook_library_and_runs(api, db, monkeypatch):  # noqa: F811  (pytest fixture)
    sw, _ = await _base(db)
    eng, = [await login(api, "eng1")]
    r = await api.post("/api/nms/access/playbooks", headers=eng, json={"name": "show-version", "content": READ_PB})
    assert r.status_code == 201 and r.json()["kind"] == "read_only" and r.json()["status"] == "draft"
    pid = r.json()["id"]
    assert (await api.post("/api/nms/access/playbooks", headers=eng, json={"name": "bad", "content": "- hosts: targets\n  tasks:\n    - shell: id\n"})).status_code == 422
    assert (await api.post(f"/api/nms/access/playbooks/{pid}/runs", headers=eng, json={"device_ids": [sw.id]})).status_code == 409   # not approved
    appr = await login(api, "appr1")
    assert (await api.post(f"/api/nms/access/playbooks/{pid}/approve", headers=appr, json={})).json()["approved"] is True
    eng = await login(api, "eng1")
    r = await api.post(f"/api/nms/access/playbooks/{pid}/runs", headers=eng, json={"device_ids": [sw.id]})
    assert r.status_code == 201 and r.json()["status"] == "queued"
    # editing clears the approval; the editor cannot approve their own version
    r = await api.put(f"/api/nms/access/playbooks/{pid}", headers=eng, json={"name": "show-version", "content": READ_PB + "\n# v2\n"})
    assert r.json()["approved"] is False
    # change playbooks: dry run directly, real run needs changes enabled and a second person
    c = (await api.post("/api/nms/access/playbooks", headers=eng, json={"name": "describe", "content": CHANGE_PB})).json()
    appr = await login(api, "appr1")
    await api.post(f"/api/nms/access/playbooks/{c['id']}/approve", headers=appr, json={})
    eng = await login(api, "eng1")
    assert (await api.post(f"/api/nms/access/playbooks/{c['id']}/runs", headers=eng, json={"device_ids": [sw.id], "mode": "run"})).status_code == 409
    assert (await api.post(f"/api/nms/access/playbooks/{c['id']}/runs", headers=eng, json={"device_ids": [sw.id], "mode": "check"})).json()["status"] == "queued"
    monkeypatch.setenv("NMS_CONFIG_CHANGES_ENABLED", "true")
    get_settings.cache_clear()
    try:
        r = await api.post(f"/api/nms/access/playbooks/{c['id']}/runs", headers=eng, json={"device_ids": [sw.id], "mode": "run"})
        assert r.json()["status"] == "pending_approval"
        rid = r.json()["id"]
        assert (await api.post(f"/api/nms/access/playbooks/runs/{rid}/approve", headers=eng, json={})).status_code == 403
        appr = await login(api, "appr1")
        assert (await api.post(f"/api/nms/access/playbooks/runs/{rid}/approve", headers=appr, json={})).json()["status"] == "queued"
    finally:
        get_settings.cache_clear()


FAKE_ANSIBLE = """#!/bin/sh
# stands in for ansible-playbook: shows what it was given, prints a recap
echo "ARGS: $@"
echo "HOME=$HOME"
cat "$2"
ls -la "$HOME/.ssh"
echo "PLAY RECAP *********"
echo "R1 : ok=2    changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0"
"""


async def test_runner_executes_with_a_private_inventory(db, tmp_path):
    sw, cred = await _base(db)
    sw.ssh_host_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
    unpinned = Switch(name="R2", address="192.0.2.11", vendor="cisco", family="Catalyst", site="HQ", monitoring="active", ssh_credential_id=cred.id,
                      capabilities={}, group_state={}, health={}, thresholds={})
    db.add(unpinned)
    pb = NmsPlaybook(name="v", content=READ_PB, sha256=runner.sha256(READ_PB), kind="read_only", status="approved", approved_sha256=runner.sha256(READ_PB),
                     approved_by="appr1", created_by="eng1", updated_by="eng1")
    db.add(pb)
    await db.flush()
    run = NmsPlaybookRun(playbook_id=pb.id, playbook_sha256=pb.sha256, kind="read_only", mode="run", device_ids=[sw.id, unpinned.id],
                         requested_by="eng1", status="queued")
    db.add(run)
    await db.commit()
    fake = tmp_path / "ansible-playbook"
    fake.write_text(FAKE_ANSIBLE)
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    before = set(os.listdir(os.path.dirname(os.path.realpath(__import__("tempfile").gettempdir() + "/x"))))
    r = await runner.execute(run.id, bin_path=str(fake))
    assert r.status == "done", (r.error, r.output)
    assert r.hosts["R1"]["ok"] == 2 and "no pinned SSH host key" in r.hosts["R2"]["skipped_reason"]
    assert "pw-123456" not in r.output and "ansible_host: 192.0.2.10" in r.output and "R2" not in r.output.split("PLAY RECAP")[0]
    assert "known_hosts" in r.output and "--forks" in r.output
    after = set(os.listdir(os.path.dirname(os.path.realpath(__import__("tempfile").gettempdir() + "/x"))))
    assert not any(x.startswith(f"pbrun-{run.id}-") for x in after - before)              # work directory removed
    # a tampered playbook (content changed after approval) does not run
    pb.content = READ_PB + "\n# tampered\n"
    run2 = NmsPlaybookRun(playbook_id=pb.id, playbook_sha256=pb.sha256, kind="read_only", mode="run", device_ids=[sw.id], requested_by="eng1")
    db.add(run2)
    await db.commit()
    r2 = await runner.execute(run2.id, bin_path=str(fake))
    assert r2.status == "failed" and "changed or is no longer approved" in r2.error


def test_recap_parse():
    out = "PLAY RECAP\nsw-1 : ok=3 changed=1 unreachable=0 failed=0 skipped=2 rescued=0 ignored=0\nsw-2 : ok=0 changed=0 unreachable=1 failed=0\n"
    assert runner.recap(out) == {"sw-1": {"ok": 3, "changed": 1, "unreachable": 0, "failed": 0, "skipped": 2},
                                 "sw-2": {"ok": 0, "changed": 0, "unreachable": 1, "failed": 0, "skipped": 0}}


ANSIBLE_BIN = os.environ.get("ANSIBLE_TEST_BIN", "")


@pytest.mark.skipif(not ANSIBLE_BIN, reason="set ANSIBLE_TEST_BIN (and ANSIBLE_COLLECTIONS_PATH) to run real ansible-playbook against the simulator")
async def test_real_ansible_against_simulated_ios(db, device_ssh_sim, monkeypatch):
    monkeypatch.setattr(runner, "SSH_PORT", 22022)
    sw, cred = await _base(db)
    sw.address = "127.0.0.1"
    sw.ssh_host_key = device_ssh_sim["key"]
    db.add(SwitchNetwork(cidr="127.0.0.0/8"))
    pb = NmsPlaybook(name="v", content=READ_PB, sha256=runner.sha256(READ_PB), kind="read_only", status="approved", approved_sha256=runner.sha256(READ_PB),
                     approved_by="appr1", created_by="eng1", updated_by="eng1")
    db.add(pb)
    await db.flush()
    run = NmsPlaybookRun(playbook_id=pb.id, playbook_sha256=pb.sha256, kind="read_only", mode="run", device_ids=[sw.id], requested_by="eng1")
    db.add(run)
    await db.commit()
    import app.switches.poller as P
    orig = P.validate_address
    P.validate_address = lambda a, n: a                    # loopback is refused in production; the simulator lives there
    try:
        r = await runner.execute(run.id, bin_path=ANSIBLE_BIN)
    finally:
        P.validate_address = orig
    assert r.status == "done", r.output[-3000:]
    assert r.hosts["R1"]["ok"] >= 1 and r.hosts["R1"]["failed"] == 0


@pytest.fixture
async def device_ssh_sim():
    """An IOS-like shell for real Ansible network_cli (prompt, terminal length / width, show version)."""
    async def handle(proc):
        proc.stdout.write("\r\nR1#")
        while True:
            try:
                line = await proc.stdin.readline()
            except (asyncssh.BreakReceived, asyncssh.SignalReceived, asyncssh.TerminalSizeChanged):
                continue
            except Exception:
                break
            if not line:
                break
            line = line.strip()
            if line == "exit":
                break
            if line.startswith("show version"):
                proc.stdout.write("\r\nCisco IOS XE Software, Version 17.9.4a\r\nR1 uptime is 1 week\r\n")
            elif line.startswith("show ip interface brief"):
                proc.stdout.write("\r\nInterface IP-Address OK? Method Status Protocol\r\n")
            proc.stdout.write("\r\nR1#")
        proc.exit(0)
    key = asyncssh.generate_private_key("ssh-ed25519")
    srv = await asyncssh.create_server(_Srv, "127.0.0.1", 22022, server_host_keys=[key], process_factory=handle)
    yield {"key": key.export_public_key("openssh").decode().strip()}
    srv.close()


@pytest.fixture(autouse=True)
def _python_path_for_fake():
    sys.path.insert(0, os.path.dirname(__file__))
    yield
    sys.path.remove(os.path.dirname(__file__))
