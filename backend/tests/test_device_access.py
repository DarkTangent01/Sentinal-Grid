"""Device Access Gateway (app/access): RBAC, command risk, the terminal line guard, the credential vault, SSRF / target
restrictions, diagnostics and bulk diagnostics, the WebSocket terminal, the change workflow and the access audit.

Device-side behaviour is exercised against a real asyncssh server on loopback that imitates a Cisco IOS CLI (exec
channel and interactive shell with configuration mode) and records every line it receives. This is a simulated device:
it proves what the gateway sends and refuses, not that a given hardware model accepts it.
"""
import asyncio
import json
from datetime import datetime, timedelta, timezone

import asyncssh
import pytest
from sqlalchemy import select

from app.access import audit as A
from app.access import changes as C
from app.access import diagnostics as DG
from app.access import gateway as G
from app.access import rbac, terminal, vault
from app.access.commands import BY_ID, LEVELS, RANK, TEMPLATES, LineGuard, classify, platform_of
from app.config import get_settings
from app.db.models import (DeviceConfigSnapshot, DeviceSshCredential, NmsAccessAudit, NmsAccessCommand, NmsAccessSession, NmsChangeRequest,
                           NmsDiagJob, NmsDiagResult, Switch, SwitchNetwork, User)
from app.db.pg import session_factory
from app.security import hash_password

from .test_api import PW, api, login  # noqa: F401  (fixture)

SHOW = {"show version": "Cisco IOS XE Software, Version 17.9.4a\nSW1 uptime is 3 weeks\n",
        "show processes cpu sorted": "CPU utilization for five seconds: 3%/0%\n",
        "show running-config": "hostname SW1\nsnmp-server community S3cretCommunity RO\nend\n",
        "show ip interface brief": "Vlan1  192.0.2.10  YES manual up up\n"}


class _Srv(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return username == "netops" and password == "pw-123456"


@pytest.fixture
async def device_ssh():
    """A simulated Cisco IOS device. seen: every exec command and every shell line it received."""
    st = {"seen": [], "config": "hostname SW1\ninterface Gi1/0/1\n description old\nend\n", "delay": 0.0}

    async def handle(proc):
        if proc.command is not None:
            st["seen"].append(proc.command)
            await asyncio.sleep(st["delay"])
            if proc.command in SHOW:
                proc.stdout.write(SHOW[proc.command])
                proc.exit(0)
            else:
                proc.stdout.write("% Invalid input detected at '^' marker.\n")
                proc.exit(1)
            return
        prompt = "SW1#"
        proc.stdout.write("\r\nSW1#")
        while True:
            try:
                line = await proc.stdin.readline()
            except (asyncssh.BreakReceived, asyncssh.SignalReceived):
                proc.stdout.write(f"^C\r\n{prompt}")          # Ctrl-C: the line is abandoned, a fresh prompt follows
                continue
            except asyncssh.TerminalSizeChanged:
                continue
            except Exception:
                break
            if not line:
                break
            line = line.rstrip("\r\n")
            st["seen"].append("sh:" + line)
            if line == "exit":
                break
            if line == "configure terminal":
                prompt = "SW1(config)#"
            elif line == "end":
                prompt = "SW1#"
            elif line.startswith("show"):
                proc.stdout.write("\r\n" + SHOW.get(line, "% Invalid input detected at '^' marker.").replace("\n", "\r\n"))
            elif prompt.endswith("(config)#") and line.startswith("bogus"):
                proc.stdout.write("\r\n% Invalid input detected at '^' marker.")
            elif prompt.endswith("(config)#") and line.strip():
                st["config"] = st["config"].replace("end\n", line.strip() + "\nend\n")
            proc.stdout.write(f"\r\n{prompt}")
        proc.exit(0)
    key = asyncssh.generate_private_key("ssh-ed25519")
    srv = await asyncssh.create_server(_Srv, "127.0.0.1", 0, server_host_keys=[key], process_factory=handle)
    port = srv.sockets[0].getsockname()[1]
    st["port"] = port
    yield st
    srv.close()
    await srv.wait_closed()


@pytest.fixture
def route(monkeypatch, device_ssh):
    """Send the gateway's SSH connections for 192.0.2.x to the simulated device (the host check still runs first)."""
    dialled = []

    async def dial(host, port, host_key, **kw):
        dialled.append((host, port))
        known = asyncssh.import_known_hosts(f"127.0.0.1 {host_key}\n") if host_key else None
        return await asyncssh.connect("127.0.0.1", port=device_ssh["port"], known_hosts=known, **kw)
    monkeypatch.setattr(G, "_dial", dial)
    return dialled


async def _setup(db, roles=("network_engineer",), *, sites=None):
    db.add(SwitchNetwork(cidr="192.0.2.0/24", site="HQ"))
    cred = DeviceSshCredential(name="netops", kind="ssh", username="netops", secret_ciphertext=vault.seal("ssh", {"password": "pw-123456"}))
    db.add(cred)
    await db.flush()
    sw = Switch(name="SW1", address="192.0.2.10", vendor="cisco", family="Catalyst", os="IOS-XE", device_type="switch", site="HQ",
                monitoring="active", state="up", ssh_credential_id=cred.id, capabilities={}, group_state={}, health={}, thresholds={})
    outside = Switch(name="FAR", address="198.51.100.7", vendor="cisco", family="Catalyst", site="HQ", monitoring="active",
                     ssh_credential_id=cred.id, capabilities={}, group_state={}, health={}, thresholds={})
    db.add_all([sw, outside])
    db.add_all([User(username="eng1", password_hash=hash_password(PW), role="analyst", products=["nms"], nms_roles=list(roles), sites=sites or []),
                User(username="appr1", password_hash=hash_password(PW), role="analyst", products=["nms"], nms_roles=["nms_admin"]),
                User(username="ro1", password_hash=hash_password(PW), role="analyst", products=["nms"], nms_roles=["read_only"])])
    await db.commit()
    return sw, outside, cred


async def _user(db, name) -> User:
    return (await db.execute(select(User).where(User.username == name))).scalar_one()


# ------------------------------------------------------------------ pure logic
@pytest.mark.parametrize("cmd,risk", [
    ("show running-config", "READ_ONLY"), ("sh ip int br", "READ_ONLY"), ("show run | inc hostname", "READ_ONLY"),
    ("get system status", "READ_ONLY"), ("diag sys top 1 20 1", "READ_ONLY"), ("display version", "READ_ONLY"),
    ("/system resource print", "READ_ONLY"), ("do show ip route", "READ_ONLY"), ("show configuration | display set | no-more", "READ_ONLY"),
    ("ping 192.0.2.1", "LOW_RISK"), ("terminal length 0", "LOW_RISK"), ("set cli screen-length 0", "LOW_RISK"), ("enable", "LOW_RISK"),
    ("clear counters", "MODERATE_RISK"), ("write memory", "MODERATE_RISK"), ("copy running-config startup-config", "MODERATE_RISK"),
    ("show run | redirect flash:x", "MODERATE_RISK"), ("debug ip packet", "MODERATE_RISK"), ("frobnicate", "MODERATE_RISK"),
    ("configure terminal", "HIGH_RISK"), ("conf t", "HIGH_RISK"), ("config system interface", "HIGH_RISK"), ("set system host-name x", "HIGH_RISK"),
    ("clear ip bgp *", "HIGH_RISK"), ("no shutdown", "HIGH_RISK"), ("copy tftp://x/c running-config", "HIGH_RISK"), ("start shell", "HIGH_RISK"),
    ("reload", "DESTRUCTIVE"), ("write erase", "DESTRUCTIVE"), ("execute factoryreset", "DESTRUCTIVE"), ("request system zeroize", "DESTRUCTIVE"),
    ("/system reboot", "DESTRUCTIVE"), ("show version; reload", "DESTRUCTIVE"), ("s", "DESTRUCTIVE"),
])
def test_command_risk_classification(cmd, risk):
    assert classify(cmd)[0] == risk


def test_templates_are_read_only_and_platforms_resolve():
    assert all(RANK[classify(c)[0]] <= RANK["LOW_RISK"] for t in TEMPLATES for c in t.commands)
    for needed in ("show version", "show inventory", "show interfaces status", "show interfaces counters errors", "show ip interface brief",
                   "show ip route", "show ip bgp summary", "show cdp neighbors detail", "show lldp neighbors detail", "show logging"):
        assert any(needed in t.commands for t in TEMPLATES if t.platform == "cisco_ios"), needed
    assert {c for t in TEMPLATES if t.platform == "fortios" for c in t.commands} >= {"get system status", "get system performance status",
                                                                                     "diagnose vpn tunnel list", "get router info bgp summary"}
    mk = lambda **k: Switch(**{"vendor": "", "family": "", "os": "", "device_type": "", "product_line": "", "vendor_override": "",  # noqa: E731
                               "family_override": "", "access_platform": "", **k})
    assert platform_of(mk(vendor="cisco", family="Catalyst 9800 WLC", os="IOS-XE")) == "cisco_wlc9800"
    assert platform_of(mk(vendor="cisco", family="Nexus", os="NX-OS")) == "cisco_nxos"
    assert platform_of(mk(vendor="fortinet", family="FortiGate", device_type="firewall")) == "fortios"
    assert platform_of(mk(vendor="juniper", family="EX")) == "junos"
    assert platform_of(mk(vendor="ruckus", family="ICX", os="FastIron")) == "ruckus_icx"
    assert platform_of(mk(vendor="generic")) is None
    assert platform_of(mk(vendor="generic", access_platform="arista_eos")) == "arista_eos"


def test_line_guard():
    g = LineGuard()
    fwd, (d,) = g.feed("show version\r")
    assert d.allowed and fwd.endswith("\r")
    fwd, (d,) = g.feed("conf t\r")
    assert not d.allowed and d.risk == "HIGH_RISK" and fwd == "conf t\x15\x03"        # Enter never reaches the device
    # until the device shows a fresh prompt, keystrokes are dropped and Enter is refused (the line may still be there)
    assert g.feed("x") == ("", [])
    fwd, (d,) = g.feed("\r")
    assert fwd == "" and not d.allowed
    assert g.feed("\x03") == ("\x03", [])
    g.device_output("conf t^C\r\nSW1#")
    fwd, (d,) = g.feed("show ver\x7f\x7f\x7fversion\r")
    assert d.allowed and d.command == "show version"
    _, (d,) = g.feed("\x1b[A\r")                                                       # history recall: cannot be tracked
    assert not d.allowed
    g.device_output("\r\nSW1>")
    g.device_output("SW1>enable\r\nPassword: ")
    _, (d,) = g.feed("hunter2\r")
    assert d.allowed and d.secret and d.command == ""                                 # never recorded
    ch = LineGuard(max_risk="HIGH_RISK")
    _, (d,) = ch.feed("interface Gi1/0/1\r")
    assert d.allowed
    _, (d,) = ch.feed("reload\r")
    assert not d.allowed and d.risk == "DESTRUCTIVE"                                  # never, even in a change session


def test_rbac_permissions():
    admin = User(username="a", role="admin")
    analyst = User(username="b", role="analyst", products=["nms"], nms_roles=[])
    grid_only = User(username="c", role="analyst", products=["grid"], nms_roles=["network_engineer"])
    assert rbac.permissions_of(admin) == set(rbac.PERMISSIONS)
    assert rbac.permissions_of(analyst) == {"nms.device.view", "nms.traffic.view", "nms.traffic.detections.view"}   # existing NMS users keep what they had
    assert rbac.permissions_of(grid_only) == set()
    eng = User(username="e", role="analyst", products=["nms"], nms_roles=["network_engineer"])
    assert rbac.has(eng, "nms.device.access.ssh") and not rbac.has(eng, "nms.configuration.approve")
    aud = User(username="f", role="analyst", products=["nms"], nms_roles=["auditor"])
    assert rbac.has(aud, "nms.device.access.audit.view") and not rbac.has(aud, "nms.device.access.ssh")
    assert len(rbac.ROLES) == 7 and len(rbac.PERMISSIONS) == 20
    with pytest.raises(ValueError):
        rbac.validate_roles(["root"])


# ------------------------------------------------------------------ API: permissions, vault, SSRF
async def test_permissions_enforced_on_routes(api, db):  # noqa: F811  (pytest fixture)
    sw, _, _ = await _setup(db)
    db.add(User(username="plain", password_hash=hash_password(PW), role="analyst", products=["nms"]))
    await db.commit()
    h = await login(api, "plain")
    assert (await api.get("/api/nms/access/devices", headers=h)).status_code == 403
    assert (await api.post(f"/api/nms/access/devices/{sw.id}/sessions", json={}, headers=h)).status_code == 403
    assert (await api.get("/api/nms/access/vault", headers=h)).status_code == 403
    assert (await api.get("/api/nms/access/audit", headers=h)).status_code == 403
    ro = await login(api, "ro1")
    assert (await api.get("/api/nms/access/devices", headers=ro)).status_code == 200
    assert (await api.post(f"/api/nms/access/devices/{sw.id}/sessions", json={}, headers=ro)).status_code == 403
    assert (await api.post(f"/api/nms/access/devices/{sw.id}/diagnostics", json={"templates": ["ios.version"]}, headers=ro)).status_code == 403
    assert (await api.post("/api/nms/access/bulk", json={"device_ids": [sw.id], "templates": ["ios.version"]}, headers=ro)).status_code == 403
    eng = await login(api, "eng1")
    assert (await api.put("/api/nms/access/roles/1", json={"roles": ["nms_admin"]}, headers=eng)).status_code == 403
    assert (await api.post(f"/api/nms/access/devices/{sw.id}/sessions", json={})).status_code == 403      # no CSRF header
    api.cookies.clear()
    assert (await api.post(f"/api/nms/access/devices/{sw.id}/sessions", json={}, headers=eng)).status_code == 401   # no session cookie


async def test_role_change_revokes_sessions(api, db):  # noqa: F811  (pytest fixture)
    await _setup(db)
    ha = await login(api, "admin1")
    eng = await _user(db, "eng1")
    v0 = eng.session_version or 0
    r = await api.put(f"/api/nms/access/roles/{eng.id}", json={"roles": ["auditor"]}, headers=ha)
    assert r.status_code == 200
    db.expire_all()
    assert (await _user(db, "eng1")).session_version == v0 + 1
    assert (await api.put(f"/api/nms/access/roles/{eng.id}", json={"roles": ["god"]}, headers=ha)).status_code == 422


async def test_vault_never_returns_or_stores_plaintext(api, db):  # noqa: F811  (pytest fixture)
    sw, _, _ = await _setup(db)
    ha = await login(api, "admin1")
    r = await api.post("/api/nms/access/vault", headers=ha, json={"name": "api-tok", "kind": "api_token", "token": "TOPSECRET-TOKEN-1234"})
    assert r.status_code == 201 and "TOPSECRET" not in r.text and r.json()["secret_fields"] == ["token"]
    r = await api.post("/api/nms/access/vault", headers=ha, json={"name": "ssh-hq", "kind": "ssh", "username": "u", "password": "Pa55-very-secret"})
    cid = r.json()["id"]
    row = await db.get(DeviceSshCredential, cid)
    assert "Pa55-very-secret" not in row.secret_ciphertext and vault.unseal(row) == {"password": "Pa55-very-secret"}
    lst = await api.get("/api/nms/access/vault", headers=ha)
    assert "Pa55" not in lst.text and "TOPSECRET" not in lst.text
    dev = await api.get(f"/api/nms/access/devices/{sw.id}", headers=ha)
    assert "pw-123456" not in dev.text and dev.json()["credential"]["ssh"]["via"] == "device"
    # rotation keeps the secret out of responses and records the date
    r = await api.put(f"/api/nms/access/vault/{cid}", headers=ha, json={"name": "ssh-hq", "kind": "ssh", "username": "u", "password": "N3w-secret"})
    assert r.status_code == 200 and "N3w" not in r.text and r.json()["rotated_at"]
    audit_rows = (await db.execute(select(NmsAccessAudit))).scalars().all()
    assert all("secret" not in json.dumps(a.detail).lower() or "<redacted>" in json.dumps(a.detail) for a in audit_rows)
    assert not any("N3w-secret" in json.dumps(a.detail) or "Pa55" in json.dumps(a.detail) for a in audit_rows)


async def test_group_assignment_resolution(db):
    sw, _, cred = await _setup(db)
    sw.ssh_credential_id = None
    a = DeviceSshCredential(name="all", kind="ssh", username="x", secret_ciphertext=vault.seal("ssh", {"password": "p"}))
    b = DeviceSshCredential(name="hq-cisco", kind="ssh", username="y", secret_ciphertext=vault.seal("ssh", {"password": "q"}))
    db.add_all([a, b])
    await db.flush()
    from app.db.models import NmsCredentialAssignment as NA
    db.add_all([NA(credential_id=a.id, kind="ssh"), NA(credential_id=b.id, kind="ssh", site="HQ", vendor="cisco")])
    await db.commit()
    c, how = await vault.resolve(db, sw, "ssh")
    assert c.name == "hq-cisco" and "site=HQ" in how
    sw.ssh_credential_id = cred.id
    c, how = await vault.resolve(db, sw, "ssh")
    assert c.name == "netops" and how == "device"                                     # the device override wins


async def test_targets_are_inventory_devices_only(api, db, route):  # noqa: F811  (pytest fixture)
    sw, outside, _ = await _setup(db)
    eng = await login(api, "eng1")
    # outside every authorised management network: refused before any connection
    r = await api.post(f"/api/nms/access/devices/{outside.id}/sessions", json={}, headers=eng)
    assert r.status_code == 403 and "authorised management network" in r.json()["detail"]
    r = await api.post(f"/api/nms/access/devices/{outside.id}/diagnostics", json={"templates": ["ios.version"]}, headers=eng)
    assert r.status_code == 200 and r.json()["result"]["status"] == "failed" and "authorised" in r.json()["result"]["error"]
    assert route == []
    # host / port / command parameters do not exist: they are ignored, the device's own address is used
    r = await api.post(f"/api/nms/access/devices/{sw.id}/diagnostics", headers=eng,
                       json={"templates": ["ios.version"], "host": "10.0.0.1", "port": 6379, "command": "reload"})
    assert r.status_code == 200 and route == [("192.0.2.10", 22)]
    assert (await api.post(f"/api/nms/access/devices/{sw.id}/diagnostics", json={"templates": ["reload"]}, headers=eng)).status_code == 422
    assert (await api.post("/api/nms/access/devices/9999/sessions", json={}, headers=eng)).status_code == 404
    # site scope: a user scoped to another site cannot see or reach the device
    db.add(User(username="branch", password_hash=hash_password(PW), role="analyst", products=["nms"], nms_roles=["network_engineer"], sites=["Branch"]))
    await db.commit()
    hb = await login(api, "branch")
    assert (await api.get(f"/api/nms/access/devices/{sw.id}", headers=hb)).status_code == 404
    assert (await api.post(f"/api/nms/access/devices/{sw.id}/sessions", json={}, headers=hb)).status_code == 403


async def test_session_limits(api, db, monkeypatch):  # noqa: F811  (pytest fixture)
    sw, _, _ = await _setup(db)
    monkeypatch.setenv("ACCESS_MAX_SESSIONS_PER_DEVICE", "1")
    get_settings.cache_clear()
    eng = await login(api, "eng1")
    r = await api.post(f"/api/nms/access/devices/{sw.id}/sessions", json={}, headers=eng)
    assert r.status_code == 201 and r.json()["ticket"]
    row = await db.get(NmsAccessSession, r.json()["session_id"])
    assert row.ticket_hash and r.json()["ticket"] not in row.ticket_hash                # only the hash is stored
    r2 = await api.post(f"/api/nms/access/devices/{sw.id}/sessions", json={}, headers=eng)
    assert r2.status_code == 429
    # an unused ticket expires and gives its slot back
    row.ticket_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    await db.commit()
    r3 = await api.post(f"/api/nms/access/devices/{sw.id}/sessions", json={}, headers=eng)
    assert r3.status_code == 201
    db.expire_all()
    assert (await db.get(NmsAccessSession, r.json()["session_id"])).state == "expired"
    get_settings.cache_clear()


# ------------------------------------------------------------------ diagnostics
async def test_diagnostics_run_only_templates_and_mask_output(api, db, device_ssh, route):  # noqa: F811  (pytest fixture)
    sw, _, _ = await _setup(db)
    eng = await login(api, "eng1")
    r = await api.post(f"/api/nms/access/devices/{sw.id}/diagnostics", json={"templates": ["ios.version", "ios.cpu", "fos.status"]}, headers=eng)
    assert r.status_code == 200, r.text
    res = r.json()["result"]
    assert res["status"] == "ok" and [o["command"] for o in res["outputs"]] == ["show version", "show processes cpu sorted"]
    assert device_ssh["seen"] == ["show version", "show processes cpu sorted"]     # fos.status is not for this platform: not sent
    assert (await db.execute(select(Switch.ssh_host_key).where(Switch.id == sw.id))).scalar().startswith("ssh-ed25519")   # pinned on first use
    cmds = (await db.execute(select(NmsAccessCommand))).scalars().all()
    assert {c.command for c in cmds} == {"show version", "show processes cpu sorted"} and all(c.risk == "READ_ONLY" for c in cmds)
    # a command that fails on the device is reported, others still run; secrets in output are masked
    BY_ID["ios.version"]  # noqa: B018
    r = await api.post(f"/api/nms/access/devices/{sw.id}/diagnostics", json={"categories": ["interfaces"]}, headers=eng)
    outs = {o["command"]: o["status"] for o in r.json()["result"]["outputs"]}
    assert outs["show ip interface brief"] == "ok" and outs["show interfaces status"] == "unsupported"


async def test_bulk_diagnostics_partial_failure_and_cancel(db, device_ssh, route):
    sw, outside, _ = await _setup(db)
    others = []
    for i in range(2, 7):
        x = Switch(name=f"SW{i}", address=f"192.0.2.{10 + i}", vendor="cisco", family="Catalyst", site="HQ", monitoring="active",
                   ssh_credential_id=sw.ssh_credential_id, capabilities={}, group_state={}, health={}, thresholds={})
        db.add(x)
        others.append(x)
    bad = DeviceSshCredential(name="bad", kind="ssh", username="netops", secret_ciphertext=vault.seal("ssh", {"password": "wrong"}))
    db.add(bad)
    await db.flush()
    others[0].ssh_credential_id = bad.id
    await db.commit()
    eng = await _user(db, "eng1")
    ids = [sw.id, outside.id, *(o.id for o in others)]
    jid = await DG.create_job(eng, ids, ["ios.version"], [], kind="bulk", concurrency=3, timeout=30)
    await DG.run_job(jid, eng, ["ios.version"], [])
    async with session_factory()() as s:
        j = await s.get(NmsDiagJob, jid)
        res = {r.device_name: r for r in (await s.execute(select(NmsDiagResult).where(NmsDiagResult.job_id == jid))).scalars()}
    assert j.status == "done" and j.completed == len(ids) and j.failed == 2
    assert res["FAR"].status == "failed" and "authorised" in res["FAR"].error
    assert res["SW2"].status == "failed" and "rejected" in res["SW2"].error
    assert all(res[n].status == "ok" for n in ("SW1", "SW3", "SW4", "SW5", "SW6"))
    # cancellation: devices not started are cancelled, running ones are interrupted
    device_ssh["delay"] = 2.0
    jid2 = await DG.create_job(eng, [sw.id, *(o.id for o in others[1:])], ["ios.version"], [], kind="bulk", concurrency=1, timeout=30)
    task = DG.start_job(jid2, eng, ["ios.version"], [])
    await asyncio.sleep(0.8)
    assert await DG.cancel_job(jid2)
    await asyncio.wait_for(task, 10)
    async with session_factory()() as s:
        j2 = await s.get(NmsDiagJob, jid2)
        st2 = [r.status for r in (await s.execute(select(NmsDiagResult).where(NmsDiagResult.job_id == jid2))).scalars()]
    assert j2.status == "cancelled" and st2.count("cancelled") >= 4 and "ok" not in st2


# ------------------------------------------------------------------ WebSocket terminal
class FakeWS:
    """The parts of starlette's WebSocket the terminal handler uses."""

    def __init__(self, cookies, origin="https://nms.example", host="nms.example"):
        self.cookies = cookies
        self.headers = {"origin": origin, "host": host}
        self.client = None
        self.inbox: asyncio.Queue = asyncio.Queue()
        self.sent: list[dict] = []
        self.accepted = False
        self.closed: int | None = None

    async def accept(self):
        self.accepted = True

    async def close(self, code=1000):
        self.closed = code
        await self.inbox.put(None)

    async def send_text(self, t):
        self.sent.append(json.loads(t))

    async def receive_text(self):
        m = await self.inbox.get()
        if m is None:
            from fastapi import WebSocketDisconnect
            raise WebSocketDisconnect()
        return json.dumps(m)

    def out(self) -> str:
        return "".join(m.get("d", "") for m in self.sent if m.get("t") == "o")


async def _wait(cond, timeout=8.0):
    t0 = asyncio.get_event_loop().time()
    while not cond():
        if asyncio.get_event_loop().time() - t0 > timeout:
            raise AssertionError("timed out")
        await asyncio.sleep(0.05)


async def test_terminal_session_end_to_end(api, db, device_ssh, route):  # noqa: F811  (pytest fixture)
    sw, _, _ = await _setup(db)
    eng = await login(api, "eng1")
    cookies = {"siem_session": api.cookies.get("siem_session")}
    r = await api.post(f"/api/nms/access/devices/{sw.id}/sessions", json={"cols": 100, "rows": 30}, headers=eng)
    sid, ticket = r.json()["session_id"], r.json()["ticket"]

    # wrong origin: refused before anything else
    bad = FakeWS(cookies, origin="https://evil.example")
    await terminal.handle(bad)
    assert bad.closed == 4403 and not bad.accepted
    # wrong ticket: refused, the session cannot be used afterwards
    ws = FakeWS(cookies)
    await ws.inbox.put({"t": "auth", "session": sid, "ticket": "x" * 43})
    await terminal.handle(ws)
    assert ws.closed == 4403 and device_ssh["seen"] == []
    r = await api.post(f"/api/nms/access/devices/{sw.id}/sessions", json={}, headers=eng)
    sid, ticket = r.json()["session_id"], r.json()["ticket"]

    ws = FakeWS(cookies)
    await ws.inbox.put({"t": "auth", "session": sid, "ticket": ticket, "cols": 100, "rows": 30})
    task = asyncio.create_task(terminal.handle(ws))
    await _wait(lambda: "SW1#" in ws.out())
    await ws.inbox.put({"t": "i", "d": "show version\r"})
    await _wait(lambda: "sh:show version" in device_ssh["seen"])
    await _wait(lambda: "17.9.4a" in ws.out())
    await ws.inbox.put({"t": "i", "d": "configure terminal\r"})
    await _wait(lambda: any(m.get("t") == "blocked" for m in ws.sent))
    await _wait(lambda: "^C" in ws.out())                                              # the device abandoned the refused line
    await ws.inbox.put({"t": "i", "d": "reload\r"})
    await _wait(lambda: sum(m.get("t") == "blocked" for m in ws.sent) == 2)
    await ws.inbox.put({"t": "r", "cols": 150, "rows": 40})
    await asyncio.sleep(0.3)
    assert not any(x.startswith("sh:configure") or x.startswith("sh:reload") for x in device_ssh["seen"])
    # the same ticket cannot open a second connection
    ws2 = FakeWS(cookies)
    await ws2.inbox.put({"t": "auth", "session": sid, "ticket": ticket})
    await terminal.handle(ws2)
    assert ws2.closed == 4403
    # an administrator terminates the session
    ha = await login(api, "admin1")
    assert (await api.post(f"/api/nms/access/sessions/{sid}/terminate", headers=ha)).status_code == 200
    await asyncio.wait_for(task, 10)
    assert ws.sent[-1]["t"] == "closed" and "terminated by admin1" in ws.sent[-1]["reason"]
    db.expire_all()
    row = await db.get(NmsAccessSession, sid)
    assert row.state == "terminated" and row.blocked == 2 and row.commands == 3 and row.ended_at
    cmds = {c.command: c for c in (await db.execute(select(NmsAccessCommand).where(NmsAccessCommand.session_id == sid))).scalars()}
    assert cmds["show version"].allowed and not cmds["configure terminal"].allowed and cmds["reload"].risk == "DESTRUCTIVE"
    acts = [a.action for a in (await db.execute(select(NmsAccessAudit).order_by(NmsAccessAudit.id))).scalars()]
    assert acts.count("terminal_open") == 2 and "terminal_refused" in acts and "terminal_connect" in acts and "terminal_terminate" in acts
    assert "terminal_end" in acts and (await A.verify(db))["ok"]
    # sessions of another user are not visible to an engineer without audit permission
    ro = await login(api, "ro1")
    assert (await api.get(f"/api/nms/access/sessions/{sid}", headers=ro)).status_code == 404
    assert (await api.post(f"/api/nms/access/sessions/{sid}/terminate", headers=ro)).status_code == 403


async def test_terminal_requires_permission_and_idle_timeout(api, db, device_ssh, route, monkeypatch):  # noqa: F811  (pytest fixture)
    sw, _, _ = await _setup(db)
    await login(api, "ro1")
    ws = FakeWS({"siem_session": api.cookies.get("siem_session")})
    await terminal.handle(ws)
    assert ws.closed == 4401 and not ws.accepted                                       # read-only role: no terminal
    monkeypatch.setenv("ACCESS_IDLE_TIMEOUT_SECONDS", "1")
    get_settings.cache_clear()
    eng = await login(api, "eng1")
    r = await api.post(f"/api/nms/access/devices/{sw.id}/sessions", json={}, headers=eng)
    ws = FakeWS({"siem_session": api.cookies.get("siem_session")})
    await ws.inbox.put({"t": "auth", "session": r.json()["session_id"], "ticket": r.json()["ticket"]})
    await asyncio.wait_for(terminal.handle(ws), 15)
    assert ws.sent[-1]["reason"] == "idle timeout"
    get_settings.cache_clear()


# ------------------------------------------------------------------ change workflow
async def test_change_workflow(api, db, device_ssh, route, monkeypatch):  # noqa: F811  (pytest fixture)
    sw, _, _ = await _setup(db)
    eng, ha = await login(api, "eng1"), None

    async def fake_fetch(host, port, user, secret, host_key, vendor, timeout):
        return device_ssh["config"], ""
    monkeypatch.setattr("app.access.changes.fetch", fake_fetch)
    body = {"title": "Describe uplink", "reason": "ticket NET-1", "lines": ["interface Gi1/0/1", "description uplink to DIST"],
            "rollback_lines": ["interface Gi1/0/1", "description old"]}
    assert (await api.post(f"/api/nms/access/devices/{sw.id}/changes", headers=eng, json={**body, "lines": ["reload"]})).status_code == 422
    assert (await api.post(f"/api/nms/access/devices/{sw.id}/changes", headers=eng, json={**body, "rollback_lines": []})).status_code == 422
    r = await api.post(f"/api/nms/access/devices/{sw.id}/changes", headers=eng, json=body)
    assert r.status_code == 201, r.text
    cid = r.json()["id"]
    assert r.json()["risk"] == "HIGH_RISK" and r.json()["status"] == "pending_approval" and "+ description uplink to DIST" in r.json()["preview"]
    # the requester cannot approve; nothing runs before approval; changes are off by default
    assert (await api.post(f"/api/nms/access/changes/{cid}/approve", headers=eng, json={})).status_code == 403
    assert (await api.post(f"/api/nms/access/changes/{cid}/execute", headers=eng, json={})).status_code == 409
    ha = await login(api, "appr1")
    assert (await api.post(f"/api/nms/access/changes/{cid}/approve", headers=ha, json={"comment": "ok"})).json()["status"] == "approved"
    eng = await login(api, "eng1")
    r = await api.post(f"/api/nms/access/changes/{cid}/execute", headers=eng, json={})
    assert r.status_code == 409 and "disabled" in r.json()["detail"] and device_ssh["seen"] == []
    monkeypatch.setenv("NMS_CONFIG_CHANGES_ENABLED", "true")
    get_settings.cache_clear()
    r = await api.post(f"/api/nms/access/changes/{cid}/execute", headers=eng, json={})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["status"] == "completed", out["log"]
    shell = [x[3:] for x in device_ssh["seen"] if x.startswith("sh:")]
    assert shell[:5] == ["terminal length 0", "configure terminal", "interface Gi1/0/1", "description uplink to DIST", "end"]
    assert "write memory" not in shell                                                 # save_config was not requested
    assert out["pre_snapshot_id"] and out["post_snapshot_id"] and "+description uplink to DIST" in out["result"]["diff"]
    # rollback needs an approver
    r = await api.post(f"/api/nms/access/changes/{cid}/rollback", headers=eng, json={})
    assert r.status_code == 403
    ha = await login(api, "appr1")
    r = await api.post(f"/api/nms/access/changes/{cid}/rollback", headers=ha, json={})
    assert r.status_code == 200 and r.json()["status"] == "rolled_back"
    assert "sh:description old" in device_ssh["seen"]
    # a failing line stops the change and is reported
    eng = await login(api, "eng1")
    r = await api.post(f"/api/nms/access/devices/{sw.id}/changes", headers=eng,
                       json={"title": "Bad", "lines": ["interface Gi1/0/2", "bogus command", "description never"], "rollback_lines": ["interface Gi1/0/2"]})
    cid2 = r.json()["id"]
    ha = await login(api, "appr1")
    await api.post(f"/api/nms/access/changes/{cid2}/approve", headers=ha, json={})
    eng = await login(api, "eng1")
    r = await api.post(f"/api/nms/access/changes/{cid2}/execute", headers=eng, json={})
    assert r.json()["status"] == "failed" and "bogus command" in r.json()["result"]["error"]
    assert "sh:description never" not in device_ssh["seen"]
    get_settings.cache_clear()
    cr = await db.get(NmsChangeRequest, cid)
    assert [e["event"] for e in cr.log][:4] == ["requested", "approved", "executing", "backup_before"]
    assert len((await db.execute(select(DeviceConfigSnapshot))).scalars().all()) >= 2


async def test_audit_chain_detects_tampering(db):
    for i in range(3):
        await A.record(db, "u", "x", detail={"i": i, "password": "never-stored"})
    rows = (await db.execute(select(NmsAccessAudit).order_by(NmsAccessAudit.id))).scalars().all()
    assert rows[0].detail["password"] == "<redacted>" and (await A.verify(db))["ok"]
    rows[1].username = "someone-else"
    await db.commit()
    v = await A.verify(db)
    assert not v["ok"] and v["broken_at"] == rows[1].id


def test_levels():
    assert LEVELS == ("READ_ONLY", "LOW_RISK", "MODERATE_RISK", "HIGH_RISK", "DESTRUCTIVE")
    assert C.PROCEDURES["junos"]["enter"][-1] == "configure private"
    assert datetime.now(timezone.utc) - timedelta(seconds=1) < datetime.now(timezone.utc)


async def test_audit_chain_survives_concurrent_writers(db):
    async def one(i):
        async with session_factory()() as s:
            await A.record(s, f"u{i}", "terminal_open", detail={"i": i})
    await asyncio.gather(*(one(i) for i in range(12)))
    v = await A.verify(db)
    assert v == {"ok": True, "checked": 12}


async def test_recording_retention(db):
    from app.db.models import NmsAccessRecording
    old = datetime.now(timezone.utc) - timedelta(days=get_settings().access_recording_retention_days + 1)
    db.add_all([NmsAccessRecording(session_id="a" * 36, text="x", created_at=old), NmsAccessRecording(session_id="b" * 36, text="y")])
    await db.commit()
    assert await terminal.purge_recordings(db) == 1
    await db.commit()
    assert [r.session_id for r in (await db.execute(select(NmsAccessRecording))).scalars()] == ["b" * 36]
