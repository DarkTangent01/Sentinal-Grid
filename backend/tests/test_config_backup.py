"""Read-only SSH configuration backup (app/configs). The SSH path is tested against a real asyncssh server on loopback
that answers only the expected show command and records every command it receives."""
from datetime import datetime, timedelta, timezone

import asyncssh
import pytest
from sqlalchemy import select

from app.configs import backup as B
from app.configs.alerts import housekeeping, rule_switch_config_changed, rule_switch_ssh_hostkey_changed
from app.db.models import DeviceConfigSnapshot, DeviceSshCredential, Switch, SwitchNetwork

from .test_api import api  # noqa: F401  (fixture)

CONFIG = """Building configuration...

Current configuration : 2048 bytes
! Last configuration change at 10:00:00 UTC Fri Nov 13 2026 by admin
hostname ACC1
enable secret 9 $9$abcdefghijklmnop
username netops privilege 15 secret 9 $9$qrstuvwxyz
snmp-server community S3cretCommunity RO
tacacs server ISE
 key 7 0822455D0A16
interface GigabitEthernet1/0/1
 description uplink
end
"""


class _Srv(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return username == "backup" and password == "pw-123456"


@pytest.fixture
async def sshd():
    seen: list[str] = []
    state = {"config": CONFIG}

    async def handle(proc):
        seen.append(proc.command or "<shell>")
        if proc.command == "show running-config":
            proc.stdout.write(state["config"])
            proc.exit(0)
        else:
            proc.stderr.write("% Invalid input")
            proc.exit(1)
    key = asyncssh.generate_private_key("ssh-ed25519")
    srv = await asyncssh.create_server(_Srv, "127.0.0.1", 0, server_host_keys=[key], process_factory=handle)
    port = srv.sockets[0].getsockname()[1]
    yield {"port": port, "seen": seen, "state": state, "key": key, "server": srv}
    srv.close()
    await srv.wait_closed()


def test_masking_and_normalisation():
    t = B.mask(B.normalise(CONFIG))
    assert "S3cretCommunity" not in t and "$9$abc" not in t and "0822455D0A16" not in t and "qrstuvwxyz" not in t
    assert "snmp-server community <masked> RO" in t and "enable secret 9 <masked>" in t and " key 7 <masked>" in t
    assert "Last configuration change" not in t and "Current configuration" not in t and t.startswith("hostname ACC1")
    j = B.mask('set system root-authentication encrypted-password "$6$xyz"\nset snmp community public authorization read-only')
    assert "$6$xyz" not in j and "public" not in j
    assert B.ALLOWED == {"show running-config", "show configuration | display set | no-more", "skip-page-display"}


async def test_fetch_runs_only_the_show_command_and_pins_the_host_key(sshd):
    out, key = await B.fetch("127.0.0.1", sshd["port"], "backup", {"password": "pw-123456"}, "", "cisco", 10)
    assert "hostname ACC1" in out and key.startswith("ssh-ed25519 ") and sshd["seen"] == ["show running-config"]
    out2, _ = await B.fetch("127.0.0.1", sshd["port"], "backup", {"password": "pw-123456"}, key, "cisco", 10)   # pinned key: accepted
    assert out2 == out
    other = asyncssh.generate_private_key("ssh-ed25519").export_public_key("openssh").decode().strip()
    with pytest.raises(B.BackupError) as e:
        await B.fetch("127.0.0.1", sshd["port"], "backup", {"password": "pw-123456"}, other, "cisco", 10)
    assert e.value.kind == "host_key_changed"
    with pytest.raises(B.BackupError) as e:
        await B.fetch("127.0.0.1", sshd["port"], "backup", {"password": "wrong"}, "", "cisco", 10)
    assert e.value.kind == "auth"
    assert sshd["seen"] == ["show running-config", "show running-config"]       # nothing ran on the refused connections


async def _device(db):
    db.add(SwitchNetwork(cidr="192.0.2.0/24", site="HQ"))
    cred = DeviceSshCredential(name="backup", username="backup", secret_ciphertext=B.seal("pw-123456"))
    db.add(cred)
    await db.flush()
    sw = Switch(name="ACC1", address="192.0.2.10", vendor="cisco", monitoring="active", state="up", ssh_credential_id=cred.id,
                capabilities={}, group_state={}, health={}, thresholds={})
    db.add(sw)
    await db.commit()
    return sw


async def test_backup_stores_only_changes_with_a_diff_and_alerts(db, sshd, ch):
    sw = await _device(db)
    calls = []

    async def via_sshd(host, port, user, secret, host_key, vendor, timeout):
        calls.append((host, vendor))
        return await B.fetch("127.0.0.1", sshd["port"], user, secret, host_key, vendor, timeout)
    t0 = datetime(2026, 11, 13, 10, tzinfo=timezone.utc)
    r = await B.backup_switch(db, sw, now=t0, fetcher=via_sshd)
    assert r["ok"] and not r["changed"] and calls == [("192.0.2.10", "cisco")] and sw.ssh_host_key.startswith("ssh-ed25519")
    r = await B.backup_switch(db, sw, now=t0 + timedelta(hours=1), fetcher=via_sshd)     # same config, new timestamp line
    assert r["ok"] and not r["changed"]
    assert len((await db.execute(select(DeviceConfigSnapshot))).scalars().all()) == 1
    sshd["state"]["config"] = CONFIG.replace(" description uplink", " description uplink to DIST\n shutdown")
    r = await B.backup_switch(db, sw, now=t0 + timedelta(hours=2), trigger="trap", fetcher=via_sshd)
    assert r["changed"] and r["added"] == 2 and r["removed"] == 1
    snap = await db.get(DeviceConfigSnapshot, r["snapshot_id"])
    assert "+ shutdown" in snap.diff and "S3cretCommunity" not in snap.diff + snap.text and snap.trigger == "trap"
    (alert,) = await rule_switch_config_changed(ch, t0 + timedelta(hours=2, minutes=5), {"window_minutes": 120})
    assert alert.evidence["added"] == 2 and "trap backup" in alert.explanation
    # host key changes: backup refused, alert raised, nothing stored
    sw.ssh_host_key = asyncssh.generate_private_key("ssh-ed25519").export_public_key("openssh").decode().strip()
    await db.commit()
    r = await B.backup_switch(db, sw, now=t0 + timedelta(hours=3), fetcher=via_sshd)
    assert not r["ok"] and r["kind"] == "host_key_changed"
    (hk,) = await rule_switch_ssh_hostkey_changed(ch, t0, {})
    assert hk.evidence["switch"] == "ACC1"
    # an address outside the authorised networks is never contacted
    sw.address = "198.51.100.7"
    calls.clear()
    r = await B.backup_switch(db, sw, now=t0, fetcher=via_sshd)
    assert not r["ok"] and r["kind"] == "config" and calls == []


async def test_due_selection_and_retention(db, ch, monkeypatch):
    sw = await _device(db)
    seen = []

    async def ok(host, port, user, secret, host_key, vendor, timeout):
        seen.append(host)
        return CONFIG, "ssh-ed25519 AAAA"
    now = datetime.now(timezone.utc)
    assert (await B.run_due(ch, db, now, fetcher=ok))["due"] == 1
    await db.refresh(sw)
    assert (await B.run_due(ch, db, now + timedelta(hours=1), fetcher=ok))["due"] == 0          # backed up within the interval
    assert (await B.run_due(ch, db, now + timedelta(hours=25), fetcher=ok))["due"] == 1
    old = DeviceConfigSnapshot(switch_id=sw.id, taken_at=now - timedelta(days=500), config_hash="x", text="old")
    db.add(old)
    await db.commit()
    assert await housekeeping(db, now, 400) == 1
    await db.commit()
    assert len((await db.execute(select(DeviceConfigSnapshot))).scalars().all()) == 1       # the newest is always kept


async def test_api_is_admin_for_text_and_never_returns_secrets(api, db):  # noqa: F811
    from .test_iac import As
    sw = await _device(db)
    db.add(DeviceConfigSnapshot(switch_id=sw.id, taken_at=datetime.now(timezone.utc), config_hash="h", text="hostname ACC1", trigger="first"))
    await db.commit()
    A_ = await As.login(api, "admin1")
    N = await As.login(api, "analyst1")
    creds = (await A_.get("/api/nms/config/credentials")).json()["items"]
    assert creds[0]["has_secret"] and "pw-123456" not in str(creds) and "secret_ciphertext" not in str(creds)
    assert (await N.get("/api/nms/config/credentials")).status_code == 403
    dev = next(d for d in (await N.get("/api/nms/config/devices")).json()["items"] if d["id"] == sw.id)
    assert dev["supported"] and dev["commands"] == ["show running-config"] and dev["ssh_credential"] == "backup"
    ch_ = (await N.get("/api/nms/config/changes")).json()["items"]
    assert ch_[0]["switch"] == "ACC1" and "text" not in ch_[0]
    assert (await N.get(f"/api/nms/config/snapshots/{ch_[0]['id']}")).status_code == 403
    assert (await A_.get(f"/api/nms/config/snapshots/{ch_[0]['id']}")).json()["text"] == "hostname ACC1"
    r = await A_.post("/api/nms/config/credentials", json={"name": "k", "username": "u"})
    assert r.status_code == 422
    assert (await A_.post(f"/api/nms/config/devices/{sw.id}/backup")).json()["queued"]


