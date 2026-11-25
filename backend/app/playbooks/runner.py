"""Ansible runner service (python -m app.playbooks.runner; docker-compose service "ansible").

Takes queued playbook runs from the database, one at a time, and runs `ansible-playbook` in a private, short-lived
work directory (0700, on the container's tmpfs) that is deleted afterwards:
  * the playbook is the approved version only: its SHA-256 must equal the approved one, and the policy check runs again;
  * change playbooks need a second person's approval of the run and NMS_CONFIG_CHANGES_ENABLED; each device is backed
    up before (no backup, no run) and after the run, and the diff is stored;
  * the inventory holds only the run's devices, each with its validated management address, network OS and vault
    credential, in a 0600 file; known_hosts holds the host keys Sentinel pinned (a device without one is skipped), and
    host key checking is on with auto-add off;
  * the environment is built from scratch (no inherited secrets), the controller is the runner itself: playbooks cannot
    run local tasks (policy), and the process has a hard timeout and is stopped on cancellation;
  * output is masked before it is stored.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import shutil
import signal
import tempfile
import time
from datetime import datetime, timedelta, timezone

import yaml
from sqlalchemy import select, update

from ..config import get_settings
from ..configs.backup import mask
from ..db.models import DeviceConfigSnapshot, NmsPlaybook, NmsPlaybookRun, Switch, SwitchNetwork
from ..db.pg import session_factory
from ..access import audit, vault
from ..access.commands import platform_of
from .policy import PolicyError, check

log = logging.getLogger("playbooks.runner")
NETWORK_OS = {"cisco_ios": "cisco.ios.ios", "cisco_wlc9800": "cisco.ios.ios", "cisco_nxos": "cisco.nxos.nxos", "junos": "junipernetworks.junos.junos",
              "arista_eos": "arista.eos.eos"}
SSH_PORT = 22          # devices' SSH port (the access gateway's fixed port); tests point it at a local simulator
RECAP = re.compile(r"^(\S+)\s*:\s*ok=(\d+)\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)(?:\s+skipped=(\d+))?", re.M)


def now() -> datetime:
    return datetime.now(timezone.utc)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def recap(output: str) -> dict:
    return {m.group(1): {"ok": int(m.group(2)), "changed": int(m.group(3)), "unreachable": int(m.group(4)), "failed": int(m.group(5)),
                         "skipped": int(m.group(6) or 0)} for m in RECAP.finditer(output)}


def _write(path: str, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)


async def build_inventory(s, run: NmsPlaybookRun, work: str) -> tuple[dict, list[dict], dict]:
    """(inventory dict, skipped devices, name → switch id). Writes private keys and known_hosts into `work`."""
    from ..switches.poller import validate_address
    nets = (await s.execute(select(SwitchNetwork))).scalars().all()
    hosts, skipped, ids, known = {}, [], {}, []
    for sid in run.device_ids:
        sw = await s.get(Switch, sid)
        if sw is None:
            skipped.append({"switch_id": sid, "reason": "device not found"})
            continue
        try:
            ip = validate_address(sw.address, nets)
        except ValueError as e:
            skipped.append({"switch_id": sid, "device": sw.name, "reason": str(e)})
            continue
        nos = NETWORK_OS.get(platform_of(sw) or "")
        if nos is None:
            skipped.append({"switch_id": sid, "device": sw.name, "reason": f"no Ansible network OS for platform {platform_of(sw)}"})
            continue
        if not sw.ssh_host_key:
            skipped.append({"switch_id": sid, "device": sw.name, "reason": "no pinned SSH host key yet: open a terminal or run diagnostics once"})
            continue
        cred, _ = await vault.resolve(s, sw, "ssh")
        if cred is None:
            skipped.append({"switch_id": sid, "device": sw.name, "reason": "no SSH credential"})
            continue
        sec = vault.unseal(cred)
        name = re.sub(r"[^A-Za-z0-9_.-]", "_", sw.name)
        h = {"ansible_host": ip, "ansible_port": SSH_PORT, "ansible_network_os": nos, "ansible_connection": "ansible.netcommon.network_cli",
             "ansible_user": cred.username}
        if sec.get("private_key"):
            kp = os.path.join(work, f"key-{sid}")
            _write(kp, sec["private_key"] if sec["private_key"].endswith("\n") else sec["private_key"] + "\n")
            h["ansible_ssh_private_key_file"] = kp
        if sec.get("password"):
            h["ansible_password"] = sec["password"]
        hosts[name] = h
        ids[name] = sid
        known.append(f"{ip if SSH_PORT == 22 else f'[{ip}]:{SSH_PORT}'} {sw.ssh_host_key}")
    os.makedirs(os.path.join(work, ".ssh"), mode=0o700)
    _write(os.path.join(work, ".ssh", "known_hosts"), "\n".join(known) + "\n")
    return {"all": {"children": {"targets": {"hosts": hosts}}}}, skipped, ids


ANSIBLE_CFG = """[defaults]
host_key_checking = True
retry_files_enabled = False
interpreter_python = auto_silent
nocolor = True
gathering = explicit
deprecation_warnings = False

[paramiko_connection]
host_key_auto_add = False
record_host_keys = False
look_for_keys = False

[persistent_connection]
command_timeout = 60
connect_timeout = 30
"""


def env_for(work: str) -> dict:
    keep = {k: os.environ[k] for k in ("PATH", "LANG", "LC_ALL", "ANSIBLE_COLLECTIONS_PATH", "PYTHONPATH") if k in os.environ}
    return {**keep, "HOME": work, "ANSIBLE_CONFIG": os.path.join(work, "ansible.cfg"), "ANSIBLE_LOCAL_TEMP": os.path.join(work, "tmp"),
            "ANSIBLE_REMOTE_TEMP": os.path.join(work, "tmp"), "ANSIBLE_NETWORK_CLI_SSH_TYPE": "paramiko", "ANSIBLE_HOST_KEY_CHECKING": "True",
            "ANSIBLE_FORCE_COLOR": "0", "ANSIBLE_STDOUT_CALLBACK": "default", "ANSIBLE_GALAXY_SERVER": "https://localhost.invalid"}


async def _backups(s, ids: dict, trigger: str) -> dict:
    from ..configs.backup import backup_switch
    out = {}
    for name, sid in ids.items():
        sw = await s.get(Switch, sid)
        r = await backup_switch(s, sw, trigger=trigger)
        out[str(sid)] = {"device": name, "ok": r.get("ok"), "snapshot_id": r.get("snapshot_id"), "error": r.get("error", "")}
    return out


async def execute(run_id: int, *, bin_path: str | None = None) -> NmsPlaybookRun:
    st = get_settings()
    async with session_factory()() as s:
        run = await s.get(NmsPlaybookRun, run_id)
        pb = await s.get(NmsPlaybook, run.playbook_id)
        run.status, run.started_at = "running", now()
        await s.commit()
        work = tempfile.mkdtemp(prefix=f"pbrun-{run_id}-")
        os.chmod(work, 0o700)
        os.makedirs(os.path.join(work, "tmp"), mode=0o700)
        try:
            if pb is None or pb.status != "approved" or pb.approved_sha256 != pb.sha256 or sha256(pb.content) != pb.sha256 or run.playbook_sha256 != pb.sha256:
                raise RuntimeError("the playbook changed or is no longer approved since the run was requested")
            res = check(pb.content)
            if res["kind"] != run.kind:
                raise RuntimeError("the playbook's classification changed")
            if run.kind == "change" and run.mode == "run":
                if not st.nms_config_changes_enabled:
                    raise RuntimeError("configuration changes are disabled (NMS_CONFIG_CHANGES_ENABLED)")
                if not run.approved_by or run.approved_by == run.requested_by:
                    raise RuntimeError("a change run needs approval by a second person")
            inv, skipped, ids = await build_inventory(s, run, work)
            if not ids:
                raise RuntimeError("no device can be targeted: " + "; ".join(f"{x.get('device', x['switch_id'])}: {x['reason']}" for x in skipped)[:500])
            _write(os.path.join(work, "inventory.yml"), yaml.safe_dump(inv))
            _write(os.path.join(work, "playbook.yml"), pb.content)
            _write(os.path.join(work, "ansible.cfg"), ANSIBLE_CFG)
            backups = {}
            if run.kind == "change" and run.mode == "run":
                backups = {"before": await _backups(s, ids, "change")}
                bad = [b["device"] for b in backups["before"].values() if not b["ok"]]
                if bad:
                    run.backups = backups
                    raise RuntimeError(f"backup before the change failed for {', '.join(bad)}; nothing was run")
            argv = [bin_path or st.ansible_playbook_bin, "-i", os.path.join(work, "inventory.yml"), os.path.join(work, "playbook.yml"),
                    "--forks", str(max(1, min(st.ansible_forks, 50)))]
            if run.mode == "check":
                argv += ["--check", "--diff"]
            proc = await asyncio.create_subprocess_exec(*argv, cwd=work, env=env_for(work), stdout=asyncio.subprocess.PIPE,
                                                        stderr=asyncio.subprocess.STDOUT, start_new_session=True)
            chunks: list[bytes] = []

            async def pump():
                while True:
                    b = await proc.stdout.read(65536)
                    if not b:
                        return
                    if sum(map(len, chunks)) < 4_000_000:
                        chunks.append(b)
            reader = asyncio.create_task(pump())
            deadline, cancelled = time.monotonic() + st.ansible_run_timeout_seconds, False
            while proc.returncode is None:
                try:
                    await asyncio.wait_for(proc.wait(), 2)
                except asyncio.TimeoutError:
                    s.expire(run)
                    await s.refresh(run)
                    if run.cancel_requested or time.monotonic() > deadline:
                        cancelled = run.cancel_requested
                        try:
                            os.killpg(proc.pid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                        try:
                            await asyncio.wait_for(proc.wait(), 10)
                        except asyncio.TimeoutError:
                            os.killpg(proc.pid, signal.SIGKILL)
                            await proc.wait()
                        break
            await reader
            output = b"".join(chunks).decode("utf-8", errors="replace")
            for name, h in inv["all"]["children"]["targets"]["hosts"].items():      # never store a password the output echoed
                if h.get("ansible_password"):
                    output = output.replace(h["ansible_password"], "<masked>")
            run.output = mask(output)[:1_000_000]
            run.hosts = recap(output)
            if skipped:
                run.hosts.update({x.get("device", str(x["switch_id"])): {"skipped_reason": x["reason"]} for x in skipped})
            if run.kind == "change" and run.mode == "run":
                backups["after"] = await _backups(s, ids, "change")
                diffs = {}
                for sid, b in backups["after"].items():
                    pre, post = backups["before"].get(sid, {}).get("snapshot_id"), b.get("snapshot_id")
                    if pre and post and pre != post:
                        snap = await s.get(DeviceConfigSnapshot, post)
                        diffs[sid] = snap.diff if snap else ""
                backups["diffs"] = diffs
                run.backups = backups
            if cancelled:
                run.status, run.error = "cancelled", "cancelled by the user"
            elif proc.returncode == 0:
                run.status = "done"
            else:
                run.status = "failed"
                run.error = "timed out" if time.monotonic() > deadline else f"ansible-playbook exited with status {proc.returncode}"
        except (PolicyError, RuntimeError, OSError) as e:
            run.status, run.error = "failed", str(e)[:2000]
        finally:
            shutil.rmtree(work, ignore_errors=True)
        run.finished_at, run.lease_until = now(), None
        await s.commit()
        await audit.record(s, run.requested_by, "playbook_run_finished", target=pb.name if pb else "",
                           detail={"run_id": run.id, "status": run.status, "mode": run.mode, "kind": run.kind, "devices": len(run.device_ids),
                                   "approved_by": run.approved_by, "error": run.error[:300]}, success=run.status == "done")
        return run


async def claim() -> int | None:
    async with session_factory()() as s:
        r = (await s.execute(select(NmsPlaybookRun).where(NmsPlaybookRun.status == "queued").order_by(NmsPlaybookRun.id).limit(1))).scalars().first()
        if r is None:
            return None
        res = await s.execute(update(NmsPlaybookRun).where(NmsPlaybookRun.id == r.id, NmsPlaybookRun.status == "queued")
                              .values(status="running", lease_until=now() + timedelta(seconds=get_settings().ansible_run_timeout_seconds + 120)))
        await s.commit()
        return r.id if res.rowcount == 1 else None


async def recover() -> int:
    """Runs left running by a previous runner process cannot be resumed."""
    async with session_factory()() as s:
        n = 0
        for r in (await s.execute(select(NmsPlaybookRun).where(NmsPlaybookRun.status == "running"))).scalars():
            r.status, r.error, r.finished_at, n = "failed", "the runner restarted during this run", now(), n + 1
        await s.commit()
        return n


async def main() -> None:
    from ..logging_setup import setup_logging
    from ..db.pg import init_engine
    setup_logging(get_settings().log_level)
    init_engine(pool_size=2, max_overflow=2)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    n = await recover()
    if n:
        log.warning("%d interrupted playbook run(s) marked failed", n)
    log.info("ansible runner started")
    while not stop.is_set():
        try:
            open("/tmp/runner.heartbeat", "w").close()
            rid = await claim()
            if rid is not None:
                await execute(rid)
                continue
        except Exception:
            log.exception("playbook runner loop failed")
        try:
            await asyncio.wait_for(stop.wait(), 5)
        except asyncio.TimeoutError:
            pass


if __name__ == "__main__":
    asyncio.run(main())
