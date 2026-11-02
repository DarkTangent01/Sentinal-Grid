"""Sentinel Grid TACACS+ deploy agent (runs inside the tacacs container, stdlib only).

It supervises tac_plus-ng and is the only component that changes the live configuration. The SIEM worker talks to it
through files in /tacacs/config (a volume shared by the two containers, group tacshare):

    candidates/<id>.cfg        candidate configuration written by the SIEM (id: digits only)
    requests/<id>.json         {"id": <id>, "action": "validate" | "deploy", "sha256": "<hex of the candidate>"}
    results/<id>.json          written by the agent: outcome, sanitised parser output, backup name, health
    status.json                written every 10 s: process state, active config hash, listener health
    active/tac_plus-ng.cfg     live configuration (atomic replace only)
    backups/<ts>-<sha>.cfg     previous configurations (last 30 kept)

Safety:
  * requests name fixed paths only (the id is validated as digits); nothing from a request is executed or used as a path
  * the candidate must match the sha256 in the request (no swap between validation and activation)
  * every candidate is parsed with `tac_plus-ng -P` before activation; activation is an atomic rename
  * after a reload the agent checks the process and TCP/49; on failure it restores the backup automatically
  * subprocesses are argument lists (no shell), with timeouts; parser output is truncated and secrets masked
"""
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time

BASE = "/tacacs/config"
ACTIVE = f"{BASE}/active/tac_plus-ng.cfg"
BIN = "/usr/local/sbin/tac_plus-ng"
AGENT_VERSION = "1.0"
ID = re.compile(r"^\d{1,12}$")
SECRET = re.compile(r"(?i)\b(key(?:\s+warn[^=]*)?|password\s+\w+|enable\s*\d*|LDAP_PASSWD|setenv\s+\S*PASS\S*)\s*=\s*(?:clear|crypt|6|7|\")?\s*\S+")

state = {"proc": None, "started_at": None, "restarts": 0, "last_reload": None, "last_result": None}


def log(msg: str) -> None:
    print(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} tacagent: {msg}", flush=True)


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(path: str, data: dict) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.replace(tmp, path)


def sanitize(text: str) -> str:
    return SECRET.sub(lambda m: m.group(1) + " = ***", text)[-4000:]


def start() -> None:
    state["proc"] = subprocess.Popen([BIN, ACTIVE], stdout=sys.stdout, stderr=sys.stderr)
    state["started_at"] = time.time()
    log(f"tac_plus-ng started pid {state['proc'].pid}")


def alive() -> bool:
    p = state["proc"]
    return p is not None and p.poll() is None


def listening(port: int = 49) -> bool:
    """A LISTEN socket on the port, read from /proc/net (connecting would make tac_plus-ng log a rejected connection every 10 s)."""
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path) as f:
                next(f, None)
                for line in f:
                    parts = line.split()
                    if len(parts) > 3 and parts[3] == "0A" and int(parts[1].rsplit(":", 1)[1], 16) == port:
                        return True
        except (OSError, ValueError, IndexError):
            continue
    return False


def parse_check(path: str) -> tuple[bool, str]:
    try:
        r = subprocess.run([BIN, "-P", path], capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired:
        return False, "parser timed out"
    return r.returncode == 0, sanitize((r.stdout or "") + (r.stderr or ""))


def reload() -> None:
    if alive():
        state["proc"].send_signal(signal.SIGHUP)  # spawnd master re-reads the configuration; children drain
    else:
        start()
    state["last_reload"] = time.time()


def healthy(wait: float = 8.0) -> bool:
    deadline = time.time() + wait
    while time.time() < deadline:
        if alive() and listening():
            return True
        time.sleep(0.5)
    return False


def handle(rid: str, req: dict) -> dict:
    cand = f"{BASE}/candidates/{rid}.cfg"
    out = {"id": int(rid), "action": req.get("action"), "finished_at": None, "ok": False, "status": "failed", "output": "", "backup": None}
    if req.get("action") not in ("validate", "deploy"):
        out["output"] = "unknown action"
        return out
    if not os.path.isfile(cand):
        out["output"] = "candidate file missing"
        return out
    if sha256(cand) != req.get("sha256"):
        out["output"] = "candidate does not match the requested sha256"
        return out
    ok, text = parse_check(cand)
    text = sanitize(text)  # defence in depth: whatever produced it, parser output is masked before it leaves the agent
    out["output"] = text
    if not ok:
        out["status"] = "invalid"
        return out
    if req["action"] == "validate":
        out.update(ok=True, status="valid")
        return out
    backup = None
    if os.path.isfile(ACTIVE):
        backup = f"{BASE}/backups/{time.strftime('%Y%m%dT%H%M%S')}-{sha256(ACTIVE)[:12]}.cfg"
        shutil.copy2(ACTIVE, backup)
    tmp = f"{BASE}/active/.incoming"
    shutil.copyfile(cand, tmp)
    os.chmod(tmp, 0o640)
    os.replace(tmp, ACTIVE)
    reload()
    if healthy():
        out.update(ok=True, status="deployed", backup=os.path.basename(backup) if backup else None, active_sha256=sha256(ACTIVE))
    else:
        log("new configuration unhealthy: restoring backup")
        if backup:
            shutil.copyfile(backup, tmp)
            os.replace(tmp, ACTIVE)
            if alive():
                state["proc"].terminate()
                try:
                    state["proc"].wait(10)
                except subprocess.TimeoutExpired:
                    state["proc"].kill()
            start()
            restored = healthy()
        else:
            restored = False
        out.update(status="rolled_back" if restored else "failed_unhealthy", backup=os.path.basename(backup) if backup else None,
                   output=(text + "\nhealth check after reload failed; " + ("previous configuration restored" if restored else "restore failed")))
    backups = sorted(os.listdir(f"{BASE}/backups"))
    for old in backups[:-30]:
        os.remove(f"{BASE}/backups/{old}")
    return out


def status() -> None:
    write_json(f"{BASE}/status.json", {
        "agent_version": AGENT_VERSION, "implementation": "tac_plus-ng", "commit": os.environ.get("TAC_PLUS_NG_COMMIT", ""),
        "running": alive(), "pid": state["proc"].pid if alive() else None, "started_at": state["started_at"], "restarts": state["restarts"],
        "listening": listening(), "active_sha256": sha256(ACTIVE) if os.path.isfile(ACTIVE) else None, "last_reload": state["last_reload"],
        "time": time.time()})


def main() -> None:
    signal.signal(signal.SIGTERM, lambda *_: (state["proc"] and state["proc"].terminate(), sys.exit(0)))
    start()
    last_status = 0.0
    backoff = 1.0
    while True:
        if not alive():
            state["restarts"] += 1
            log(f"tac_plus-ng exited ({state['proc'].returncode if state['proc'] else '?'}); restarting in {backoff:.0f}s")
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)
            start()
        elif time.time() - (state["started_at"] or 0) > 60:
            backoff = 1.0
        for name in sorted(os.listdir(f"{BASE}/requests")):
            rid = name[:-5] if name.endswith(".json") else ""
            path = f"{BASE}/requests/{name}"
            if not ID.match(rid):
                continue
            req: dict = {}
            try:
                with open(path) as f:
                    req = json.load(f)
                res = handle(rid, req)
            except Exception as e:  # never let one request stop the agent
                res = {"id": int(rid), "ok": False, "status": "failed", "output": f"agent error: {type(e).__name__}"}
            res["finished_at"] = time.time()
            write_json(f"{BASE}/results/{rid}.json", res)
            os.remove(path)
            log(f"request {rid} {req.get('action') if isinstance(req, dict) else '?'}: {res['status']}")
        if time.time() - last_status >= 10:
            status()
            last_status = time.time()
        time.sleep(2)


if __name__ == "__main__":
    main()
