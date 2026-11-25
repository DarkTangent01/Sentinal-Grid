#!/usr/bin/env python3
"""Runtime security audit of running containers (Docker or Podman). Read-only: `inspect` and `top` only.

Usage: container_audit.py [--cli docker|podman] [--project NAME] [--only nonroot] [--json]
Prints one PASS / FAIL / WARN line per check and container, then a summary; exit 1 when any check FAILs.
A check that could not be performed is reported as WARN ("not tested"), never as PASS.

Expected exceptions (documented in security/CONTAINER_SECURITY_ASSESSMENT.md) are listed in ALLOW and reported as WARN.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys

SENSITIVE = ("/", "/etc", "/root", "/boot", "/proc", "/sys", "/dev", "/var/run", "/run", "/var/lib/docker", "/var/lib/containers", "/home")
SOCKETS = ("docker.sock", "podman.sock", "containerd.sock", "crio.sock")
DANGEROUS_CAPS = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "SYS_RAWIO", "ALL", "CAP_SYS_ADMIN", "CAP_NET_ADMIN",
                  "CAP_SYS_PTRACE", "CAP_SYS_MODULE", "CAP_DAC_READ_SEARCH", "CAP_SYS_RAWIO"}
# container name fragment -> checks allowed to fail (reported as WARN with the reason)
ALLOW: dict[str, dict[str, str]] = {}

results: list[tuple[str, str, str, str]] = []


def run(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout


def record(status: str, name: str, check: str, detail: str = "") -> None:
    if status == "FAIL":
        for frag, allowed in ALLOW.items():
            if frag in name and check in allowed:
                status, detail = "WARN", f"{detail} (accepted exception: {allowed[check]})"
    results.append((status, name, check, detail))


def audit(cli: str, project: str | None, only: str | None) -> None:
    ids = run([cli, "ps", "-q"] + (["--filter", f"label=com.docker.compose.project={project}"] if project else [])).split()
    if not ids:
        record("WARN", "-", "containers", "no running container matched: nothing tested")
        return
    for c in json.loads(run([cli, "inspect"] + ids)):
        name = c["Name"].lstrip("/")
        hc, cfg = c["HostConfig"], c["Config"]
        # 1. non-root: configured user, and the uids of the processes actually running
        try:
            if cli == "docker":   # docker top needs a pid column
                procs = run([cli, "top", c["Id"], "-eo", "pid,uid,comm"]).splitlines()
                rows = [p.split(None, 2)[1:] for p in procs[1:] if p.strip()]
            else:
                rows = [p.split(None, 1) for p in run([cli, "top", c["Id"], "huser", "comm"]).splitlines() if p.strip()]
            root = [r for r in rows if r and r[0] in ("0", "root")]
            record("FAIL" if root else "PASS", name, "non-root processes",
                   f"root processes: {', '.join(r[1] if len(r) > 1 else '?' for r in root)}" if root else f"{len(rows)} process(es), none uid 0")
        except subprocess.CalledProcessError as e:
            record("WARN", name, "non-root processes", f"not tested: {cli} top failed ({e.returncode})")
        user = cfg.get("User") or ""
        record("PASS" if user and user.split(":")[0] not in ("0", "root") else "WARN", name, "configured user",
               f"user={user or '(image default)'}")
        if only == "nonroot":
            continue
        # 2. privileged / namespaces
        record("FAIL" if hc.get("Privileged") else "PASS", name, "not privileged")
        for key, label in (("PidMode", "host PID"), ("IpcMode", "host IPC"), ("NetworkMode", "host network")):
            record("FAIL" if (hc.get(key) or "") == "host" else "PASS", name, f"no {label}")
        # 3. capabilities and privilege escalation
        add = set(hc.get("CapAdd") or [])
        drop = set(hc.get("CapDrop") or [])
        record("FAIL" if add & DANGEROUS_CAPS else ("WARN" if add else "PASS"), name, "capabilities", f"add={sorted(add) or '-'} drop={sorted(drop) or '-'}")
        # Docker reports CapDrop [ALL]; Podman lists each dropped capability and reports what remains as EffectiveCaps
        all_dropped = bool(drop & {"ALL", "CAP_ALL"}) or ("EffectiveCaps" in c and not c["EffectiveCaps"] and not add)
        detail = ""
        if cli == "podman":     # Podman can show the processes' effective capability sets: check what actually runs
            try:
                caps = {ln.strip() for ln in run([cli, "top", c["Id"], "capeff"]).splitlines()[1:] if ln.strip()}
                all_dropped = all_dropped and caps <= {"none"}
                detail = f"process capabilities: {', '.join(sorted(caps))}"
            except subprocess.CalledProcessError:
                detail = "process capabilities not read"
        record("PASS" if all_dropped else "FAIL", name, "all capabilities dropped", detail)
        sec = " ".join(hc.get("SecurityOpt") or [])
        record("PASS" if "no-new-privileges:true" in sec or "no-new-privileges" == sec.strip() or "no-new-privileges=true" in sec else "FAIL",
               name, "no-new-privileges", sec or "-")
        record("FAIL" if "seccomp=unconfined" in sec or "seccomp:unconfined" in sec else "PASS", name, "seccomp confined")
        record("PASS" if hc.get("ReadonlyRootfs") else "WARN", name, "read-only root filesystem")
        # 4. mounts: runtime sockets and host system directories
        for m in c.get("Mounts") or []:
            src = m.get("Source") or ""
            if any(s in src for s in SOCKETS):
                record("FAIL", name, "no runtime socket", src)
            elif m.get("Type") == "bind" and (src.rstrip("/") or "/") in SENSITIVE:
                record("FAIL", name, "no host system directory", src)
            elif m.get("Type") == "bind" and m.get("RW") and not src.startswith(("/home/", "/srv/", "/opt/", "/private/", "/Users/")):
                record("WARN", name, "writable bind mount", src)
        if not any(r[1] == name and r[2] in ("no runtime socket", "no host system directory") for r in results):
            record("PASS", name, "no runtime socket / host system mount")
        # 5. resource limits
        mem, cpu, pids = hc.get("Memory") or 0, (hc.get("NanoCpus") or 0) or (hc.get("CpuQuota") or 0), hc.get("PidsLimit") or 0
        record("PASS" if mem and cpu else "FAIL", name, "cpu / memory limits", f"memory={mem} cpu={cpu}")
        record("PASS" if pids and pids > 0 else "WARN", name, "process limit", f"pids={pids}")
        record("PASS" if hc.get("Init") else "WARN", name, "init process")
        # 6. published ports on every interface
        for port, binds in (hc.get("PortBindings") or {}).items():
            for b in binds or []:
                if (b.get("HostIp") or "") in ("", "0.0.0.0", "::"):
                    record("WARN", name, "port bound to all interfaces", f"{port} -> {b.get('HostPort')} (restrict with the host firewall)")
        # 7. no secret values in the environment
        env = cfg.get("Env") or []
        leaked = [e.split("=", 1)[0] for e in env if "=" in e and any(k in e.split("=", 1)[0] for k in ("PASSWORD", "SECRET", "TOKEN", "API_KEY"))
                  and not e.split("=", 1)[0].endswith("_FILE") and e.split("=", 1)[1]]
        record("FAIL" if leaked else "PASS", name, "no secrets in environment", ", ".join(leaked))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cli", default="docker")
    ap.add_argument("--project")
    ap.add_argument("--only", choices=["nonroot"])
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    try:
        audit(a.cli, a.project, a.only)
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        print(f"FAIL  -  {a.cli} unavailable: {e}")
        return 2
    if a.json:
        print(json.dumps([dict(zip(("status", "container", "check", "detail"), r)) for r in results], indent=1))
    else:
        for st, n, chk, d in results:
            print(f"{st:<5} {n:<28} {chk:<34} {d}")
    counts = {s: sum(1 for r in results if r[0] == s) for s in ("PASS", "WARN", "FAIL")}
    print(f"summary: {counts['PASS']} PASS, {counts['WARN']} WARN, {counts['FAIL']} FAIL")
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
