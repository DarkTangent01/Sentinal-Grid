"""Deployment state for administrators (Administration → Deployments): what each service runs, when it was deployed,
the previous version kept for rollback, and the deployment history.

scripts/release.sh writes the files on the server (deploy/state, mounted read-only into the api):
  versions.env   SERVICE_TAG=<image tag> lines currently deployed (the same values docker-compose.yml interpolates)
  status.json    per-service container state and health right after the last deployment
  history.jsonl  one JSON object per deployment step: {ts, service, from, to, result, duration_s, note}
Nothing here can change a deployment; deployments run only from the server (scripts/release.sh).
"""
from __future__ import annotations

import json
import os
from pathlib import Path

STATE_DIR = Path(os.environ.get("DEPLOY_STATE_DIR", "/var/lib/siem/deploy-state"))
MAX_HISTORY = 300


def _versions(p: Path) -> dict[str, str]:
    out = {}
    try:
        for ln in p.read_text().splitlines():
            ln = ln.strip()
            if ln and not ln.startswith("#") and "=" in ln:
                k, v = ln.split("=", 1)
                if k.endswith("_TAG") and len(v) <= 80:
                    out[k] = v
    except OSError:
        pass
    return out


def _history(p: Path) -> list[dict]:
    try:
        lines = p.read_text().splitlines()[-MAX_HISTORY:]
    except OSError:
        return []
    out = []
    for ln in lines:
        try:
            x = json.loads(ln)
        except ValueError:
            continue
        if isinstance(x, dict):
            out.append({k: x.get(k) for k in ("ts", "service", "from", "to", "result", "duration_s", "note", "kind")})
    return list(reversed(out))


def state(state_dir: Path | None = None) -> dict:
    d = state_dir or STATE_DIR
    versions = _versions(d / "versions.env")
    prev = _versions(d / "versions.prev.env")
    try:
        status = json.loads((d / "status.json").read_text())
    except (OSError, ValueError):
        status = {}
    hist = _history(d / "history.jsonl")
    last_ok = {}
    for h in reversed(hist):          # oldest → newest: last successful deploy per service
        if h.get("result") == "ok":
            last_ok[h.get("service")] = h
    services = []
    for svc, info in sorted((status.get("services") or {}).items()):
        key = info.get("tag_var") or ""
        services.append({"service": svc, "tag": versions.get(key) or info.get("tag"), "previous": prev.get(key),
                         "state": info.get("state"), "health": info.get("health"), "containers": info.get("containers"),
                         "deployed_at": (last_ok.get(svc) or {}).get("ts")})
    return {"available": d.exists(), "running_api_version": os.environ.get("SENTINEL_VERSION", "dev"), "captured_at": status.get("ts"),
            "ui_release": status.get("ui_release"), "services": services, "versions": versions, "history": hist}
