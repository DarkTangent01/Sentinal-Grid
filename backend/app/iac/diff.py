"""Desired vs observed comparison: per-resource create / update / delete / move with field-level diffs, dependencies,
risk classification and disruption flags. Used for plans (desired → device) and drift (device vs desired)."""
from __future__ import annotations

from .resources import SINGLETONS, TYPES

SEV = ["info", "low", "medium", "high", "critical"]
MATCH_FIELDS = ("srcintf", "dstintf", "srcaddr", "dstaddr", "service", "internet_service", "internet_service_name",
                "internet_service_group", "internet_service_custom", "schedule")


def field_diff(cur: dict | None, des: dict | None, fields: list[str] | None = None) -> list[dict]:
    cur, des = cur or {}, des or {}
    keys = fields if fields is not None else sorted(set(cur) | set(des))
    out = []
    for k in keys:
        a, b = cur.get(k), des.get(k)
        if isinstance(a, list) or isinstance(b, list):
            sa, sb = set(a or []), set(b or [])
            if sa != sb:
                out.append({"field": k, "current": a, "desired": b, "added": sorted(sb - sa), "removed": sorted(sa - sb)})
        elif a != b and not (a in (None, "") and b in (None, "")):
            out.append({"field": k, "current": a, "desired": b})
    return out


def _refs(rtype: str, obj: dict) -> list[tuple[str, str]]:
    if rtype == "address_group":
        return [("address", m) for m in obj.get("members", [])] + [("address_group", m) for m in obj.get("members", [])]
    if rtype == "service_group":
        return [("service", m) for m in obj.get("members", [])] + [("service_group", m) for m in obj.get("members", [])]
    if rtype == "policy":
        return ([("address", a) for a in obj.get("srcaddr", []) + obj.get("dstaddr", [])]
                + [("address_group", a) for a in obj.get("srcaddr", []) + obj.get("dstaddr", [])]
                + [("service", x) for x in obj.get("service", [])] + [("service_group", x) for x in obj.get("service", [])])
    return []


def compute(desired: dict, observed: dict, *, managed_types: set[str], prune_types: set[str], previously_managed: dict,
            desired_order: list[str] | None = None, observed_order: list[str] | None = None,
            ignored: dict[str, set[str]] | None = None) -> list[dict]:
    """Changes needed to make the device match the desired state, in safe execution order.

    Deletion happens only for objects of a managed type that are (a) in `prune_types`, or (b) were deployed by IaC
    before (`previously_managed`) and are no longer declared. Everything else on the device is left alone, and objects in
    `ignored` (manage.ignore) are never touched, even with prune."""
    changes: list[dict] = []
    for t in sorted(managed_types, key=lambda x: TYPES[x]["order"]):
        des, obs = desired.get(t) or {}, observed.get(t) or {}
        if t in SINGLETONS:
            d, o = des.get(""), obs.get("") or {}
            if not d:
                continue
            fd = field_diff({k: o.get(k) for k in d}, d, list(d))
            if fd:
                changes.append({"type": t, "key": "", "action": "update", "current": {k: o.get(k) for k in d}, "desired": d, "fields": fd})
            continue
        for k in sorted(des, key=lambda x: (len(x), x)):
            if k not in obs:
                changes.append({"type": t, "key": k, "action": "create", "current": None, "desired": des[k], "fields": field_diff(None, des[k])})
            else:
                fd = field_diff({f: obs[k].get(f) for f in set(des[k]) | {"comment", "comments"} if f in obs[k] or f in des[k]}, des[k])
                if fd:
                    changes.append({"type": t, "key": k, "action": "update", "current": obs[k], "desired": des[k], "fields": fd})
        prev = set(previously_managed.get(t) or [])
        skip = (ignored or {}).get(t) or set()
        for k in sorted(obs):
            if k in des or k in skip:
                continue
            if t in prune_types or k in prev:
                changes.append({"type": t, "key": k, "action": "delete", "current": obs[k], "desired": None, "fields": field_diff(obs[k], None),
                                "reason": "pruned (not declared)" if t in prune_types else "previously deployed by IaC, now removed"})
    # policy order: FortiGate matches top-down, so sequence is part of the configuration
    if "policy" in managed_types and desired_order:
        changes += order_moves(desired_order, observed_order or [])
    # dependencies + execution order: creates/updates by type order, moves after policies exist, deletes reverse
    keyset = {(c["type"], c["key"]) for c in changes if c["action"] == "create"}
    for c in changes:
        if c["action"] in ("create", "update") and c["desired"]:
            c["depends_on"] = sorted({f"{t}:{k}" for t, k in _refs(c["type"], c["desired"]) if (t, k) in keyset})
        elif c["action"] == "move":
            ref = c["desired"].get("after") or c["desired"].get("before")
            c["depends_on"] = sorted({f"policy:{x}" for x in (ref, c["key"]) if ("policy", x) in keyset})
        else:
            c["depends_on"] = []
    rank = {"create": 0, "update": 0, "move": 1, "delete": 2}
    for i, c in enumerate(changes):
        c["_i"] = i
    # moves keep their generated sequence (each depends on the previous one's result)
    changes.sort(key=lambda c: (rank[c["action"]], TYPES[c["type"]]["order"] * (-1 if c["action"] == "delete" else 1),
                                c["_i"] if c["action"] == "move" else 0, c["key"]))
    for c in changes:
        c.pop("_i")
    return changes


def order_moves(desired_order: list[str], observed_order: list[str]) -> list[dict]:
    """Minimal 'move' operations so the declared policies appear in the declared relative order. New policies are
    appended by FortiOS, so they start at the end. Undeclared policies keep their place relative to each other."""
    want = list(dict.fromkeys(desired_order))
    wanted = set(want)
    cur = [k for k in observed_order if k in wanted] + [k for k in want if k not in set(observed_order)]
    moves = []
    for i, k in enumerate(want):
        if i == 0:
            if cur and cur[0] != k:
                moves.append({"type": "policy", "key": k, "action": "move", "current": {"before": None}, "desired": {"before": cur[0]},
                              "fields": [{"field": "position", "current": f"after {cur[cur.index(k) - 1]}", "desired": f"before {cur[0]}"}]})
                cur.remove(k)
                cur.insert(0, k)
            continue
        prev = want[i - 1]
        j = cur.index(prev)
        if j + 1 >= len(cur) or cur[j + 1] != k:
            was = cur.index(k)
            moves.append({"type": "policy", "key": k, "action": "move", "current": {"after": cur[was - 1] if was else None},
                          "desired": {"after": prev}, "fields": [{"field": "position", "current": f"after {cur[was - 1]}" if was else "first",
                                                                  "desired": f"after {prev}"}]})
            cur.remove(k)
            cur.insert(cur.index(prev) + 1, k)
    return moves


def classify(c: dict, overrides: dict | None = None) -> dict:
    """Risk, rule id, explanation and disruption flag for one change (plan) or difference (drift)."""
    t, a, fields = c["type"], c["action"], {f["field"]: f for f in c.get("fields", [])}
    d, cur = c.get("desired") or {}, c.get("current") or {}
    rid, sev, why, disruptive = "DRIFT-OBJECT", "low", "", False
    if t == "policy":
        if a == "create":
            rid, sev = "DRIFT-POLICY-ADDED", "high" if d.get("action") == "accept" else "medium"
            why = f"new {d.get('action')} policy {c['key']} '{d.get('name', '')}'"
            if d.get("action") == "accept" and "all" in d.get("srcaddr", []) and "all" in d.get("dstaddr", []):
                sev, why = "critical", why + " allowing any source to any destination"
        elif a == "delete":
            rid, sev, why, disruptive = "DRIFT-POLICY-DELETED", "high" if cur.get("action") == "accept" else "medium", \
                f"policy {c['key']} '{cur.get('name', '')}' removed: traffic it allowed will hit the next matching policy", True
        elif a == "move":
            rid, sev, why, disruptive = "DRIFT-POLICY-ORDER", "medium", "policy order changes which policy matches first", True
        elif "action" in fields:
            rid = "DRIFT-POLICY-ACTION"
            sev = "critical" if d.get("action") == "accept" else "high"
            why, disruptive = f"action {fields['action']['current']} → {fields['action']['desired']}", True
        elif "status" in fields:
            rid, sev, why, disruptive = "DRIFT-POLICY-STATUS", "high", f"policy {fields['status']['desired']}d", True
        elif any(f in fields for f in MATCH_FIELDS):
            rid, sev = "DRIFT-POLICY-MATCH", "medium"
            why = "match criteria changed: " + ", ".join(f for f in MATCH_FIELDS if f in fields)
            widened = [f for f in ("srcaddr", "dstaddr", "service") if "all" in (fields.get(f, {}).get("added") or []) or "ALL" in (fields.get(f, {}).get("added") or [])]
            if widened and d.get("action") == "accept":
                sev, why = "high", why + f" (widened to any in {', '.join(widened)})"
            disruptive = True
        elif "nat" in fields:
            rid, sev, why, disruptive = "DRIFT-POLICY-NAT", "medium", f"NAT {fields['nat']['current']} → {fields['nat']['desired']}", True
        elif "logtraffic" in fields:
            rid = "DRIFT-POLICY-LOG"
            sev = "high" if fields["logtraffic"]["desired"] == "disable" else "low"
            why = f"logging {fields['logtraffic']['current']} → {fields['logtraffic']['desired']}"
        else:
            rid, sev, why = "DRIFT-POLICY-META", "info", "name / comments changed"
    elif t == "static_route":
        rid, sev, disruptive = "DRIFT-ROUTE", "high", True
        dst = (d or cur).get("dst", "")
        why = f"route {c['key']} to {dst} {a}d" + (" (DEFAULT ROUTE)" if dst in ("0.0.0.0/0", "::/0") else "")
        if dst in ("0.0.0.0/0", "::/0"):
            sev = "critical"
    elif t == "system_global":
        rid, sev, disruptive = "DRIFT-ADMIN", "critical", False
        why = "administrative access settings changed: " + ", ".join(fields)
    elif t == "syslog":
        rid = "DRIFT-LOGGING"
        sev = "high" if (fields.get("status") or {}).get("desired") == "disable" or "server" in fields else "medium"
        why = "syslog forwarding changed: " + ", ".join(fields)
    else:
        if a == "create":
            rid, sev, why = "DRIFT-OBJECT-ADDED", "low", f"{t} '{c['key']}' added"
        elif a == "delete":
            rid, sev, why = "DRIFT-OBJECT-DELETED", "medium", f"{t} '{c['key']}' deleted"
        else:
            rid, sev, why = "DRIFT-OBJECT-MODIFIED", "medium", f"{t} '{c['key']}' modified: " + ", ".join(fields)
            if t in ("address", "address_group") and ("subnet" in fields or "members" in fields):
                why += " (changes what every policy using it matches)"
    if overrides and rid in overrides:
        sev = overrides[rid]
    return {"rule_id": rid, "risk": sev, "impact": why, "disruptive": disruptive}


def counts(items: list[dict], key: str = "risk") -> dict:
    out = {s: 0 for s in SEV}
    for x in items:
        out[x.get(key, "info")] = out.get(x.get(key, "info"), 0) + 1
    return out
