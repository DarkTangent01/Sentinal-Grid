"""Authorization policy engine: the single source of evaluation order for both simulation and configuration rendering.

Order (first match wins, exactly as rendered into the tac_plus-ng ruleset):
  1. deny rules: disabled users, authentication-policy restrictions (local / directory / emergency per device group)
  2. role mappings sorted by priority (lower first), then specificity (device > device group > site > vendor > global),
     then id
Inside the selected role's vendor profile, command rules are evaluated by priority (lower first), deny before permit at
equal priority, then the role's permitted command categories, then the role's default action. An empty command (shell
start) is always permitted once exec authorization succeeded.

The snapshot passed in is a plain dict (see service.snapshot), so tests and the UI simulator use the same data the
renderer uses.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from .vendors import CAPABILITIES, category_regex, categorize, normalize_cmd, per_command

NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_FORBIDDEN = re.compile(r"\(\?[<=!#a-zA-Z]|\\[1-9]|\\[kgpPQE]")  # lookaround, backrefs, inline flags, named / unicode escapes


class PolicyError(ValueError):
    pass


def validate_name(v: str, what: str = "name") -> str:
    if not NAME.match(v or ""):
        raise PolicyError(f"{what} must be 1-64 characters: letters, digits, '.', '_' or '-' (starting with a letter or digit)")
    return v


def validate_pattern(p: str) -> str:
    """Command regexes are rendered between slashes for the server's PCRE2 engine and evaluated here with Python re:
    only the common subset (no lookaround, back-references or inline flags) is accepted, so both agree."""
    if not p or len(p) > 256:
        raise PolicyError("pattern must be 1-256 characters")
    if _FORBIDDEN.search(p):
        raise PolicyError("lookaround, back-references, inline flags and \\k \\g \\p \\Q escapes are not allowed")
    if "\n" in p or '"' in p:
        raise PolicyError("pattern cannot contain newlines or double quotes")
    try:
        re.compile(p)
    except re.error as e:
        raise PolicyError(f"invalid regular expression: {e}")
    return p


def _aware(v):
    if v is None:
        return None
    if isinstance(v, str):
        v = datetime.fromisoformat(v)
    return v if v.tzinfo else v.replace(tzinfo=timezone.utc)


def active(x: dict, now: datetime) -> bool:
    exp = _aware(x.get("expires_at"))
    return bool(x.get("enabled", True)) and (exp is None or exp > now)


# ------------------------------------------------------------------ cron-style time windows (minute hour dom month dow)
def _field(spec: str, lo: int, hi: int) -> set[int]:
    out: set[int] = set()
    for part in spec.split(","):
        step = 1
        if "/" in part:
            part, s = part.split("/", 1)
            step = int(s)
        if part == "*":
            a, b = lo, hi
        elif "-" in part:
            a, b = (int(x) for x in part.split("-", 1))
        else:
            a = b = int(part)
        if a < lo or b > hi or a > b or step < 1:
            raise PolicyError(f"time field '{spec}' out of range {lo}-{hi}")
        out |= set(range(a, b + 1, step))
    return out


def validate_window(w: str) -> str:
    if not w:
        return ""
    parts = w.split()
    if len(parts) != 5:
        raise PolicyError("time window must have 5 cron fields: minute hour day-of-month month day-of-week, e.g. '* 8-19 * * 1-5'")
    for p, (lo, hi) in zip(parts, ((0, 59), (0, 23), (1, 31), (1, 12), (0, 7))):
        if not re.fullmatch(r"[0-9*,/-]+", p):
            raise PolicyError(f"invalid time field '{p}'")
        _field(p, lo, hi)
    return w


def in_window(w: str, now: datetime) -> bool:
    if not w:
        return True
    m, h, dom, mon, dow = w.split()
    d = (now.weekday() + 1) % 7  # cron: 0 = Sunday
    dows = _field(dow, 0, 7)
    return (now.minute in _field(m, 0, 59) and now.hour in _field(h, 0, 23) and now.day in _field(dom, 1, 31)
            and now.month in _field(mon, 1, 12) and (d in dows or (d == 0 and 7 in dows)))


# ------------------------------------------------------------------ scope / ordering
def clients_in_scope(m: dict, clients: list[dict]) -> list[dict]:
    out = []
    for c in clients:
        if not c.get("enabled", True):
            continue
        if m.get("scope_clients") and c["name"] not in m["scope_clients"]:
            continue
        if m.get("scope_sites") and c.get("site") not in m["scope_sites"]:
            continue
        if m.get("scope_device_groups") and c.get("device_group") not in m["scope_device_groups"]:
            continue
        if m.get("scope_vendors") and c.get("vendor") not in m["scope_vendors"]:
            continue
        out.append(c)
    return out


def specificity(m: dict) -> int:
    if m.get("scope_clients"):
        return 0
    if m.get("scope_device_groups"):
        return 1
    if m.get("scope_sites"):
        return 2
    if m.get("scope_vendors"):
        return 3
    return 4


def ordered_mappings(snap: dict, now: datetime) -> list[dict]:
    return sorted((m for m in snap["mappings"] if active(m, now) and m["role_id"] in snap["roles"]),
                  key=lambda m: (m.get("priority", 100), specificity(m), m["id"]))


def deny_rules(snap: dict, now: datetime) -> list[dict]:
    """[{reason, users: [...] | None (= every user of that kind), kind: local|directory|any, clients: [...] | None}]"""
    out = []
    disabled = sorted(u["username"] for u in snap["users"] if not u.get("enabled", True) or
                      (_aware(u.get("valid_until")) and _aware(u.get("valid_until")) <= now))
    if disabled:
        out.append({"id": "disabled-users", "reason": "account disabled or expired", "users": disabled, "kind": "any", "clients": None})
    local = sorted(u["username"] for u in snap["users"] if u.get("source_kind") == "local" and u.get("enabled", True))
    emergency = sorted(u["username"] for u in snap["users"] if u.get("emergency") and u.get("enabled", True))
    for p in sorted((p for p in snap.get("policies", []) if p.get("enabled", True)), key=lambda p: (p.get("priority", 100), p["name"])):
        scope = [c for c in snap["clients"] if not p.get("device_groups") or c.get("device_group") in p["device_groups"]]
        names = [c["name"] for c in scope] if p.get("device_groups") else None
        allowed = set(p.get("allowed_sources") or ["local", "directory"])
        if not p.get("allow_emergency", True) and emergency:
            out.append({"id": f"policy:{p['name']}:emergency", "reason": f"policy {p['name']}: emergency accounts not allowed", "users": emergency,
                        "kind": "any", "clients": names})
        blocked_local = [u for u in local if not (p.get("allow_emergency", True) and u in emergency)]  # break-glass stays usable
        if "local" not in allowed and blocked_local:
            out.append({"id": f"policy:{p['name']}:local", "reason": f"policy {p['name']}: local accounts not allowed", "users": blocked_local,
                        "kind": "local", "clients": names})
        if "directory" not in allowed:
            out.append({"id": f"policy:{p['name']}:directory", "reason": f"policy {p['name']}: directory accounts not allowed",
                        "users": None, "exclude": local, "kind": "directory", "clients": names})
    return out


# ------------------------------------------------------------------ evaluation
def _principal_matches(m: dict, user: str, groups: list[str]) -> bool:
    return (m["principal_type"] == "user" and m["principal"] == user) or (m["principal_type"] == "group" and m["principal"] in groups)


def evaluate_exec(snap: dict, user: str, groups: list[str], client: dict, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    trace = []
    for d in deny_rules(snap, now):
        if d["clients"] is not None and client["name"] not in d["clients"]:
            continue
        hit = (d["users"] is None and user not in d.get("exclude", [])) or (d["users"] is not None and user in d["users"])
        trace.append({"step": d["id"], "matched": hit})
        if hit:
            return {"decision": "deny", "reason": d["reason"], "rule": d["id"], "role": None, "trace": trace}
    for m in ordered_mappings(snap, now):
        if not _principal_matches(m, user, groups):
            continue
        in_scope = client["name"] in {c["name"] for c in clients_in_scope(m, snap["clients"])}
        in_time = in_window(m.get("time_window", ""), now)
        trace.append({"step": f"mapping:{m['id']}", "matched": in_scope and in_time, "in_scope": in_scope, "in_time": in_time})
        if in_scope and in_time:
            role = snap["roles"][m["role_id"]]
            prof = (role.get("vendor_profiles") or {}).get(client["vendor"]) or {}
            return {"decision": "permit", "reason": f"{m['principal_type']} {m['principal']} → role {role['name']}", "rule": f"mapping:{m['id']}",
                    "role": role["name"], "role_id": m["role_id"], "vendor_profile": prof, "trace": trace}
    return {"decision": "deny", "reason": "no role mapping matches this user, device and time (default deny)", "rule": "default", "role": None, "trace": trace}


def command_rules(snap: dict, role_id: int, vendor: str, now: datetime) -> list[dict]:
    """Ordered list of {action, regex, source} for a role on a vendor (explicit rules, then permitted categories)."""
    role = snap["roles"][role_id]
    explicit = sorted((r for r in snap["rules"] if r["role_id"] == role_id and r["vendor"] in (vendor, "any") and active(r, now)),
                      key=lambda r: (r.get("priority", 100), 0 if r["action"] == "deny" else 1, r["id"]))
    out = []
    for r in explicit:
        rx = r["pattern"] if r["match"] == "regex" else category_regex(vendor, r["category"])
        if rx:
            out.append({"action": r["action"], "regex": rx, "source": f"rule:{r['id']}", "exception": r.get("exception", False)})
    for cat in role.get("command_categories") or []:
        rx = category_regex(vendor, cat)
        if rx:
            out.append({"action": "permit", "regex": rx, "source": f"category:{cat}", "exception": False})
    return out


def evaluate_command(snap: dict, user: str, groups: list[str], client: dict, cmd: str, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    ex = evaluate_exec(snap, user, groups, client, now)
    c = normalize_cmd(cmd)
    res = {"exec": ex, "command": c, "category": categorize(client["vendor"], c), "vendor": client["vendor"],
           "enforcement": CAPABILITIES.get(client["vendor"], CAPABILITIES["other"])["enforcement"]}
    if ex["decision"] != "permit":
        return {**res, "decision": "deny", "reason": f"exec authorization denied: {ex['reason']}", "rule": ex["rule"]}
    if not per_command(client["vendor"]):
        return {**res, "decision": "not_enforced", "reason": f"{CAPABILITIES[client['vendor']]['label']} does not send per-command authorization: "
                f"access is controlled by the role's profile only", "rule": None}
    if not c:
        return {**res, "decision": "permit", "reason": "shell start", "rule": "shell"}
    for r in command_rules(snap, ex["role_id"], client["vendor"], now):
        if re.search(r["regex"], c):
            return {**res, "decision": r["action"], "reason": f"{r['source']} ({r['action']})", "rule": r["source"]}
    role = snap["roles"][ex["role_id"]]
    return {**res, "decision": role.get("default_command_action", "deny"), "reason": f"no rule matched: role default {role.get('default_command_action', 'deny')}",
            "rule": "role-default"}


def conflicts(snap: dict, now: datetime | None = None) -> list[dict]:
    now = now or datetime.now(timezone.utc)
    out = []
    for role_id, role in snap["roles"].items():
        rules = [r for r in snap["rules"] if r["role_id"] == role_id and active(r, now)]
        seen: dict[tuple, dict] = {}
        for r in sorted(rules, key=lambda r: (r.get("priority", 100), r["id"])):
            key = (r["vendor"], r["match"], r["pattern"] if r["match"] == "regex" else r["category"])
            if key in seen and seen[key]["action"] != r["action"]:
                out.append({"type": "contradiction", "role": role["name"], "rules": [seen[key]["id"], r["id"]],
                            "detail": f"same {r['match']} '{key[2]}' is both {seen[key]['action']} and {r['action']}; rule {seen[key]['id']} wins"})
            elif key in seen:
                out.append({"type": "duplicate", "role": role["name"], "rules": [seen[key]["id"], r["id"]], "detail": f"rule {r['id']} never decides (duplicate)"})
            seen.setdefault(key, r)
            if r["match"] == "category" and r["action"] == "deny" and r["category"] in (role.get("command_categories") or []):
                out.append({"type": "override", "role": role["name"], "rules": [r["id"]],
                            "detail": f"category {r['category']} is permitted by the role but denied by rule {r['id']} (the deny wins)"})
            if r.get("exception") and (not r.get("owner") or not r.get("expires_at")):
                out.append({"type": "exception_incomplete", "role": role["name"], "rules": [r["id"]], "detail": "exceptions need an owner and an expiry"})
    maps = ordered_mappings(snap, now)
    for i, a in enumerate(maps):
        for b in maps[i + 1:]:
            if a["principal_type"] == b["principal_type"] and a["principal"] == b["principal"] and a["role_id"] != b["role_id"] \
                    and (a.get("priority", 100), specificity(a)) == (b.get("priority", 100), specificity(b)):
                sa = {c["name"] for c in clients_in_scope(a, snap["clients"])}
                sb = {c["name"] for c in clients_in_scope(b, snap["clients"])}
                if sa & sb:
                    out.append({"type": "ambiguous_mapping", "role": f"{snap['roles'][a['role_id']]['name']} / {snap['roles'][b['role_id']]['name']}",
                                "rules": [a["id"], b["id"]], "detail": f"{a['principal_type']} {a['principal']} maps to two roles on "
                                f"{len(sa & sb)} device(s) at the same priority; mapping {a['id']} wins"})
    return out


def explain(snap: dict, role_id: int, now: datetime | None = None) -> dict:
    """Effective access of a role per vendor, in words."""
    now = now or datetime.now(timezone.utc)
    role = snap["roles"][role_id]
    out = {"role": role["name"], "vendors": {}}
    for vendor, cap in CAPABILITIES.items():
        prof = (role.get("vendor_profiles") or {}).get(vendor) or {}
        rules = command_rules(snap, role_id, vendor, now) if per_command(vendor) else []
        out["vendors"][vendor] = {
            "label": cap["label"], "enforcement": cap["enforcement"], "profile": prof,
            "privilege": (f"priv-lvl {prof['priv_lvl']}" if vendor == "cisco" and "priv_lvl" in prof else
                          f"foundry-privlvl {prof['priv_lvl']} ({ {0: 'super-user', 4: 'port-config', 5: 'read-only'}.get(prof['priv_lvl'], 'custom') })"
                          if vendor == "ruckus" and "priv_lvl" in prof else f"admin profile {prof['admin_profile']}" if "admin_profile" in prof
                          else "not configured for this vendor (exec authorization will not return a privilege)"),
            "permitted_categories": role.get("command_categories") or [],
            "explicit_rules": [r for r in rules if r["source"].startswith("rule:")],
            "default": role.get("default_command_action", "deny") if per_command(vendor) else "n/a",
            "note": cap["command_authorization"]}
    return out
