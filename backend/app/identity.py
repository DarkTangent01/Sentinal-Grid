"""User and identity analytics: who authenticated where, from which IPs and devices, failures, unusual logins,
administrator activity and changes to administrator accounts / privileges.

Sources (all already ingested; nothing new is collected):
  * Dial-up IPsec (FortiClient) VPN: the person is `xauthuser` (FortiOS puts the client's local IP in `user`), with
    xauthgroup, remip (public IP), assignip (tunnel IP), fctuid (FortiClient device id) and srccountry.
    0101037138 tunnel-up / tunnel-down, 0101037139 phase2-up, 0101037141 tunnel statistics, 0101037121 XAUTH failure.
  * SSL VPN (tunneltype ssl-*) and PAN-OS GlobalProtect (mapped to subtype vpn).
  * Firewall administrators: 0100032001 login, 0100032002 login failed, 0100032003 logout (user, srcip, ui, profile);
    0100044546/7 configuration changes (cfgpath, cfgobj, cfgattr, action); 0100044548 CLI commands.
  * Windows Security logons (log sources) and firewall user authentication (subtype user).
The VPN assigned IP links a person to their traffic: traffic from that IP during the session is theirs.
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from .vpnmon import _aware, _fw

ADMIN_LOGIN, ADMIN_FAIL, ADMIN_LOGOUT = "0100032001", "0100032002", "0100032003"
CFG_LOGIDS = ("0100044544", "0100044545", "0100044546", "0100044547")
CLI_LOGID = "0100044548"
ACCOUNT_PATHS = ("system.admin", "system.accprofile", "system.api-user", "user.local", "user.group", "user.radius",
                 "user.tacacs+", "user.ldap", "user.saml", "system.sso-admin", "user.peer", "system.password-policy")
PRIV_WORDS = ("accprofile", "super_admin", "trusthost", "password", "two-factor", "vdom", "ssh-public-key", "remote-auth",
              "wildcard", "api-key", "member")
WIN_ACCOUNT = {"4720": "account created", "4722": "account enabled", "4723": "password change attempt", "4724": "password reset",
               "4725": "account disabled", "4726": "account deleted", "4738": "account changed", "4728": "added to global group",
               "4732": "added to local group", "4756": "added to universal group", "4729": "removed from global group",
               "4733": "removed from local group", "4757": "removed from universal group", "4740": "account locked out"}


def _x(field: str, quoted: bool = True) -> str:
    # unquoted fields (remip, assignip, duration ...) are quoted by some senders: accept both
    return f"extract(raw, '{field}=\"([^\"]*)\"')" if quoted else f"extract(raw, '{field}=\"?([^\" ]+)')"


UX = _x("xauthuser")
# the person behind an event: xauthuser for FortiClient IPsec, else `user` unless it is an IP / N/A (FortiOS peer ids)
IDENT = (f"multiIf({UX} NOT IN ('', 'N/A'), {UX}, user IN ('', 'N/A', 'system') OR isIPv4String(user) OR isIPv6String(user), '', user)")
AUTH_WHERE = (
    f"((event_subtype = 'vpn' AND ({UX} NOT IN ('', 'N/A') OR positionCaseInsensitive({_x('tunneltype')}, 'ssl') > 0 "
    "OR orig_action LIKE 'ssl-%' OR parser_version LIKE 'panos%')) "
    f"OR log_id IN ('{ADMIN_LOGIN}', '{ADMIN_FAIL}', '{ADMIN_LOGOUT}') OR positionCaseInsensitive(msg, 'login fail') > 0 "
    "OR (event_type = 'windows' AND action IN ('logon', 'logon-fail', 'lockout')) "
    "OR (event_subtype = 'user' AND positionCaseInsensitive(orig_action, 'auth') > 0))")
VPN_SKIP = ("0101037128", "0101037127", "0101037124", "0101037120", "0101037122", "0101037129")  # IKE progress noise


def _cosmetic(attr: str) -> bool:
    """An admin editing only their own GUI preferences (dashboard widgets, menu favourites, theme) is logged as
    `Edit system.admin <name>`; that is not an account or privilege change."""
    parts = [p.strip() for p in (attr or "").split(",") if p.strip()]
    return bool(parts) and all(p.startswith(("gui-", "theme", "dashboard")) for p in parts)


def _tz_offset(tz: str) -> timedelta:
    tz = (tz or "").strip()
    if len(tz) == 5 and tz[0] in "+-" and tz[1:].isdigit():
        return timedelta(hours=int(tz[1:3]), minutes=int(tz[3:5])) * (1 if tz[0] == "+" else -1)
    return timedelta(0)


def classify(r: dict) -> tuple[str, str]:
    """(kind, result) for one auth row. kind: vpn | admin | windows | fw_auth. result: success | failure | logout | info."""
    act = (r["act"] or "").lower()
    status = (r["status"] or "").lower()
    res = (r["result"] or "").lower()
    if r["log_id"] in (ADMIN_LOGIN, ADMIN_FAIL, ADMIN_LOGOUT) or (r["sub"] == "system" and act in ("login", "logout")) or "login fail" in (r["msg"] or "").lower():
        if r["log_id"] == ADMIN_FAIL or status == "failed" or "fail" in (r["msg"] or "").lower():
            return "admin", "failure"
        return "admin", "logout" if r["log_id"] == ADMIN_LOGOUT or act == "logout" else "success"
    if r["typ"] == "windows":
        return "windows", {"logon": "success", "logon-fail": "failure", "lockout": "failure"}.get(r["action"], "info")
    if r["sub"] == "user":
        return "fw_auth", "failure" if "fail" in status or "fail" in act else "success"
    if "fail" in act or status in ("failure", "failed") or "fail" in res or "denied" in res:
        return "vpn", "failure"
    if act in ("tunnel-up", "ssl-login", "ssl-web-login", "login", "connected"):
        return "vpn", "success"
    if act in ("tunnel-down", "ssl-logout", "logout", "disconnected"):
        return "vpn", "logout"
    return "vpn", "info"


async def auth_events(ch, t0: datetime, t1: datetime, fw_ids: list[int] | None = None, user: str | None = None, limit: int = 200_000) -> list[dict]:
    p: dict = {"t0": t0, "t1": t1}
    fw = _fw(fw_ids, p)
    uf = ""
    if user:
        p["u"] = user
        uf = f" AND lower({IDENT}) = lower({{u:String}})"
    rows = await ch.aquery(
        f"SELECT event_time AS t, firewall_id, firewall_name, log_id, event_subtype AS sub, event_type AS typ, orig_action AS act, action, "
        f"{IDENT} AS u, src_ip, src_country, src_lat, src_lon, extract(raw, '(?:^| )user=\"([^\"]*)\"') AS raw_user, {_x('remip', False)} AS remip, "
        f"{_x('assignip', False)} AS assignip, {_x('tunnelip', False)} AS tunnelip, {_x('fctuid')} AS fctuid, "
        f"if({_x('xauthgroup')} NOT IN ('', 'N/A'), {_x('xauthgroup')}, {_x('group')}) AS grp, vpn_tunnel AS ttype, "
        f"{_x('vpntunnel')} AS tunnel, {_x('status')} AS status, {_x('result')} AS result, {_x('reason')} AS reason, "
        f"{_x('ui')} AS ui, {_x('profile')} AS profile, {_x('method')} AS method, {_x('tz')} AS tz, hostname, src_name, src_mac, msg, "
        f"toUInt64OrZero({_x('duration', False)}) AS dur, toUInt64OrZero({_x('sentbyte', False)}) AS sb, toUInt64OrZero({_x('rcvdbyte', False)}) AS rb "
        f"FROM events WHERE category = 'system' AND event_time >= {{t0:DateTime64(3)}} AND event_time < {{t1:DateTime64(3)}} "
        f"AND log_id NOT IN {VPN_SKIP} AND {AUTH_WHERE}{fw}{uf} ORDER BY event_time LIMIT {int(limit)}", p)
    out = []
    for r in rows:
        kind, result = classify(r)
        u = r["u"]
        if not u:
            continue
        t = _aware(r["t"])
        src = r["remip"] if r["remip"] not in ("", "N/A") else r["src_ip"]
        dev = r["fctuid"] if r["fctuid"] not in ("", "N/A") else (r["src_name"] or r["hostname"] or "")
        client_ip = r["raw_user"] if r["raw_user"] and _is_ip(r["raw_user"]) and r["raw_user"] != src else ""
        assigned = next((x for x in (r["assignip"], r["tunnelip"]) if x and x not in ("N/A", "0.0.0.0") and _is_ip(x)), "")
        out.append({"t": t, "local_hour": (t + _tz_offset(r["tz"])).hour, "local_dow": (t + _tz_offset(r["tz"])).weekday(),
                    "firewall_id": int(r["firewall_id"]), "firewall_name": r["firewall_name"], "user": u, "key": u.lower(), "kind": kind,
                    "result": result, "src_ip": src or "", "country": r["src_country"] or "", "lat": r["src_lat"], "lon": r["src_lon"],
                    "assigned_ip": assigned, "client_ip": client_ip, "device": dev, "group": r["grp"] if r["grp"] not in ("N/A",) else "",
                    "tunnel": r["tunnel"] if r["tunnel"] not in ("N/A",) else "", "method": r["method"] or (r["ui"].split("(")[0] if r["ui"] else ""),
                    "profile": r["profile"], "detail": r["result"] or r["reason"] or r["msg"] or "", "action": r["act"],
                    "duration": int(r["dur"] or 0), "sent": int(r["sb"] or 0), "rcvd": int(r["rb"] or 0)})
    return out


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


# ------------------------------------------------------------------ VPN sessions
def sessions(events: list[dict], now: datetime) -> list[dict]:
    """Pair VPN logins with logouts per (firewall, user, tunnel instance); enrich with assigned IP / device / bytes."""
    open_: dict[tuple, dict] = {}
    out: list[dict] = []
    for e in events:
        if e["kind"] != "vpn":
            continue
        k = (e["firewall_id"], e["key"], e["tunnel"] or e["src_ip"])
        s = open_.get(k)
        if e["result"] == "success":
            if s:  # a second login without logout: close the previous one at this point
                s["end"], s["ended_by"] = e["t"], "relogin"
                out.append(s)
            open_[k] = {"firewall_id": e["firewall_id"], "firewall_name": e["firewall_name"], "user": e["user"], "start": e["t"], "end": None,
                        "src_ip": e["src_ip"], "country": e["country"], "assigned_ip": e["assigned_ip"], "device": e["device"],
                        "client_ip": e["client_ip"], "group": e["group"], "tunnel": e["tunnel"], "sent": 0, "rcvd": 0, "ended_by": ""}
        elif s is not None:
            for f in ("assigned_ip", "device", "client_ip", "group"):
                s[f] = s[f] or e[f]
            if e["sent"] or e["rcvd"]:
                s["sent"], s["rcvd"] = max(s["sent"], e["sent"]), max(s["rcvd"], e["rcvd"])
            if e["result"] == "logout":
                s["end"], s["ended_by"] = e["t"], "logout"
                out.append(s)
                del open_[k]
    out += list(open_.values())
    for s in out:
        end = s["end"] or now
        s["duration_s"] = round((end - s["start"]).total_seconds())
        s["active"] = s["end"] is None
        s["start"], s["end"] = s["start"].isoformat(), s["end"].isoformat() if s["end"] else None
    out.sort(key=lambda s: s["start"], reverse=True)
    return out


async def traffic_for_sessions(ch, sess: list[dict], limit: int = 20) -> dict:
    """Traffic sourced from a session's assigned IP while the session was up — the person's own traffic."""
    pairs = [(s["assigned_ip"], s["start"], s["end"] or datetime.now(timezone.utc).isoformat()) for s in sess if s["assigned_ip"]][:limit]
    if not pairs:
        return {"bytes_sent": 0, "bytes_rcvd": 0, "events": 0, "destinations": [], "apps": []}
    cond = " OR ".join(f"(src_ip = {{ip{i}:String}} AND event_time >= {{a{i}:DateTime64(3)}} AND event_time < {{b{i}:DateTime64(3)}})" for i in range(len(pairs)))
    p: dict = {}
    for i, (ip, a, b) in enumerate(pairs):
        p.update({f"ip{i}": ip, f"a{i}": _aware(a), f"b{i}": _aware(b)})
    tot = await ch.aquery(f"SELECT count() AS n, sum(sent_bytes) AS s, sum(rcvd_bytes) AS r FROM events WHERE category = 'traffic' AND ({cond})", p)
    dst = await ch.aquery(f"SELECT dst_ip, any(dst_country) AS country, any(app) AS app, count() AS n, sum(sent_bytes + rcvd_bytes) AS bytes "
                          f"FROM events WHERE category = 'traffic' AND ({cond}) GROUP BY dst_ip ORDER BY bytes DESC LIMIT 15", p)
    apps = await ch.aquery(f"SELECT if(app = '', service, app) AS a, count() AS n, sum(sent_bytes + rcvd_bytes) AS bytes FROM events "
                           f"WHERE category = 'traffic' AND ({cond}) GROUP BY a ORDER BY bytes DESC LIMIT 10", p)
    t = tot[0] if tot else {}
    return {"events": int(t.get("n") or 0), "bytes_sent": int(t.get("s") or 0), "bytes_rcvd": int(t.get("r") or 0),
            "destinations": [{**d, "n": int(d["n"]), "bytes": int(d["bytes"])} for d in dst],
            "apps": [{"app": a["a"], "n": int(a["n"]), "bytes": int(a["bytes"])} for a in apps]}


# ------------------------------------------------------------------ baselines and anomalies
def baseline(events: list[dict]) -> dict[str, dict]:
    """Per user: countries, source /24s, devices and local login hours seen in successful logins."""
    b: dict[str, dict] = {}
    for e in events:
        if e["result"] != "success":
            continue
        x = b.setdefault(e["key"], {"logins": 0, "countries": set(), "nets": set(), "devices": set(), "hours": defaultdict(int), "sources": set()})
        x["logins"] += 1
        if e["country"]:
            x["countries"].add(e["country"])
        if e["src_ip"]:
            x["sources"].add(e["src_ip"])
            x["nets"].add(_net24(e["src_ip"]))
        if e["device"]:
            x["devices"].add(e["device"])
        x["hours"][e["local_hour"]] += 1
    return b


def _net24(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip)
        return str(ipaddress.ip_network(f"{ip}/{24 if a.version == 4 else 48}", strict=False))
    except ValueError:
        return ip


def anomalies(events: list[dict], base: dict[str, dict], *, min_baseline: int = 5, work_hours: tuple[int, int] = (7, 22),
              weekend: bool = True) -> list[dict]:
    """Flags on successful logins: new country, new network, new device, unusual hour for this user, outside business hours,
    admin login from a new source."""
    out = []
    for e in events:
        if e["result"] != "success":
            continue
        b = base.get(e["key"])
        reasons = []
        known = b is not None and b["logins"] >= min_baseline
        if known:
            if e["country"] and e["country"] not in b["countries"]:
                reasons.append(("new_country", f"first login from {e['country']} (usual: {', '.join(sorted(b['countries'])) or 'none'})"))
            if e["src_ip"] and _net24(e["src_ip"]) not in b["nets"] and e["kind"] == "admin":
                reasons.append(("new_admin_source", f"administrator login from a new network {_net24(e['src_ip'])}"))
            elif e["src_ip"] and _net24(e["src_ip"]) not in b["nets"] and not reasons:
                reasons.append(("new_network", f"login from a network not seen for this user ({_net24(e['src_ip'])})"))
            if e["device"] and b["devices"] and e["device"] not in b["devices"]:
                reasons.append(("new_device", f"new device {e['device'][:12]}… (user has {len(b['devices'])} known)"))
            seen = sum(b["hours"].values())
            if seen >= 10 and b["hours"].get(e["local_hour"], 0) == 0 and not any(b["hours"].get((e["local_hour"] + d) % 24) for d in (-1, 1)):
                reasons.append(("unusual_hour", f"login at {e['local_hour']:02d}:00 local, a time this user never logs in"))
        # business hours apply to administrators; everyone else is judged against their own hours (unusual_hour above)
        if e["kind"] == "admin" and (not (work_hours[0] <= e["local_hour"] < work_hours[1]) or (weekend and e["local_dow"] >= 5)):
            reasons.append(("off_hours", f"administrator login at {e['local_hour']:02d}:00 local" + (" on a weekend" if e["local_dow"] >= 5 else "")))
        if reasons:
            out.append({"t": e["t"].isoformat(), "user": e["user"], "kind": e["kind"], "firewall_id": e["firewall_id"], "firewall_name": e["firewall_name"],
                        "src_ip": e["src_ip"], "country": e["country"], "device": e["device"], "reasons": [{"type": a, "detail": d} for a, d in reasons],
                        "score": sum({"new_country": 40, "new_admin_source": 35, "new_device": 25, "unusual_hour": 20, "new_network": 10,
                                      "off_hours": 15}.get(a, 10) for a, _ in reasons) + (15 if e["kind"] == "admin" else 0)})
    out.sort(key=lambda x: (-x["score"], x["t"]))
    return out


def failures(events: list[dict], window: timedelta = timedelta(minutes=30)) -> dict:
    """Repeated authentication failures by user and by source, password spraying, and success after failures."""
    by_user: dict[str, dict] = {}
    by_src: dict[str, dict] = {}
    fails_by_user: dict[str, list] = defaultdict(list)
    after: list[dict] = []
    for e in events:
        if e["result"] == "failure":
            u = by_user.setdefault(e["key"], {"user": e["user"], "failures": 0, "sources": set(), "kinds": set(), "first": e["t"], "last": e["t"],
                                              "countries": set(), "detail": ""})
            u["failures"] += 1
            u["sources"].add(e["src_ip"])
            u["kinds"].add(e["kind"])
            u["last"] = e["t"]
            u["detail"] = e["detail"] or u["detail"]
            if e["country"]:
                u["countries"].add(e["country"])
            s = by_src.setdefault(e["src_ip"] or "unknown", {"src_ip": e["src_ip"], "failures": 0, "users": set(), "kinds": set(), "country": e["country"],
                                                              "first": e["t"], "last": e["t"]})
            s["failures"] += 1
            s["users"].add(e["user"])
            s["kinds"].add(e["kind"])
            s["last"] = e["t"]
            fails_by_user[e["key"]].append(e)
        elif e["result"] == "success":
            prior = [f for f in fails_by_user.get(e["key"], []) if e["t"] - window <= f["t"] <= e["t"]]
            if len(prior) >= 3:
                after.append({"t": e["t"].isoformat(), "user": e["user"], "kind": e["kind"], "failures": len(prior), "src_ip": e["src_ip"],
                              "failed_from": sorted({f["src_ip"] for f in prior if f["src_ip"]})[:10], "firewall_id": e["firewall_id"],
                              "firewall_name": e["firewall_name"], "same_source": any(f["src_ip"] == e["src_ip"] for f in prior)})
                fails_by_user[e["key"]] = []

    def fin(d, sets):
        return {**d, **{k: sorted(x for x in d[k] if x) for k in sets}, "first": d["first"].isoformat(), "last": d["last"].isoformat()}
    users = sorted((fin(u, ("sources", "kinds", "countries")) for u in by_user.values()), key=lambda x: -x["failures"])
    srcs = sorted((fin(s, ("users", "kinds")) for s in by_src.values()), key=lambda x: -x["failures"])
    return {"by_user": users[:300], "by_source": srcs[:300], "spraying": [s for s in srcs if len(s["users"]) >= 5][:100],
            "success_after_failures": after[-200:][::-1]}


# ------------------------------------------------------------------ administrators
async def admin_activity(ch, t0: datetime, t1: datetime, fw_ids: list[int] | None = None) -> dict:
    """Configuration changes and CLI commands by administrator, plus changes to admin accounts and privileges."""
    p: dict = {"t0": t0, "t1": t1}
    fw = _fw(fw_ids, p)
    rows = await ch.aquery(
        f"SELECT event_time AS t, firewall_id, firewall_name, log_id, user, {_x('ui')} AS ui, orig_action AS act, {_x('cfgpath')} AS path, "
        f"{_x('cfgobj')} AS obj, {_x('cfgattr')} AS attr, msg, src_ip, event_type AS typ, event_subtype AS sub, action, {_x('tz')} AS tz "
        f"FROM events WHERE category = 'system' AND event_time >= {{t0:DateTime64(3)}} AND event_time < {{t1:DateTime64(3)}} "
        f"AND (log_id IN {CFG_LOGIDS + (CLI_LOGID,)} OR (event_type = 'windows' AND event_subtype IN {tuple(WIN_ACCOUNT)})){fw} "
        f"ORDER BY event_time LIMIT 100000", p)
    changes, account, commands = [], [], []
    ha_synced = 0
    for r in rows:
        if (r["ui"] or "").startswith("ha_daemon"):  # replicated to the other HA member: the original change is already counted
            ha_synced += 1
            continue
        ta = _aware(r["t"])
        t = ta.isoformat()
        loc = ta + _tz_offset(r["tz"])
        src = r["src_ip"] or (r["ui"].split("(")[-1].rstrip(")") if "(" in (r["ui"] or "") else "")
        base = {"t": t, "firewall_id": int(r["firewall_id"]), "firewall_name": r["firewall_name"], "admin": r["user"] or "?",
                "method": (r["ui"] or "").split("(")[0], "src_ip": src, "local_hour": loc.hour, "local_dow": loc.weekday()}
        if r["typ"] == "windows":
            account.append({**base, "path": "windows", "object": r["user"], "action": WIN_ACCOUNT.get(r["sub"], r["sub"]),
                            "attr": r["msg"][:300], "privilege": r["sub"] in ("4728", "4732", "4756"), "detail": r["msg"][:300]})
            continue
        if r["log_id"] == CLI_LOGID:
            commands.append({**base, "action": r["act"], "command": (r["msg"] or "")[:300]})
            continue
        c = {**base, "path": r["path"], "object": r["obj"], "action": r["act"], "attr": (r["attr"] or "")[:500], "detail": (r["msg"] or "")[:300],
             "cosmetic": r["path"] == "system.admin" and _cosmetic(r["attr"])}
        changes.append(c)
        if any(r["path"] == a or r["path"].startswith(a + ".") or r["path"].startswith(a + ":") for a in ACCOUNT_PATHS) and not _cosmetic(r["attr"]):
            attr = (r["attr"] or "").lower()
            priv = r["act"].lower() in ("add", "delete") and r["path"] in ("system.admin", "system.api-user", "system.accprofile") \
                or any(w in attr for w in PRIV_WORDS) or "super_admin" in (r["msg"] or "").lower()
            account.append({**c, "privilege": bool(priv)})
    admins: dict[str, dict] = {}
    for c in changes + commands:
        a = admins.setdefault(c["admin"], {"admin": c["admin"], "changes": 0, "commands": 0, "paths": defaultdict(int), "sources": set(),
                                           "methods": set(), "firewalls": set(), "last": c["t"]})
        if "command" in c:
            a["commands"] += 1
        else:
            a["changes"] += 1
            a["paths"][c["path"]] += 1
        if c["src_ip"]:
            a["sources"].add(c["src_ip"])
        if c["method"]:
            a["methods"].add(c["method"])
        a["firewalls"].add(c["firewall_name"])
        a["last"] = max(a["last"], c["t"])
    adm = [{**a, "paths": sorted(({"path": k, "n": v} for k, v in a["paths"].items()), key=lambda x: -x["n"])[:10],
            "sources": sorted(a["sources"]), "methods": sorted(a["methods"]), "firewalls": sorted(a["firewalls"])} for a in admins.values()]
    adm.sort(key=lambda x: -(x["changes"] + x["commands"]))
    return {"admins": adm, "changes": changes[::-1][:1000], "account_changes": account[::-1][:500], "commands": commands[::-1][:500],
            "ha_synced": ha_synced}


# ------------------------------------------------------------------ overview
async def overview(ch, t0: datetime, t1: datetime, fw_ids: list[int] | None = None, baseline_days: int = 30) -> dict:
    now = min(t1, datetime.now(timezone.utc))
    hist = await auth_events(ch, t0 - timedelta(days=baseline_days), t0, fw_ids)
    evs = await auth_events(ch, t0, t1, fw_ids)
    base = baseline(hist)
    sess = sessions(evs, now)
    anom = anomalies(evs, base)
    fails = failures(evs)
    admin = await admin_activity(ch, t0, t1, fw_ids)
    users: dict[str, dict] = {}
    for e in evs:
        u = users.setdefault(e["key"], {"user": e["user"], "kinds": set(), "logins": 0, "failures": 0, "sources": set(), "countries": set(),
                                        "devices": set(), "assigned_ips": set(), "client_ips": set(), "groups": set(), "profiles": set(),
                                        "firewalls": set(), "last_login": None, "last_failure": None, "last_src": "", "last_country": ""})
        u["kinds"].add(e["kind"])
        u["firewalls"].add(e["firewall_name"])
        for k, f in (("sources", "src_ip"), ("countries", "country"), ("devices", "device"), ("assigned_ips", "assigned_ip"),
                     ("client_ips", "client_ip"), ("groups", "group")):
            if e[f]:
                u[k].add(e[f])
        if e["profile"]:
            u["profiles"].add(e["profile"])
        if e["result"] == "success":
            u["logins"] += 1
            u["last_login"] = e["t"]
            u["last_src"], u["last_country"] = e["src_ip"], e["country"]
        elif e["result"] == "failure":
            u["failures"] += 1
            u["last_failure"] = e["t"]
    active = {s["user"].lower() for s in sess if s["active"]}
    risk: dict[str, int] = defaultdict(int)
    for a in anom:
        risk[a["user"].lower()] = max(risk[a["user"].lower()], a["score"])
    for f in fails["by_user"]:
        risk[f["user"].lower()] += min(40, f["failures"] * 4)
    for s in fails["success_after_failures"]:
        risk[s["user"].lower()] += 40
    out = []
    for k, u in users.items():
        out.append({**{x: sorted(u[x]) for x in ("kinds", "sources", "countries", "devices", "assigned_ips", "client_ips", "groups", "profiles", "firewalls")},
                    "user": u["user"], "logins": u["logins"], "failures": u["failures"], "active": k in active, "is_admin": "admin" in u["kinds"],
                    "last_login": u["last_login"].isoformat() if u["last_login"] else None,
                    "last_failure": u["last_failure"].isoformat() if u["last_failure"] else None, "last_src": u["last_src"], "last_country": u["last_country"],
                    "anomalies": sum(1 for a in anom if a["user"].lower() == k), "risk": min(100, risk.get(k, 0)),
                    "baseline_logins": base.get(k, {}).get("logins", 0)})
    out.sort(key=lambda x: (-x["risk"], -x["failures"], -x["logins"]))
    # username <-> IP <-> device map
    links: dict[tuple, dict] = {}
    for e in evs:
        for ip, typ in ((e["src_ip"], "public" if e["kind"] == "vpn" else "source"), (e["assigned_ip"], "vpn-assigned"), (e["client_ip"], "client-local")):
            if not ip:
                continue
            lk = links.setdefault((e["key"], ip, typ), {"user": e["user"], "ip": ip, "type": typ, "device": e["device"], "country": e["country"] if typ in ("public", "source") else "",
                                                       "first": e["t"], "last": e["t"], "events": 0, "kind": e["kind"]})
            lk["events"] += 1
            lk["last"] = e["t"]
            lk["device"] = lk["device"] or e["device"]
    ip_map = sorted(({**v, "first": v["first"].isoformat(), "last": v["last"].isoformat()} for v in links.values()), key=lambda x: x["last"], reverse=True)
    shared = defaultdict(set)
    for v in ip_map:
        if v["type"] in ("public", "source", "client-local"):
            shared[v["ip"]].add(v["user"])
    hourly = [0] * 24
    for e in evs:
        if e["result"] == "success":
            hourly[e["local_hour"]] += 1
    return {
        "window": {"start": t0.isoformat(), "end": t1.isoformat()},
        "totals": {"users": len(out), "admins": sum(1 for u in out if u["is_admin"]), "vpn_users": sum(1 for u in out if "vpn" in u["kinds"]),
                   "active_sessions": sum(1 for s in sess if s["active"]), "logins": sum(u["logins"] for u in out),
                   "failures": sum(u["failures"] for u in out), "anomalies": len(anom), "success_after_failures": len(fails["success_after_failures"]),
                   "account_changes": len(admin["account_changes"]), "privilege_changes": sum(1 for a in admin["account_changes"] if a["privilege"]),
                   "config_changes": len(admin["changes"])},
        "users": out[:1000], "sessions": sess[:1000], "anomalies": anom[:500], "failures": fails, "ip_map": ip_map[:2000],
        "shared_ips": sorted(({"ip": ip, "users": sorted(us)} for ip, us in shared.items() if len(us) > 1), key=lambda x: -len(x["users"]))[:100],
        "login_hours": hourly, "admin": admin,
    }


async def user_detail(ch, user: str, t0: datetime, t1: datetime) -> dict | None:
    now = min(t1, datetime.now(timezone.utc))
    evs = await auth_events(ch, t0, t1, user=user)
    hist = await auth_events(ch, t0 - timedelta(days=30), t0, user=user)
    if not evs and not hist:
        return None
    base = baseline(hist)
    sess = sessions(evs, now)
    admin = await admin_activity(ch, t0, t1)
    key = user.lower()
    mine = {k: [x for x in admin[k] if (x.get("admin") or "").lower() == key or (x.get("object") or "").lower() == key]
            for k in ("changes", "account_changes", "commands")}
    b = base.get(key)
    return {"user": evs[-1]["user"] if evs else hist[-1]["user"],
            "events": [{**e, "t": e["t"].isoformat()} for e in reversed(evs[-1000:])],
            "sessions": sess[:200], "traffic": await traffic_for_sessions(ch, sess),
            "anomalies": anomalies(evs, base), "failures": failures(evs),
            "baseline": {"logins": b["logins"], "countries": sorted(b["countries"]), "devices": sorted(b["devices"]), "sources": sorted(b["sources"])[:50],
                         "hours": [b["hours"].get(h, 0) for h in range(24)]} if b else None,
            "login_hours": [sum(1 for e in evs if e["result"] == "success" and e["local_hour"] == h) for h in range(24)],
            "admin": mine}
