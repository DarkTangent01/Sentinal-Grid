"""Non-FortiGate log sources: Windows Security events, CEF from any vendor, and plain syslog.

A source is registered by the IP address(es) it sends from (Log sources page). Its events go into the same `events`
table with firewall_id = SOURCE_ID_BASE + source id, firewall_name = source name and devid = source kind, so every
dashboard, search, detection and report works across FortiGate and non-FortiGate data.

Windows (event_type = "windows", event_subtype = EventID):
    NXLog `to_json` or Winlogbeat JSON (optionally after a syslog header), or Snare "MSWinEventLog" tab-separated.
    user = TargetUserName (SubjectUserName when there is no target), src_ip = IpAddress, src_name = WorkstationName,
    hostname = Computer, app = the object acted on (group / service / task name), action = logon | logon-fail | …
CEF (event_type = "cef"): the standard extension keys (src, dst, spt, dpt, act, suser, request, dhost, in, out, …).
Anything else (event_type = "syslog"): stored as a system event with the line as the message.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

from .normalize import normalize

SOURCE_ID_BASE = 1_000_000
KINDS = ("windows", "cef", "syslog")

WIN_EVENTS: dict[str, tuple[str, str, str]] = {  # EventID → (action, severity, description)
    "4624": ("logon", "informational", "An account was successfully logged on"),
    "4625": ("logon-fail", "warning", "An account failed to log on"),
    "4634": ("logoff", "informational", "An account was logged off"),
    "4648": ("logon-explicit", "notice", "A logon was attempted using explicit credentials"),
    "4672": ("privileged-logon", "notice", "Special privileges assigned to new logon"),
    "4720": ("user-created", "notice", "A user account was created"),
    "4722": ("user-enabled", "notice", "A user account was enabled"),
    "4723": ("password-change", "notice", "An attempt was made to change an account's password"),
    "4724": ("password-reset", "notice", "An attempt was made to reset an account's password"),
    "4725": ("user-disabled", "notice", "A user account was disabled"),
    "4726": ("user-deleted", "warning", "A user account was deleted"),
    "4728": ("group-add", "warning", "A member was added to a security-enabled global group"),
    "4732": ("group-add", "warning", "A member was added to a security-enabled local group"),
    "4756": ("group-add", "warning", "A member was added to a security-enabled universal group"),
    "4740": ("lockout", "warning", "A user account was locked out"),
    "4767": ("unlock", "notice", "A user account was unlocked"),
    "4768": ("kerberos-tgt", "informational", "A Kerberos authentication ticket (TGT) was requested"),
    "4771": ("kerberos-preauth-fail", "warning", "Kerberos pre-authentication failed"),
    "4776": ("ntlm-validate", "informational", "The computer attempted to validate the credentials for an account"),
    "4697": ("service-installed", "warning", "A service was installed in the system"),
    "7045": ("service-installed", "warning", "A new service was installed in the system"),
    "4698": ("task-created", "warning", "A scheduled task was created"),
    "1102": ("log-cleared", "alert", "The audit log was cleared"),
    "104": ("log-cleared", "alert", "The event log was cleared"),
}
SEVERITY = {"informational": "informational", "notice": "low", "warning": "medium", "alert": "high", "critical": "critical"}
_JSON_START = re.compile(r"\{")
_CEF = re.compile(r"CEF:(\d+)\|((?:[^|\\]|\\.)*)\|((?:[^|\\]|\\.)*)\|((?:[^|\\]|\\.)*)\|((?:[^|\\]|\\.)*)\|((?:[^|\\]|\\.)*)\|((?:[^|\\]|\\.)*)\|(.*)$")
_CEF_KV = re.compile(r"(\w+)=((?:[^=\\]|\\.)*?)(?=\s+\w+=|$)")


def _flatten(d: dict, prefix: str = "") -> dict:
    out = {}
    for k, v in d.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(_flatten(v, f"{key}."))
        else:
            out[key] = v
    return out


def _first(d: dict, *keys, default=""):
    for k in keys:
        v = d.get(k)
        if v not in (None, "", "-"):
            return v
    return default


def _ts(v) -> datetime | None:
    if v in (None, ""):
        return None
    try:
        if isinstance(v, (int, float)) or str(v).isdigit():
            x = float(v)
            return datetime.fromtimestamp(x / 1000 if x > 1e11 else x, timezone.utc)
        s = str(v).replace("Z", "+00:00").replace(" ", "T", 1)
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


def _base(src: dict, ts: datetime | None, extra: dict, raw: str) -> dict:
    """Build a FortiGate-shaped field dict and run it through the standard normalizer."""
    f = {**extra}
    t = ts or datetime.now(timezone.utc)
    f["eventtime"] = str(int(t.timestamp() * 1e9))
    ev = normalize(f, source="syslog", raw=raw, firewall={"id": SOURCE_ID_BASE + int(src["id"]), "name": src["name"], "site": src.get("site", "")})
    # identity = source + exact line: a re-sent line dedupes, distinct records (RecordNumber, rt, ...) never collide
    ev["event_id"] = hashlib.sha256(f"{src['id']}|{raw}".encode()).hexdigest()[:32]
    ev["devid"] = src["kind"]
    return ev


def windows(src: dict, line: str) -> dict | None:
    j = None
    m = _JSON_START.search(line)
    if m:
        try:
            j = _flatten(json.loads(line[m.start():]))
        except ValueError:
            j = None
    if j is None and "MSWinEventLog" in line:
        parts = line.split("\t")  # Snare: ... MSWinEventLog \t crit \t channel \t num \t date \t EventID \t source \t user \t sidtype \t ...
        try:
            i = next(k for k, p in enumerate(parts) if p.strip().endswith("MSWinEventLog"))
            j = {"EventID": parts[i + 5].strip(), "Channel": parts[i + 2].strip(), "EventTime": parts[i + 4].strip(),
                 "TargetUserName": parts[i + 7].strip(), "Message": "\t".join(parts[i + 12:]).strip(), "Hostname": parts[i + 10].strip() if len(parts) > i + 10 else ""}
        except (StopIteration, IndexError):
            return None
    if j is None:
        return None
    eid = str(_first(j, "EventID", "winlog.event_id", "event.code", "EventId"))
    if not eid:
        return None
    action, sev, desc = WIN_EVENTS.get(eid, ("event", "informational", ""))
    status = str(_first(j, "Status", "winlog.event_data.Status", "Result")).lower()
    if eid == "4776" and status not in ("", "0x0", "0"):
        action, sev = "ntlm-fail", "warning"
    get = lambda *ks: _first(j, *ks, *[f"winlog.event_data.{k}" for k in ks], *[f"EventData.{k}" for k in ks])  # noqa: E731
    target = get("TargetUserName")
    subject = get("SubjectUserName")
    member = get("MemberName", "MemberSid")
    obj = {"group-add": target, "service-installed": get("ServiceName"), "task-created": get("TaskName")}.get(action, "")
    user = (member if action == "group-add" else target or subject) or ""
    ip = str(get("IpAddress", "ClientAddress", "source.ip")).replace("::ffff:", "")
    if ip in ("-", "::1", "127.0.0.1"):
        ip = ""
    msg = str(get("Message", "message") or desc).split("\r")[0].split("\n")[0][:500]
    if action == "group-add" and target:
        msg = f"{desc}: {member or 'member'} → {target}"
    extra = {"type": "windows", "subtype": eid, "logid": f"win-{eid}", "level": sev, "srcip": ip, "srcport": str(get("IpPort") or ""),
             "user": str(user)[:128], "hostname": str(_first(j, "Hostname", "Computer", "host.name", "winlog.computer_name"))[:255],
             "app": str(obj)[:255], "action": action, "msg": msg, "srcname": str(get("WorkstationName"))[:128]}
    ev = _base(src, _ts(_first(j, "EventTime", "@timestamp", "TimeCreated", "EventReceivedTime")), extra, line.strip())
    ev.update({"category": "system", "event_type": "windows", "event_subtype": eid, "action": action, "orig_action": action,
               "severity": SEVERITY[sev], "src_name": extra["srcname"]})
    return ev


def _cef_unescape(v: str) -> str:
    return v.replace("\\=", "=").replace("\\|", "|").replace("\\\\", "\\").replace("\\n", " ").strip()


def cef(src: dict, line: str) -> dict | None:
    m = _CEF.search(line)
    if not m:
        return None
    _, vendor, product, _ver, sig, name, sev, ext = m.groups()
    kv = {k: _cef_unescape(v) for k, v in _CEF_KV.findall(ext)}
    act = kv.get("act", "").lower()
    dpt = kv.get("dpt", "")
    name = _cef_unescape(name)
    if kv.get("request") or kv.get("requestMethod"):
        cat, sub = "web", "webfilter"
    elif dpt == "53" or "dns" in name.lower():
        cat, sub = "dns", "dns"
    elif (kv.get("src") or kv.get("dst")) and act in ("allow", "allowed", "accept", "permit", "deny", "denied", "block", "blocked", "drop", "dropped"):
        cat, sub = "traffic", "forward"
    elif kv.get("src") or kv.get("dst"):
        cat, sub = "security", "ips"
    else:
        cat, sub = "system", "event"
    try:
        sevn = int(float(sev))
    except ValueError:
        sevn = {"low": 2, "medium": 5, "high": 8, "very-high": 10}.get(sev.lower(), 3)
    severity = "critical" if sevn >= 9 else "high" if sevn >= 7 else "medium" if sevn >= 4 else "low" if sevn >= 1 else "informational"
    act_norm = {"allowed": "accept", "allow": "accept", "permit": "accept", "denied": "deny", "blocked": "block", "dropped": "deny", "drop": "deny"}.get(act, act)
    extra = {"type": "cef", "subtype": sub, "logid": f"cef-{_cef_unescape(sig)}"[:64], "srcip": kv.get("src", ""), "dstip": kv.get("dst", ""),
             "srcport": kv.get("spt", ""), "dstport": dpt, "proto": {"tcp": "6", "udp": "17", "icmp": "1"}.get(kv.get("proto", "").lower(), ""),
             "action": act_norm, "user": kv.get("suser") or kv.get("duser", ""), "hostname": kv.get("dhost", ""),
             "url": kv.get("request", ""), "qname": kv.get("dhost", "") if cat == "dns" else "", "sentbyte": kv.get("out", ""),
             "rcvdbyte": kv.get("in", ""), "msg": kv.get("msg") or name, "app": kv.get("app", ""), "catdesc": kv.get("cat", ""),
             "attack": name if cat == "security" else ""}
    ev = _base(src, _ts(kv.get("rt") or kv.get("end")), extra, line.strip())
    ev.update({"category": cat, "event_type": "cef", "event_subtype": f"{_cef_unescape(vendor)}/{_cef_unescape(product)}"[:64],
               "severity": severity, "action": act_norm if act_norm in ("accept", "deny", "block", "close") else (act_norm or ""),
               "orig_action": act})
    return ev


def plain(src: dict, line: str) -> dict:
    ev = _base(src, None, {"type": "syslog", "subtype": "", "msg": line.strip()[:1000]}, line.strip())
    ev.update({"category": "system", "event_type": "syslog", "severity": "informational"})
    return ev


def parse(src: dict, line: str) -> dict | None:
    """Parse one line from a registered generic source; falls back to plain syslog so nothing is silently lost."""
    if src["kind"] == "windows":
        return windows(src, line) or plain(src, line)
    if src["kind"] == "cef":
        return cef(src, line) or plain(src, line)
    return cef(src, line) or plain(src, line)
