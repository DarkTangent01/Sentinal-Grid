"""Additional log formats for registered log sources: Zeek JSON logs, generic JSON (ECS-style and flat keys, including
AWS CloudTrail field names), LEEF 1.0 / 2.0, Linux authentication messages (sshd, sudo, su, PAM), Juniper Junos and
Aruba structured syslog tags, and the RFC 5424 / RFC 3164 syslog header.

Every parser returns the same event shape as the rest of the pipeline (generic._base → normalize) or None when the
line is not in its format; generic.parse then falls back to plain syslog, so a line is never lost to a parser.
Each parser has a version (PARSERS): it is stored in `parser_version` on every event it produces.

Zeek events use category "zeek" (event_subtype = the log: conn, dns, http, ssl, x509, notice, files, dhcp, ssh, weird).
They are kept apart from the firewall categories on purpose: a sensor sees the same connections as the firewall, so
counting both as "traffic" / "dns" would double every volume. The connection uid is kept in `log_id` (and a stable
numeric form in `session_id`), so all Zeek logs of one connection can be pulled together. A Zeek record is an
observation, not a verdict: nothing here sets a severity above "low" except Zeek's own notices.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

PARSERS = {"zeek": "zeek-json-1.0", "json": "json-1.0", "leef": "leef-1.0", "linux": "linux-auth-1.0", "juniper": "junos-1.0",
           "aruba": "aruba-1.0"}

# ------------------------------------------------------------------ syslog header (RFC 5424 / RFC 3164)
_H5424 = re.compile(r"^(?:<(?P<pri>\d{1,3})>)?1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) (?P<msgid>\S+) (?P<rest>.*)$", re.S)
_H3164 = re.compile(r"^(?:<(?P<pri>\d{1,3})>)?(?P<ts>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT\S+) (?P<host>[^\s:\[]+) "
                    r"(?P<app>[^\s:\[]+)(?:\[(?P<procid>\d+)\])?: ?(?P<msg>.*)$", re.S)
_SD = re.compile(r"^(?:-|(?:\[(?:[^\]\\]|\\.)*\])+) ?")
_SEV = ("critical", "critical", "critical", "high", "medium", "low", "informational", "informational")  # syslog severity 0..7


def syslog_header(line: str) -> dict:
    """{pri, facility, severity, ts, host, app, procid, msgid, msg, rfc}: empty values when the line has no header."""
    out = {"pri": None, "facility": None, "severity": "", "ts": None, "host": "", "app": "", "procid": "", "msgid": "", "msg": line, "rfc": ""}
    m = _H5424.match(line)
    if m:
        rest = m.group("rest")
        sd = _SD.match(rest)
        out.update(rfc="5424", host=_dash(m.group("host")), app=_dash(m.group("app")), procid=_dash(m.group("procid")),
                   msgid=_dash(m.group("msgid")), msg=rest[sd.end():] if sd else rest, ts=_ts(m.group("ts")))
    else:
        m = _H3164.match(line)
        if not m:
            return out
        out.update(rfc="3164", host=m.group("host"), app=m.group("app"), procid=m.group("procid") or "", msg=m.group("msg"),
                   ts=_ts3164(m.group("ts")))
    if m.group("pri") is not None and int(m.group("pri")) <= 191:
        pri = int(m.group("pri"))
        out.update(pri=pri, facility=pri >> 3, severity=_SEV[pri & 7])
    return out


def _ver(ev: dict, key: str) -> str:
    """This parser's version, keeping the normalizer's timestamp marker (+bad-ts) when it set one."""
    return PARSERS[key] + ("+bad-ts" if ev["parser_version"].endswith("+bad-ts") else "")


def _dash(v: str) -> str:
    return "" if v == "-" else v


def _ts(v) -> datetime | None:
    if v in (None, "", "-"):
        return None
    try:
        if isinstance(v, (int, float)) or re.fullmatch(r"\d+(\.\d+)?", str(v)):
            x = float(v)
            x = x / 1e9 if x > 1e17 else x / 1e6 if x > 1e14 else x / 1e3 if x > 1e11 else x
            return datetime.fromtimestamp(x, timezone.utc)
        dt = datetime.fromisoformat(str(v).replace("Z", "+00:00").replace(" ", "T", 1))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


def _ts3164(v: str) -> datetime | None:
    """RFC 3164 timestamps carry no year and no zone: the current year in UTC, last year when that would be in the future."""
    if v[:4].isdigit():
        return _ts(v)
    now = datetime.now(timezone.utc)
    try:
        dt = datetime.strptime(f"{now.year} {v}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return dt.replace(year=now.year - 1) if (dt - now).days >= 2 else dt


def _json_of(line: str) -> dict | None:
    i = line.find("{")
    if i < 0:
        return None
    try:
        j = json.loads(line[i:])
    except ValueError:
        return None
    return j if isinstance(j, dict) else None


def _flat(d: dict, prefix: str = "") -> dict:
    out = {}
    for k, v in d.items():
        if isinstance(v, dict):
            out.update(_flat(v, f"{prefix}{k}."))
        else:
            out[f"{prefix}{k}"] = v
    return out


def _g(d: dict, *keys, default=""):
    for k in keys:
        v = d.get(k)
        if v not in (None, "", "-", []):
            return v
    return default


def _s(v, n: int = 255) -> str:
    if isinstance(v, (list, tuple)):
        v = ",".join(str(x) for x in v)
    return str(v)[:n] if v not in (None, "-") else ""


_PROTO = {"tcp": "6", "udp": "17", "icmp": "1", "icmp6": "58", "ipv6-icmp": "58", "gre": "47", "esp": "50"}


def _proto(v) -> str:
    v = str(v or "").lower()
    return _PROTO.get(v, v if v.isdigit() else "")


# ------------------------------------------------------------------ Zeek (JSON logs)
ZEEK_LOGS = ("conn", "dns", "http", "ssl", "x509", "notice", "files", "dhcp", "ssh", "weird")
_ZEEK_HINT = (("conn_state", "conn"), ("qtype_name", "dns"), ("query", "dns"), ("uri", "http"), ("status_code", "http"),
              ("certificate.subject", "x509"), ("certificate.serial", "x509"), ("note", "notice"), ("fuid", "files"),
              ("assigned_addr", "dhcp"), ("client_addr", "dhcp"), ("auth_success", "ssh"), ("auth_attempts", "ssh"), ("cipher", "ssl"),
              ("server_name", "ssl"), ("validation_status", "ssl"), ("addl", "weird"), ("name", "weird"))


def zeek_uid_num(uid: str) -> str:
    """Stable 63-bit number for a connection uid (session_id is numeric): the same uid always gives the same number."""
    return str(int.from_bytes(hashlib.sha256(uid.encode()).digest()[:8], "big") >> 1) if uid else ""


def zeek_log_of(j: dict) -> str:
    path = str(j.get("_path") or "").split(".")[0]
    if path:
        return path
    return next((log for key, log in _ZEEK_HINT if key in j), "")


def zeek(src: dict, line: str, base) -> dict | None:
    j = _json_of(line)
    if j is None:
        return None
    j = _flat(j)
    log = zeek_log_of(j)
    if log not in ZEEK_LOGS:
        return None
    uid = _s(_g(j, "uid", "conn_uids", "uids"), 64).split(",")[0]
    x = {"type": "zeek", "subtype": log, "logid": uid, "sessionid": zeek_uid_num(uid), "srcip": _s(_g(j, "id.orig_h", "src", "tx_hosts", "client_addr")).split(",")[0],
         "dstip": _s(_g(j, "id.resp_h", "dst", "rx_hosts", "server_addr")).split(",")[0], "srcport": _s(_g(j, "id.orig_p", "p")), "dstport": _s(j.get("id.resp_p", "")),
         "proto": _proto(j.get("proto")), "service": _s(j.get("service", ""), 64), "level": "information"}
    sev, threat, msg = "informational", "", ""
    if log == "conn":
        x.update(duration=str(int(float(_g(j, "duration", default=0) or 0))), sentbyte=_s(_g(j, "orig_bytes", default=0)), rcvdbyte=_s(_g(j, "resp_bytes", default=0)),
                 sentpkt=_s(_g(j, "orig_pkts", default=0)), rcvdpkt=_s(_g(j, "resp_pkts", default=0)), app=_s(j.get("service", ""), 64))
        x["action"] = _s(j.get("conn_state", ""), 16)
        msg = f"conn {x['action']} history={_s(j.get('history', ''), 32)}".strip()
    elif log == "dns":
        x.update(qname=_s(j.get("query", "")), qtype=_s(_g(j, "qtype_name", "qtype"), 16), rcode=_s(_g(j, "rcode_name", "rcode"), 16),
                 ipaddr=",".join(a for a in (_s(j.get("answers", ""), 2000).split(",")) if re.fullmatch(r"[0-9a-fA-F:.]+", a))[:1000])
        if j.get("rtt") not in (None, "", "-"):
            x["latency"] = str(round(float(j["rtt"]) * 1000, 2))
        msg = f"answers={_s(j.get('answers', ''), 300)}"
    elif log == "http":
        host, uri = _s(j.get("host", "")), _s(j.get("uri", ""), 2000)
        x.update(hostname=host, url=f"{host}{uri}"[:2000], method=_s(j.get("method", ""), 16), action=_s(j.get("status_code", ""), 8),
                 sentbyte=_s(_g(j, "request_body_len", default=0)), rcvdbyte=_s(_g(j, "response_body_len", default=0)), app="http")
        msg = f"{x['method']} {uri[:200]} → {x['action']} ua={_s(j.get('user_agent', ''), 200)}"
    elif log == "ssl":
        status = _s(j.get("validation_status", ""), 200)
        x.update(hostname=_s(j.get("server_name", "")), app="ssl", action="established" if j.get("established") in (True, "T", "true") else "failed")
        if status and status.lower() != "ok":
            threat, sev = f"certificate validation: {status}"[:255], "low"
        msg = f"{_s(j.get('version', ''), 16)} {_s(j.get('cipher', ''), 64)} subject={_s(j.get('subject', ''), 200)} issuer={_s(j.get('issuer', ''), 200)}".strip()
    elif log == "x509":
        subj, iss = _s(j.get("certificate.subject", ""), 300), _s(j.get("certificate.issuer", ""), 300)
        x.update(logid=_s(_g(j, "fingerprint", "id"), 64), hostname=_s(_g(j, "san.dns"), 255).split(",")[0])
        nva = _ts(j.get("certificate.not_valid_after"))
        if subj and subj == iss:
            threat, sev = "self-signed certificate", "low"
        elif nva and nva < datetime.now(timezone.utc):
            threat, sev = "expired certificate", "low"
        msg = f"subject={subj} issuer={iss} not_after={nva.isoformat() if nva else ''}"
    elif log == "notice":
        threat = _s(j.get("note", ""))
        x.update(srcip=_s(_g(j, "id.orig_h", "src")), dstip=_s(_g(j, "id.resp_h", "dst")), dstport=_s(_g(j, "id.resp_p", "p")))
        sev = "medium"
        msg = f"{_s(j.get('msg', ''), 600)} {_s(j.get('sub', ''), 300)}".strip()
    elif log == "files":
        x.update(app=_s(j.get("source", ""), 64), hostname=_s(j.get("filename", "")), logid=uid or _s(j.get("fuid", ""), 64))
        msg = " ".join(f"{k}={_s(j.get(k, ''), 128)}" for k in ("fuid", "mime_type", "filename", "md5", "sha1", "sha256", "total_bytes") if j.get(k) not in (None, "", "-"))
    elif log == "dhcp":
        x.update(srcip=_s(_g(j, "assigned_addr", "client_addr", "requested_addr")), dstip=_s(j.get("server_addr", "")), srcmac=_s(j.get("mac", ""), 17).lower(),
                 srcname=_s(_g(j, "host_name", "client_fqdn"), 128), action=_s(j.get("msg_types", ""), 64))
        msg = f"dhcp {x['action']} lease={_s(j.get('lease_time', ''), 16)}"
    elif log == "ssh":
        ok = j.get("auth_success")
        x.update(app="ssh", action="logon" if ok in (True, "T", "true") else "logon-fail" if ok in (False, "F", "false") else "")
        msg = f"attempts={_s(j.get('auth_attempts', ''), 8)} client={_s(j.get('client', ''), 100)} server={_s(j.get('server', ''), 100)}"
    elif log == "weird":
        threat, sev = _s(j.get("name", "")), "low"
        msg = f"{_s(j.get('addl', ''), 300)} notice={_s(j.get('notice', ''), 8)}".strip()
    x["msg"] = msg[:1000]
    ev = base(src, _ts(j.get("ts")), x, line.strip())
    if log == "dns":
        ev["dns_resolved"] = [a for a in x.get("ipaddr", "").split(",") if a]
    ev.update({"category": "zeek", "event_type": "zeek", "event_subtype": log, "severity": sev, "threat": threat, "action": x.get("action", ""),
               "orig_action": x.get("action", ""), "orig_severity": "", "parser_version": _ver(ev, "zeek"), "src_name": x.get("srcname", ""),
               "http_method": x.get("method", "")})
    return ev


# ------------------------------------------------------------------ generic JSON (ECS names, flat names, CloudTrail)
_ALLOW = ("allow", "allowed", "accept", "accepted", "permit", "permitted", "pass", "success", "succeeded")
_DENY = ("deny", "denied", "block", "blocked", "drop", "dropped", "reject", "rejected")
_SEV_WORD = {"emerg": "critical", "emergency": "critical", "alert": "critical", "crit": "critical", "critical": "critical", "fatal": "critical",
             "err": "high", "error": "high", "high": "high", "warn": "medium", "warning": "medium", "medium": "medium", "notice": "low",
             "low": "low", "info": "informational", "informational": "informational", "information": "informational", "debug": "informational"}


def _severity(v) -> str:
    if v in (None, ""):
        return "informational"
    s = str(v).lower()
    if s in _SEV_WORD:
        return _SEV_WORD[s]
    try:
        n = float(s)
    except ValueError:
        return "informational"
    # ECS event.severity is source-defined; 0-10 (CEF style) and 0-100 scales are the common ones
    n = n / 10 if n > 10 else n
    return "critical" if n >= 9 else "high" if n >= 7 else "medium" if n >= 4 else "low" if n >= 1 else "informational"


def json_event(src: dict, line: str, base) -> dict | None:
    j = _json_of(line)
    if j is None:
        return None
    j = _flat(j)
    act = _s(_g(j, "event.action", "action", "act", "eventName", "operationName", "event_type"), 64)
    outcome = _s(_g(j, "event.outcome", "outcome", "result", "status"), 32).lower()
    if j.get("errorCode") or j.get("errorMessage"):  # AWS CloudTrail: either marks a failed call
        outcome = "failure"
    user = _s(_g(j, "user.name", "source.user.name", "username", "user", "userName", "userIdentity.userName", "userIdentity.arn", "suser", "account"), 128)
    url = _s(_g(j, "url.full", "url.original", "url", "request", "uri"), 2000)
    qname = _s(_g(j, "dns.question.name", "qname", "query_name"))
    dport = _s(_g(j, "destination.port", "dst_port", "dstport", "dport", "dest_port"))
    cat_hint = _s(_g(j, "event.category", "category", "eventSource", "event.dataset"), 64).lower()
    if qname or "dns" in cat_hint:
        cat, sub = "dns", "dns"
    elif url or "web" in cat_hint or "http" in cat_hint:
        cat, sub = "web", "webfilter"
    elif "authentication" in cat_hint or re.search(r"log[io]n|auth|sign.?in", act, re.I):
        cat, sub = "system", "auth"
    elif _g(j, "source.ip", "src_ip", "srcip", "src") and _g(j, "destination.ip", "dst_ip", "dstip", "dst") and (act.lower() in _ALLOW + _DENY or dport):
        cat, sub = "traffic", "forward"
    else:
        cat, sub = "system", "event"
    a = act.lower()
    if sub == "auth":
        action = "logon-fail" if outcome in ("failure", "failed", "fail", "denied") or "fail" in a else "logon"
    else:
        action = "accept" if a in _ALLOW else "deny" if a in _DENY else ""
    x = {"type": "json", "subtype": sub, "logid": _s(_g(j, "event.code", "event.id", "event_id", "eventID", "id"), 64),
         "srcip": _s(_g(j, "source.ip", "client.ip", "src_ip", "srcip", "src", "sourceIPAddress", "callerIpAddress", "remote_addr")),
         "dstip": _s(_g(j, "destination.ip", "server.ip", "dst_ip", "dstip", "dst")),
         "srcport": _s(_g(j, "source.port", "src_port", "srcport", "sport")), "dstport": dport,
         "proto": _proto(_g(j, "network.transport", "proto", "protocol")), "user": user,
         "hostname": _s(_g(j, "host.name", "host.hostname", "hostname", "host", "computer", "destination.domain", "awsRegion")),
         "url": url, "qname": qname, "method": _s(_g(j, "http.request.method", "method"), 16),
         "app": _s(_g(j, "network.application", "app", "application", "process.name", "eventSource", "service.name"), 255),
         "sentbyte": _s(_g(j, "source.bytes", "bytes_sent", "sent_bytes", "out")), "rcvdbyte": _s(_g(j, "destination.bytes", "bytes_received", "rcvd_bytes", "in")),
         "srcintf": _s(_g(j, "observer.ingress.interface.name", "in_interface"), 64), "dstintf": _s(_g(j, "observer.egress.interface.name", "out_interface"), 64),
         "srcmac": _s(_g(j, "source.mac", "mac", "src_mac"), 17), "srcname": _s(_g(j, "source.domain", "src_host", "workstation"), 128),
         "msg": _s(_g(j, "message", "msg", "event.original", "errorMessage", "description", default=act), 1000)}
    ev = base(src, _ts(_g(j, "@timestamp", "timestamp", "eventTime", "time", "event.created", "ts", "datetime", default=None)), x, line.strip())
    ev.update({"category": cat, "event_type": "json", "event_subtype": sub, "severity": _severity(_g(j, "event.severity", "severity", "level", "log.level")),
               "orig_severity": _s(_g(j, "event.severity", "severity", "level", "log.level"), 32), "action": action, "orig_action": act,
               "parser_version": _ver(ev, "json"), "src_name": x["srcname"], "http_method": x["method"]})
    return ev


# ------------------------------------------------------------------ LEEF
_LEEF = re.compile(r"LEEF:(?P<ver>[12]\.0)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<pver>[^|]*)\|(?P<eid>[^|]*)\|(?P<rest>.*)$", re.S)


def leef(src: dict, line: str, base) -> dict | None:
    m = _LEEF.search(line)
    if not m:
        return None
    rest, delim = m.group("rest"), "\t"
    if m.group("ver") == "2.0":
        d, sep, tail = rest.partition("|")
        if sep:  # LEEF 2.0: an optional delimiter field (one character, or 0xHH / xHH) before the attributes
            if re.fullmatch(r"(?:0x|x)[0-9a-fA-F]{2}", d):
                delim, rest = chr(int(d[-2:], 16)), tail
            elif len(d) == 1:
                delim, rest = d, tail
            elif d == "":
                rest = tail
    kv = {}
    for part in rest.split(delim):
        k, eq, v = part.partition("=")
        if eq and k.strip():
            kv[k.strip()] = v.strip()
    act = (kv.get("action") or kv.get("act") or "").lower()
    cat_name = kv.get("cat", "")
    dport = kv.get("dstPort", "")
    if kv.get("url"):
        cat, sub = "web", "webfilter"
    elif (kv.get("src") or kv.get("dst")) and act in _ALLOW + _DENY:
        cat, sub = "traffic", "forward"
    elif re.search(r"auth|log[io]n", f"{cat_name} {m.group('eid')}", re.I):
        cat, sub = "system", "auth"
    elif kv.get("src") or kv.get("dst"):
        cat, sub = "security", "ips"
    else:
        cat, sub = "system", "event"
    action = "accept" if act in _ALLOW else "deny" if act in _DENY else ""
    if sub == "auth":
        action = "logon-fail" if re.search(r"fail|denied|invalid", f"{act} {m.group('eid')} {cat_name}", re.I) else "logon"
    x = {"type": "leef", "subtype": sub, "logid": f"leef-{m.group('eid')}"[:64], "srcip": kv.get("src", ""), "dstip": kv.get("dst", ""),
         "srcport": kv.get("srcPort", ""), "dstport": dport, "proto": _proto(kv.get("proto")), "user": kv.get("usrName", "")[:128],
         "hostname": kv.get("identHostName", "")[:255], "url": kv.get("url", "")[:2000], "sentbyte": kv.get("srcBytes", ""), "rcvdbyte": kv.get("dstBytes", ""),
         "srcmac": kv.get("srcMAC", "").lower(), "catdesc": cat_name[:255], "attack": m.group("eid") if cat == "security" else "",
         "msg": (kv.get("msg") or kv.get("reason") or f"{m.group('eid')} {cat_name}".strip())[:1000], "app": kv.get("app", "")[:255]}
    ev = base(src, _ts(kv.get("devTime")) if re.fullmatch(r"[\d.]+|\d{4}-\d\d-\d\d[T ].*", kv.get("devTime", "")) else None, x, line.strip())
    ev.update({"category": cat, "event_type": "leef", "event_subtype": f"{m.group('vendor')}/{m.group('product')}"[:64], "severity": _severity(kv.get("sev")),
               "orig_severity": kv.get("sev", "")[:32], "action": action, "orig_action": act, "parser_version": _ver(ev, "leef")})
    return ev


# ------------------------------------------------------------------ Linux authentication (sshd, sudo, su, PAM, useradd)
_SSH_FAIL = re.compile(r"Failed (?P<method>password|publickey|keyboard-interactive/pam|none) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)")
_SSH_OK = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)")
_SSH_INVALID = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+)")
_SUDO = re.compile(r"^\s*(?P<user>\S+) : (?:(?P<fail>\d+ incorrect password attempts?|user NOT in sudoers|command not allowed) ; )?TTY=(?P<tty>\S+) ; PWD=(?P<pwd>\S+) ; USER=(?P<as>\S+) ; COMMAND=(?P<cmd>.*)$")
_PAM_FAIL = re.compile(r"pam_unix\((?P<svc>[\w-]+):auth\): authentication failure;.*?(?:rhost=(?P<ip>\S*))?(?:\s+user=(?P<user>\S+))?$")
_SU = re.compile(r"session opened for user (?P<as>\S+?)(?:\(uid=\d+\))? by (?P<user>\S*?)(?:\(uid=\d+\))?$")
_USERADD = re.compile(r"new user: name=(?P<user>[^,\s]+)")
_USERDEL = re.compile(r"delete user '(?P<user>[^']+)'")
_GROUPADD = re.compile(r"add '(?P<user>[^']+)' to group '(?P<group>[^']+)'")


def linux_auth(src: dict, line: str, base) -> dict | None:
    h = syslog_header(line)
    app, msg = h["app"].lower(), h["msg"]
    if not h["rfc"]:
        return None
    action = user = ip = port = obj = ""
    sev = "informational"
    if (m := _SSH_FAIL.search(msg)):
        action, user, ip, port, sev = "logon-fail", m["user"], m["ip"], m["port"], "low"
    elif (m := _SSH_OK.search(msg)):
        action, user, ip, port = "logon", m["user"], m["ip"], m["port"]
    elif (m := _SSH_INVALID.search(msg)):
        action, user, ip, sev = "logon-fail", m["user"], m["ip"], "low"
    elif app == "sudo" and (m := _SUDO.search(msg)):
        action, user, obj = ("sudo-fail" if m["fail"] else "sudo"), m["user"], m["cmd"][:255]
        sev = "medium" if m["fail"] else "low"
        msg = f"sudo as {m['as']}: {m['cmd']}"[:1000] if not m["fail"] else f"sudo denied ({m['fail']}): {m['cmd']}"[:1000]
    elif (m := _PAM_FAIL.search(msg)):
        action, user, ip, sev = "logon-fail", m["user"] or "", m["ip"] or "", "low"
    elif app in ("su", "sudo", "systemd-logind", "login") and (m := _SU.search(msg)):
        action, user, obj = "privileged-logon" if m["as"] == "root" else "logon", m["user"] or m["as"], m["as"]
        sev = "low"
    elif (m := _USERADD.search(msg)):
        action, user, sev = "user-created", m["user"], "low"
    elif (m := _USERDEL.search(msg)):
        action, user, sev = "user-deleted", m["user"], "medium"
    elif (m := _GROUPADD.search(msg)):
        action, user, obj, sev = "group-add", m["user"], m["group"], "medium"
    else:
        return None
    if ip and not re.fullmatch(r"[0-9a-fA-F:.]+", ip):
        ip = ""
    x = {"type": "linux", "subtype": h["app"][:64], "logid": f"linux-{action}", "srcip": ip, "srcport": port, "user": user[:128], "hostname": h["host"][:255],
         "app": obj, "action": action, "msg": msg[:1000]}
    ev = base(src, h["ts"], x, line.strip())
    ev.update({"category": "system", "event_type": "linux", "event_subtype": h["app"][:64], "severity": sev, "action": action, "orig_action": action,
               "parser_version": _ver(ev, "linux")})
    return ev


# ------------------------------------------------------------------ Juniper Junos (structured message tags) and Aruba
_JUNOS = re.compile(r"(?:^|[\s:])(?P<tag>(?:UI|RPD|SNMP|SNMPD|LOGIN|SSHD|CHASSISD|KERN|DCD|PFE|RT|JSRPD|AUTHD|LICENSE)_[A-Z0-9_]{3,}): (?P<text>.*)$")
_JUNOS_KIND = (("UI_COMMIT", "config_change", "config", "low"), ("UI_CFG_AUDIT", "config_change", "config", "low"), ("UI_LOGIN_EVENT", "login", "logon", "informational"),
               ("UI_AUTH_EVENT", "login", "logon", "informational"), ("LOGIN_FAILED", "login", "logon-fail", "low"), ("SSHD_LOGIN_FAILED", "login", "logon-fail", "low"),
               ("UI_LOGOUT_EVENT", "login", "logoff", "informational"), ("RPD_BGP_NEIGHBOR_STATE_CHANGED", "bgp", "state-change", "medium"),
               ("RPD_OSPF_NBRDOWN", "ospf", "down", "medium"), ("RPD_OSPF_NBRUP", "ospf", "up", "informational"), ("SNMP_TRAP_LINK_DOWN", "link", "down", "low"),
               ("SNMP_TRAP_LINK_UP", "link", "up", "informational"), ("RT_FLOW_SESSION_DENY", "traffic", "deny", "informational"))
_ARUBA = re.compile(r"<(?P<code>\d{6})>\s*(?:<\d+>\s*)?<(?P<sev>[A-Z]{3,5})>\s*(?:<[^>]*>\s*)?(?:\|(?P<proc>[\w-]+)\|\s*)?(?P<text>.*)$")
_ARUBA_SEV = {"EMERG": "critical", "ALERT": "critical", "CRIT": "critical", "ERRS": "high", "ERR": "high", "WARN": "medium", "NOTI": "low", "INFO": "informational",
              "DBUG": "informational"}


def _find(rx: str, text: str) -> str:
    m = re.search(rx, text, re.I)
    return m.group(1) if m else ""


def juniper(src: dict, line: str, base) -> dict | None:
    m = _JUNOS.search(line)
    if not m:
        return None
    tag, text = m["tag"], m["text"]
    kind, action, sev = next(((k, a, s) for t, k, a, s in _JUNOS_KIND if tag == t), ("other", "", "informational"))
    h = syslog_header(line)
    x = {"type": "netdev", "subtype": kind, "logid": tag[:64], "user": _find(r"[Uu]ser '?([\w.@\\-]+)'?", text)[:128],
         "srcip": _find(r"(?:from|host|peer|client)[ :]+'?((?:\d{1,3}\.){3}\d{1,3})", text), "hostname": h["host"][:255], "app": "juniper",
         "srcintf": _find(r"ifName ([\w/.:-]+)", text)[:64], "action": action, "msg": f"{tag}: {text}"[:1000]}
    ev = base(src, h["ts"], x, line.strip())
    ev.update({"category": "system", "event_type": "netdev", "event_subtype": kind, "severity": sev, "orig_severity": tag, "action": action, "orig_action": action,
               "parser_version": _ver(ev, "juniper")})
    return ev


def aruba(src: dict, line: str, base) -> dict | None:
    m = _ARUBA.search(line)
    if not m:
        return None
    text = m["text"]
    t = text.lower()
    kind, action = "other", ""
    if "authentication successful" in t or "auth success" in t:
        kind, action = "login", "logon"
    elif "authentication failed" in t or "auth fail" in t or "deauth" in t and "reason" in t and "fail" in t:
        kind, action = "login", "logon-fail"
    elif "rogue" in t:
        kind = "rogue_ap"
    elif "config" in t and ("changed" in t or "written" in t or "saved" in t):
        kind, action = "config_change", "config"
    h = syslog_header(line)
    x = {"type": "netdev", "subtype": kind, "logid": f"aruba-{m['code']}", "user": _find(r"username=([^\s,]+)", text)[:128],
         "srcip": _find(r"\bIP=((?:\d{1,3}\.){3}\d{1,3})", text), "srcmac": _find(r"\bMAC=((?:[0-9a-f]{2}:){5}[0-9a-f]{2})", text).lower(),
         "hostname": h["host"][:255], "app": "aruba", "action": action, "msg": text[:1000]}
    ev = base(src, h["ts"], x, line.strip())
    ev.update({"category": "system", "event_type": "netdev", "event_subtype": kind, "severity": _ARUBA_SEV.get(m["sev"], "informational"),
               "orig_severity": m["sev"], "action": action, "orig_action": action, "parser_version": _ver(ev, "aruba")})
    return ev
