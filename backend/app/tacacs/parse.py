"""tac_plus-ng log formats (rendered into the server configuration) and the parser for the resulting log lines.

The SIEM defines the formats, so parsing does not depend on the defaults. Each line written to a file destination is
"<RFC5424 timestamp> <tab-separated fields>". Event classes come from tac_plus-ng message ids, which separate a wrong
password (AUTHC-FAIL-DENY) from a backend outage (AUTHC-FAIL-BACKEND) and an ACL / ruleset denial (AUTHC-FAIL-ACL).

Secrets in command arguments are redacted before anything is stored, indexed, displayed, exported or alerted on.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone

FIELDS = {
    "authc": ["msgid", "session.id", "device.address", "device.name", "user", "device.port", "client", "result", "action", "priv-lvl",
              "profile", "rule", "server.address", "identity-source", "hint"],
    "authz": ["msgid", "session.id", "device.address", "device.name", "user", "device.port", "client", "result", "service", "priv-lvl",
              "profile", "rule", "server.address", "cmd", "args"],
    "acct": ["msgid", "session.id", "device.address", "device.name", "user", "device.port", "client", "accttype", "service", "priv-lvl",
             "profile", "rule", "server.address", "cmd", "args"],
    "conn": ["msgid", "accttype", "conn.protocol", "peer.address", "peer.port", "server.address", "server.port"],
}
LOG_FILES = {"authc": "authc.log", "authz": "authz.log", "acct": "acct.log", "conn": "conn.log"}
FORMAT_KEY = {"authc": "authentication", "authz": "authorization", "acct": "accounting", "conn": "connection"}


def format_string(kind: str) -> str:
    parts = []
    for f in FIELDS[kind]:
        parts.append("${args,|}" if f == "args" else "${" + f + "}")
    return "${FS}".join(parts)


# msgids as emitted by tac_plus-ng at the pinned commit (authen.c hint table, packet.c, acct.c, main.c)
EVENT = {
    "AUTHC-PASS": ("auth_success", "success"),
    "AUTHC-FAIL-BACKEND": ("auth_backend_error", "backend_unavailable"),
    "AUTHC-FAIL-ACL": ("auth_policy_deny", "policy_deny"),
    "AUTHC-FAIL-DENY": ("auth_failure", "failure"),
    "AUTHC-FAIL-DENY-RETRY": ("auth_failure", "failure"),
    "AUTHC-FAIL-NOPASS": ("auth_failure", "failure"),
    "AUTHC-FAIL-WEAKPASSWORD": ("auth_failure", "failure"),
    "AUTHC-FAIL-PASSWORD-NOT-TEXT": ("auth_failure", "failure"),
    "AUTHC-FAIL-EXPIRED": ("auth_failure", "failure"),
    "AUTHC-FAIL-NOUSER": ("auth_failure", "failure"),
    "AUTHC-FAIL-USERPROFILE": ("auth_policy_deny", "policy_deny"),
    "AUTHC-FAIL-BADSECRET": ("protocol_error", "protocol_error"),
    "AUTHC-ERROR": ("protocol_error", "protocol_error"),
    "AUTHC-PASS-PERMIT": ("auth_success", "success"),
    "AUTHC-FAIL": ("auth_failure", "failure"),
    "AUTHC-FAIL-ABORT": ("auth_aborted", "aborted"),
    "AUTHC-FAIL-BUG": ("protocol_error", "protocol_error"),
    "AUTHC-FAIL-BAD-CHALLENGE-LENGTH": ("protocol_error", "protocol_error"),
    "AUTHZ-PASS": ("authz_permit", "permit"),
    "AUTHZ-PASS-ADD": ("authz_permit", "permit"),
    "AUTHZ-PASS-REPL": ("authz_permit", "permit"),
    "AUTHZ-FAIL": ("authz_deny", "deny"),
    "ACCT-START": ("acct_start", "recorded"),
    "ACCT-STOP": ("acct_stop", "recorded"),
    "ACCT-UPDATE": ("acct_update", "recorded"),
    "ACCT-UNKNOWN": ("acct_unknown", "non_compliant"),
    "ACCT-ON": ("acct_system", "recorded"),
    "ACCT-OFF": ("acct_system", "recorded"),
    "CONN-START": ("conn_start", "connected"),
    "CONN-STOP": ("conn_stop", "closed"),
    "CONN-REJECT": ("conn_reject", "rejected"),
}

DEFAULT_REDACTIONS = [
    # keyword [type digit] value  →  keyword [type digit] ***
    r"(?i)\b(password|passwd|secret|key|community|psksecret|passphrase|pre-shared-key|auth-password|priv-password|"
    r"super-user-password|port-config-password|read-only-password|authentication-key|md5-key)\b(\s+(?:\d\s+)?)((?:ENC\s+)?(?:\"[^\"]*\"|\S+))",
    r"(?i)\b(set\s+(?:password|psksecret|passwd|secret|key|apikey|private-key))\s+(\"[^\"]*\"|\S+)",
    r"(?i)\b(ENC)\s+[A-Za-z0-9+/=]{8,}",
]


def compile_redactions(extra: list[str] | None = None) -> list[re.Pattern]:
    out = []
    for p in DEFAULT_REDACTIONS + list(extra or []):
        try:
            out.append(re.compile(p))
        except re.error:
            continue
    return out


_DEFAULT_RX = compile_redactions()


def redact(text: str, rules: list[re.Pattern] | None = None) -> str:
    s = text or ""
    for rx in rules or _DEFAULT_RX:
        if rx.groups >= 3:
            s = rx.sub(lambda m: m.group(1) + m.group(2) + "***", s)
        elif rx.groups == 2:
            s = rx.sub(lambda m: m.group(1) + " ***", s)
        else:
            s = rx.sub(lambda m: (m.group(1) if rx.groups else "") + " ***", s)
    return s


AV = re.compile(r"(?:^|\|)(task_id|elapsed_time|start_time|stop_time|priv-lvl|service|protocol|reason|err_msg)[=*]([^|]*)")


def _ts(s: str) -> datetime | None:
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        try:
            d = datetime.strptime(s, "%Y-%m-%d %H:%M:%S %z")
        except ValueError:
            return None
    return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def parse_line(kind: str, line: str, server_id: int, rules: list[re.Pattern] | None = None) -> dict:
    """One log line → normalised event dict (parse_ok = 0 with the reason when the line does not fit the format)."""
    raw = line.rstrip("\n")
    safe = redact(raw, rules)
    fp = hashlib.sha1(f"{server_id}|{kind}|{raw}".encode("utf-8", "replace")).hexdigest()
    ev = {"server_id": server_id, "log": kind, "raw": safe[:4000], "fingerprint": fp, "parse_ok": 0, "parse_error": ""}
    ts, _, rest = raw.partition(" ")
    t = _ts(ts)
    fields = rest.split("\t")
    names = FIELDS[kind]
    if t is None or len(fields) < len(names) - 1:
        ev.update(ts=datetime.now(timezone.utc), parse_error="line does not match the configured format")
        return ev
    vals = dict(zip(names, fields + [""] * (len(names) - len(fields))))
    msgid = vals.get("msgid", "")
    etype, result = EVENT.get(msgid, ("unknown", vals.get("result") or ""))
    args = vals.get("args", "")
    av = {k: v for k, v in AV.findall(args)}
    priv = vals.get("priv-lvl") or av.get("priv-lvl") or ""
    cmd = redact(vals.get("cmd", ""), rules)
    ev.update(ts=t, parse_ok=1, msgid=msgid, event_type=etype, result=result if kind != "authz" else (vals.get("result") or result),
              session_id=vals.get("session.id", ""), device_address=vals.get("device.address", "") or vals.get("peer.address", ""),
              device_name=vals.get("device.name", ""), username=vals.get("user", ""), port=vals.get("device.port", ""),
              remote_addr=vals.get("client", ""), service=vals.get("service", "") or av.get("service", ""),
              priv_lvl=int(priv) if priv.isdigit() and int(priv) <= 15 else None, profile=vals.get("profile", ""), rule=vals.get("rule", ""),
              server_address=vals.get("server.address", ""), cmd=cmd[:2000], task_id=av.get("task_id", ""),
              elapsed_s=int(av["elapsed_time"]) if av.get("elapsed_time", "").isdigit() else None,
              action=vals.get("action", "") or vals.get("accttype", ""), hint=redact(vals.get("hint", ""), rules)[:500],
              identity_source=vals.get("identity-source", ""), accttype=vals.get("accttype", ""))
    if kind == "authz" and etype == "authz_permit" and vals.get("result") == "deny":
        ev.update(event_type="authz_deny", result="deny")
    return ev
