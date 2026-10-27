"""Palo Alto Networks PAN-OS syslog (default CSV format) → the common field dictionary used for FortiGate logs.

PAN-OS sends one CSV record per message, after a BSD or RFC 5424 syslog header:
    <14>Oct 26 12:00:00 PA-HOST 1,2026/10/26 12:00:00,0123456789,TRAFFIC,end,2561,2026/10/26 12:00:00,10.0.0.5,...
Field positions are fixed per log type (PAN-OS 9.1-11.x syslog field descriptions). Only the leading fields that
are stable across those releases are used; the device name comes from the syslog header.

The output keys mirror FortiOS key=value names (srcip, dstip, sentbyte, policyname, ...) so `normalize()` and every
dashboard, search and detection work unchanged. Two deliberate mappings let the built-in detections cover PAN-OS:
CONFIG commits use the FortiOS configuration-change log id, and failed admin logins carry "login failed" in the
message. PAN-OS logs local time without an offset: the firewall's configured log time zone is applied after the
device is identified (EventSink.add_fields).
"""
from __future__ import annotations

import csv
import re

PARSER_VERSION = "panos-csv-1.0"
_TYPES = "TRAFFIC|THREAT|SYSTEM|CONFIG|GLOBALPROTECT|HIPMATCH|USERID|AUTH|DECRYPTION|TUNNEL|SCTP|IPTAG|CORRELATION|GTP"
# "<host> <future_use>,<receive time>,<serial>,<type>,"  — the record starts at the future-use field before the date
_START = re.compile(r"(?:^|\s)(?P<host>[^\s,]+)?\s*(?P<rec>\d+,\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2},[0-9A-Za-z]+,(?:" + _TYPES + r"),.*)$")
# necessary condition for _START, without its per-position backtracking: rejects FortiGate lines cheaply
_QUICK = re.compile(r"\d,\d{4}/\d\d/\d\d \d\d:\d\d:\d\d,")
_RFC5424_HOST = re.compile(r"^<\d+>1 \S+ (\S+) ")
PROTO = {"tcp": "6", "udp": "17", "icmp": "1", "icmp6": "58", "ipv6-icmp": "58", "gre": "47", "esp": "50", "sctp": "132"}
TRAFFIC_ACTION = {"allow": "accept", "deny": "deny", "drop": "deny", "drop-icmp": "deny", "reset-client": "deny",
                  "reset-server": "deny", "reset-both": "deny"}
THREAT_ACTION = {"alert": "monitor", "allow": "monitor", "continue": "monitor", "override": "monitor",
                 "drop": "block", "drop-all-packets": "block", "reset-client": "block", "reset-server": "block",
                 "reset-both": "block", "block-ip": "block", "deny": "block", "sinkhole": "block", "block": "block"}
URL_BLOCKED = {"block-url", "block-continue", "block-override", "override-lockout", "drop", "reset-both", "reset-client",
               "reset-server", "block"}
THREAT_SUBTYPE = {"virus": "virus", "wildfire-virus": "virus", "wildfire": "virus", "spyware": "ips", "vulnerability": "ips",
                  "flood": "anomaly", "scan": "anomaly", "packet": "anomaly", "file": "file-filter", "data": "dlp"}
LEVEL = {"informational": "information", "low": "notice", "medium": "warning", "high": "error", "critical": "critical"}
FORTIOS_CONFIG_CHANGE = "0100044547"


class NotPanos(ValueError):
    pass


def detect(line: str) -> tuple[str, list[str]] | None:
    """(device hostname from the syslog header, CSV fields) when the line is a PAN-OS CSV record, else None."""
    if "," not in line or not _QUICK.search(line):
        return None
    m = _START.search(line.rstrip("\r\n"))
    if not m:
        return None
    try:
        fields = next(csv.reader([m.group("rec")]))
    except (csv.Error, StopIteration):
        return None
    if len(fields) < 9:
        return None
    host = m.group("host") or ""
    if host in ("", "-") or host == fields[0]:
        h = _RFC5424_HOST.match(line)
        host = h.group(1) if h else ""
    return host, fields


def _g(f: list[str], i: int) -> str:
    return f[i].strip() if i < len(f) else ""


def _date_time(v: str) -> tuple[str, str]:
    d, _, t = v.partition(" ")
    return d.replace("/", "-"), t


def _common(host: str, f: list[str]) -> dict:
    date, time = _date_time(_g(f, 6) or _g(f, 1))
    return {"devid": _g(f, 2), "devname": host, "date": date, "time": time, "_pan": "1", "_panlog": _g(f, 3).lower()}


def _session(f: list[str], d: dict) -> None:
    """Fields 7-29, shared by TRAFFIC and THREAT."""
    d.update({"srcip": _g(f, 7), "dstip": _g(f, 8), "transip": _g(f, 9) if _g(f, 9) not in ("0.0.0.0", "::") else "",
              "tranip": _g(f, 10) if _g(f, 10) not in ("0.0.0.0", "::") else "", "policyname": _g(f, 11),
              "user": _g(f, 12) or _g(f, 13), "app": _g(f, 14), "vd": _g(f, 15), "srcintf": _g(f, 18), "dstintf": _g(f, 19),
              "sessionid": _g(f, 22), "srcport": _g(f, 24), "dstport": _g(f, 25), "transport": _g(f, 26) if _g(f, 26) != "0" else "",
              "tranport": _g(f, 27) if _g(f, 27) != "0" else "", "proto": PROTO.get(_g(f, 29).lower(), "")})


def parse(host: str, f: list[str]) -> dict:
    """CSV fields → FortiOS-style key/value dict (see module docstring)."""
    typ, sub = _g(f, 3).upper(), _g(f, 4).lower()
    d = _common(host, f)
    d["logid"] = f"pan-{typ.lower()}-{sub}"[:32]
    if typ == "TRAFFIC":
        _session(f, d)
        act = _g(f, 30).lower()
        start = sub == "start"  # start records carry partial counters; the end record has the session totals
        d.update({"type": "traffic", "subtype": "forward", "action": TRAFFIC_ACTION.get(act, act),
                  "sentbyte": "0" if start else _g(f, 32), "rcvdbyte": "0" if start else _g(f, 33),
                  "sentpkt": "0" if start else _g(f, 44), "rcvdpkt": "0" if start else _g(f, 45),
                  "duration": _g(f, 36), "catdesc": _g(f, 37), "srccountry": _g(f, 41), "dstcountry": _g(f, 42),
                  "service": _g(f, 14), "level": "notice",
                  "msg": f"session {sub}" + (f" ({_g(f, 46)})" if _g(f, 46) else "")})
        return d
    if typ == "THREAT":
        _session(f, d)
        act = _g(f, 30).lower()
        misc = _g(f, 31)
        sev = _g(f, 34).lower()
        if sub == "url":
            url = misc
            hostpart = url.split("/", 1)[0].split(":", 1)[0] if "://" not in url else url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
            d.update({"type": "utm", "subtype": "webfilter", "url": url, "hostname": hostpart, "catdesc": _g(f, 33),
                      "action": "blocked" if act in URL_BLOCKED else "passthrough",
                      "eventtype": "ftgd_blk" if act in URL_BLOCKED else "ftgd_allow", "level": "notice",
                      "msg": f"URL {act}: {_g(f, 33)}", "srccountry": _g(f, 38), "dstcountry": _g(f, 39)})
            return d
        name = _g(f, 32)
        d.update({"type": "utm", "subtype": THREAT_SUBTYPE.get(sub, "ips"), "action": THREAT_ACTION.get(act, act),
                  "severity": sev if sev in ("critical", "high", "medium", "low") else "info", "level": "warning",
                  "msg": f"{sub}: {name}" + (f" [{misc}]" if misc else ""), "srccountry": _g(f, 38), "dstcountry": _g(f, 39),
                  "catdesc": _g(f, 33)})
        d["virus" if THREAT_SUBTYPE.get(sub) == "virus" else "attack"] = name
        if misc and sub in ("file", "virus", "wildfire", "wildfire-virus"):
            d["filename"] = misc
        return d
    if typ == "SYSTEM":
        desc = _g(f, 14)
        eventid = _g(f, 8)
        sev = _g(f, 13).lower()
        d.update({"type": "event", "subtype": "vpn" if sub == "globalprotect" else "system", "logdesc": eventid,
                  "level": LEVEL.get(sev, "information"), "msg": desc, "action": eventid})
        if eventid in ("auth-fail", "auth-failure") or ("authentication" in desc.lower() and "fail" in desc.lower()):
            # wording the built-in "administrative login failures" detection matches; the original text follows
            d.update({"msg": f"Admin login failed: {desc}", "action": "login", "status": "failed"})
            m = re.search(r"user '([^']+)'", desc)
            if m:
                d["user"] = m.group(1)
            m = re.search(r"From: ([0-9a-fA-F.:]+)", desc)
            if m:
                d["srcip"] = m.group(1).rstrip(".")
        return d
    if typ == "CONFIG":
        cmd, admin, client, result, path = _g(f, 9), _g(f, 10), _g(f, 11), _g(f, 12), _g(f, 13)
        d.update({"type": "event", "subtype": "system", "logid": FORTIOS_CONFIG_CHANGE, "user": admin, "ui": client,
                  "action": cmd, "cfgpath": path, "vd": _g(f, 8), "srcip": _g(f, 7), "level": "information",
                  "msg": f"Configuration {cmd} by {admin or 'unknown'} ({result}): {path}"[:1000]})
        return d
    if typ == "GLOBALPROTECT":
        eventid, status = _g(f, 8), _g(f, 28).lower()
        ok = status in ("success", "")
        connected = eventid in ("gateway-connected", "portal-auth", "gateway-auth", "portal-prelogin", "gateway-register")
        action = ("tunnel-up" if eventid in ("gateway-connected", "gateway-register") else "login") if ok and connected else \
            ("tunnel-down" if eventid in ("gateway-logout", "gateway-disconnect") else f"{eventid}-fail" if not ok else eventid)
        d.update({"type": "event", "subtype": "vpn", "user": _g(f, 12), "remip": _g(f, 15), "srccountry": _g(f, 13),
                  "action": action, "level": "information" if ok else "warning", "tunneltype": _g(f, 11),
                  "msg": f"GlobalProtect {eventid} {status or ''}".strip() + (f": {_g(f, 25)}" if _g(f, 25) else ""),
                  "tunnelip": _g(f, 17)})
        return d
    # other log types (HIPMATCH, USERID, AUTH, DECRYPTION, ...) are kept as system events with their text
    d.update({"type": "event", "subtype": typ.lower(), "level": "information", "msg": ",".join(f[3:12])[:1000]})
    return d
