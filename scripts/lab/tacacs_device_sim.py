#!/usr/bin/env python3
"""Plays a Cisco IOS device against the real tac_plus-ng (runs inside the worker container of a LAB stack, which is the registered
client address). Reads its inputs as JSON on stdin (keys and passwords never on argv); prints statuses only."""
import json
import socket
import sys

from tacacs_plus.client import TACACSClient
from tacacs_plus.flags import (TAC_PLUS_ACCT_FLAG_START, TAC_PLUS_ACCT_FLAG_STOP, TAC_PLUS_AUTHEN_STATUS_FAIL, TAC_PLUS_AUTHEN_STATUS_PASS,
                               TAC_PLUS_AUTHEN_TYPE_ASCII, TAC_PLUS_AUTHEN_TYPE_PAP, TAC_PLUS_AUTHOR_STATUS_FAIL, TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
                               TAC_PLUS_AUTHOR_STATUS_PASS_REPL)

cfg = json.load(sys.stdin)
host, port = cfg["host"], cfg.get("port", 49)


def cli(key, timeout=5):
    return TACACSClient(host, port, key, timeout=timeout, family=socket.AF_INET)


AUTHN = {TAC_PLUS_AUTHEN_STATUS_PASS: "PASS", TAC_PLUS_AUTHEN_STATUS_FAIL: "FAIL"}
AUTHZ = {TAC_PLUS_AUTHOR_STATUS_PASS_ADD: "PASS_ADD", TAC_PLUS_AUTHOR_STATUS_PASS_REPL: "PASS_REPL", TAC_PLUS_AUTHOR_STATUS_FAIL: "FAIL"}
out = {}


def authn(label, user, pw, key=None, atype=TAC_PLUS_AUTHEN_TYPE_PAP):
    try:
        r = cli(key or cfg["key"]).authenticate(user, pw, authen_type=atype, rem_addr="192.0.2.50", port="tty2")
        out[label] = AUTHN.get(r.status, f"status {r.status}")
    except Exception as e:
        out[label] = f"error {type(e).__name__}"


def authz(label, user, args):
    try:
        r = cli(cfg["key"]).authorize(user, arguments=[a.encode() for a in args], rem_addr="192.0.2.50", port="tty2")
        avs = [a.decode(errors="replace") for a in (r.arguments or [])]
        out[label] = AUTHZ.get(r.status, f"status {r.status}") + (f" {';'.join(avs)}" if avs else "")
    except Exception as e:
        out[label] = f"error {type(e).__name__}"


def acct(label, user, flag, args):
    try:
        r = cli(cfg["key"]).account(user, flag, arguments=[a.encode() for a in args], rem_addr="192.0.2.50", port="tty2")
        out[label] = "SUCCESS" if r.valid else f"status {r.status}"
    except Exception as e:
        out[label] = f"error {type(e).__name__}"


u = cfg["users"]
authn("authn engineer good password (PAP)", "netops1", u["netops1"])
authn("authn engineer good password (ASCII login)", "netops1", u["netops1"], atype=TAC_PLUS_AUTHEN_TYPE_ASCII)
authn("authn engineer wrong password", "netops1", u["netops1"] + "x")
authn("authn unknown user", "ghost", "Whatever-Password-1")
authn("authn disabled user", "olduser", u["olduser"])
authn("authn read-only good password", "viewer1", u["viewer1"])
authn("authn wrong shared secret", "netops1", u["netops1"], key=cfg["wrong_key"])
authz("authz engineer exec", "netops1", ["service=shell", "cmd="])
authz("authz engineer 'show version'", "netops1", ["service=shell", "cmd=show", "cmd-arg=version", "cmd-arg=<cr>"])
authz("authz engineer 'configure terminal'", "netops1", ["service=shell", "cmd=configure", "cmd-arg=terminal", "cmd-arg=<cr>"])
authz("authz engineer 'reload'", "netops1", ["service=shell", "cmd=reload", "cmd-arg=<cr>"])
authz("authz read-only exec", "viewer1", ["service=shell", "cmd="])
authz("authz read-only 'show ip route'", "viewer1", ["service=shell", "cmd=show", "cmd-arg=ip", "cmd-arg=route", "cmd-arg=<cr>"])
authz("authz read-only 'configure terminal'", "viewer1", ["service=shell", "cmd=configure", "cmd-arg=terminal", "cmd-arg=<cr>"])
authz("authz unknown user exec", "ghost", ["service=shell", "cmd="])
t = cfg["task"]
acct("acct exec start", "netops1", TAC_PLUS_ACCT_FLAG_START, [f"task_id={t}", "service=shell", "priv-lvl=15"])
acct("acct command", "netops1", TAC_PLUS_ACCT_FLAG_STOP, [f"task_id={t + 1}", "service=shell", "priv-lvl=15", "cmd=show version <cr>"])
acct("acct command with secret", "netops1", TAC_PLUS_ACCT_FLAG_STOP,
     [f"task_id={t + 2}", "service=shell", "priv-lvl=15", "cmd=username bob secret 0 " + cfg["canary"] + " <cr>"])
acct("acct exec stop", "netops1", TAC_PLUS_ACCT_FLAG_STOP, [f"task_id={t}", "service=shell", "elapsed_time=42"])
print(json.dumps(out))
