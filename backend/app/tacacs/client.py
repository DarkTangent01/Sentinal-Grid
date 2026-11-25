"""AAA testing center: real tests executed by the backend (no canned results).

* TCP/49 reachability (outbound guard applied)
* test-user authentication and an accounting round trip through the tacacs_plus client library, sent from the SIEM as
  the dedicated `sentinel_grid_tester` device (its own key; deny-all profile, so a test can never open a shell)
* correlation: after an authentication test the server's own authentication log line is looked up, so a failure is
  reported as wrong password, backend unavailable or policy denial from the server's message id, not guessed
* LDAP / AD bind tests with the stored bind credential (TLS verified; StartTLS or LDAPS)

Passwords typed for a test are used once and never stored or logged; results keep only sanitised categories.
"""
from __future__ import annotations

import asyncio
import socket
import ssl
import struct
import time
from datetime import datetime, timedelta, timezone

from ..netguard import DestinationError, acheck_host

CATEGORY_HELP = {
    "timeout": "No answer: check routing / firewall rules for TCP/49 and that the TACACS+ service is running.",
    "dns": "The server name does not resolve from the SIEM: use the compose service name 'tacacs' for the managed server, or an IP address.",
    "refused": "Nothing listens on the port: check the tacacs service and its published port.",
    "auth_reject": "The server rejected the credentials.",
    "policy_deny": "Credentials may be valid, but the ruleset denied this user on this device (no role mapping, disabled, or policy).",
    "backend_unavailable": "The identity backend (LDAP / AD / PAM) did not answer: check the identity source test.",
    "protocol_error": "The reply could not be decoded: usually a shared-secret mismatch between the client and the server.",
    "server_error": "The server returned an error status.",
    "reset": "The server closed the connection without answering: the SIEM's source address is not a device the active configuration "
             "knows (check the tester address under Settings: container addresses change when containers are recreated; a subnet "
             "avoids that), or no version has been deployed yet (the bootstrap configuration rejects every connection).",
    "not_configured": "The tester device is not configured: set the tester address in TACACS+ → Settings and deploy a version.",
    "blocked": "The destination is not allowed by the outbound guard.",
    "ldap_bind": "The directory rejected the bind DN or password.",
    "ldap_unreachable": "The directory server could not be reached.",
    "ldap_tls": "TLS handshake or certificate verification failed: install the directory's CA; verification is never disabled.",
    "not_ingested": "The record was accepted but did not appear in ingestion: check the shared log volume and the worker.",
}


def _step(name: str, ok: bool, started: float, detail: str = "", category: str = "") -> dict:
    return {"name": name, "ok": ok, "started_at": datetime.fromtimestamp(started, timezone.utc).isoformat(),
            "finished_at": datetime.now(timezone.utc).isoformat(), "detail": detail[:500], "category": category,
            "help": CATEGORY_HELP.get(category, "") if not ok else ""}


async def tcp(host: str, port: int, timeout: float) -> dict:
    t0 = time.time()
    try:
        await acheck_host(host, port)
    except DestinationError as e:
        return _step(f"TCP {host}:{port}", False, t0, str(e), "blocked")
    try:
        _r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        w.close()
        return _step(f"TCP {host}:{port}", True, t0, f"connected in {(time.time() - t0) * 1000:.0f} ms")
    except asyncio.TimeoutError:
        return _step(f"TCP {host}:{port}", False, t0, f"no answer within {timeout:g}s", "timeout")
    except ConnectionRefusedError:
        return _step(f"TCP {host}:{port}", False, t0, "connection refused", "refused")
    except socket.gaierror as e:
        return _step(f"TCP {host}:{port}", False, t0, f"name does not resolve ({e.strerror or 'DNS error'})", "dns")
    except OSError as e:
        return _step(f"TCP {host}:{port}", False, t0, e.strerror or type(e).__name__, "timeout")


# RFC 8907 reply status codes; anything else means the body was decrypted with the wrong key (pseudo-pad mismatch)
AUTHEN_STATUSES = {1, 2, 3, 4, 5, 6, 7, 0x21}
ACCT_STATUSES = {1, 2, 0x21}


def _failure(name: str, t0: float, e: BaseException, timeout: float) -> dict:
    """Classify a transport / protocol exception from the tacacs_plus client (messages never include credentials)."""
    if isinstance(e, (asyncio.TimeoutError, socket.timeout, TimeoutError)):
        return _step(name, False, t0, f"no reply within {timeout:g}s", "timeout")
    if isinstance(e, ConnectionRefusedError):
        return _step(name, False, t0, "connection refused", "refused")
    if isinstance(e, socket.gaierror):
        return _step(name, False, t0, f"name does not resolve ({e.strerror or 'DNS error'})", "dns")
    if isinstance(e, (ConnectionResetError, BrokenPipeError, EOFError, struct.error)):  # struct.error: short read of the reply header
        return _step(name, False, t0, "connection closed by the server without a reply", "reset")
    return _step(name, False, t0, f"reply could not be decoded ({type(e).__name__})", "protocol_error")


def _client(host: str, port: int, key: str, timeout: float):
    from tacacs_plus.client import TACACSClient
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    return TACACSClient(host, port, key, timeout=timeout, family=fam)


async def authenticate(host: str, port: int, key: str, username: str, password: str, timeout: float) -> dict:
    from tacacs_plus.flags import TAC_PLUS_AUTHEN_STATUS_FAIL, TAC_PLUS_AUTHEN_STATUS_PASS, TAC_PLUS_AUTHEN_TYPE_PAP
    t0 = time.time()
    try:
        await acheck_host(host, port)
    except DestinationError as e:
        return _step("authentication", False, t0, str(e), "blocked")

    def run():
        return _client(host, port, key, timeout).authenticate(username, password, authen_type=TAC_PLUS_AUTHEN_TYPE_PAP,
                                                              rem_addr="sentinel-grid", port="aaa-test")
    try:
        r = await asyncio.wait_for(asyncio.to_thread(run), timeout + 2)
    except Exception as e:  # never includes the password
        return _failure("authentication", t0, e, timeout)
    if r.status not in AUTHEN_STATUSES or r.flags not in (0, 1):  # only NOECHO is defined: anything else is a wrong-key decode
        return _step("authentication", False, t0, f"undecodable reply (status byte {r.status})", "protocol_error")
    if r.status == TAC_PLUS_AUTHEN_STATUS_PASS:
        return _step("authentication", True, t0, "PASS")
    if r.status == TAC_PLUS_AUTHEN_STATUS_FAIL:
        return _step("authentication", False, t0, "FAIL", "auth_reject")
    return _step("authentication", False, t0, f"status {r.status}", "server_error")


async def account(host: str, port: int, key: str, username: str, task_id: str, timeout: float) -> dict:
    from tacacs_plus.flags import TAC_PLUS_ACCT_FLAG_START, TAC_PLUS_ACCT_FLAG_STOP
    t0 = time.time()
    try:
        await acheck_host(host, port)
    except DestinationError as e:
        return _step("accounting record", False, t0, str(e), "blocked")

    def run():
        args = [b"service=shell", f"task_id={task_id}".encode(), b"cmd=sentinel-grid-accounting-check"]
        r = _client(host, port, key, timeout).account(username, TAC_PLUS_ACCT_FLAG_START, arguments=args, rem_addr="sentinel-grid", port="aaa-test")
        if getattr(r, "valid", False):  # close the record so the check never shows up as a session left open
            r = _client(host, port, key, timeout).account(username, TAC_PLUS_ACCT_FLAG_STOP, arguments=args + [b"elapsed_time=0"],
                                                          rem_addr="sentinel-grid", port="aaa-test")
        return r
    try:
        r = await asyncio.wait_for(asyncio.to_thread(run), timeout + 2)
    except Exception as e:
        return _failure("accounting record", t0, e, timeout)
    if getattr(r, "valid", False):
        return _step("accounting record", True, t0, "accepted")
    if r.status not in ACCT_STATUSES:
        return _step("accounting record", False, t0, f"undecodable reply (status byte {r.status})", "protocol_error")
    return _step("accounting record", False, t0, f"status {r.status}", "server_error")


async def correlate_auth(ch, server_id: int, username: str, since: datetime, wait: float = 12.0) -> dict | None:
    """The server's own log line for a test: msgid tells wrong password / backend outage / ACL denial apart."""
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        rows = await ch.aquery("SELECT msgid, event_type, result, hint, rule FROM tacacs_events WHERE server_id = {s:UInt32} AND log = 'authc' "
                               "AND username = {u:String} AND ts >= {t:DateTime64(3)} ORDER BY ts DESC LIMIT 1",
                               {"s": server_id, "u": username, "t": since - timedelta(seconds=2)})
        if rows:
            return rows[0]
        await asyncio.sleep(1.5)
    return None


async def wait_ingested(ch, server_id: int, task_id: str, wait: float = 15.0) -> bool:
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        rows = await ch.aquery("SELECT count() AS n FROM tacacs_events WHERE server_id = {s:UInt32} AND task_id = {t:String}",
                               {"s": server_id, "t": task_id})
        if rows and int(rows[0]["n"]):
            return True
        await asyncio.sleep(1.5)
    return False


async def ldap_bind(settings: dict, bind_password: str, timeout: float) -> list[dict]:
    """Bind with the service account against each configured host; TLS is always verified."""
    import ldap3
    from ldap3.core.exceptions import LDAPBindError, LDAPException, LDAPSocketOpenError, LDAPStartTLSError
    steps = []
    for url in settings.get("hosts") or []:
        t0 = time.time()
        use_ssl = url.lower().startswith("ldaps://")
        hostport = url.split("://", 1)[-1].rstrip("/")
        host, _, port = hostport.rpartition(":") if hostport.count(":") == 1 else (hostport, "", "")
        host = host or hostport
        port_i = int(port) if port.isdigit() else (636 if use_ssl else 389)
        try:
            await acheck_host(host, port_i)
        except DestinationError as e:
            steps.append(_step(f"bind {url}", False, t0, str(e), "blocked"))
            continue
        if not use_ssl and not settings.get("starttls"):
            steps.append(_step(f"bind {url}", False, t0, "refusing a clear-text bind: use ldaps:// or enable StartTLS", "ldap_tls"))
            continue

        def run():
            tls = ldap3.Tls(validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLS_CLIENT)
            srv = ldap3.Server(host, port=port_i, use_ssl=use_ssl, tls=tls, connect_timeout=timeout, get_info=ldap3.NONE)
            conn = ldap3.Connection(srv, user=settings.get("bind_dn") or None, password=bind_password or None, receive_timeout=timeout, auto_bind=False,
                                    raise_exceptions=True)
            conn.open()
            if not use_ssl:
                conn.start_tls()
            conn.bind()
            ok = conn.search(settings.get("base") or "", "(objectClass=*)", search_scope=ldap3.BASE, attributes=[])
            conn.unbind()
            return ok
        try:
            found = await asyncio.wait_for(asyncio.to_thread(run), timeout * 2 + 2)
            steps.append(_step(f"bind {url}", True, t0, "bound" + (" and read the base DN" if found else "; base DN not readable")))
        except asyncio.TimeoutError:
            steps.append(_step(f"bind {url}", False, t0, "timed out", "ldap_unreachable"))
        except LDAPBindError:
            steps.append(_step(f"bind {url}", False, t0, "invalid bind credentials", "ldap_bind"))
        except LDAPStartTLSError as e:
            steps.append(_step(f"bind {url}", False, t0, f"StartTLS failed: {type(e).__name__}", "ldap_tls"))
        except LDAPSocketOpenError as e:
            cat = "ldap_tls" if "ssl" in str(e).lower() or "certificate" in str(e).lower() else "ldap_unreachable"
            steps.append(_step(f"bind {url}", False, t0, "socket / TLS error opening the connection", cat))
        except LDAPException as e:
            steps.append(_step(f"bind {url}", False, t0, type(e).__name__, "ldap_unreachable"))
    return steps
