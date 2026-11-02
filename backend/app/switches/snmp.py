"""Read-only SNMP client (GET / GETNEXT / GETBULK only) on top of pysnmp's asyncio API.

* Never sends SET. The module has no code path that writes to a switch.
* Values come back as plain Python: int (Integer, Counter32/64, Gauge32, TimeTicks), bytes (OCTET STRING), str (OID,
  IpAddress). A missing object is MISSING, never 0, so "unsupported" and "zero" stay distinguishable.
* Errors are classified (timeout / auth / protocol) so the poller can tell an unreachable switch from wrong
  credentials. Messages never contain the community or USM keys.
* One pysnmp engine per credential set: a shared engine re-registers the USM user whenever two switches use the same
  user name with different keys, which races under concurrency.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from collections import OrderedDict
from dataclasses import asdict, dataclass

MISSING = type("Missing", (), {"__repr__": lambda s: "MISSING", "__bool__": lambda s: False})()

AUTH_PROTOCOLS = ("none", "md5", "sha", "sha224", "sha256", "sha384", "sha512")
PRIV_PROTOCOLS = ("none", "des", "3des", "aes128", "aes192", "aes256")


class SnmpError(Exception):
    """kind: timeout | auth | protocol | config"""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind
        self.message = message


@dataclass(frozen=True)
class Credentials:
    version: str = "v3"            # v2c | v3
    community: str = ""
    username: str = ""
    auth_protocol: str = "sha"
    auth_key: str = ""
    priv_protocol: str = "aes128"
    priv_key: str = ""

    @property
    def security_level(self) -> str:
        if self.version != "v3":
            return "community"
        if self.auth_protocol == "none":
            return "noAuthNoPriv"
        return "authNoPriv" if self.priv_protocol == "none" else "authPriv"

    def fingerprint(self) -> str:
        return hashlib.sha256(json.dumps(asdict(self), sort_keys=True).encode()).hexdigest()

    def validate(self) -> None:
        if self.version not in ("v2c", "v3"):
            raise SnmpError("config", "SNMP version must be v2c or v3")
        if self.version == "v2c":
            if not self.community or len(self.community) > 64:
                raise SnmpError("config", "a community string (1-64 characters) is required for SNMPv2c")
            return
        if not self.username or len(self.username) > 32:
            raise SnmpError("config", "an SNMPv3 user name (1-32 characters) is required")
        if self.auth_protocol not in AUTH_PROTOCOLS or self.priv_protocol not in PRIV_PROTOCOLS:
            raise SnmpError("config", "unsupported SNMPv3 authentication or privacy protocol")
        if self.auth_protocol == "none" and self.priv_protocol != "none":
            raise SnmpError("config", "SNMPv3 privacy requires authentication")
        for proto, key, what in ((self.auth_protocol, self.auth_key, "authentication"), (self.priv_protocol, self.priv_key, "privacy")):
            if proto != "none" and not (8 <= len(key) <= 128):
                raise SnmpError("config", f"the SNMPv3 {what} passphrase must be 8-128 characters")


def _convert(v):
    from pyasn1.type import univ
    from pysnmp.proto import rfc1902, rfc1905
    if isinstance(v, (rfc1905.NoSuchObject, rfc1905.NoSuchInstance, rfc1905.EndOfMibView)) or v is None:
        return MISSING
    if isinstance(v, rfc1902.IpAddress):
        return ".".join(str(b) for b in v.asOctets())
    if isinstance(v, univ.ObjectIdentifier):
        return ".".join(str(x) for x in v)
    if isinstance(v, (univ.OctetString,)):
        return bytes(v.asOctets())
    if isinstance(v, univ.Integer):
        return int(v)
    if isinstance(v, univ.Null):
        return MISSING
    return v


def _auth_error(ind: str) -> bool:
    s = ind.lower()
    return any(w in s for w in ("wrongdigest", "unknownusername", "decryption", "unsupportedseclevel", "authentication",
                                "unknown user", "wrong digest", "digest", "usm user", "decrypt", "notintimewindow", "unknownengineid", "unknown engine"))


class _EnginePool:
    def __init__(self, size: int = 256):
        self.size = size
        self.engines: OrderedDict[str, object] = OrderedDict()

    def get(self, key: str):
        from pysnmp.hlapi.v3arch.asyncio import SnmpEngine
        e = self.engines.pop(key, None)
        if e is None:
            e = SnmpEngine()
            while len(self.engines) >= self.size:
                _, old = self.engines.popitem(last=False)
                try:
                    old.close_dispatcher()
                except Exception:
                    pass
        self.engines[key] = e
        return e


_pool = _EnginePool()


class PysnmpClient:
    """Bound to one switch. Requests to that switch are serialised (one in flight) so a poll never floods a device."""

    def __init__(self, host: str, creds: Credentials, *, port: int = 161, timeout: float = 3.0, retries: int = 1,
                 max_repetitions: int = 25, max_rows: int = 20000):
        creds.validate()
        self.host, self.port, self.creds = host, port, creds
        self.timeout, self.retries = timeout, retries
        self.max_repetitions, self.max_rows = max_repetitions, max_rows
        self.requests = 0
        self._lock = asyncio.Lock()
        self._target = None

    def _auth(self, context: str | None):
        from pysnmp.hlapi.v3arch import asyncio as h
        c = self.creds
        if c.version == "v2c":
            comm = c.community + (f"@{context}" if context else "")  # Cisco community string indexing (per-VLAN BRIDGE-MIB)
            return h.CommunityData(comm, mpModel=1), h.ContextData()
        auth = {"none": h.usmNoAuthProtocol, "md5": h.usmHMACMD5AuthProtocol, "sha": h.usmHMACSHAAuthProtocol,
                "sha224": h.usmHMAC128SHA224AuthProtocol, "sha256": h.usmHMAC192SHA256AuthProtocol,
                "sha384": h.usmHMAC256SHA384AuthProtocol, "sha512": h.usmHMAC384SHA512AuthProtocol}[c.auth_protocol]
        priv = {"none": h.usmNoPrivProtocol, "des": h.usmDESPrivProtocol, "3des": h.usm3DESEDEPrivProtocol,
                "aes128": h.usmAesCfb128Protocol, "aes192": h.usmAesCfb192Protocol, "aes256": h.usmAesCfb256Protocol}[c.priv_protocol]
        user = h.UsmUserData(c.username, authKey=c.auth_key or None, privKey=c.priv_key or None, authProtocol=auth, privProtocol=priv)
        return user, h.ContextData(contextName=(context or "").encode())

    async def _target_obj(self):
        from pysnmp.hlapi.v3arch import asyncio as h
        if self._target is None:
            cls = h.Udp6TransportTarget if ":" in self.host else h.UdpTransportTarget
            self._target = await cls.create((self.host, self.port), timeout=self.timeout, retries=self.retries)
        return self._target

    def _engine(self):
        return _pool.get(self.creds.fingerprint())

    def _raise(self, ind, status, index, varbinds=None):
        if ind:
            s = str(ind)
            if "timeout" in s.lower() or "no snmp response" in s.lower():
                raise SnmpError("timeout", f"no SNMP response from {self.host}:{self.port} within {self.timeout:g}s × {self.retries + 1} attempts")
            if _auth_error(s):
                raise SnmpError("auth", f"SNMPv3 authentication/privacy rejected by {self.host} ({s})")
            raise SnmpError("protocol", f"SNMP error from {self.host}: {s}")
        if status and int(status) not in (2,):  # noSuchName (v1-style) is treated as missing by callers
            raise SnmpError("protocol", f"SNMP error-status {status.prettyPrint() if hasattr(status, 'prettyPrint') else status} at index {index}")

    async def get(self, oids: list[str], context: str | None = None) -> dict[str, object]:
        from pysnmp.hlapi.v3arch import asyncio as h
        out: dict[str, object] = {}
        async with self._lock:
            target = await self._target_obj()
            auth, ctx = self._auth(context)
            for i in range(0, len(oids), 20):
                chunk = oids[i:i + 20]
                self.requests += 1
                ind, status, index, vbs = await h.get_cmd(self._engine(), auth, target, ctx,
                                                          *[h.ObjectType(h.ObjectIdentity(o)) for o in chunk], lookupMib=False)
                if status and int(status) == 2:  # v1-style noSuchName: retry one by one
                    for o in chunk:
                        out.update(await self._get_one(o, auth, target, ctx))
                    continue
                self._raise(ind, status, index)
                for name, val in vbs:
                    out[".".join(str(x) for x in name)] = _convert(val)
        return out

    async def _get_one(self, oid, auth, target, ctx):
        from pysnmp.hlapi.v3arch import asyncio as h
        self.requests += 1
        ind, status, index, vbs = await h.get_cmd(self._engine(), auth, target, ctx, h.ObjectType(h.ObjectIdentity(oid)), lookupMib=False)
        if status and int(status) == 2:
            return {oid: MISSING}
        self._raise(ind, status, index)
        return {".".join(str(x) for x in n): _convert(v) for n, v in vbs}

    async def walk(self, base: str, context: str | None = None, max_rows: int | None = None) -> list[tuple[str, object]]:
        """GETBULK walk of one subtree. Stops at the end of the subtree, at max_rows, or on a non-increasing OID."""
        from pysnmp.hlapi.v3arch import asyncio as h
        limit = max_rows or self.max_rows
        prefix = base.rstrip(".") + "."
        rows: list[tuple[str, object]] = []
        async with self._lock:
            target = await self._target_obj()
            auth, ctx = self._auth(context)
            cur = base
            last = tuple(int(x) for x in base.split("."))
            while len(rows) < limit:
                self.requests += 1
                ind, status, index, vbs = await h.bulk_cmd(self._engine(), auth, target, ctx, 0, self.max_repetitions,
                                                           h.ObjectType(h.ObjectIdentity(cur)), lookupMib=False)
                self._raise(ind, status, index)
                if not vbs:
                    break
                done = False
                for name, val in vbs:
                    oid = ".".join(str(x) for x in name)
                    v = _convert(val)
                    if not oid.startswith(prefix) or v is MISSING:
                        done = True
                        break
                    t = tuple(name)
                    if t <= last:  # agent returned a non-increasing OID: stop instead of looping
                        done = True
                        break
                    last = t
                    rows.append((oid, v))
                    if len(rows) >= limit:
                        break
                if done:
                    break
                cur = rows[-1][0] if rows else base
        return rows

    async def walk_multi(self, bases: list[str], context: str | None = None, max_rows: int | None = None) -> dict[str, list[tuple[str, object]]]:
        """Walk several table columns side by side: each GETBULK carries one varbind per unfinished column, so a
        table of N rows × C columns costs about N / repetitions requests instead of C × N / repetitions."""
        from pysnmp.hlapi.v3arch import asyncio as h
        limit = max_rows or self.max_rows
        out: dict[str, list] = {b: [] for b in bases}
        cur = {b: b for b in bases}
        last = {b: tuple(int(x) for x in b.split(".")) for b in bases}
        active = list(bases)
        async with self._lock:
            target = await self._target_obj()
            auth, ctx = self._auth(context)
            while active:
                reps = max(1, min(self.max_repetitions, 60 // len(active)))
                self.requests += 1
                ind, status, index, vbs = await h.bulk_cmd(self._engine(), auth, target, ctx, 0, reps,
                                                           *[h.ObjectType(h.ObjectIdentity(cur[b])) for b in active], lookupMib=False)
                self._raise(ind, status, index)
                if not vbs:
                    break
                n = len(active)
                finished = set()
                for i, (name, val) in enumerate(vbs):
                    b = active[i % n]
                    if b in finished:
                        continue
                    oid = ".".join(str(x) for x in name)
                    v = _convert(val)
                    t = tuple(name)
                    if not oid.startswith(b + ".") or v is MISSING or t <= last[b] or len(out[b]) >= limit:
                        finished.add(b)
                        continue
                    last[b] = t
                    out[b].append((oid, v))
                    cur[b] = oid
                if len(vbs) < n:  # truncated response: avoid spinning on columns that got nothing back
                    finished |= set(active[len(vbs):])
                active = [b for b in active if b not in finished]
        return out

    async def close(self) -> None:
        self._target = None
