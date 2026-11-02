"""Simulated SNMP agents for tests (no network devices involved).

* FakeClient: in-memory implementation of the client interface (get / walk) over an OID → value fixture, with
  switchable failure modes. Used by the collector / normaliser / poller tests.
* UdpAgent: a real SNMP agent on 127.0.0.1 built on pysnmp's command responder, serving the same kind of fixture
  over v2c and SNMPv3 (USM auth + priv). Used to test the real client: GET, GETBULK walks, auth failures, timeouts.
"""
from __future__ import annotations

import asyncio
import bisect

from app.switches.snmp import MISSING, SnmpError


def _key(oid: str) -> tuple:
    return tuple(int(x) for x in oid.strip(".").split("."))


def plain(v):
    """Fixture value → what the real client returns (int / bytes / dotted str)."""
    if isinstance(v, tuple):
        return v[1] if v[0] in ("oid", "ip") else int(v[1])
    if isinstance(v, str):
        return v.encode()
    if isinstance(v, bool):
        return 1 if v else 2
    return v


class FakeClient:
    def __init__(self, tree: dict[str, object], *, fail: str | None = None, contexts: dict[str, dict] | None = None,
                 broken_prefixes: tuple[str, ...] = (), version: str = "v3"):
        self.tree = {k: plain(v) for k, v in tree.items()}
        self.contexts = {c: {k: plain(v) for k, v in t.items()} for c, t in (contexts or {}).items()}
        self.creds = type("C", (), {"version": version})()
        self.fail = fail                 # None | "timeout" | "auth"
        self.broken_prefixes = broken_prefixes  # subtrees that time out (one failing metric group)
        self.requests = 0
        self.walked: list[str] = []

    def _t(self, context):
        return self.contexts.get(context, {}) if context else self.tree

    def _check(self, oid: str):
        if self.fail == "timeout":
            raise SnmpError("timeout", "no SNMP response from 192.0.2.10:161 within 1s × 2 attempts")
        if self.fail == "auth":
            raise SnmpError("auth", "SNMPv3 authentication/privacy rejected by 192.0.2.10 (wrongDigest)")
        if any(oid.startswith(p) for p in self.broken_prefixes):
            raise SnmpError("timeout", "no SNMP response from 192.0.2.10:161 within 1s × 2 attempts")

    async def get(self, oids, context=None):
        self.requests += 1
        t = self._t(context)
        out = {}
        for o in oids:
            self._check(o)
            out[o] = t.get(o, MISSING)
        return out

    async def walk(self, base, context=None, max_rows=None):
        self.requests += 1
        self._check(base)
        self.walked.append(base + (f"@{context}" if context else ""))
        t = self._t(context)
        pre = base + "."
        rows = sorted(((k, v) for k, v in t.items() if k.startswith(pre)), key=lambda kv: _key(kv[0]))
        return rows[: max_rows or 20000]

    async def walk_multi(self, bases, context=None, max_rows=None):
        return {b: await self.walk(b, context, max_rows) for b in bases}

    async def close(self):
        pass


def _to_asn1(v):
    from pysnmp.proto import rfc1902
    if isinstance(v, tuple) and len(v) == 2 and isinstance(v[0], str):
        kind, x = v
        return {"c32": rfc1902.Counter32, "c64": rfc1902.Counter64, "g32": rfc1902.Gauge32, "tt": rfc1902.TimeTicks,
                "ip": rfc1902.IpAddress, "oid": rfc1902.ObjectName}[kind](x)
    if isinstance(v, bool):
        return rfc1902.Integer(1 if v else 2)
    if isinstance(v, int):
        return rfc1902.Integer(v)
    if isinstance(v, bytes):
        return rfc1902.OctetString(v)
    if isinstance(v, str):
        return rfc1902.OctetString(v.encode())
    raise TypeError(v)


class _Instrum:
    """MIB instrumentation over a sorted OID list (GET / GETNEXT)."""

    def __init__(self, tree: dict[str, object]):
        from pysnmp.proto import rfc1902
        self.keys = sorted(_key(k) for k in tree)
        self.vals = {_key(k): _to_asn1(v) for k, v in tree.items()}
        self.rfc1902 = rfc1902

    def read_variables(self, *varBinds, **context):
        from pysnmp.proto import rfc1905
        out = []
        for name, _ in varBinds:
            k = tuple(name)
            out.append((self.rfc1902.ObjectName(k), self.vals.get(k, rfc1905.noSuchInstance)))
        return out

    def read_next_variables(self, *varBinds, **context):
        from pysnmp.proto import rfc1905
        out = []
        for name, _ in varBinds:
            k = tuple(name)
            i = bisect.bisect_right(self.keys, k)
            if i < len(self.keys):
                nk = self.keys[i]
                out.append((self.rfc1902.ObjectName(nk), self.vals[nk]))
            else:
                out.append((self.rfc1902.ObjectName(k), rfc1905.endOfMibView))
        return out

    def write_variables(self, *varBinds, **context):
        from pysnmp.smi import error
        raise error.NotWritableError(idx=0)


class UdpAgent:
    """Real SNMP agent on 127.0.0.1:<random port>. v2c community and/or one SNMPv3 user (SHA/AES by default)."""

    def __init__(self, tree: dict[str, object], *, community: str | None = "public-test", v3_user: str | None = None,
                 auth_key: str = "auth-pass-123", priv_key: str = "priv-pass-456", auth="sha", priv="aes128"):
        self.tree, self.community = tree, community
        self.v3_user, self.auth_key, self.priv_key, self.auth, self.priv = v3_user, auth_key, priv_key, auth, priv
        self.port = None
        self.engine = None

    async def start(self):
        from pysnmp.carrier.asyncio.dgram import udp
        from pysnmp.entity import config, engine
        from pysnmp.entity.rfc3413 import cmdrsp, context
        e = engine.SnmpEngine()
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as so:  # pick a free port
            so.bind(("127.0.0.1", 0))
            self.port = so.getsockname()[1]
        transport = udp.UdpAsyncioTransport().open_server_mode(("127.0.0.1", self.port))
        config.add_transport(e, udp.DOMAIN_NAME, transport)
        lport = getattr(transport, "_lport", None)
        if isinstance(lport, asyncio.Future):
            await lport
        if self.community:
            config.add_v1_system(e, "test-area", self.community)
            config.add_vacm_user(e, 2, "test-area", "noAuthNoPriv", (1, 3, 6), ())
        if self.v3_user:
            auth = {"md5": config.USM_AUTH_HMAC96_MD5, "sha": config.USM_AUTH_HMAC96_SHA,
                    "sha256": config.USM_AUTH_HMAC192_SHA256}[self.auth]
            priv = {"none": config.USM_PRIV_NONE, "des": config.USM_PRIV_CBC56_DES, "aes128": config.USM_PRIV_CFB128_AES,
                    "aes256": config.USM_PRIV_CFB256_AES}[self.priv]
            config.add_v3_user(e, self.v3_user, auth, self.auth_key, priv, self.priv_key if self.priv != "none" else None)
            level = "authPriv" if self.priv != "none" else "authNoPriv"
            config.add_vacm_user(e, 3, self.v3_user, level, (1, 3, 6), ())
            config.add_vacm_user(e, 3, self.v3_user, level, (1, 2, 840), ())
        ctx = context.SnmpContext(e)
        ctx.unregister_context_name(b"")
        ctx.register_context_name(b"", _Instrum(self.tree))
        cmdrsp.GetCommandResponder(e, ctx)
        cmdrsp.NextCommandResponder(e, ctx)
        cmdrsp.BulkCommandResponder(e, ctx)
        self.engine = e
        return self

    def stop(self):
        if self.engine is not None:
            self.engine.close_dispatcher()
