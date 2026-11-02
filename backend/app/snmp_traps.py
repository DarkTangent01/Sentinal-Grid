"""SNMP trap / inform receiver (docker service "traps": python -m app.snmp_traps; UDP 1162 in the container, published as
162/udp on TRAP_BIND_IP). docs/SNMP.md.

Security
* Only devices in the SNMP inventory are accepted: the source address must be a monitored device's management address.
* The message must authenticate with that device's own credential profile: the SNMPv1/v2c community of its profile, or
  its SNMPv3 user (traps: keys localised to the device's snmpEngineID, learned by polling; informs: this receiver's
  engine). A valid credential of another device is rejected. Everything else is counted and dropped, never stored.
* Nothing is ever sent to a device except the inform acknowledgement the protocol requires.

Processing
* v1 traps are translated to v2 form by pysnmp (RFC 3584); every trap is normalised to: device, vendor, snmpTrapOID,
  name, severity, component / ifIndex, summary and raw varbinds (OID, type, value).
* Vendor parsers (PARSERS) map known notifications to severity and component; unknown notifications keep severity
  "informational" and are named from imported MIB modules where possible.
* De-duplication: the same (device, trap, component) within DEDUP_SECONDS is counted on the stored row, not re-stored.
* Rows go to ClickHouse snmp_traps; the snmp_trap alert rule (app/nms/alerts.py) raises / clears alerts from them.
"""
from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

log = logging.getLogger("traps")
TRAP_COLS = ["ts", "switch_id", "source_ip", "version", "vendor", "trap_oid", "trap_name", "severity", "component", "ifindex", "summary",
             "varbinds", "repeats"]
DEDUP_SECONDS = 30
DEDUP_MAX_KEYS = 50_000
SNMP_TRAP_OID = "1.3.6.1.6.3.1.1.4.1.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"

# notification OID → name (standard, plus vendor notifications whose OIDs are fixed in the public MIBs)
TRAP_NAMES = {
    "1.3.6.1.6.3.1.1.5.1": "SNMPv2-MIB::coldStart", "1.3.6.1.6.3.1.1.5.2": "SNMPv2-MIB::warmStart",
    "1.3.6.1.6.3.1.1.5.3": "IF-MIB::linkDown", "1.3.6.1.6.3.1.1.5.4": "IF-MIB::linkUp",
    "1.3.6.1.6.3.1.1.5.5": "SNMPv2-MIB::authenticationFailure",
    "1.3.6.1.2.1.15.7.1": "BGP4-MIB::bgpEstablished", "1.3.6.1.2.1.15.7.2": "BGP4-MIB::bgpBackwardTransition",
    "1.3.6.1.2.1.14.16.2.2": "OSPF-TRAP-MIB::ospfNbrStateChange", "1.3.6.1.2.1.47.2.0.1": "ENTITY-MIB::entConfigChange",
    "1.3.6.1.2.1.17.0.1": "BRIDGE-MIB::newRoot", "1.3.6.1.2.1.17.0.2": "BRIDGE-MIB::topologyChange",
    "1.3.6.1.2.1.105.0.1": "POWER-ETHERNET-MIB::pethPsePortOnOffNotification",
    "1.3.6.1.2.1.105.0.2": "POWER-ETHERNET-MIB::pethMainPowerUsageOnNotification",
    "1.3.6.1.2.1.105.0.3": "POWER-ETHERNET-MIB::pethMainPowerUsageOffNotification",
    "1.3.6.1.4.1.9.9.13.3.0.1": "CISCO-ENVMON-MIB::ciscoEnvMonShutdownNotification",
    "1.3.6.1.4.1.9.9.13.3.0.2": "CISCO-ENVMON-MIB::ciscoEnvMonVoltageNotification",
    "1.3.6.1.4.1.9.9.13.3.0.3": "CISCO-ENVMON-MIB::ciscoEnvMonTemperatureNotification",
    "1.3.6.1.4.1.9.9.13.3.0.4": "CISCO-ENVMON-MIB::ciscoEnvMonFanNotification",
    "1.3.6.1.4.1.9.9.13.3.0.5": "CISCO-ENVMON-MIB::ciscoEnvMonRedundantSupplyNotification",
    "1.3.6.1.4.1.9.9.43.2.0.1": "CISCO-CONFIG-MAN-MIB::ciscoConfigManEvent",
    "1.3.6.1.4.1.2636.4.1.1": "JUNIPER-MIB::jnxPowerSupplyFailure", "1.3.6.1.4.1.2636.4.1.2": "JUNIPER-MIB::jnxFanFailure",
    "1.3.6.1.4.1.2636.4.1.3": "JUNIPER-MIB::jnxOverTemperature",
    "1.3.6.1.4.1.2636.4.2.1": "JUNIPER-MIB::jnxPowerSupplyOK", "1.3.6.1.4.1.2636.4.2.2": "JUNIPER-MIB::jnxFanOK",
    "1.3.6.1.4.1.2636.4.2.3": "JUNIPER-MIB::jnxTemperatureOK",
}
# raising notification → the notification that clears it (the alert rule pairs them per device + component)
CLEARS = {"1.3.6.1.6.3.1.1.5.3": "1.3.6.1.6.3.1.1.5.4", "1.3.6.1.2.1.15.7.2": "1.3.6.1.2.1.15.7.1",
          "1.3.6.1.4.1.2636.4.1.1": "1.3.6.1.4.1.2636.4.2.1", "1.3.6.1.4.1.2636.4.1.2": "1.3.6.1.4.1.2636.4.2.2",
          "1.3.6.1.4.1.2636.4.1.3": "1.3.6.1.4.1.2636.4.2.3"}
CLEARED_BY = {v: k for k, v in CLEARS.items()}
IF_INDEX = "1.3.6.1.2.1.2.2.1.1."
IF_DESCR = "1.3.6.1.2.1.2.2.1.2."
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1."
BGP_PEER_STATE = "1.3.6.1.2.1.15.3.1.2."
JNX_CONTENTS_DESCR = "1.3.6.1.4.1.2636.3.1.8.1.6."
C_ENV_DESCR = ("1.3.6.1.4.1.9.9.13.1.3.1.2.", "1.3.6.1.4.1.9.9.13.1.4.1.2.", "1.3.6.1.4.1.9.9.13.1.5.1.2.")


# ------------------------------------------------------------------ normalisation (pure; tested directly)
def _text(v) -> str:
    if isinstance(v, bytes):
        try:
            return v.decode("utf-8")
        except UnicodeDecodeError:
            return v.hex(":")
    return str(v)


def varbind_rows(varbinds: list[tuple[str, object]]) -> list[dict]:
    return [{"oid": o, "type": "bytes" if isinstance(v, bytes) else type(v).__name__, "value": _text(v) if isinstance(v, bytes) else v}
            for o, v in varbinds]


def _find(vbs: dict, prefix) -> tuple[str, object] | None:
    for o, v in vbs.items():
        if any(o.startswith(p) for p in ((prefix,) if isinstance(prefix, str) else prefix)):
            return o, v
    return None


def parse_standard(trap: str, vbs: dict) -> dict:
    out = {"severity": "informational", "component": "", "ifindex": None, "summary": ""}
    if trap in ("1.3.6.1.6.3.1.1.5.3", "1.3.6.1.6.3.1.1.5.4"):
        f = _find(vbs, IF_INDEX)
        ix = int(f[1]) if f and isinstance(f[1], int) else (int(f[0].rsplit(".", 1)[1]) if f else None)
        name = _find(vbs, (IF_NAME, IF_DESCR))
        out.update(ifindex=ix, component=_text(name[1]) if name else (f"ifIndex {ix}" if ix is not None else "interface"))
        down = trap.endswith(".3")
        out.update(severity="medium" if down else "informational", summary=f"{out['component']} link {'down' if down else 'up'}")
    elif trap == "1.3.6.1.6.3.1.1.5.1" or trap == "1.3.6.1.6.3.1.1.5.2":
        out.update(severity="high" if trap.endswith(".1") else "medium", component="system",
                   summary="cold start (device rebooted)" if trap.endswith(".1") else "warm start (agent restarted)")
    elif trap == "1.3.6.1.6.3.1.1.5.5":
        out.update(severity="medium", component="snmp", summary="device received an SNMP request with a bad community / credentials")
    elif trap in ("1.3.6.1.2.1.15.7.1", "1.3.6.1.2.1.15.7.2"):
        f = _find(vbs, BGP_PEER_STATE)
        peer = f[0][len(BGP_PEER_STATE):] if f else ""
        up = trap.endswith(".1")
        out.update(severity="informational" if up else "high", component=f"BGP peer {peer}" if peer else "BGP",
                   summary=f"BGP session {'established' if up else 'left established'}{' with ' + peer if peer else ''}")
    elif trap == "1.3.6.1.2.1.14.16.2.2":
        out.update(severity="medium", component="OSPF", summary="OSPF neighbour state change")
    elif trap in ("1.3.6.1.2.1.17.0.1", "1.3.6.1.2.1.17.0.2"):
        out.update(severity="medium" if trap.endswith(".1") else "low", component="STP",
                   summary="this bridge became the spanning-tree root" if trap.endswith(".1") else "spanning-tree topology change")
    elif trap == "1.3.6.1.2.1.47.2.0.1":
        out.update(severity="low", component="inventory", summary="hardware inventory changed (module inserted / removed)")
    elif trap.startswith("1.3.6.1.2.1.105.0."):
        out.update(severity="medium" if trap.endswith(".2") else "informational", component="PoE",
                   summary={"1": "PoE port power on/off", "2": "PoE power usage over threshold", "3": "PoE power usage back under threshold"}[trap[-1]])
    return out


def parse_cisco(trap: str, vbs: dict) -> dict | None:
    if trap.startswith("1.3.6.1.4.1.9.9.13.3.0."):
        f = _find(vbs, C_ENV_DESCR)
        kind = {"1": "shutdown", "2": "voltage", "3": "temperature", "4": "fan", "5": "redundant power supply"}.get(trap.rsplit(".", 1)[1], "environment")
        return {"severity": "critical" if kind == "shutdown" else "high", "component": _text(f[1]) if f else kind, "ifindex": None,
                "summary": f"environmental alarm: {kind}" + (f" ({_text(f[1])})" if f else "")}
    if trap == "1.3.6.1.4.1.9.9.43.2.0.1":
        return {"severity": "low", "component": "configuration", "ifindex": None, "summary": "configuration changed (CISCO-CONFIG-MAN-MIB)"}
    return None


def parse_juniper(trap: str, vbs: dict) -> dict | None:
    if trap.startswith(("1.3.6.1.4.1.2636.4.1.", "1.3.6.1.4.1.2636.4.2.")):
        f = _find(vbs, JNX_CONTENTS_DESCR)
        comp = _text(f[1]) if f else "chassis"
        ok = trap.startswith("1.3.6.1.4.1.2636.4.2.")
        what = {"1": "power supply", "2": "fan", "3": "temperature"}.get(trap.rsplit(".", 1)[1], "chassis component")
        return {"severity": "informational" if ok else "high" if what != "temperature" else "critical", "component": comp, "ifindex": None,
                "summary": f"{what} {'recovered' if ok else 'failure' if what != 'temperature' else 'over temperature'}: {comp}"}
    return None


PARSERS = {"cisco": parse_cisco, "juniper": parse_juniper}


def canonical(trap: str) -> str:
    """SNMPv1 traps reach us translated per RFC 3584 as enterprise.0.specific; when enterprise.specific is a known SMIv2
    notification (e.g. jnxFanFailure 1.3.6.1.4.1.2636.4.1.2 sent as v1 → …2636.4.1.0.2) use that, so v1 and v2c / v3
    copies of the same event share one name, parser and alert key."""
    head, sep, tail = trap.rpartition(".0.")
    if sep and tail.isdigit() and trap not in TRAP_NAMES and f"{head}.{tail}" in TRAP_NAMES:
        return f"{head}.{tail}"
    return trap


def normalise(vendor: str, varbinds: list[tuple[str, object]], names: dict[str, str] | None = None) -> dict:
    vbs = dict(varbinds)
    trap = vbs.get(SNMP_TRAP_OID)
    trap = canonical(trap if isinstance(trap, str) else _text(trap) if trap is not None else "")
    parsed = (PARSERS.get(vendor) or (lambda *_: None))(trap, vbs) or parse_standard(trap, vbs)
    from .snmp_profiles import name_oid
    nm = TRAP_NAMES.get(trap) or (name_oid(trap, names) if names else "") or trap
    if not parsed["summary"]:
        parsed["summary"] = nm
    payload = [v for v in varbind_rows(varbinds) if v["oid"] not in (SNMP_TRAP_OID, SYS_UPTIME)]
    if names:
        for v in payload:
            v["name"] = name_oid(v["oid"], names)
    return {"trap_oid": trap, "trap_name": nm, **parsed, "varbinds": payload}


@dataclass
class Dedup:
    window: float = DEDUP_SECONDS
    seen: dict = field(default_factory=dict)

    def hit(self, key: tuple, now: float) -> bool:
        """True when the same key arrived within the window (counted, not stored)."""
        last = self.seen.get(key)
        if last is not None and now - last[0] < self.window:
            self.seen[key] = (last[0], last[1] + 1)
            return True
        self.seen[key] = (now, 0)
        if len(self.seen) > DEDUP_MAX_KEYS:
            for k in [k for k, (t, _) in self.seen.items() if now - t > self.window]:
                self.seen.pop(k, None)
            # a storm of unique keys inside one window would otherwise grow this without bound: drop the oldest
            # (insertion order = first seen); worst case a repeat of an evicted key is stored once more
            excess = len(self.seen) - int(DEDUP_MAX_KEYS * 0.9)
            for k in list(self.seen)[:max(0, excess)]:
                self.seen.pop(k, None)
        return False

    def repeats(self, key: tuple) -> int:
        return self.seen.get(key, (0, 0))[1]


# ------------------------------------------------------------------ receiver
class Inventory:
    """Source address → device and its credential (refreshed every minute)."""

    def __init__(self):
        self.by_ip: dict[str, dict] = {}
        self.fingerprint = ""

    async def load(self):
        from sqlalchemy import select

        from .db.models import Switch, SwitchCredential
        from .db.pg import session_factory
        from .switches.poller import credentials_of
        async with session_factory()() as s:
            sws = (await s.execute(select(Switch).where(Switch.credential_id.is_not(None)))).scalars().all()
            creds = {c.id: c for c in (await s.execute(select(SwitchCredential))).scalars()}
        out = {}
        for sw in sws:
            c = creds.get(sw.credential_id)
            if not c:
                continue
            try:
                cr = credentials_of(c)
            except Exception:
                continue
            out[sw.address] = {"switch_id": sw.id, "name": sw.name, "vendor": sw.vendor_override or sw.vendor, "cred_id": c.id, "creds": cr,
                               "engine_id": sw.engine_id or ""}
        fp = json.dumps(sorted((ip, d["cred_id"], d["engine_id"], d["creds"].fingerprint()) for ip, d in out.items()))
        changed = fp != self.fingerprint
        self.by_ip, self.fingerprint = out, fp
        return changed


class Receiver:
    def __init__(self, ch, port: int = 1162, host: str = "0.0.0.0"):
        self.ch, self.port, self.host = ch, port, host
        self.inv = Inventory()
        self.dedup = Dedup()
        self.names: dict[str, str] = {}
        self.engine = None
        self.stats = {"received": 0, "stored": 0, "deduplicated": 0, "rejected_source": 0, "rejected_credential": 0, "errors": 0,
                      "dropped_queue_full": 0}
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=10000)

    def _build(self):
        from pysnmp.carrier.asyncio.dgram import udp
        from pysnmp.entity import config, engine
        from pysnmp.entity.rfc3413 import ntfrcv
        from pysnmp.proto import rfc1902
        if self.engine is not None:   # release the UDP socket before binding the rebuilt engine
            try:
                self.engine.close_dispatcher()
            except Exception:
                log.exception("closing the previous trap engine failed")
        e = engine.SnmpEngine()
        config.add_transport(e, udp.DOMAIN_NAME, udp.UdpTransport().open_server_mode((self.host, self.port)))
        auth = {"none": config.USM_AUTH_NONE, "md5": config.USM_AUTH_HMAC96_MD5, "sha": config.USM_AUTH_HMAC96_SHA,
                "sha224": config.USM_AUTH_HMAC128_SHA224, "sha256": config.USM_AUTH_HMAC192_SHA256, "sha384": config.USM_AUTH_HMAC256_SHA384,
                "sha512": config.USM_AUTH_HMAC384_SHA512}
        priv = {"none": config.USM_PRIV_NONE, "des": config.USM_PRIV_CBC56_DES, "3des": config.USM_PRIV_CBC168_3DES,
                "aes128": config.USM_PRIV_CFB128_AES, "aes192": config.USM_PRIV_CFB192_AES, "aes256": config.USM_PRIV_CFB256_AES}
        done = set()
        for d in self.inv.by_ip.values():
            c, sec = d["creds"], f"cred{d['cred_id']}"
            if c.version == "v2c":
                if ("c", d["cred_id"]) not in done:
                    config.add_v1_system(e, f"idx{d['cred_id']}", c.community, securityName=sec)
                    done.add(("c", d["cred_id"]))
                continue
            # pysnmp indexes its USM table by security name, so it must equal the user name (the receiver then checks that
            # the user is the one in this device's own profile)
            kw = dict(authKey=c.auth_key or None, privKey=c.priv_key or None)
            if d["engine_id"] and ("u", d["cred_id"], d["engine_id"]) not in done:   # traps: keys localised to the sender's engine
                config.add_v3_user(e, c.username, auth[c.auth_protocol], privProtocol=priv[c.priv_protocol],
                                   securityEngineId=rfc1902.OctetString(hexValue=d["engine_id"]), **kw)
                done.add(("u", d["cred_id"], d["engine_id"]))
            if ("u", d["cred_id"]) not in done:                                       # informs: keys localised to this receiver
                config.add_v3_user(e, c.username, auth[c.auth_protocol], privProtocol=priv[c.priv_protocol], **kw)
                done.add(("u", d["cred_id"]))
        e.observer.register_observer(lambda *_: None, "rfc3412.receiveMessage:request")
        ntfrcv.NotificationReceiver(e, self._on_trap)
        self.engine = e

    def _on_trap(self, snmp_engine, state_ref, ctx_engine_id, ctx_name, varbinds, cb_ctx):
        self.stats["received"] += 1
        try:
            ex = snmp_engine.observer.get_execution_context("rfc3412.receiveMessage:request")
            src = str(ex["transportAddress"][0]).removeprefix("::ffff:")
            sec_name = str(ex.get("securityName", ""))
            model = int(ex.get("securityModel", 0))
            d = self.inv.by_ip.get(src)
            if d is None:
                self.stats["rejected_source"] += 1
                return
            expect = f"cred{d['cred_id']}" if d["creds"].version == "v2c" else d["creds"].username
            if (model == 3) != (d["creds"].version == "v3") or not hmac.compare_digest(sec_name, expect):
                self.stats["rejected_credential"] += 1
                return
            vbs = []
            for name, val in varbinds:
                from .switches.snmp import MISSING, _convert
                v = _convert(val)
                vbs.append((str(name), None if v is MISSING else v))
            self.queue.put_nowait((src, d, {1: "v1", 2: "v2c", 3: "v3"}.get(model, str(model)), vbs))
        except asyncio.QueueFull:
            self.stats["dropped_queue_full"] += 1  # counted apart from errors: the writer is behind, not a bad trap
        except Exception:
            self.stats["errors"] += 1
            log.exception("trap handling failed")

    async def _writer(self):
        batch: list[dict] = []
        last = time.monotonic()
        while True:
            try:
                item = await asyncio.wait_for(self.queue.get(), timeout=2)
            except asyncio.TimeoutError:
                item = None
            if item:
                src, d, ver, vbs = item
                n = normalise(d["vendor"], vbs, self.names)
                key = (d["switch_id"], n["trap_oid"], n["component"])
                if self.dedup.hit(key, time.monotonic()):
                    self.stats["deduplicated"] += 1
                else:
                    batch.append({"ts": datetime.now(timezone.utc).replace(microsecond=0), "switch_id": d["switch_id"], "source_ip": src, "version": ver,
                                  "vendor": d["vendor"], "trap_oid": n["trap_oid"], "trap_name": n["trap_name"], "severity": n["severity"],
                                  "component": n["component"][:255], "ifindex": n["ifindex"], "summary": n["summary"][:1000],
                                  "varbinds": json.dumps(n["varbinds"], default=str)[:20000], "repeats": 0})
            if batch and (len(batch) >= 200 or time.monotonic() - last > 2):
                try:
                    await self.ch.ainsert("snmp_traps", batch, TRAP_COLS)
                    self.stats["stored"] += len(batch)
                except Exception:
                    self.stats["errors"] += len(batch)
                    log.exception("clickhouse insert into snmp_traps failed")
                batch, last = [], time.monotonic()

    async def run(self, stop: asyncio.Event):
        from .db.pg import session_factory
        from .snmp_profiles import oid_names
        await self.inv.load()
        async with session_factory()() as s:
            self.names = await oid_names(s)
        self._build()
        writer = asyncio.create_task(self._writer())
        log.info("SNMP trap receiver listening on udp %s:%s for %d device(s)", self.host, self.port, len(self.inv.by_ip))
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=60)
            except asyncio.TimeoutError:
                pass
            try:
                with open("/tmp/traps.heartbeat", "w") as f:
                    f.write(json.dumps(self.stats))
            except OSError:
                pass
            try:
                if await self.inv.load():
                    self._build()
                    log.info("trap receiver reloaded: %d device(s)", len(self.inv.by_ip))
                async with session_factory()() as s:
                    self.names = await oid_names(s)
            except Exception:
                log.exception("trap receiver reload failed")
            log.info("traps: %s", self.stats)
        writer.cancel()


async def main():
    import signal

    from .config import get_settings
    from .db.ch import get_ch
    from .db.pg import init_engine
    from .logging_setup import setup_logging
    st = get_settings()
    setup_logging(st.log_level)
    init_engine(st.database_url)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    await Receiver(get_ch(), port=int(os.environ.get("TRAP_PORT", "1162"))).run(stop)


if __name__ == "__main__":
    asyncio.run(main())
