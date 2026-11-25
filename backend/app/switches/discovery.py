"""Discovery inside authorised management networks only.

A run sweeps one SwitchNetwork that has allow_discovery set, with any of these methods:
  snmp  one SNMP GET of sysDescr / sysObjectID / sysName per address with one credential profile (no walks)
  icmp  one ICMP echo per address (800 ms)
  tcp   a TCP connect to the management ports (22 ssh, 23 telnet, 80 http, 443 https, 830 netconf), 800 ms each
  arp   the ARP tables (IP-MIB ipNetToMediaTable) of the devices already monitored, filtered to this network: hosts that
        are silent to ICMP / TCP / SNMP still show up with their MAC and the device that learned them
Bounded concurrency, short timeouts, no retries, a hard cap on the subnet size, and every address is checked by
netguard (no loopback / reserved). Nothing is onboarded automatically: results are candidates an administrator adds.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..icmp import ping
from ..db.models import Switch, SwitchCredential, SwitchDiscoveryRun, SwitchNetwork
from ..netguard import DestinationError, check_ip
from .collect import identify, text
from .poller import check_version_allowed, credentials_of
from .snmp import PysnmpClient, SnmpError

log = logging.getLogger("switches.discovery")


def hosts_of(cidr: str) -> list[str]:
    net = ipaddress.ip_network(cidr, strict=False)
    limit = get_settings().switch_discovery_max_hosts
    if net.num_addresses > limit + 2:
        raise ValueError(f"{cidr} has {net.num_addresses} addresses; discovery is limited to {limit} per run (SWITCH_DISCOVERY_MAX_HOSTS)")
    out = []
    for ip in (net.hosts() if net.num_addresses > 2 else net):
        try:
            check_ip(ip)
        except DestinationError:
            continue
        out.append(str(ip))
    return out


METHODS = ("snmp", "icmp", "tcp", "arp")
TCP_PORTS = {22: "ssh", 23: "telnet", 80: "http", 443: "https", 830: "netconf"}
ARP_PHYS = "1.3.6.1.2.1.4.22.1.2"          # ipNetToMediaPhysAddress.<ifIndex>.<a.b.c.d>


async def tcp_ports(ip: str, ports=tuple(TCP_PORTS), timeout: float = 0.8) -> list[int]:
    async def one(p):
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(ip, p), timeout)
            w.close()
            return p
        except (OSError, asyncio.TimeoutError):
            return None
    return [p for p in await asyncio.gather(*(one(p) for p in ports)) if p]


def _mac(v) -> str:
    b = v if isinstance(v, (bytes, bytearray)) else b""
    return ":".join(f"{x:02x}" for x in b) if len(b) == 6 else ""


async def arp_entries(s: AsyncSession, cidr: str, client_factory=None) -> dict[str, dict]:
    """IP → {mac, learned_from} from the ARP tables of monitored devices, for addresses inside `cidr`."""
    from .poller import make_client
    net = ipaddress.ip_network(cidr, strict=False)
    sws = (await s.execute(select(Switch).where(Switch.monitoring == "active", Switch.credential_id.is_not(None), Switch.state == "up"))).scalars().all()
    nets = (await s.execute(select(SwitchNetwork))).scalars().all()
    from .poller import validate_address
    out: dict[str, dict] = {}
    sem = asyncio.Semaphore(8)

    async def one(sw: Switch):
        async with sem:
            try:
                validate_address(sw.address, nets)
            except ValueError:
                return
            cred = await s.get(SwitchCredential, sw.credential_id)
            try:
                c = client_factory(sw) if client_factory else make_client(sw, cred)
            except Exception:
                return
            try:
                rows = await asyncio.wait_for(c.walk(ARP_PHYS, max_rows=20000), 60)
            except Exception:
                return
            finally:
                await c.close()
            for oid, v in rows:
                parts = oid[len(ARP_PHYS) + 1:].split(".")
                if len(parts) != 5:
                    continue
                try:
                    ip = ipaddress.ip_address(".".join(parts[1:]))
                except ValueError:
                    continue
                mac = _mac(v)
                if ip in net and mac and str(ip) not in out:
                    out[str(ip)] = {"mac": mac, "learned_from": sw.name, "learned_from_id": sw.id}
    await asyncio.gather(*(one(x) for x in sws))
    return out


async def run(s: AsyncSession, r: SwitchDiscoveryRun, client_factory=None, pinger=None, prober=None, arp_client_factory=None) -> SwitchDiscoveryRun:
    st = get_settings()
    net = await s.get(SwitchNetwork, r.network_id)
    cred = await s.get(SwitchCredential, r.credential_id) if r.credential_id else None
    methods = [m for m in (r.methods or ["snmp"]) if m in METHODS] or ["snmp"]
    pinger, prober = pinger or ping, prober or tcp_ports
    r.status, r.started_at = "running", datetime.now(timezone.utc)
    await s.commit()
    try:
        if net is None or not net.allow_discovery or net.cidr != r.cidr:
            raise ValueError("the network is not authorised for discovery")
        creds = None
        if "snmp" in methods:
            if cred is None:
                raise ValueError("SNMP discovery needs a credential profile")
            creds = credentials_of(cred)
            check_version_allowed(creds.version)
        hosts = hosts_of(net.cidr)
        known = {a for (a,) in (await s.execute(select(Switch.address))).all()}
        sem = asyncio.Semaphore(max(1, st.switch_discovery_concurrency))
        arp = await arp_entries(s, net.cidr, arp_client_factory) if "arp" in methods else {}
        found = []

        async def one(ip: str):
            async with sem:
                e: dict = {"address": ip, "already_monitored": ip in known, "methods": []}
                if "icmp" in methods:
                    pr = await pinger(ip, count=1, timeout_ms=800)
                    if pr.received:
                        e["methods"].append("icmp")
                        e["rtt_ms"] = pr.rtts[0] if pr.rtts else None
                if "tcp" in methods:
                    ports = await prober(ip)
                    if ports:
                        e["methods"].append("tcp")
                        e["open_ports"] = ports
                        e["services"] = [TCP_PORTS.get(p, str(p)) for p in ports]
                if ip in arp:
                    e["methods"].append("arp")
                    e.update(mac=arp[ip]["mac"], learned_from=arp[ip]["learned_from"])
                if "snmp" in methods:
                    c = client_factory(ip) if client_factory else PysnmpClient(ip, creds, timeout=1.0, retries=0)
                    try:
                        v = await c.get(["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.5.0"])
                    except SnmpError as err:
                        v = None
                        if err.kind == "auth":
                            e.update(status="auth_failed", error=err.message[:200])
                            e["methods"].append("snmp")
                    finally:
                        await c.close()
                    if v is not None:
                        descr, oid = text(v.get("1.3.6.1.2.1.1.1.0")), v.get("1.3.6.1.2.1.1.2.0")
                        if descr or isinstance(oid, str):
                            ident = identify(oid if isinstance(oid, str) else "", descr)
                            e["methods"].append("snmp")
                            e.update(status="found", sys_name=text(v.get("1.3.6.1.2.1.1.5.0"))[:128], sys_descr=descr[:300],
                                     sys_object_id=oid if isinstance(oid, str) else "", vendor=ident["vendor"], model=ident["model"],
                                     firmware=ident["firmware"], supported=ident["vendor"] in ("cisco", "fortinet", "juniper", "ruckus"),
                                     product_line=ident.get("product_line", ""), device_type=ident.get("device_type", ""),
                                     confidence=ident.get("confidence", ""))
                if not e["methods"]:
                    return
                e.setdefault("status", "alive" if set(e["methods"]) & {"icmp", "tcp"} else "arp_only")
                found.append(e)
        await asyncio.gather(*(one(ip) for ip in hosts))
        r.scanned = len(hosts)
        r.results = sorted(found, key=lambda x: ipaddress.ip_address(x["address"]))
        r.status = "done"
    except (ValueError, SnmpError) as e:
        r.status, r.error = "failed", str(getattr(e, "message", e))[:1000]
    except Exception as e:
        log.exception("discovery run %s failed", r.id)
        r.status, r.error = "failed", f"internal error: {type(e).__name__}"
    r.finished_at = datetime.now(timezone.utc)
    await s.commit()
    return r


async def run_queued(session_factory) -> int:
    async with session_factory() as s:
        r = (await s.execute(select(SwitchDiscoveryRun).where(SwitchDiscoveryRun.status == "queued").order_by(SwitchDiscoveryRun.id).limit(1))).scalars().first()
        if r is None:
            return 0
        from sqlalchemy import update
        res = await s.execute(update(SwitchDiscoveryRun).where(SwitchDiscoveryRun.id == r.id, SwitchDiscoveryRun.status == "queued").values(status="running"))
        await s.commit()
        if res.rowcount != 1:  # another worker took it
            return 0
        await s.refresh(r)
        await run(s, r)
        return 1
