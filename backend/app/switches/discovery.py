"""Discovery inside authorised management networks only.

A run sweeps one SwitchNetwork that has allow_discovery set, with one credential profile: a single SNMP GET of
sysDescr / sysObjectID / sysName per address (no walks), bounded concurrency, short timeout, no retries, and a hard cap
on the subnet size. Nothing is onboarded automatically: results are candidates an administrator adds explicitly.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
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


async def run(s: AsyncSession, r: SwitchDiscoveryRun, client_factory=None) -> SwitchDiscoveryRun:
    st = get_settings()
    net = await s.get(SwitchNetwork, r.network_id)
    cred = await s.get(SwitchCredential, r.credential_id)
    r.status, r.started_at = "running", datetime.now(timezone.utc)
    await s.commit()
    try:
        if net is None or not net.allow_discovery or net.cidr != r.cidr:
            raise ValueError("the network is not authorised for discovery")
        creds = credentials_of(cred)
        check_version_allowed(creds.version)
        hosts = hosts_of(net.cidr)
        known = {a for (a,) in (await s.execute(select(Switch.address))).all()}
        sem = asyncio.Semaphore(max(1, st.switch_discovery_concurrency))
        found = []

        async def one(ip: str):
            async with sem:
                c = client_factory(ip) if client_factory else PysnmpClient(ip, creds, timeout=1.0, retries=0)
                try:
                    v = await c.get(["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.5.0"])
                except SnmpError as e:
                    if e.kind == "auth":
                        found.append({"address": ip, "status": "auth_failed", "error": e.message[:200], "already_monitored": ip in known})
                    return
                finally:
                    await c.close()
                descr, oid = text(v.get("1.3.6.1.2.1.1.1.0")), v.get("1.3.6.1.2.1.1.2.0")
                if not descr and not isinstance(oid, str):
                    return
                ident = identify(oid if isinstance(oid, str) else "", descr)
                found.append({"address": ip, "status": "found", "sys_name": text(v.get("1.3.6.1.2.1.1.5.0"))[:128], "sys_descr": descr[:300],
                              "sys_object_id": oid if isinstance(oid, str) else "", "vendor": ident["vendor"], "model": ident["model"],
                              "firmware": ident["firmware"], "supported": ident["vendor"] in ("cisco", "fortinet", "juniper", "ruckus"),
                              "product_line": ident.get("product_line", ""), "device_type": ident.get("device_type", ""), "confidence": ident.get("confidence", ""), "already_monitored": ip in known})
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
