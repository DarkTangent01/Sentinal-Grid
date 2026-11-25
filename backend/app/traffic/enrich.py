"""Enrichment: who an address is (query time, bounded to the rows shown) and what runs on it (background loop).

Query time (hosts): batched lookups for the addresses of one result page — inventory devices (switches / controllers /
firewalls), wireless clients (MAC, SSID, VLAN; user names only with the sensitive-data permission), MAC location from
switch MAC tables, the cached enrichment row, and the configured range (site / VLAN / zone). Never one query per row,
never a network lookup.

Background (run_enrichment, worker loop "traffic_enrichment"): for the busiest server-side addresses of the last two
hours, each run combines
  firewall application control (events, category traffic, app)          → confirmed
  DNS answers in collected DNS logs (events, category dns, dns_resolved) → high, unless the address serves many
                                                                            unrelated names (shared CDN address)
  local ASN database (platform.geoip)                                    → probable (provider only)
  reverse DNS (optional, off by default, rate-limited, 1 s timeout)      → hostname only, never an application
and stores the result in traffic_ip_info. DNS logs and firewall logs are read only when collected; nothing is
fabricated when they are absent.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from collections import Counter
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import Firewall, Switch, SwitchInterface, SwitchMac, TrafficIpInfo, WirelessClient
from . import networks as N
from . import registry as R
from .settings import load_settings

log = logging.getLogger("traffic")
SHARED_DOMAINS = 4            # an address answering for more registered domains than this is treated as shared (CDN)


def _reg_domain(name: str) -> str:
    parts = (name or "").lower().rstrip(".").split(".")
    return ".".join(parts[-3:]) if len(parts) > 2 and len(parts[-1]) == 2 and len(parts[-2]) <= 3 else ".".join(parts[-2:])


def _valid_ips(ips) -> list[str]:
    out = []
    for ip in ips:
        try:
            out.append(str(ipaddress.ip_address(ip)))
        except (ValueError, TypeError):
            continue
    return sorted(set(out))


async def hosts(s: AsyncSession, ips, *, sensitive: bool, macs: dict[str, str] | None = None) -> dict[str, dict]:
    """ip → {hostname, kind, device, site, zone, vlan, network, mac, switch, port, ssid, user, asn, as_org, country}."""
    ips = _valid_ips(ips)[:1000]
    if not ips:
        return {}
    nets = await N.load(s)
    out: dict[str, dict] = {}
    for ip in ips:
        n = nets.lookup(ip)
        out[ip] = {"hostname": "", "kind": "", "device": "", "site": n.site if n else "", "zone": n.zone if n else "",
                   "vlan": n.vlan if n else None, "network": n.name or n.cidr if n else "", "internal": nets.is_internal(ip),
                   "mac": "", "switch": "", "port": "", "ssid": "", "user": "", "asn": 0, "as_org": "", "country": "", "vendor": "", "device_type": "",
                   "device_confidence": "", "device_evidence": [], "os": "", "randomized": False}
    for sw in (await s.execute(select(Switch).where(Switch.address.in_(ips)))).scalars():
        o = out[sw.address]
        o.update(kind="switch", device=sw.name, hostname=sw.sys_name or sw.name, site=sw.site or o["site"])
    for fw in (await s.execute(select(Firewall).where(Firewall.host.in_(ips), Firewall.is_demo.is_(False)))).scalars():
        o = out[fw.host]
        o.update(kind="firewall", device=fw.name, hostname=fw.name, site=getattr(fw, "site", "") or o["site"])
    clients = (await s.execute(select(WirelessClient).where(WirelessClient.ip.in_(ips)).order_by(WirelessClient.last_seen.desc()))).scalars().all()
    for c in clients:
        o = out.get(c.ip)
        if o is None or o["kind"]:
            continue
        o.update(kind="wireless-client", mac=c.mac, ssid=c.ssid, vlan=c.vlan if c.vlan is not None else o["vlan"])
        if sensitive and c.username:
            o["user"] = c.username
    for ip, mac in (macs or {}).items():
        if ip in out and mac and not out[ip]["mac"]:
            out[ip]["mac"] = mac
    want_macs = {o["mac"] for o in out.values() if o["mac"]}
    if want_macs:
        rows = (await s.execute(select(SwitchMac, Switch.name).join(Switch, Switch.id == SwitchMac.switch_id)
                                .where(SwitchMac.mac.in_(want_macs)))).all()
        lag_ports = {(i.switch_id, i.ifindex) for i in (await s.execute(select(SwitchInterface).where(
            SwitchInterface.switch_id.in_({m.switch_id for m, _ in rows} or {0}), SwitchInterface.kind == "lag"))).scalars()}
        best: dict[str, tuple] = {}
        per_port = Counter((m.switch_id, m.ifindex) for m, _ in rows)
        for m, swname in rows:
            # the access port: not a LAG, and the port with the fewest learned MACs (uplinks learn many)
            score = (1 if (m.switch_id, m.ifindex) in lag_ports else 0, per_port[(m.switch_id, m.ifindex)])
            if m.mac not in best or score < best[m.mac][0]:
                best[m.mac] = (score, swname, m.port_name or f"ifIndex {m.ifindex}", m.vlan_id)
        for o in out.values():
            b = best.get(o["mac"])
            if b:
                o.update(switch=b[1], port=b[2], vlan=o["vlan"] if o["vlan"] is not None else (b[3] or None))
    for r in (await s.execute(select(TrafficIpInfo).where(TrafficIpInfo.ip.in_(ips)))).scalars():
        o = out[r.ip]
        o.update(asn=r.asn, as_org=r.as_org, country=r.country)
        if sensitive and r.rdns and not o["hostname"]:
            o["hostname"] = r.rdns
    from ..platform.identity import identities
    for ip, idn in (await identities(s, ips, sensitive=True)).items():
        o = out[ip]
        o.update(vendor=idn["vendor"], device_type=idn["device_type"], device_confidence=idn["confidence"], device_evidence=idn["evidence"],
                 os=idn["os"], randomized=idn["randomized"])
        for k in ("mac", "switch", "port", "ap", "ssid", "site"):
            if idn.get(k) and not o.get(k):
                o[k] = idn[k]
        if o.get("vlan") is None and idn.get("vlan"):
            o["vlan"] = idn["vlan"]
        if idn.get("hostname") and not o["hostname"]:
            o["hostname"] = idn["hostname"]
        if idn.get("user") and sensitive and not o["user"]:
            o["user"] = idn["user"]
    if not sensitive:
        for o in out.values():
            o["mac"] = ""
            o["user"] = ""
    return out


async def ip_apps(s: AsyncSession, limit: int = 5000) -> dict[str, tuple[str, str, str]]:
    rows = (await s.execute(select(TrafficIpInfo.ip, TrafficIpInfo.app, TrafficIpInfo.category, TrafficIpInfo.confidence)
                            .where(TrafficIpInfo.app != "", TrafficIpInfo.confidence.in_(["confirmed", "high", "probable"]))
                            .order_by(TrafficIpInfo.updated_at.desc()).limit(limit))).all()
    return {ip: (app, cat or "other", conf) for ip, app, cat, conf in rows}


# ------------------------------------------------------------------ background enrichment
async def _dns_names(ch, ips: list[str], since: datetime) -> dict[str, list[str]]:
    from ..platform.eventquery import table
    try:
        rows = await ch.aquery(
            f"SELECT ip, groupUniqArray(50)(dns_qname) AS names FROM (SELECT arrayJoin(dns_resolved) AS ip, dns_qname FROM {table()} "
            "WHERE event_time >= {t:DateTime64(3)} AND category = 'dns' AND notEmpty(dns_resolved) AND hasAny(dns_resolved, {ips:Array(String)})) "
            "WHERE ip IN {ips:Array(String)} GROUP BY ip", {"t": since, "ips": ips})
    except Exception:
        log.warning("DNS log correlation unavailable", exc_info=True)
        return {}
    return {r["ip"]: [n for n in r["names"] if n] for r in rows}


async def _fw_apps(ch, ips: list[str], since: datetime) -> dict[str, list[tuple[str, str, int]]]:
    from ..platform.eventquery import table
    try:
        rows = await ch.aquery(
            f"SELECT dst_ip, app, app_cat, count() AS n FROM {table()} WHERE event_time >= {{t:DateTime64(3)}} AND category = 'traffic' "
            "AND app != '' AND dst_ip IN {ips:Array(String)} GROUP BY dst_ip, app, app_cat ORDER BY n DESC LIMIT 20000", {"t": since, "ips": ips})
    except Exception:
        log.warning("firewall application correlation unavailable", exc_info=True)
        return {}
    out: dict[str, list] = {}
    for r in rows:
        out.setdefault(r["dst_ip"], []).append((r["app"], r["app_cat"] or "", int(r["n"])))
    return out


GENERIC_FW_APPS = {"https", "http", "ssl", "tcp", "udp", "unknown", "https.browser", "http.browser", "ssl_tls", "web-browsing", "quic"}


def classify(ip: str, fw: list[tuple[str, str, int]], names: list[str], asn: int, as_org: str, reg: R.Registry) -> dict:
    """Evidence-based application of one server address. Pure (tested)."""
    ev: list[str] = []
    specific = [(a, c, n) for a, c, n in fw if a.lower() not in GENERIC_FW_APPS]
    if specific:
        total = sum(n for _, _, n in specific)
        a, c, n = specific[0]
        if n >= 0.8 * total:
            ev.append(f"firewall application control: {a} ({n} of {total} sessions)")
            return {"app": a, "category": (c or "other").lower()[:32], "confidence": "confirmed", "evidence": ev}
        ev.append("firewall application control: several applications on this address (" + ", ".join(x[0] for x in specific[:4]) + ")")
    regs = sorted({_reg_domain(n) for n in names if n})
    if names:
        matches = {reg.domain_app(n) for n in names} - {None}
        if len(regs) > SHARED_DOMAINS:
            ev.append(f"DNS: shared address ({len(regs)} registered domains resolve to it), not attributed to one application")
        elif len(matches) == 1:
            app, cat = next(iter(matches))
            shown = ", ".join(sorted(set(names))[:3])
            ev.append(f"DNS: resolved from {shown}")
            return {"app": app, "category": cat, "confidence": "high", "evidence": ev}
        elif len(matches) > 1:
            ev.append("DNS: names of several applications resolve to this address")
        else:
            ev.append("DNS: resolved from " + ", ".join(sorted(set(names))[:3]) + " (no signature)")
    if asn and asn in reg.asn:
        prov, cat = reg.asn[asn]
        ev.append(f"ASN {asn} {as_org}".strip())
        return {"app": prov, "category": cat, "confidence": "probable", "evidence": ev}
    if asn:
        ev.append(f"ASN {asn} {as_org}".strip())
    return {"app": "", "category": "", "confidence": "unknown", "evidence": ev}


def _rdns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0][:255]
    except (OSError, UnicodeError):
        return ""


async def run_enrichment(ch, s: AsyncSession, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    st = await load_settings(s)
    reg = await R.load(s, max_age=0)
    nets = await N.load(s, max_age=0)
    top_n = int(st.get("enrich_top_n") or 2000)
    rows = await ch.aquery(
        "SELECT if(server_is_dst = 1, dst_ip, src_ip) AS ip, sum(bytes) AS b FROM flows_conv_hourly WHERE hour >= toStartOfHour({t:DateTime64(3)}) "
        "GROUP BY ip ORDER BY b DESC LIMIT {n:UInt32}", {"t": now - timedelta(hours=2), "n": top_n})
    cands = _valid_ips(r["ip"] for r in rows)
    if not cands:
        return {"candidates": 0}
    fresh = now - timedelta(hours=int(st.get("enrich_refresh_hours") or 6))
    have = {r.ip: r for r in (await s.execute(select(TrafficIpInfo).where(TrafficIpInfo.ip.in_(cands)))).scalars()}
    todo = [ip for ip in cands if ip not in have or (have[ip].updated_at.replace(tzinfo=timezone.utc) if have[ip].updated_at.tzinfo is None
                                                       else have[ip].updated_at) < fresh]
    if not todo:
        return {"candidates": len(cands), "enriched": 0}
    since = now - timedelta(hours=24)
    names = await _dns_names(ch, todo, since) if st.get("enrich_dns") else {}
    fw = await _fw_apps(ch, todo, since) if st.get("enrich_firewall_apps") else {}
    geo = None
    if st.get("enrich_asn"):
        try:
            from ..platform.geoip import get_geo
            geo = get_geo()
        except Exception:
            geo = None
    rdns: dict[str, str] = {}
    if st.get("enrich_rdns"):
        sem = asyncio.Semaphore(10)
        loop = asyncio.get_running_loop()

        async def one(ip):
            async with sem:
                try:
                    rdns[ip] = await asyncio.wait_for(loop.run_in_executor(None, _rdns, ip), timeout=1.0)
                except asyncio.TimeoutError:
                    rdns[ip] = ""
        await asyncio.gather(*(one(ip) for ip in todo[: int(st.get("rdns_per_run") or 100)]))
    n = 0
    for ip in todo:
        g = geo.lookup(ip) if geo and not nets.is_internal(ip) else {}
        c = classify(ip, fw.get(ip, []), names.get(ip, []), int(g.get("asn") or 0), g.get("as_org") or "", reg)
        row = have.get(ip) or TrafficIpInfo(ip=ip)
        row.asn, row.as_org, row.country = int(g.get("asn") or 0), (g.get("as_org") or "")[:255], (g.get("country") or "")[:64]
        if ip in rdns:
            row.rdns = rdns[ip]
        regs = sorted({_reg_domain(x) for x in names.get(ip, [])})
        row.domains, row.domain_count = sorted(set(names.get(ip, [])))[:50], len(regs)
        best = (fw.get(ip) or [("", "", 0)])[0]
        row.fw_app, row.fw_app_cat = best[0][:128], best[1][:64]
        row.app, row.category, row.confidence, row.evidence = c["app"][:64], c["category"][:32], c["confidence"], c["evidence"][:10]
        row.updated_at = now
        if ip not in have:
            s.add(row)
        n += 1
    await s.execute(delete(TrafficIpInfo).where(TrafficIpInfo.updated_at < now - timedelta(days=30)))
    await s.commit()
    return {"candidates": len(cands), "enriched": n, "dns_matched": len(names), "firewall_matched": len(fw), "rdns": len(rdns)}
