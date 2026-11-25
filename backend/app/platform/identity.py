"""Shared identity index: who and what is behind an IP address (docs/architecture → identity, docs/nms/IDENTITY.md).

Each product registers *contributors* (register_contributor) that read its own evidence and return Observations:
  Sentinel NMS  wireless clients, switch MAC tables, sFlow MACs, TACACS+ accounting
  Sentinel Grid FortiGate device detection (srcmac / vendor / devtype / OS), VPN logins, Windows logons, DHCP logs
The worker loop identity_index (run_identity) merges them into three tables both products read through this module:
  host_identities   per device (MAC): vendor, randomised MAC, device type + evidence, OS, hostname, connection point, user
  ip_mac_bindings   IP ↔ MAC timeline per source;   ip_user_bindings   IP ↔ user timeline per source
This module imports neither product: contributors register themselves when their product's composition is loaded.

Evidence rules
  - A MAC that appears behind more than ROUTER_IPS addresses in one window (a router, firewall or AP doing routing / NAT)
    is never bound to an IP as a host; contributors drop such MACs.
  - Locally administered MACs (second bit of the first octet) are private / randomised: no vendor, marked randomized.
  - Device type: inventory (confirmed) > device fingerprinting (high) > vendor or behaviour (probable); every type keeps
    the evidence that produced it.
"""
from __future__ import annotations

import gzip
import ipaddress
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import HostIdentity, IpMacBinding, IpUserBinding

log = logging.getLogger("identity")
ROUTER_IPS = 3
RETENTION_DAYS = 30
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
CONF_RANK = {"confirmed": 4, "high": 3, "probable": 2, "": 0}


# ------------------------------------------------------------------ MAC helpers
def norm_mac(v: str | None) -> str:
    m = (v or "").strip().lower().replace("-", ":").replace(".", "")
    if len(m) == 12 and ":" not in m:
        m = ":".join(m[i:i + 2] for i in range(0, 12, 2))
    return m if MAC_RE.match(m) else ""


def is_unicast_host_mac(mac: str) -> bool:
    if not mac or mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return False
    first = int(mac[:2], 16)
    return not first & 1                                   # multicast / broadcast bit


def is_randomized(mac: str) -> bool:
    return bool(mac) and bool(int(mac[:2], 16) & 2)        # locally administered: private / random address


_OUI: dict[int, dict[int, str]] | None = None


def _load_oui() -> dict[int, dict[int, str]]:
    global _OUI
    if _OUI is not None:
        return _OUI
    tables: dict[int, dict[int, str]] = {24: {}, 28: {}, 36: {}}
    path = Path(__file__).parent / "data" / "manuf.gz"
    try:
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if not line or line[0] == "#":
                    continue
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 2:
                    continue
                block = parts[0].strip()
                name = (parts[2] if len(parts) > 2 and parts[2].strip() else parts[1]).strip()
                bits = 24
                if "/" in block:
                    block, b = block.split("/", 1)
                    bits = int(b)
                hexs = block.replace(":", "").replace("-", "")
                if bits not in tables or not hexs:
                    continue
                n = int(hexs, 16) >> (len(hexs) * 4 - bits) if len(hexs) * 4 >= bits else int(hexs, 16)
                tables[bits][n] = name[:128]
    except OSError:
        log.warning("MAC vendor database not available (%s)", path)
    _OUI = tables
    return tables


def vendor_of(mac: str) -> str:
    """Manufacturer from the IEEE registries (bundled), "" for unknown or randomised MACs."""
    if not mac or is_randomized(mac):
        return ""
    t = _load_oui()
    v = int(mac.replace(":", ""), 16)
    for bits in (36, 28, 24):
        hit = t[bits].get(v >> (48 - bits))
        if hit:
            return hit
    return ""


# ------------------------------------------------------------------ device classification
# (pattern in vendor name, device type) — probable: a vendor makes mostly this kind of device
VENDOR_TYPES: list[tuple[str, str]] = [
    (r"hikvision|dahua|axis communications|hanwha|uniview|cp plus|vivotek|hikrobot", "IP camera"),
    (r"canon|seiko epson|epson|brother industries|xerox|kyocera|ricoh|lexmark|konica|sharp corp", "Printer"),
    (r"yealink|polycom|avaya|grandstream|snom|mitel|fanvil", "IP phone"),
    (r"espressif|tuya|shelly|itead|sonoff|broadlink|lumi united|xiaomi.*iot", "IoT device"),
    (r"raspberry pi", "Single-board computer"),
    (r"vmware|xensource|qemu|virtualbox|parallels|proxmox", "Virtual machine"),
    (r"^apple", "Apple device"),
    (r"samsung|oneplus|oppo|vivo mobile|realme|motorola mobility|huawei device|honor device|nothing technology|google", "Phone or tablet"),
    (r"intel corporate|realtek|liteon|azurewave|dell|lenovo|asustek|acer|hewlett packard|hp inc|microsoft", "Computer"),
    (r"cisco|ruckus|aruba|juniper|fortinet|ubiquiti|arista|extreme networks|mikrotik|tp-link|netgear|commscope", "Network equipment"),
    (r"lg electronics|sony|tcl|roku|hisense|vizio", "TV or media device"),
    (r"zebra|honeywell|datalogic", "Scanner or handheld"),
]
FORTI_TYPES = {"phone": "Phone or tablet", "tablet": "Phone or tablet", "windows pc": "Computer", "linux pc": "Computer", "mac": "Computer",
               "printer": "Printer", "ip phone": "IP phone", "camera": "IP camera", "media": "TV or media device", "game": "Game console",
               "router": "Network equipment", "network": "Network equipment", "server": "Server", "iot": "IoT device"}
BEHAVIOUR_TYPES = {554: "IP camera", 8554: "IP camera", 9100: "Printer", 631: "Printer", 515: "Printer", 5060: "IP phone", 1883: "IoT device"}


def classify(facts: dict) -> tuple[str, str, list[str]]:
    """(device type, confidence, evidence) from the facts gathered for one MAC. Pure (tested)."""
    ev: list[str] = []
    if facts.get("inventory"):
        return facts["inventory"], "confirmed", [f"inventory: {facts['inventory']}"]
    fd = (facts.get("fortigate_devtype") or "").strip().lower()
    if fd and fd in FORTI_TYPES and fd != "router":
        os_ = f", {facts['os']}" if facts.get("os") else ""
        return FORTI_TYPES[fd], "high", [f"FortiGate device detection: {facts['fortigate_devtype']}{os_}"]
    vendor = (facts.get("vendor") or "").lower()
    for pat, typ in VENDOR_TYPES:
        if vendor and re.search(pat, vendor):
            ev.append(f"manufacturer: {facts.get('vendor')}")
            if typ == "Phone or tablet" and facts.get("wireless"):
                ev.append("wireless client")
            return typ, "probable", ev
    for port, typ in BEHAVIOUR_TYPES.items():
        if port in (facts.get("server_ports") or ()):
            return typ, "probable", [f"serves TCP/UDP {port}"]
    if facts.get("randomized") and facts.get("wireless"):
        return "Mobile device (private MAC)", "probable", ["randomised MAC on Wi-Fi (phones and laptops use private addresses)"]
    if facts.get("wireless"):
        return "Wireless client", "probable", ["seen as a wireless client"]
    return "", "", ev


# ------------------------------------------------------------------ contributors
@dataclass
class Observations:
    ip_mac: list[tuple[str, str, str, datetime]] = field(default_factory=list)       # ip, mac, source, seen
    ip_user: list[tuple[str, str, str, datetime]] = field(default_factory=list)      # ip, user, source, seen
    devices: dict[str, dict] = field(default_factory=dict)                            # mac → facts (see HostIdentity)

    def device(self, mac: str) -> dict:
        return self.devices.setdefault(mac, {})

    def merge(self, other: "Observations") -> None:
        self.ip_mac += other.ip_mac
        self.ip_user += other.ip_user
        for mac, f in other.devices.items():
            cur = self.devices.setdefault(mac, {})
            for k, v in f.items():
                if k == "sources":
                    cur.setdefault("sources", set()).update(v)
                elif v not in (None, "", [], set()) and (not cur.get(k) or k in ("last_ip", "seen")):
                    cur[k] = v


CONTRIBUTORS: dict[str, tuple[str, object]] = {}   # name → (product, async fn(ch, s, since, now) -> Observations)
_STATE: dict[str, datetime] = {}


def register_contributor(name: str, product: str, fn) -> None:
    CONTRIBUTORS[name] = (product, fn)


def router_macs(pairs: list[tuple[str, str]]) -> set[str]:
    """MACs seen behind more than ROUTER_IPS addresses: routers / gateways / NAT devices, never host identities."""
    by: dict[str, set] = {}
    for ip, mac in pairs:
        by.setdefault(mac, set()).add(ip)
    return {m for m, ips in by.items() if len(ips) > ROUTER_IPS}


def _aware(t):
    return t if t is None or t.tzinfo else t.replace(tzinfo=timezone.utc)


async def run_identity(ch, s: AsyncSession, now: datetime | None = None, products: set[str] | None = None) -> dict:
    """One pass: every registered contributor (of the loaded products) for the time since its last pass, merged and
    stored. Bounded: at most 30 minutes of evidence per pass, at most 50 000 bindings."""
    now = now or datetime.now(timezone.utc)
    obs = Observations()
    stats: dict = {}
    for name, (product, fn) in CONTRIBUTORS.items():
        if products and product not in products:
            continue
        since = max(_STATE.get(name, now - timedelta(minutes=30)), now - timedelta(minutes=30))
        try:
            o = await fn(ch, s, since, now)
            obs.merge(o)
            stats[name] = {"ip_mac": len(o.ip_mac), "ip_user": len(o.ip_user), "devices": len(o.devices)}
            _STATE[name] = now
        except Exception as e:
            await s.rollback()
            log.exception("identity contributor %s failed", name)
            stats[name] = {"error": str(e)[:200]}
    stats["stored"] = await store(s, obs, now)
    return stats


async def _upsert_bindings(s: AsyncSession, model, key: str, rows: list[tuple[str, str, str, datetime]]) -> int:
    agg: dict[tuple, list] = {}
    for ip, val, src, seen in rows:
        k = (ip, val, src)
        a = agg.get(k)
        if a:
            a[0], a[1], a[2] = min(a[0], seen), max(a[1], seen), a[2] + 1
        else:
            agg[k] = [seen, seen, 1]
    keys = list(agg)[:50_000]
    col = getattr(model, key)
    n = 0
    for i in range(0, len(keys), 500):
        chunk = keys[i:i + 500]
        ips = {k[0] for k in chunk}
        have = {(r.ip, getattr(r, key), r.source): r for r in (await s.execute(select(model).where(model.ip.in_(ips), col.in_({k[1] for k in chunk})))).scalars()}
        for k in chunk:
            first, last, cnt = agg[k]
            r = have.get(k)
            if r:
                r.last_seen = max(_aware(r.last_seen), last)
                r.seen = (r.seen or 0) + cnt
            else:
                s.add(model(ip=k[0], **{key: k[1]}, source=k[2], first_seen=first, last_seen=last, seen=cnt))
            n += 1
        await s.flush()
    return n


async def store(s: AsyncSession, obs: Observations, now: datetime) -> dict:
    out = {"ip_mac": await _upsert_bindings(s, IpMacBinding, "mac", obs.ip_mac),
           "ip_user": await _upsert_bindings(s, IpUserBinding, "username", obs.ip_user)}
    # devices seen in bindings get a row even without other facts
    for ip, mac, src, seen in obs.ip_mac:
        d = obs.device(mac)
        if not d.get("seen") or seen >= d["seen"]:
            d["last_ip"], d["seen"] = ip, seen
        d.setdefault("sources", set()).add(src)
    macs = list(obs.devices)
    n = 0
    for i in range(0, len(macs), 500):
        chunk = macs[i:i + 500]
        have = {r.mac: r for r in (await s.execute(select(HostIdentity).where(HostIdentity.mac.in_(chunk)))).scalars()}
        for mac in chunk:
            f = obs.devices[mac]
            r = have.get(mac)
            if r is None:
                r = HostIdentity(mac=mac, first_seen=f.get("seen") or now)
                s.add(r)
            _apply(r, f, now)
            n += 1
        await s.flush()
    out["devices"] = n
    await s.execute(delete(IpMacBinding).where(IpMacBinding.last_seen < now - timedelta(days=RETENTION_DAYS)))
    await s.execute(delete(IpUserBinding).where(IpUserBinding.last_seen < now - timedelta(days=RETENTION_DAYS)))
    await s.commit()
    return out


def _apply(r: HostIdentity, f: dict, now: datetime) -> None:
    r.randomized = is_randomized(r.mac)
    if not r.vendor or f.get("vendor_source") == "fortigate":
        v = f.get("vendor") or vendor_of(r.mac)
        if v:
            r.vendor, r.vendor_source = v[:128], f.get("vendor_source") or ("ieee" if not f.get("vendor") else "fortigate")
    for k in ("os", "switch", "port", "ap", "ssid", "site"):
        if f.get(k):
            setattr(r, k, str(f[k])[: {"ssid": 64}.get(k, 128)])
    if f.get("vlan"):
        r.vlan = int(f["vlan"])
    if f.get("hostname"):
        r.hostname, r.hostname_source = str(f["hostname"])[:255], f.get("hostname_source", "")
    if f.get("user"):
        r.last_user = str(f["user"])[:128]
    if f.get("last_ip"):
        r.last_ip = f["last_ip"]
    facts = {"inventory": f.get("inventory"), "fortigate_devtype": f.get("fortigate_devtype"), "os": f.get("os") or r.os, "vendor": r.vendor,
             "wireless": f.get("wireless") or bool(r.ssid), "randomized": r.randomized, "server_ports": f.get("server_ports") or ()}
    typ, conf, ev = classify(facts)
    if typ and CONF_RANK.get(conf, 0) >= CONF_RANK.get(r.device_type_confidence or "", 0):
        r.device_type, r.device_type_confidence, r.device_evidence = typ, conf, ev
    r.sources = sorted(set(r.sources or []) | set(f.get("sources") or ()))
    seen = f.get("seen") or now
    r.last_seen = max(_aware(r.last_seen) or seen, seen)


# ------------------------------------------------------------------ read API (both products)
def _valid(ips) -> list[str]:
    out = []
    for ip in ips:
        try:
            out.append(str(ipaddress.ip_address(ip)))
        except (ValueError, TypeError):
            continue
    return sorted(set(out))[:2000]


async def identities(s: AsyncSession, ips, *, at: datetime | None = None, sensitive: bool = True) -> dict[str, dict]:
    """ip → {mac, vendor, randomized, device_type, confidence, evidence, os, hostname, user, switch, port, vlan, ap, ssid,
    site, sources, mac_source, last_seen}. `at`: the binding valid at that time (else the latest)."""
    ips = _valid(ips)
    if not ips:
        return {}
    q = select(IpMacBinding).where(IpMacBinding.ip.in_(ips))
    if at:
        q = q.where(IpMacBinding.first_seen <= at + timedelta(minutes=30), IpMacBinding.last_seen >= at - timedelta(hours=2))
    best: dict[str, IpMacBinding] = {}
    for b in (await s.execute(q)).scalars():
        cur = best.get(b.ip)
        if cur is None or _aware(b.last_seen) > _aware(cur.last_seen):
            best[b.ip] = b
    users: dict[str, IpUserBinding] = {}
    uq = select(IpUserBinding).where(IpUserBinding.ip.in_(ips))
    if at:
        uq = uq.where(IpUserBinding.first_seen <= at + timedelta(minutes=30), IpUserBinding.last_seen >= at - timedelta(hours=8))
    for b in (await s.execute(uq)).scalars():
        cur = users.get(b.ip)
        if cur is None or _aware(b.last_seen) > _aware(cur.last_seen):
            users[b.ip] = b
    hosts = {h.mac: h for h in (await s.execute(select(HostIdentity).where(HostIdentity.mac.in_({b.mac for b in best.values()} or {""})))).scalars()}
    out: dict[str, dict] = {}
    for ip in ips:
        b, u = best.get(ip), users.get(ip)
        h = hosts.get(b.mac) if b else None
        if not (b or u):
            continue
        d = {"mac": b.mac if b else "", "mac_source": b.source if b else "", "vendor": h.vendor if h else (vendor_of(b.mac) if b else ""),
             "randomized": h.randomized if h else False, "device_type": h.device_type if h else "", "confidence": h.device_type_confidence if h else "",
             "evidence": h.device_evidence if h else [], "os": h.os if h else "", "hostname": h.hostname if h else "", "switch": h.switch if h else "",
             "port": h.port if h else "", "vlan": h.vlan if h else None, "ap": h.ap if h else "", "ssid": h.ssid if h else "", "site": h.site if h else "",
             "sources": h.sources if h else [], "user": u.username if u else (h.last_user if h else ""), "user_source": u.source if u else "",
             "last_seen": (_aware(b.last_seen).isoformat() if b else None)}
        if not sensitive:
            d.update(mac="", user="", hostname="")
        out[ip] = d
    return out


async def timeline(s: AsyncSession, ip: str, days: int = 7) -> dict:
    """Every MAC and user an address was bound to over the last `days` (who had this IP when)."""
    ip = _valid([ip])[0] if _valid([ip]) else ""
    if not ip:
        return {"ip": ip, "macs": [], "users": []}
    since = datetime.now(timezone.utc) - timedelta(days=days)
    macs = (await s.execute(select(IpMacBinding).where(IpMacBinding.ip == ip, IpMacBinding.last_seen >= since).order_by(IpMacBinding.last_seen.desc()).limit(50))).scalars().all()
    users = (await s.execute(select(IpUserBinding).where(IpUserBinding.ip == ip, IpUserBinding.last_seen >= since).order_by(IpUserBinding.last_seen.desc()).limit(50))).scalars().all()
    hosts = {h.mac: h for h in (await s.execute(select(HostIdentity).where(HostIdentity.mac.in_({m.mac for m in macs} or {""})))).scalars()}
    iso = lambda t: _aware(t).isoformat() if t else None   # noqa: E731
    return {"ip": ip,
            "macs": [{"mac": m.mac, "source": m.source, "first_seen": iso(m.first_seen), "last_seen": iso(m.last_seen), "seen": m.seen,
                      "vendor": hosts[m.mac].vendor if m.mac in hosts else vendor_of(m.mac),
                      "device_type": hosts[m.mac].device_type if m.mac in hosts else ""} for m in macs],
            "users": [{"user": u.username, "source": u.source, "first_seen": iso(u.first_seen), "last_seen": iso(u.last_seen), "seen": u.seen} for u in users]}
