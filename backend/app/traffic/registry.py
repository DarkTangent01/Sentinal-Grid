"""Classification registry: protocol and port signatures, ASN providers and domain signatures.

The rows live in PostgreSQL (traffic_signatures) so administrators add, edit or disable signatures without a code
change. BUILTIN below is only the first seed: ensure_defaults() inserts a built-in row once (by builtin_key) and never
overwrites a row an administrator has edited or deleted.

Evidence levels (what a classification may claim):
  port-based  the protocol / port matches a registry entry; nothing about the payload or the application is known.
              Entries marked ambiguous (UDP/443, 8080, real-time media ranges) are labelled "(possible)".
  probable    the server address belongs to a provider's network (ASN); the application inside is not known.
  high        the server address was resolved from a DNS name matching a domain signature, and the address is not
              shared by many unrelated names (CDN).
  confirmed   firewall application control identified the session, or the sampled packet bytes prove the protocol
              (QUIC long header, TLS record, HTTP/1.x line, SSH banner).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import TrafficSignature

# IP protocol numbers (IANA) — level 1 identification
PROTOCOLS = {0: "HOPOPT", 1: "ICMP", 2: "IGMP", 4: "IP-in-IP", 6: "TCP", 17: "UDP", 41: "IPv6-in-IPv4", 47: "GRE", 50: "ESP", 51: "AH",
             58: "ICMPv6", 88: "EIGRP", 89: "OSPF", 103: "PIM", 112: "VRRP", 115: "L2TP", 132: "SCTP", 137: "MPLS-in-IP"}
CONFIDENCE = ("confirmed", "high", "probable", "port-based", "unknown")
CATEGORIES = ("web", "email", "dns", "remote-access", "file-transfer", "database", "messaging", "real-time", "vpn", "routing",
              "network-services", "monitoring", "discovery", "iot", "cloud", "saas", "cdn", "streaming", "social", "update", "other")
TCP, UDP = 6, 17

# (key, proto, port_from, port_to, app, category, encrypted, ambiguous, description)
_P = [
    ("tcp-80", TCP, 80, 80, "HTTP", "web", False, False, "Plain-text web"),
    ("tcp-443", TCP, 443, 443, "HTTPS", "web", True, False, "TLS on 443: HTTP/1.1 or HTTP/2 (not distinguishable from flow records)"),
    ("udp-443", UDP, 443, 443, "QUIC", "web", True, True, "UDP/443: possible QUIC / HTTP/3; confirmed only when a sampled packet shows a QUIC header"),
    ("tcp-8080", TCP, 8080, 8080, "HTTP Alternate", "web", False, True, "Often HTTP proxies or application servers"),
    ("tcp-8443", TCP, 8443, 8443, "HTTPS Alternate", "web", True, True, ""),
    ("tcp-8000", TCP, 8000, 8000, "HTTP Alternate", "web", False, True, ""),
    ("udp-53", UDP, 53, 53, "DNS", "dns", False, False, ""),
    ("tcp-53", TCP, 53, 53, "DNS", "dns", False, False, "DNS over TCP (zone transfers, large answers)"),
    ("tcp-853", TCP, 853, 853, "DNS over TLS", "dns", True, False, ""),
    ("udp-853", UDP, 853, 853, "DNS over QUIC", "dns", True, False, ""),
    ("tcp-22", TCP, 22, 22, "SSH", "remote-access", True, False, ""),
    ("tcp-23", TCP, 23, 23, "Telnet", "remote-access", False, False, "Unencrypted remote terminal"),
    ("tcp-3389", TCP, 3389, 3389, "RDP", "remote-access", True, False, ""),
    ("udp-3389", UDP, 3389, 3389, "RDP", "remote-access", True, False, "RDP UDP transport"),
    ("tcp-5900", TCP, 5900, 5900, "VNC", "remote-access", None, False, "Encryption depends on the VNC server"),
    ("tcp-5985", TCP, 5985, 5985, "WinRM (HTTP)", "remote-access", False, False, ""),
    ("tcp-5986", TCP, 5986, 5986, "WinRM (HTTPS)", "remote-access", True, False, ""),
    ("tcp-25", TCP, 25, 25, "SMTP", "email", None, False, "STARTTLS may or may not be used"),
    ("tcp-465", TCP, 465, 465, "SMTPS", "email", True, False, ""),
    ("tcp-587", TCP, 587, 587, "SMTP Submission", "email", None, False, "Usually STARTTLS"),
    ("tcp-110", TCP, 110, 110, "POP3", "email", False, False, ""),
    ("tcp-995", TCP, 995, 995, "POP3S", "email", True, False, ""),
    ("tcp-143", TCP, 143, 143, "IMAP", "email", False, False, ""),
    ("tcp-993", TCP, 993, 993, "IMAPS", "email", True, False, ""),
    ("tcp-20", TCP, 20, 20, "FTP Data", "file-transfer", False, False, ""),
    ("tcp-21", TCP, 21, 21, "FTP", "file-transfer", False, False, "Unencrypted file transfer control channel"),
    ("tcp-990", TCP, 990, 990, "FTPS", "file-transfer", True, False, ""),
    ("udp-69", UDP, 69, 69, "TFTP", "file-transfer", False, False, ""),
    ("tcp-445", TCP, 445, 445, "SMB", "file-transfer", None, False, "SMB 3 can encrypt; the dialect (e.g. SMBv1) is not visible in flow records"),
    ("tcp-139", TCP, 139, 139, "NetBIOS Session", "file-transfer", False, False, ""),
    ("udp-137", UDP, 137, 137, "NetBIOS Name Service", "discovery", False, False, ""),
    ("udp-138", UDP, 138, 138, "NetBIOS Datagram", "discovery", False, False, ""),
    ("tcp-2049", TCP, 2049, 2049, "NFS", "file-transfer", None, False, ""),
    ("tcp-3260", TCP, 3260, 3260, "iSCSI", "file-transfer", None, False, ""),
    ("udp-161", UDP, 161, 161, "SNMP", "monitoring", None, False, "SNMPv3 can encrypt; v1 / v2c cannot (version not visible)"),
    ("udp-162", UDP, 162, 162, "SNMP Trap", "monitoring", None, False, ""),
    ("udp-514", UDP, 514, 514, "Syslog", "monitoring", False, False, ""),
    ("tcp-514", TCP, 514, 514, "Syslog (TCP)", "monitoring", False, False, ""),
    ("tcp-6514", TCP, 6514, 6514, "Syslog over TLS", "monitoring", True, False, ""),
    ("udp-2055", UDP, 2055, 2055, "NetFlow", "monitoring", False, False, ""),
    ("udp-4739", UDP, 4739, 4739, "IPFIX", "monitoring", False, False, ""),
    ("udp-6343", UDP, 6343, 6343, "sFlow", "monitoring", False, False, ""),
    ("tcp-830", TCP, 830, 830, "NETCONF", "monitoring", True, False, ""),
    ("tcp-49", TCP, 49, 49, "TACACS+", "network-services", None, False, "Body obfuscated with a shared key, not TLS"),
    ("udp-1812", UDP, 1812, 1812, "RADIUS", "network-services", None, False, ""),
    ("udp-1813", UDP, 1813, 1813, "RADIUS Accounting", "network-services", None, False, ""),
    ("tcp-389", TCP, 389, 389, "LDAP", "network-services", None, False, "StartTLS may or may not be used"),
    ("tcp-636", TCP, 636, 636, "LDAPS", "network-services", True, False, ""),
    ("tcp-88", TCP, 88, 88, "Kerberos", "network-services", None, False, ""),
    ("udp-88", UDP, 88, 88, "Kerberos", "network-services", None, False, ""),
    ("udp-123", UDP, 123, 123, "NTP", "network-services", False, False, ""),
    ("udp-67", UDP, 67, 68, "DHCP", "network-services", False, False, ""),
    ("udp-500", UDP, 500, 500, "IPsec IKE", "vpn", True, False, ""),
    ("udp-4500", UDP, 4500, 4500, "IPsec NAT-T", "vpn", True, False, ""),
    ("udp-1194", UDP, 1194, 1194, "OpenVPN", "vpn", True, False, ""),
    ("udp-51820", UDP, 51820, 51820, "WireGuard", "vpn", True, True, ""),
    ("tcp-179", TCP, 179, 179, "BGP", "routing", False, False, ""),
    ("udp-3478", UDP, 3478, 3478, "STUN", "real-time", None, False, "NAT traversal for voice / video"),
    ("udp-3479", UDP, 3479, 3481, "Microsoft Teams media", "real-time", True, True, "Port range used by Teams media; port evidence only"),
    ("tcp-5349", TCP, 5349, 5349, "TURN over TLS", "real-time", True, False, ""),
    ("udp-5349", UDP, 5349, 5349, "TURN over DTLS", "real-time", True, False, ""),
    ("udp-8801", UDP, 8801, 8810, "Zoom media", "real-time", True, True, "Port range used by Zoom media; port evidence only"),
    ("udp-19302", UDP, 19302, 19309, "Google STUN / Meet media", "real-time", True, True, "Port range used by Google STUN; port evidence only"),
    ("udp-5060", UDP, 5060, 5060, "SIP", "real-time", False, False, ""),
    ("tcp-5060", TCP, 5060, 5060, "SIP", "real-time", False, False, ""),
    ("tcp-5061", TCP, 5061, 5061, "SIP over TLS", "real-time", True, False, ""),
    ("tcp-5222", TCP, 5222, 5222, "XMPP", "messaging", None, False, ""),
    ("tcp-5223", TCP, 5223, 5223, "XMPP over TLS", "messaging", True, False, "Also Apple push notifications"),
    ("tcp-1883", TCP, 1883, 1883, "MQTT", "iot", False, False, "Unencrypted MQTT"),
    ("tcp-8883", TCP, 8883, 8883, "MQTT over TLS", "iot", True, False, ""),
    ("udp-5683", UDP, 5683, 5683, "CoAP", "iot", False, False, ""),
    ("tcp-7680", TCP, 7680, 7680, "Microsoft Delivery Optimization", "update", None, False, "Peer-to-peer Windows update sharing"),
    ("udp-1900", UDP, 1900, 1900, "SSDP", "discovery", False, False, ""),
    ("udp-5353", UDP, 5353, 5353, "mDNS", "discovery", False, False, ""),
    ("udp-5355", UDP, 5355, 5355, "LLMNR", "discovery", False, False, ""),
    ("udp-3702", UDP, 3702, 3702, "WS-Discovery", "discovery", False, False, ""),
    ("tcp-3306", TCP, 3306, 3306, "MySQL", "database", None, False, "TLS optional"),
    ("tcp-5432", TCP, 5432, 5432, "PostgreSQL", "database", None, False, "TLS optional"),
    ("tcp-1433", TCP, 1433, 1433, "Microsoft SQL Server", "database", None, False, ""),
    ("tcp-1521", TCP, 1521, 1521, "Oracle", "database", None, False, ""),
    ("tcp-6379", TCP, 6379, 6379, "Redis", "database", False, False, "No TLS by default"),
    ("tcp-9200", TCP, 9200, 9200, "Elasticsearch", "database", None, True, ""),
    ("tcp-27017", TCP, 27017, 27017, "MongoDB", "database", None, False, ""),
    ("tcp-9092", TCP, 9092, 9092, "Kafka", "database", None, True, ""),
    ("tcp-9100", TCP, 9100, 9100, "Printing (JetDirect)", "other", False, True, ""),
    ("tcp-631", TCP, 631, 631, "IPP", "other", None, False, ""),
    # protocol-only signatures (no ports)
    ("ip-50", 50, None, None, "IPsec ESP", "vpn", True, False, ""),
    ("ip-51", 51, None, None, "IPsec AH", "vpn", False, False, "Authentication only, no encryption"),
    ("ip-47", 47, None, None, "GRE", "vpn", False, False, "Tunnel; the inner traffic is not visible"),
    ("ip-89", 89, None, None, "OSPF", "routing", False, False, ""),
    ("ip-88", 88, None, None, "EIGRP", "routing", False, False, ""),
    ("ip-112", 112, None, None, "VRRP", "routing", False, False, ""),
    ("ip-2", 2, None, None, "IGMP", "discovery", False, False, ""),
    ("ip-103", 103, None, None, "PIM", "routing", False, False, ""),
    ("ip-1", 1, None, None, "ICMP", "network-services", False, False, ""),
    ("ip-58", 58, None, None, "ICMPv6", "network-services", False, False, ""),
    ("ip-132", 132, None, None, "SCTP", "other", None, False, ""),
]
# ASN → provider (probable: "this server is in the provider's network", never a specific product)
_A = [
    ("asn-8075", "8075", "Microsoft", "cloud"), ("asn-8068", "8068", "Microsoft", "cloud"), ("asn-15169", "15169", "Google", "cloud"),
    ("asn-396982", "396982", "Google Cloud", "cloud"), ("asn-36040", "36040", "YouTube (Google)", "streaming"),
    ("asn-13335", "13335", "Cloudflare", "cdn"), ("asn-16509", "16509", "Amazon AWS", "cloud"), ("asn-14618", "14618", "Amazon AWS", "cloud"),
    ("asn-20940", "20940", "Akamai", "cdn"), ("asn-16625", "16625", "Akamai", "cdn"), ("asn-54113", "54113", "Fastly", "cdn"),
    ("asn-32934", "32934", "Meta", "social"), ("asn-30103", "30103", "Zoom", "real-time"), ("asn-2906", "2906", "Netflix", "streaming"),
    ("asn-714", "714", "Apple", "cloud"), ("asn-6185", "6185", "Apple", "cloud"), ("asn-19679", "19679", "Dropbox", "saas"),
    ("asn-13445", "13445", "Cisco Webex", "real-time"), ("asn-46489", "46489", "Twitch", "streaming"), ("asn-8987", "8987", "Amazon AWS", "cloud"),
]
# domain suffix → application (high when the destination IP was resolved from such a name and is not a shared CDN address)
_D = [
    ("dom-teams", "teams.microsoft.com", "Microsoft Teams", "real-time"), ("dom-teams-live", "teams.live.com", "Microsoft Teams", "real-time"),
    ("dom-skype", "skype.com", "Microsoft Teams", "real-time"),
    ("dom-o365", "office365.com", "Microsoft 365", "saas"), ("dom-office", "office.com", "Microsoft 365", "saas"),
    ("dom-outlook", "outlook.office.com", "Microsoft 365", "saas"), ("dom-sharepoint", "sharepoint.com", "Microsoft 365", "saas"),
    ("dom-msol", "microsoftonline.com", "Microsoft 365", "saas"), ("dom-onedrive", "onedrive.live.com", "Microsoft 365", "saas"),
    ("dom-winupd", "windowsupdate.com", "Windows Update", "update"), ("dom-msdelivery", "delivery.mp.microsoft.com", "Windows Update", "update"),
    ("dom-meet", "meet.google.com", "Google Meet", "real-time"), ("dom-gdocs", "docs.google.com", "Google Workspace", "saas"),
    ("dom-gdrive", "drive.google.com", "Google Workspace", "saas"), ("dom-gmail", "mail.google.com", "Google Workspace", "saas"),
    ("dom-youtube", "youtube.com", "YouTube", "streaming"), ("dom-gvideo", "googlevideo.com", "YouTube", "streaming"),
    ("dom-ytimg", "ytimg.com", "YouTube", "streaming"), ("dom-zoom", "zoom.us", "Zoom", "real-time"), ("dom-zoomcom", "zoom.com", "Zoom", "real-time"),
    ("dom-webex", "webex.com", "Cisco Webex", "real-time"), ("dom-slack", "slack.com", "Slack", "messaging"),
    ("dom-whatsapp", "whatsapp.net", "WhatsApp", "messaging"), ("dom-fb", "facebook.com", "Meta", "social"), ("dom-fbcdn", "fbcdn.net", "Meta", "social"),
    ("dom-insta", "instagram.com", "Meta", "social"), ("dom-netflix", "nflxvideo.net", "Netflix", "streaming"),
    ("dom-dropbox", "dropbox.com", "Dropbox", "saas"), ("dom-aws", "amazonaws.com", "Amazon AWS", "cloud"),
    ("dom-cloudfront", "cloudfront.net", "Amazon CloudFront", "cdn"), ("dom-akamai", "akamaized.net", "Akamai", "cdn"),
    ("dom-azure", "azure.com", "Microsoft Azure", "cloud"), ("dom-azureedge", "azureedge.net", "Microsoft Azure CDN", "cdn"),
    ("dom-apple", "icloud.com", "Apple iCloud", "cloud"), ("dom-github", "github.com", "GitHub", "saas"),
]
MAX_RANGE = 2048            # a port signature expands to at most this many ports in a ClickHouse lookup


def builtin_rows() -> list[dict]:
    rows = [dict(builtin_key=k, kind="port", proto=pr, port_from=a, port_to=b, app=app, category=cat, encrypted=enc, ambiguous=amb,
                 description=desc) for k, pr, a, b, app, cat, enc, amb, desc in _P]
    rows += [dict(builtin_key=k, kind="asn", match=m, app=app, category=cat, encrypted=None, ambiguous=False,
                  description="Provider network (ASN): the application inside is not identified") for k, m, app, cat in _A]
    rows += [dict(builtin_key=k, kind="domain", match=m, app=app, category=cat, encrypted=None, ambiguous=False,
                  description="Domain signature (needs DNS logs)") for k, m, app, cat in _D]
    return rows


async def ensure_defaults(s: AsyncSession) -> int:
    """Insert built-in signatures that were never seeded (one marker row per key records deletions too)."""
    from .settings import load_settings, save_settings
    st = await load_settings(s)
    seeded = set(st.get("_seeded_signatures") or [])
    have = {r for (r,) in (await s.execute(select(TrafficSignature.builtin_key).where(TrafficSignature.builtin_key != ""))).all()}
    n = 0
    for row in builtin_rows():
        k = row["builtin_key"]
        if k in have or k in seeded:
            continue
        s.add(TrafficSignature(**row, updated_by="built-in"))
        n += 1
    st["_seeded_signatures"] = sorted(seeded | {r["builtin_key"] for r in builtin_rows()})
    await save_settings(s, st, "built-in")
    from .networks import ensure_default_policies
    n += await ensure_default_policies(s)
    await s.commit()
    return n


@dataclass
class Registry:
    port_keys: list[int] = field(default_factory=list)          # proto * 65536 + port, proto-only: proto * 65536 + 0 with flag
    port_labels: list[str] = field(default_factory=list)
    port_cats: list[str] = field(default_factory=list)
    port_enc: list[int] = field(default_factory=list)          # 1 encrypted, 0 not, 2 unknown / depends
    proto_keys: list[int] = field(default_factory=list)        # protocol-only signatures
    proto_labels: list[str] = field(default_factory=list)
    proto_cats: list[str] = field(default_factory=list)
    asn: dict[int, tuple[str, str]] = field(default_factory=dict)
    domains: list[tuple[str, str, str]] = field(default_factory=list)   # (suffix, app, category), longest first
    by_label: dict[str, dict] = field(default_factory=dict)

    def port_app(self, proto: int, sport: int, dport: int) -> tuple[str, str]:
        """Python twin of the SQL lookup (used for single rows and tests)."""
        idx = {k: i for i, k in enumerate(self.port_keys)}
        kd, ks = proto * 65536 + dport, proto * 65536 + sport
        cand = [k for k in (kd, ks) if k in idx and k % 65536]
        if len(cand) == 2:
            cand = [kd if dport <= sport else ks]
        if cand:
            i = idx[cand[0]]
            return self.port_labels[i], self.port_cats[i]
        if proto in self.proto_keys:
            i = self.proto_keys.index(proto)
            return self.proto_labels[i], self.proto_cats[i]
        return "Unknown", "other"

    def domain_app(self, name: str) -> tuple[str, str] | None:
        n = (name or "").lower().rstrip(".")
        for suf, app, cat in self.domains:
            if n == suf or n.endswith("." + suf):
                return app, cat
        return None


_CACHE: dict = {"t": 0.0, "reg": None}


def label_of(app: str, ambiguous: bool) -> str:
    return f"{app} (possible)" if ambiguous else app


async def load(s: AsyncSession, max_age: float = 30.0) -> Registry:
    if _CACHE["reg"] is not None and time.monotonic() - _CACHE["t"] < max_age:
        return _CACHE["reg"]
    reg = Registry()
    rows = (await s.execute(select(TrafficSignature).where(TrafficSignature.enabled.is_(True)).order_by(TrafficSignature.id))).scalars().all()
    seen: set[int] = set()
    for r in rows:
        enc = 2 if r.encrypted is None else int(bool(r.encrypted))
        if r.kind == "port" and r.proto is not None:
            label = label_of(r.app, r.ambiguous)
            reg.by_label[label] = {"app": r.app, "category": r.category, "encrypted": r.encrypted, "ambiguous": r.ambiguous,
                                   "description": r.description}
            if r.port_from is None:
                if r.proto not in reg.proto_keys:
                    reg.proto_keys.append(r.proto)
                    reg.proto_labels.append(label)
                    reg.proto_cats.append(r.category)
                continue
            lo, hi = sorted((max(0, r.port_from), min(65535, r.port_to if r.port_to is not None else r.port_from)))
            for port in range(lo, min(hi, lo + MAX_RANGE - 1) + 1):
                k = r.proto * 65536 + port
                if k in seen:
                    continue                 # first (lowest id) signature wins for a port
                seen.add(k)
                reg.port_keys.append(k)
                reg.port_labels.append(label)
                reg.port_cats.append(r.category)
                reg.port_enc.append(enc)
        elif r.kind == "asn" and r.match.strip().isdigit():
            reg.asn.setdefault(int(r.match.strip()), (r.app, r.category))
        elif r.kind == "domain" and r.match.strip():
            reg.domains.append((r.match.strip().lower().lstrip("*.").rstrip("."), r.app, r.category))
    reg.domains.sort(key=lambda x: -len(x[0]))
    _CACHE.update(t=time.monotonic(), reg=reg)
    return reg


def invalidate() -> None:
    _CACHE.update(t=0.0, reg=None)
