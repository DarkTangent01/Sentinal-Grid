"""DEMO MODE: synthetic, sanitized FortiGate-format logs.

All demo events are tagged source='demo', demo firewalls are flagged is_demo=True, and the UI shows a
persistent DEMO banner. IPs use private and RFC 5737 documentation ranges; domains use example/.test names.
Demo data is never presented as live telemetry.
Usage: python -m app.demo --backfill-hours 24   (one-off history)   |  started automatically by the worker when DEMO_MODE=true
"""
import argparse
import asyncio
import logging
import random
import string
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from .config import get_settings
from .db.ch import get_ch
from .db.models import Firewall
from .db.pg import session_factory
from .ingest.pipeline import DeviceRegistry, EventSink
from .logging_setup import setup_logging

log = logging.getLogger("demo")

DEMO_FIREWALLS = [
    {"name": "DEMO-HQ-FW01", "serial": "FGDEMO0000000001", "site": "HQ (demo)", "host": "192.0.2.1"},
    {"name": "DEMO-BRANCH-FW02", "serial": "FGDEMO0000000002", "site": "Branch-North (demo)", "host": "192.0.2.2"},
    {"name": "DEMO-WH-FW03", "serial": "FGDEMO0000000003", "site": "Warehouse-East (demo)", "host": "192.0.2.3"},
]
INTERNAL = [f"10.10.{n}.{h}" for n in (10, 20, 30) for h in range(10, 60)]
EXTERNAL = [f"{p}.{h}" for p in ("198.51.100", "203.0.113") for h in range(1, 120)]
DNS_SERVERS = ["10.10.0.53", "10.10.0.54"]
DOMAINS = ["www.example.com", "mail.example.com", "cdn.example.net", "api.example.org", "updates.example.com",
           "portal.corp.test", "files.example.net", "video.example.org", "news.example.com", "login.example.org",
           "intranet.corp.test", "telemetry.example.net"]
APPS = [("HTTPS.BROWSER", 40568, "Web.Client", "HTTPS", 443, 6), ("DNS", 16195, "Network.Service", "DNS", 53, 17),
        ("SSL", 15895, "Network.Service", "HTTPS", 443, 6), ("Microsoft.Office.365", 33182, "Collaboration", "HTTPS", 443, 6),
        ("SSH", 16060, "Remote.Access", "SSH", 22, 6), ("NTP", 16270, "Network.Service", "NTP", 123, 17),
        ("RDP", 15895, "Remote.Access", "RDP", 3389, 6), ("SMB", 16150, "Network.Service", "SMB", 445, 6)]
COUNTRIES = ["United States", "Netherlands", "Germany", "Singapore", "Ireland", "Japan", "United Kingdom", "India", "France"]
OSES = ["Windows", "macOS", "Linux", "iOS", "Android"]
VPN_USERS = ["rahul", "priya", "amit", "neha", "vikram", "sara"]
VPN_SOURCES = {"India": "198.51.100.10", "Netherlands": "198.51.100.20", "Singapore": "198.51.100.30", "United States": "198.51.100.40"}
DEMO_IOC = "203.0.113.66"  # synthetic "C2" indicator, added to the Manual IOC list in demo mode only
CATEGORIES = ["Information Technology", "Business", "News and Media", "Search Engines and Portals", "Streaming Media and Download",
              "Malicious Websites", "Phishing", "Social Networking"]


def kv(d: dict) -> str:
    return " ".join(f'{k}="{v}"' if isinstance(v, str) else f"{k}={v}" for k, v in d.items())


def header(fw, ts: datetime, logid: str, typ: str, sub: str, level: str = "notice") -> dict:
    return {"date": ts.strftime("%Y-%m-%d"), "time": ts.strftime("%H:%M:%S"), "devname": fw["name"], "devid": fw["serial"],
            "eventtime": int(ts.timestamp() * 1e9) + random.randint(0, 999_999), "tz": "+0000", "logid": logid,
            "type": typ, "subtype": sub, "level": level, "vd": "root"}


class DemoGenerator:
    def __init__(self, seed: int | None = None):
        self.r = random.Random(seed)
        self.session = self.r.randint(10_000, 99_999)

    def traffic(self, fw, ts, src=None, dst=None, dport=None, action=None):
        self.session += 1
        app, appid, appcat, svc, port, proto = self.r.choice(APPS)
        action = action or self.r.choices(["close", "accept", "deny", "timeout", "client-rst"], [55, 15, 18, 7, 5])[0]
        sent = 0 if action == "deny" else int(self.r.lognormvariate(8, 1.6))
        d = header(fw, ts, "0000000013" if action != "deny" else "0000000013", "traffic", "forward")
        srcip = src or self.r.choice(INTERNAL)
        dstip = dst or self.r.choice(EXTERNAL)
        last = int(srcip.split(".")[-1])
        d.update({"srccountry": "Reserved", "dstcountry": COUNTRIES[int(dstip.split(".")[-1]) % len(COUNTRIES)],
                  "srcmac": f"00:16:3e:00:{int(srcip.split('.')[2]):02x}:{last:02x}", "srcname": f"host-{srcip.split('.')[2]}-{last}",
                  "osname": OSES[last % len(OSES)]})
        d.update({"srcip": srcip, "srcport": self.r.randint(1024, 65535), "srcintf": "port1",
                  "srcintfrole": "lan", "dstip": dstip, "dstport": dport or port, "dstintf": "wan1",
                  "dstintfrole": "wan", "sessionid": self.session, "proto": proto, "action": action,
                  "policyid": 0 if action == "deny" else self.r.choice([1, 2, 5, 12]),
                  "policyname": "Implicit Deny" if action == "deny" else self.r.choice(["LAN-to-WAN", "Guest-Web", "Branch-VPN", "Servers-Out"]),
                  "service": svc if dport is None else f"tcp/{dport}", "trandisp": "snat", "transip": "192.0.2.100",
                  "transport": self.r.randint(1024, 65535), "duration": self.r.randint(0, 600),
                  "sentbyte": sent, "rcvdbyte": 0 if action == "deny" else int(sent * self.r.uniform(0.5, 12)),
                  "sentpkt": max(1, sent // 900), "rcvdpkt": max(0, sent // 600)})
        if dport is None:
            d.update({"appid": appid, "app": app, "appcat": appcat})
        return kv(d)

    def dns(self, fw, ts, src=None, qname=None, rcode=None):
        qname = qname or self.r.choice(DOMAINS)
        d = header(fw, ts, "1501054802", "utm", "dns", "information")
        blocked = self.r.random() < 0.03
        d.update({"eventtype": "dns-response", "srcip": src or self.r.choice(INTERNAL), "srcport": self.r.randint(1024, 65535),
                  "srcintf": "port1", "dstip": self.r.choice(DNS_SERVERS), "dstport": 53, "dstintf": "root", "proto": 17,
                  "policyid": 1, "sessionid": self.r.randint(10**6, 10**7), "profile": "default",
                  "xid": self.r.randint(1, 65535), "qname": qname, "qtype": self.r.choices(["A", "AAAA", "HTTPS", "PTR", "TXT", "MX"], [60, 20, 8, 5, 4, 3])[0],
                  "qtypeval": 1, "qclass": "IN"})
        if rcode == "NXDOMAIN":
            d.update({"msg": "Domain was not found (NXDOMAIN)", "action": "pass", "rcode": "NXDOMAIN"})
        elif blocked:
            d.update({"action": "block", "cat": 26, "catdesc": "Malicious Websites", "msg": "Domain is blocked due to its category"})
        else:
            d.update({"ipaddr": self.r.choice(EXTERNAL), "msg": "Domain is monitored", "action": "pass", "cat": 52,
                      "catdesc": "Information Technology"})
        return kv(d)

    def web(self, fw, ts):
        host = self.r.choice(DOMAINS)
        blocked = self.r.random() < 0.12
        d = header(fw, ts, "0316013056" if blocked else "0317013312", "utm", "webfilter", "warning" if blocked else "notice")
        cat = "Phishing" if blocked and self.r.random() < 0.4 else self.r.choice(CATEGORIES)
        d.update({"eventtype": "ftgd_blk" if blocked else "ftgd_allow", "policyid": 1, "sessionid": self.r.randint(10**6, 10**7),
                  "srcip": self.r.choice(INTERNAL), "srcport": self.r.randint(1024, 65535), "srcintf": "port1",
                  "dstip": self.r.choice(EXTERNAL), "dstport": 443, "dstintf": "wan1", "proto": 6, "service": "HTTPS",
                  "hostname": host, "profile": "default", "action": "blocked" if blocked else "passthrough",
                  "reqtype": "direct", "url": self.r.choice(["/", "/index.html", "/login", "/api/v1/items", "/static/app.js"]),
                  "sentbyte": self.r.randint(200, 4000), "rcvdbyte": 0 if blocked else self.r.randint(500, 900_000),
                  "direction": "outgoing", "msg": "URL belongs to a denied category in policy" if blocked else "URL belongs to an allowed category in policy",
                  "method": "domain", "cat": 1, "catdesc": cat})
        if self.r.random() < 0.3:  # full URL as some logs carry it (e.g. flow inspection with full-URL logging)
            d["url"] = f"https://{host}{d['url']}"
        return kv(d)

    def ips(self, fw, ts):
        sev = self.r.choice(["critical", "high", "medium", "low", "info"])
        d = header(fw, ts, "0419016384", "utm", "ips", "alert")
        d.update({"eventtype": "signature", "severity": sev, "srcip": self.r.choice(EXTERNAL), "dstip": self.r.choice(INTERNAL),
                  "srcport": self.r.randint(1024, 65535), "dstport": self.r.choice([80, 443, 445, 3389]), "proto": 6,
                  "srcintf": "wan1", "dstintf": "port1", "policyid": 5, "sessionid": self.r.randint(10**6, 10**7),
                  "action": self.r.choice(["dropped", "detected", "reset"]),
                  "attack": self.r.choice(["Demo.Signature.SQL.Injection", "Demo.Signature.Path.Traversal", "Demo.Signature.Brute.Force"]),
                  "attackid": self.r.randint(10000, 99999), "msg": "demo signature match"})
        return kv(d)

    def admin_login(self, fw, ts, failed=True):
        d = header(fw, ts, "0100032002" if failed else "0100032001", "event", "system", "alert" if failed else "information")
        d.update({"logdesc": "Admin login failed" if failed else "Admin login successful", "sn": "0", "user": "admin",
                  "ui": "https(10.10.30.99)", "method": "https", "srcip": "10.10.30.99", "dstip": fw["host"],
                  "action": "login", "status": "failed" if failed else "success", "reason": "passwd_invalid" if failed else "none",
                  "msg": f"Administrator admin login {'failed' if failed else 'successful'} from https(10.10.30.99)"})
        return kv(d)

    def config_change(self, fw, ts):
        d = header(fw, ts, "0100044547", "event", "system", "information")
        d.update({"logdesc": "Object attribute configured", "user": "netops", "ui": "GUI(10.10.30.10)", "action": "Edit",
                  "cfgtid": self.r.randint(10**6, 10**7), "cfgpath": "firewall.policy", "cfgobj": "12",
                  "cfgattr": "status[enable->disable]", "msg": "Edit firewall.policy 12"})
        return kv(d)

    def admin_account_change(self, fw, ts):
        d = header(fw, ts, "0100044547", "event", "system", "information")
        d.update({"logdesc": "Object attribute configured", "user": "netops", "ui": "ssh(10.10.30.10)", "action": "Edit",
                  "cfgtid": self.r.randint(10**6, 10**7), "cfgpath": "system.admin", "cfgobj": "helpdesk",
                  "cfgattr": "accprofile[prof_admin->super_admin]", "msg": "Edit system.admin helpdesk"})
        return kv(d)

    def vpn(self, fw, ts, user, country, ok=True, ip=None):
        d = header(fw, ts, "0101039947" if ok else "0101039426", "event", "vpn", "information" if ok else "alert")
        d.update({"logdesc": "SSL VPN tunnel up" if ok else "SSL VPN login fail", "action": "tunnel-up" if ok else "ssl-login-fail",
                  "tunneltype": "ssl-tunnel", "remip": ip or VPN_SOURCES.get(country, "198.51.100.99"), "srccountry": country,
                  "user": user, "group": "VPN-Users", "reason": "N/A" if ok else "sslvpn_login_permission_denied",
                  "msg": "SSL tunnel established" if ok else "SSL user failed to logged in"})
        return kv(d)

    # demo WAN links: (interface, base latency ms); each firewall has two ISPs monitored by two health checks
    WAN = {"wan1": 6.0, "wan2": 14.0}
    CHECKS = ("DNS_Ping", "SaaS_HTTP")

    def wan_down(self, fw, iface: str, ts: datetime) -> tuple[bool, bool]:
        """Scripted provider behaviour: (link down, SaaS check down). wan2 on the branch drops 8 min every 3 h;
        HQ wan1 loses only the SaaS target for 3 min each hour (a partial, not an ISP outage)."""
        mins = ts.hour * 60 + ts.minute
        full = fw["serial"].endswith("2") and iface == "wan2" and mins % 180 < 8
        partial = fw["serial"].endswith("1") and iface == "wan1" and ts.minute in (25, 26, 27)
        return full, full or partial

    def sdwan(self, fw, ts, iface: str, check: str, down: bool) -> str:
        base = self.WAN[iface]
        d = header(fw, ts, "0113022925", "event", "sdwan", "information")
        d.update({"logdesc": "SDWAN SLA information", "eventtype": "SLA", "healthcheck": check, "slatargetid": 1, "interface": iface,
                  "status": "down" if down else "up", "latency": f"{base + self.r.random() * 4:.3f}" if not down else "0.000",
                  "jitter": f"{self.r.random() * 1.5:.3f}", "packetloss": "100.000" if down else f"{max(0, self.r.gauss(0.05, 0.1)):.3f}",
                  "moscodec": "g711", "mosvalue": "1.000" if down else f"{4.35 + self.r.random() * 0.05:.3f}",
                  "inbandwidthused": f"{self.r.uniform(20, 90):.2f}Mbps", "outbandwidthused": f"{self.r.uniform(2, 20):.2f}Mbps",
                  "msg": "Health Check SLA status."})
        return kv(d)

    def sdwan_state(self, fw, ts, iface: str, check: str, dead: bool) -> str:
        d = header(fw, ts, "0113022931" if dead else "0113022933", "event", "sdwan", "warning" if dead else "notice")
        d.update({"logdesc": "SDWAN SLA information warning", "eventtype": "Health Check", "healthcheck": check, "interface": iface,
                  "probeproto": "ping", "oldvalue": "alive" if dead else "dead", "newvalue": "dead" if dead else "alive",
                  "msg": "SD-WAN health-check member changed state."})
        return kv(d)

    def wan_logs(self, ts: datetime) -> list[str]:
        """State changes whenever a check flips, plus an SLA sample per check every 30 s (works for any step size)."""
        out = []
        if not hasattr(self, "_wan_state"):
            self._wan_state, self._wan_sample = {}, {}
        for fw in DEMO_FIREWALLS:
            for iface in self.WAN:
                full, saas = self.wan_down(fw, iface, ts)
                for check, down in (("DNS_Ping", full), ("SaaS_HTTP", saas)):
                    k = (fw["serial"], iface, check)
                    if self._wan_state.get(k, False) != down:
                        out.append(self.sdwan_state(fw, ts, iface, check, down))
                        self._wan_state[k] = down
                    if k not in self._wan_sample or (ts - self._wan_sample[k]).total_seconds() >= 30:
                        out.append(self.sdwan(fw, ts, iface, check, down))
                        self._wan_sample[k] = ts
        return out

    # (firewall index, neighbor, minutes cycle, down from minute, down until minute, reason, routes withdrawn while down)
    BGP_PEERS = ((1, "169.254.10.1", 120, 37, 41, "Hold Timer Expired", ("10.40.0.0/16", "10.41.0.0/16", "172.20.8.0/22")),
                 (0, "169.254.20.1", 240, 100, 101, "BGP Notification FSM-ERR", ("10.60.0.0/16",)))

    def router(self, fw, ts, logid: str, msg: str) -> str:
        d = header(fw, ts, logid, "event", "router", "warning")
        d.update({"logdesc": "BGP neighbor status changed" if logid == "0103020300" else "Routing log warning", "msg": msg})
        return kv(d)

    def bgp_logs(self, ts: datetime) -> list[str]:
        """Scripted BGP-over-IPsec neighbors: the branch peer drops for 4 min every 2 h (hold timer), HQ briefly every 4 h."""
        out = []
        if not hasattr(self, "_bgp_state"):
            self._bgp_state = {}
        mins = ts.hour * 60 + ts.minute
        for i, peer, cycle, a, b, reason, routes in self.BGP_PEERS:
            fw = DEMO_FIREWALLS[i]
            down = a <= mins % cycle < b
            if peer not in self._bgp_state:
                self._bgp_state[peer] = down
                if not down:
                    out.append(self.router(fw, ts, "0103020300", f"BGP: %BGP-5-ADJCHANGE: VRF 0 neighbor {peer} Up "))
                continue
            if self._bgp_state[peer] == down:
                continue
            self._bgp_state[peer] = down
            if down:
                if reason == "Hold Timer Expired":
                    out.append(self.router(fw, ts, "0103020304", f"BGP: %BGP-3-NOTIFICATION: sending to {peer} 4/0 (Hold Timer Expired/Unspecified Error Subcode) 0 data-bytes []"))
                out.append(self.router(fw, ts, "0103020300", f"BGP: %BGP-5-ADJCHANGE: VRF 0 neighbor {peer} Down {reason}"))
                out += [self.router(fw, ts, "0103020304", f"BGP: {peer}-Outgoing [RIB] Withdraw: Can't find route {r}") for r in routes]
            else:
                out.append(self.router(fw, ts, "0103020300", f"BGP: %BGP-5-ADJCHANGE: VRF 0 neighbor {peer} Up "))
        return out

    def tunnel_qname(self):
        label = "".join(self.r.choices(string.ascii_lowercase + string.digits, k=self.r.randint(40, 60)))
        return f"{label}.t.tunnel-demo.example.net"

    def batch(self, ts: datetime) -> list[str]:
        """One second worth of mixed demo logs, including periodic scenarios that exercise detections."""
        out = []
        fw = self.r.choice(DEMO_FIREWALLS)
        for _ in range(self.r.randint(6, 12)):
            out.append(self.traffic(self.r.choice(DEMO_FIREWALLS), ts))
        for _ in range(self.r.randint(3, 7)):
            out.append(self.dns(self.r.choice(DEMO_FIREWALLS), ts))
        if self.r.random() < 0.5:
            out.append(self.web(fw, ts))
        if self.r.random() < 0.05:
            out.append(self.ips(fw, ts))
        minute = ts.minute
        if minute % 15 == 0:  # port scan scenario
            for _ in range(8):
                out.append(self.traffic(DEMO_FIREWALLS[1], ts, src="10.10.20.66", dport=self.r.randint(1, 10000), action="deny"))
        if minute % 20 == 5:  # dns tunneling scenario
            for _ in range(2):
                out.append(self.dns(DEMO_FIREWALLS[0], ts, src="10.10.10.77", qname=self.tunnel_qname()))
        if minute % 10 == 3:  # nxdomain scenario
            out.append(self.dns(DEMO_FIREWALLS[2], ts, src="10.10.30.45", qname=f"{''.join(self.r.choices(string.ascii_lowercase, k=12))}.example.test", rcode="NXDOMAIN"))
        if minute % 30 == 7 and ts.second < 20:
            out.append(self.admin_login(DEMO_FIREWALLS[0], ts))
        if minute == 42 and ts.second == 0:
            out.append(self.config_change(DEMO_FIREWALLS[2], ts))
        if ts.hour % 3 == 1 and minute == 17 and ts.second < 5:  # privilege escalation of a helpdesk admin account
            out.append(self.admin_account_change(DEMO_FIREWALLS[0], ts))
        if minute % 30 == 7 and 20 <= ts.second < 25:  # the admin gets in after the failures
            out.append(self.admin_login(DEMO_FIREWALLS[0], ts, failed=False))
        if ts.second < 5:  # periodic beacon to the demo IOC (beaconing + threat-intel scenarios)
            out.append(self.traffic(DEMO_FIREWALLS[0], ts, src="10.10.10.88", dst=DEMO_IOC, dport=8443, action="close"))
        if ts.second % 30 < 5 and self.r.random() < 0.5:  # normal VPN logins (country varies per user)
            u = self.r.choice(VPN_USERS)
            out.append(self.vpn(DEMO_FIREWALLS[0], ts, u, "India" if u != "sara" else "Singapore"))
        if minute % 12 == 0 and ts.second < 30:  # VPN brute force from one source
            out.append(self.vpn(DEMO_FIREWALLS[0], ts, self.r.choice(["admin", "test", "vpn", "root"]), "Netherlands", ok=False, ip="198.51.100.250"))
        if minute % 30 == 1 and ts.second < 5:  # impossible travel: India, then Netherlands 10 min later
            out.append(self.vpn(DEMO_FIREWALLS[0], ts, "rahul", "India"))
        if minute % 30 == 11 and ts.second < 5:
            out.append(self.vpn(DEMO_FIREWALLS[1], ts, "rahul", "Netherlands"))
        out.extend(self.wan_logs(ts))
        out.extend(self.bgp_logs(ts))
        return out


async def ensure_demo_firewalls() -> None:
    async with session_factory()() as s:
        existing = {f.serial for f in (await s.execute(select(Firewall).where(Firewall.is_demo.is_(True)))).scalars()}
        for d in DEMO_FIREWALLS:
            if d["serial"] not in existing:
                s.add(Firewall(name=d["name"], host=d["host"], serial=d["serial"], hostname=d["name"], site=d["site"],
                               is_demo=True, api_status="demo", tags=["demo"], syslog_source_ips=[], capabilities={},
                               health={"note": "Demo device: no API polling is performed"}, api_log_cursor={},
                               fortios_version_declared="7.4.0"))
        await s.commit()


# demo BGP inventory as the API poller would record it: (firewall index, neighbor, local IP, tunnel, remote AS, state, prefixes)
DEMO_BGP = ((0, "169.254.20.1", "169.254.20.2", "dc-tun-1", 65010, "Established", [f"10.20.{i}.0/24" for i in range(12)] + ["0.0.0.0/0"]),
            (0, "169.254.30.2", "169.254.30.1", "branch-tun-1", 65001, "Established", ["10.40.0.0/16", "10.41.0.0/16", "172.20.8.0/22"]),
            (1, "169.254.30.1", "169.254.30.2", "hq-tun-1", 65001, "Established", [f"10.10.{i}.0/24" for i in range(8)] + ["10.20.0.0/16"]),
            (1, "169.254.10.1", "169.254.10.2", "isp-tun-1", 65020, "Established", ["10.60.0.0/16", "172.16.0.0/12"]),
            (2, "169.254.40.1", "169.254.40.2", "wh-tun-1", 65001, "Connect", []))


async def seed_demo_bgp(backfill_hours: float) -> None:
    """Neighbors, installed routes, sanitised configuration and prefix samples for the demo firewalls (source: demo)."""
    from .bgp_analysis import audit as bgp_audit
    from .db.models import BgpPeer, BgpRouter
    now = datetime.now(timezone.utc)
    async with session_factory()() as s:
        fws = {f.serial: f for f in (await s.execute(select(Firewall).where(Firewall.is_demo.is_(True)))).scalars()}
        ids = [fws[d["serial"]].id for d in DEMO_FIREWALLS if d["serial"] in fws]
        if len(ids) < 3 or (await s.execute(select(BgpRouter).where(BgpRouter.firewall_id.in_(ids)))).first():
            return
        samples = []
        for i, fid in enumerate(ids):
            peers = [b for b in DEMO_BGP if b[0] == i]
            cfg = {"vendor": "fortinet", "local_as": 65001, "router_id": f"10.254.0.{i + 1}", "holdtime": 180, "keepalive": 60,
                   "graceful_restart": i != 2, "dampening": False, "log_changes": True, "networks": [["10.10.0.0/16", "10.40.0.0/16", "10.50.0.0/16"][i]],
                   "neighbors": {ip: {"remote_as": asn, "description": tun, "shutdown": False, "bfd": i == 0 and ip.endswith(".20.1"),
                                      "password": i == 0, "holdtime": None, "keepalive": None, "max_prefix": 500 if i == 0 else 0,
                                      "filter_in": i == 0, "filter_out": False, "graceful_restart": False, "interface": tun}
                                 for _, ip, _, tun, asn, _, _ in peers}}
            rib = {}
            rows = []
            for _, ip, local, tun, asn, state, pre in peers:
                rows.append({"peer": ip, "state": state, "state_since": now - timedelta(days=3), "prefixes": len(pre), "interface": tun})
                s.add(BgpPeer(firewall_id=fid, peer_ip=ip, remote_as=asn, local_ip=local, peer_type="ipv4", admin_status="up", state=state,
                              state_since=now - timedelta(days=3), prefixes=len(pre), routes=sorted(pre), interface=tun,
                              config=cfg["neighbors"][ip], known_prefixes={x: now.isoformat() for x in pre}, last_polled_at=now,
                              first_seen=now - timedelta(days=30)))
                for x in pre:
                    rib.setdefault(x, []).append({"peer": ip, "interface": tun, "gateway": f"203.0.113.{10 + i}",
                                                  "installed": (now - timedelta(hours=30 + len(x))).isoformat()})
                for h in range(int(max(backfill_hours, 1) * 6)):
                    samples.append({"ts": (now - timedelta(minutes=10 * h)).replace(microsecond=0), "firewall_id": fid, "peer": ip, "state": state,
                                    "up": int(state == "Established"), "prefixes": len(pre)})
            s.add(BgpRouter(firewall_id=fid, local_as=65001, router_id=cfg["router_id"], config=cfg, config_polled_at=now,
                            rib=rib, rib_polled_at=now, audit=bgp_audit(cfg, rows, now)))
        await s.commit()
    if samples:
        await get_ch().ainsert("bgp_samples", samples, ["ts", "firewall_id", "peer", "state", "up", "prefixes"])


async def run(backfill_hours: float = 0, live: bool = True, rate: int | None = None, step_seconds: int = 1) -> None:
    await ensure_demo_firewalls()
    try:
        await seed_demo_policies()
        await seed_demo_ioc()
        await seed_demo_bgp(backfill_hours)
    except Exception:
        log.exception("demo policy/IOC/BGP seeding failed")
    registry = DeviceRegistry()
    await registry.refresh()
    from .enrich.enricher import Enricher
    enricher = Enricher()
    await enricher.refresh_ti(force=True)
    sink = EventSink(get_ch(), registry, batch_size=5000, enricher=enricher)
    gen = DemoGenerator()
    if backfill_hours and (await get_ch().aquery("SELECT count() AS n FROM events WHERE source = 'demo'"))[0]["n"]:
        log.info("demo history already present; skipping backfill")
        backfill_hours = 0
    if backfill_hours:
        now = datetime.now(timezone.utc)
        t = now - timedelta(hours=backfill_hours)
        while t < now:
            for line in gen.batch(t):
                sink.add_line(line, source="demo")
            if sink.should_flush():
                await sink.flush()
            t += timedelta(seconds=step_seconds)
        await sink.flush()
        log.info("demo backfill complete: %s", sink.counters)
    while live:
        for line in gen.batch(datetime.now(timezone.utc)):
            sink.add_line(line, source="demo")
        await sink.flush()
        await asyncio.sleep(1)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--backfill-hours", type=float, default=6)
    ap.add_argument("--step-seconds", type=int, default=5, help="simulated seconds between backfill batches")
    ap.add_argument("--live", action="store_true")
    a = ap.parse_args()
    setup_logging(get_settings().log_level)
    asyncio.run(run(a.backfill_hours, a.live, step_seconds=a.step_seconds))


# ---------------------------------------------------------------- demo policies (synthetic, source='demo')
DEMO_OBJECTS = {
    "address": [
        {"name": "LAN", "type": "ipmask", "subnet": "10.10.0.0 255.255.0.0"},
        {"name": "LAN-Servers", "type": "ipmask", "subnet": "10.10.20.0 255.255.255.0"},
        {"name": "Admins", "type": "ipmask", "subnet": "10.10.30.0 255.255.255.192"},
        {"name": "Guest", "type": "ipmask", "subnet": "10.10.40.0 255.255.255.0"},
        {"name": "Branch-Nets", "type": "ipmask", "subnet": "172.16.0.0 255.240.0.0"},
        {"name": "CloudApp", "type": "fqdn", "fqdn": "app.example.com"},
    ],
    "addrgrp": [],
    "service_custom": [
        {"name": "ALL", "protocol": "IP", "protocol-number": 0},
        {"name": "HTTP", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "80"},
        {"name": "HTTPS", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "443"},
        {"name": "DNS", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "53", "udp-portrange": "53"},
        {"name": "NTP", "protocol": "TCP/UDP/SCTP", "udp-portrange": "123"},
        {"name": "RDP", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "3389"},
        {"name": "TELNET", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "23"},
    ],
    "service_group": [{"name": "Web", "member": [{"name": "HTTP"}, {"name": "HTTPS"}]}],
    "zone": [],
}


def _demo_policy(pid, name, src, dst, svc, action="accept", status="enable", log="all", dstintf="wan1", schedule="always"):
    n = lambda xs: [{"name": x} for x in xs]  # noqa: E731
    return {"policyid": pid, "name": name, "uuid": f"00000000-demo-0000-0000-{pid:012d}", "srcintf": n(["port1"]),
            "dstintf": n([dstintf]), "srcaddr": n(src), "dstaddr": n(dst), "service": n(svc), "action": action, "status": status,
            "logtraffic": log, "schedule": schedule, "nat": "enable" if action == "accept" else "disable"}


DEMO_POLICIES = [
    _demo_policy(12, "Servers-Out", ["LAN-Servers"], ["all"], ["ALL"]),
    _demo_policy(1, "LAN-to-WAN", ["LAN"], ["all"], ["Web", "DNS", "NTP"]),
    _demo_policy(2, "Guest-Web", ["Guest"], ["all"], ["Web"]),
    _demo_policy(5, "Branch-VPN", ["LAN"], ["Branch-Nets"], ["ALL"], dstintf="vpn-branch"),
    _demo_policy(20, "Legacy-Servers-HTTPS", ["LAN-Servers"], ["all"], ["HTTPS"]),
    _demo_policy(21, "Block-Telnet", ["LAN"], ["all"], ["TELNET"], action="deny"),
    _demo_policy(22, "Old-Partner-Access", ["LAN"], ["Branch-Nets"], ["RDP"], status="disable"),
    _demo_policy(24, "Deny-RDP-to-WAN", ["all"], ["all"], ["RDP"], action="deny"),
    _demo_policy(23, "Allow-RDP-Admins", ["Admins"], ["all"], ["RDP"]),
    _demo_policy(25, "Guest-DNS-NoLog", ["Guest"], ["all"], ["DNS"], log="disable"),
    _demo_policy(26, "CloudApp-HTTPS", ["LAN"], ["CloudApp"], ["HTTPS"]),
]


async def seed_demo_ioc() -> None:
    from .db.models import TiFeed, TiIndicator
    from .enrich.feeds import MANUAL, ensure_default_feeds
    async with session_factory()() as s:
        await ensure_default_feeds(s)
        feed = (await s.execute(select(TiFeed).where(TiFeed.name == MANUAL))).scalar_one()
        exists = (await s.execute(select(TiIndicator).where(TiIndicator.feed_id == feed.id, TiIndicator.indicator == DEMO_IOC))).first()
        if not exists:
            s.add(TiIndicator(feed_id=feed.id, indicator=DEMO_IOC, type="ip", note="DEMO synthetic C2 indicator"))
            feed.indicator_count = (feed.indicator_count or 0) + 1
        await s.commit()


async def seed_demo_policies() -> None:
    from .db.models import PolicySync
    from .policy.model import normalize_policy
    from .policy.store import refresh_assessments, run_analysis, store_objects, store_policies
    async with session_factory()() as s:
        fws = (await s.execute(select(Firewall).where(Firewall.is_demo.is_(True)))).scalars().all()
        for fw in fws:
            vdom = "root"
            pols = [normalize_policy(p, seq) for seq, p in enumerate(DEMO_POLICIES, start=1)]
            await store_policies(s, fw.id, vdom, pols, source="demo")
            await store_objects(s, fw.id, vdom, DEMO_OBJECTS, {})
            st = await s.get(PolicySync, (fw.id, vdom))
            if st is None:
                st = PolicySync(firewall_id=fw.id, vdom=vdom, details={})
                s.add(st)
            st.status, st.counters_supported, st.policies = "ok", False, len(pols)
            st.last_attempt = st.last_success = datetime.now(timezone.utc)
            st.details = {"note": "demo policies (synthetic); no firewall counters"}
            await s.commit()
            await run_analysis(s, fw.id, vdom)
            await refresh_assessments(s, get_ch(), fw.id, vdom, False)
