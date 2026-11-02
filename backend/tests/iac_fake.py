"""In-memory FortiGate REST API for IaC tests (httpx MockTransport). Never contacts a real device."""
from __future__ import annotations

import json
from urllib.parse import unquote

import httpx

from app.iac.resources import TYPES

PATH_TYPE = {d["path"]: t for t, d in TYPES.items()}


class FakeFortiGate:
    def __init__(self):
        self.tables: dict[str, dict] = {t: {} for t, d in TYPES.items() if d["key"]}
        self.singletons: dict[str, dict] = {"system_global": {"admintimeout": 5, "strong-crypto": "enable", "admin-https-redirect": "enable",
                                                              "admin-telnet": "disable", "hostname": "FGT-LAB"},
                                            "syslog": {"status": "enable", "server": "10.0.0.5", "port": 514, "mode": "udp"}}
        self.order: list[str] = []          # firewall policy sequence
        self.central = {"type": "none", "fmg": ""}
        self.writes: list[tuple[str, str]] = []
        self.fail_on: tuple[str, str] | None = None   # (method, path fragment) -> HTTP 500
        self.allow_backup = True
        self.interfaces = ["port1", "port2", "wan1", "wan2", "internal"]
        # predefined objects like a factory-default FortiGate
        for n in ("ALL", "HTTP", "HTTPS", "DNS", "SSH", "PING"):
            self.tables["service"][n] = {"name": n, "protocol": "TCP/UDP/SCTP", "tcp-portrange": {"HTTP": "80", "HTTPS": "443", "DNS": "53", "SSH": "22"}.get(n, "1-65535")}
        self.tables["address"]["all"] = {"name": "all", "type": "ipmask", "subnet": "0.0.0.0 0.0.0.0"}

    def add_real_world_variants(self):
        """Object shapes seen on production FortiOS 7.x (sanitised): variants beyond plain ipmask / port services."""
        self.add("address", {"name": "MGMT-LOOP", "type": "interface-subnet", "subnet": "172.16.3.100 255.255.255.255",
                             "interface": "port1", "macaddr": [], "comment": ""})
        self.add("address", {"name": "PRINTER-MAC", "type": "mac", "macaddr": [{"macaddr": "94:B6:09:00:00:01"}], "comment": ""})
        self.add("address", {"name": "EMS-TAG", "type": "dynamic", "sub-type": "ems-tag", "macaddr": [], "comment": ""})
        self.add("address", {"name": "IN", "type": "geography", "country": "IN", "comment": ""})
        self.add("address", {"name": "PUSH-WILD", "type": "fqdn", "fqdn": "*.push.*", "comment": ""})
        self.add("service", {"name": "webproxy", "protocol": "ALL", "proxy": "enable", "tcp-portrange": "0-65535:0-65535"})
        self.add("service", {"name": "AH", "protocol": "IP", "protocol-number": 51, "proxy": "disable"})
        self.add("service", {"name": "ALL_ICMP", "protocol": "ICMP", "icmptype": None, "proxy": "disable"})
        self.add("static_route", {"seq-num": 1, "dst": "0.0.0.0 0.0.0.0", "gateway": "0.0.0.0", "device": "", "blackhole": "disable",
                                  "sdwan-zone": [{"name": "virtual-wan-link"}], "distance": 1, "status": "enable"})
        self.add("static_route", {"seq-num": 2, "dst": "192.0.2.0 255.255.255.0", "gateway": "0.0.0.0", "device": "", "blackhole": "enable",
                                  "sdwan-zone": [], "distance": 254, "status": "enable"})
        self.add("policy", {"policyid": 59, "name": "to-saas", "srcintf": [{"name": "port1"}], "dstintf": [{"name": "wan1"}],
                            "srcaddr": [{"name": "all"}], "dstaddr": [], "service": [], "internet-service": "enable",
                            "internet-service-name": [{"name": "Example-SaaS.Cloud"}], "internet-service-group": [],
                            "internet-service-custom": [], "action": "accept", "schedule": "always", "nat": "enable",
                            "logtraffic": "all", "status": "enable"})
        self.add("policy", {"policyid": 60, "name": "from-isdb", "srcintf": [{"name": "wan1"}], "dstintf": [{"name": "port1"}],
                            "srcaddr": [], "internet-service-src": "enable", "internet-service-src-name": [{"name": "Example-SaaS.Cloud"}],
                            "dstaddr": [{"name": "all"}], "service": [{"name": "HTTPS"}], "action": "accept", "schedule": "always",
                            "logtraffic": "all", "status": "enable"})
        self.add("policy", {"policyid": 61, "name": "v6-only", "srcintf": [{"name": "port1"}], "dstintf": [{"name": "wan1"}],
                            "srcaddr": [], "dstaddr": [], "srcaddr6": [{"name": "all"}], "dstaddr6": [{"name": "all"}],
                            "service": [{"name": "HTTPS"}], "action": "accept", "schedule": "always", "logtraffic": "all", "status": "enable"})

    # convenience for tests
    def add(self, rtype: str, obj: dict):
        key = str(obj[TYPES[rtype]["key"]])
        self.tables[rtype][key] = obj
        if rtype == "policy" and key not in self.order:
            self.order.append(key)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def _ok(self, results=None, **extra):
        return httpx.Response(200, json={"status": "success", "http_status": 200, "results": results if results is not None else [], **extra})

    def handle(self, request: httpx.Request) -> httpx.Response:
        path, method, params = request.url.path, request.method, dict(request.url.params)
        if method != "GET":
            self.writes.append((method, path))
            if self.fail_on and method == self.fail_on[0] and self.fail_on[1] in path:
                return httpx.Response(500, json={"status": "error", "http_status": 500, "cli_error": "entry not found (-3)"})
        if path == "/api/v2/monitor/system/status":
            return self._ok({"hostname": "FGT-LAB", "model_name": "FortiGate-60F"}, version="v7.2.8", serial="FGTLAB0000000001")
        if path == "/api/v2/monitor/system/resource/usage":
            return self._ok({"cpu": [{"current": 7}], "mem": [{"current": 31}], "session": [{"current": 100}], "disk": [{"current": 3}]})
        if path == "/api/v2/monitor/system/config/backup":
            if not self.allow_backup:
                return httpx.Response(403, json={"status": "error"})
            return httpx.Response(200, text="#config-version=FGT60F-7.2.8\nconfig system global\n    set hostname FGT-LAB\nend\n"
                                             "config system admin\n    edit admin\n        set password ENC SH2abcdefghijklmnop==\n    next\nend\n")
        if path == "/api/v2/cmdb/system/central-management":
            return self._ok(self.central)
        if path == "/api/v2/cmdb/system/interface":
            return self._ok([{"name": n} for n in self.interfaces])
        if path in ("/api/v2/cmdb/system/zone", "/api/v2/cmdb/firewall.schedule/onetime"):
            return self._ok([])
        if path == "/api/v2/cmdb/firewall.schedule/recurring":
            return self._ok([{"name": "always"}])
        for t in ("system_global", "syslog"):
            if path == TYPES[t]["path"]:
                if method == "GET":
                    return self._ok(dict(self.singletons[t]))
                if method == "PUT":
                    self.singletons[t].update(json.loads(request.content))
                    return self._ok()
        rtype, key = PATH_TYPE.get(path), None
        if rtype is None:
            head, _, tail = path.rpartition("/")
            rtype, key = PATH_TYPE.get(head), unquote(tail)
        if rtype is None:
            return httpx.Response(404, json={"status": "error", "http_status": 404})
        table = self.tables[rtype]
        if method == "GET":
            items = [table[k] for k in self.order if k in table] if rtype == "policy" else list(table.values())
            return self._ok(items)
        if method == "POST":
            body = json.loads(request.content)
            k = str(body[TYPES[rtype]["key"]])
            if k in table:
                return httpx.Response(500, json={"status": "error", "http_status": 500, "cli_error": "duplicate entry (-5)"})
            table[k] = body
            if rtype == "policy":
                self.order.append(k)
            return self._ok(mkey=k)
        if method == "PUT" and key is not None:
            if key not in table:
                return httpx.Response(404, json={"status": "error", "http_status": 404})
            if params.get("action") == "move":
                self.order.remove(key)
                ref = params.get("after") or params.get("before")
                i = self.order.index(ref)
                self.order.insert(i + 1 if "after" in params else i, key)
                return self._ok()
            body = json.loads(request.content)
            table[key] = {**table[key], **body}
            return self._ok()
        if method == "DELETE" and key is not None:
            if key not in table:
                return httpx.Response(404, json={"status": "error", "http_status": 404})
            in_use = any(key in [m.get("name") for m in (o.get(f) or [])] for t in ("policy", "address_group", "service_group")
                         for o in self.tables[t].values() for f in ("srcaddr", "dstaddr", "service", "member"))
            if in_use:
                return httpx.Response(500, json={"status": "error", "http_status": 500, "cli_error": "entry is used (-23)"})
            del table[key]
            if rtype == "policy":
                self.order.remove(key)
            return self._ok()
        return httpx.Response(405, json={"status": "error"})
