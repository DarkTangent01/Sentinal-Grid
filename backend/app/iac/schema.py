"""Desired-state file format (YAML), schema validation with line numbers, variables, per-device rendering and import.

    apiVersion: iac.sentinelgrid/v1
    kind: FirewallConfig
    metadata: {name: branch-baseline, description: ...}
    variables: {lan_subnet: 10.20.0.0/16}           # project defaults
    sites:   {Branch-North: {lan_subnet: 10.21.0.0/16}}
    devices: {FW-BRANCH-01: {wan_gw: 203.0.113.1}}  # by firewall name; device > site > project
    manage:  {prune: [address]}                     # delete objects of these types that are not declared
    resources:
      addresses:      [{name: LAN, subnet: "${lan_subnet}"}]
      address_groups: [{name: LAN-ALL, members: [LAN]}]
      services:       [{name: APP-8443, tcp: ["8443"]}]
      service_groups: [{name: WEB, members: [HTTP, HTTPS]}]
      static_routes:  [{id: 1, dst: 0.0.0.0/0, gateway: "${wan_gw}", device: wan1}]
      policies:       [{id: 100, name: LAN-out, srcintf: [port1], dstintf: [wan1], srcaddr: [LAN], dstaddr: [all],
                        service: [HTTPS], action: accept, nat: enable, logtraffic: all}]
      system_global:  {admintimeout: 15, strong-crypto: enable}
      syslog:         {status: enable, server: 10.0.0.5, port: 514}

Only `${name}` substitution is supported (no expressions, no code). Unknown keys are errors, never ignored.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .resources import ISDB_FIELDS, PORT_PROTOCOLS, TYPES, UNSUPPORTED, to_cidr

MAX_BYTES = 1_000_000
NAME = r"^[^\"\\\x00-\x1f\x7f]{1,79}$"
VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]{0,63})\}")
RES_KEYS = {"addresses": "address", "address_groups": "address_group", "services": "service", "service_groups": "service_group",
            "static_routes": "static_route", "policies": "policy", "system_global": "system_global", "syslog": "syslog"}
TYPE_KEYS = {v: k for k, v in RES_KEYS.items()}
EXAMPLE = """apiVersion: iac.sentinelgrid/v1
kind: FirewallConfig
metadata:
  name: branch-baseline
  description: Example desired state (fictional addresses)
variables:
  lan_subnet: 10.20.0.0/16
  wan_gateway: 203.0.113.1
manage:
  prune: []
resources:
  addresses:
    - {name: BRANCH-LAN, subnet: "${lan_subnet}", comment: Branch LAN}
    - {name: DNS-SERVERS, type: iprange, start_ip: 10.20.0.53, end_ip: 10.20.0.54}
  address_groups:
    - {name: BRANCH-INTERNAL, members: [BRANCH-LAN, DNS-SERVERS]}
  services:
    - {name: APP-8443, tcp: ["8443"]}
  policies:
    - {id: 100, name: LAN-to-Internet, srcintf: [port1], dstintf: [wan1], srcaddr: [BRANCH-LAN], dstaddr: [all],
       service: [HTTPS, APP-8443], action: accept, nat: enable, logtraffic: all}
  static_routes:
    - {id: 1, dst: 0.0.0.0/0, gateway: "${wan_gateway}", device: wan1}
  system_global:
    admintimeout: 15
    strong-crypto: enable
"""


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


def _name(v: str) -> str:
    if not re.match(NAME, v or ""):
        raise ValueError("1-79 characters, no quotes, backslashes or control characters")
    return v


MAC = r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}(-[0-9a-f]{2}(:[0-9a-f]{2}){5})?$"


class Address(Strict):
    name: str
    type: Literal["ipmask", "iprange", "fqdn", "interface-subnet", "mac"] = "ipmask"
    subnet: str | None = None
    start_ip: str | None = None
    end_ip: str | None = None
    fqdn: str | None = None
    macaddr: list[str] = Field(default_factory=list, max_length=1000)
    interface: str = ""
    comment: str = Field("", max_length=255)
    _n = field_validator("name")(lambda cls, v: _name(v))

    @field_validator("macaddr", mode="before")
    @classmethod
    def _mac(cls, v):
        v = [str(x).lower() for x in (v or [])]
        for x in v:
            if not re.match(MAC, x):
                raise ValueError(f"MAC address '{x}' must look like 00:11:22:33:44:55 (or a range a-b)")
        return v

    @model_validator(mode="after")
    def _variant(self):
        if self.type == "interface-subnet" and not self.interface:
            raise ValueError("interface-subnet addresses need 'interface'")
        if self.type == "mac" and not self.macaddr:
            raise ValueError("mac addresses need at least one entry in 'macaddr'")
        if self.macaddr and self.type != "mac":
            raise ValueError("'macaddr' is only valid with type: mac")
        return self


class Group(Strict):
    name: str
    members: list[str] = Field(min_length=1, max_length=600)
    comment: str = Field("", max_length=255)
    _n = field_validator("name")(lambda cls, v: _name(v))


class Service(Strict):
    name: str
    protocol: Literal["TCP/UDP/SCTP", "TCP/UDP/UDP-Lite/SCTP", "IP", "ICMP", "ICMP6"] = "TCP/UDP/SCTP"
    tcp: list[str] = Field(default_factory=list)
    udp: list[str] = Field(default_factory=list)
    udplite: list[str] = Field(default_factory=list)
    sctp: list[str] = Field(default_factory=list)
    protocol_number: int | None = Field(None, ge=0, le=255)
    icmp_type: int | None = Field(None, ge=0, le=255)
    comment: str = Field("", max_length=255)
    _n = field_validator("name")(lambda cls, v: _name(v))

    @field_validator("tcp", "udp", "udplite", "sctp", mode="before")
    @classmethod
    def _p(cls, v):
        v = [str(x) for x in (v or [])]
        for x in v:
            if not re.match(r"^\d{1,5}(-\d{1,5})?(:\d{1,5}(-\d{1,5})?)?$", x):
                raise ValueError(f"port range '{x}' must look like 443, 8000-8080 or 443:1024-65535")
        return v


class Route(Strict):
    id: int = Field(ge=1, le=4294967294)
    dst: str
    gateway: str = "0.0.0.0"
    device: str = ""
    sdwan_zone: list[str] = Field(default_factory=list, max_length=16)
    blackhole: Literal["enable", "disable"] | None = None
    distance: int = Field(10, ge=1, le=255)
    status: Literal["enable", "disable"] = "enable"
    comment: str = Field("", max_length=255)

    @model_validator(mode="after")
    def _egress(self):
        ways = [w for w, on in (("device", bool(self.device)), ("sdwan_zone", bool(self.sdwan_zone)), ("blackhole", self.blackhole == "enable")) if on]
        if not ways:
            raise ValueError("a route needs 'device', 'sdwan_zone' or 'blackhole: enable'")
        if len(ways) > 1:
            raise ValueError(f"set only one of device / sdwan_zone / blackhole (got {', '.join(ways)})")
        return self


class Policy(Strict):
    id: int = Field(ge=1, le=4294967294)
    name: str = Field("", max_length=35)
    srcintf: list[str] = Field(min_length=1)
    dstintf: list[str] = Field(min_length=1)
    srcaddr: list[str] = Field(min_length=1)
    dstaddr: list[str] = Field(default_factory=list)
    service: list[str] = Field(default_factory=list)
    # destination by Internet Service Database entry instead of dstaddr + service
    internet_service: Literal["enable", "disable"] = "disable"
    internet_service_name: list[str] = Field(default_factory=list)
    internet_service_group: list[str] = Field(default_factory=list)
    internet_service_custom: list[str] = Field(default_factory=list)
    action: Literal["accept", "deny"] = "deny"
    schedule: str = "always"
    nat: Literal["enable", "disable"] = "disable"
    logtraffic: Literal["all", "utm", "disable"] = "utm"
    status: Literal["enable", "disable"] = "enable"
    comments: str = Field("", max_length=1023)

    @model_validator(mode="after")
    def _destination(self):
        isdb = [k for k, _ in ISDB_FIELDS if getattr(self, k)]
        if self.internet_service == "enable":
            if not isdb:
                raise ValueError("internet_service: enable needs internet_service_name, _group or _custom")
            if self.dstaddr or self.service:
                raise ValueError("with internet_service: enable, leave dstaddr and service empty (FortiOS rejects both)")
        else:
            if isdb:
                raise ValueError(f"{isdb[0]} needs internet_service: enable")
            missing = [f for f in ("dstaddr", "service") if not getattr(self, f)]
            if missing:
                raise ValueError(f"{' and '.join(missing)} required (or internet_service: enable with internet_service_name)")
        return self


class GlobalSettings(Strict):
    admintimeout: int | None = Field(None, ge=1, le=480)
    admin_https_redirect: Literal["enable", "disable"] | None = Field(None, alias="admin-https-redirect")
    strong_crypto: Literal["enable", "disable"] | None = Field(None, alias="strong-crypto")
    admin_lockout_threshold: int | None = Field(None, ge=1, le=10, alias="admin-lockout-threshold")
    admin_lockout_duration: int | None = Field(None, ge=1, le=2147483647, alias="admin-lockout-duration")
    admin_telnet: Literal["enable", "disable"] | None = Field(None, alias="admin-telnet")
    admin_sport: int | None = Field(None, ge=1, le=65535, alias="admin-sport")
    admin_ssh_port: int | None = Field(None, ge=1, le=65535, alias="admin-ssh-port")


class Syslog(Strict):
    status: Literal["enable", "disable"] | None = None
    server: str | None = None
    port: int | None = Field(None, ge=1, le=65535)
    mode: Literal["udp", "legacy-reliable", "reliable"] | None = None
    facility: str | None = None
    format: Literal["default", "csv", "cef", "rfc5424", "json"] | None = None


class Resources(Strict):
    addresses: list[Address] = Field(default_factory=list)
    address_groups: list[Group] = Field(default_factory=list)
    services: list[Service] = Field(default_factory=list)
    service_groups: list[Group] = Field(default_factory=list)
    static_routes: list[Route] = Field(default_factory=list)
    policies: list[Policy] = Field(default_factory=list)
    system_global: GlobalSettings | None = None
    syslog: Syslog | None = None


PRUNABLE = ("address", "address_group", "service", "service_group", "static_route", "policy")


class Manage(Strict):
    prune: list[Literal["address", "address_group", "service", "service_group", "static_route", "policy"]] = Field(default_factory=list)
    # objects on the device that IaC leaves alone: never changed, deleted (even with prune) or reported as drift.
    # The import lists here what it could not represent.
    ignore: list[str] = Field(default_factory=list, max_length=5000)

    @field_validator("ignore")
    @classmethod
    def _ign(cls, v):
        for x in v:
            t, sep, k = x.partition(":")
            if not sep or t not in PRUNABLE or not k:
                raise ValueError(f"'{x}' must be <type>:<name or id>, type one of {', '.join(PRUNABLE)}")
        return v

    def ignored(self) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {}
        for x in self.ignore:
            t, _, k = x.partition(":")
            out.setdefault(t, set()).add(k)
        return out


class Metadata(Strict):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field("", max_length=2000)


class Document(Strict):
    apiVersion: Literal["iac.sentinelgrid/v1"]
    kind: Literal["FirewallConfig"]
    metadata: Metadata
    variables: dict[str, str | int] = Field(default_factory=dict)
    sites: dict[str, dict[str, str | int]] = Field(default_factory=dict)
    devices: dict[str, dict[str, str | int]] = Field(default_factory=dict)
    manage: Manage = Field(default_factory=Manage)
    resources: Resources = Field(default_factory=Resources)


class ConfigError(ValueError):
    def __init__(self, errors: list[dict]):
        super().__init__("; ".join(e["message"] for e in errors))
        self.errors = errors


# ------------------------------------------------------------------ parsing with locations
def _locate(node, path: tuple) -> tuple[int | None, int | None]:
    """Line/column (1-based) of a pydantic error path inside the composed YAML tree; nearest ancestor if missing."""
    best = node
    for part in path:
        nxt = None
        if isinstance(node, yaml.MappingNode):
            for k, v in node.value:
                if str(k.value) == str(part):
                    nxt = v
                    break
        elif isinstance(node, yaml.SequenceNode) and isinstance(part, int) and part < len(node.value):
            nxt = node.value[part]
        if nxt is None:
            break
        node = best = nxt
    if best is None:
        return None, None
    return best.start_mark.line + 1, best.start_mark.column + 1


def parse(text: str) -> Document:
    """YAML text → validated Document, or ConfigError with line-numbered messages."""
    if len(text.encode()) > MAX_BYTES:
        raise ConfigError([{"line": None, "column": None, "path": "", "message": f"file larger than {MAX_BYTES // 1000} kB"}])
    try:
        node = yaml.compose(text, Loader=yaml.SafeLoader)
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        mark = getattr(e, "problem_mark", None)
        raise ConfigError([{"line": mark.line + 1 if mark else None, "column": mark.column + 1 if mark else None, "path": "",
                            "message": f"YAML syntax error: {getattr(e, 'problem', None) or e}"}]) from None
    if not isinstance(data, dict):
        raise ConfigError([{"line": 1, "column": 1, "path": "", "message": "the document must be a mapping (apiVersion, kind, metadata, resources)"}])
    res = data.get("resources")
    if isinstance(res, dict):
        unknown = [k for k in res if k not in RES_KEYS]
        if unknown:
            errs = []
            for k in unknown:
                line, col = _locate(node, ("resources", k))
                hint = next((n for t, n in UNSUPPORTED.items() if t in k.lower()), "")
                errs.append({"line": line, "column": col, "path": f"resources.{k}",
                             "message": f"unsupported resource type '{k}'. Supported: {', '.join(RES_KEYS)}" + (f" ({hint})" if hint else "")})
            raise ConfigError(errs)
    try:
        return Document.model_validate(data)
    except ValidationError as e:
        errs = []
        for x in e.errors():
            loc = tuple(x["loc"])
            line, col = _locate(node, loc)
            errs.append({"line": line, "column": col, "path": ".".join(str(p) for p in loc), "message": f"{'.'.join(str(p) for p in loc)}: {x['msg']}"})
        raise ConfigError(errs) from None


# ------------------------------------------------------------------ rendering
def variables_for(doc: Document, device_name: str, site: str, device_vars: dict | None = None) -> dict:
    v = {**doc.variables}
    v.update(doc.sites.get(site, {}))
    v.update(doc.devices.get(device_name, {}))
    v.update(device_vars or {})
    return {k: str(x) for k, x in v.items()}


def _subst(value, variables: dict, path: str, errors: list):
    if isinstance(value, str):
        def rep(m):
            if m.group(1) not in variables:
                errors.append({"line": None, "column": None, "path": path, "message": f"{path}: undefined variable ${{{m.group(1)}}}"})
                return m.group(0)
            return variables[m.group(1)]
        return VAR.sub(rep, value)
    if isinstance(value, list):
        return [_subst(x, variables, f"{path}[{i}]", errors) for i, x in enumerate(value)]
    if isinstance(value, dict):
        return {k: _subst(x, variables, f"{path}.{k}", errors) for k, x in value.items()}
    return value


def render(doc: Document, variables: dict) -> tuple[dict, list[str], list[dict]]:
    """Canonical desired state {type: {key: obj}}, policy order, render errors (undefined vars, bad addresses)."""
    errors: list[dict] = []
    raw = _subst(doc.resources.model_dump(by_alias=True, exclude_none=True), variables, "resources", errors)
    out: dict[str, dict] = {t: {} for t in TYPES}
    order: list[str] = []
    seen: dict[tuple, int] = {}

    def dup(t, k, path):
        if (t, k) in seen:
            errors.append({"line": None, "column": None, "path": path, "message": f"{path}: duplicate {t} '{k}'"})
        seen[(t, k)] = 1

    for i, a in enumerate(raw.get("addresses", [])):
        dup("address", a["name"], f"resources.addresses.{i}")
        c = {"type": a.get("type", "ipmask"), "comment": a.get("comment", ""), "interface": a.get("interface", "")}
        try:
            if c["type"] in ("ipmask", "interface-subnet"):
                c["subnet"] = to_cidr(a.get("subnet") or "")
            elif c["type"] == "iprange":
                for f in ("start_ip", "end_ip"):
                    ipaddress.ip_address(a.get(f) or "")
                c["start_ip"], c["end_ip"] = a["start_ip"], a["end_ip"]
            elif c["type"] == "mac":
                c["macaddr"] = sorted(set(a["macaddr"]))
            else:
                # FortiOS wildcard FQDNs may use '*' at either end ('*.example.*'); underscores occur in real host names
                if not re.match(r"^[A-Za-z0-9*_]([A-Za-z0-9\-.*_]{0,251}[A-Za-z0-9*_])?$", a.get("fqdn") or "") or ".." in a["fqdn"]:
                    raise ValueError("invalid fqdn")
                c["fqdn"] = a["fqdn"]
        except (ValueError, KeyError) as e:
            errors.append({"line": None, "column": None, "path": f"resources.addresses.{i}",
                           "message": f"address '{a['name']}': {c['type']} value is missing or invalid ({e})"})
            continue
        out["address"][a["name"]] = {k: v for k, v in c.items() if v not in ("", None) or k == "comment"}
    for key, t in (("address_groups", "address_group"), ("service_groups", "service_group")):
        for i, g in enumerate(raw.get(key, [])):
            dup(t, g["name"], f"resources.{key}.{i}")
            out[t][g["name"]] = {"members": sorted(set(g["members"])), "comment": g.get("comment", "")}
    for i, s in enumerate(raw.get("services", [])):
        dup("service", s["name"], f"resources.services.{i}")
        c = {"protocol": s.get("protocol", "TCP/UDP/SCTP"), "comment": s.get("comment", "")}
        for k in ("tcp", "udp", "udplite", "sctp"):
            if s.get(k):
                c[k] = sorted(set(s[k]))
        for k in ("protocol_number", "icmp_type"):
            if s.get(k) is not None:
                c[k] = s[k]
        if c["protocol"] in PORT_PROTOCOLS and not any(c.get(k) for k in ("tcp", "udp", "udplite", "sctp")):
            errors.append({"line": None, "column": None, "path": f"resources.services.{i}", "message": f"service '{s['name']}': no tcp/udp/sctp ports"})
        out["service"][s["name"]] = c
    for i, r in enumerate(raw.get("static_routes", [])):
        dup("static_route", str(r["id"]), f"resources.static_routes.{i}")
        try:
            dst = to_cidr(r["dst"])
            ipaddress.ip_address(r.get("gateway", "0.0.0.0"))
        except ValueError as e:
            errors.append({"line": None, "column": None, "path": f"resources.static_routes.{i}", "message": f"route {r['id']}: {e}"})
            continue
        c = {"dst": dst, "gateway": r.get("gateway", "0.0.0.0"), "device": r.get("device", ""),
             "distance": r.get("distance", 10), "status": r.get("status", "enable"), "comment": r.get("comment", "")}
        if r.get("sdwan_zone"):
            c["sdwan_zone"] = sorted(set(r["sdwan_zone"]))
        if r.get("blackhole") == "enable":
            c["blackhole"] = "enable"
        out["static_route"][str(r["id"])] = c
    for i, p in enumerate(raw.get("policies", [])):
        dup("policy", str(p["id"]), f"resources.policies.{i}")
        out["policy"][str(p["id"])] = {"name": p.get("name", ""), **{f: sorted(set(p[f])) for f in ("srcintf", "dstintf", "srcaddr", "dstaddr", "service")},
                                       "action": p.get("action", "deny"), "schedule": p.get("schedule", "always"), "nat": p.get("nat", "disable"),
                                       "logtraffic": p.get("logtraffic", "utm"), "status": p.get("status", "enable"), "comments": p.get("comments", "")}
        if p.get("internet_service") == "enable":
            out["policy"][str(p["id"])]["internet_service"] = "enable"
            for k, _ in ISDB_FIELDS:
                out["policy"][str(p["id"])][k] = sorted(set(p.get(k) or []))
        order.append(str(p["id"]))
    for t in ("system_global", "syslog"):
        if raw.get(t):
            out[t] = {"": dict(raw[t])}
    for t, keys in doc.manage.ignored().items():
        for k in sorted(keys & set(out.get(t) or {})):
            errors.append({"line": None, "column": None, "path": "manage.ignore",
                           "message": f"{t} '{k}' is both declared and listed in manage.ignore; remove one of them"})
    return out, order, errors


def declared_types(doc: Document) -> set[str]:
    r = doc.resources
    return {t for k, t in RES_KEYS.items() if (getattr(r, k) not in (None, []))}


# ------------------------------------------------------------------ import (observed canonical -> YAML text)
MODELS = {"address": Address, "address_group": Group, "service": Service, "service_group": Group, "static_route": Route,
          "policy": Policy, "system_global": GlobalSettings, "syslog": Syslog}
SUPPORTED_ADDRESS = ("ipmask", "iprange", "fqdn", "interface-subnet", "mac")


def _item(t: str, k: str, o: dict) -> dict:
    o = dict(o)
    if t == "address" and o.get("type") == "ipmask":
        o.pop("type")  # the default; keeps imports short
    if t in ("policy", "static_route"):
        return {"id": int(k), **o}
    return {"name": k, **o}


def _why_not(t: str, o: dict) -> str | None:
    """Reason an observed object cannot be represented in the desired-state format (checked before the schema)."""
    if t == "address" and o.get("type") not in SUPPORTED_ADDRESS:
        return f"address type '{o.get('type')}' is not supported (supported: {', '.join(SUPPORTED_ADDRESS)})"
    if t == "service" and o.get("proxy") == "enable":
        return "explicit-proxy service (proxy: enable) is not supported"
    if o.get("unsupported"):
        return f"uses {o['unsupported']}, which the IaC module cannot represent"
    return None


def _schema_reason(t: str, item: dict) -> str | None:
    try:
        MODELS[t].model_validate(item)
    except ValidationError as e:
        x = e.errors()[0]
        where = ".".join(str(p) for p in x["loc"])
        return (f"{where}: " if where else "") + x["msg"].removeprefix("Value error, ")
    return None


def import_yaml(state: dict, order: list[str], name: str, types: list[str],
                unsupported_seen: list[str] | None = None) -> tuple[str, list[dict]]:
    """Observed canonical state → desired-state YAML that is guaranteed to parse and render, plus what was skipped.

    Objects the format cannot represent are never emitted in a partial or invalid form: they are left out, listed in
    a header comment and in `manage.ignore`, so later plans neither change them nor report them as drift."""
    skipped: list[dict] = []
    res: dict = {}
    for t in types:
        objs = state.get(t) or {}
        if t in ("system_global", "syslog"):
            if objs.get(""):
                why = _schema_reason(t, objs[""])
                if why:
                    skipped.append({"type": t, "key": "", "reason": why})
                else:
                    res[TYPE_KEYS[t]] = objs[""]
            continue
        items = []
        keys = [k for k in order if k in objs] + sorted(set(objs) - set(order), key=int) if t == "policy" else sorted(objs)
        for k in keys:
            item = _item(t, k, objs[k])
            why = _why_not(t, objs[k]) or _schema_reason(t, item)
            if why:
                skipped.append({"type": t, "key": k, "reason": why})
            else:
                items.append(item)
        if items:
            res[TYPE_KEYS[t]] = items
    doc = {"apiVersion": "iac.sentinelgrid/v1", "kind": "FirewallConfig",
           "metadata": {"name": name, "description": "Imported from the live firewall (read-only GET). Review before committing."},
           "manage": {"prune": [], "ignore": []}, "resources": res}
    # second line of defence: objects that pass the schema but fail rendering (bad subnet, '${' in a comment, ...)
    for _ in range(5):
        try:
            d = Document.model_validate(doc)
        except ValidationError:
            break
        _, _, errs = render(d, {})
        bad = set()
        for e in errs:
            m = re.match(r"resources\.(\w+)\.(\d+)", e.get("path") or "")
            if m and m.group(1) in RES_KEYS and int(m.group(2)) < len(res.get(m.group(1), [])):
                bad.add((m.group(1), int(m.group(2)), e["message"]))
        if not bad:
            break
        for key, idx, msg in sorted(bad, key=lambda x: -x[1]):
            it = res[key].pop(idx)
            t = RES_KEYS[key]
            skipped.append({"type": t, "key": str(it.get("id", it.get("name"))), "reason": msg})
        for key in [k for k, v in res.items() if v == []]:
            res.pop(key)
    doc["manage"]["ignore"] = [f"{x['type']}:{x['key']}" for x in skipped if x["key"]]
    head = []
    if unsupported_seen:
        head.append("# Not imported (unsupported by the IaC module): " + ", ".join(unsupported_seen))
    if skipped:
        head.append(f"# Skipped {len(skipped)} object(s) the IaC format cannot represent; they are listed in manage.ignore so")
        head.append("# plans leave them unchanged and drift checks do not report them:")
        head += [f"#   {x['type']} {x['key'] or ''}: {x['reason']}".replace("\n", " ") for x in skipped]
    text = ("\n".join(head) + "\n" if head else "") + yaml.safe_dump(doc, sort_keys=False, default_flow_style=False, width=140)
    return text, skipped


def to_yaml(state: dict, order: list[str], name: str, types: list[str], unsupported_seen: list[str] | None = None) -> str:
    return import_yaml(state, order, name, types, unsupported_seen)[0]
