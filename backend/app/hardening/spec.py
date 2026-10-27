"""Hardening plan specification. Plans describe FortiOS objects; the SIEM only renders them as CLI for an engineer
to review and apply. Nothing here talks to a firewall in write mode."""
import ipaddress
import re

from pydantic import BaseModel, Field, field_validator, model_validator

# FortiOS object names: no quotes/backslashes/control chars. Limits follow FortiOS 7.x defaults.
_NAME = re.compile(r'^[^"\\\x00-\x1f\x7f]+$')
OBJ_NAME_MAX = 79
POLICY_NAME_MAX = 35
PORTS = re.compile(r"^\d{1,5}(-\d{1,5})?$")
# predefined FortiOS services commonly referenced by groups/policies
PREDEFINED_SERVICES = {"ALL", "ALL_TCP", "ALL_UDP", "ALL_ICMP", "HTTP", "HTTPS", "DNS", "NTP", "SSH", "SMTP", "SMTPS",
                       "IMAP", "IMAPS", "POP3", "POP3S", "FTP", "RDP", "SNMP", "PING", "TELNET", "SAMBA", "LDAP", "KERBEROS"}
PREDEFINED_ADDRESSES = {"all", "none"}


def _text(v: str) -> str:
    """Free text (comments) is emitted inside a quoted CLI value: a quote, backslash or newline would end the value
    and turn the rest into CLI commands run by whoever pastes the script."""
    if v and not _NAME.match(v):
        raise ValueError("text must not contain quotes, backslashes or control characters")
    return v


def _name(v: str, maxlen: int = OBJ_NAME_MAX) -> str:
    v = v.strip()
    if not v or len(v) > maxlen or not _NAME.match(v):
        raise ValueError(f"invalid name (1-{maxlen} chars, no quotes or backslashes)")
    return v


class Address(BaseModel):
    name: str
    subnet: str | None = None  # IPv4 host or CIDR
    fqdn: str | None = None
    comment: str = Field("", max_length=255)
    _c = field_validator("comment")(lambda cls, v: _text(v))

    _n = field_validator("name")(lambda cls, v: _name(v))

    @model_validator(mode="after")
    def _one(self):
        if bool(self.subnet) == bool(self.fqdn):
            raise ValueError(f"address {self.name}: set exactly one of subnet or fqdn")
        if self.subnet:
            net = ipaddress.ip_network(self.subnet.strip(), strict=False)
            if net.version != 4:
                raise ValueError(f"address {self.name}: only IPv4 is supported (use address6 manually)")
            self.subnet = str(net)
        if self.fqdn and not re.match(r"^[A-Za-z0-9*]([A-Za-z0-9\-.*]{0,251}[A-Za-z0-9])?$", self.fqdn.strip()):
            raise ValueError(f"address {self.name}: invalid fqdn")
        return self


class Group(BaseModel):
    name: str
    members: list[str] = Field(min_length=1, max_length=600)
    comment: str = Field("", max_length=255)
    _c = field_validator("comment")(lambda cls, v: _text(v))

    _n = field_validator("name")(lambda cls, v: _name(v))

    @field_validator("members")
    @classmethod
    def _m(cls, v):
        return [_name(m) for m in v]


class Service(BaseModel):
    name: str
    tcp: list[str] = Field(default_factory=list)  # "443", "8000-8080"
    udp: list[str] = Field(default_factory=list)
    comment: str = Field("", max_length=255)
    _c = field_validator("comment")(lambda cls, v: _text(v))

    _n = field_validator("name")(lambda cls, v: _name(v))

    @field_validator("tcp", "udp")
    @classmethod
    def _ports(cls, v):
        out = []
        for p in v:
            p = str(p).strip()
            if not PORTS.match(p):
                raise ValueError(f"invalid port '{p}' (use 443 or 8000-8080)")
            lo, _, hi = p.partition("-")
            lo_i, hi_i = int(lo), int(hi or lo)
            if not (1 <= lo_i <= hi_i <= 65535):
                raise ValueError(f"port out of range '{p}'")
            out.append(p)
        return out

    @model_validator(mode="after")
    def _any(self):
        if not self.tcp and not self.udp:
            raise ValueError(f"service {self.name}: at least one TCP or UDP port is required")
        if self.name.upper() in PREDEFINED_SERVICES:
            raise ValueError(f"service {self.name}: name collides with a predefined FortiOS service")
        return self


class UrlEntry(BaseModel):
    url: str = Field(min_length=1, max_length=511)
    type: str = Field("wildcard", pattern=r"^(simple|wildcard|regex)$")
    action: str = Field("allow", pattern=r"^(allow|block|monitor|exempt)$")

    @field_validator("url")
    @classmethod
    def _url(cls, v):
        v = v.strip()
        if '"' in v or "\\" in v or " " in v or any(ord(c) < 32 for c in v):
            raise ValueError(f"invalid url pattern '{v}' (no quotes, spaces or backslashes; for regex use [.] instead of \\.)")
        if v.lower().startswith(("http://", "https://")):
            raise ValueError("enter the URL without http:// or https:// (FortiGate matches host/path)")
        return v


class UrlFilter(BaseModel):
    table_id: int = Field(ge=1, le=4096)
    name: str
    entries: list[UrlEntry] = Field(min_length=1, max_length=2000)
    block_others: bool = False  # append "*" wildcard block so only listed URLs are reachable
    profile_name: str | None = None  # create/update a web-filter profile that uses this table

    _n = field_validator("name")(lambda cls, v: _name(v, 35))

    @field_validator("profile_name")
    @classmethod
    def _p(cls, v):
        return _name(v, 47) if v else v


class Policy(BaseModel):
    name: str
    srcintf: list[str] = Field(min_length=1)
    dstintf: list[str] = Field(min_length=1)
    srcaddr: list[str] = Field(default_factory=lambda: ["all"])
    dstaddr: list[str] = Field(default_factory=lambda: ["all"])
    service: list[str] = Field(min_length=1)
    action: str = Field("accept", pattern=r"^(accept|deny)$")
    nat: bool = True
    schedule: str = "always"
    webfilter_profile: str | None = None
    ssl_ssh_profile: str = "certificate-inspection"
    logtraffic: str = Field("all", pattern=r"^(all|utm|disable)$")
    comments: str = Field("", max_length=1023)

    _t = field_validator("comments")(lambda cls, v: _text(v))
    _s = field_validator("schedule", "ssl_ssh_profile")(lambda cls, v: _name(v))
    _w = field_validator("webfilter_profile")(lambda cls, v: _name(v, 47) if v else v)

    @field_validator("name")
    @classmethod
    def _pn(cls, v):
        return _name(v, POLICY_NAME_MAX)

    @field_validator("srcintf", "dstintf", "srcaddr", "dstaddr", "service")
    @classmethod
    def _names(cls, v):
        return [_name(x) for x in v]


class PlanSpec(BaseModel):
    vdom: str | None = None  # emit "config vdom / edit <vdom>" when the firewall runs multiple VDOMs

    _v = field_validator("vdom")(lambda cls, v: _name(v, 31) if v else v)
    addresses: list[Address] = Field(default_factory=list)
    address_groups: list[Group] = Field(default_factory=list)
    services: list[Service] = Field(default_factory=list)
    service_groups: list[Group] = Field(default_factory=list)
    url_filters: list[UrlFilter] = Field(default_factory=list)
    policies: list[Policy] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique(self):
        for label, items in (("address", [*self.addresses, *self.address_groups]),
                             ("service", [*self.services, *self.service_groups]),
                             ("policy", self.policies), ("url filter", self.url_filters)):
            names = [i.name for i in items]
            dup = {n for n in names if names.count(n) > 1}
            if dup:
                raise ValueError(f"duplicate {label} names: {sorted(dup)}")
        ids = [u.table_id for u in self.url_filters]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate URL filter table ids")
        return self

    def external_references(self) -> dict[str, set[str]]:
        """Names referenced but not defined in this plan: they must already exist on the firewall."""
        addr_defined = {a.name for a in self.addresses} | {g.name for g in self.address_groups} | PREDEFINED_ADDRESSES
        svc_defined = {s.name for s in self.services} | {g.name for g in self.service_groups}
        prof_defined = {u.profile_name for u in self.url_filters if u.profile_name}
        refs = {"address": set(), "service": set(), "webfilter_profile": set(), "interface": set()}
        for g in self.address_groups:
            refs["address"] |= set(g.members) - addr_defined
        for g in self.service_groups:
            refs["service"] |= {m for m in g.members if m not in svc_defined and m.upper() not in PREDEFINED_SERVICES}
        for p in self.policies:
            refs["address"] |= (set(p.srcaddr) | set(p.dstaddr)) - addr_defined
            refs["service"] |= {m for m in p.service if m not in svc_defined and m.upper() not in PREDEFINED_SERVICES}
            if p.webfilter_profile and p.webfilter_profile not in prof_defined:
                refs["webfilter_profile"].add(p.webfilter_profile)
            refs["interface"] |= set(p.srcintf) | set(p.dstintf)
        return refs
