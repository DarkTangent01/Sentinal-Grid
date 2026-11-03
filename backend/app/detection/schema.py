"""YAML detection rule model (docs/DETECTION_RULES.md).

A rule selects events from one category of the `events` table, optionally excludes some (filter, allowlist,
business hours), groups them, and alerts when a per-group metric reaches a threshold inside a time frame:

    id: NET-1002
    name: External port scan
    version: 1
    severity: high
    log_source: {category: traffic}
    detection:
      selection: {src_ip: {internal: false}, dst_ip: {internal: true}}
      condition: {group_by: [src_ip], distinct_count: {field: dst_port, threshold: 50}, timeframe: 5m}

Only columns in FIELDS can be referenced and only the operators in OPERATORS exist, so a rule can never inject SQL
(values are always bound parameters; see compiler.py).
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# events columns a rule may reference → ClickHouse type (used for validation and for the test-data structure)
FIELDS: dict[str, str] = {
    "category": "String", "event_type": "String", "event_subtype": "String", "log_id": "String", "firewall_id": "UInt32",
    "firewall_name": "String", "site": "String", "devid": "String", "vdom": "String", "source": "String", "severity": "String",
    "src_ip": "String", "src_port": "Nullable(UInt16)", "dst_ip": "String", "dst_port": "Nullable(UInt16)", "proto": "Nullable(UInt8)",
    "proto_name": "String", "src_intf": "String", "dst_intf": "String", "policy_id": "Nullable(UInt32)", "policy_name": "String",
    "action": "String", "app": "String", "app_cat": "String", "service": "String", "hostname": "String", "url": "String",
    "http_method": "String", "url_category": "String", "sent_bytes": "UInt64", "rcvd_bytes": "UInt64", "sent_pkts": "UInt64",
    "rcvd_pkts": "UInt64", "duration": "UInt32", "nat_src_ip": "String", "nat_dst_ip": "String", "dns_qname": "String",
    "dns_qtype": "String", "dns_rcode": "String", "dns_qname_len": "UInt16", "dns_entropy": "Float32", "threat": "String",
    "user": "String", "msg": "String", "src_country": "String", "dst_country": "String", "src_mac": "String", "src_name": "String",
    "ti_match": "String", "ti_category": "String",
}
NUMERIC = {k for k, t in FIELDS.items() if re.search(r"Int|Float", t)}
IP_FIELDS = {"src_ip", "dst_ip", "nat_src_ip", "nat_dst_ip"}
OPERATORS = ("eq", "ne", "in", "not_in", "contains", "startswith", "endswith", "regex", "gt", "gte", "lt", "lte", "cidr", "not_cidr",
             "internal", "exists")
CATEGORIES = ("traffic", "dns", "web", "security", "system")
SEVERITIES = ("informational", "low", "medium", "high", "critical")
WEEKDAYS = {"mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6, "sun": 7}
ID_RE = re.compile(r"^[A-Z][A-Z0-9]{1,7}-\d{3,5}$")


def parse_duration(v: str | int) -> int:
    """'90s' / '5m' / '2h' / '1d' / 300 → seconds (1 s to 7 d)."""
    if isinstance(v, int):
        n = v
    else:
        m = re.fullmatch(r"\s*(\d+)\s*([smhd])\s*", str(v))
        if not m:
            raise ValueError(f"invalid duration {v!r}: use e.g. 60s, 5m, 1h")
        n = int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
    if not 1 <= n <= 7 * 86400:
        raise ValueError("duration must be between 1 second and 7 days")
    return n


def rule_key(rule_id: str) -> str:
    """NET-1002 → yml_net_1002 (the alert_rules key; prefix keeps YAML rules apart from built-in and custom rules)."""
    return "yml_" + rule_id.lower().replace("-", "_")


def _check_field(name: str) -> str:
    if name not in FIELDS:
        raise ValueError(f"unknown field {name!r}; allowed: {', '.join(sorted(FIELDS))}")
    return name


def _check_clause(field: str, spec: Any) -> None:
    _check_field(field)
    if isinstance(spec, dict):
        if not spec:
            raise ValueError(f"{field}: empty operator map")
        for op, val in spec.items():
            if op not in OPERATORS:
                raise ValueError(f"{field}: unknown operator {op!r}; allowed: {', '.join(OPERATORS)}")
            if op in ("internal", "exists") and not isinstance(val, bool):
                raise ValueError(f"{field}: {op} takes true / false")
            if op in ("in", "not_in", "cidr", "not_cidr") and not (isinstance(val, list) and val):
                raise ValueError(f"{field}: {op} takes a non-empty list")
            if op in ("cidr", "not_cidr", "internal") and field not in IP_FIELDS:
                raise ValueError(f"{field}: {op} only applies to IP fields ({', '.join(sorted(IP_FIELDS))})")
            if op in ("gt", "gte", "lt", "lte") and (field not in NUMERIC or not isinstance(val, (int, float))):
                raise ValueError(f"{field}: {op} needs a numeric field and a number")
            if op == "regex":
                try:
                    re.compile(str(val))
                except re.error as e:
                    raise ValueError(f"{field}: invalid regex: {e}")
                if len(str(val)) > 300:
                    raise ValueError(f"{field}: regex longer than 300 characters")
            if op in ("cidr", "not_cidr"):
                import ipaddress
                for c in val:
                    try:
                        ipaddress.ip_network(str(c), strict=False)
                    except ValueError:
                        raise ValueError(f"{field}: invalid CIDR {c!r}")
    elif isinstance(spec, list):
        if not spec:
            raise ValueError(f"{field}: empty list")
    elif not isinstance(spec, (str, int, float, bool)):
        raise ValueError(f"{field}: value must be a scalar, a list or an operator map")


Selection = dict[str, Any]


class Metric(BaseModel):
    model_config = ConfigDict(extra="forbid")
    field: str
    threshold: float = Field(gt=0)

    @field_validator("field")
    @classmethod
    def _f(cls, v):
        return _check_field(v)


class Condition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    group_by: list[str] = Field(min_length=1, max_length=4)
    timeframe: int
    count: int | None = Field(None, ge=1)
    distinct_count: Metric | None = None
    sum: Metric | None = None

    @field_validator("timeframe", mode="before")
    @classmethod
    def _tf(cls, v):
        return parse_duration(v)

    @field_validator("group_by")
    @classmethod
    def _gb(cls, v):
        return [_check_field(x) for x in v]

    @model_validator(mode="after")
    def _one_metric(self):
        n = sum(x is not None for x in (self.count, self.distinct_count, self.sum))
        if n != 1:
            raise ValueError("condition needs exactly one of: count, distinct_count, sum")
        if self.sum and self.sum.field not in NUMERIC:
            raise ValueError("sum needs a numeric field")
        return self

    @property
    def threshold(self) -> float:
        return float(self.count if self.count is not None else (self.distinct_count or self.sum).threshold)  # type: ignore[union-attr]


class OutsideHours(BaseModel):
    """Match only events outside business hours (in a time zone); days are business days."""
    model_config = ConfigDict(extra="forbid")
    start: str = "08:00"
    end: str = "20:00"
    days: list[str] = Field(default_factory=lambda: ["mon", "tue", "wed", "thu", "fri"])
    timezone: str = "UTC"

    @field_validator("start", "end")
    @classmethod
    def _hhmm(cls, v):
        if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", v):
            raise ValueError("times are HH:MM")
        return v

    @field_validator("days")
    @classmethod
    def _days(cls, v):
        bad = [d for d in v if d.lower()[:3] not in WEEKDAYS]
        if bad:
            raise ValueError(f"unknown day(s): {bad}")
        return [d.lower()[:3] for d in v]

    @field_validator("timezone")
    @classmethod
    def _tz(cls, v):
        try:
            ZoneInfo(v)
        except (ZoneInfoNotFoundError, ValueError):
            raise ValueError(f"unknown time zone {v!r}")
        return v

    def minutes(self, which: str) -> int:
        h, m = getattr(self, which).split(":")
        return int(h) * 60 + int(m)


class Detection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    selection: Selection | list[Selection] = Field(default_factory=dict)
    filter: Selection | list[Selection] | None = None
    condition: Condition
    outside_hours: OutsideHours | None = None

    @field_validator("selection", "filter")
    @classmethod
    def _sel(cls, v):
        if v is None:
            return v
        for block in (v if isinstance(v, list) else [v]):
            if not isinstance(block, dict):
                raise ValueError("selection / filter blocks are field → value maps")
            for f, spec in block.items():
                _check_clause(f, spec)
        return v


class LogSource(BaseModel):
    model_config = ConfigDict(extra="forbid")
    category: Literal["traffic", "dns", "web", "security", "system"]
    event_type: str | None = None
    product: str | None = None          # documentation only (e.g. "fortigate", "cisco")


class Mitre(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tactic: str = Field(pattern=r"^TA\d{4}$")
    techniques: list[str] = Field(default_factory=list)

    @field_validator("techniques")
    @classmethod
    def _t(cls, v):
        for t in v:
            if not re.fullmatch(r"T\d{4}(\.\d{3})?", t):
                raise ValueError(f"invalid ATT&CK technique {t!r}")
        return v


class RuleTest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    events: list[dict[str, Any]] = Field(min_length=1, max_length=200)
    expect_alerts: int = Field(ge=0)
    expect_groups: list[dict[str, Any]] = Field(default_factory=list)
    now: datetime | None = None          # evaluation time for this case (default: runner.TEST_NOW)


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    name: str = Field(min_length=3, max_length=128)
    description: str = Field(min_length=3, max_length=2000)
    version: int = Field(ge=1)
    status: Literal["enabled", "disabled", "experimental"] = "enabled"
    severity: Literal["informational", "low", "medium", "high", "critical"]
    category: str = Field(max_length=64)
    log_source: LogSource
    detection: Detection
    allowlist: dict[str, list[Any]] = Field(default_factory=dict)
    explanation: str = Field("", max_length=500)
    data_sources: list[str] = Field(min_length=1)
    falsepositives: list[str] = Field(min_length=1)
    investigation: list[str] = Field(min_length=1)
    mitre: Mitre | None = None
    tests: list[RuleTest] = Field(min_length=1)
    tags: list[str] = Field(default_factory=list)

    @field_validator("id")
    @classmethod
    def _id(cls, v):
        if not ID_RE.fullmatch(v):
            raise ValueError("id must look like NET-1002 (letters, dash, 3-5 digits)")
        return v

    @field_validator("allowlist")
    @classmethod
    def _allow(cls, v):
        for f, vals in v.items():
            _check_field(f)
            if not isinstance(vals, list) or not vals:
                raise ValueError(f"allowlist {f}: a non-empty list")
        return v

    @property
    def key(self) -> str:
        return rule_key(self.id)

    def mitre_dict(self) -> dict:
        return {"tactic": self.mitre.tactic, "techniques": self.mitre.techniques} if self.mitre else {}
