"""PostgreSQL models: inventory, credentials (encrypted), users, rules, alerts, audit, retention."""
from datetime import datetime, timezone

from sqlalchemy import JSON, BigInteger, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="analyst")  # admin | analyst
    timezone: Mapped[str] = mapped_column(String(64), default="UTC")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # bumped on logout, password change, role change or disable; session JWTs carry it and stop working when it moves
    session_version: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    iac_roles: Mapped[list] = mapped_column(JSON, default=list)  # IaC: editor | approver | deployer | admin (viewer is implicit)
    tacacs_roles: Mapped[list] = mapped_column(JSON, default=list)  # TACACS+: auditor | operator | policy_admin | approver
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # product access (app/products.py): "grid" (SIEM) and / or "nms" (network monitoring); admins have both implicitly.
    # New accounts get none until an administrator assigns them; migration 0020 gave existing accounts both.
    products: Mapped[list] = mapped_column(JSON, default=list)
    default_product: Mapped[str | None] = mapped_column(String(8), nullable=True)  # skip the product selector at sign-in
    # NMS site scope (app/products.py site_allowed): empty = every site; administrators always see every site
    sites: Mapped[list] = mapped_column(JSON, default=list)


class Firewall(Base):
    __tablename__ = "firewalls"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    host: Mapped[str] = mapped_column(String(255))
    vendor: Mapped[str] = mapped_column(String(16), default="fortinet")  # fortinet | paloalto
    log_tz: Mapped[str] = mapped_column(String(64), default="UTC")  # IANA zone of local log times (PAN-OS logs carry none)
    https_port: Mapped[int] = mapped_column(Integer, default=443)
    api_method: Mapped[str] = mapped_column(String(16), default="token")  # token (Bearer header)
    token_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True)
    ca_bundle_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    vdom: Mapped[str] = mapped_column(String(64), default="root")
    site: Mapped[str] = mapped_column(String(128), default="")
    tags: Mapped[list] = mapped_column(JSON, default=list)
    poll_interval_seconds: Mapped[int] = mapped_column(Integer, default=60)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    # identity (detected from /monitor/system/status)
    serial: Mapped[str | None] = mapped_column(String(64), nullable=True, unique=True)
    hostname: Mapped[str | None] = mapped_column(String(128), nullable=True)
    fortios_version_declared: Mapped[str | None] = mapped_column(String(32), nullable=True)
    fortios_version_detected: Mapped[str | None] = mapped_column(String(32), nullable=True)
    model: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # syslog source addresses that map to this device (in addition to devid=serial)
    syslog_source_ips: Mapped[list] = mapped_column(JSON, default=list)
    # API log pull (best effort, optional)
    api_log_pull: Mapped[bool] = mapped_column(Boolean, default=False)
    api_log_device: Mapped[str] = mapped_column(String(16), default="disk")  # memory|disk|fortianalyzer
    api_log_cursor: Mapped[dict] = mapped_column(JSON, default=dict)
    # health — API connectivity and log ingestion are tracked separately
    api_status: Mapped[str] = mapped_column(String(16), default="unknown")  # ok|auth_error|unreachable|error|unknown
    api_last_success: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    api_last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    api_last_error_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    capabilities: Mapped[dict] = mapped_column(JSON, default=dict)
    health: Mapped[dict] = mapped_column(JSON, default=dict)  # cpu, mem, sessions, uptime, interfaces
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class AlertRule(Base):
    __tablename__ = "alert_rules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    mitre: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        UniqueConstraint("rule_key", "group_key", "open_seq", name="uq_alert_group"),
        Index("ix_alerts_dst_ip", "dst_ip"),                     # src OR dst lookups (investigate, hunt)
        Index("ix_alerts_first_seen", "first_seen"),             # NMS alert analytics by day
        Index("ix_alerts_status_last_seen", "status", "last_seen"),
        # product filters use prefix LIKE ('switch_%', '<switch id>:%'): only pattern-ops indexes serve that on
        # PostgreSQL with a non-C collation (other databases ignore postgresql_ops)
        Index("ix_alerts_rule_key_pattern", "rule_key", postgresql_ops={"rule_key": "varchar_pattern_ops"}),
        Index("ix_alerts_group_key_pattern", "group_key", postgresql_ops={"group_key": "varchar_pattern_ops"}),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_key: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(128))
    severity: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default="new", index=True)  # new|investigating|resolved|suppressed
    group_key: Mapped[str] = mapped_column(String(512))
    open_seq: Mapped[int] = mapped_column(Integer, default=0)  # increments each time a resolved group re-opens
    src_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    firewall_ids: Mapped[list] = mapped_column(JSON, default=list)
    sites: Mapped[list] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    event_count: Mapped[int] = mapped_column(BigInteger, default=0)
    explanation: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    event_filter: Mapped[dict] = mapped_column(JSON, default=dict)  # explorer filter for related events
    assignee: Mapped[str | None] = mapped_column(String(64), nullable=True)
    notes: Mapped[str] = mapped_column(Text, default="")
    mitre: Mapped[dict] = mapped_column(JSON, default=dict)  # {tactic, tactic_name, techniques: [...]}
    incident_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    asset_criticality: Mapped[str] = mapped_column(String(16), default="")
    base_severity: Mapped[str] = mapped_column(String(16), default="")
    disposition: Mapped[str | None] = mapped_column(String(24), nullable=True)  # true_positive | false_positive | benign
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Suppression(Base):
    __tablename__ = "alert_suppressions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_key: Mapped[str] = mapped_column(String(64))
    group_key: Mapped[str] = mapped_column(String(512))
    until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reason: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RetentionPolicy(Base):
    __tablename__ = "retention_policies"
    category: Mapped[str] = mapped_column(String(16), primary_key=True)  # traffic|dns|web|security|system
    days: Mapped[int] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class RetentionRun(Base):
    __tablename__ = "retention_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    category: Mapped[str] = mapped_column(String(16))
    cutoff: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    partitions_dropped: Mapped[list] = mapped_column(JSON, default=list)
    rows_dropped: Mapped[int] = mapped_column(BigInteger, default=0)
    status: Mapped[str] = mapped_column(String(16))
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    username: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(255), default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    client_ip: Mapped[str] = mapped_column(String(64), default="")
    success: Mapped[bool] = mapped_column(Boolean, default=True)


class IngestStat(Base):
    """Per-firewall, per-source ingestion health (separate from API connectivity)."""
    __tablename__ = "ingest_stats"
    firewall_id: Mapped[int] = mapped_column(ForeignKey("firewalls.id", ondelete="CASCADE"), primary_key=True)
    source: Mapped[str] = mapped_column(String(16), primary_key=True)  # syslog|api_log|demo
    last_event_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_ingest_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lag_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    events_total: Mapped[int] = mapped_column(BigInteger, default=0)
    parse_errors: Mapped[int] = mapped_column(BigInteger, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)


class HardeningPlan(Base):
    """Firewall hardening plan. Rendered to FortiOS CLI for manual review/apply; never pushed by the SIEM."""
    __tablename__ = "hardening_plans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(Text, default="")
    firewall_id: Mapped[int | None] = mapped_column(ForeignKey("firewalls.id", ondelete="SET NULL"), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="draft")  # draft | ready | exported
    spec: Mapped[dict] = mapped_column(JSON, default=dict)
    last_check: Mapped[dict] = mapped_column(JSON, default=dict)
    created_by: Mapped[str] = mapped_column(String(64))
    updated_by: Mapped[str] = mapped_column(String(64))
    last_exported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


# ---------------------------------------------------------------- policy analytics (read-only collection)
class FirewallPolicy(Base):
    """Current (or last-known) configuration of a firewall policy, in evaluation order (seq)."""
    __tablename__ = "firewall_policies"
    __table_args__ = (UniqueConstraint("firewall_id", "vdom", "policyid", name="uq_fw_policy"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    firewall_id: Mapped[int] = mapped_column(ForeignKey("firewalls.id", ondelete="CASCADE"), index=True)
    vdom: Mapped[str] = mapped_column(String(64), default="root")
    policyid: Mapped[int] = mapped_column(Integer)
    uuid: Mapped[str] = mapped_column(String(64), default="")
    seq: Mapped[int] = mapped_column(Integer, default=0)
    name: Mapped[str] = mapped_column(String(128), default="")
    status: Mapped[str] = mapped_column(String(16), default="enable")
    action: Mapped[str] = mapped_column(String(16), default="deny")
    logtraffic: Mapped[str] = mapped_column(String(16), default="utm")
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    config_hash: Mapped[str] = mapped_column(String(32), default="")
    uuid_history: Mapped[list] = mapped_column(JSON, default=list)  # [{uuid, first_seen}] to detect policy-ID reuse
    analysis: Mapped[dict] = mapped_column(JSON, default=dict)  # latest shadow-analysis status for this policy
    assessment: Mapped[dict] = mapped_column(JSON, default=dict)  # latest usage assessment (default window)
    source: Mapped[str] = mapped_column(String(16), default="api")  # api | demo
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class PolicyConfigChange(Base):
    __tablename__ = "policy_config_changes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    firewall_id: Mapped[int] = mapped_column(ForeignKey("firewalls.id", ondelete="CASCADE"), index=True)
    vdom: Mapped[str] = mapped_column(String(64))
    policyid: Mapped[int] = mapped_column(Integer, index=True)
    uuid: Mapped[str] = mapped_column(String(64), default="")
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    change_type: Mapped[str] = mapped_column(String(16))  # created | modified | reordered | deleted | reused
    changed_fields: Mapped[list] = mapped_column(JSON, default=list)
    old_config: Mapped[dict] = mapped_column(JSON, default=dict)
    new_config: Mapped[dict] = mapped_column(JSON, default=dict)


class PolicyObjectSet(Base):
    """Address/service/zone objects used to expand policies (latest collection per firewall/VDOM)."""
    __tablename__ = "policy_object_sets"
    firewall_id: Mapped[int] = mapped_column(ForeignKey("firewalls.id", ondelete="CASCADE"), primary_key=True)
    vdom: Mapped[str] = mapped_column(String(64), primary_key=True)
    objects: Mapped[dict] = mapped_column(JSON, default=dict)
    errors: Mapped[dict] = mapped_column(JSON, default=dict)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PolicySync(Base):
    """Per firewall/VDOM policy collection health (separate from monitor polling and log ingestion)."""
    __tablename__ = "policy_syncs"
    firewall_id: Mapped[int] = mapped_column(ForeignKey("firewalls.id", ondelete="CASCADE"), primary_key=True)
    vdom: Mapped[str] = mapped_column(String(64), primary_key=True)
    status: Mapped[str] = mapped_column(String(16), default="never")  # ok | partial | error | never
    last_attempt: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_success: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    counters_supported: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    policies: Mapped[int] = mapped_column(Integer, default=0)
    details: Mapped[dict] = mapped_column(JSON, default=dict)


class PolicyAnalysisRun(Base):
    __tablename__ = "policy_analysis_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    firewall_id: Mapped[int] = mapped_column(ForeignKey("firewalls.id", ondelete="CASCADE"), index=True)
    vdom: Mapped[str] = mapped_column(String(64))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="running")
    policies: Mapped[int] = mapped_column(Integer, default=0)
    findings: Mapped[int] = mapped_column(Integer, default=0)
    config_fingerprint: Mapped[str] = mapped_column(String(32), default="")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class ShadowFinding(Base):
    __tablename__ = "shadow_findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("policy_analysis_runs.id", ondelete="CASCADE"), index=True)
    firewall_id: Mapped[int] = mapped_column(ForeignKey("firewalls.id", ondelete="CASCADE"), index=True)
    vdom: Mapped[str] = mapped_column(String(64))
    earlier_policyid: Mapped[int] = mapped_column(Integer)
    later_policyid: Mapped[int] = mapped_column(Integer, index=True)
    classification: Mapped[str] = mapped_column(String(24), index=True)
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[str] = mapped_column(String(16))
    explanation: Mapped[str] = mapped_column(Text)
    data: Mapped[dict] = mapped_column(JSON, default=dict)  # names, seqs, dimensions, evidence, assumptions, verification


class PolicyAssessmentChange(Base):
    __tablename__ = "policy_assessment_changes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    firewall_id: Mapped[int] = mapped_column(ForeignKey("firewalls.id", ondelete="CASCADE"), index=True)
    vdom: Mapped[str] = mapped_column(String(64))
    policyid: Mapped[int] = mapped_column(Integer, index=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    state: Mapped[str] = mapped_column(String(24))
    method: Mapped[str] = mapped_column(String(64))
    confidence: Mapped[str] = mapped_column(String(16))
    window_days: Mapped[int] = mapped_column(Integer)


# ---------------------------------------------------------------- next-gen SIEM features
class TiFeed(Base):
    __tablename__ = "ti_feeds"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    url: Mapped[str] = mapped_column(String(1024), default="")  # empty for the manual list
    kind: Mapped[str] = mapped_column(String(16), default="ip")  # ip | cidr | domain | mixed | manual
    category: Mapped[str] = mapped_column(String(48), default="malicious")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    refresh_hours: Mapped[int] = mapped_column(Integer, default=6)
    last_fetch: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_success: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[str] = mapped_column(Text, default="never fetched")
    indicator_count: Mapped[int] = mapped_column(Integer, default=0)


class TiIndicator(Base):
    __tablename__ = "ti_indicators"
    __table_args__ = (UniqueConstraint("feed_id", "indicator", name="uq_ti_feed_indicator"),)
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True)
    feed_id: Mapped[int] = mapped_column(ForeignKey("ti_feeds.id", ondelete="CASCADE"), index=True)
    indicator: Mapped[str] = mapped_column(String(255), index=True)
    type: Mapped[str] = mapped_column(String(8))  # ip | cidr | domain
    note: Mapped[str] = mapped_column(String(255), default="")
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Asset(Base):
    """Learned from traffic (FortiGate device identification) and/or maintained manually."""
    __tablename__ = "assets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    hostname: Mapped[str] = mapped_column(String(255), default="")
    mac: Mapped[str] = mapped_column(String(32), default="")
    os: Mapped[str] = mapped_column(String(64), default="")
    last_user: Mapped[str] = mapped_column(String(128), default="")
    users: Mapped[list] = mapped_column(JSON, default=list)
    firewall_ids: Mapped[list] = mapped_column(JSON, default=list)
    criticality: Mapped[str] = mapped_column(String(16), default="normal")  # low | normal | high | critical
    tags: Mapped[list] = mapped_column(JSON, default=list)
    owner: Mapped[str] = mapped_column(String(128), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(16), default="observed")  # observed | manual
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class Incident(Base):
    """Correlated group of alerts about one entity, managed as a case."""
    __tablename__ = "incidents"
    __table_args__ = (Index("ix_incidents_category_created", "category", "created_at"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(255))
    entity_type: Mapped[str] = mapped_column(String(16))  # ip | user | firewall
    entity: Mapped[str] = mapped_column(String(255), index=True)
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)  # open | in_progress | resolved | closed
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    score: Mapped[int] = mapped_column(Integer, default=0)
    tactics: Mapped[list] = mapped_column(JSON, default=list)
    techniques: Mapped[list] = mapped_column(JSON, default=list)
    rule_keys: Mapped[list] = mapped_column(JSON, default=list)
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    asset_criticality: Mapped[str] = mapped_column(String(16), default="")
    assignee: Mapped[str | None] = mapped_column(String(64), nullable=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    closure_reason: Mapped[str | None] = mapped_column(String(24), nullable=True)  # true_positive | false_positive | benign | duplicate
    evidence: Mapped[list] = mapped_column(JSON, default=list)  # [{type, ref, label, added_by, at}]
    tasks: Mapped[list] = mapped_column(JSON, default=list)  # [{id, text, done, done_by, done_at, added_by}]
    linked: Mapped[list] = mapped_column(JSON, default=list)  # related incident ids
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    sla_ack_due: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sla_resolve_due: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    # WAN / ISP incidents (category "wan", app/wan.py) share the case workflow; security incidents keep category "security"
    category: Mapped[str] = mapped_column(String(16), default="security", server_default="security", index=True)
    site: Mapped[str] = mapped_column(String(128), default="", server_default="")
    isp_name: Mapped[str] = mapped_column(String(128), default="", server_default="")
    isp_link_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    correlation_key: Mapped[str] = mapped_column(String(255), default="", server_default="", index=True)
    probable_cause: Mapped[str] = mapped_column(Text, default="", server_default="")        # evidence-based hint, never a conclusion
    root_cause_category: Mapped[str | None] = mapped_column(String(48), nullable=True)      # confirmed by a person
    root_cause_detail: Mapped[str] = mapped_column(Text, default="", server_default="")


class IncidentComment(Base):
    __tablename__ = "incident_comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    author: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(16), default="comment")  # comment | status | system | evidence
    body: Mapped[str] = mapped_column(Text)


class NotificationChannel(Base):
    __tablename__ = "notification_channels"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    type: Mapped[str] = mapped_column(String(16))  # email | slack | teams | webhook
    config: Mapped[dict] = mapped_column(JSON, default=dict)  # non-secret settings
    secret_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)  # webhook URL / SMTP password (Fernet)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class NotificationRule(Base):
    __tablename__ = "notification_rules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64))
    channel_id: Mapped[int] = mapped_column(ForeignKey("notification_channels.id", ondelete="CASCADE"))
    event_types: Mapped[list] = mapped_column(JSON, default=list)  # alert.created, incident.created, incident.escalated, report.ready, search.threshold
    min_severity: Mapped[str] = mapped_column(String(16), default="high")
    rule_keys: Mapped[list] = mapped_column(JSON, default=list)  # empty = all
    quiet_start: Mapped[str | None] = mapped_column(String(5), nullable=True)  # "22:00" (critical still sent)
    quiet_end: Mapped[str | None] = mapped_column(String(5), nullable=True)
    quiet_tz: Mapped[str] = mapped_column(String(64), default="UTC")
    dedupe_minutes: Mapped[int] = mapped_column(Integer, default=30)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class NotificationOutbox(Base):
    __tablename__ = "notification_outbox"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    rule_id: Mapped[int | None] = mapped_column(ForeignKey("notification_rules.id", ondelete="SET NULL"), nullable=True)
    channel_id: Mapped[int] = mapped_column(ForeignKey("notification_channels.id", ondelete="CASCADE"))
    event_type: Mapped[str] = mapped_column(String(32))
    dedupe_key: Mapped[str] = mapped_column(String(255), index=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)  # pending | sent | failed | suppressed
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class SavedSearch(Base):
    __tablename__ = "saved_searches"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    query: Mapped[str] = mapped_column(Text, default="")
    range: Mapped[str] = mapped_column(String(8), default="24h")
    owner: Mapped[str] = mapped_column(String(64))
    shared: Mapped[bool] = mapped_column(Boolean, default=True)
    schedule: Mapped[str] = mapped_column(String(16), default="none")  # none | hourly | daily
    threshold: Mapped[int] = mapped_column(Integer, default=1)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    last_run: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_count: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ReportDefinition(Base):
    __tablename__ = "report_definitions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    period: Mapped[str] = mapped_column(String(8), default="daily")  # daily | weekly
    sections: Mapped[list] = mapped_column(JSON, default=list)
    channel_ids: Mapped[list] = mapped_column(JSON, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    send_hour: Mapped[int] = mapped_column(Integer, default=7)  # local hour in tz
    tz: Mapped[str] = mapped_column(String(64), default="UTC")
    last_run: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str] = mapped_column(String(64))


class ReportRun(Base):
    __tablename__ = "report_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    definition_id: Mapped[int | None] = mapped_column(ForeignKey("report_definitions.id", ondelete="SET NULL"), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(128))
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    html: Mapped[str] = mapped_column(Text)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)


class ConfigSnapshot(Base):
    """Read-only snapshot of selected FortiGate configuration tables for drift detection."""
    __tablename__ = "config_snapshots"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    firewall_id: Mapped[int] = mapped_column(ForeignKey("firewalls.id", ondelete="CASCADE"), index=True)
    vdom: Mapped[str] = mapped_column(String(64))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    config_hash: Mapped[str] = mapped_column(String(32))
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    changes: Mapped[list] = mapped_column(JSON, default=list)  # diff vs previous snapshot
    risks: Mapped[list] = mapped_column(JSON, default=list)
    errors: Mapped[dict] = mapped_column(JSON, default=dict)


# ------------------------------------------------------------------ hunting, watchlists, workbooks, automation
class Watchlist(Base):
    """Named lookup list (IPs/CIDRs, domains, users or plain strings) usable from the pipeline query language."""
    __tablename__ = "watchlists"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)  # [A-Za-z0-9_]
    description: Mapped[str] = mapped_column(Text, default="")
    kind: Mapped[str] = mapped_column(String(16), default="ip")  # ip | domain | user | string
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class WatchlistItem(Base):
    __tablename__ = "watchlist_items"
    __table_args__ = (UniqueConstraint("watchlist_id", "value", name="uq_watchlist_value"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    watchlist_id: Mapped[int] = mapped_column(ForeignKey("watchlists.id", ondelete="CASCADE"), index=True)
    value: Mapped[str] = mapped_column(String(255))
    label: Mapped[str] = mapped_column(String(255), default="")
    added_by: Mapped[str] = mapped_column(String(64), default="")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class HuntingQuery(Base):
    __tablename__ = "hunting_queries"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)  # built-in library entries
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(Text, default="")
    query: Mapped[str] = mapped_column(Text)
    range: Mapped[str] = mapped_column(String(8), default="24h")
    tactic: Mapped[str] = mapped_column(String(16), default="")
    techniques: Mapped[list] = mapped_column(JSON, default=list)
    builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    author: Mapped[str] = mapped_column(String(64), default="system")
    last_run: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_count: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Bookmark(Base):
    """Rows saved from a hunt or search as evidence; can be attached to an incident."""
    __tablename__ = "bookmarks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    query: Mapped[str] = mapped_column(Text)
    window_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    window_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    columns: Mapped[list] = mapped_column(JSON, default=list)
    rows: Mapped[list] = mapped_column(JSON, default=list)
    notes: Mapped[str] = mapped_column(Text, default="")
    tags: Mapped[list] = mapped_column(JSON, default=list)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Workbook(Base):
    """User-built dashboard: panels backed by pipeline queries."""
    __tablename__ = "workbooks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)  # built-in templates
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(Text, default="")
    range: Mapped[str] = mapped_column(String(8), default="24h")
    panels: Mapped[list] = mapped_column(JSON, default=list)  # [{id, title, query, viz, width, range?}]
    owner: Mapped[str] = mapped_column(String(64))
    shared: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class AutomationRule(Base):
    """SOAR-style playbook: when <trigger> and <conditions> then run <actions> (SIEM-side only; never touches firewalls)."""
    __tablename__ = "automation_rules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    priority: Mapped[int] = mapped_column(Integer, default=100)  # lower runs first
    trigger: Mapped[str] = mapped_column(String(32))  # alert.created | incident.created | incident.escalated
    conditions: Mapped[dict] = mapped_column(JSON, default=dict)
    actions: Mapped[list] = mapped_column(JSON, default=list)
    stop_processing: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[str] = mapped_column(String(64))
    run_count: Mapped[int] = mapped_column(Integer, default=0)
    last_run: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class AutomationRun(Base):
    __tablename__ = "automation_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_id: Mapped[int | None] = mapped_column(ForeignKey("automation_rules.id", ondelete="SET NULL"), nullable=True, index=True)
    rule_name: Mapped[str] = mapped_column(String(128))
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    trigger: Mapped[str] = mapped_column(String(32))
    target_type: Mapped[str] = mapped_column(String(16))  # alert | incident
    target_id: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16))  # ok | partial | error | dry_run
    results: Mapped[list] = mapped_column(JSON, default=list)  # [{action, ok, detail}]


class IspLink(Base):
    """A WAN link (firewall + SD-WAN member interface) and the provider/contract details an admin attaches to it."""
    __tablename__ = "isp_links"
    __table_args__ = (UniqueConstraint("firewall_id", "interface", name="uq_isp_link"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # circuits monitored only by ICMP have no firewall (firewall_id NULL, interface "")
    firewall_id: Mapped[int | None] = mapped_column(ForeignKey("firewalls.id", ondelete="CASCADE"), index=True, nullable=True)
    interface: Mapped[str] = mapped_column(String(64))
    isp_name: Mapped[str] = mapped_column(String(128), default="")      # set by an admin; groups links into providers
    circuit_id: Mapped[str] = mapped_column(String(128), default="")
    bandwidth_mbps: Mapped[float | None] = mapped_column(Float, nullable=True)
    target_availability: Mapped[float] = mapped_column(Float, default=99.5)  # contractual SLA, percent
    outage_checks: Mapped[list] = mapped_column(JSON, default=list)      # health checks that define "down" (empty = all)
    hidden: Mapped[bool] = mapped_column(Boolean, default=False)         # e.g. IPsec overlay members
    notes: Mapped[str] = mapped_column(Text, default="")
    support_contact: Mapped[str] = mapped_column(String(255), default="")
    alias: Mapped[str] = mapped_column(String(128), default="")          # discovered (FortiGate interface alias)
    description: Mapped[str] = mapped_column(String(255), default="")    # discovered
    gateway: Mapped[str] = mapped_column(String(64), default="")         # discovered from logs / SD-WAN config
    as_org: Mapped[str] = mapped_column(String(255), default="")         # gateway ASN organisation (GeoIP)
    discovered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    # circuit inventory (WAN observability): an ISP link is the circuit; ICMP targets attach to it via isp_link_id
    name: Mapped[str] = mapped_column(String(128), default="", server_default="")
    site: Mapped[str] = mapped_column(String(128), default="", server_default="", index=True)
    location: Mapped[str] = mapped_column(String(255), default="", server_default="")
    role: Mapped[str] = mapped_column(String(16), default="primary", server_default="primary")   # primary | backup
    owner: Mapped[str] = mapped_column(String(128), default="", server_default="")
    monitoring_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"))


class LogSource(Base):
    """Non-FortiGate syslog sender (Windows event forwarder, CEF device, generic syslog), identified by source IP."""
    __tablename__ = "log_sources"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    kind: Mapped[str] = mapped_column(String(16), default="windows")  # windows | cef | netdev | syslog
    source_ips: Mapped[list] = mapped_column(JSON, default=list)
    site: Mapped[str] = mapped_column(String(64), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    description: Mapped[str] = mapped_column(Text, default="")
    events_total: Mapped[int] = mapped_column(BigInteger, default=0)
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IcmpTarget(Base):
    """Public IP (ISP WAN address, gateway, upstream DNS ...) pinged from the SIEM, NMS style."""
    __tablename__ = "icmp_targets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    address: Mapped[str] = mapped_column(String(255), unique=True)
    isp_link_id: Mapped[int | None] = mapped_column(ForeignKey("isp_links.id", ondelete="SET NULL"), nullable=True)
    isp_name: Mapped[str] = mapped_column(String(128), default="")      # grouping when not linked to an ISP link
    site: Mapped[str] = mapped_column(String(128), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    interval_seconds: Mapped[int] = mapped_column(Integer, default=30)
    probes: Mapped[int] = mapped_column(Integer, default=3)              # echo requests per check
    timeout_ms: Mapped[int] = mapped_column(Integer, default=1000)
    down_after: Mapped[int] = mapped_column(Integer, default=3)          # consecutive failed checks before DOWN
    up_after: Mapped[int] = mapped_column(Integer, default=2)            # consecutive good checks before UP again
    rtt_warn_ms: Mapped[float] = mapped_column(Float, default=150.0)
    loss_warn_pct: Mapped[float] = mapped_column(Float, default=20.0)
    # live state (written by the prober)
    state: Mapped[str] = mapped_column(String(16), default="unknown")    # up | down | degraded | unknown
    state_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    fail_streak: Mapped[int] = mapped_column(Integer, default=0)
    ok_streak: Mapped[int] = mapped_column(Integer, default=0)
    last_check: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_rtt_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    last_loss_pct: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # state machine detail (app/icmp.py): observation times of the current streaks and the last healthy check
    jitter_warn_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    retries: Mapped[int] = mapped_column(Integer, default=0, server_default="0")          # re-checks before a check counts as failed
    fail_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ok_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_ok_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_jitter_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    last_error: Mapped[str] = mapped_column(Text, default="", server_default="")
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)   # poll claimed by a worker
    paused_reason: Mapped[str] = mapped_column(String(255), default="", server_default="")
    # degraded damping: consecutive poor (reachable but over a threshold) checks before DEGRADED, healthy ones to clear it
    degrade_after: Mapped[int] = mapped_column(Integer, default=3, server_default="3")
    clear_after: Mapped[int] = mapped_column(Integer, default=2, server_default="2")
    poor_streak: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    healthy_streak: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    poor_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    healthy_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class IcmpEvent(Base):
    """State change log (up → down, down → up, ...) with the duration of the state that ended."""
    __tablename__ = "icmp_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("icmp_targets.id", ondelete="CASCADE"), index=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    from_state: Mapped[str] = mapped_column(String(16))
    to_state: Mapped[str] = mapped_column(String(16))
    previous_duration_s: Mapped[int | None] = mapped_column(Integer, nullable=True)
    detail: Mapped[str] = mapped_column(Text, default="")


class WanOutage(Base):
    """One confirmed outage (or degradation) of a monitored target or SD-WAN link: the single source of truth for outage
    counts and downtime on every WAN page. Timing convention (docs/WAN.md): started_at = first failed observation of the
    streak that crossed the threshold, last_ok_at = last healthy observation before it, detected_at = when the failure
    threshold was met; recovered_at = first healthy observation of the recovery streak, recovery_detected_at = when the
    recovery threshold was met. duration_s = recovered_at - started_at."""
    __tablename__ = "wan_outages"
    __table_args__ = (Index("uq_wan_outage_open", "target_id", "source", "kind", unique=True,
                            postgresql_where=text("recovered_at IS NULL AND target_id IS NOT NULL"),
                            sqlite_where=text("recovered_at IS NULL AND target_id IS NOT NULL")),
                      Index("ix_wan_outage_link_start", "isp_link_id", "source", "started_at"))
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(16), default="icmp")                      # icmp | sdwan
    kind: Mapped[str] = mapped_column(String(16), default="down")                        # down | degraded
    target_id: Mapped[int | None] = mapped_column(ForeignKey("icmp_targets.id", ondelete="SET NULL"), nullable=True, index=True)
    isp_link_id: Mapped[int | None] = mapped_column(ForeignKey("isp_links.id", ondelete="SET NULL"), nullable=True, index=True)
    firewall_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    target_name: Mapped[str] = mapped_column(String(255), default="")                    # snapshots: history survives renames / deletes
    address: Mapped[str] = mapped_column(String(255), default="")
    isp_name: Mapped[str] = mapped_column(String(128), default="", index=True)
    site: Mapped[str] = mapped_column(String(128), default="", index=True)
    circuit_name: Mapped[str] = mapped_column(String(255), default="")
    last_ok_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    recovered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    recovery_detected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_s: Mapped[int | None] = mapped_column(Integer, nullable=True)
    failed_checks: Mapped[int] = mapped_column(Integer, default=0)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)                           # failures that confirmed it, recovery checks
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    maintenance_id: Mapped[int | None] = mapped_column(Integer, nullable=True)           # inside a maintenance window: no incident, not SLA downtime
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class WanMaintenance(Base):
    """Planned maintenance: outages inside it are recorded but open no incident, send no notification and are excluded
    from availability."""
    __tablename__ = "wan_maintenance"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    scope: Mapped[str] = mapped_column(String(16), default="all")                        # all | site | isp | circuit | target
    scope_value: Mapped[str] = mapped_column(String(255), default="")
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ends_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    reason: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class WanSetting(Base):
    """Single row: correlation strategy, recovery behaviour, root-cause categories, severities."""
    __tablename__ = "wan_settings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_by: Mapped[str] = mapped_column(String(64), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class WanCollector(Base):
    """Heartbeat of the ICMP collection loop (monitoring-system health, kept apart from target health)."""
    __tablename__ = "wan_collector"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    worker: Mapped[str] = mapped_column(String(128), default="")
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_checked: Mapped[int] = mapped_column(Integer, default=0)
    last_errors: Mapped[int] = mapped_column(Integer, default=0)
    backlog: Mapped[int] = mapped_column(Integer, default=0)                             # due targets not checked in the cycle
    last_error: Mapped[str] = mapped_column(Text, default="")


class BgpPeer(Base):
    """A BGP neighbor as last reported by the firewall's read-only API. `routes` holds the prefixes received from the
    peer at the last poll (when small enough) so the next poll can report announcements and withdrawals."""
    __tablename__ = "bgp_peers"
    __table_args__ = (UniqueConstraint("firewall_id", "peer_ip", name="uq_bgp_peer"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    firewall_id: Mapped[int] = mapped_column(ForeignKey("firewalls.id", ondelete="CASCADE"), index=True)
    peer_ip: Mapped[str] = mapped_column(String(64))
    remote_as: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    local_ip: Mapped[str] = mapped_column(String(64), default="")
    peer_type: Mapped[str] = mapped_column(String(32), default="")      # ibgp | ebgp (when reported)
    admin_status: Mapped[str] = mapped_column(String(32), default="")
    state: Mapped[str] = mapped_column(String(32), default="unknown")    # Established, Active, Idle, Connect, ...
    state_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    prefixes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    routes: Mapped[list | None] = mapped_column(JSON, nullable=True)
    routes_truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    last_polled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    interface: Mapped[str] = mapped_column(String(64), default="")      # tunnel / port the session runs over
    config: Mapped[dict | None] = mapped_column(JSON, nullable=True)     # sanitised neighbor settings (never secrets)
    known_prefixes: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # prefix -> last seen (7-day memory)


class BgpRouter(Base):
    """Per-firewall BGP process: global settings, configuration audit findings and the installed BGP routes (RIB)."""
    __tablename__ = "bgp_routers"
    firewall_id: Mapped[int] = mapped_column(ForeignKey("firewalls.id", ondelete="CASCADE"), primary_key=True)
    local_as: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    router_id: Mapped[str] = mapped_column(String(64), default="")
    config: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    audit: Mapped[list | None] = mapped_column(JSON, nullable=True)
    config_polled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rib: Mapped[dict | None] = mapped_column(JSON, nullable=True)        # prefix -> [{peer, interface, gateway, installed}]
    rib_polled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# ------------------------------------------------------------------ Infrastructure as Code
class IacProject(Base):
    """A desired-state configuration for a set of managed firewalls in one environment."""
    __tablename__ = "iac_projects"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    environment: Mapped[str] = mapped_column(String(16), default="development")  # development | staging | production
    draft_content: Mapped[str] = mapped_column(Text, default="")
    draft_updated_by: Mapped[str] = mapped_column(String(64), default="")
    draft_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    draft_base_version_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    approved_version_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    archived: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IacVersion(Base):
    """Immutable committed desired-state version (content hash bound into plans and approvals)."""
    __tablename__ = "iac_versions"
    __table_args__ = (UniqueConstraint("project_id", "number", name="uq_iac_version"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("iac_projects.id", ondelete="CASCADE"), index=True)
    number: Mapped[int] = mapped_column(Integer)
    content: Mapped[str] = mapped_column(Text)
    content_hash: Mapped[str] = mapped_column(String(64))
    message: Mapped[str] = mapped_column(Text, default="")
    author: Mapped[str] = mapped_column(String(64))
    parent_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    valid: Mapped[bool] = mapped_column(Boolean, default=False)
    validation: Mapped[dict] = mapped_column(JSON, default=dict)       # errors + security findings at commit time
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IacDevice(Base):
    """A firewall managed by an IaC project: per-device variables, capabilities and the latest observed state."""
    __tablename__ = "iac_devices"
    __table_args__ = (UniqueConstraint("project_id", "firewall_id", name="uq_iac_device"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("iac_projects.id", ondelete="CASCADE"), index=True)
    firewall_id: Mapped[int] = mapped_column(ForeignKey("firewalls.id", ondelete="CASCADE"), index=True)
    managed: Mapped[bool] = mapped_column(Boolean, default=True)
    integration: Mapped[str] = mapped_column(String(32), default="fortigate_api")   # fortigate_api | fortimanager
    variables: Mapped[dict] = mapped_column(JSON, default=dict)
    capabilities: Mapped[dict] = mapped_column(JSON, default=dict)
    observed: Mapped[dict | None] = mapped_column(JSON, nullable=True)             # normalised managed resources (no secrets)
    observed_hash: Mapped[str] = mapped_column(String(64), default="")
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    drift_status: Mapped[str] = mapped_column(String(16), default="unknown")       # in_sync | drift | unknown | error
    last_drift_check: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_backup_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_deploy_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_deploy_status: Mapped[str] = mapped_column(String(16), default="")
    last_deployed_version_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    managed_keys: Mapped[dict] = mapped_column(JSON, default=dict)                  # resource type -> keys deployed by IaC
    # undeclared policies / routes already on the device at the last successful deployment (not "unexpected" drift)
    baseline_unmanaged: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IacPlan(Base):
    __tablename__ = "iac_plans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("iac_projects.id", ondelete="CASCADE"), index=True)
    version_id: Mapped[int | None] = mapped_column(ForeignKey("iac_versions.id", ondelete="SET NULL"), nullable=True)
    version_hash: Mapped[str] = mapped_column(String(64), default="")
    kind: Mapped[str] = mapped_column(String(16), default="change")                # change | recovery
    recovery_backup_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="draft", index=True)
    environment: Mapped[str] = mapped_column(String(16), default="development")
    targets: Mapped[list] = mapped_column(JSON, default=list)                      # firewall ids
    observed_hashes: Mapped[dict] = mapped_column(JSON, default=dict)              # firewall id -> observed hash at planning
    ruleset_hash: Mapped[str] = mapped_column(String(64), default="")
    plan_hash: Mapped[str] = mapped_column(String(64), default="", index=True)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    findings: Mapped[list] = mapped_column(JSON, default=list)
    errors: Mapped[list] = mapped_column(JSON, default=list)
    blocking: Mapped[bool] = mapped_column(Boolean, default=False)
    destructive: Mapped[bool] = mapped_column(Boolean, default=False)
    stale_reason: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class IacPlanChange(Base):
    __tablename__ = "iac_plan_changes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    plan_id: Mapped[int] = mapped_column(ForeignKey("iac_plans.id", ondelete="CASCADE"), index=True)
    firewall_id: Mapped[int] = mapped_column(Integer, index=True)
    seq: Mapped[int] = mapped_column(Integer, default=0)
    resource_type: Mapped[str] = mapped_column(String(32))
    resource_id: Mapped[str] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(16))                                 # create | update | delete | move | no-op
    current: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    desired: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    fields: Mapped[list] = mapped_column(JSON, default=list)
    depends_on: Mapped[list] = mapped_column(JSON, default=list)
    risk: Mapped[str] = mapped_column(String(16), default="low")
    rule_id: Mapped[str] = mapped_column(String(32), default="")
    impact: Mapped[str] = mapped_column(Text, default="")
    disruptive: Mapped[bool] = mapped_column(Boolean, default=False)


class IacApproval(Base):
    __tablename__ = "iac_approvals"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    plan_id: Mapped[int] = mapped_column(ForeignKey("iac_plans.id", ondelete="CASCADE"), index=True)
    username: Mapped[str] = mapped_column(String(64))
    decision: Mapped[str] = mapped_column(String(16))                               # approve | reject
    comment: Mapped[str] = mapped_column(Text, default="")
    plan_hash: Mapped[str] = mapped_column(String(64))
    acknowledged_destructive: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IacJob(Base):
    __tablename__ = "iac_jobs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    plan_id: Mapped[int | None] = mapped_column(ForeignKey("iac_plans.id", ondelete="SET NULL"), nullable=True, index=True)
    project_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(16))                                   # deploy | dry_run | drift
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)   # queued|running|succeeded|failed|cancelled
    plan_hash: Mapped[str] = mapped_column(String(64), default="")
    requested_by: Mapped[str] = mapped_column(String(64))
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    current_operation: Mapped[str] = mapped_column(Text, default="")
    progress: Mapped[dict] = mapped_column(JSON, default=dict)
    log: Mapped[list] = mapped_column(JSON, default=list)
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class IacJobDevice(Base):
    __tablename__ = "iac_job_devices"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("iac_jobs.id", ondelete="CASCADE"), index=True)
    firewall_id: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    backup_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    results: Mapped[list] = mapped_column(JSON, default=list)
    verification: Mapped[dict] = mapped_column(JSON, default=dict)
    health: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class IacLock(Base):
    """One deployment at a time per firewall (primary key enforces it across API and worker replicas)."""
    __tablename__ = "iac_locks"
    firewall_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job_id: Mapped[int] = mapped_column(Integer)
    acquired_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class IacBackup(Base):
    """Pre-change capture. The full device configuration (may contain encrypted secrets) is stored Fernet-encrypted;
    the normalised managed-resource snapshot (no secrets) drives recovery plans."""
    __tablename__ = "iac_backups"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    firewall_id: Mapped[int] = mapped_column(ForeignKey("firewalls.id", ondelete="CASCADE"), index=True)
    job_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    plan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    kind: Mapped[str] = mapped_column(String(16), default="pre_change")              # pre_change | manual
    snapshot: Mapped[dict] = mapped_column(JSON, default=dict)
    snapshot_sha256: Mapped[str] = mapped_column(String(64))
    full_config_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    full_config_sha256: Mapped[str] = mapped_column(String(64), default="")
    full_config_note: Mapped[str] = mapped_column(Text, default="")
    validated: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class IacDrift(Base):
    __tablename__ = "iac_drift"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("iac_devices.id", ondelete="CASCADE"), index=True)
    firewall_id: Mapped[int] = mapped_column(Integer, index=True)
    project_id: Mapped[int] = mapped_column(Integer, index=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    status: Mapped[str] = mapped_column(String(16))                                 # in_sync | drift | error
    version_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    observed_hash: Mapped[str] = mapped_column(String(64), default="")
    findings: Mapped[list] = mapped_column(JSON, default=list)
    counts: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str] = mapped_column(Text, default="")


class IacRule(Base):
    """Configurable validation / drift-classification rule (severity, deployment blocking, parameters)."""
    __tablename__ = "iac_rules"
    rule_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    family: Mapped[str] = mapped_column(String(16))                                  # security | drift
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16))
    blocks_deploy: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    remediation: Mapped[str] = mapped_column(Text, default="")


class IacException(Base):
    __tablename__ = "iac_exceptions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(32), index=True)
    project_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    firewall_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    resource: Mapped[str] = mapped_column(String(255), default="*")                   # "policy:100", "address:*", "*"
    owner: Mapped[str] = mapped_column(String(128))
    justification: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IacSetting(Base):
    __tablename__ = "iac_settings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_by: Mapped[str] = mapped_column(String(64), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class IacAudit(Base):
    """Append-only, hash-chained record of every IaC operation (each row commits to the previous row's hash)."""
    __tablename__ = "iac_audit"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    username: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    project_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    plan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    job_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    target: Mapped[str] = mapped_column(String(255), default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    client_ip: Mapped[str] = mapped_column(String(64), default="")
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    hash: Mapped[str] = mapped_column(String(64))


# ------------------------------------------------------------------ switch monitoring (Cisco / Ruckus ICX over SNMP)
class SwitchCredential(Base):
    """Reusable SNMP credential profile. Secrets (community, USM passphrases) are Fernet-encrypted and never returned."""
    __tablename__ = "switch_credentials"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    version: Mapped[str] = mapped_column(String(8), default="v3")             # v3 | v2c
    username: Mapped[str] = mapped_column(String(64), default="")            # SNMPv3 user (not secret)
    auth_protocol: Mapped[str] = mapped_column(String(16), default="sha")
    priv_protocol: Mapped[str] = mapped_column(String(16), default="aes128")
    secret_ciphertext: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class SwitchNetwork(Base):
    """Authorised management subnet. Switches can only be added, polled and discovered inside these networks."""
    __tablename__ = "switch_networks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cidr: Mapped[str] = mapped_column(String(64), unique=True)
    site: Mapped[str] = mapped_column(String(128), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    allow_discovery: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Switch(Base):
    __tablename__ = "switches"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    address: Mapped[str] = mapped_column(String(64), unique=True)            # management IP literal
    port: Mapped[int] = mapped_column(Integer, default=161)
    credential_id: Mapped[int | None] = mapped_column(ForeignKey("switch_credentials.id", ondelete="RESTRICT"), nullable=True)
    vendor: Mapped[str] = mapped_column(String(16), default="unknown")       # cisco | fortinet | juniper | ruckus | generic | unknown (until identified)
    family: Mapped[str] = mapped_column(String(64), default="")
    product_line: Mapped[str] = mapped_column(String(64), default="")       # fingerprint family: Catalyst, Nexus, FortiGate, EX, ICX …
    device_type: Mapped[str] = mapped_column(String(16), default="")        # switch | router | firewall | wlc | ap | server | other
    id_confidence: Mapped[str] = mapped_column(String(16), default="")      # exact | family | vendor | descr | override | unknown
    vendor_override: Mapped[str] = mapped_column(String(16), default="")    # administrator: force the vendor profile
    family_override: Mapped[str] = mapped_column(String(64), default="")    # administrator: force the product line
    engine_id: Mapped[str] = mapped_column(String(80), default="")          # snmpEngineID (hex): authenticates its SNMPv3 traps
    model: Mapped[str] = mapped_column(String(64), default="")
    serial: Mapped[str] = mapped_column(String(128), default="")
    firmware: Mapped[str] = mapped_column(String(128), default="")
    os: Mapped[str] = mapped_column(String(32), default="")
    sys_descr: Mapped[str] = mapped_column(Text, default="")
    sys_object_id: Mapped[str] = mapped_column(String(128), default="")
    sys_name: Mapped[str] = mapped_column(String(255), default="")
    location: Mapped[str] = mapped_column(String(255), default="")
    site: Mapped[str] = mapped_column(String(128), default="")
    building: Mapped[str] = mapped_column(String(128), default="")
    floor: Mapped[str] = mapped_column(String(64), default="")
    rack: Mapped[str] = mapped_column(String(64), default="")
    role: Mapped[str] = mapped_column(String(32), default="")                # access | distribution | core | ...
    parent_id: Mapped[int | None] = mapped_column(ForeignKey("switches.id", ondelete="SET NULL"), nullable=True, index=True)  # upstream device
    notes: Mapped[str] = mapped_column(Text, default="")
    monitoring: Mapped[str] = mapped_column(String(16), default="active")    # active | paused
    poll_interval_seconds: Mapped[int] = mapped_column(Integer, default=60)
    group_intervals: Mapped[dict] = mapped_column(JSON, default=dict)        # {group: seconds, 0 = disabled}
    thresholds: Mapped[dict] = mapped_column(JSON, default=dict)             # per-switch alert threshold overrides
    timeout_ms: Mapped[int] = mapped_column(Integer, default=3000)
    retries: Mapped[int] = mapped_column(Integer, default=1)
    # live state (written by the poller)
    state: Mapped[str] = mapped_column(String(16), default="unknown")        # up | down | auth_failed | unknown
    state_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    fail_streak: Mapped[int] = mapped_column(Integer, default=0)
    last_poll_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str] = mapped_column(Text, default="")
    last_error_kind: Mapped[str] = mapped_column(String(16), default="")
    poll_duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    uptime_ticks: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    cpu_pct: Mapped[float | None] = mapped_column(Float, nullable=True)
    mem_pct: Mapped[float | None] = mapped_column(Float, nullable=True)
    temp_max_c: Mapped[float | None] = mapped_column(Float, nullable=True)
    poe_budget_w: Mapped[float | None] = mapped_column(Float, nullable=True)
    poe_used_w: Mapped[float | None] = mapped_column(Float, nullable=True)
    if_total: Mapped[int | None] = mapped_column(Integer, nullable=True)
    if_up: Mapped[int | None] = mapped_column(Integer, nullable=True)
    if_errors: Mapped[int | None] = mapped_column(Integer, nullable=True)
    coverage_pct: Mapped[float | None] = mapped_column(Float, nullable=True)
    capabilities: Mapped[dict] = mapped_column(JSON, default=dict)
    group_state: Mapped[dict] = mapped_column(JSON, default=dict)            # {group: {last_run, ok, duration_ms, error}}
    health: Mapped[dict] = mapped_column(JSON, default=dict)                 # latest cpu / memory / environment / stack / poe / stp / lacp / routing / inventory
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    backoff_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)  # failing device: next poll not before
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SwitchInterface(Base):
    __tablename__ = "switch_interfaces"
    __table_args__ = (UniqueConstraint("switch_id", "ifindex", name="uq_switch_if"), Index("ix_switch_interfaces_present", "switch_id", postgresql_where=text("present")))
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    switch_id: Mapped[int] = mapped_column(ForeignKey("switches.id", ondelete="CASCADE"), index=True)
    ifindex: Mapped[int] = mapped_column(BigInteger)
    name: Mapped[str] = mapped_column(String(128), default="")
    descr: Mapped[str] = mapped_column(String(255), default="")
    alias: Mapped[str] = mapped_column(String(255), default="")
    if_type: Mapped[int | None] = mapped_column(Integer, nullable=True)
    mtu: Mapped[int | None] = mapped_column(Integer, nullable=True)
    speed_bps: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    speed_source: Mapped[str] = mapped_column(String(64), default="")
    admin: Mapped[str] = mapped_column(String(16), default="")
    oper: Mapped[str] = mapped_column(String(24), default="")
    duplex: Mapped[str] = mapped_column(String(8), default="")
    mac: Mapped[str] = mapped_column(String(17), default="")
    kind: Mapped[str] = mapped_column(String(16), default="")                # physical | lag | svi | virtual
    mode: Mapped[str] = mapped_column(String(8), default="")                 # access | trunk | ""
    access_vlan: Mapped[int | None] = mapped_column(Integer, nullable=True)
    native_vlan: Mapped[int | None] = mapped_column(Integer, nullable=True)
    lag_ifindex: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    poe: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    rx_bps: Mapped[float | None] = mapped_column(Float, nullable=True)
    tx_bps: Mapped[float | None] = mapped_column(Float, nullable=True)
    rx_util: Mapped[float | None] = mapped_column(Float, nullable=True)
    tx_util: Mapped[float | None] = mapped_column(Float, nullable=True)
    in_errors_delta: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    out_errors_delta: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    crc_delta: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    discards_delta: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    sample_flags: Mapped[int] = mapped_column(Integer, default=0)
    sample_note: Mapped[str] = mapped_column(String(255), default="")
    counters: Mapped[dict] = mapped_column(JSON, default=dict)               # last raw sample for the next delta
    last_change_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_sample_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    present: Mapped[bool] = mapped_column(Boolean, default=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SwitchVlan(Base):
    __tablename__ = "switch_vlans"
    __table_args__ = (UniqueConstraint("switch_id", "vlan_id", name="uq_switch_vlan"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    switch_id: Mapped[int] = mapped_column(ForeignKey("switches.id", ondelete="CASCADE"), index=True)
    vlan_id: Mapped[int] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(String(128), default="")
    state: Mapped[str] = mapped_column(String(16), default="")
    tagged: Mapped[list] = mapped_column(JSON, default=list)                 # ifIndexes
    untagged: Mapped[list] = mapped_column(JSON, default=list)
    present: Mapped[bool] = mapped_column(Boolean, default=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SwitchMac(Base):
    """MAC address table entry (high cardinality, so it lives here and not in time-series labels)."""
    __tablename__ = "switch_macs"
    __table_args__ = (UniqueConstraint("switch_id", "mac", "vlan_id", name="uq_switch_mac"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    switch_id: Mapped[int] = mapped_column(ForeignKey("switches.id", ondelete="CASCADE"), index=True)
    mac: Mapped[str] = mapped_column(String(17), index=True)
    vlan_id: Mapped[int] = mapped_column(Integer, default=0)
    ifindex: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    port_name: Mapped[str] = mapped_column(String(128), default="")
    status: Mapped[str] = mapped_column(String(16), default="")
    moves: Mapped[int] = mapped_column(Integer, default=0)
    present: Mapped[bool] = mapped_column(Boolean, default=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SwitchEvent(Base):
    """State changes and observations: reachability, port up/down, flaps, MAC moves, STP root / topology changes,
    LACP membership, stack, environment, restarts, firmware changes, polling failures, recoveries."""
    __tablename__ = "switch_events"
    __table_args__ = (Index("ix_switch_events_switch_at", "switch_id", "at"), Index("ix_switch_events_switch_kind_at", "switch_id", "kind", "at"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    switch_id: Mapped[int] = mapped_column(ForeignKey("switches.id", ondelete="CASCADE"), index=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(16), default="informational")
    component: Mapped[str] = mapped_column(String(255), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    data: Mapped[dict] = mapped_column(JSON, default=dict)


class SwitchPollRun(Base):
    """Collection history: one row per poll / test with per-group outcome and timing."""
    __tablename__ = "switch_poll_runs"
    __table_args__ = (Index("ix_switch_poll_runs_switch_started", "switch_id", "started_at"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    switch_id: Mapped[int] = mapped_column(ForeignKey("switches.id", ondelete="CASCADE"), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    ok: Mapped[bool] = mapped_column(Boolean, default=False)
    kind: Mapped[str] = mapped_column(String(16), default="poll")            # poll | test
    requests: Mapped[int] = mapped_column(Integer, default=0)
    groups: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str] = mapped_column(Text, default="")


class SwitchDiscoveryRun(Base):
    __tablename__ = "switch_discovery_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    network_id: Mapped[int] = mapped_column(ForeignKey("switch_networks.id", ondelete="CASCADE"), index=True)
    cidr: Mapped[str] = mapped_column(String(64))
    credential_id: Mapped[int] = mapped_column(ForeignKey("switch_credentials.id", ondelete="CASCADE"))
    status: Mapped[str] = mapped_column(String(16), default="queued")        # queued | running | done | failed
    requested_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scanned: Mapped[int] = mapped_column(Integer, default=0)
    results: Mapped[list] = mapped_column(JSON, default=list)
    error: Mapped[str] = mapped_column(Text, default="")


class SwitchNeighbor(Base):
    """LLDP / CDP neighbor seen on a switch port (topology). Absent neighbors are kept for 30 days as 'lost' links."""
    __tablename__ = "switch_neighbors"
    __table_args__ = (UniqueConstraint("switch_id", "local_ifindex", "remote_key", name="uq_switch_neighbor"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    switch_id: Mapped[int] = mapped_column(ForeignKey("switches.id", ondelete="CASCADE"), index=True)
    local_ifindex: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    local_port: Mapped[str] = mapped_column(String(128), default="")
    remote_key: Mapped[str] = mapped_column(String(255))                     # lower-case short system name, else chassis id
    protocol: Mapped[str] = mapped_column(String(16), default="lldp")       # lldp | cdp | lldp+cdp
    remote_name: Mapped[str] = mapped_column(String(255), default="")
    chassis_id: Mapped[str] = mapped_column(String(128), default="")
    remote_port: Mapped[str] = mapped_column(String(128), default="")
    remote_port_desc: Mapped[str] = mapped_column(String(255), default="")
    remote_mgmt_ip: Mapped[str] = mapped_column(String(64), default="")
    remote_descr: Mapped[str] = mapped_column(String(300), default="")
    capabilities: Mapped[list] = mapped_column(JSON, default=list)
    present: Mapped[bool] = mapped_column(Boolean, default=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# ------------------------------------------------------------------ TACACS+ AAA (tac_plus-ng)
class TacServer(Base):
    """A TACACS+ server. kind=managed: tac_plus-ng with the SIEM deploy agent (configuration + accounting ingestion);
    kind=external: an existing server the SIEM only health-checks and tests."""
    __tablename__ = "tacacs_servers"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    kind: Mapped[str] = mapped_column(String(16), default="managed")             # managed | external
    management_address: Mapped[str] = mapped_column(String(255))                # where the SIEM checks it
    client_address: Mapped[str] = mapped_column(String(255), default="")        # what devices are configured with
    port: Mapped[int] = mapped_column(Integer, default=49)
    site: Mapped[str] = mapped_column(String(128), default="")
    environment: Mapped[str] = mapped_column(String(16), default="production")
    role: Mapped[str] = mapped_column(String(16), default="primary")            # primary | secondary
    implementation: Mapped[str] = mapped_column(String(64), default="tac_plus-ng")
    version: Mapped[str] = mapped_column(String(128), default="")
    monitoring: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(16), default="unknown")          # up | degraded | down | unknown
    status_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    fail_streak: Mapped[int] = mapped_column(Integer, default=0)
    last_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_ok_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str] = mapped_column(Text, default="")
    agent: Mapped[dict] = mapped_column(JSON, default=dict)                     # last agent status.json
    deployed_version_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    deployed_sha256: Mapped[str] = mapped_column(String(64), default="")
    last_deploy_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_accounting_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_authentication_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ingestion: Mapped[dict] = mapped_column(JSON, default=dict)                 # per log file: offset, lines, parse errors, last line time
    notes: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TacClient(Base):
    """A network device allowed to talk to the TACACS+ servers. The shared secret is Fernet-encrypted and only returned
    once, at creation or rotation."""
    __tablename__ = "tacacs_clients"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)                   # tac_plus-ng device object name
    address: Mapped[str] = mapped_column(String(64), unique=True)                # IP or CIDR (wide CIDRs need approval)
    vendor: Mapped[str] = mapped_column(String(16))                              # fortinet | cisco | ruckus | other
    model: Mapped[str] = mapped_column(String(64), default="")
    firmware: Mapped[str] = mapped_column(String(64), default="")
    site: Mapped[str] = mapped_column(String(128), default="")
    device_group: Mapped[str] = mapped_column(String(64), default="")
    role: Mapped[str] = mapped_column(String(32), default="")
    primary_server_id: Mapped[int | None] = mapped_column(ForeignKey("tacacs_servers.id", ondelete="SET NULL"), nullable=True)
    secondary_server_id: Mapped[int | None] = mapped_column(ForeignKey("tacacs_servers.id", ondelete="SET NULL"), nullable=True)
    firewall_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    switch_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    secret_ciphertext: Mapped[str] = mapped_column(Text, default="")
    pending_secret_ciphertext: Mapped[str] = mapped_column(Text, default="")    # rotation: both keys accepted until completed
    secret_version: Mapped[int] = mapped_column(Integer, default=1)
    secret_rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rotation_state: Mapped[str] = mapped_column(String(16), default="")         # "" | pending | completed
    wide_cidr_approved_by: Mapped[str] = mapped_column(String(64), default="")
    wide_cidr_justification: Mapped[str] = mapped_column(Text, default="")
    sync_status: Mapped[str] = mapped_column(String(16), default="pending")     # pending (not in a deployed version) | in_sync
    last_auth_test_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_auth_test_ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    last_accounting_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_authentication_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class TacIdentitySource(Base):
    """local (users defined in tac_plus-ng with crypt hashes), ldap / ad (MAVIS LDAP module), pam (MAVIS PAM)."""
    __tablename__ = "tacacs_identity_sources"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    kind: Mapped[str] = mapped_column(String(16))                                # local | ldap | ad | pam
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    settings: Mapped[dict] = mapped_column(JSON, default=dict)                   # hosts, base, group base, filter, memberof regex, starttls
    bind_secret_ciphertext: Mapped[str] = mapped_column(Text, default="")
    last_test_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_test_ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    last_test_detail: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TacUser(Base):
    """A TACACS+ identity known to the SIEM: local users (password stored only as a SHA-512 crypt hash) and directory
    users referenced for direct role mappings or disablement. Directory users are not copied wholesale."""
    __tablename__ = "tacacs_users"
    __table_args__ = (UniqueConstraint("username", "source_id", name="uq_tacacs_user"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), index=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("tacacs_identity_sources.id", ondelete="CASCADE"))
    display_name: Mapped[str] = mapped_column(String(128), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    emergency: Mapped[bool] = mapped_column(Boolean, default=False)              # break-glass account: every use alerts
    password_hash: Mapped[str] = mapped_column(Text, default="")                 # $6$... (local only), never a reversible form
    password_set_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    groups: Mapped[list] = mapped_column(JSON, default=list)                     # local group membership
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    disabled_reason: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TacRole(Base):
    """Authorization role, rendered per vendor (Cisco / Ruckus privilege levels mean different things; FortiGate maps to
    an admin profile)."""
    __tablename__ = "tacacs_roles"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    privileged: Mapped[bool] = mapped_column(Boolean, default=False)
    vendor_profiles: Mapped[dict] = mapped_column(JSON, default=dict)           # {cisco: {priv_lvl}, ruckus: {priv_lvl}, fortinet: {admin_profile}}
    default_command_action: Mapped[str] = mapped_column(String(8), default="deny")  # applies where per-command authorization exists
    command_categories: Mapped[list] = mapped_column(JSON, default=list)        # categories permitted
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TacRoleMapping(Base):
    """User or group → role, optionally scoped to sites / device groups / vendors / specific devices and a time window."""
    __tablename__ = "tacacs_role_mappings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    principal_type: Mapped[str] = mapped_column(String(8))                       # user | group
    principal: Mapped[str] = mapped_column(String(128), index=True)
    role_id: Mapped[int] = mapped_column(ForeignKey("tacacs_roles.id", ondelete="CASCADE"), index=True)
    scope_sites: Mapped[list] = mapped_column(JSON, default=list)
    scope_device_groups: Mapped[list] = mapped_column(JSON, default=list)
    scope_vendors: Mapped[list] = mapped_column(JSON, default=list)
    scope_clients: Mapped[list] = mapped_column(JSON, default=list)              # client names
    time_window: Mapped[str] = mapped_column(String(128), default="")           # cron-style, e.g. "* 8-19 * * 1-5"
    priority: Mapped[int] = mapped_column(Integer, default=100)
    justification: Mapped[str] = mapped_column(Text, default="")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TacCommandRule(Base):
    """Command authorization rule for a role and vendor. Exceptions carry an owner, justification and expiry."""
    __tablename__ = "tacacs_command_rules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    role_id: Mapped[int] = mapped_column(ForeignKey("tacacs_roles.id", ondelete="CASCADE"), index=True)
    vendor: Mapped[str] = mapped_column(String(16))                              # cisco | ruckus | any
    action: Mapped[str] = mapped_column(String(8))                               # permit | deny
    match: Mapped[str] = mapped_column(String(16), default="regex")             # regex | category
    pattern: Mapped[str] = mapped_column(String(512), default="")
    category: Mapped[str] = mapped_column(String(32), default="")
    priority: Mapped[int] = mapped_column(Integer, default=100)                  # lower = evaluated first
    exception: Mapped[bool] = mapped_column(Boolean, default=False)
    owner: Mapped[str] = mapped_column(String(64), default="")
    justification: Mapped[str] = mapped_column(Text, default="")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    description: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TacAuthPolicy(Base):
    __tablename__ = "tacacs_auth_policies"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    device_groups: Mapped[list] = mapped_column(JSON, default=list)              # empty = all devices
    allowed_sources: Mapped[list] = mapped_column(JSON, default=list)            # identity source ids; empty = all enabled
    allow_local_users: Mapped[bool] = mapped_column(Boolean, default=True)
    require_group_mapping: Mapped[bool] = mapped_column(Boolean, default=True)   # deny users without a role mapping
    allow_emergency: Mapped[bool] = mapped_column(Boolean, default=True)
    failure_alert_threshold: Mapped[int] = mapped_column(Integer, default=5)     # alerts only; no lockout
    priority: Mapped[int] = mapped_column(Integer, default=100)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    description: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TacSetting(Base):
    __tablename__ = "tacacs_settings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)                       # redaction rules, client networks, approvals ...
    updated_by: Mapped[str] = mapped_column(String(64), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class TacConfigVersion(Base):
    __tablename__ = "tacacs_config_versions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    number: Mapped[int] = mapped_column(Integer, unique=True)
    message: Mapped[str] = mapped_column(Text, default="")
    content_redacted: Mapped[str] = mapped_column(Text)                          # secrets replaced by ***
    content_ciphertext: Mapped[str] = mapped_column(Text)                        # full configuration, Fernet-encrypted
    sha256: Mapped[str] = mapped_column(String(64))                              # of the full configuration
    model: Mapped[dict] = mapped_column(JSON, default=dict)                      # structured snapshot (no secrets)
    validation: Mapped[dict] = mapped_column(JSON, default=dict)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TacDeployJob(Base):
    __tablename__ = "tacacs_deploy_jobs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    version_id: Mapped[int] = mapped_column(ForeignKey("tacacs_config_versions.id", ondelete="CASCADE"), index=True)
    server_id: Mapped[int] = mapped_column(ForeignKey("tacacs_servers.id", ondelete="CASCADE"), index=True)
    action: Mapped[str] = mapped_column(String(16), default="deploy")            # validate | deploy
    status: Mapped[str] = mapped_column(String(24), default="pending_approval")
    # pending_approval | approved | rejected | queued | running | succeeded | invalid | failed | rolled_back | cancelled
    requested_by: Mapped[str] = mapped_column(String(64))
    approved_by: Mapped[str] = mapped_column(String(64), default="")
    approval_hash: Mapped[str] = mapped_column(String(64), default="")         # sha256 of version sha + server + base sha
    base_sha256: Mapped[str] = mapped_column(String(64), default="")           # server's active config when requested
    comment: Mapped[str] = mapped_column(Text, default="")
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class TacTestRun(Base):
    __tablename__ = "tacacs_test_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    target: Mapped[str] = mapped_column(String(255), default="")
    server_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    client_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="queued")           # queued | running | passed | failed
    category: Mapped[str] = mapped_column(String(32), default="")              # e.g. timeout, auth_reject, backend_unavailable
    detail: Mapped[str] = mapped_column(Text, default="")
    steps: Mapped[list] = mapped_column(JSON, default=list)
    requested_by: Mapped[str] = mapped_column(String(64), default="")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class TacHealthCheck(Base):
    __tablename__ = "tacacs_health_checks"
    __table_args__ = (Index("ix_tacacs_health_checks_server_at", "server_id", "at"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    server_id: Mapped[int] = mapped_column(ForeignKey("tacacs_servers.id", ondelete="CASCADE"), index=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    tcp_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    agent_ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="unknown")
    detail: Mapped[str] = mapped_column(Text, default="")


# ---------------------------------------------------------------------------------------------- wireless (Cisco WLC)
# The controller itself is a `switches` row with role "wlc" (same credentials, polling, capability registry); these
# tables hold what the controller reports about its APs, radios, WLANs and clients (app/wireless, docs/WIRELESS.md).
class WirelessAp(Base):
    __tablename__ = "wireless_aps"
    __table_args__ = (UniqueConstraint("wlc_id", "mac", name="uq_wireless_ap"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    wlc_id: Mapped[int] = mapped_column(ForeignKey("switches.id", ondelete="CASCADE"), index=True)
    mac: Mapped[str] = mapped_column(String(17), index=True)                 # base radio MAC (table index)
    name: Mapped[str] = mapped_column(String(64), default="", index=True)
    ip: Mapped[str] = mapped_column(String(64), default="")
    model: Mapped[str] = mapped_column(String(64), default="")
    serial: Mapped[str] = mapped_column(String(64), default="")
    software: Mapped[str] = mapped_column(String(64), default="")
    location: Mapped[str] = mapped_column(String(255), default="")
    site: Mapped[str] = mapped_column(String(128), default="", index=True)   # admin override, else the controller's site
    building: Mapped[str] = mapped_column(String(128), default="")
    floor: Mapped[str] = mapped_column(String(64), default="")
    tags: Mapped[dict] = mapped_column(JSON, default=dict)                   # site / RF / policy tag (9800)
    state: Mapped[str] = mapped_column(String(16), default="unknown")        # up | down | degraded | unknown | maintenance
    state_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    oper_status: Mapped[str] = mapped_column(String(32), default="")         # raw bsnAPOperationStatus
    admin_enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    uptime_s: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    join_uptime_s: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    last_reboot_reason: Mapped[str] = mapped_column(String(64), default="")
    cpu_pct: Mapped[float | None] = mapped_column(Float, nullable=True)
    mem_pct: Mapped[float | None] = mapped_column(Float, nullable=True)
    clients: Mapped[int | None] = mapped_column(Integer, nullable=True)
    radio_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    power_status: Mapped[str] = mapped_column(String(32), default="")
    uplink: Mapped[dict] = mapped_column(JSON, default=dict)                  # CDP: {switch, address, port, platform}
    switch_id: Mapped[int | None] = mapped_column(Integer, nullable=True)     # monitored switch matched from CDP (name / address)
    switch_ifindex: Mapped[int | None] = mapped_column(Integer, nullable=True)
    counters: Mapped[dict] = mapped_column(JSON, default=dict)                # last raw counters (rates)
    present: Mapped[bool] = mapped_column(Boolean, default=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class WirelessRadio(Base):
    __tablename__ = "wireless_radios"
    __table_args__ = (UniqueConstraint("ap_id", "slot", name="uq_wireless_radio"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ap_id: Mapped[int] = mapped_column(ForeignKey("wireless_aps.id", ondelete="CASCADE"), index=True)
    wlc_id: Mapped[int] = mapped_column(Integer, index=True)
    slot: Mapped[int] = mapped_column(Integer)
    band: Mapped[str] = mapped_column(String(16), default="")                # 2.4 | 5 | 6 | dual (xor) | unknown
    radio_type: Mapped[str] = mapped_column(String(32), default="")
    admin_enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    oper_up: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    state: Mapped[str] = mapped_column(String(16), default="unknown")        # up | down | disabled | unknown
    state_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    channel: Mapped[int | None] = mapped_column(Integer, nullable=True)
    channel_width_mhz: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tx_power_level: Mapped[int | None] = mapped_column(Integer, nullable=True)  # 1..8 (1 = highest), not dBm
    channel_util_pct: Mapped[float | None] = mapped_column(Float, nullable=True)
    tx_util_pct: Mapped[float | None] = mapped_column(Float, nullable=True)
    rx_util_pct: Mapped[float | None] = mapped_column(Float, nullable=True)
    noise_dbm: Mapped[float | None] = mapped_column(Float, nullable=True)
    interference_pct: Mapped[float | None] = mapped_column(Float, nullable=True)
    interference_dbm: Mapped[float | None] = mapped_column(Float, nullable=True)
    clients: Mapped[int | None] = mapped_column(Integer, nullable=True)
    poor_snr_clients: Mapped[int | None] = mapped_column(Integer, nullable=True)
    retry_pct: Mapped[float | None] = mapped_column(Float, nullable=True)     # retries / transmitted frames over the last interval
    counters: Mapped[dict] = mapped_column(JSON, default=dict)
    wlans: Mapped[list] = mapped_column(JSON, default=list)                  # [{wlan_id, ssid, bssid}]
    channel_changes: Mapped[int] = mapped_column(Integer, default=0)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    present: Mapped[bool] = mapped_column(Boolean, default=True)
    # RF & frequency (app/wireless/rf.py; derived values are computed from channel + band + width, never guessed)
    frequency_mhz: Mapped[int | None] = mapped_column(Integer, nullable=True)            # primary 20 MHz channel
    center_frequency_mhz: Mapped[int | None] = mapped_column(Integer, nullable=True)     # bonded block center (None when unknown)
    dfs: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    radio_mac: Mapped[str] = mapped_column(String(17), default="", server_default="")
    link_changes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    tx_power_dbm: Mapped[float | None] = mapped_column(Float, nullable=True)             # only when the controller reports mW per level
    power_levels: Mapped[dict] = mapped_column(JSON, default=dict)                         # {level: mW}
    channel_assignment: Mapped[str] = mapped_column(String(16), default="", server_default="")   # automatic (RRM) | customized
    power_assignment: Mapped[str] = mapped_column(String(16), default="", server_default="")
    regdomain_supported: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    country: Mapped[str] = mapped_column(String(8), default="", server_default="")
    environment: Mapped[str] = mapped_column(String(16), default="", server_default="")  # indoor | outdoor | all
    recommended_channel: Mapped[int | None] = mapped_column(Integer, nullable=True)      # RRM recommendation (never applied)
    recommended_power_level: Mapped[int | None] = mapped_column(Integer, nullable=True)
    radar: Mapped[list] = mapped_column(JSON, default=list)                               # [{channel, last_heard_s, seen_at}]
    neighbors: Mapped[list] = mapped_column(JSON, default=list)                           # RRM neighbours heard by this radio
    last_channel_change_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rf_collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    meta_collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    neighbors_collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class WirelessWlan(Base):
    __tablename__ = "wireless_wlans"
    __table_args__ = (UniqueConstraint("wlc_id", "wlan_id", name="uq_wireless_wlan"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    wlc_id: Mapped[int] = mapped_column(ForeignKey("switches.id", ondelete="CASCADE"), index=True)
    wlan_id: Mapped[int] = mapped_column(Integer)
    profile: Mapped[str] = mapped_column(String(64), default="")
    ssid: Mapped[str] = mapped_column(String(64), default="")
    enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    security: Mapped[str] = mapped_column(String(64), default="")            # summary only, never keys
    max_clients: Mapped[int | None] = mapped_column(Integer, nullable=True)
    clients: Mapped[int | None] = mapped_column(Integer, nullable=True)
    radios: Mapped[int | None] = mapped_column(Integer, nullable=True)
    aps: Mapped[int | None] = mapped_column(Integer, nullable=True)
    present: Mapped[bool] = mapped_column(Boolean, default=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class WirelessClient(Base):
    """Current (and recently seen) client sessions as reported by the controller. Usernames are shown to admins only."""
    __tablename__ = "wireless_clients"
    __table_args__ = (UniqueConstraint("wlc_id", "mac", name="uq_wireless_client"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    wlc_id: Mapped[int] = mapped_column(ForeignKey("switches.id", ondelete="CASCADE"), index=True)
    mac: Mapped[str] = mapped_column(String(17), index=True)
    ip: Mapped[str] = mapped_column(String(64), default="", index=True)
    username: Mapped[str] = mapped_column(String(128), default="")
    ap_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    ap_mac: Mapped[str] = mapped_column(String(17), default="")
    slot: Mapped[int | None] = mapped_column(Integer, nullable=True)
    band: Mapped[str] = mapped_column(String(16), default="")
    protocol: Mapped[str] = mapped_column(String(16), default="")
    ssid: Mapped[str] = mapped_column(String(64), default="", index=True)
    wlan_profile: Mapped[str] = mapped_column(String(64), default="")
    vlan: Mapped[int | None] = mapped_column(Integer, nullable=True)
    channel: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="")
    auth_mode: Mapped[str] = mapped_column(String(24), default="")
    reason: Mapped[str] = mapped_column(String(64), default="")
    rssi_dbm: Mapped[float | None] = mapped_column(Float, nullable=True)
    snr_db: Mapped[float | None] = mapped_column(Float, nullable=True)
    tx_rate_mbps: Mapped[float | None] = mapped_column(Float, nullable=True)
    session_s: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    rx_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    tx_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    roams: Mapped[int] = mapped_column(Integer, default=0)
    disconnects: Mapped[int] = mapped_column(Integer, default=0)
    sources: Mapped[list] = mapped_column(JSON, default=list)                # MIBs that reported this client
    present: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)


class WirelessEvent(Base):
    """AP up/down, radio changes, channel changes, client association / disassociation and roams (from SNMP state
    changes between polls; timestamps are poll times, so roam timing is inferred, never measured)."""
    __tablename__ = "wireless_events"
    __table_args__ = (Index("ix_wireless_events_ap_at", "ap_id", "at"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    wlc_id: Mapped[int] = mapped_column(ForeignKey("switches.id", ondelete="CASCADE"), index=True)
    ap_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    client_mac: Mapped[str] = mapped_column(String(17), default="", index=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(16), default="informational")
    component: Mapped[str] = mapped_column(String(255), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    data: Mapped[dict] = mapped_column(JSON, default=dict)


class NmsMaintenance(Base):
    """Planned maintenance window for network devices (Sentinel NMS): alerts of in-scope devices are held back while it
    is active (collection continues). One-off (starts_at → ends_at) or weekly (weekdays + local start time + duration)."""
    __tablename__ = "nms_maintenance"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    reason: Mapped[str] = mapped_column(Text, default="")
    kind: Mapped[str] = mapped_column(String(8), default="once")             # once | weekly
    starts_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    weekdays: Mapped[list] = mapped_column(JSON, default=list)               # 0 = Monday
    start_time: Mapped[str] = mapped_column(String(5), default="")          # HH:MM in `timezone`
    duration_minutes: Mapped[int] = mapped_column(Integer, default=60)
    timezone: Mapped[str] = mapped_column(String(64), default="UTC")
    all_devices: Mapped[bool] = mapped_column(Boolean, default=False)
    switch_ids: Mapped[list] = mapped_column(JSON, default=list)
    sites: Mapped[list] = mapped_column(JSON, default=list)
    service_ids: Mapped[list] = mapped_column(JSON, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class NmsService(Base):
    """Service check (Zabbix simple / web checks, LibreNMS services): TCP connect, HTTP(S) request, DNS lookup or TLS
    certificate expiry against an operator-defined target. Read-only probes; TLS certificates are always verified."""
    __tablename__ = "nms_services"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    kind: Mapped[str] = mapped_column(String(8))                             # tcp | http | dns | tls
    target: Mapped[str] = mapped_column(String(255))                         # host name / IP, or the URL for http
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    expect: Mapped[str] = mapped_column(String(64), default="")              # http: accepted status codes / ranges ("200-399")
    match: Mapped[str] = mapped_column(String(255), default="")              # http: text the body must contain; dns: expected address
    record: Mapped[str] = mapped_column(String(8), default="A")              # dns record type
    switch_id: Mapped[int | None] = mapped_column(ForeignKey("switches.id", ondelete="SET NULL"), nullable=True, index=True)
    site: Mapped[str] = mapped_column(String(128), default="")
    interval_seconds: Mapped[int] = mapped_column(Integer, default=60)
    timeout_ms: Mapped[int] = mapped_column(Integer, default=5000)
    latency_warn_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cert_warn_days: Mapped[int] = mapped_column(Integer, default=21)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    state: Mapped[str] = mapped_column(String(10), default="unknown")       # ok | warning | critical | unknown
    state_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    fail_streak: Mapped[int] = mapped_column(Integer, default=0)
    last_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    last_message: Mapped[str] = mapped_column(Text, default="")
    cert_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SnmpCustomOid(Base):
    """Administrator-defined read-only OID item (Zabbix item / LibreNMS custom OID): a scalar GET or one table column
    WALK, polled with the device's own credential in the "custom" group and stored as switch_metrics
    (metric "custom:<name>"). Only GET / GETBULK are ever sent."""
    __tablename__ = "snmp_custom_oids"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    oid: Mapped[str] = mapped_column(String(255))
    method: Mapped[str] = mapped_column(String(8), default="get")            # get (scalar) | walk (table column)
    value_type: Mapped[str] = mapped_column(String(8), default="gauge")      # gauge | counter | state | info
    unit: Mapped[str] = mapped_column(String(16), default="")
    scale: Mapped[float] = mapped_column(Float, default=1.0)
    vendor: Mapped[str] = mapped_column(String(16), default="")              # "" = any
    product_line: Mapped[str] = mapped_column(String(64), default="")        # "" = any
    switch_ids: Mapped[list] = mapped_column(JSON, default=list)             # [] = every matching device
    description: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class SnmpProfileVersion(Base):
    """History of custom OID definitions and imported MIB modules (rollback restores `data`)."""
    __tablename__ = "snmp_profile_versions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(8))                             # oid | mib
    ref_id: Mapped[int] = mapped_column(Integer, index=True)
    version: Mapped[int] = mapped_column(Integer)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    action: Mapped[str] = mapped_column(String(16), default="update")
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SnmpMibModule(Base):
    """An imported MIB module: parsed (never executed) into object names → OIDs for search, OID test and naming of
    trap varbinds. A definition in a MIB is documentation; support on a device is only shown from what it answered."""
    __tablename__ = "snmp_mib_modules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    sha256: Mapped[str] = mapped_column(String(64))
    imports: Mapped[list] = mapped_column(JSON, default=list)
    unresolved: Mapped[list] = mapped_column(JSON, default=list)
    objects: Mapped[dict] = mapped_column(JSON, default=dict)                # name → {oid, kind, syntax, access, status, description}
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    imported_by: Mapped[str] = mapped_column(String(64), default="")
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SnmpMetricSetting(Base):
    """Administrator switch for a built-in registry metric (disabled metrics are skipped by collection where the
    collector supports it and hidden from capability coverage)."""
    __tablename__ = "snmp_metric_settings"
    key: Mapped[str] = mapped_column(String(96), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_by: Mapped[str] = mapped_column(String(64), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
