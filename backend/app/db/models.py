"""PostgreSQL models: inventory, credentials (encrypted), users, rules, alerts, audit, retention."""
from datetime import datetime, timezone

from sqlalchemy import JSON, BigInteger, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
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
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


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
    __table_args__ = (UniqueConstraint("rule_key", "group_key", "open_seq", name="uq_alert_group"),)
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
    firewall_id: Mapped[int] = mapped_column(ForeignKey("firewalls.id", ondelete="CASCADE"), index=True)
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


class LogSource(Base):
    """Non-FortiGate syslog sender (Windows event forwarder, CEF device, generic syslog), identified by source IP."""
    __tablename__ = "log_sources"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    kind: Mapped[str] = mapped_column(String(16), default="windows")  # windows | cef | syslog
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
