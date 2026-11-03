"""Environment-based configuration. Secrets come from files (`<NAME>_FILE`, see secret_files.py) or, for development and
not-yet-migrated installations, from the environment; never from the database or the image."""
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: str = "production"
    log_level: str = "INFO"

    # PostgreSQL (metadata, users, config, audit)
    # no password in the URL: it comes from DATABASE_PASSWORD_FILE (or is embedded only in environment-only installs)
    database_url: str = Field(default="postgresql+asyncpg://siem@postgres:5432/siem", repr=False)
    database_password: str = Field(default="", repr=False)
    # Connection pool per process (pool + overflow = peak connections). The long-running processes share PostgreSQL's
    # default max_connections=100, so the defaults stay small; the worker sizes its own pool from its poll concurrency
    # and syslog parser processes use 1+1 (budget: docs/DEPLOYMENT_AND_ROLLBACK_GUIDE.md).
    db_pool_size: int = 4
    db_max_overflow: int = 4
    db_pool_timeout_seconds: float = 30.0
    db_pool_recycle_seconds: int = 1800

    # ClickHouse (events). mode=server uses clickhouse-connect; mode=embedded uses chdb (dev/tests only).
    clickhouse_mode: str = "server"
    clickhouse_host: str = "clickhouse"
    clickhouse_port: int = 8123
    clickhouse_user: str = "siem"
    clickhouse_password: str = Field(default="", repr=False)
    clickhouse_database: str = "siem"
    clickhouse_embedded_path: str = ""
    # Concurrent ClickHouse requests per process. One shared client behind a lock serialised every query and insert, so
    # one slow hunt/export query stalled every dashboard in that process; each slot is an independent HTTP client.
    clickhouse_pool_size: int = 4
    # FINAL collapses not-yet-merged duplicates at query time but is very expensive at tens of millions of rows/day.
    # Duplicates are already suppressed at ingest (fingerprint LRU) and collapsed by background merges, so it is off by default.
    clickhouse_query_final: bool = False

    # Security
    secret_key: str = Field(default="", repr=False, description="JWT signing key (>=32 chars)")
    token_encryption_key: str = Field(default="", repr=False, description="Fernet key used to encrypt stored device credentials")
    # comma-separated earlier Fernet keys, accepted for decryption only while `python -m app.rotate_keys` re-encrypts
    token_encryption_key_previous: str = Field(default="", repr=False)
    session_ttl_minutes: int = 480
    cookie_secure: bool = True
    login_rate_limit_per_minute: int = 10
    api_rate_limit_per_minute: int = 600
    max_query_range_days: int = 92  # widest custom start/end window accepted by event queries
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str = Field(default="", repr=False)

    # FortiGate API client
    fortigate_timeout_seconds: float = 15.0
    fortigate_max_retries: int = 4
    fortigate_requests_per_second: float = 5.0
    fortigate_ca_bundle: str = ""  # path to CA bundle used to verify FortiGate certificates
    fortigate_ca_dir: str = "/certs"  # per-firewall ca_bundle_path must point inside this directory
    # comma-separated hosts exempt from the outbound SSRF guard (see app/netguard.py); empty = none
    outbound_allowed_hosts: str = ""
    fortigate_log_page_rows: int = 500

    # Syslog
    syslog_udp_port: int = 5514
    syslog_tcp_port: int = 5514
    # rows per ClickHouse insert: fewer, larger parts keep background merges (the main ClickHouse CPU cost) down
    syslog_batch_size: int = 10000
    # Events held in memory while ClickHouse is slow or down (0 = 10 x syslog_batch_size). At the cap, TCP sessions and
    # parser workers stop reading (backpressure reaches the relay's disk queue); only inline UDP counts drops.
    syslog_buffer_max_events: int = 0
    # A chunk ClickHouse keeps rejecting while other chunks insert fine (e.g. too many partitions, a bad value) is
    # written here as JSON lines after this many attempts instead of blocking ingestion: python -m app.ingest.deadletter
    ingest_insert_max_attempts: int = 3
    ingest_deadletter_dir: str = "/tmp/siem-deadletter"
    syslog_flush_seconds: float = 2.0
    # parser workers insert a partial batch after this long, so a quiet feed still lands within seconds
    syslog_worker_flush_seconds: float = 8.0
    syslog_allow_unknown_devices: bool = False
    # devid/devname in a syslog line are plain text anyone can send. By default the sender's IP must also be one of the
    # firewall's addresses (host / syslog_source_ips). true restores the old behaviour of trusting the message fields.
    syslog_trust_device_fields: bool = False
    syslog_tcp_idle_seconds: float = 300.0
    syslog_tcp_max_connections: int = 256
    # Relay port: the ingress container (deploy/ingress, rsyslog) owns host port 514, buffers while this service restarts
    # and forwards "<sender-ip> <original line>" frames here. Only connections from SYSLOG_RELAY_HOSTS are accepted,
    # because the frame names the sender: an untrusted peer could otherwise impersonate a firewall. 0 disables it.
    syslog_relay_port: int = 5515
    syslog_relay_hosts: str = "ingress"
    # parser processes behind the receiver (0 = one per CPU, minus one, at most 4; 1 = parse in the receiver process)
    syslog_workers: int = 0
    # Infrastructure as Code. The only path that may write to firewalls; off unless the operator sets this AND an IaC
    # administrator enables writes in the IaC settings. Plans, drift, validation and dry runs never write.
    iac_device_writes: bool = False
    iac_job_timeout_seconds: int = 1800        # whole deployment job
    iac_max_concurrent_jobs: int = 2
    iac_max_plan_devices: int = 25

    # Switch monitoring (SNMP, read-only). SNMPv2c sends the community in clear text: refused unless enabled here.
    switch_allow_snmpv2c: bool = False
    switch_max_concurrent_polls: int = 16      # switches polled at once (each switch: one request in flight)
    switch_poll_timeout_seconds: int = 240     # whole poll of one switch
    switch_wlc_poll_timeout_seconds: int = 900       # whole poll of a wireless controller (large AP / client tables walk slowly)
    switch_wireless_group_timeout_seconds: int = 300 # one wireless collection group (e.g. the client table)
    switch_discovery_max_hosts: int = 1024     # largest subnet a discovery run may sweep
    switch_discovery_concurrency: int = 16
    switch_event_retention_days: int = 180
    switch_max_vlan_contexts: int = 64         # Cisco per-VLAN contexts read for MAC table / PVST
    switch_max_macs: int = 50000

    # TACACS+ AAA (tac_plus-ng + deploy agent, see docs/TACACS.md). Shared volumes mounted into the worker.
    tacacs_config_dir: str = "/tacacs/config"
    tacacs_log_dir: str = "/tacacs/logs"
    tacacs_deploy_timeout_seconds: int = 90
    tacacs_test_timeout_seconds: float = 8.0

    # Worker
    alert_interval_seconds: int = 60
    retention_interval_seconds: int = 3600
    policy_sync_interval_seconds: int = 900
    # enrichment / next-gen features
    geoip_dir: str = "/geoip"
    # AI assistant (Claude API). Off unless an API key is configured. Question → query sends only the question and the
    # field catalogue; summaries send incident/alert content and therefore need AI_ALLOW_DATA_SHARING=true as well.
    anthropic_api_key: str = Field(default="", repr=False)
    ai_model: str = "claude-opus-5-5"
    ai_allow_data_sharing: bool = False
    ti_refresh_minutes: int = 60
    ti_fetch_max_bytes: int = 25_000_000
    asset_learn_interval_seconds: int = 600
    internal_cidrs: str = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
    public_base_url: str = ""  # used for links in notifications/reports, e.g. https://siem.example.internal  # policy config + counter snapshots (read-only GETs)

    # Demo mode: synthetic, sanitized FortiGate-format logs tagged source='demo'
    demo_mode: bool = False
    demo_events_per_second: int = 20


@lru_cache
def get_settings() -> Settings:
    from .secret_files import file_overrides, inject_database_password
    s = Settings(**file_overrides())
    s.database_url = inject_database_password(s.database_url, s.database_password)
    return s
