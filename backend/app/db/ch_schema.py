"""Versioned ClickHouse migrations (applied by `python -m app.migrate`)."""
import logging

from .ch import ClickHouse

log = logging.getLogger(__name__)

EVENT_COLUMNS = [
    "event_id", "event_time", "ingest_time", "category", "event_type", "event_subtype", "log_id",
    "firewall_id", "firewall_name", "site", "devid", "vdom", "source", "parser_version",
    "severity", "orig_severity", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "proto_name",
    "src_intf", "dst_intf", "policy_id", "policy_name", "action", "orig_action", "session_id",
    "app", "app_id", "app_cat", "service", "hostname", "url", "url_is_full", "http_method", "url_category",
    "sent_bytes", "rcvd_bytes", "sent_pkts", "rcvd_pkts", "duration",
    "nat_src_ip", "nat_src_port", "nat_dst_ip", "nat_dst_port",
    "dns_qname", "dns_qtype", "dns_rcode", "dns_resolved", "dns_latency_ms", "dns_qname_len", "dns_entropy",
    "threat", "user", "msg", "raw", "policy_uuid",
    "src_country", "dst_country", "dst_asn", "dst_as_org", "src_lat", "src_lon",
    "src_mac", "src_name", "src_os", "ti_match", "ti_source", "ti_category", "vpn_tunnel",
]

def _backfill_rollup(ch: ClickHouse) -> None:
    """Backfill events_1m from rows ingested before the materialized view existed.

    The view is created first and captures every insert from then on; rows with ingest_time before the cut are
    copied once. Run with syslog/worker stopped (see README upgrade steps) so no batch straddles the cut."""
    cut = ch.query("SELECT max(created) AS c FROM (SELECT metadata_modification_time AS created FROM system.tables "
                   "WHERE database = currentDatabase() AND name = 'events_1m_mv')")[0]["c"]
    ch.command(f"""
        INSERT INTO events_1m
        SELECT toStartOfMinute(event_time) AS minute, category, firewall_id, site, action, source,
               count() AS events, sum(sent_bytes) AS bytes_sent, sum(rcvd_bytes) AS bytes_rcvd
        FROM events FINAL WHERE ingest_time < toDateTime64('{cut}', 3, 'UTC')
        GROUP BY minute, category, firewall_id, site, action, source""")


def _backfill_src_hourly(ch: ClickHouse) -> None:
    """Seed 14 days of per-source history from events ingested before the view existed (same cut-off approach as v4)."""
    cut = ch.query("SELECT max(metadata_modification_time) AS c FROM system.tables "
                   "WHERE database = currentDatabase() AND name = 'src_hourly_mv'")[0]["c"]
    ch.command(f"""
        INSERT INTO src_hourly
        SELECT toStartOfHour(event_time) AS hour, firewall_id, src_ip, count(), sum(sent_bytes), sum(rcvd_bytes)
        FROM events WHERE category = 'traffic' AND src_ip != '' AND event_time >= now() - INTERVAL 14 DAY
          AND ingest_time < toDateTime64('{cut}', 3, 'UTC')
        GROUP BY hour, firewall_id, src_ip""")


MIGRATIONS: list[tuple[int, str, list]] = [
    (1, "events table", [
        """
        CREATE TABLE IF NOT EXISTS events (
            event_id String,
            event_time DateTime64(3, 'UTC'),
            ingest_time DateTime64(3, 'UTC') DEFAULT now64(3),
            category LowCardinality(String),
            event_type LowCardinality(String),
            event_subtype LowCardinality(String),
            log_id String,
            firewall_id UInt32,
            firewall_name LowCardinality(String),
            site LowCardinality(String),
            devid LowCardinality(String),
            vdom LowCardinality(String),
            source LowCardinality(String),
            parser_version LowCardinality(String),
            severity LowCardinality(String),
            orig_severity LowCardinality(String),
            src_ip String,
            src_port Nullable(UInt16),
            dst_ip String,
            dst_port Nullable(UInt16),
            proto Nullable(UInt8),
            proto_name LowCardinality(String),
            src_intf LowCardinality(String),
            dst_intf LowCardinality(String),
            policy_id Nullable(UInt32),
            policy_name String,
            action LowCardinality(String),
            orig_action LowCardinality(String),
            session_id Nullable(UInt64),
            app String,
            app_id Nullable(UInt32),
            app_cat LowCardinality(String),
            service LowCardinality(String),
            hostname String,
            url String,
            url_is_full UInt8,
            http_method LowCardinality(String),
            url_category LowCardinality(String),
            sent_bytes UInt64,
            rcvd_bytes UInt64,
            sent_pkts UInt64,
            rcvd_pkts UInt64,
            duration UInt32,
            nat_src_ip String,
            nat_src_port Nullable(UInt16),
            nat_dst_ip String,
            nat_dst_port Nullable(UInt16),
            dns_qname String,
            dns_qtype LowCardinality(String),
            dns_rcode LowCardinality(String),
            dns_resolved Array(String),
            dns_latency_ms Nullable(Float32),
            dns_qname_len UInt16,
            dns_entropy Float32,
            threat String,
            user String,
            msg String,
            raw String CODEC(ZSTD(3)),
            INDEX idx_src src_ip TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_dst dst_ip TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_host hostname TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_qname dns_qname TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_dport dst_port TYPE minmax GRANULARITY 4
        )
        ENGINE = ReplacingMergeTree(ingest_time)
        PARTITION BY (category, toYYYYMMDD(event_time))
        ORDER BY (category, firewall_id, event_time, event_id)
        SETTINGS index_granularity = 8192
        """,
    ]),
    (2, "per-minute ingestion rollup", [
        """
        CREATE TABLE IF NOT EXISTS events_minute (
            minute DateTime('UTC'),
            category LowCardinality(String),
            firewall_id UInt32,
            source LowCardinality(String),
            events UInt64,
            bytes UInt64
        ) ENGINE = SummingMergeTree
        PARTITION BY toYYYYMM(minute)
        ORDER BY (minute, category, firewall_id, source)
        TTL minute + INTERVAL 400 DAY
        """,
        """
        CREATE MATERIALIZED VIEW IF NOT EXISTS events_minute_mv TO events_minute AS
        SELECT toStartOfMinute(event_time) AS minute, category, firewall_id, source,
               count() AS events, sum(sent_bytes + rcvd_bytes) AS bytes
        FROM events GROUP BY minute, category, firewall_id, source
        """,
    ]),
    (3, "device metrics history", [
        """
        CREATE TABLE IF NOT EXISTS device_metrics (
            ts DateTime('UTC'),
            firewall_id UInt32,
            cpu Nullable(Float32),
            mem Nullable(Float32),
            sessions Nullable(UInt64),
            disk Nullable(Float32)
        ) ENGINE = MergeTree
        PARTITION BY toYYYYMM(ts)
        ORDER BY (firewall_id, ts)
        TTL ts + INTERVAL 90 DAY
        """,
    ]),
    (4, "per-minute rollup for dashboards", [
        """
        CREATE TABLE IF NOT EXISTS events_1m (
            minute DateTime('UTC'),
            category LowCardinality(String),
            firewall_id UInt32,
            site LowCardinality(String),
            action LowCardinality(String),
            source LowCardinality(String),
            events UInt64,
            bytes_sent UInt64,
            bytes_rcvd UInt64
        ) ENGINE = SummingMergeTree
        PARTITION BY (category, toYYYYMMDD(minute))
        ORDER BY (category, minute, firewall_id, site, action, source)
        """,
        """
        CREATE MATERIALIZED VIEW IF NOT EXISTS events_1m_mv TO events_1m AS
        SELECT toStartOfMinute(event_time) AS minute, category, firewall_id, site, action, source,
               count() AS events, sum(sent_bytes) AS bytes_sent, sum(rcvd_bytes) AS bytes_rcvd
        FROM events GROUP BY minute, category, firewall_id, site, action, source
        """,
        _backfill_rollup,
    ]),
    (5, "policy analytics: counter snapshots + policy uuid on events", [
        "ALTER TABLE events ADD COLUMN IF NOT EXISTS policy_uuid String DEFAULT ''",
        """
        CREATE TABLE IF NOT EXISTS policy_counters (
            ts DateTime('UTC'),
            firewall_id UInt32,
            vdom LowCardinality(String),
            policyid UInt32,
            uuid String,
            hit_count Nullable(UInt64),
            bytes Nullable(UInt64),
            packets Nullable(UInt64),
            active_sessions Nullable(UInt64),
            first_used Nullable(DateTime('UTC')),
            last_used Nullable(DateTime('UTC')),
            source LowCardinality(String)
        ) ENGINE = ReplacingMergeTree
        PARTITION BY toYYYYMM(ts)
        ORDER BY (firewall_id, vdom, policyid, ts)
        TTL ts + INTERVAL 400 DAY
        """,
    ]),
    (6, "enrichment: geo, ASN, asset identity, threat intel, VPN", [
        "ALTER TABLE events ADD COLUMN IF NOT EXISTS src_country LowCardinality(String) DEFAULT ''",
        "ALTER TABLE events ADD COLUMN IF NOT EXISTS dst_country LowCardinality(String) DEFAULT ''",
        "ALTER TABLE events ADD COLUMN IF NOT EXISTS dst_asn UInt32 DEFAULT 0",
        "ALTER TABLE events ADD COLUMN IF NOT EXISTS dst_as_org LowCardinality(String) DEFAULT ''",
        "ALTER TABLE events ADD COLUMN IF NOT EXISTS src_lat Nullable(Float32)",
        "ALTER TABLE events ADD COLUMN IF NOT EXISTS src_lon Nullable(Float32)",
        "ALTER TABLE events ADD COLUMN IF NOT EXISTS src_mac String DEFAULT ''",
        "ALTER TABLE events ADD COLUMN IF NOT EXISTS src_name String DEFAULT ''",
        "ALTER TABLE events ADD COLUMN IF NOT EXISTS src_os LowCardinality(String) DEFAULT ''",
        "ALTER TABLE events ADD COLUMN IF NOT EXISTS ti_match String DEFAULT ''",
        "ALTER TABLE events ADD COLUMN IF NOT EXISTS ti_source LowCardinality(String) DEFAULT ''",
        "ALTER TABLE events ADD COLUMN IF NOT EXISTS ti_category LowCardinality(String) DEFAULT ''",
        "ALTER TABLE events ADD COLUMN IF NOT EXISTS vpn_tunnel LowCardinality(String) DEFAULT ''",
        "ALTER TABLE events ADD INDEX IF NOT EXISTS idx_ti ti_match TYPE bloom_filter(0.01) GRANULARITY 4",
        # per-source hourly traffic rollup: cheap behavioural baselines (UEBA) without scanning raw events
        """
        CREATE TABLE IF NOT EXISTS src_hourly (
            hour DateTime('UTC'),
            firewall_id UInt32,
            src_ip String,
            events UInt64,
            bytes_sent UInt64,
            bytes_rcvd UInt64
        ) ENGINE = SummingMergeTree
        PARTITION BY toYYYYMM(hour)
        ORDER BY (src_ip, hour, firewall_id)
        TTL hour + INTERVAL 120 DAY
        """,
        """
        CREATE MATERIALIZED VIEW IF NOT EXISTS src_hourly_mv TO src_hourly AS
        SELECT toStartOfHour(event_time) AS hour, firewall_id, src_ip, count() AS events,
               sum(sent_bytes) AS bytes_sent, sum(rcvd_bytes) AS bytes_rcvd
        FROM events WHERE category = 'traffic' AND src_ip != '' GROUP BY hour, firewall_id, src_ip
        """,
        _backfill_src_hourly,
    ]),
    (7, "ICMP reachability probes (ISP / public IP monitoring)", [
        """
        CREATE TABLE IF NOT EXISTS icmp_results (
            ts DateTime64(3, 'UTC'),
            target_id UInt32,
            address LowCardinality(String),
            sent UInt8,
            received UInt8,
            rtt_min Nullable(Float32),
            rtt_avg Nullable(Float32),
            rtt_max Nullable(Float32),
            jitter Nullable(Float32),
            up UInt8,
            state LowCardinality(String)
        ) ENGINE = MergeTree
        PARTITION BY toYYYYMM(ts)
        ORDER BY (target_id, ts)
        TTL toDateTime(ts) + INTERVAL 400 DAY
        """,
    ]),
    (8, "BGP peer samples and peer/route events from API polling", [
        """
        CREATE TABLE IF NOT EXISTS bgp_samples (
            ts DateTime('UTC'),
            firewall_id UInt32,
            peer LowCardinality(String),
            state LowCardinality(String),
            up UInt8,
            prefixes Nullable(UInt32)
        ) ENGINE = MergeTree
        PARTITION BY toYYYYMM(ts)
        ORDER BY (firewall_id, peer, ts)
        TTL ts + INTERVAL 400 DAY
        """,
        """
        CREATE TABLE IF NOT EXISTS bgp_events (
            ts DateTime64(3, 'UTC'),
            firewall_id UInt32,
            peer LowCardinality(String),
            kind LowCardinality(String),
            prefix String,
            detail String
        ) ENGINE = MergeTree
        PARTITION BY toYYYYMM(ts)
        ORDER BY (firewall_id, peer, ts)
        TTL toDateTime(ts) + INTERVAL 400 DAY
        """,
    ]),
]


def migrate(ch: ClickHouse) -> list[int]:
    ch.command(
        "CREATE TABLE IF NOT EXISTS schema_migrations (version UInt32, name String, applied_at DateTime DEFAULT now()) "
        "ENGINE = MergeTree ORDER BY version"
    )
    applied = {int(r["version"]) for r in ch.query("SELECT version FROM schema_migrations")}
    done = []
    for version, name, stmts in MIGRATIONS:
        if version in applied:
            continue
        for stmt in stmts:
            stmt(ch) if callable(stmt) else ch.command(stmt)
        ch.command("INSERT INTO schema_migrations (version, name) VALUES ({v:UInt32}, {n:String})", {"v": version, "n": name})
        log.info("applied clickhouse migration %s %s", version, name)
        done.append(version)
    return done
