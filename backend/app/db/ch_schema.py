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
    (9, "Switch monitoring: device metrics, interface samples, hourly rollups", [
        # device-level gauges; component is a bounded label (CPU id, sensor / PSU / fan name, PoE unit), never a MAC or description
        """
        CREATE TABLE IF NOT EXISTS switch_metrics (
            ts DateTime('UTC'),
            switch_id UInt32,
            metric LowCardinality(String),
            component LowCardinality(String),
            value Float64
        ) ENGINE = MergeTree
        PARTITION BY toYYYYMM(ts)
        ORDER BY (switch_id, metric, component, ts)
        TTL ts + INTERVAL 90 DAY
        """,
        """
        CREATE TABLE IF NOT EXISTS switch_metrics_hourly (
            hour DateTime('UTC'),
            switch_id UInt32,
            metric LowCardinality(String),
            component LowCardinality(String),
            samples SimpleAggregateFunction(sum, UInt64),
            total SimpleAggregateFunction(sum, Float64),
            vmin SimpleAggregateFunction(min, Float64),
            vmax SimpleAggregateFunction(max, Float64)
        ) ENGINE = AggregatingMergeTree
        PARTITION BY toYYYYMM(hour)
        ORDER BY (switch_id, metric, component, hour)
        TTL hour + INTERVAL 400 DAY
        """,
        """
        CREATE MATERIALIZED VIEW IF NOT EXISTS switch_metrics_hourly_mv TO switch_metrics_hourly AS
        SELECT toStartOfHour(ts) AS hour, switch_id, metric, component, count() AS samples, sum(value) AS total,
               min(value) AS vmin, max(value) AS vmax
        FROM switch_metrics GROUP BY hour, switch_id, metric, component
        """,
        # per-interface rates and per-interval counter increments (nulls where no valid delta exists)
        """
        CREATE TABLE IF NOT EXISTS switch_if_samples (
            ts DateTime('UTC'),
            switch_id UInt32,
            ifindex UInt32,
            interval_s Float32,
            rx_bps Nullable(Float64),
            tx_bps Nullable(Float64),
            rx_util Nullable(Float32),
            tx_util Nullable(Float32),
            rx_pps Nullable(Float64),
            tx_pps Nullable(Float64),
            in_errors Nullable(UInt64),
            out_errors Nullable(UInt64),
            in_discards Nullable(UInt64),
            out_discards Nullable(UInt64),
            crc Nullable(UInt64),
            oper UInt8,
            admin UInt8,
            flags UInt8
        ) ENGINE = MergeTree
        PARTITION BY toYYYYMMDD(ts)
        ORDER BY (switch_id, ifindex, ts)
        TTL ts + INTERVAL 35 DAY
        """,
        """
        CREATE TABLE IF NOT EXISTS switch_if_hourly (
            hour DateTime('UTC'),
            switch_id UInt32,
            ifindex UInt32,
            samples SimpleAggregateFunction(sum, UInt64),
            rated SimpleAggregateFunction(sum, UInt64),
            rx_bps_sum SimpleAggregateFunction(sum, Float64),
            tx_bps_sum SimpleAggregateFunction(sum, Float64),
            rx_bps_max SimpleAggregateFunction(max, Float64),
            tx_bps_max SimpleAggregateFunction(max, Float64),
            rx_util_max SimpleAggregateFunction(max, Float32),
            tx_util_max SimpleAggregateFunction(max, Float32),
            in_errors SimpleAggregateFunction(sum, UInt64),
            out_errors SimpleAggregateFunction(sum, UInt64),
            in_discards SimpleAggregateFunction(sum, UInt64),
            out_discards SimpleAggregateFunction(sum, UInt64),
            crc SimpleAggregateFunction(sum, UInt64),
            down_samples SimpleAggregateFunction(sum, UInt64)
        ) ENGINE = AggregatingMergeTree
        PARTITION BY toYYYYMM(hour)
        ORDER BY (switch_id, ifindex, hour)
        TTL hour + INTERVAL 400 DAY
        """,
        """
        CREATE MATERIALIZED VIEW IF NOT EXISTS switch_if_hourly_mv TO switch_if_hourly AS
        SELECT toStartOfHour(ts) AS hour, switch_id, ifindex, count() AS samples, countIf(rx_bps IS NOT NULL) AS rated,
               sum(ifNull(rx_bps, 0)) AS rx_bps_sum, sum(ifNull(tx_bps, 0)) AS tx_bps_sum,
               max(ifNull(rx_bps, 0)) AS rx_bps_max, max(ifNull(tx_bps, 0)) AS tx_bps_max,
               max(ifNull(rx_util, 0)) AS rx_util_max, max(ifNull(tx_util, 0)) AS tx_util_max,
               sum(ifNull(in_errors, 0)) AS in_errors, sum(ifNull(out_errors, 0)) AS out_errors,
               sum(ifNull(in_discards, 0)) AS in_discards, sum(ifNull(out_discards, 0)) AS out_discards,
               sum(ifNull(crc, 0)) AS crc, countIf(oper = 0 AND admin = 1) AS down_samples
        FROM switch_if_samples GROUP BY hour, switch_id, ifindex
        """,
    ]),
    (10, "TACACS+ AAA events (authentication, authorization, accounting, connections)", [
        """
        CREATE TABLE IF NOT EXISTS tacacs_events (
            ts DateTime64(3, 'UTC'),
            server_id UInt32,
            log LowCardinality(String),
            msgid LowCardinality(String),
            event_type LowCardinality(String),
            result LowCardinality(String),
            username String,
            device_address String,
            device_name LowCardinality(String),
            client_id UInt32,
            vendor LowCardinality(String),
            site LowCardinality(String),
            port String,
            remote_addr String,
            service LowCardinality(String),
            priv_lvl Nullable(UInt8),
            profile LowCardinality(String),
            rule LowCardinality(String),
            server_address String,
            identity_source LowCardinality(String),
            action String,
            cmd String,
            cmd_category LowCardinality(String),
            task_id String,
            session_id String,
            elapsed_s Nullable(UInt32),
            hint String,
            raw String,
            fingerprint String,
            ingest_time DateTime('UTC') DEFAULT now(),
            INDEX ix_user username TYPE bloom_filter GRANULARITY 4,
            INDEX ix_dev device_address TYPE bloom_filter GRANULARITY 4,
            INDEX ix_task task_id TYPE bloom_filter GRANULARITY 4
        ) ENGINE = ReplacingMergeTree
        PARTITION BY toYYYYMM(ts)
        ORDER BY (server_id, ts, fingerprint)
        TTL toDateTime(ts) + INTERVAL 400 DAY
        """,
    ]),
    (11, "WAN observability: per-probe RTTs, error class, scheduling delay and ingestion time on ICMP checks", [
        # rtts: every successful echo RTT of the check, in send order (exact percentiles and jitter from real samples)
        "ALTER TABLE icmp_results ADD COLUMN IF NOT EXISTS rtts Array(Float32) DEFAULT []",
        # error_class: '' (replied or network timeout) | 'local' (resolver / socket failure on the SIEM: not packet loss)
        "ALTER TABLE icmp_results ADD COLUMN IF NOT EXISTS error_class LowCardinality(String) DEFAULT ''",
        "ALTER TABLE icmp_results ADD COLUMN IF NOT EXISTS error String DEFAULT ''",
        "ALTER TABLE icmp_results ADD COLUMN IF NOT EXISTS attempts UInt8 DEFAULT 1",
        "ALTER TABLE icmp_results ADD COLUMN IF NOT EXISTS sched_delay_ms Float32 DEFAULT 0",
        "ALTER TABLE icmp_results ADD COLUMN IF NOT EXISTS ingested_at DateTime64(3, 'UTC') DEFAULT now64(3)",
    ]),
    (12, "Wireless (Cisco WLC): AP / radio / WLAN / controller metrics and client RF samples", [
        """
        CREATE TABLE IF NOT EXISTS wireless_metrics (
            ts DateTime64(3, 'UTC'),
            wlc_id UInt32,
            ap_id UInt32 DEFAULT 0,
            slot Int16 DEFAULT -1,
            wlan_id UInt32 DEFAULT 0,
            band LowCardinality(String) DEFAULT '',
            metric LowCardinality(String),
            value Float64,
            source LowCardinality(String) DEFAULT ''
        ) ENGINE = MergeTree
        PARTITION BY toYYYYMM(ts)
        ORDER BY (wlc_id, metric, ap_id, slot, ts)
        TTL toDateTime(ts) + INTERVAL 90 DAY
        """,
        # client samples: high cardinality by design (one row per client per poll), short retention, never labels
        """
        CREATE TABLE IF NOT EXISTS wireless_client_samples (
            ts DateTime64(3, 'UTC'),
            wlc_id UInt32,
            mac String,
            ap_id UInt32 DEFAULT 0,
            slot Int16 DEFAULT -1,
            ssid LowCardinality(String) DEFAULT '',
            band LowCardinality(String) DEFAULT '',
            rssi_dbm Nullable(Float32),
            snr_db Nullable(Float32),
            tx_rate_mbps Nullable(Float32),
            rx_bytes Nullable(UInt64),
            tx_bytes Nullable(UInt64),
            source LowCardinality(String) DEFAULT ''
        ) ENGINE = MergeTree
        PARTITION BY toYYYYMMDD(ts)
        ORDER BY (wlc_id, mac, ts)
        TTL toDateTime(ts) + INTERVAL 14 DAY
        """,
    ]),
    (13, "RF & frequency telemetry: vendor-neutral per-radio samples with band, channel, frequency, source, status and quality", [
        # value is NULL whenever status != 'ok' (missing / invalid / stale): missing telemetry is never stored as zero
        """
        CREATE TABLE IF NOT EXISTS rf_telemetry (
            ts DateTime64(3, 'UTC'),
            site LowCardinality(String) DEFAULT '',
            wlc_id UInt32,
            ap_id UInt32,
            radio_id UInt32,
            slot Int16,
            vendor LowCardinality(String) DEFAULT '',
            band LowCardinality(String) DEFAULT '',
            channel Nullable(Int16),
            center_mhz Nullable(Int32),
            width_mhz Nullable(Int16),
            metric LowCardinality(String),
            value Nullable(Float64),
            unit LowCardinality(String) DEFAULT '',
            source LowCardinality(String) DEFAULT '',
            status LowCardinality(String) DEFAULT 'ok',
            quality LowCardinality(String) DEFAULT 'measured'
        ) ENGINE = MergeTree
        PARTITION BY toYYYYMMDD(ts)
        ORDER BY (metric, wlc_id, ap_id, radio_id, ts)
        TTL toDateTime(ts) + INTERVAL 30 DAY
        """,
    ]),
    (14, "NMS service checks: one row per TCP / HTTP / DNS / TLS check result", [
        # latency is NULL when the check could not measure it (connection refused, DNS failure): never stored as zero
        """
        CREATE TABLE IF NOT EXISTS service_results (
            ts DateTime('UTC'),
            service_id UInt32,
            state LowCardinality(String),
            latency_ms Nullable(Float32),
            message String
        ) ENGINE = MergeTree
        PARTITION BY toYYYYMM(ts)
        ORDER BY (service_id, ts)
        TTL ts + INTERVAL 400 DAY
        """,
    ]),
    (15, "SNMP traps / informs: normalised notification rows with raw varbinds", [
        # severity / component come from the vendor trap parsers; varbinds is the raw list as JSON (OID, type, value, name)
        """
        CREATE TABLE IF NOT EXISTS snmp_traps (
            ts DateTime('UTC'),
            switch_id UInt32,
            source_ip String,
            version LowCardinality(String),
            vendor LowCardinality(String),
            trap_oid String,
            trap_name String,
            severity LowCardinality(String),
            component String,
            ifindex Nullable(UInt32),
            summary String,
            varbinds String,
            repeats UInt32 DEFAULT 0
        ) ENGINE = MergeTree
        PARTITION BY toYYYYMM(ts)
        ORDER BY (switch_id, ts)
        TTL ts + INTERVAL 180 DAY
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
