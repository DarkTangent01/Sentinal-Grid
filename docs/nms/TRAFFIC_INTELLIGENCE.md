# Sentinel NMS: Application & Protocol Intelligence

Traffic analytics from the flow records that network devices export: NetFlow v5 / v9, IPFIX and sFlow v5. It covers:

- applications and protocols;
- QUIC / HTTP/3;
- talkers and conversations;
- VLANs and the inter-VLAN matrix;
- interfaces;
- DNS and domains;
- traffic security detections.

Navigation: **Sentinel NMS → Application & Protocol Intelligence** (`/nms/traffic`). The former Flow Analytics page
(`/nms/flows`) redirects here.

Everything shown comes from real telemetry. Pages are empty until a device exports flows. No sample data is shipped.

## 1. Architecture

```
devices ──NetFlow/IPFIX/sFlow──▶ flows service (app/flows)          ClickHouse
                                  decode, inventory allowlist   ──▶  flows (raw, 30 d)
                                  counters → nms_self_metrics          ├─▶ flows_conv_hourly (conversations, 35 d)   [new]
                                                                       ├─▶ flows_if_hourly   (interfaces, 400 d)
                                                                       └─▶ flows_talkers_hourly (pairs, 90 d)
worker loop traffic_enrichment (5 min) ── DNS logs / firewall app control / ASN / rDNS ──▶ PostgreSQL traffic_ip_info
NMS alert pass ── app/traffic/detections.py ──▶ alerts (dedup, suppression, ack, assign, notes, notifications)
API /api/nms/traffic/* (app/api/traffic.py) ── app/traffic/{query,analytics}.py ── reads the tables above
UI  frontend/src/pages/nms/Traffic.tsx, TrafficConfig.tsx
```

**Reused, not duplicated:**

- the existing flow collector and decoders (extended, not replaced);
- ClickHouse and PostgreSQL;
- the NMS alert framework (alerts, suppressions, notifications, maintenance windows);
- NMS RBAC (`app/access/rbac.py`) and site scope;
- inventory: switches, interfaces, LAG membership, VLANs, MAC tables and wireless clients;
- local GeoIP / ASN databases (`app/platform/geoip.py`);
- the report framework (section `traffic_intelligence`, HTML + PDF);
- self-monitoring (`nms_self_metrics`);
- the UI components.

**Product boundary:**

- `app/traffic` and `app/api/traffic.py` are Sentinel NMS modules (enforced by `tests/test_product_boundaries.py`).
- DNS logs and firewall application-control results are read from the shared event store through
  `app/platform/eventquery`. When the products' databases are separated (migration plan, phase 6), these become
  "unavailable" unless the integration provides them. The module never fabricates them.

## 2. What the telemetry can and cannot tell

| Question | Source | Notes |
|---|---|---|
| Bytes / packets | flow records | sFlow and sampled NetFlow / IPFIX are multiplied by the sampling rate: **estimates**, marked `≈` and "sampled" |
| Protocol (TCP / UDP / ICMP / ESP / GRE …) | IP protocol field | exact |
| Application, port-based | signature registry | "port-based" confidence; ambiguous ports are labelled "(possible)" |
| QUIC confirmed | sFlow sampled packet head shows a QUIC long header (version 1 / 2 / draft) | only handshake packets carry it; other UDP/443 traffic is "possible QUIC" |
| HTTP/2 vs HTTP/1.1 | — | not visible (TLS hides ALPN); the UI says so |
| Plain HTTP / SSH / TLS proven | sFlow packet head (request line, banner, TLS record) | "confirmed" protocol, not an application |
| Application confirmed | firewall application control for the destination (≥ 80 % of its sessions) | needs FortiGate traffic logs with application control |
| Application high | destination resolved from a DNS name matching a domain signature, and the address is not shared by more than 4 registered domains | needs DNS logs (Zeek, FortiGate DNS, resolver syslog) |
| Provider probable | the destination's ASN is in the registry (Microsoft, Google, Cloudflare, AWS …) | never a specific product (not "Teams" from ASN 8075) |
| MAC address | sFlow Ethernet header, IPFIX IE 56 / 80 | layer-2 next hop when the traffic was routed |
| TCP flags | NetFlow v5, v9 / IPFIX IE 6, sFlow TCP header | used for scan detection (SYN-only probes) |
| VLAN | 802.1Q tag in the sampled header, sFlow extended switch record (1001), IPFIX IE 58 / 59; else the switches' MAC address tables (SNMP) for the client's MAC; else the configured range | resolved by the collector at ingest, so rollups carry it. A MAC learned in several VLANs (gateway / router) is never used. Samples taken before this existed keep VLAN 0 |

## 3. Classification engine

- **Level 1 (protocol):** the IANA protocol number (`registry.PROTOCOLS`).
- **Level 2 (port signatures):** PostgreSQL `traffic_signatures` (kind `port`). The protocol and port range map to an
  application, a category, whether it is encrypted, and whether the port is ambiguous. Raw records check both ports:
  the destination port first, the source port for replies, and the lower port when both match. Rollups store the
  service port (the lower non-zero port). Built-in signatures cover the list in the requirements plus 40 more.
  Administrators add, edit or disable rows in **Rules & Signatures**, with no code change; changes apply within 30 s.
  A deleted built-in signature is not re-seeded.
- **Level 3 (application):** enrichment per server address (`app/traffic/enrich.py`), cached in `traffic_ip_info`
  and recomputed every 6 hours for the busiest 2 000 destinations of the last 2 hours. Evidence order: firewall
  application control → DNS-correlated domain signature → ASN provider. The evidence text is stored and shown in the
  host drawer.
- **Confidence:** `confirmed`, `high`, `probable`, `port-based`, `unknown`. In SQL the labels are built from bound
  parameter arrays (`transform`). Requests never contain SQL.

## 4. Direction, networks and zones

**Network ranges.** PostgreSQL `traffic_networks` holds the CIDR, internal flag, site, VLAN and zone (corporate, guest,
iot, cctv, management, server, dmz, vpn, voice, other), managed under **Networks & Settings**.

- The most specific range wins.
- A range marked not internal carves an address out of a larger internal range.
- Until any internal range exists, the private blocks (RFC 1918, RFC 6598, RFC 4193, link-local) count as internal.
- No site subnet is built into the code.

**Direction:**

| Source → destination | Direction |
|---|---|
| internal → internal | east-west |
| internal → external | outbound |
| external → internal | inbound |
| external → external | transit |

**VLAN / zone policies** (`traffic_vlan_policies`):

- Each policy is `allow` or `deny` between two endpoints: `any`, `internal`, `external`, `zone:<zone>` or `vlan:<id>`.
- A VLAN-level allow beats a zone-level deny.
- Nine zone policies are seeded: guest → internal zones, IoT → corporate / management, CCTV → corporate / guest /
  internet, and corporate → management.
- They only take effect for ranges tagged with those zones.

## 5. Deduplication and LAG

**Across exporters** (setting `dedup`). The same conversation exported by several devices on its path is counted once:
per conversation (source, destination, protocol, service port) and time bucket, the largest exporter's figures are
kept. The alternative, `none`, adds them up. Device and interface views are never deduplicated.

**LAG** (setting `lag_mode`):

- `members` (default): LAG members are counted, and the LAG row shows their sum.
- `logical`: the logical interface is counted and members are marked.

A LAG and its members are never both counted.

## 6. Detections (NMS alert rules, prefix `traffic_`)

| Rule | Window | Fires on | Guards against false positives |
|---|---|---|---|
| `traffic_unexpected_mqtt` | 15 min | TCP 1883 / 8883 to a broker not approved, or from a network not allowed to use MQTT | approved brokers / clients; cross-VLAN only reported when enabled |
| `traffic_unauthorized_snmp` | 15 min | SNMP requests from, or traps to, an address that is not an authorised manager | **silent until authorised managers are configured** (never flags the NMS itself) |
| `traffic_excessive_dns` | 15 min | DNS packets above a threshold, DNS to resolvers outside the approved list (when configured), large average DNS payloads (tunnelling indicator) | approved resolvers are not clients; SYN-only TCP probes ignored; query names / NXDOMAIN stay with the SIEM DNS rules (DNS logs) |
| `traffic_new_external_destination` | 60 min | an external server not seen in the 7-day baseline receives ≥ 50 MB; single-device destinations are raised | learning period (3 days of history) |
| `traffic_port_scan` | 10 min | ≥ 100 ports on one host, or ≥ 50 hosts on one port, with small flows; sequential ranges and SYN-only probes raise severity | allowed scanners; thresholds on observed (sampled) counts |
| `traffic_vlan_policy` | 15 min | traffic between zones / VLANs a policy denies; new VLAN pairs (informational) only when enabled | inter-VLAN traffic as such is never reported |
| `traffic_insecure_protocol` | 60 min | services of the listed unencrypted protocols (Telnet, FTP, TFTP, POP3, IMAP, MQTT, Redis, CoAP; HTTP optional) | SYN-only probes ignored; encryption is never claimed as verified unless an HTTP request line was sampled |
| `traffic_custom` | per rule | custom watch rules: protocol / ports / networks / direction above a volume | per-rule exclusions |

**Behaviour common to every rule:**

- Each run returns at most 25 detections.
- Detections are grouped per conversation, source or policy. While the condition continues, the existing open alert is
  updated, not duplicated.
- Every rule is excluded from the networks in `detection_exclusions`.

**Each detection carries:**

- severity, source and destination;
- evidence: bytes, packets, ports, VLANs, sampling, exporters, confidence and threshold;
- first and last seen, and event count;
- next steps;
- a "View traffic" filter.

**Workflow** (Detections tab or `/api/nms/traffic/detections`):

- acknowledge, assign, add resolution notes, resolve;
- suppress for 24 h (rule managers);
- incident link (combined deployment).

Thresholds, windows, severities and allow-lists are edited under **Rules & Signatures → Detection rules**. The API
validates each value against its default's type and range.

## 7. API (`/api/nms/traffic`)

**Common filters:**

- time: `range` (5m, 15m, 1h, 6h, 24h, 7d, 30d), or `start` / `end` (ISO 8601 with zone, at most 30 days);
- `site`, `exporter`, `interface` (needs `exporter`), `vlan`, `app`, `category`, `proto`, `port`;
- `src`, `dst` and `ip` (each an IP or CIDR), `direction`.

**Paging and sorting:** `limit` ≤ 500 and `offset` ≤ 100 000. `sort` accepts only whitelisted keys (prefix `-` for
descending).

| Method | Path | Permission |
|---|---|---|
| GET | overview, applications, protocols, web, top-sources, top-destinations, conversations, flows (≤ 24 h), vlans, vlan-matrix, interfaces, trends, collectors, options, hosts/{addr}, signatures, networks, vlan-policies, settings | `nms.traffic.view` |
| GET | domains | `nms.traffic.sensitive.view` (unscoped accounts only) |
| GET / PATCH | detections, detections/{id}, detection-rules, rules | `nms.traffic.detections.view` |
| POST | detections/{id}/suppress | `nms.traffic.rules.manage` |
| PUT | detection-rules/{key} | `nms.traffic.rules.manage` |
| POST / PUT / DELETE | rules, signatures, vlan-policies | `nms.traffic.rules.manage` |
| POST / PUT / DELETE | networks | `nms.traffic.collector.manage` |
| PUT | settings | `nms.traffic.collector.manage`; the enrichment keys need `nms.traffic.enrichment.manage` |
| GET | export/{view}.csv | `nms.traffic.export`: at most 10 000 rows, 10 exports a minute per user, audited |

**How the API handles requests:**

- **Responses** say which source answered (`raw records` / `hourly rollups`).
- **Caching:** 20 s in-process for identical requests; enrichment results are cached for 60 s.
- **Audit log:** every change and every export.
- **Site scope:** accounts with a site list see only the exporters of their sites. DNS / domain intelligence is not
  site-scoped, so it is refused for scoped accounts.

## 8. Permissions (NMS roles)

| Permission | Granted to |
|---|---|
| `nms.traffic.view`, `nms.traffic.detections.view` | every account with the NMS product (as Flow Analytics and alerts were) |
| `nms.traffic.sensitive.view` (MACs, domains / DNS, reverse-DNS names, wireless user names), `nms.traffic.export` | network engineer, auditor, NMS / site / super administrator |
| `nms.traffic.rules.manage` | network engineer, NMS / site / super administrator |
| `nms.traffic.enrichment.manage`, `nms.traffic.collector.manage` | NMS / site / super administrator |

## 9. Data model changes

- **ClickHouse migration 22:**
  - `flows` gains `src_mac`, `dst_mac`, `tcp_flags`, `dst_vlan` and `l7` (defaults, no rewrite).
  - New `flows_conv_hourly` (AggregatingMergeTree, 35-day TTL). It keeps first / last seen, the largest sampling rate
    and SYN-only counts, and is fed by a materialized view.
  - The migration backfills the last 35 days from `flows`, up to the moment the view was created, so nothing is
    counted twice.
- **PostgreSQL migration 0038** (additive, six tables): `traffic_signatures`, `traffic_networks`,
  `traffic_vlan_policies`, `traffic_rules`, `traffic_settings`, `traffic_ip_info`.
- **Seeding** (`bootstrap.seed`, NMS): built-in signatures and zone policies, once.
- **Retention:**

  | Data | Kept |
  |---|---|
  | raw flows | 30 days |
  | conversations | 35 days |
  | interface rollup | 400 days |
  | talker pairs | 90 days |
  | enrichment rows | 30 days unused |

## 10. Performance

- Windows up to 6 h read raw records (minute detail); longer windows read the hourly rollups. Interface views read the
  interface rollup.
- Queries are bounded: window ≤ 30 days, `LIMIT` ≤ 500, `OFFSET` ≤ 100 000.
- Classification lookups are bound arrays, not joins.
- Host enrichment is batched per page; there is no per-row query.
- External enrichment never runs during a request: the background loop is capped and reverse DNS is rate-limited.
- The UI pages server-side and never loads full result sets.

**Not measured yet:** response times at production volume. The deployment has no flows yet (see section 12). Measure
them after the first day of real exports.

## 11. Configuration to enable the feature

1. **Expose the collector.** Set `FLOW_BIND_IP=<server address>` in `.env` (production: done, `10.200.64.58`).
2. **Allow the ports** in the host firewall: UDP 6343 (sFlow), 2055 (NetFlow) and 4739 (IPFIX). The server runs
   firewalld (`public` zone), for example `firewall-cmd --zone=public --add-port=6343/udp --permanent && firewall-cmd --reload`.
3. **Point the devices' exports** at the server, using their **management address as the source**. The collector
   accepts only inventory devices. Other senders are listed under Collectors → unknown senders.
4. **Networks & Settings → Network ranges:** add your subnets with site, VLAN and zone.
5. **Networks & Settings → Traffic settings:** authorised SNMP managers (include the NMS server), approved DNS
   resolvers and MQTT brokers.
6. **Optional:** DNS logs (Zeek / FortiGate DNS / resolver syslog) and FortiGate application control raise
   application confidence.

## 12. Limitations and unsupported telemetry

- **DHCP / IPAM:** hostnames come from the inventory, wireless clients and optional reverse DNS. DHCP leases are not
  collected.
- **MAC vendor (OUI):** not resolved; no OUI database ships with the product.
- **HTTP/2 vs HTTP/1.1:** cannot be determined from flows. TLS SNI is usually beyond the sampled 128 bytes and is not
  parsed.
- **SMBv1:** cannot be determined (the dialect is not visible).
- **Reputation feeds:** not integrated in NMS (the SIEM's threat intelligence stays in the SIEM). New / rare external
  destinations are detected instead.
- **Inline DPI:** no DPI engine; only firewall application control is used.
- **Flow collector:** sFlow counter samples, NetFlow v9 / IPFIX options records and NSEL are not used.
- **Scans under sampling:** heavy sampling hides small scans. Thresholds apply to observed counts.
- **DNS / firewall correlation** reads the shared event store. After the database separation (phase 6) it needs the
  optional SIEM ↔ NMS integration.

## 13. Tests

- `backend/tests/test_traffic.py` (20 tests):
  - decoder evidence (QUIC header, MACs, flags);
  - registry and ambiguity;
  - direction (IPv6, carve-outs);
  - deduplication across exporters;
  - rollup path;
  - LAG counting;
  - enrichment evidence levels and the DNS-log loop;
  - DNS unavailable;
  - every detection rule, with its guards;
  - engine deduplication;
  - API authentication, RBAC, validation, configuration round trip, detection workflow, every view and export.
- `backend/tests/test_flows.py`: decoders and collector.
- `frontend/src/pages/nms/traffic/model.test.ts`: URL filters, drill-down, series pivot, rule parameters.
- Flow rows in tests are fixtures inside the test database only.
