# Sentinel NMS implementation roadmap

## Done in this release (phase A: device access)

| Step | Delivered | Acceptance (met) |
|---|---|---|
| A1 | NMS roles and permissions | 7 roles, 13 permissions. Existing users unchanged. A role change revokes sessions. |
| A2 | Credential vault | Encrypted kinds, group assignment, rotation date. Secrets never returned. |
| A3 | Access gateway | Device-id-only targets, allowlist, fixed ports, caps, single dial path. SSRF tests. |
| A4 | Command library and risk | 71 templates on 11 platforms. Classifier with 36 cases. Templates ≤ `LOW_RISK` enforced. |
| A5 | Browser terminal | xterm.js, ticket WebSocket, guard, timeouts, termination, recording. E2E test and browser check. |
| A6 | Diagnostics and bulk | Bounded, cancellable, partial failure, export. 2,000-device simulation. |
| A7 | Change workflow | Four eyes, off switch, window, backups before / after, verify, Junos commit confirmed, rollback |
| A8 | Access audit | Hash chain, verification, CSV, concurrency-safe |
| A9 | UI | Device Access page (7 tabs), device Access tab, navigation group |
| A10 | Deployment | `access` service, nginx WebSocket route, k8s upstream, migration 0035 (up / down / up tested) |

## Next (ordered by value / risk)

| # | Item | Why | Size | Acceptance |
|---|---|---|---|---|
| R1 | **Lab validation** of the access platforms on real Cisco IOS-XE, Junos, FortiOS and ICX | Every access path is `NEEDS_VALIDATION` | S per platform | Templates run; change procedure and rollback verified on a lab device; results recorded in VENDOR_SUPPORT_MATRIX |
| R2 ✓ done ([NMS_EXTENSIONS.md](NMS_EXTENSIONS.md)) | ICMP / TCP liveness sweep and ARP-table discovery | Devices without SNMP are invisible | M | Sweep inside authorised networks only, rate-limited, candidates not auto-onboarded |
| R3 | Separate `access` Deployment on Kubernetes | Isolation equal to Compose | S | Manifest, NetworkPolicy (egress to management networks only), upstream switched |
| R4 ✓ done | L3 / WAN topology layer | Routing and site-to-site views | L | Edges from BGP / OSPF peers and VPN tunnels, marked as their source |
| R5 ✓ done | Read-only NETCONF / RESTCONF adapter (Junos, IOS-XE) | Structured data instead of CLI text | M | Fixed RPCs only, same gateway and allowlist |
| R6 | Full-configuration restore (IOS `configure replace`, Junos `load override`) | Rollback beyond line-based | M | Approved, from a stored snapshot, verified diff = 0 afterwards |
| R7 ✓ done (with Mist and Aruba Central) | Ruckus SmartZone / One REST client | Ruckus wireless parity | L | AP / radio / client inventory and history like the 9800 |
| R8 | Vendor adapters for Arista / Aruba CX / Huawei (identification + health OIDs) | Beyond generic MIBs | M each | Identified as the vendor; health metrics with fixtures |
| R9 | Per-user device credentials (optional) | Device-side attribution | M | Users can store their own device login; the vault account stays the default |
| R10 | Gateway horizontal scale (multiple processes) | More than about 50 devices/s for bulk jobs | M | Session routing by ticket; job distribution through the database |

## Explicitly not planned

- Telnet on by default (it is now opt-in, off by default, and marked clear text).
- Automatic changes from alerts.
- Scheduled configuration changes.
- Unrestricted SSH proxying.
- AI-generated commands executed on devices.
