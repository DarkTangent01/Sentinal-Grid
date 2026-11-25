# Identity, device intelligence, behaviour baselines and threat intel on flows

Four capabilities that tie Sentinel NMS and Sentinel Grid together, without coupling their code:
1. a shared identity index;
2. device intelligence;
3. behaviour baselines;
4. threat intelligence on flow telemetry.

## 1. Identity index (shared)

Code: `backend/app/platform/identity.py`, with tables `host_identities`, `ip_mac_bindings` and `ip_user_bindings`
(migration 0039).

Each product registers **contributors**, the same pattern as the alert engine. The worker loop `identity_index`
(every 5 minutes) runs those of the products the process loads, and merges what they return.

| Product | Contributor | Evidence |
|---|---|---|
| NMS | `nms.wireless` | controller client tables: IP ↔ MAC, SSID, AP, VLAN, user name |
| NMS | `nms.switch_mac` | switch MAC tables: the access port and VLAN of a MAC (uplinks, LAGs and ports with more than 20 MACs are skipped) |
| NMS | `nms.sflow` | sampled frames: the internal endpoint's MAC |
| NMS | `nms.tacacs` | TACACS+ logins: administrator workstation ↔ user |
| Grid | `grid.fortigate` | FortiGate device detection in traffic logs: `srcmac`, `srchwvendor`, `devtype`, `osname`, `srcname` |
| Grid | `grid.vpn` | VPN logins: tunnel address ↔ user, and the remote address |
| Grid | `grid.windows` | successful Windows logons: workstation ↔ account |
| Grid | `grid.dhcp` | FortiGate DHCP Ack logs and Zeek `dhcp.log`: IP ↔ MAC ↔ host name |

**Evidence rules:**
- **Router MACs:** a MAC seen behind more than 3 addresses in one pass is a router, gateway or AP. It's recorded as
  network equipment and **never bound to an address as a host**.
  - On production, most FortiGate `srcmac` values are such next hops (Cisco or Ruckus "Router").
  - The gateway MAC in the switch's uplink sFlow is the same case.
- **Private MACs:** locally administered (randomised) MACs are marked as private, with no manufacturer.
- **Retention:** bindings are kept 30 days. Each pass reads at most 30 minutes of evidence; the raw-log scan reads at
  most 10.

**Read API** (both products): `/api/identities/ip/{ip}` (current identity plus the 7-day timeline of MACs and
users), `POST /api/identities/lookup`, and `/api/identities/devices`.
- MAC, user name and host name are personal data. They're returned to administrators, to Sentinel Grid users, and to
  NMS roles with traffic-sensitive access (engineer, auditor, NMS or site administrator).

**UI:**
- Sentinel Grid → Investigate (IP): a **Network context** card.
- Sentinel NMS → host drawer: an **Identity** card.
- Traffic tables show device type and manufacturer.

## 2. Device intelligence

**Manufacturer.**
- **Source:** a bundled copy of the IEEE MA-L, MA-M and MA-S registries (`backend/app/platform/data/manuf.gz`,
  Wireshark's generated list, downloaded 2026-11-25).
- **Runtime:** nothing is fetched while running.
- **Refresh:** download the same file again, at most weekly.

**Device type** (`classify`): every type keeps its evidence.

| Confidence | Evidence |
|---|---|
| confirmed | monitored inventory, or a MAC routing for several addresses (network equipment) |
| high | FortiGate device fingerprint (`devtype` and OS) |
| probable | manufacturer (cameras, printers, IP phones, IoT, phones and tablets, computers, network equipment, virtual machines, TVs, scanners), behaviour (serves RTSP 554, printing 9100 / 631 / 515, SIP 5060, MQTT 1883), or a randomised MAC on Wi-Fi |

**UI:** Sentinel NMS → Application & Protocol Intelligence → **Device Intelligence**: device counts by type, a
searchable inventory, and the connection point (switch port or AP / SSID).

## 3. Behaviour baselines (NMS)

Code: `backend/app/traffic/baselines.py`, with the rule `traffic_behaviour_anomaly`.

**What it measures.** For each internal host (the client side of its conversations) and each VLAN, it takes the last
full hour's upload, download and number of distinct peers. Each is compared with the same hour of the day over the
previous 14 days, using the median and the median absolute deviation (MAD). A day with no traffic counts as zero.

**When it fires.** All three conditions must hold:
- value ≥ median + k × max(MAD, 10 % of median, floor), with k = 6;
- value ≥ 5 × usual;
- value ≥ a minimum: 200 MB upload, 1 GB download or 100 peers.

**Details:**
- No verdicts until the hourly rollup holds **5 days** of history.
- 20 × the usual upload is high severity.
- Thresholds are editable under Traffic → Rules & Signatures.

**UI:** the host drawer's **Upload vs normal** chart (actual, usual, expected maximum), from
`/api/nms/traffic/baseline/{ip}`.

**Limit:** an internal server is profiled only as a client; its server-side traffic is not baselined yet.

## 4. Threat intelligence on flows (Grid)

Code: `backend/app/enrich/ti_flows.py`, with the SIEM rule `ti_flow_match`.

- **What it does:** matches the external endpoint of every flow record (last 15 minutes) against the SIEM's enabled,
  unexpired indicators (IPs and CIDRs), using the same indicator set as the firewall-log `ti_match`.
- **What it catches:** contact that never reaches a logging firewall, such as switched, east-west and branch traffic.
- **Each alert carries:** the indicator, feed, category, direction, bytes, ports, sampling rate and exporters.
- **Coupling:** data only. The rule reads the ClickHouse `flows` table by name and imports no NMS code.
- **Limit:** sampled telemetry can miss short contacts.

## 5. From a network detection to a security incident

`POST /api/incidents/from-alert/{alert_id}` (Sentinel Grid) opens a security incident from any alert, or returns the
one already linked.
- **UI:** NMS traffic detections show **Open security incident** for accounts that also use Sentinel Grid.
- **Products apart:** in a Sentinel NMS-only deployment the button is not shown.

## Product boundary

- `platform/identity.py` imports neither product.
- Contributors live in their product (`traffic/identity_sources.py`, `enrich/identity_sources.py`) and are loaded by
  `composition.load()`.
- `tests/test_product_boundaries.py` enforces this.
- After the database separation (migration plan phase 6), each product keeps its own index from its own evidence. A
  cross-product view then needs the optional integration API.

## Tests

`backend/tests/test_identity_index.py` covers:
- vendor lookup and the MAC rules;
- classification order;
- every contributor end to end, including router-MAC rejection and idempotent passes;
- the read API and personal-data withholding;
- baselines (detection, a steady-but-large host not flagged, the learning period);
- threat intel on flows (IP and CIDR, inbound and outbound);
- alert → incident escalation, at most once.
