# Wireless Analysis (Sentinel NMS): Cisco Catalyst 9800 over SNMP

Read-only monitoring of Cisco wireless LAN controllers and of the APs, radios, WLANs and clients they report. It is
**Sentinel NMS → Wireless Analysis** (`/wireless`): Overview, WLC Inventory, Access Points, Radio & RF, Clients,
WLAN / SSID, Roaming, Events, Wireless Alerts, Troubleshooting and Monitoring Health.

Nothing changes a controller. There is no RF optimisation, and channels, power, WLANs and client sessions are never
touched. Only SNMP GET / GETNEXT / GETBULK requests are sent.

## Architecture

The module reuses the switch-monitoring SNMP stack rather than adding a second one:

```
Catalyst 9800 ──SNMPv3 (authPriv)──▶ existing switch poller (leases, bounded concurrency, damping, capability registry)
                                      ├─ system / CPU / memory / interfaces (existing groups)
                                      └─ wireless groups (role "wlc" only, Cisco only)
                                           ├─ wireless_ap           60 s   APs and their state
                                           ├─ wireless_radio        60 s   radios, channel, utilisation, retries
                                           ├─ wireless_radio_rf    300 s   noise + 802.11 interference (current channel row)
                                           ├─ wireless_client      120 s   clients (bounded: 20 000 rows per poll)
                                           ├─ wireless_wlan        600 s   WLANs + per-radio SSIDs / BSSIDs
                                           └─ wireless_ap_cdp      900 s   AP uplink neighbour (switch + port)
      ▼ app/wireless/store.py: inventory (PostgreSQL), state machines, events; history → ClickHouse
      ▼ app/wireless/service.py: overview, RF ranking, client score, roaming, switch correlation, troubleshooting
      ▼ app/wireless/alerts.py: 13 rules in the existing alert engine
```

- **Controllers:** a controller is a monitored device: a `switches` row with **role `wlc`**. Credentials, authorised
  networks, polling intervals (`group_intervals`), the connectivity test and audit are shared with switch monitoring.
  There is no second device inventory.
- **Per-group intervals:** set per controller with `group_intervals`, e.g. `{"wireless_client": 300}`. 0 disables a
  group.
- **Storage:**
  - PostgreSQL (migration `0021_wireless`): `wireless_aps`, `wireless_radios`, `wireless_wlans`, `wireless_clients`
    and `wireless_events`.
  - ClickHouse migration 12:
    - `wireless_metrics`: numeric history per WLC / AP / radio / WLAN, kept 90 days.
    - `wireless_client_samples`: per-client RSSI, SNR, rate and bytes, kept 14 days, stored as rows (never as metric
      labels).

## MIB sources and the OID registry

`app/wireless/oids.py` is **generated** from Cisco's published MIB files (`github.com/cisco/cisco-mibs`, `v2/`) by
resolving each OBJECT-TYPE to its numeric OID. See `backend/tools/wireless_mibs/` to regenerate it.

- The generator refuses objects that cannot be read.
- MIBs used: AIRESPACE-WIRELESS-MIB, CISCO-LWAPP-AP-MIB, CISCO-LWAPP-WLAN-MIB, CISCO-LWAPP-DOT11-CLIENT-MIB and
  CISCO-LWAPP-CDP-MIB.
- The controller's CPU, memory and interfaces come from the existing switch groups (CISCO-PROCESS-MIB,
  CISCO-MEMORY-POOL-MIB, IF-MIB).

**Support is decided per controller, at run time.** Cisco states that many AireOS-era MIB objects are not
implemented, or only partly implemented, on the Catalyst 9800, depending on the release. Users report
`bsnMobileStationTable` not listing every client on some releases.

So every metric's status comes from what the controller actually returned (Wireless → Monitoring Health, or the
**Test** button when adding a controller):

| Status | Meaning |
|---|---|
| healthy | collected on the last poll |
| unsupported | never returned |
| unavailable | returned before, missing now |
| failed | the request errored |
| stale | not collected within 3 intervals |

An unsupported metric is shown as "—" and is never stored as 0.

Where the AIRESPACE and CISCO-LWAPP MIBs both describe the same thing, both are read and each value keeps its source
MIB. For example, AP CPU comes from `cLApCpuCurrentUsage` only.

**Nothing here has been validated against a live 9800 yet.** Use the Test button on your controller to see which
objects your release returns.

### Registry

| Object | OID | MIB | Group | Metric | Unit | Note |
|---|---|---|---|---|---|---|
| `bsnAPName` | `1.3.6.1.4.1.14179.2.2.1.1.3` | AIRESPACE-WIRELESS-MIB | ap |  |  |  |
| `bsnAPLocation` | `1.3.6.1.4.1.14179.2.2.1.1.4` | AIRESPACE-WIRELESS-MIB | ap |  |  |  |
| `bsnAPOperationStatus` | `1.3.6.1.4.1.14179.2.2.1.1.6` | AIRESPACE-WIRELESS-MIB | ap | `wireless_ap_up` |  | associated = joined to this controller |
| `bsnAPSoftwareVersion` | `1.3.6.1.4.1.14179.2.2.1.1.8` | AIRESPACE-WIRELESS-MIB | ap |  |  |  |
| `bsnAPModel` | `1.3.6.1.4.1.14179.2.2.1.1.16` | AIRESPACE-WIRELESS-MIB | ap |  |  |  |
| `bsnAPSerialNumber` | `1.3.6.1.4.1.14179.2.2.1.1.17` | AIRESPACE-WIRELESS-MIB | ap |  |  |  |
| `bsnApIpAddress` | `1.3.6.1.4.1.14179.2.2.1.1.19` | AIRESPACE-WIRELESS-MIB | ap |  |  |  |
| `bsnAPNumOfSlots` | `1.3.6.1.4.1.14179.2.2.1.1.2` | AIRESPACE-WIRELESS-MIB | ap |  |  |  |
| `bsnAPPrimaryMwarName` | `1.3.6.1.4.1.14179.2.2.1.1.10` | AIRESPACE-WIRELESS-MIB | ap |  |  |  |
| `bsnAPAdminStatus` | `1.3.6.1.4.1.14179.2.2.1.1.37` | AIRESPACE-WIRELESS-MIB | ap |  |  |  |
| `bsnAPGroupVlanName` | `1.3.6.1.4.1.14179.2.2.1.1.30` | AIRESPACE-WIRELESS-MIB | ap |  |  |  |
| `cLApName` | `1.3.6.1.4.1.9.9.513.1.1.1.1.5` | CISCO-LWAPP-AP-MIB | ap |  |  |  |
| `cLApUpTime` | `1.3.6.1.4.1.9.9.513.1.1.1.1.6` | CISCO-LWAPP-AP-MIB | ap | `wireless_ap_uptime_seconds` | s | AP uptime (TimeTicks) |
| `cLLwappUpTime` | `1.3.6.1.4.1.9.9.513.1.1.1.1.7` | CISCO-LWAPP-AP-MIB | ap | `wireless_ap_join_uptime_seconds` | s | time since the AP joined the controller |
| `cLApLastRebootReason` | `1.3.6.1.4.1.9.9.513.1.1.1.1.16` | CISCO-LWAPP-AP-MIB | ap |  |  |  |
| `cLApAssociatedClientCount` | `1.3.6.1.4.1.9.9.513.1.1.1.1.54` | CISCO-LWAPP-AP-MIB | ap | `wireless_ap_client_count` | clients |  |
| `cLApCpuCurrentUsage` | `1.3.6.1.4.1.9.9.513.1.1.1.1.57` | CISCO-LWAPP-AP-MIB | ap | `wireless_ap_cpu_percent` | % |  |
| `cLApMemoryCurrentUsage` | `1.3.6.1.4.1.9.9.513.1.1.1.1.55` | CISCO-LWAPP-AP-MIB | ap | `wireless_ap_memory_percent` | % |  |
| `cLApAssocFailTimes` | `1.3.6.1.4.1.9.9.513.1.1.1.1.75` | CISCO-LWAPP-AP-MIB | ap | `wireless_ap_assoc_failures` | count | Counter32 |
| `cLApReassocFailCount` | `1.3.6.1.4.1.9.9.513.1.1.1.1.68` | CISCO-LWAPP-AP-MIB | ap | `wireless_ap_reassoc_failures` | count | Counter32 |
| `cLApSiteTagName` | `1.3.6.1.4.1.9.9.513.1.1.1.1.104` | CISCO-LWAPP-AP-MIB | ap |  |  |  |
| `cLApRfTagName` | `1.3.6.1.4.1.9.9.513.1.1.1.1.105` | CISCO-LWAPP-AP-MIB | ap |  |  |  |
| `cLApPolicyTagName` | `1.3.6.1.4.1.9.9.513.1.1.1.1.106` | CISCO-LWAPP-AP-MIB | ap |  |  |  |
| `cLApPowerStatus` | `1.3.6.1.4.1.9.9.513.1.1.1.1.20` | CISCO-LWAPP-AP-MIB | ap |  |  |  |
| `clcCdpApCacheNeighName` | `1.3.6.1.4.1.9.9.623.1.3.1.1.6` | CISCO-LWAPP-CDP-MIB | ap_cdp | `wireless_ap_uplink_neighbor` |  | switch the AP is cabled to (CDP) |
| `clcCdpApCacheNeighAddress` | `1.3.6.1.4.1.9.9.623.1.3.1.1.8` | CISCO-LWAPP-CDP-MIB | ap_cdp |  |  |  |
| `clcCdpApCacheNeighInterface` | `1.3.6.1.4.1.9.9.623.1.3.1.1.9` | CISCO-LWAPP-CDP-MIB | ap_cdp |  |  |  |
| `clcCdpApCachePlatform` | `1.3.6.1.4.1.9.9.623.1.3.1.1.12` | CISCO-LWAPP-CDP-MIB | ap_cdp |  |  |  |
| `bsnAPIfType` | `1.3.6.1.4.1.14179.2.2.2.1.2` | AIRESPACE-WIRELESS-MIB | radio |  |  |  |
| `bsnAPIfPhyChannelNumber` | `1.3.6.1.4.1.14179.2.2.2.1.4` | AIRESPACE-WIRELESS-MIB | radio | `wireless_radio_channel` |  |  |
| `bsnAPIfPhyTxPowerLevel` | `1.3.6.1.4.1.14179.2.2.2.1.6` | AIRESPACE-WIRELESS-MIB | radio | `wireless_radio_tx_power_level` | level 1-8 | power level (1 = highest), not dBm |
| `bsnAPIfOperStatus` | `1.3.6.1.4.1.14179.2.2.2.1.12` | AIRESPACE-WIRELESS-MIB | radio | `wireless_radio_up` |  |  |
| `bsnAPIfAdminStatus` | `1.3.6.1.4.1.14179.2.2.2.1.34` | AIRESPACE-WIRELESS-MIB | radio |  |  |  |
| `bsnApIfNoOfUsers` | `1.3.6.1.4.1.14179.2.2.2.1.15` | AIRESPACE-WIRELESS-MIB | radio | `wireless_radio_client_count` | clients |  |
| `cLAp11ChannelBandwidth` | `1.3.6.1.4.1.9.9.513.1.2.1.1.23` | CISCO-LWAPP-AP-MIB | radio | `wireless_radio_channel_width_mhz` | MHz | CISCO-LWAPP-AP-MIB cLApDot11IfTable |
| `bsnAPIfLoadChannelUtilization` | `1.3.6.1.4.1.14179.2.2.13.1.3` | AIRESPACE-WIRELESS-MIB | radio | `wireless_radio_channel_utilization_percent` | % | AP-measured channel busy percentage |
| `bsnAPIfLoadTxUtilization` | `1.3.6.1.4.1.14179.2.2.13.1.2` | AIRESPACE-WIRELESS-MIB | radio | `wireless_radio_tx_utilization_percent` | % |  |
| `bsnAPIfLoadRxUtilization` | `1.3.6.1.4.1.14179.2.2.13.1.1` | AIRESPACE-WIRELESS-MIB | radio | `wireless_radio_rx_utilization_percent` | % |  |
| `bsnAPIfPoorSNRClients` | `1.3.6.1.4.1.14179.2.2.13.1.24` | AIRESPACE-WIRELESS-MIB | radio | `wireless_radio_poor_snr_clients` | clients |  |
| `bsnAPIfDBNoisePower` | `1.3.6.1.4.1.14179.2.2.15.1.21` | AIRESPACE-WIRELESS-MIB | radio_rf | `wireless_radio_noise_dbm` | dBm | average noise power on the radio's current channel |
| `bsnAPIfInterferenceUtilization` | `1.3.6.1.4.1.14179.2.2.14.1.22` | AIRESPACE-WIRELESS-MIB | radio_rf | `wireless_radio_interference_percent` | % | interference from other 802.11 networks on the current channel |
| `bsnAPIfInterferencePower` | `1.3.6.1.4.1.14179.2.2.14.1.2` | AIRESPACE-WIRELESS-MIB | radio_rf | `wireless_radio_interference_dbm` | dBm | power of other 802.11 networks on the current channel |
| `bsnAPIfDot11TransmittedFrameCount` | `1.3.6.1.4.1.14179.2.2.6.1.12` | AIRESPACE-WIRELESS-MIB | radio | `wireless_radio_tx_frames` | frames/s | rate from Counter32 |
| `bsnAPIfDot11RetryCount` | `1.3.6.1.4.1.14179.2.2.6.1.3` | AIRESPACE-WIRELESS-MIB | radio | `wireless_radio_retries` | frames/s |  |
| `bsnAPIfDot11FailedCount` | `1.3.6.1.4.1.14179.2.2.6.1.33` | AIRESPACE-WIRELESS-MIB | radio | `wireless_radio_tx_failed` | frames/s |  |
| `bsnAPIfDot11FCSErrorCount` | `1.3.6.1.4.1.14179.2.2.6.1.11` | AIRESPACE-WIRELESS-MIB | radio | `wireless_radio_fcs_errors` | frames/s |  |
| `bsnAPIfDot11ACKFailureCount` | `1.3.6.1.4.1.14179.2.2.6.1.8` | AIRESPACE-WIRELESS-MIB | radio | `wireless_radio_ack_failures` | frames/s |  |
| `cLWlanProfileName` | `1.3.6.1.4.1.9.9.512.1.1.1.1.3` | CISCO-LWAPP-WLAN-MIB | wlan |  |  |  |
| `cLWlanSsid` | `1.3.6.1.4.1.9.9.512.1.1.1.1.4` | CISCO-LWAPP-WLAN-MIB | wlan | `wireless_wlan_up` |  | SSID / profile defined |
| `cLWlanRowStatus` | `1.3.6.1.4.1.9.9.512.1.1.1.1.2` | CISCO-LWAPP-WLAN-MIB | wlan |  |  |  |
| `cLWlanMaxClientsAccepted` | `1.3.6.1.4.1.9.9.512.1.1.1.1.22` | CISCO-LWAPP-WLAN-MIB | wlan |  |  |  |
| `bsnDot11EssSsid` | `1.3.6.1.4.1.14179.2.1.1.1.2` | AIRESPACE-WIRELESS-MIB | wlan |  |  |  |
| `bsnDot11EssAdminStatus` | `1.3.6.1.4.1.14179.2.1.1.1.6` | AIRESPACE-WIRELESS-MIB | wlan |  |  |  |
| `bsnDot11EssSecurityAuthType` | `1.3.6.1.4.1.14179.2.1.1.1.7` | AIRESPACE-WIRELESS-MIB | wlan |  |  |  |
| `bsnDot11EssNumberOfMobileStations` | `1.3.6.1.4.1.14179.2.1.1.1.38` | AIRESPACE-WIRELESS-MIB | wlan | `wireless_wlan_client_count` | clients |  |
| `cLApRadioWlanSsid` | `1.3.6.1.4.1.9.9.513.1.10.2.1.1` | CISCO-LWAPP-AP-MIB | wlan | `wireless_wlan_radio_count` | radios | WLANs broadcast per AP radio |
| `cLApRadioWlanBssid` | `1.3.6.1.4.1.9.9.513.1.10.2.1.2` | CISCO-LWAPP-AP-MIB | wlan |  |  |  |
| `cldcClientStatus` | `1.3.6.1.4.1.9.9.599.1.3.1.1.2` | CISCO-LWAPP-DOT11-CLIENT-MIB | client | `wireless_client_count` | clients |  |
| `cldcClientWlanProfileName` | `1.3.6.1.4.1.9.9.599.1.3.1.1.3` | CISCO-LWAPP-DOT11-CLIENT-MIB | client |  |  |  |
| `cldcApMacAddress` | `1.3.6.1.4.1.9.9.599.1.3.1.1.8` | CISCO-LWAPP-DOT11-CLIENT-MIB | client |  |  |  |
| `cldcIfType` | `1.3.6.1.4.1.9.9.599.1.3.1.1.9` | CISCO-LWAPP-DOT11-CLIENT-MIB | client |  |  |  |
| `cldcClientIPAddress` | `1.3.6.1.4.1.9.9.599.1.3.1.1.10` | CISCO-LWAPP-DOT11-CLIENT-MIB | client |  |  |  |
| `cldcClientAccessVLAN` | `1.3.6.1.4.1.9.9.599.1.3.1.1.13` | CISCO-LWAPP-DOT11-CLIENT-MIB | client |  |  |  |
| `cldcClientUpTime` | `1.3.6.1.4.1.9.9.599.1.3.1.1.15` | CISCO-LWAPP-DOT11-CLIENT-MIB | client | `wireless_client_session_seconds` | s | MIB: SYNTAX TimeInterval but UNITS Seconds; read as seconds per the UNITS clause |
| `cldcClientUsername` | `1.3.6.1.4.1.9.9.599.1.3.1.1.27` | CISCO-LWAPP-DOT11-CLIENT-MIB | client |  |  | RBAC: admins only |
| `cldcClientSSID` | `1.3.6.1.4.1.9.9.599.1.3.1.1.28` | CISCO-LWAPP-DOT11-CLIENT-MIB | client |  |  |  |
| `cldcClientChannel` | `1.3.6.1.4.1.9.9.599.1.3.1.1.35` | CISCO-LWAPP-DOT11-CLIENT-MIB | client |  |  |  |
| `cldcClientAuthMode` | `1.3.6.1.4.1.9.9.599.1.3.1.1.36` | CISCO-LWAPP-DOT11-CLIENT-MIB | client |  |  |  |
| `cldcClientReasonCode` | `1.3.6.1.4.1.9.9.599.1.3.1.1.37` | CISCO-LWAPP-DOT11-CLIENT-MIB | client |  |  |  |
| `cldcClientApRoamMacAddress` | `1.3.6.1.4.1.9.9.599.1.3.1.1.39` | CISCO-LWAPP-DOT11-CLIENT-MIB | client |  |  | previous AP when the client roamed |
| `cldcClientCurrentTxRate` | `1.3.6.1.4.1.9.9.599.1.3.1.1.50` | CISCO-LWAPP-DOT11-CLIENT-MIB | client | `wireless_client_tx_rate_mbps` | Mbit/s |  |
| `bsnMobileStationIpAddress` | `1.3.6.1.4.1.14179.2.1.4.1.2` | AIRESPACE-WIRELESS-MIB | client |  |  |  |
| `bsnMobileStationAPMacAddr` | `1.3.6.1.4.1.14179.2.1.4.1.4` | AIRESPACE-WIRELESS-MIB | client |  |  |  |
| `bsnMobileStationAPIfSlotId` | `1.3.6.1.4.1.14179.2.1.4.1.5` | AIRESPACE-WIRELESS-MIB | client |  |  |  |
| `bsnMobileStationSsid` | `1.3.6.1.4.1.14179.2.1.4.1.7` | AIRESPACE-WIRELESS-MIB | client |  |  |  |
| `bsnMobileStationStatus` | `1.3.6.1.4.1.14179.2.1.4.1.9` | AIRESPACE-WIRELESS-MIB | client |  |  |  |
| `bsnMobileStationReasonCode` | `1.3.6.1.4.1.14179.2.1.4.1.10` | AIRESPACE-WIRELESS-MIB | client |  |  |  |
| `bsnMobileStationProtocol` | `1.3.6.1.4.1.14179.2.1.4.1.25` | AIRESPACE-WIRELESS-MIB | client |  |  |  |
| `bsnMobileStationVlanId` | `1.3.6.1.4.1.14179.2.1.4.1.29` | AIRESPACE-WIRELESS-MIB | client |  |  |  |
| `bsnMobileStationUserName` | `1.3.6.1.4.1.14179.2.1.4.1.3` | AIRESPACE-WIRELESS-MIB | client |  |  | RBAC: admins only |
| `bsnMobileStationRSSI` | `1.3.6.1.4.1.14179.2.1.6.1.1` | AIRESPACE-WIRELESS-MIB | client | `wireless_client_rssi_dbm` | dBm | client-side average packet RSSI reported by the controller |
| `bsnMobileStationSnr` | `1.3.6.1.4.1.14179.2.1.6.1.26` | AIRESPACE-WIRELESS-MIB | client | `wireless_client_snr_db` | dB |  |
| `bsnMobileStationBytesReceived` | `1.3.6.1.4.1.14179.2.1.6.1.2` | AIRESPACE-WIRELESS-MIB | client | `wireless_client_rx_bytes` | bytes | Counter64 |
| `bsnMobileStationBytesSent` | `1.3.6.1.4.1.14179.2.1.6.1.3` | AIRESPACE-WIRELESS-MIB | client | `wireless_client_tx_bytes` | bytes | Counter64 |
| `bsnMobileStationPacketsReceived` | `1.3.6.1.4.1.14179.2.1.6.1.5` | AIRESPACE-WIRELESS-MIB | client |  | packets | Counter64 |
| `bsnMobileStationPacketsSent` | `1.3.6.1.4.1.14179.2.1.6.1.6` | AIRESPACE-WIRELESS-MIB | client |  | packets | Counter64 |

**Units and semantics, as the MIBs define them:**

- **Transmit power:** `bsnAPIfPhyTxPowerLevel` is a power **level** from 1 (highest) to 8, not dBm. It is shown as a
  level.
- **Interference:** `bsnAPIfInterferenceUtilization` / `Power` measure interference **from other 802.11 networks** on
  the channel (co-channel Wi-Fi). They are not non-Wi-Fi interference.
- **Noise:** `bsnAPIfDBNoisePower` is the average noise on a channel. The noise and interference tables are per
  channel; the row for the radio's **current** channel is used.
- **Channel utilisation:** `bsnAPIfLoadChannelUtilization` is the AP's own measure of how busy the channel is. It is
  not compared with any other vendor's counter.
- **Client signal:** RSSI and SNR (`bsnMobileStationStatsTable`) are **client-side** measurements reported by the
  controller. They are kept separate from the AP-side radio statistics. RSSI 0 means "not measured" and is stored as
  missing.
- **Session duration:** `cldcClientUpTime` has SYNTAX TimeInterval (hundredths of a second) but UNITS "Seconds". It is
  read as seconds, per the UNITS clause.
- **Traffic:** client byte counters (Counter64) are totals since association. They are not RF airtime or wired
  bandwidth.

### Known gaps: not available through these MIBs

| Wanted | Why it is missing |
|---|---|
| Actual transmit power in dBm | only the power level is exposed |
| Antenna details | not collected |
| Non-802.11 interferer identification | needs spectrum analysis (CleanAir) data, which SNMP does not provide |
| 802.1X, EAP, RADIUS and DHCP failure details | SNMP gives counts and client status only (`aaaPending`, `excluded`). Ingest the controller's syslog into the SIEM for the reasons. |
| Measured roaming duration | roams are **inferred** from a client's AP changing between polls. Times are poll times; no roam duration is reported. |
| Per-AP traffic | only per-client byte counters, summed by AP or WLAN |
| Optional RESTCONF / NETCONF / telemetry adapter | not implemented. SNMP is the only source, and every value records its MIB. |

## State and correlation rules

**AP state:**

| State | When |
|---|---|
| up | listed by the controller and associated |
| degraded | listed but downloading an image, disassociating, a radio that is administratively up is down, or CPU ≥ 90 % |
| maintenance | administratively disabled on the controller |
| down | absent from **two consecutive successful** AP-table polls |
| unknown | never seen. If the controller answers but its AP table is empty or unreadable, APs keep their state; it is a collection problem, not an outage. |

**Radio state:** up / down / disabled, from `bsnAPIfOperStatus` / `AdminStatus`.

**Change events:**

- channel changes
- AP reboots (uptime decreased)
- software changes
- client associations, disconnections and roams. Client events are capped at 2,000 per poll; the rest are
  summarised.

**Retry rate:** Δretries / Δtransmitted frames between polls. Counter resets and wraps produce no value, never a
negative one.

**AP ↔ switch:**

- The AP's uplink comes only from the controller's CDP cache (CISCO-LWAPP-CDP-MIB): neighbour switch name or address,
  and port. It is matched to a monitored switch by address or hostname, and to its interface by normalised port name.
- It is never inferred from the AP's IP address.
- Troubleshooting then reads that port's oper state, PoE status and errors from switch monitoring.

## Client Experience Score

The score runs from 0 to 100 and is the weighted mean of the components that were measured:

| Component | Weight | Scores 100 at | Scores 0 at |
|---|---|---|---|
| RSSI | 30 | −67 dBm | −80 dBm |
| SNR | 30 | 25 dB | 10 dB |
| Data rate | 15 | 100 Mbit/s | 12 Mbit/s |
| Serving radio channel utilisation | 15 | band threshold − 30 | band threshold + 10 |
| Serving radio retry rate | 10 | half the threshold | threshold + 10 |

- Scoring is linear between the two points.
- Missing components are left out, and **confidence** = measured weight ÷ 100.
- A client with no measured component has no score. Hover a score to see its components.
- Grades: good ≥ 75, fair ≥ 50, poor below 50.

## Thresholds

The defaults are below. Set per-controller overrides (one controller per site is the usual layout) in Wireless → WLC
Inventory → Thresholds, or with `PUT /api/wireless/controllers/{id}/thresholds`.

| Threshold | Default |
|---|---|
| Channel utilisation | 2.4 GHz 70 %, 5 GHz 80 %, 6 GHz 80 % |
| 802.11 interference | 30 % |
| Noise floor | −85 dBm |
| Poor RSSI | −75 dBm |
| Low SNR | 15 dB |
| Low data rate | 12 Mbit/s |
| Retry rate | 20 % |
| AP client overload | 40 clients |
| Roaming | 10 roams per hour |

## Alerts

The rules run in the existing engine, with its thresholds, windows, severity, cooldown, de-duplication by group key
and notification routing. Rules that auto-resolve send `alert.resolved`. All rules skip paused controllers and APs in
maintenance.

| Rule | Condition |
|---|---|
| `wireless_ap_down` | AP left the controller; only while the controller itself answers |
| `wireless_radio_down` | an enabled radio is down |
| `wireless_channel_utilization` | sustained over the window, using ClickHouse history |
| `wireless_interference` | sustained 802.11 interference |
| `wireless_noise_high` | sustained high noise floor |
| `wireless_retry_high` | sustained high retry rate |
| `wireless_poor_rssi` | many clients of one AP with poor RSSI |
| `wireless_low_snr` | many clients of one AP with low SNR |
| `wireless_ap_overload` | AP client count over the threshold |
| `wireless_client_disconnects` | many disconnections at one AP within the window |
| `wireless_assoc_failures` | spike in the AP's failed-association counter |
| `wireless_excessive_roaming` | a client roamed more than the threshold |
| `wireless_stale_metrics` | a wireless group is stale or keeps failing |

WLC unreachable, CPU and memory are covered by the switch rules (`switch_unreachable`, `switch_cpu_high`,
`switch_memory_high`), because the controller is a monitored device.

Wireless alerts belong to Sentinel NMS. They correlate into incidents by site, like switch alerts.

## Troubleshooting engine

`POST /api/wireless/troubleshoot` with a scenario:

- **Poor wireless performance**
- **AP offline:** controller reachability, AP state and events, CDP port, the switch's port and PoE state
- **Client cannot connect:** SSID enabled and broadcast, radio state, client status (`aaaPending` / `excluded`), VLAN
- **Frequent disconnections**
- **High client load**

Every check lists its source and threshold, plus severity, confidence and next steps. Probable causes are presented as
correlations, never as root causes. Stale data is flagged first.

## APIs (Sentinel NMS product access; usernames are shown to administrators only)

| Endpoint | Purpose |
|---|---|
| `/api/wireless/meta`, `/overview`, `/controllers`, `/controllers/{id}`, `/health`, `/oids` | metadata, overview, inventory, capability and health views, OID registry |
| `/api/wireless/aps`, `/aps/{id}`, `/aps/{id}/history`, `/radios`, `/radios/{id}/history`, `/rf` | APs, radios and RF analytics |
| `/api/wireless/clients`, `/clients/{mac}`, `/wlans`, `/roaming`, `/events` | clients, WLANs, roaming and events |
| `POST /api/wireless/troubleshoot` | troubleshooting engine |
| `PUT /api/wireless/controllers/{id}/thresholds` | per-controller thresholds (admin) |

Onboarding goes through the switch APIs: `POST /api/switches` with `role: "wlc"`, and `POST /api/switches/test` with
`wlc: true` for the capability scan.

## RF & Frequency Monitoring

**Wireless → RF & Frequency Monitoring** (`/wireless?tab=rf-…`) has these pages:

- RF Overview
- Frequency Distribution
- Utilisation Heatmap
- AP Radio Details
- RF Events
- RF Findings & Troubleshooting

The former "Radio & RF" tab now opens the RF Overview.

It uses the same collector, inventory and scheduler as the rest of Wireless Analysis: the WLC row in `switches` and the
switch poller with its leases, concurrency limits and timeouts. Monitoring is read-only. Recommendations from RRM are
displayed, never applied. Channels, transmit power and RF profiles are never changed.

### Collection

| Group | Interval | Tables |
|---|---|---|
| `wireless_radio` | 60 s | Channel, width, power level, utilisation (total, Tx, Rx), clients, 802.11 counters, radio link-change count |
| `wireless_radio_rf` | 300 s | Noise and 802.11 interference on the current channel; DFS radar detections per channel |
| `wireless_radio_meta` | 900 s | Channel and power assignment mode, regulatory-domain support, country, RRM recommended channel and power level, mW-per-level power table, radio MAC |
| `wireless_rf_neighbors` | 300 s | RRM neighbour list: other AP radios each radio hears, with RSSI, channel and width |

- Intervals are set per controller with `group_intervals`, like every other group (0 disables a group).
- The neighbour walk is bounded to 100 000 rows; the noise and interference walks to 200 000.

New objects resolved from the Cisco MIB sources (`backend/tools/wireless_mibs`; the generator refuses unreadable objects):

| Object | MIB | OID | Group | Unit / note |
|---|---|---|---|---|
| `cLApDot11IfLinkChangeCount` | CISCO-LWAPP-AP-MIB | `1.3.6.1.4.1.9.9.513.1.2.1.1.15` | wireless_radio | count — radio link up/down transitions (CISCO-LWAPP-AP-MIB cLApDot11IfTable) |
| `bsnAPIfPhyChannelAssignment` | AIRESPACE-WIRELESS-MIB | `1.3.6.1.4.1.14179.2.2.2.1.3` | wireless_radio_meta | automatic = channel assigned by RRM (DCA) |
| `bsnAPIfPhyTxPowerControl` | AIRESPACE-WIRELESS-MIB | `1.3.6.1.4.1.14179.2.2.2.1.5` | wireless_radio_meta | automatic = power assigned by RRM (TPC) |
| `bsnAPIfRegulatoryDomainSupport` | AIRESPACE-WIRELESS-MIB | `1.3.6.1.4.1.14179.2.2.2.1.23` | wireless_radio_meta | whether the radio's regulatory domain is supported by the controller |
| `bsnAPIfDot11CountryString` | AIRESPACE-WIRELESS-MIB | `1.3.6.1.4.1.14179.2.2.3.1.9` | wireless_radio_meta | ISO 3166-1 country code plus indoor/outdoor flag |
| `bsnAPIfRecommendedChannelNumber` | AIRESPACE-WIRELESS-MIB | `1.3.6.1.4.1.14179.2.2.20.1.1` | wireless_radio_meta | channel recommended by RRM (read only; never applied by this system) |
| `bsnAPIfRecommendedTxPowerLevel` | AIRESPACE-WIRELESS-MIB | `1.3.6.1.4.1.14179.2.2.20.1.2` | wireless_radio_meta | power level recommended by RRM |
| `bsnAPIfDot11NumberSupportedPowerLevels` | AIRESPACE-WIRELESS-MIB | `1.3.6.1.4.1.14179.2.2.8.1.1` | wireless_radio_meta | deprecated in the MIB |
| `bsnAPIfDot11TxPowerLevel1 … Level8` | AIRESPACE-WIRELESS-MIB | `1.3.6.1.4.1.14179.2.2.8.1.2` | wireless_radio_meta | mW — deprecated in the MIB; mW per power level, converted to dBm for the current level when answered (Level2–8: next columns of the same table) |
| `cLApDot11RadioMACAddress` | CISCO-LWAPP-AP-MIB | `1.3.6.1.4.1.9.9.513.1.2.3.1.1` | wireless_radio_meta | base MAC address of the radio |
| `bsnAPIfRadarDetectedChannelNumber` | AIRESPACE-WIRELESS-MIB | `1.3.6.1.4.1.14179.2.2.24.1.1` | wireless_radio_rf | channel on which radar was detected |
| `bsnAPIfRadarSignalLastHeard` | AIRESPACE-WIRELESS-MIB | `1.3.6.1.4.1.14179.2.2.24.1.2` | wireless_radio_rf | s — seconds since radar was last heard on that channel |
| `bsnAPIfRxNeighborIpAddress` | AIRESPACE-WIRELESS-MIB | `1.3.6.1.4.1.14179.2.2.17.1.2` | wireless_rf_neighbors |  |
| `bsnAPIfRxNeighborRSSI` | AIRESPACE-WIRELESS-MIB | `1.3.6.1.4.1.14179.2.2.17.1.3` | wireless_rf_neighbors | dBm — RSSI at which this radio hears the neighbouring AP radio |
| `bsnAPIfRxNeighborSlot` | AIRESPACE-WIRELESS-MIB | `1.3.6.1.4.1.14179.2.2.17.1.24` | wireless_rf_neighbors |  |
| `bsnAPIfRxNeighborChannel` | AIRESPACE-WIRELESS-MIB | `1.3.6.1.4.1.14179.2.2.17.1.26` | wireless_rf_neighbors |  |
| `bsnAPIfRxNeighborChannelWidth` | AIRESPACE-WIRELESS-MIB | `1.3.6.1.4.1.14179.2.2.17.1.27` | wireless_rf_neighbors | the MIB defines widths up to 40 MHz only |

As with every wireless metric, support is decided per controller at run time:

- **Capability status:** Wireless → Monitoring Health, and the RF API's `/capabilities`, which also lists per AP model what the radios actually returned.
- **Deprecated objects:** `bsnAPIfDot11PhyTxPowerTable` is deprecated in the MIB. When a 9800 release does not answer it, transmit power is shown as the level (1–8) only, never as an invented dBm value.

### Frequencies

`backend/app/wireless/rf.py` converts channels to frequencies with a separate table per band:

| Band | Channels | Frequency |
|---|---|---|
| 2.4 GHz | 1–13 | 2407 + 5·ch MHz |
| 2.4 GHz | 14 | 2484 MHz |
| 5 GHz | 32–177 | 5000 + 5·ch MHz |
| 5 GHz (Japan 4.9 GHz) | 183–196 | 4000 + 5·ch MHz |
| 6 GHz | 1–233 | 5950 + 5·ch MHz |
| 6 GHz | 2 | 5935 MHz |

- **Validation:** channels that are not valid for the band give no frequency.
- **Center frequency:** for 40/80/160 MHz it comes from the IEEE channel block (5 GHz tables; 6 GHz blocks aligned from channel 1), not from the primary channel.
- **Unknown center:** a 2.4 GHz 40 MHz center (the bonding direction is not reported), an 80+80 MHz channel, and the ambiguous band of a dual 5/6 GHz (XOR) radio are left unknown.
- **DFS:** 5 GHz channels 52–64 and 100–144, including any bonded block that touches them. The radio's country code is shown next to it, because local rules vary.

### Telemetry model

ClickHouse table `rf_telemetry` (migration 13, 30-day TTL) is vendor-neutral. Each row holds:

- ts, site, wlc_id, ap_id, radio_id, slot, vendor
- band, channel, center_mhz, width_mhz
- metric, value, unit, source (MIB / table)
- **status**: `ok`, `missing` or `invalid`
- **quality**: `measured`, or `derived` (retry percentage from counter deltas; dBm from the mW table)

A value that is missing or outside a plausible range (for example utilisation above 100 %, or noise above −20 dBm) is
stored with a NULL value and its status. It is never stored as zero and never clamped. The heatmap and history show such
intervals as "no data". Current values also live on `wireless_radios` (migration `0023`).

### Events

| Event | Detail |
|---|---|
| `channel_change` | Old and new channel and MHz, plus a **reason with a confidence**. "Radar detected on channel N (DFS)" is high confidence when the radar table shows a recent detection on the old channel. "Assigned by RRM / DCA" is medium confidence when the channel assignment mode is automatic; SNMP does not carry the DCA trigger. "Static channel changed" applies when the assignment is customised. |
| `dfs_radar` | — |
| `tx_power_change` | — |
| `radio_link_change` | — |
| `radio_up`, `radio_down`, `radio_disabled` | — |

RF Events also lists RF alerts from the alert engine.

### Analytics (`backend/app/wireless/rf_analytics.py`)

The findings are rule-based and explainable:

- high channel utilisation
- channel contention (utilisation minus the radio's own Tx and Rx)
- co-channel interference
- adjacent-channel interference
- high noise floor
- poor client SNR
- excessive retries
- uneven client distribution
- repeated channel changes
- radio failure (down while enabled, or repeated link changes)

Every finding carries:

- site, AP, radio, band, channel, frequency and center frequency
- the observed value and the threshold
- duration and persistence (from `rf_telemetry` over the persistence window)
- the radio's own 7-day average
- evidence lines and a confidence
- possible causes and troubleshooting steps

**Interference findings** need all of the following:

1. An RRM neighbour heard at or above `cochannel_rssi_dbm` / `adjacent_rssi_dbm`.
2. Spectral overlap computed from both radios' channel and width.
3. A measured impact (utilisation ≥ 80 % of the threshold, or 802.11 interference ≥ the threshold).

Equal channel numbers alone never produce a finding. Two radios in the same 80 MHz block with different primary channels
are correctly treated as co-channel. Without history a finding is shown with low confidence and "persistence not
established". Without its inputs a rule produces nothing, and the page lists the missing inputs.

**Root-cause extension point:** `RCA_PROVIDERS` holds the rule-based provider. An AI provider would receive the same
finding and collected telemetry, may not add facts, and is not implemented (the API accepts `engine=rules` only).

### Thresholds and alerts

The new per-controller thresholds (`thresholds.wireless`) are:

| Threshold | Default |
|---|---|
| `rf_persistence_minutes` / `rf_persistence_fraction` | 15 min / 0.6 |
| `contention_pct` | 30 |
| `cochannel_rssi_dbm` | −75 |
| `adjacent_rssi_dbm` | −70 |
| `channel_changes_per_day` | 4 |
| `uneven_ratio` / `uneven_min_clients` | 2.5 / 15 |
| `poor_snr_min_clients` | 3 |
| `link_changes_per_day` | 3 |
| Clear margins: `clear_margin_util_pct` / `clear_margin_interference_pct` / `clear_margin_noise_db` / `clear_margin_retry_pct` | 10 / 5 / 3 / 5 |

Alerts:

- **Hysteresis:** the utilisation, interference, noise and retry rules have it. An open alert stays open until the latest sample is below threshold − margin, so a value hovering at the threshold does not flap.
- **New rule:** `wireless_channel_changes` (repeated channel changes, with the reasons listed).
- **Existing rules:** radio down and poor SNR use `wireless_radio_down` and `wireless_low_snr`.

All rules use the existing deduplication, cooldown, notifications and auto-resolve.

### RF API (`/api/wireless/rf`, Sentinel NMS product access)

| Endpoint | Purpose |
|---|---|
| `GET overview`, `distribution`, `heatmap` | Summary cards, channel / width / site distribution, AP radio × time (filters: `site`, `wlc_id`, `ap_id`, `radio_id`, `band`, `metric`, `range`) |
| `GET radios`, `radios/{id}`, `radios/{id}/history` | Radio list, detail (2.4 / 5 GHz sections, neighbours, radar, metric status, findings, events), history with sample counts |
| `GET events`, `findings` | RF events and alerts; findings (`engine=rules`) |
| `GET capabilities`, `channels` | Per controller and AP-model support; channel / frequency reference |

### Deployment

- **Migrations:** Postgres `0023_wireless_rf` (additive) and ClickHouse migration 13 run with the usual migrate step.
- **SNMPv3 view:** the read-only view must include `1.3.6.1.4.1.14179` (AIRESPACE-WIRELESS-MIB) and `1.3.6.1.4.1.9.9` (CISCO-LWAPP-AP-MIB), as already required.
- **Verify on the controller:** press **Test** on the controller and check Monitoring Health for the RF groups.

### Unsupported or limited

- **Streaming telemetry and RESTCONF / NETCONF:** the Catalyst 9800 adapter is not implemented. SNMP is the only source.
- **Channel-change trigger:** the DCA trigger is not available over SNMP, so the reason is inferred (see Events).
- **Channel busy vs channel utilisation:** both are the same value, `bsnAPIfLoadChannelUtilization`.
- **Channel width:** neighbour width is reported only up to 40 MHz by the MIB. When the neighbour is a known AP, its own radio width is used instead.
- **Radio health:** radio uptime and a radio reset counter are not exposed. The radio link-change count is used instead.
- **Per-client retries:** not available. Retry percentage is per radio.
- **DFS:** the DFS state comes from the channel table plus the radar table. There is no separate DFS status object, and the CAC state is not available.
- **6 GHz:** appears only when the controller reports 6 GHz radios. The C9120AXI-D is a 2.4 / 5 GHz AP.
- **Site-level access:** the application has no site-level RBAC. Access is per product (Sentinel NMS), and site filters only narrow queries.
- **Validation:** this feature was validated with labelled, MIB-shaped fixtures and a fixture controller seeded through the real poller, not against a live 9800 on IOS XE 17.12.04. Confirm per-release support with the Test button and `/api/wireless/rf/capabilities`.

## Controller SNMP configuration

1. **Create a read-only SNMPv3 user (authPriv) on the 9800.** Use SHA-2 and AES where the release supports them, and
   bind it to a view that includes these subtrees:
   - `1.3.6.1.2.1` (MIB-2)
   - `1.3.6.1.4.1.9.9` (CISCO-LWAPP-*, CISCO-PROCESS-MIB)
   - `1.3.6.1.4.1.14179` (AIRESPACE-WIRELESS-MIB)

   For example:

   ```
   snmp-server view SIEM-RO iso included
   snmp-server group SIEM-RO v3 priv read SIEM-RO access <ACL permitting the SIEM>
   snmp-server user siem-ro SIEM-RO v3 auth sha <auth-pass> priv aes 128 <priv-pass>
   ```
2. **Add the SNMP credential** in Sentinel NMS → Switch Monitoring → Settings, and authorise the controller's
   management network.
3. **Add the controller** in Wireless → WLC Inventory → **+ Add controller**, then press **Test**. The result lists
   every wireless object with the status this release returned.
4. **Large deployments:** raise `wireless_client` to 300–600 s. The client table is the largest walk, and its rows are
   bounded at 20,000 per poll; a larger table is flagged as truncated, and disconnects are not inferred from a
   truncated walk.

## Limitations

- Validated only against MIB-shaped fixtures in automated tests. Per-release behaviour must be confirmed with the
  Test / Monitoring Health views on the real controller.
- Polling is SNMP only. The optional RESTCONF / telemetry adapter described in the brief is not implemented.
- Roaming and disconnection timing has poll granularity (60–120 s by default).
- Site, building and floor come from the controller's own site / building / floor fields, or an admin override on the
  AP. There are no floor maps.
