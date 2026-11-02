import json, sys
d = json.load(open(sys.argv[1])); en = json.load(open(sys.argv[2]))["enums"]
# (object, group, category, metric key or "" for attribute, unit, note)
SEL = [
 # AP inventory / state (AIRESPACE-WIRELESS-MIB bsnAPTable, index bsnAPDot3MacAddress)
 ("bsnAPName","wireless_ap","ap_inventory","","",""),("bsnAPLocation","wireless_ap","ap_inventory","","",""),
 ("bsnAPOperationStatus","wireless_ap","ap_state","wireless_ap_up","","associated = joined to this controller"),
 ("bsnAPSoftwareVersion","wireless_ap","ap_inventory","","",""),("bsnAPModel","wireless_ap","ap_inventory","","",""),
 ("bsnAPSerialNumber","wireless_ap","ap_inventory","","",""),("bsnApIpAddress","wireless_ap","ap_inventory","","",""),
 ("bsnAPNumOfSlots","wireless_ap","ap_inventory","","",""),("bsnAPPrimaryMwarName","wireless_ap","ap_inventory","","",""),
 ("bsnAPAdminStatus","wireless_ap","ap_state","","",""),("bsnAPGroupVlanName","wireless_ap","ap_inventory","","",""),
 # AP detail (CISCO-LWAPP-AP-MIB cLApTable, index cLApSysMacAddress)
 ("cLApName","wireless_ap","ap_inventory","","",""),("cLApUpTime","wireless_ap","ap_state","wireless_ap_uptime_seconds","s","AP uptime (TimeTicks)"),
 ("cLLwappUpTime","wireless_ap","ap_state","wireless_ap_join_uptime_seconds","s","time since the AP joined the controller"),
 ("cLApLastRebootReason","wireless_ap","ap_state","","",""),("cLApAssociatedClientCount","wireless_ap","ap_clients","wireless_ap_client_count","clients",""),
 ("cLApCpuCurrentUsage","wireless_ap","ap_resources","wireless_ap_cpu_percent","%",""),("cLApMemoryCurrentUsage","wireless_ap","ap_resources","wireless_ap_memory_percent","%",""),
 ("cLApAssocFailTimes","wireless_ap","ap_clients","wireless_ap_assoc_failures","count","Counter32"),
 ("cLApReassocFailCount","wireless_ap","ap_clients","wireless_ap_reassoc_failures","count","Counter32"),
 ("cLApSiteTagName","wireless_ap","ap_inventory","","",""),("cLApRfTagName","wireless_ap","ap_inventory","","",""),("cLApPolicyTagName","wireless_ap","ap_inventory","","",""),
 ("cLApPowerStatus","wireless_ap","ap_state","","",""),
 # AP uplink neighbour (CISCO-LWAPP-CDP-MIB clcCdpApCacheTable, index cLApSysMacAddress.clcCdpApCacheDeviceIndex)
 ("clcCdpApCacheNeighName","wireless_ap_cdp","ap_uplink","wireless_ap_uplink_neighbor","","switch the AP is cabled to (CDP)"),
 ("clcCdpApCacheNeighAddress","wireless_ap_cdp","ap_uplink","","",""),("clcCdpApCacheNeighInterface","wireless_ap_cdp","ap_uplink","","",""),
 ("clcCdpApCachePlatform","wireless_ap_cdp","ap_uplink","","",""),
 # radios (bsnAPIfTable, index bsnAPDot3MacAddress.bsnAPIfSlotId)
 ("bsnAPIfType","wireless_radio","radio_state","","",""),("bsnAPIfPhyChannelNumber","wireless_radio","radio_state","wireless_radio_channel","",""),
 ("bsnAPIfPhyTxPowerLevel","wireless_radio","radio_state","wireless_radio_tx_power_level","level 1-8","power level (1 = highest), not dBm"),
 ("bsnAPIfOperStatus","wireless_radio","radio_state","wireless_radio_up","",""),("bsnAPIfAdminStatus","wireless_radio","radio_state","","",""),
 ("bsnApIfNoOfUsers","wireless_radio","radio_clients","wireless_radio_client_count","clients",""),
 ("cLAp11ChannelBandwidth","wireless_radio","radio_state","wireless_radio_channel_width_mhz","MHz","CISCO-LWAPP-AP-MIB cLApDot11IfTable"),
 ("cLApDot11XorRadioBand","wireless_radio","radio_state","wireless_radio_xor_band","","operating band of a dual-band (XOR) radio; used when bsnAPIfType does not give the band"),
 # radio load (bsnAPIfLoadParametersTable)
 ("bsnAPIfLoadChannelUtilization","wireless_radio","radio_rf","wireless_radio_channel_utilization_percent","%","AP-measured channel busy percentage"),
 ("bsnAPIfLoadTxUtilization","wireless_radio","radio_rf","wireless_radio_tx_utilization_percent","%",""),
 ("bsnAPIfLoadRxUtilization","wireless_radio","radio_rf","wireless_radio_rx_utilization_percent","%",""),
 ("bsnAPIfPoorSNRClients","wireless_radio","radio_clients","wireless_radio_poor_snr_clients","clients",""),
 # per-channel noise / Wi-Fi interference (indexed by channel; the current channel's row is used)
 ("bsnAPIfDBNoisePower","wireless_radio_rf","radio_rf","wireless_radio_noise_dbm","dBm","average noise power on the radio's current channel"),
 ("bsnAPIfInterferenceUtilization","wireless_radio_rf","radio_rf","wireless_radio_interference_percent","%","interference from other 802.11 networks on the current channel"),
 ("bsnAPIfInterferencePower","wireless_radio_rf","radio_rf","wireless_radio_interference_dbm","dBm","power of other 802.11 networks on the current channel"),
 # radio 802.11 counters (bsnAPIfDot11CountersTable, Counter32)
 ("bsnAPIfDot11TransmittedFrameCount","wireless_radio","radio_counters","wireless_radio_tx_frames","frames/s","rate from Counter32"),
 ("bsnAPIfDot11RetryCount","wireless_radio","radio_counters","wireless_radio_retries","frames/s",""),
 ("bsnAPIfDot11FailedCount","wireless_radio","radio_counters","wireless_radio_tx_failed","frames/s",""),
 ("bsnAPIfDot11FCSErrorCount","wireless_radio","radio_counters","wireless_radio_fcs_errors","frames/s",""),
 ("bsnAPIfDot11ACKFailureCount","wireless_radio","radio_counters","wireless_radio_ack_failures","frames/s",""),
 ("cLApDot11IfLinkChangeCount","wireless_radio","radio_health","wireless_radio_link_changes","count","radio link up/down transitions (CISCO-LWAPP-AP-MIB cLApDot11IfTable)"),
 # radio configuration / regulatory (slow-changing: bsnAPIfEntry, bsnAPIfSmtParamTable, bsnAPIfRecommendedRFParametersTable,
 # bsnAPIfDot11PhyTxPowerTable, cLApDot11RadioTable; index AP MAC.slot)
 ("bsnAPIfPhyChannelAssignment","wireless_radio_meta","radio_config","","","automatic = channel assigned by RRM (DCA)"),
 ("bsnAPIfPhyTxPowerControl","wireless_radio_meta","radio_config","","","automatic = power assigned by RRM (TPC)"),
 ("bsnAPIfRegulatoryDomainSupport","wireless_radio_meta","radio_config","","","whether the radio's regulatory domain is supported by the controller"),
 ("bsnAPIfDot11CountryString","wireless_radio_meta","radio_config","wireless_radio_country","","ISO 3166-1 country code plus indoor/outdoor flag"),
 ("bsnAPIfRecommendedChannelNumber","wireless_radio_meta","radio_config","wireless_radio_rrm_recommended_channel","","channel recommended by RRM (read only; never applied by this system)"),
 ("bsnAPIfRecommendedTxPowerLevel","wireless_radio_meta","radio_config","","","power level recommended by RRM"),
 ("bsnAPIfDot11NumberSupportedPowerLevels","wireless_radio_meta","radio_power","","","deprecated in the MIB"),
 ("bsnAPIfDot11TxPowerLevel1","wireless_radio_meta","radio_power","wireless_radio_tx_power_dbm","mW","deprecated in the MIB; mW per power level, converted to dBm for the current level when answered"),
 ("bsnAPIfDot11TxPowerLevel2","wireless_radio_meta","radio_power","","mW",""),("bsnAPIfDot11TxPowerLevel3","wireless_radio_meta","radio_power","","mW",""),
 ("bsnAPIfDot11TxPowerLevel4","wireless_radio_meta","radio_power","","mW",""),("bsnAPIfDot11TxPowerLevel5","wireless_radio_meta","radio_power","","mW",""),
 ("bsnAPIfDot11TxPowerLevel6","wireless_radio_meta","radio_power","","mW",""),("bsnAPIfDot11TxPowerLevel7","wireless_radio_meta","radio_power","","mW",""),
 ("bsnAPIfDot11TxPowerLevel8","wireless_radio_meta","radio_power","","mW",""),
 ("cLApDot11RadioMACAddress","wireless_radio_meta","radio_config","wireless_radio_mac","","base MAC address of the radio"),
 # DFS radar detections (bsnAPIfRadarChannelStatisticsTable, index AP MAC.slot.channel)
 ("bsnAPIfRadarDetectedChannelNumber","wireless_radio_rf","radio_dfs","","","channel on which radar was detected"),
 ("bsnAPIfRadarSignalLastHeard","wireless_radio_rf","radio_dfs","wireless_radio_radar_detected","s","seconds since radar was last heard on that channel"),
 # RRM neighbours heard by each radio (bsnAPIfRxNeighborsTable, index AP MAC.slot.neighbour radio MAC)
 ("bsnAPIfRxNeighborIpAddress","wireless_rf_neighbors","rf_neighbors","","",""),
 ("bsnAPIfRxNeighborRSSI","wireless_rf_neighbors","rf_neighbors","wireless_radio_neighbor_rssi_dbm","dBm","RSSI at which this radio hears the neighbouring AP radio"),
 ("bsnAPIfRxNeighborSlot","wireless_rf_neighbors","rf_neighbors","","",""),
 ("bsnAPIfRxNeighborChannel","wireless_rf_neighbors","rf_neighbors","","",""),
 ("bsnAPIfRxNeighborChannelWidth","wireless_rf_neighbors","rf_neighbors","","","the MIB defines widths up to 40 MHz only"),
 # WLANs (CISCO-LWAPP-WLAN-MIB cLWlanConfigTable, index cLWlanIndex) + bsnDot11EssTable (index bsnDot11EssIndex)
 ("cLWlanProfileName","wireless_wlan","wlan","","",""),("cLWlanSsid","wireless_wlan","wlan","wireless_wlan_up","","SSID / profile defined"),
 ("cLWlanRowStatus","wireless_wlan","wlan","","",""),("cLWlanMaxClientsAccepted","wireless_wlan","wlan","","",""),
 ("bsnDot11EssSsid","wireless_wlan","wlan","","",""),("bsnDot11EssAdminStatus","wireless_wlan","wlan","","",""),
 ("bsnDot11EssSecurityAuthType","wireless_wlan","wlan","","",""),("bsnDot11EssNumberOfMobileStations","wireless_wlan","wlan","wireless_wlan_client_count","clients",""),
 # radio → WLAN (cLApRadioWlanInfoTable, index cLApSysMacAddress.cLApDot11IfSlotId.cLWlanIndex)
 ("cLApRadioWlanSsid","wireless_wlan","wlan","wireless_wlan_radio_count","radios","WLANs broadcast per AP radio"),("cLApRadioWlanBssid","wireless_wlan","wlan","","",""),
 # clients (CISCO-LWAPP-DOT11-CLIENT-MIB cldcClientTable, index cldcClientMacAddress)
 ("cldcClientStatus","wireless_client","client","wireless_client_count","clients",""),("cldcClientWlanProfileName","wireless_client","client","","",""),
 ("cldcApMacAddress","wireless_client","client","","",""),("cldcIfType","wireless_client","client","","",""),
 ("cldcClientIPAddress","wireless_client","client","","",""),("cldcClientAccessVLAN","wireless_client","client","","",""),
 ("cldcClientUpTime","wireless_client","client","wireless_client_session_seconds","s","MIB: SYNTAX TimeInterval but UNITS Seconds; read as seconds per the UNITS clause"),("cldcClientUsername","wireless_client","client","","","RBAC: admins only"),
 ("cldcClientSSID","wireless_client","client","","",""),("cldcClientChannel","wireless_client","client","","",""),
 ("cldcClientAuthMode","wireless_client","client","","",""),("cldcClientReasonCode","wireless_client","client","","",""),
 ("cldcClientApRoamMacAddress","wireless_client","client_roam","","","previous AP when the client roamed"),
 ("cldcClientCurrentTxRate","wireless_client","client_rf","wireless_client_tx_rate_mbps","Mbit/s",""),
 # clients (AIRESPACE bsnMobileStationTable / StatsTable, index bsnMobileStationMacAddress)
 ("bsnMobileStationIpAddress","wireless_client","client","","",""),("bsnMobileStationAPMacAddr","wireless_client","client","","",""),
 ("bsnMobileStationAPIfSlotId","wireless_client","client","","",""),("bsnMobileStationSsid","wireless_client","client","","",""),
 ("bsnMobileStationStatus","wireless_client","client","","",""),("bsnMobileStationReasonCode","wireless_client","client","","",""),
 ("bsnMobileStationProtocol","wireless_client","client","","",""),("bsnMobileStationVlanId","wireless_client","client","","",""),
 ("bsnMobileStationUserName","wireless_client","client","","","RBAC: admins only"),
 ("bsnMobileStationRSSI","wireless_client","client_rf","wireless_client_rssi_dbm","dBm","client-side average packet RSSI reported by the controller"),
 ("bsnMobileStationSnr","wireless_client","client_rf","wireless_client_snr_db","dB",""),
 ("bsnMobileStationBytesReceived","wireless_client","client_traffic","wireless_client_rx_bytes","bytes","Counter64"),
 ("bsnMobileStationBytesSent","wireless_client","client_traffic","wireless_client_tx_bytes","bytes","Counter64"),
 ("bsnMobileStationPacketsReceived","wireless_client","client_traffic","","packets","Counter64"),
 ("bsnMobileStationPacketsSent","wireless_client","client_traffic","","packets","Counter64"),
]
out = ['"""Wireless OID registry, generated from the Cisco MIB sources (github.com/cisco/cisco-mibs, v2/*.my) by resolving each',
       'OBJECT-TYPE to its numeric OID. Every object listed here is defined in the named MIB; whether a Catalyst 9800 release',
       'implements it is decided per controller at run time (capability registry), never assumed. Do not edit OIDs by hand."""',
       "from __future__ import annotations", "", "OBJ: dict[str, dict] = {"]
for name, group, cat, key, unit, note in SEL:
    v = d[name]
    assert v["oid"], name
    assert v["access"].startswith("read"), (name, v["access"])
    out.append(f'    "{name}": {{"oid": "{v["oid"]}", "mib": "{v["mib"]}", "syntax": {json.dumps(v["syntax"][:60])}, "group": "{group}", '
               f'"category": "{cat}", "metric": "{key}", "unit": "{unit}", "note": {json.dumps(note)}}},')
out.append("}")
out.append("")
ENUMS = ["bsnAPIfType","bsnAPOperationStatus","bsnAPIfOperStatus","bsnAPIfAdminStatus","bsnAPAdminStatus","bsnMobileStationStatus","bsnMobileStationProtocol",
         "bsnMobileStationReasonCode","bsnDot11EssAdminStatus","bsnDot11EssSecurityAuthType","cLApLastRebootReason","cLAp11ChannelBandwidth","cldcClientAuthMode",
         "cldcClientReasonCode","cLApPowerStatus","bsnAPIfPhyChannelAssignment","bsnAPIfPhyTxPowerControl","bsnAPIfRegulatoryDomainSupport",
         "bsnAPIfRxNeighborChannelWidth","cLApDot11XorRadioBand"]
out.append("ENUMS: dict[str, dict[int, str]] = {")
for e in ENUMS:
    out.append(f'    "{e}": {json.dumps({int(k): v for k, v in en[e].items()})},'.replace('"{', '{').replace('}"', '}'))
out.append('    "cldcClientStatus": {"1": "idle", "2": "aaaPending", "3": "authenticated", "4": "associated", "5": "powersave", "6": "disassociated", "7": "tobedeleted", "8": "probing", "9": "excluded"},')
out.append('    "cldcIfType": {"1": "dot11bg", "2": "dot11a", "3": "uwb", "4": "dot11abgn", "5": "rlan", "6": "dot11_6ghz", "7": "dot11_xor_5_6ghz"},')
out.append("}")
out.append("ENUMS = {k: {int(i): n for i, n in v.items()} for k, v in ENUMS.items()}")
out.append("")
out.append("def oid(name: str) -> str:\n    return OBJ[name][\"oid\"]")
print("\n".join(out))
