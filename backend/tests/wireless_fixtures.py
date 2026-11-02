"""Catalyst 9800-shaped SNMP fixtures for the wireless tests.

Values are placed at the registry OIDs (app/wireless/oids.py, generated from Cisco's MIB files) with the MIB INDEX
encodings: MAC addresses as 6 sub-identifiers, radios as MAC.slot, per-channel noise / interference as MAC.slot.channel,
radio WLANs as MAC.slot.wlanIndex, CDP cache as MAC.deviceIndex, clients as the client MAC. Values use the SMI types
the real client returns (int, bytes for OCTET STRING / MacAddress, ("ip", "a.b.c.d") for IpAddress).
"""
from app.wireless.oids import OBJ

SYS = "1.3.6.1.2.1.1"


def mi(m: str) -> str:
    return ".".join(str(int(x, 16)) for x in m.split(":"))


def mb(m: str) -> bytes:
    return bytes(int(x, 16) for x in m.split(":"))


def put(t: dict, obj: str, index: str, value):
    t[f"{OBJ[obj]['oid']}.{index}"] = value


AP1, AP2 = "00:11:22:33:44:01", "00:11:22:33:44:02"
C1, C2, C3 = "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02", "aa:bb:cc:00:00:03"


def c9800(step: int = 0, *, aps=(AP1, AP2), with_lwapp_ap=True, clients=None, retries=(1000, 2000), ap_table=True, rf=False,
          radar_heard: int | None = None, util_over: dict | None = None, channel: dict | None = None) -> dict:
    """step moves time / counters. clients: {mac: (ap_mac, slot, rssi, snr)}.
    rf=True adds the RF tables (radio configuration / regulatory, transmit-power table in mW, radio MAC, link-change count,
    RRM neighbours); radar_heard adds a DFS radar row on AP1 slot 1 heard that many seconds ago. util_over / channel override
    {(ap_mac, slot): value}. LABELLED FIXTURE: MIB-shaped synthetic values, not a captured controller response."""
    t = {f"{SYS}.1.0": b"Cisco IOS Software [Cupertino], C9800 Software (C9800_IOSXE-K9), Version 17.9.4, RELEASE SOFTWARE (fc5)",
         f"{SYS}.2.0": ("oid", "1.3.6.1.4.1.9.1.2391"), f"{SYS}.3.0": ("ticks", 9_000_000 + step * 6000), f"{SYS}.5.0": b"WLC-WH1",
         f"{SYS}.6.0": b"WH1 server room"}
    if not ap_table:
        return t
    for n, m in enumerate(aps, start=1):
        i = mi(m)
        put(t, "bsnAPName", i, f"WH1-AP-0{n}".encode())
        put(t, "bsnAPLocation", i, b"WH1 floor 1")
        put(t, "bsnAPOperationStatus", i, 1)                  # associated
        put(t, "bsnAPAdminStatus", i, 1)
        put(t, "bsnAPSoftwareVersion", i, b"17.9.4.27")
        put(t, "bsnAPModel", i, b"C9120AXI-D")
        put(t, "bsnAPSerialNumber", i, f"FGL2400000{n}".encode())
        put(t, "bsnApIpAddress", i, ("ip", f"10.30.0.{10 + n}"))
        put(t, "bsnAPNumOfSlots", i, 2)
        if with_lwapp_ap:
            put(t, "cLApName", i, f"WH1-AP-0{n}".encode())
            put(t, "cLApUpTime", i, ("ticks", 360000 * (n + 1) + step * 6000))   # hundredths of a second
            put(t, "cLLwappUpTime", i, ("ticks", 300000 + step * 6000))
            put(t, "cLApLastRebootReason", i, 4)              # rebootFromController
            put(t, "cLApCpuCurrentUsage", i, 12 * n)
            put(t, "cLApMemoryCurrentUsage", i, 40)
            put(t, "cLApAssocFailTimes", i, ("counter", 5 + step * 30 * (n == 2)))
            put(t, "cLApSiteTagName", i, b"wh1-site")
        put(t, "clcCdpApCacheNeighName", f"{i}.1", f"WH1-ACC-SW0{n}.corp.example".encode())
        put(t, "clcCdpApCacheNeighInterface", f"{i}.1", f"GigabitEthernet1/0/{4 + n}".encode())
        put(t, "clcCdpApCachePlatform", f"{i}.1", b"cisco C9300-48P")
        for slot, (typ, ch, width, util) in enumerate(((1, 6, 3, 35 + n), (2, 36 if n == 1 else 40, 5, 82 if n == 1 else 20))):
            ri = f"{i}.{slot}"
            put(t, "bsnAPIfType", ri, typ)
            put(t, "bsnAPIfPhyChannelNumber", ri, ch)
            put(t, "bsnAPIfPhyTxPowerLevel", ri, 3)
            put(t, "bsnAPIfOperStatus", ri, 2)
            put(t, "bsnAPIfAdminStatus", ri, 1)
            put(t, "bsnApIfNoOfUsers", ri, ("counter", 2))
            put(t, "cLAp11ChannelBandwidth", ri, width)
            put(t, "bsnAPIfLoadChannelUtilization", ri, util)
            put(t, "bsnAPIfLoadTxUtilization", ri, 10)
            put(t, "bsnAPIfLoadRxUtilization", ri, 15)
            put(t, "bsnAPIfPoorSNRClients", ri, 0)
            put(t, "bsnAPIfDot11TransmittedFrameCount", ri, ("counter", 100_000 + step * 10_000))
            put(t, "bsnAPIfDot11RetryCount", ri, ("counter", retries[min(step, len(retries) - 1)] if slot == 1 and n == 1 else 500 + step * 500))
            for c in (1, 6, 11) if typ == 1 else (36, 40, 44):
                put(t, "bsnAPIfDBNoisePower", f"{ri}.{c}", -95 if c == ch else -70)        # only the current channel counts
                put(t, "bsnAPIfInterferenceUtilization", f"{ri}.{c}", 40 if (c == ch and n == 1 and slot == 1) else 5)
                put(t, "bsnAPIfInterferencePower", f"{ri}.{c}", -80)
            if util_over and (m, slot) in util_over:
                put(t, "bsnAPIfLoadChannelUtilization", ri, util_over[(m, slot)])
            if channel and (m, slot) in channel:
                put(t, "bsnAPIfPhyChannelNumber", ri, channel[(m, slot)])
            if rf:
                put(t, "bsnAPIfPhyChannelAssignment", ri, 1)                 # automatic (RRM)
                put(t, "bsnAPIfPhyTxPowerControl", ri, 1)
                put(t, "bsnAPIfRegulatoryDomainSupport", ri, 1)
                put(t, "bsnAPIfDot11CountryString", ri, b"IN ")
                put(t, "bsnAPIfRecommendedChannelNumber", ri, ch)
                put(t, "bsnAPIfDot11NumberSupportedPowerLevels", ri, 8)
                for lvl, mw in enumerate((200, 100, 50, 25, 13, 6, 3, 2), start=1):
                    put(t, f"bsnAPIfDot11TxPowerLevel{lvl}", ri, mw)
                put(t, "cLApDot11RadioMACAddress", ri, mb(m[:-2] + f"{0xa0 + slot:02x}"))
                put(t, "cLApDot11IfLinkChangeCount", ri, 2 + (step if (n == 2 and slot == 0) else 0))
                if n == 2 and slot == 0:              # as seen on a 9800: radio type outside the MIB enumeration, band from the XOR column
                    put(t, "bsnAPIfType", ri, 3)
                    put(t, "cLApDot11XorRadioBand", ri, 1)
                if n == 2 and slot == 1:
                    put(t, "bsnAPIfInterferencePower", f"{ri}.{ch}", -128)   # "no measurement" sentinel
            put(t, "cLApRadioWlanSsid", f"{ri}.1", b"CORP")
            put(t, "cLApRadioWlanBssid", f"{ri}.1", mb(m[:-2] + f"{slot:02x}"))
    if rf and AP1 in aps and AP2 in aps:
        # RRM neighbours: AP1 5 GHz hears AP2 5 GHz (channel 40 / 80 MHz: same 36-48 block as AP1 channel 36 / 80 MHz) at -60 dBm;
        # AP1 2.4 GHz hears AP2 2.4 GHz (channel 6, same channel) weakly at -82 dBm and a foreign AP on channel 8 at -65 dBm
        for slot, nmac, nslot, rssi, nch, nw in ((1, AP2, 1, -60, 40, 3), (0, AP2, 0, -82, 6, 3), (0, "02:aa:bb:cc:dd:01", 0, -65, 8, 3)):
            k = f"{mi(AP1)}.{slot}.{mi(nmac)}"
            put(t, "bsnAPIfRxNeighborRSSI", k, rssi)
            put(t, "bsnAPIfRxNeighborSlot", k, nslot)
            put(t, "bsnAPIfRxNeighborChannel", k, nch)
            put(t, "bsnAPIfRxNeighborChannelWidth", k, nw)
    if radar_heard is not None and AP1 in aps:
        put(t, "bsnAPIfRadarDetectedChannelNumber", f"{mi(AP1)}.1.52", 52)
        put(t, "bsnAPIfRadarSignalLastHeard", f"{mi(AP1)}.1.52", radar_heard)
    put(t, "cLWlanProfileName", "1", b"corp-profile")
    put(t, "cLWlanSsid", "1", b"CORP")
    put(t, "cLWlanRowStatus", "1", 1)
    put(t, "bsnDot11EssSsid", "1", b"CORP")
    put(t, "bsnDot11EssAdminStatus", "1", 1)
    put(t, "bsnDot11EssSecurityAuthType", "1", 0)
    put(t, "bsnDot11EssNumberOfMobileStations", "1", ("counter", len(clients) if clients is not None else 3))
    clients = clients if clients is not None else {C1: (AP1, 1, -60, 35), C2: (AP1, 0, -80, 9), C3: (AP2, 1, -55, 40)}
    for k, (ap, slot, rssi, snr) in clients.items():
        i = mi(k)
        put(t, "cldcClientStatus", i, 4)                       # associated
        put(t, "cldcClientWlanProfileName", i, b"corp-profile")
        put(t, "cldcApMacAddress", i, mb(ap))
        put(t, "cldcIfType", i, 2 if slot == 1 else 1)
        put(t, "cldcClientIPAddress", i, ("ip", f"10.40.0.{int(k[-2:], 16)}"))
        put(t, "cldcClientAccessVLAN", i, 40)
        put(t, "cldcClientUpTime", i, 600 + step * 60)
        put(t, "cldcClientUsername", i, f"user{int(k[-2:], 16)}@corp".encode())
        put(t, "cldcClientSSID", i, b"CORP")
        put(t, "cldcClientAuthMode", i, 2)                     # radius
        put(t, "cldcClientCurrentTxRate", i, 433 if rssi > -70 else 6)
        put(t, "bsnMobileStationAPMacAddr", i, mb(ap))
        put(t, "bsnMobileStationAPIfSlotId", i, slot)
        put(t, "bsnMobileStationSsid", i, b"CORP")
        put(t, "bsnMobileStationStatus", i, 3)
        put(t, "bsnMobileStationProtocol", i, 11 if slot == 1 else 12)
        put(t, "bsnMobileStationRSSI", i, rssi)
        put(t, "bsnMobileStationSnr", i, snr)
        put(t, "bsnMobileStationBytesReceived", i, ("counter64", 1_000_000 + step))
        put(t, "bsnMobileStationBytesSent", i, ("counter64", 2_000_000 + step))
    return t
