"""Network-device syslog parsing (Cisco IOS / IOS-XE / NX-OS / C9800, Ruckus ICX).

LABELLED SYNTHETIC FIXTURES: every line below is written in the documented message format of the platform
(%FACILITY-SEVERITY-MNEMONIC for Cisco, "Facility: text" for FastIron) with RFC 5737 addresses and fake names;
none is a capture from a production device."""
import pytest

from app.ingest import generic, netdev

SRC = {"id": 7, "name": "lab-switches", "kind": "netdev", "site": "WH1"}

CASES = [
    # (line, vendor, kind, action, severity, field checks)
    ("<189>Nov  2 10:00:01 WH1-ACC-SW01 812: Nov  2 10:00:01.123 IST: %SYS-5-CONFIG_I: Configured from console by netadmin on vty0 (192.0.2.50)",
     "cisco", "config_change", "config", "low", {"user": "netadmin", "src_ip": "192.0.2.50", "src_name": "WH1-ACC-SW01"}),
    ("<188>Nov  2 10:00:02 WH1-ACC-SW01 813: %SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: admin] [Source: 198.51.100.7] [localport: 22] [Reason: Login Authentication Failed] at 10:00:02 IST",
     "cisco", "login_failed", "logon-fail", "medium", {"user": "admin", "src_ip": "198.51.100.7", "category": "security"}),
    ("<189>814: %OSPF-5-ADJCHG: Process 1, Nbr 10.255.0.2 on Vlan10 from FULL to DOWN, Neighbor Down: Dead timer expired",
     "cisco", "ospf_adjacency", "down", "low", {"dst_ip": "10.255.0.2", "src_intf": "Vlan10"}),
    ("<189>815: %BGP-5-ADJCHANGE: neighbor 203.0.113.1 Down BGP Notification sent", "cisco", "bgp_adjacency", "down", "low", {"dst_ip": "203.0.113.1"}),
    ("<189>816: %BGP-5-ADJCHANGE: neighbor 203.0.113.1 Up", "cisco", "bgp_adjacency", "up", "low", {}),
    ("<190>817: %HSRP-5-STATECHANGE: Vlan10 Grp 1 state Standby -> Active", "cisco", "fhrp_state", "active", "low", {"src_intf": "Vlan10"}),
    ("<186>818: %SPANTREE-2-BLOCK_BPDUGUARD: Received BPDU on port GigabitEthernet1/0/7 with BPDU Guard enabled. Disabling port.",
     "cisco", "bpdu_guard", "block", "high", {"src_intf": "GigabitEthernet1/0/7", "category": "security"}),
    ("<186>819: %PORT_SECURITY-2-PSECURE_VIOLATION: Security violation occurred, caused by MAC address 0011.2233.4455 on port GigabitEthernet1/0/5.",
     "cisco", "port_security", "block", "high", {"src_mac": "00:11:22:33:44:55", "src_intf": "GigabitEthernet1/0/5"}),
    ("<189>820: %DHCP_SNOOPING-5-DHCP_SNOOPING_UNTRUSTED_PORT: DHCP_SNOOPING drop message on untrusted port, message type: DHCPOFFER, MAC sa: 00aa.bbcc.ddee",
     "cisco", "dhcp_snooping", "deny", "low", {"src_mac": "00:aa:bb:cc:dd:ee", "category": "security"}),
    ("<188>821: %SW_DAI-4-DHCP_SNOOPING_DENY: 1 Invalid ARPs (Req) on Gi1/0/3, vlan 10.([0011.2233.4466/192.0.2.99/0000.0000.0000/192.0.2.1/10:00:00 IST])",
     "cisco", "arp_inspection", "deny", "medium", {"src_ip": "192.0.2.99", "src_intf": "Gi1/0/3"}),
    ("<187>822: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/1, changed state to down", "cisco", "link_state", "down", "medium",
     {"src_intf": "GigabitEthernet1/0/1"}),
    ("<189>2026 Nov  2 10:00:03 nx1 %VSHD-5-VSHD_SYSLOG_CONFIG_I: Configured from vty by netops on 192.0.2.60@pts/0", "cisco", "config_change", "config", "low",
     {"user": "netops", "src_ip": "192.0.2.60"}),
    ("<188>Nov  2 10:00:04 C9800-WLC %RRM_UTIL-4-ROGUE_AP_DETECTED: Rogue AP 00:11:22:aa:bb:cc detected on channel 36 with RSSI -45",
     "cisco", "rogue_ap", "detected", "medium", {"category": "security"}),
    ("<14>Nov  2 10:00:05 ICX7150-FC2 Security: running-config was changed from telnet client 192.0.2.70", "ruckus", "config_change", "config", "low",
     {"src_ip": "192.0.2.70"}),
    ("<13>Nov  2 10:00:06 ICX7150-FC2 Security: SSH login failed for user operator from src IP 198.51.100.9 to dst IP 192.0.2.2", "ruckus", "login_failed",
     "logon-fail", "medium", {"user": "operator", "src_ip": "198.51.100.9"}),
    ("<14>Nov  2 10:00:07 ICX7150-FC2 System: Interface ethernet 1/1/12, state down", "ruckus", "link_state", "down", "low", {"src_intf": "1/1/12"}),
    ("<12>Nov  2 10:00:08 ICX7150-FC2 STP: VLAN 1 BPDU guard violation on port 1/1/4, port disabled", "ruckus", "bpdu_guard", "block", "high", {}),
]


@pytest.mark.parametrize("line,vendor,kind,action,sev,fields", CASES)
def test_network_device_messages(line, vendor, kind, action, sev, fields):
    ev = generic.parse(SRC, line)
    assert ev["event_type"] == "netdev" and ev["app"] == vendor
    assert (ev["event_subtype"], ev["action"], ev["severity"]) == (kind, action, sev)
    assert ev["firewall_id"] == generic.SOURCE_ID_BASE + 7 and ev["site"] == "WH1" and ev["raw"]
    for k, v in fields.items():
        assert ev[k] == v, (k, ev[k])


def test_cisco_is_auto_detected_on_plain_syslog_sources_but_ruckus_is_not():
    plain = {**SRC, "kind": "syslog"}
    assert generic.parse(plain, CASES[2][0])["event_type"] == "netdev"
    assert generic.parse(plain, CASES[13][0])["event_type"] == "syslog"     # "Security:" alone is too generic to guess
    assert generic.parse(SRC, "<14>Nov  2 10:00:00 host kernel: something unrelated happened")["event_type"] == "syslog"


def test_config_change_secrets_are_redacted():
    line = ("<189>823: %PARSER-5-CFGLOG_LOGGEDCMD: User:netadmin  logged command:username backup privilege 15 secret 0 Sup3rS3cret! "
            "snmp-server community Publ1cRW RW key-string 7 0822455D0A16")
    ev = generic.parse(SRC, line)
    assert ev["event_subtype"] == "config_change" and ev["user"] == "netadmin"
    for secret in ("Sup3rS3cret!", "Publ1cRW", "0822455D0A16"):
        assert secret not in ev["msg"] and secret not in ev["raw"]
    assert netdev.redact("enable secret 5 $1$abc") == "enable secret 5 ******"


def test_unrecognised_mnemonic_is_kept_as_other_not_dropped():
    ev = generic.parse(SRC, "<190>824: %FOO-6-BAR_BAZ: something new from a future release")
    assert ev["event_type"] == "netdev" and ev["event_subtype"] == "other" and ev["log_id"] == "FOO-6-BAR_BAZ" and ev["severity"] == "informational"
