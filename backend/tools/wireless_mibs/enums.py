"""Build enums.json (INDEX clauses and INTEGER enumerations) for the objects gen_registry.py selects.

    python3 -I enums.py mibs enums.json
"""
import json
import os
import re
import sys

NAMES = ["bsnAPIfType", "bsnAPOperationStatus", "bsnAPIfOperStatus", "bsnAPIfAdminStatus", "bsnAPAdminStatus", "bsnMobileStationStatus",
         "bsnMobileStationProtocol", "bsnMobileStationReasonCode", "bsnDot11EssAdminStatus", "bsnDot11EssSecurityAuthType", "cLApLastRebootReason",
         "cLAp11ChannelBandwidth", "cldcClientAuthMode", "cldcClientReasonCode", "cLApPowerStatus",
         "bsnAPIfPhyChannelAssignment", "bsnAPIfPhyTxPowerControl", "bsnAPIfRegulatoryDomainSupport", "bsnAPIfRxNeighborChannelWidth",
         "cLApDot11XorRadioBand"]
ENTRIES = ["bsnAPEntry", "bsnAPIfEntry", "bsnAPIfLoadParametersEntry", "bsnAPIfDot11CountersEntry", "bsnAPIfInterferenceEntry", "bsnAPIfNoiseEntry",
           "bsnMobileStationEntry", "bsnMobileStationStatsEntry", "bsnDot11EssEntry", "cLApEntry", "cLApDot11IfEntry", "cLApRadioWlanInfoEntry",
           "bsnAPIfDot11PhyTxPowerEntry", "bsnAPIfSmtParamEntry", "bsnAPIfRecommendedRFParametersEntry", "bsnAPIfRadarChannelStatisticsEntry",
           "bsnAPIfRxNeighborsEntry", "cLApDot11RadioEntry"]
text = "\n".join(open(os.path.join(sys.argv[1], f), errors="replace").read() for f in sorted(os.listdir(sys.argv[1])) if f.endswith(".my"))


def body(name):
    m = re.search(rf"^{name}\s+OBJECT-TYPE(.*?)::=", text, re.S | re.M)
    return m.group(1) if m else ""


out = {"index": {}, "enums": {}}
for e in ENTRIES:
    m = re.search(r"INDEX\s*\{([^}]*)\}", body(e))
    out["index"][e] = [x.strip() for x in m.group(1).split(",")] if m else []
for n in NAMES:
    m = re.search(r"SYNTAX\s+INTEGER\s*\{([^}]*)\}", body(n))
    assert m, n
    out["enums"][n] = {v: k for k, v in re.findall(r"([A-Za-z][\w-]*)\s*\(\s*(-?\d+)\s*\)", m.group(1))}
json.dump(out, open(sys.argv[2], "w"), indent=1)
print(len(out["enums"]), "enums,", len(out["index"]), "indexes")
