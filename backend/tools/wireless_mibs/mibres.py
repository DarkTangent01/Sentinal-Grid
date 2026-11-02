"""Resolve OBJECT-TYPE names to numeric OIDs from SMIv2 MIB text files (offline, read-only)."""
import json, re, sys, glob, os
ROOTS = {"iso": "1", "org": "1.3", "dod": "1.3.6", "internet": "1.3.6.1", "mgmt": "1.3.6.1.2", "mib-2": "1.3.6.1.2.1",
         "private": "1.3.6.1.4", "enterprises": "1.3.6.1.4.1", "snmpV2": "1.3.6.1.6", "snmpModules": "1.3.6.1.6.3"}
defs, meta = {}, {}
pat = re.compile(r"^\s*([a-zA-Z][\w-]*)\s+(OBJECT-TYPE|OBJECT IDENTIFIER|MODULE-IDENTITY|OBJECT-IDENTITY|NOTIFICATION-TYPE|OBJECT-GROUP|NOTIFICATION-GROUP|MODULE-COMPLIANCE)\b(?!\s*,)(.*?)::=\s*\{\s*([\w-]+)\s+(\d+)\s*\}", re.S | re.M)
for f in glob.glob(os.path.join(sys.argv[1], "*.my")):
    txt = open(f, encoding="latin-1").read()
    txt = re.sub(r"--[^\n]*", "", txt)
    for m in pat.finditer(txt):
        name, kind, body, parent, n = m.groups()
        defs[name] = (parent, n)
        if kind == "OBJECT-TYPE":
            g = lambda k: (re.search(k + r"\s+(.+?)\n", body) or [None, ""])[1].strip()
            meta[name] = {"mib": os.path.basename(f)[:-3], "syntax": g("SYNTAX"), "units": g("UNITS").strip('"'), "access": g("MAX-ACCESS"),
                          "index": (re.search(r"INDEX\s*\{([^}]*)\}", body) or [None, ""])[1].split(",") if "INDEX" in body else []}
            meta[name]["index"] = [x.strip() for x in meta[name]["index"] if x.strip()]
def res(n, depth=0):
    if n in ROOTS: return ROOTS[n]
    if n not in defs or depth > 60: return None
    p, i = defs[n]; b = res(p, depth + 1)
    return f"{b}.{i}" if b else None
out = {n: {"oid": res(n), **meta[n]} for n in meta}
json.dump(out, open(sys.argv[2], "w"), indent=0)
print(len(out), "objects;", sum(1 for v in out.values() if v["oid"]), "resolved")
