"""Built-in content: hunting-query library (MITRE ATT&CK tagged) and workbook templates."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .db.models import HuntingQuery, Workbook

ALLOWED = '("accept", "close", "timeout", "allow", "monitor")'

HUNTS = [
    {"key": "uncommon_ports_external", "name": "Hosts reaching many external IPs on uncommon ports", "tactic": "TA0011", "techniques": ["T1571"],
     "description": "Allowed outbound traffic to non-standard ports spread over many destinations (C2 or tunnelling tools).",
     "query": f'category:traffic | where action IN {ALLOWED} AND NOT isprivate(dst_ip) AND dst_port NOT IN (80, 443, 53, 123) '
              '| stats dc(dst_ip) as dsts, dc(dst_port) as ports, sum(sent_bytes) as sent by src_ip | where dsts > 20 | sort -dsts | head 50'},
    {"key": "large_uploads", "name": "Large uploads to external destinations", "tactic": "TA0010", "techniques": ["T1048", "T1567"],
     "description": "Internal hosts that sent more than 1 GB to the internet.",
     "query": "category:traffic | where isprivate(src_ip) AND NOT isprivate(dst_ip) | stats sum(sent_bytes) as sent, dc(dst_ip) as dsts, "
              "values(dst_country) as countries by src_ip | where sent > 1000000000 | sort -sent | head 50"},
    {"key": "dns_long_names", "name": "Long / high-entropy DNS names (tunnelling)", "tactic": "TA0011", "techniques": ["T1071.004"],
     "description": "Many unique long sub-domains under one registered domain from one client.",
     "query": "category:dns | where dns_qname_len > 50 | eval d = domain(dns_qname) | stats count, dc(dns_qname) as names, "
              "max(dns_entropy) as entropy by src_ip, d | where names > 10 | sort -names | head 50"},
    {"key": "nxdomain_clients", "name": "Clients with many NXDOMAIN answers (DGA)", "tactic": "TA0011", "techniques": ["T1568.002"],
     "description": "Domain-generation algorithms produce bursts of non-existent domains.",
     "query": "category:dns rcode:NXDOMAIN | stats count, dc(dns_qname) as names by src_ip | where count > 100 | sort -count | head 50"},
    {"key": "remote_services_from_internet", "name": "Remote-access ports reached from the internet", "tactic": "TA0001", "techniques": ["T1133"],
     "description": "SSH, RDP, SMB and WinRM sessions whose source is a public address.",
     "query": f'category:traffic | where NOT isprivate(src_ip) AND dst_port IN (22, 3389, 445, 5985, 5986) | stats count, '
              f'countif(action IN {ALLOWED}) as allowed, dc(src_ip) as sources, values(src_country) as countries by dst_ip, dst_port | sort -allowed'},
    {"key": "lateral_movement_ports", "name": "Internal host fan-out on admin ports", "tactic": "TA0008", "techniques": ["T1021"],
     "description": "One internal source touching many internal hosts over SMB/RPC/RDP/WinRM/SSH.",
     "query": "category:traffic | where isprivate(src_ip) AND isprivate(dst_ip) AND dst_port IN (445, 135, 3389, 5985, 22) "
              "| stats dc(dst_ip) as targets, count by src_ip, dst_port | where targets > 10 | sort -targets | head 50"},
    {"key": "denied_outbound_fanout", "name": "Denied outbound to many destinations", "tactic": "TA0011", "techniques": ["T1071"],
     "description": "Malware retrying blocked infrastructure shows as denials towards many external IPs.",
     "query": "category:traffic action:deny | where isprivate(src_ip) AND NOT isprivate(dst_ip) | stats count, dc(dst_ip) as dsts, "
              "values(dst_port) as ports by src_ip | where dsts > 25 | sort -dsts | head 50"},
    {"key": "ti_matches", "name": "Threat-intelligence indicator hits", "tactic": "TA0011", "techniques": ["T1071"],
     "description": "Every event that matched an enabled feed or the manual IOC list, grouped by host and category.",
     "query": "ti:* | stats count, values(ti_source) as feeds, values(dst_ip) as dsts, latest(action) as last_action by src_ip, ti_category | sort -count"},
    {"key": "rare_countries", "name": "Least common destination countries", "tactic": "TA0011", "techniques": ["T1071"],
     "description": "Countries contacted only a few times are worth a look.",
     "query": 'category:traffic | where dst_country != "" | rare dst_country limit=15'},
    {"key": "long_connections", "name": "Long-lived external connections", "tactic": "TA0011", "techniques": ["T1071", "T1573"],
     "description": "Sessions longer than an hour to public addresses (persistent C2 channels, unmanaged tunnels).",
     "query": "category:traffic | where duration > 3600 AND NOT isprivate(dst_ip) | stats count, max(duration) as longest, "
              "sum(sent_bytes + rcvd_bytes) as bytes by src_ip, dst_ip, dst_port | sort -longest | head 50"},
    {"key": "vpn_multi_country", "name": "VPN users connecting from several countries", "tactic": "TA0001", "techniques": ["T1078"],
     "description": "Credential sharing or compromised accounts appear as one user from multiple countries.",
     "query": 'category:system | where vpn_tunnel != "" AND user != "" AND src_country != "" | stats dc(src_country) as countries, '
              'values(src_country) as seen_in, count by user | where countries > 1 | sort -countries'},
    {"key": "blocked_web_categories", "name": "Blocked web categories by host", "tactic": "TA0001", "techniques": ["T1189"],
     "description": "Hosts repeatedly hitting blocked categories (malware, phishing, newly registered domains).",
     "query": "category:web | where action IN (\"block\", \"deny\", \"blocked\") | stats count, values(hostname) as sites by src_ip, url_category "
              "| sort -count | head 50"},
    {"key": "rare_apps", "name": "Rarely seen applications", "tactic": "TA0011", "techniques": ["T1219"],
     "description": "Remote-access and tunnelling tools often show up as rare application signatures.",
     "query": 'category:traffic | where app != "" | rare app limit=20'},
    {"key": "admin_logins", "name": "Firewall administrator logins", "tactic": "TA0006", "techniques": ["T1078.003"],
     "description": "Who logged in to the firewalls, from where, and whether it failed.",
     "query": 'category:system | where contains(msg, "login") AND contains(msg, "admin") | stats count, values(user) as users, '
              'values(src_ip) as sources by firewall_name, action | sort -count'},
]

WORKBOOKS = [
    {"key": "soc_overview", "name": "SOC overview", "description": "Volume, verdicts, threats and top offenders at a glance.", "range": "24h",
     "panels": [
         {"id": "k1", "title": "Events", "query": "| stats count as events", "viz": "kpi", "width": 3},
         {"id": "k2", "title": "Denied", "query": "action:deny | stats count as denied", "viz": "kpi", "width": 3},
         {"id": "k3", "title": "Distinct sources", "query": "| stats dc(src_ip) as sources", "viz": "kpi", "width": 3},
         {"id": "k4", "title": "Threat-intel hits", "query": "ti:* | stats count as hits", "viz": "kpi", "width": 3},
         {"id": "p1", "title": "Traffic by verdict", "query": "category:traffic | timechart count by action", "viz": "line", "width": 8},
         {"id": "p2", "title": "Events by category", "query": "| stats count by category | sort -count", "viz": "pie", "width": 4},
         {"id": "p3", "title": "Top denied sources", "query": "action:deny | stats count, dc(dst_ip) as dsts, dc(dst_port) as ports by src_ip | sort -count | head 10", "viz": "table", "width": 6},
         {"id": "p4", "title": "Top destination countries", "query": 'category:traffic | where dst_country != "" | top 10 dst_country', "viz": "bar", "width": 6},
     ]},
    {"key": "network_traffic", "name": "Network traffic", "description": "Bandwidth, talkers, applications and ports.", "range": "24h",
     "panels": [
         {"id": "n1", "title": "Bytes sent / received", "query": "category:traffic | timechart sum(sent_bytes) as sent, sum(rcvd_bytes) as received", "viz": "area", "width": 12},
         {"id": "n2", "title": "Top talkers", "query": "category:traffic | stats sum(sent_bytes) as sent, sum(rcvd_bytes) as received, dc(dst_ip) as dsts by src_ip | sort -sent | head 15", "viz": "table", "width": 6},
         {"id": "n3", "title": "Top applications", "query": 'category:traffic | where app != "" | top 10 app', "viz": "bar", "width": 6},
         {"id": "n4", "title": "Top destination ports", "query": "category:traffic | top 10 dst_port", "viz": "bar", "width": 6},
         {"id": "n5", "title": "Events per firewall", "query": "| stats count by firewall_name | sort -count", "viz": "pie", "width": 6},
     ]},
    {"key": "dns_web", "name": "DNS & web", "description": "Resolution health, top domains and web filtering.", "range": "24h",
     "panels": [
         {"id": "d1", "title": "DNS answers by response code", "query": "category:dns | timechart count by rcode", "viz": "line", "width": 8},
         {"id": "d2", "title": "NXDOMAIN share", "query": 'category:dns | stats countif(dns_rcode = "NXDOMAIN") as nx, count | eval pct = round(100 * nx / count, 2) | fields pct', "viz": "kpi", "width": 4},
         {"id": "d3", "title": "Top registered domains", "query": "category:dns | eval d = domain(dns_qname) | top 15 d", "viz": "bar", "width": 6},
         {"id": "d4", "title": "Top web categories", "query": 'category:web | where url_category != "" | top 10 url_category', "viz": "bar", "width": 6},
         {"id": "d5", "title": "Blocked sites", "query": 'category:web | where action IN ("block", "deny", "blocked") | stats count by hostname, url_category | sort -count | head 20', "viz": "table", "width": 12},
     ]},
]


async def ensure_content(s: AsyncSession) -> None:
    """Insert missing built-in hunts and workbook templates; refresh built-in hunt definitions (not user copies)."""
    hunts = {h.key: h for h in (await s.execute(select(HuntingQuery).where(HuntingQuery.key.is_not(None)))).scalars()}
    for h in HUNTS:
        cur = hunts.get(h["key"])
        if cur is None:
            s.add(HuntingQuery(**h, builtin=True, author="system"))
        elif cur.builtin:
            cur.name, cur.description, cur.query, cur.tactic, cur.techniques = h["name"], h["description"], h["query"], h["tactic"], h["techniques"]
    books = {w.key for w in (await s.execute(select(Workbook).where(Workbook.key.is_not(None)))).scalars()}
    for w in WORKBOOKS:
        if w["key"] not in books:
            s.add(Workbook(**w, owner="system", shared=True))
    await s.commit()
