import { api, Params } from "./api";
import type { PipelineResult } from "../components/ResultView";

/** Body for POST /api/search from the global filter params (range or custom start/end, firewall). */
export function searchBody(params: Params, query: string, range?: string | null, maxRows?: number) {
  const b: Record<string, unknown> = { query };
  if (range) b.range = range;
  else if (params.start && params.end) { b.start = params.start; b.end = params.end; b.range = null; }
  else b.range = params.range || "24h";
  if (Array.isArray(params.firewall_id) && params.firewall_id.length) b.firewall_id = params.firewall_id.map(Number);
  if (maxRows) b.max_rows = maxRows;
  return b;
}

export const runSearch = (body: Record<string, unknown>) => api<PipelineResult>("/search", { method: "POST", body });

function csrf(): string {
  const m = document.cookie.match(/(?:^|; )siem_csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : "";
}

/** POST-based CSV export (the query can be long, so it is not put in a URL). */
export async function exportSearchCsv(body: Record<string, unknown>, filename = "search.csv") {
  const res = await fetch("/api/search/export.csv", {
    method: "POST", credentials: "same-origin", body: JSON.stringify(body),
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() },
  });
  if (!res.ok) {
    let msg = res.statusText;
    try { msg = (await res.json()).detail; } catch { /* ignore */ }
    throw new Error(msg);
  }
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export const PIPE_EXAMPLES: [string, string][] = [
  ["Top denied sources", "action:deny | stats count, dc(dst_ip) as dsts, dc(dst_port) as ports by src_ip | sort -count | head 20"],
  ["Traffic by verdict over time", "category:traffic | timechart count by action"],
  ["Bandwidth per host", "category:traffic | stats sum(sent_bytes) as sent, sum(rcvd_bytes) as received by src_ip | sort -sent | head 20"],
  ["Top destination ports", "category:traffic | top 15 dst_port"],
  ["Internal → external RDP/SSH", "category:traffic | where isprivate(src_ip) AND NOT isprivate(dst_ip) AND dst_port IN (22, 3389) | stats count by src_ip, dst_ip, dst_port"],
  ["DNS: top registered domains", "category:dns | eval d = domain(dns_qname) | top 20 d"],
  ["Long DNS names", "category:dns | where dns_qname_len > 50 | stats dc(dns_qname) as names by src_ip | sort -names"],
  ["Watchlist hits", "| lookup <watchlist> src_ip | where <watchlist>_match = 1 | stats count by src_ip, <watchlist>_label"],
  ["Bucketed severity", '| eval sev = case(severity = "critical", 4, severity = "high", 3, true, 1) | stats count by sev'],
];

export const PIPE_HELP: [string, string][] = [
  ["filter | …", "Start with the query language (src_ip:10.0.0.0/8 action:deny port:22 …); leave empty for all events."],
  ["where <expr>", "Keep rows: =, !=, <, >, IN (…), LIKE \"*x*\", AND/OR/NOT, functions."],
  ["eval x = <expr>", "Computed column. Comma-separate several."],
  ["stats <agg> [as n], … by f, …", "count, count(f), dc, sum, avg, min, max, median, p50…p99, values, list, earliest, latest, range, stdev, countif(cond), sumif(f, cond)."],
  ["timechart [span=5m] [limit=10] <agg> [by f]", "Time series; one series per value of f (top N + OTHER)."],
  ["top [N] f / rare f", "Most / least common values with count and percent."],
  ["sort -f, f   head N   dedup f", "Order (– = descending), limit rows, keep the first row per value."],
  ["fields f, …   fields - f   rename a as b", "Choose, drop or rename columns."],
  ["lookup <watchlist> <field>", "Adds <watchlist>_match (0/1) and <watchlist>_label. In expressions: inwatchlist(f, \"name\")."],
  ["Functions", "lower, upper, len, round, if, case, coalesce, isnull, concat, substr, contains, startswith, endswith, match (regex), cidrmatch(\"cidr\", ip), isprivate(ip), domain(host), tonumber, tostring, hour, dayofweek, strftime, now."],
];
