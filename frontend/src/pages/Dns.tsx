import React, { useState } from "react";
import { useData } from "../lib/context";
import { fmtNum } from "../lib/format";
import { Card, IpLink, Kpi, LimitSelect, Loading, NoData, useDebounced, useExplore } from "../components/ui";
import { Donut, TimeChart, TopBar } from "../components/charts";

function T({ rows, cols, empty }: { rows?: any[]; cols: [string, string, ((r: any) => any)?][]; empty?: React.ReactNode }) {
  if (!rows?.length) return <>{empty ?? <NoData category="dns" what="DNS" />}</>;
  const numeric = (k: string) => rows.every((r) => typeof r[k] === "number");
  return <div className="tbl-wrap max-h-96 overflow-y-auto"><table className="tbl"><thead><tr>{cols.map(([k, l]) => <th key={l} className={numeric(k) ? "num" : ""}>{l}</th>)}</tr></thead>
    <tbody>{rows.map((r, i) => <tr key={i}>{cols.map(([k, l, f]) => <td key={l} className={numeric(k) ? "num" : "font-mono text-xs cell-wrap min-w-[8rem]"}>{f ? f(r) : numeric(k) ? fmtNum(r[k]) : String(r[k] || "—")}</td>)}</tr>)}</tbody></table></div>;
}

export function Dns() {
  const [limit, setLimit] = useState(25);
  const [query, setQuery] = useState("");
  const dq = useDebounced(query);
  const q = useData<any>("/analytics/dns", { limit, dns_query: dq || undefined });
  const ind = useData<any>("/analytics/dns/indicators", { dns_query: dq || undefined });
  const explore = useExplore();
  const d = q.data;
  const t = d?.totals || {};
  return (
    <div className="space-y-4">
      <div className="flex gap-2 items-end">
        <div><label className="label">Query contains</label><input aria-label="Query contains" className="input w-72" placeholder="example.com" value={query} onChange={(e) => setQuery(e.target.value.trim())} /></div>
        <LimitSelect value={limit} onChange={setLimit} />
      </div>
      <p className="text-xs text-muted">Source: FortiGate DNS-filter logs (type=utm subtype=dns) via syslog or the log API. Only queries that pass through a DNS-filter profile are logged; response codes and resolved IPs appear only when FortiGate logs them.</p>
      <Loading q={q} />
      <div className="kpi-grid">
        <Kpi label="DNS queries" value={fmtNum(t.queries)} />
        <Kpi label="Unique domains" value={fmtNum(t.domains)} />
        <Kpi label="Clients" value={fmtNum(t.clients)} />
        <Kpi label="NXDOMAIN" value={fmtNum(t.nxdomain)} tone={t.nxdomain ? "warn" : undefined} onClick={() => explore({ category: "dns", dns_rcode: "NXDOMAIN" })} />
        <Kpi label="Blocked" value={fmtNum(t.blocked)} tone={t.blocked ? "bad" : undefined} onClick={() => explore({ category: "dns", verdict: "denied" })} />
        <Kpi label="With response code" value={fmtNum(t.with_rcode)} sub="records where rcode was logged" />
      </div>
      <div className="grid-cards lg:grid-cols-2 2xl:grid-cols-3">
        <Card title="DNS query volume / NXDOMAIN / blocked" className="lg:col-span-2"><TimeChart data={d?.timeseries} loading={q.isLoading} series={[{ key: "events", name: "Queries", color: "primary" }, { key: "nxdomain", name: "NXDOMAIN", color: "warn", dashed: true }, { key: "blocked", name: "Blocked", color: "alert" }]} /></Card>
        <Card title="Query types">{d?.top_qtypes?.length ? <Donut rows={d.top_qtypes} label="Query type" onClick={(k) => explore({ category: "dns", dns_qtype: k })} /> : <NoData category="dns" what="DNS" />}</Card>
        <Card title="Top queried domains">{d?.top_domains?.length ? <TopBar rows={d.top_domains} valueField="events" height={320} onClick={(k) => explore({ category: "dns", dns_query: k })} /> : <NoData category="dns" what="DNS" />}</Card>
        <Card title="Top DNS clients"><T rows={d?.top_clients} cols={[["key", "Client", (r) => <IpLink ip={r.key} />], ["events", "Queries"], ["domains", "Domains"], ["nxdomain", "NXDOMAIN"]]} /></Card>
        <Card title="Top DNS servers"><T rows={d?.top_servers} cols={[["key", "Server"], ["events", "Queries"], ["clients", "Clients"]]} /></Card>
      </div>
      <Card title="Blocked DNS queries"><T empty={<NoData category="dns" what="blocked DNS" />} rows={d?.blocked} cols={[["key", "Domain"], ["url_cat", "Category"], ["events", "Events"], ["clients", "Clients"]]} /></Card>
      <div className="card p-3 border-amber-700/50 bg-amber-500/5 text-xs text-amber-200">Indicators below are heuristics that require investigation — they are not proof of malicious activity.</div>
      <div className="grid-cards lg:grid-cols-2 2xl:grid-cols-3">
        <Card title="Potential tunneling / high-entropy subdomains"><T empty={<div className="text-sm text-muted p-4 text-center">No indicators for the selected range.</div>} rows={ind.data?.tunneling_indicators} cols={[["src_ip", "Client", (r) => <IpLink ip={r.src_ip} />], ["domain", "Domain"], ["unique_names", "Unique names"], ["max_len", "Max len"], ["avg_entropy", "Entropy"]]} /></Card>
        <Card title="Unusual query volume (z-score across clients)"><T empty={<div className="text-sm text-muted p-4 text-center">No indicators for the selected range.</div>} rows={ind.data?.unusual_volume} cols={[["src_ip", "Client", (r) => <IpLink ip={r.src_ip} />], ["events", "Queries"], ["mean", "Mean"], ["zscore", "z"]]} /></Card>
        <Card title="Repeated queries (≥100 same client+name)"><T empty={<div className="text-sm text-muted p-4 text-center">No indicators for the selected range.</div>} rows={ind.data?.repeated_queries} cols={[["src_ip", "Client", (r) => <IpLink ip={r.src_ip} />], ["dns_qname", "Name"], ["events", "Count"]]} /></Card>
      </div>
    </div>
  );
}
