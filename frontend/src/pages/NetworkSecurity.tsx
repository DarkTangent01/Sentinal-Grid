/** Sentinel Grid → Network Security Analytics (Zeek). Observations with the numbers behind them, not verdicts: each list says
 *  why an item is there. A connection uid opens every Zeek log of that connection next to the firewall's own entries. */
import { useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { fmtBytes, fmtNum } from "../lib/format";
import { useTheme } from "../lib/theme";
import { Chart, PALETTES, axisStyle } from "../components/Chart";
import { Card, Drawer, Empty, IpLink, Kpi, Loading, TableWrap, Tabs, Time, Trunc } from "../components/ui";

const TABS = [{ key: "overview", label: "Overview" }, { key: "scans", label: "Scanning" }, { key: "beacons", label: "Beaconing" }, { key: "dns", label: "DNS" },
  { key: "tls", label: "TLS / certificates" }, { key: "ports", label: "Unusual ports" }];

export function NetworkSecurity() {
  const [sp, setSp] = useSearchParams();
  const tab = TABS.some((t) => t.key === sp.get("tab")) ? sp.get("tab")! : "overview";
  const range = ["1h", "24h", "7d"].includes(sp.get("range") || "") ? sp.get("range")! : "24h";
  const uid = sp.get("uid");
  const set = (p: Record<string, string | null>) => { const n = new URLSearchParams(sp); for (const [k, v] of Object.entries(p)) v ? n.set(k, v) : n.delete(k); setSp(n); };
  return <div className="space-y-4 min-w-0">
    <p className="text-xs text-muted">Built from the Zeek sensor's logs (log sources of kind "zeek"). A sensor sees traffic the firewalls may not (east-west), and the firewalls
      see verdicts the sensor does not: open a connection to compare both. Nothing here is a verdict on its own; each result says why it is listed.</p>
    <div className="flex flex-wrap items-center gap-2">
      <select aria-label="Time range" className="input py-1" value={range} onChange={(e) => set({ range: e.target.value })}><option value="1h">Last hour</option><option value="24h">Last 24 h</option><option value="7d">Last 7 days</option></select>
      <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); const v = (new FormData(e.currentTarget).get("uid") as string || "").trim(); if (v) set({ uid: v }); }}>
        <input name="uid" aria-label="Connection uid" className="input py-1 w-56 font-mono" placeholder="Zeek connection uid (C…)" /><button type="submit" className="btn py-1">Open</button></form>
    </div>
    <Tabs value={tab} onChange={(t) => set({ tab: t })} tabs={TABS} />
    {tab === "overview" && <Overview range={range} />}
    {tab === "scans" && <Scans range={range} />}
    {tab === "beacons" && <Beacons range={range} />}
    {tab === "dns" && <Dns range={range} />}
    {tab === "tls" && <Tls range={range} />}
    {tab === "ports" && <Ports range={range} />}
    {uid && <Connection uid={uid} onClose={() => set({ uid: null })} />}
  </div>;
}

function Overview({ range }: { range: string }) {
  const { theme } = useTheme();
  const q = useQuery({ queryKey: ["ns-ov", range], queryFn: () => api<any>("/network-security/overview", { params: { range } }) });
  const d = q.data;
  const opt = useMemo(() => {
    if (!d) return null;
    const logs = Array.from(new Set(d.timeline.map((x: any) => x.log))) as string[];
    return { legend: { top: 0 }, tooltip: { trigger: "axis", confine: true }, xAxis: { type: "time", ...axisStyle }, yAxis: { type: "value", minInterval: 1, ...axisStyle },
      series: logs.map((l, i) => ({ name: l, type: "bar", stack: "a", barMaxWidth: 16, itemStyle: { color: PALETTES[theme][i % 8] },
        data: d.timeline.filter((x: any) => x.log === l).map((x: any) => [Date.parse(x.t), x.n]) })) };
  }, [d, theme]);
  if (!d) return <Loading q={q} />;
  if (!d.has_data) return <Card><Empty text="No Zeek logs in this range. Register the sensor as a log source of kind &quot;zeek&quot; (Log Sources) and send its JSON logs by syslog or HTTP ingestion." /></Card>;
  const c = d.connections;
  return <>
    <div className="kpi-grid">
      <Kpi label="Connections" value={fmtNum(c.conns)} sub={`${fmtNum(c.sources)} sources → ${fmtNum(c.destinations)} destinations`} />
      <Kpi label="Unanswered / refused" value={fmtNum(c.failed)} sub={c.conns ? `${Math.round((100 * c.failed) / c.conns)}% of connections` : undefined} />
      <Kpi label="Volume" value={fmtBytes(c.sent + c.rcvd)} sub={`${fmtBytes(c.sent)} out · ${fmtBytes(c.rcvd)} in`} />
      <Kpi label="Zeek notices" value={fmtNum(d.notices.reduce((a: number, n: any) => a + n.count, 0))} />
      <Kpi label="Sensors" value={d.sensors.length} sub={d.sensors.map((s: any) => s.sensor).join(", ")} />
    </div>
    <Card title="Logs over time">{opt && <Chart height={220} option={opt} ariaLabel="Zeek logs over time by type" />}</Card>
    <div className="grid-cards xl:grid-cols-3">
      <Card title="Logs" bodyClass="p-0"><TableWrap><table className="tbl"><thead><tr><th>Log</th><th className="num">Events</th><th>Last</th></tr></thead>
        <tbody>{d.logs.map((l: any) => <tr key={l.log}><td>{l.log}.log</td><td className="num">{fmtNum(l.events)}</td><td><Time v={l.last} /></td></tr>)}</tbody></table></TableWrap></Card>
      <Card title="Connection states" bodyClass="p-0"><TableWrap><table className="tbl"><thead><tr><th>State</th><th className="num">Connections</th></tr></thead>
        <tbody>{d.states.map((s: any) => <tr key={s.state}><td className="font-mono text-xs">{s.state}</td><td className="num">{fmtNum(s.count)}</td></tr>)}</tbody></table></TableWrap>
        <p className="text-2xs text-muted p-3">SF normal close · S0 no reply · REJ refused · RSTO/RSTR reset · SH half-open (Zeek conn_state).</p></Card>
      <Card title="Services (by protocol detection)" bodyClass="p-0"><TableWrap><table className="tbl"><thead><tr><th>Service</th><th className="num">Connections</th><th className="num">Bytes</th></tr></thead>
        <tbody>{d.services.map((s: any) => <tr key={s.service}><td>{s.service}</td><td className="num">{fmtNum(s.count)}</td><td className="num">{fmtBytes(s.bytes)}</td></tr>)}</tbody></table></TableWrap></Card>
    </div>
    <div className="grid-cards xl:grid-cols-2">
      <Card title="Zeek notices" bodyClass="p-0">{!d.notices.length ? <Empty text="No notices." /> : <TableWrap><table className="tbl"><thead><tr><th>Notice</th><th className="num">Count</th><th className="num">Sources</th><th>Sample</th></tr></thead>
        <tbody>{d.notices.map((n: any) => <tr key={n.note}><td className="font-mono text-xs nowrap">{n.note}</td><td className="num">{n.count}</td><td className="num">{n.sources}</td><td><Trunc text={n.sample} /></td></tr>)}</tbody></table></TableWrap>}</Card>
      <Card title="Protocol anomalies (weird.log)" bodyClass="p-0">{!d.weird.length ? <Empty text="No protocol anomalies." /> : <TableWrap><table className="tbl"><thead><tr><th>Anomaly</th><th className="num">Count</th><th className="num">Sources</th></tr></thead>
        <tbody>{d.weird.map((w: any) => <tr key={w.name}><td className="font-mono text-xs">{w.name}</td><td className="num">{w.count}</td><td className="num">{w.sources}</td></tr>)}</tbody></table></TableWrap>}</Card>
    </div>
  </>;
}

function Scans({ range }: { range: string }) {
  const q = useQuery({ queryKey: ["ns-scan", range], queryFn: () => api<any>("/network-security/scanners", { params: { range } }) });
  return <Card title="Sources whose connections mostly failed across many ports or hosts" bodyClass="p-0"><Loading q={q} />
    {q.data && (!q.data.items.length ? <Empty text="No scanning pattern in this range." /> : <TableWrap><table className="tbl">
      <thead><tr><th>Source</th><th>Pattern</th><th className="num">Ports</th><th className="num">Hosts</th><th className="num">Failed / attempts</th><th>Why</th><th>Last</th></tr></thead>
      <tbody>{q.data.items.map((r: any) => <tr key={r.src_ip}><td><IpLink ip={r.src_ip} /><div className="text-2xs text-muted">{r.internal ? "internal" : "external"}</div></td><td>{r.kind}</td>
        <td className="num">{r.ports}</td><td className="num">{r.hosts}</td><td className="num">{fmtNum(r.failed)} / {fmtNum(r.attempts)}</td><td className="cell-wrap text-xs min-w-[14rem]">{r.why}</td><td><Time v={r.last} /></td></tr>)}</tbody></table></TableWrap>)}</Card>;
}

function Beacons({ range }: { range: string }) {
  const q = useQuery({ queryKey: ["ns-beacon", range], queryFn: () => api<any>("/network-security/beacons", { params: { range } }) });
  return <Card title="Internal → internet pairs connecting at regular intervals" bodyClass="p-0"><Loading q={q} />
    {q.data && (!q.data.items.length ? <Empty text="No regular connection pattern in this range (at least 12 connections with timing variation under 35%)." /> : <TableWrap><table className="tbl">
      <thead><tr><th>Host</th><th>Destination</th><th className="num">Score</th><th className="num">Every</th><th className="num">Timing variation</th><th className="num">Connections</th><th className="num">Sent</th><th>Why</th></tr></thead>
      <tbody>{q.data.items.map((r: any) => <tr key={`${r.src_ip}${r.dst_ip}${r.dst_port}`}><td><IpLink ip={r.src_ip} /></td><td><IpLink ip={r.dst_ip} /><span className="text-2xs text-muted">:{r.dst_port} {r.service}</span></td>
        <td className="num font-semibold">{r.score}</td><td className="num">{Math.round(r.interval_s)} s</td><td className="num">{Math.round(r.interval_cv * 100)}%</td><td className="num">{r.connections}</td>
        <td className="num">{fmtBytes(r.sent)}</td><td className="cell-wrap text-xs min-w-[14rem]">{r.why}</td></tr>)}</tbody></table></TableWrap>)}
    <p className="text-2xs text-muted p-3">Score 0-100: regular timing (60), similar sizes (25), persistence over the range (15). Software updaters, telemetry and monitoring agents also beacon: check the destination's owner first.</p></Card>;
}

function Dns({ range }: { range: string }) {
  const q = useQuery({ queryKey: ["ns-dns", range], queryFn: () => api<any>("/network-security/dns", { params: { range } }) });
  const d = q.data;
  if (!d) return <Loading q={q} />;
  return <div className="grid-cards xl:grid-cols-2">
    <Card title="Domains resolved by one host only" bodyClass="p-0">{!d.rare_domains.length ? <Empty text="None in this range." /> : <TableWrap maxH="max-h-96"><table className="tbl">
      <thead><tr><th>Domain</th><th>Host</th><th className="num">Queries</th><th>First</th></tr></thead>
      <tbody>{d.rare_domains.map((r: any) => <tr key={r.domain}><td className="font-mono text-xs"><Trunc text={r.domain} /><div className="text-2xs text-muted">{r.sample}</div></td><td><IpLink ip={r.client} /></td>
        <td className="num">{r.queries}</td><td><Time v={r.first} /></td></tr>)}</tbody></table></TableWrap>}</Card>
    <Card title="Hosts with many failed lookups (NXDOMAIN)" bodyClass="p-0">{!d.nxdomain.length ? <Empty text="None in this range." /> : <TableWrap><table className="tbl">
      <thead><tr><th>Host</th><th className="num">NXDOMAIN</th><th className="num">Names</th><th>Why</th></tr></thead>
      <tbody>{d.nxdomain.map((r: any) => <tr key={r.src_ip}><td><IpLink ip={r.src_ip} /></td><td className="num">{r.nxdomain}</td><td className="num">{r.names}</td><td className="text-xs">{r.why}</td></tr>)}</tbody></table></TableWrap>}</Card>
    <Card title="Long query names (possible data in DNS)" bodyClass="p-0">{!d.long_queries.length ? <Empty text="None in this range." /> : <TableWrap><table className="tbl">
      <thead><tr><th>Host</th><th>Domain</th><th className="num">Queries</th><th className="num">Longest</th><th className="num">Entropy</th></tr></thead>
      <tbody>{d.long_queries.map((r: any) => <tr key={`${r.src_ip}${r.domain}`}><td><IpLink ip={r.src_ip} /></td><td className="font-mono text-xs">{r.domain}</td><td className="num">{r.count}</td>
        <td className="num">{r.longest}</td><td className="num">{r.entropy}</td></tr>)}</tbody></table></TableWrap>}</Card>
    <Card title="Most queried names" bodyClass="p-0"><TableWrap maxH="max-h-96"><table className="tbl"><thead><tr><th>Name</th><th className="num">Queries</th><th className="num">Clients</th></tr></thead>
      <tbody>{d.top.map((r: any) => <tr key={r.name}><td className="font-mono text-xs"><Trunc text={r.name} /></td><td className="num">{fmtNum(r.count)}</td><td className="num">{r.clients}</td></tr>)}</tbody></table></TableWrap></Card>
  </div>;
}

function Tls({ range }: { range: string }) {
  const q = useQuery({ queryKey: ["ns-tls", range], queryFn: () => api<any>("/network-security/tls", { params: { range } }) });
  const d = q.data;
  if (!d) return <Loading q={q} />;
  return <div className="grid-cards xl:grid-cols-2">
    <Card title="TLS sessions whose certificate did not validate" bodyClass="p-0">{!d.invalid.length ? <Empty text="None in this range." /> : <TableWrap><table className="tbl">
      <thead><tr><th>Server name</th><th>Address</th><th>Problem</th><th className="num">Sessions</th><th className="num">Clients</th></tr></thead>
      <tbody>{d.invalid.map((r: any) => <tr key={`${r.server_name}${r.dst_ip}${r.problem}`}><td className="font-mono text-xs">{r.server_name || "(none)"}</td><td><IpLink ip={r.dst_ip} /></td>
        <td className="cell-wrap text-xs">{r.problem}</td><td className="num">{r.count}</td><td className="num">{r.clients}</td></tr>)}</tbody></table></TableWrap>}
      <p className="text-2xs text-muted p-3">Internal certificate authorities Zeek does not trust also show here.</p></Card>
    <Card title="Self-signed or expired certificates" bodyClass="p-0">{!d.certificates.length ? <Empty text="None in this range." /> : <TableWrap><table className="tbl">
      <thead><tr><th>Problem</th><th>Name</th><th>Detail</th><th>Last</th></tr></thead>
      <tbody>{d.certificates.map((r: any) => <tr key={`${r.fingerprint}${r.problem}`}><td className="text-xs">{r.problem}</td><td className="font-mono text-xs">{r.name || "—"}</td><td><Trunc text={r.detail} /></td><td><Time v={r.last} /></td></tr>)}</tbody></table></TableWrap>}</Card>
    <Card title="TLS to internet addresses without a server name" bodyClass="p-0">{!d.no_server_name.length ? <Empty text="None in this range." /> : <TableWrap><table className="tbl">
      <thead><tr><th>Client</th><th>Server</th><th className="num">Sessions</th></tr></thead>
      <tbody>{d.no_server_name.map((r: any) => <tr key={`${r.src_ip}${r.dst_ip}${r.dst_port}`}><td><IpLink ip={r.src_ip} /></td><td><IpLink ip={r.dst_ip} /><span className="text-2xs text-muted">:{r.dst_port}</span></td><td className="num">{r.count}</td></tr>)}</tbody></table></TableWrap>}</Card>
    <Card title="Most contacted server names" bodyClass="p-0"><TableWrap maxH="max-h-96"><table className="tbl"><thead><tr><th>Server name</th><th className="num">Sessions</th><th className="num">Clients</th></tr></thead>
      <tbody>{d.top.map((r: any) => <tr key={r.server_name}><td className="font-mono text-xs"><Trunc text={r.server_name} /></td><td className="num">{fmtNum(r.count)}</td><td className="num">{r.clients}</td></tr>)}</tbody></table></TableWrap></Card>
  </div>;
}

function Ports({ range }: { range: string }) {
  const q = useQuery({ queryKey: ["ns-ports", range], queryFn: () => api<any>("/network-security/ports", { params: { range } }) });
  return <Card title="Protocols on ports other than their usual ones (identified by content, completed connections)" bodyClass="p-0"><Loading q={q} />
    {q.data && (!q.data.items.length ? <Empty text="None in this range." /> : <TableWrap><table className="tbl">
      <thead><tr><th>Protocol</th><th className="num">Port</th><th>Direction</th><th className="num">Connections</th><th>Sources</th><th>Destinations</th></tr></thead>
      <tbody>{q.data.items.map((r: any) => <tr key={`${r.service}${r.dst_port}${r.direction}`}><td>{r.service}</td><td className="num">{r.dst_port}</td><td>{r.direction}</td><td className="num">{fmtNum(r.count)}</td>
        <td className="text-xs font-mono">{r.sample_sources.join(", ")}{r.sources > r.sample_sources.length ? ` +${r.sources - r.sample_sources.length}` : ""}</td>
        <td className="text-xs font-mono">{r.sample_destinations.join(", ")}{r.destinations > r.sample_destinations.length ? ` +${r.destinations - r.sample_destinations.length}` : ""}</td></tr>)}</tbody></table></TableWrap>)}</Card>;
}

function Connection({ uid, onClose }: { uid: string; onClose: () => void }) {
  const q = useQuery({ queryKey: ["ns-conn", uid], queryFn: () => api<any>(`/network-security/connection/${encodeURIComponent(uid)}`) });
  const d = q.data;
  return <Drawer title={`Connection ${uid}`} onClose={onClose}>
    <Loading q={q} />
    {d && (!d.logs.length ? <Empty text="No Zeek log with this uid in the last 31 days." /> : <div className="space-y-3 text-sm">
      {d.summary && <p>{d.summary.src_ip} → {d.summary.dst_ip}:{d.summary.dst_port} {d.summary.service} · state {d.summary.state} · Zeek logs: {d.summary.logs.join(", ")} ·
        firewall verdict: {d.summary.firewall_verdicts.join(", ") || "no matching firewall log"}</p>}
      <Card title="Zeek logs (same uid)" bodyClass="p-0"><TableWrap><table className="tbl"><thead><tr><th>Time</th><th>Log</th><th>Detail</th><th>Event id</th></tr></thead>
        <tbody>{d.logs.map((r: any) => <tr key={r.event_id}><td><Time v={r.event_time} /></td><td>{r.event_subtype}</td>
          <td className="cell-wrap text-xs min-w-[16rem]">{[r.action && `state/status ${r.action}`, r.hostname, r.dns_qname, r.threat, r.msg].filter(Boolean).join(" · ")}</td>
          <td className="font-mono text-2xs">{r.event_id}</td></tr>)}</tbody></table></TableWrap></Card>
      <Card title="Firewall logs for the same addresses and port (±5 minutes)" bodyClass="p-0">{!d.firewall.length ? <Empty text="No firewall log matched: the connection may not have crossed a firewall." /> :
        <TableWrap><table className="tbl"><thead><tr><th>Time</th><th>Firewall</th><th>Action</th><th>Policy</th><th>NAT</th><th className="num">Bytes</th></tr></thead>
          <tbody>{d.firewall.map((r: any) => <tr key={r.event_id}><td><Time v={r.event_time} /></td><td>{r.firewall_name}</td><td>{r.action}</td><td>{r.policy_name || r.policy_id || "—"}</td>
            <td className="font-mono text-xs">{r.nat_src_ip || "—"}</td><td className="num">{fmtBytes((r.sent_bytes || 0) + (r.rcvd_bytes || 0))}</td></tr>)}</tbody></table></TableWrap>}</Card>
    </div>)}
  </Drawer>;
}

