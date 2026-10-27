import { Fragment, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useGlobal } from "../lib/context";
import { useTheme } from "../lib/theme";
import { escHtml, fmtDuration, fmtNum, getTimezone } from "../lib/format";
import { CHART_THEME, Chart, PALETTES, axisStyle } from "../components/Chart";
import { Card, Drawer, Empty, IpLink, Kpi, Loading, TableWrap, Tabs, Time, Trunc, rowProps } from "../components/ui";

const ST: Record<string, [string, string]> = {
  up: ["bg-emerald-400", "Established"], down: ["bg-red-500 animate-pulse", "Down"],
  admin_down: ["bg-slate-500", "Admin down"], unknown: ["bg-slate-500", "Unknown"],
};
const KIND: Record<string, [string, string]> = {
  peer_down: ["Neighbor down", "text-red-300"], peer_up: ["Neighbor up", "text-emerald-300"], notification: ["NOTIFICATION", "text-amber-300"],
  route_add: ["Route added", "text-sky-300"], route_withdraw: ["Route withdrawn", "text-orange-300"], path_change: ["Path change", "text-violet-300"],
  unreachable: ["Unreachable", "text-red-300"], state_change: ["State change", "text-amber-300"], peer_removed: ["Neighbor removed", "text-slate-400"],
  new_peer: ["New neighbor", "text-amber-300"], bfd_down: ["BFD down", "text-red-300"], bfd_up: ["BFD up", "text-emerald-300"],
  leak_suspect: ["Leak suspected", "text-red-400"], new_prefix: ["New prefix", "text-sky-300"], more_specific: ["More-specific (hijack?)", "text-red-400"],
  bogon_prefix: ["Bogon prefix", "text-orange-300"], public_via_internal: ["Public via internal", "text-orange-300"],
  default_route: ["Default route", "text-amber-300"], as_path_change: ["AS-path change", "text-violet-300"],
  fsm: ["FSM", "text-slate-400"], other: ["Other", "text-slate-400"],
};
const SERIES: [string, string, number][] = [["peer_down", "Neighbor down", 3], ["peer_up", "Neighbor up", 2], ["notification", "NOTIFICATION", 4],
  ["route_add", "Routes added", 0], ["route_withdraw", "Routes withdrawn", 1], ["path_change", "Path changes", 5]];
const SEV_C: Record<string, string> = { high: "text-red-400", medium: "text-orange-300", low: "text-amber-200", info: "text-slate-400" };
const RANGES = [["1h", "Last hour"], ["24h", "Last 24 h"], ["7d", "Last 7 days"], ["30d", "Last 30 days"]];
const timeAxis = { type: "time", ...axisStyle, axisLabel: { ...axisStyle.axisLabel, formatter: (v: number) => new Date(v).toLocaleString(undefined, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false, timeZone: getTimezone() }) } };
const dur = (s?: number | null) => (s == null ? "—" : s ? fmtDuration(s) : "0");

function Status({ s }: { s: string }) {
  const [c, l] = ST[s] || ST.unknown;
  return <span className="inline-flex items-center gap-1.5 whitespace-nowrap"><span className={`h-2.5 w-2.5 rounded-full ${c}`} aria-hidden />{l}</span>;
}

function Kind({ k }: { k: string }) {
  const [l, c] = KIND[k] || KIND.other;
  return <span className={`text-xs whitespace-nowrap ${c}`}>{l}</span>;
}

function Sev({ s }: { s: string }) {
  return <span className={`text-xs font-semibold uppercase ${SEV_C[s] || ""}`}>{s}</span>;
}

function EventChart({ timeline, bucket }: { timeline: any[]; bucket: number }) {
  const { theme } = useTheme();
  return <Chart height={230} option={{
    legend: { top: 0 }, tooltip: { trigger: "axis", confine: true }, grid: { left: 40, right: 16, top: 34, bottom: 28 },
    xAxis: timeAxis, yAxis: { type: "value", minInterval: 1, ...axisStyle },
    series: SERIES.map(([k, name, ci]) => ({ name, type: "bar", stack: k.startsWith("peer") || k === "notification" ? "peers" : "routes", barMaxWidth: 14,
      itemStyle: { color: k === "peer_down" ? "#ef4444" : k === "peer_up" ? "#10b981" : PALETTES[theme][ci] },
      data: timeline.map((r) => [Date.parse(r.t) + (bucket * 1000) / 2, r[k] || 0]) })),
  }} />;
}

function Baseline({ b, anomaly }: { b: any; anomaly?: boolean }) {
  if (!b) return <span className="text-muted">—</span>;
  return <span className={anomaly ? "text-red-300 font-semibold" : "text-muted"} title={`7-day median ${b.median}, p5–p95 ${b.p05}–${b.p95}, ${b.samples} samples`}>
    {fmtNum(b.median)}{b.deviation_pct != null && Math.abs(b.deviation_pct) >= 1 ? ` (${b.deviation_pct > 0 ? "+" : ""}${b.deviation_pct}%)` : ""}</span>;
}

export function Bgp() {
  const g = useGlobal();
  const [range, setRange] = useState("24h");
  const [tab, setTab] = useState("overview");
  const [sel, setSel] = useState<any>(null);
  const fw = Array.isArray(g.params.firewall_id) ? g.params.firewall_id : [];
  const q = useQuery({ queryKey: ["bgp", range, fw], queryFn: () => api<any>("/bgp/overview", { params: { range, firewall_id: fw } }), refetchInterval: 60_000, placeholderData: (p) => p });
  const d = q.data;
  const t = d?.totals || {};
  return (
    <div className="space-y-4 min-w-0">
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-xs text-muted flex-1 min-w-[16rem]">BGP neighbor health, routes and configuration from router event logs and read-only API polling (neighbors, received prefixes,
          installed routes and, every 6 h, the BGP configuration). Nothing is ever changed on the firewalls; suggested fixes are CLI for review.</p>
        <select aria-label="Range" className="input py-1" value={range} onChange={(e) => setRange(e.target.value)}>
          {RANGES.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
      </div>
      <Loading q={q} />
      {d && <>
        <div className="kpi-grid">
          <Kpi label="BGP neighbors" value={fmtNum(t.peers)} sub={`${t.firewalls} firewall(s) · ${fmtNum(t.up)} established`} />
          <Kpi label="Down now" value={fmtNum(t.down)} tone={t.down ? "bad" : "ok"} />
          <Kpi label="Neighbor drops" value={fmtNum(t.flaps)} sub={`in ${range}`} tone={t.flaps ? "warn" : undefined} onClick={() => setTab("drops")} />
          <Kpi label="Prefix anomalies" value={fmtNum(t.prefix_anomalies)} tone={t.prefix_anomalies ? "bad" : "ok"} sub="vs 7-day baseline" />
          <Kpi label="Routes + / − · path changes" value={`${fmtNum(t.routes_added)} / ${fmtNum(t.routes_withdrawn)} · ${fmtNum(t.path_changes)}`} onClick={() => setTab("prefixes")} />
          <Kpi label="Route security signals" value={fmtNum(t.security_events)} tone={t.security_events ? "warn" : "ok"} onClick={() => setTab("security")} />
        </div>
        <Tabs value={tab} onChange={setTab} tabs={[{ key: "overview", label: "Overview & topology" }, { key: "drops", label: "Drops & causes" },
          { key: "prefixes", label: "Prefixes & paths" }, { key: "security", label: "Route security" }, { key: "audit", label: "Config audit" }]} />
        {tab === "overview" && <Overview d={d} range={range} onSel={setSel} />}
        {tab === "drops" && <Drops range={range} fw={fw} onSel={(x: any) => setSel(d.peers.find((p: any) => p.firewall_id === x.firewall_id && p.peer === x.peer) || x)} />}
        {tab === "prefixes" && <Prefixes range={range} fw={fw} />}
        {tab === "security" && <Security range={range} fw={fw} />}
        {tab === "audit" && <Audit fw={fw} />}
      </>}
      {sel && <PeerDrawer x={sel} range={range} onClose={() => setSel(null)} />}
    </div>
  );
}

// ------------------------------------------------------------------ overview
function Overview({ d, range, onSel }: { d: any; range: string; onSel: (x: any) => void }) {
  const [kind, setKind] = useState("");
  const events = useMemo(() => (d.events || []).filter((e: any) => !kind || e.kind === kind || (kind === "route" && (e.kind.startsWith("route_") || e.kind === "path_change" || e.kind === "unreachable"))), [d, kind]);
  return <>
    <Card title="BGP neighbors" right={<span className="text-2xs text-muted">click a neighbor for timeline, root cause, prefixes, states and config</span>}>
      {!d.peers.length ? <Empty text={<>No BGP data in this range. FortiGate logs neighbor changes when <span className="font-mono">config router bgp → set log-neighbour-changes enable</span> (default) and router event logs are sent to the SIEM; live state needs API read access to router monitoring.</>} /> :
        <TableWrap><table className="tbl"><thead><tr><th>Status</th><th>Firewall</th><th>Neighbor</th><th>Tunnel / port</th><th className="num">AS</th><th>Since</th>
          <th className="num">Prefixes</th><th className="num">Baseline</th><th className="num">Availability</th><th className="num">Drops</th><th className="num">MTBF</th>
          <th className="num">MTTR</th><th className="num">Routes +/−</th><th className="num">Paths</th><th className="w-full">Last reason</th></tr></thead>
          <tbody>{d.peers.map((x: any) => <tr key={`${x.firewall_id}:${x.peer}`} {...rowProps(() => onSel(x))}>
            <td><Status s={x.status} /></td><td className="text-xs nowrap">{x.firewall_name}</td>
            <td><IpLink ip={x.peer} />{x.remote_firewall_name && <div className="text-2xs text-muted">↔ {x.remote_firewall_name}</div>}</td>
            <td className="font-mono text-xs nowrap">{x.interface || "—"}</td><td className="num">{x.remote_as ?? "—"}</td><td><Time v={x.since} /></td>
            <td className="num">{x.prefixes == null ? "—" : fmtNum(x.prefixes)}</td><td className="num text-xs"><Baseline b={x.baseline} anomaly={x.prefix_anomaly} /></td>
            <td className={`num ${x.availability != null && x.availability < 99.9 ? "text-red-300" : "text-emerald-300"}`}>{x.availability == null ? "—" : `${x.availability.toFixed(3)}%`}</td>
            <td className="num">{fmtNum(x.flaps)}</td><td className="num text-xs">{dur(x.mtbf_s)}</td><td className="num text-xs">{dur(x.mttr_s)}</td>
            <td className="num text-xs">{fmtNum(x.routes_added)} / {fmtNum(x.routes_withdrawn)}</td><td className="num text-xs">{fmtNum(x.path_changes)}</td>
            <td className="text-xs"><Trunc text={x.last_reason || "—"} /></td>
          </tr>)}</tbody></table></TableWrap>}
    </Card>
    {d.peers.length > 0 && <Topology d={d} onSel={onSel} />}
    <div className="grid gap-4 xl:grid-cols-[2fr_1fr] min-w-0">
      <Card title="BGP events over time">{d.timeline.length ? <EventChart timeline={d.timeline} bucket={d.bucket_seconds} /> : <Empty text="No BGP events in this range." />}</Card>
      <Card title="Why neighbors went down">
        <ul className="text-sm space-y-1">{d.down_reasons.map((r: any) => <li key={r.reason} className="flex gap-2"><span className="flex-1">{r.reason}</span><b className="tabular-nums">{fmtNum(r.count)}</b></li>)}
          {!d.down_reasons.length && <li className="text-muted">no neighbor drops</li>}</ul>
        <p className="text-2xs text-muted mt-3">"Hold Timer Expired" means keepalives stopped arriving (link loss or an overloaded peer / underlay tunnel); the Drops &amp; causes tab
          checks the tunnel, WAN, ICMP and firewall health at that moment. "FSM-ERR" and other NOTIFICATION codes point at a protocol or configuration mismatch.</p>
      </Card>
    </div>
    <Card title={`BGP events (${fmtNum(events.length)}) · ${range}`} bodyClass="p-0" right={
      <select aria-label="Event type" className="input py-0.5 text-xs" value={kind} onChange={(e) => setKind(e.target.value)}>
        <option value="">All events</option><option value="peer_down">Neighbor down</option><option value="peer_up">Neighbor up</option>
        <option value="notification">NOTIFICATIONs</option><option value="route">Route / path changes</option><option value="bfd_down">BFD down</option>
        <option value="state_change">State changes</option><option value="new_peer">New neighbors</option></select>}>
      {events.length ? <EventTable rows={events.slice(0, 500)} /> : <Empty text="No events of this type." />}
    </Card>
  </>;
}

function Topology({ d, onSel }: { d: any; onSel: (x: any) => void }) {
  const { theme } = useTheme();
  const t0 = Date.parse(d.window.start), t1 = Math.min(Date.parse(d.window.end), Date.now());
  const [pos, setPos] = useState(1000);
  const at = t0 + ((t1 - t0) * pos) / 1000;
  const live = pos >= 1000;
  const stateAt = (x: any) => {
    if (live) return x.status;
    if (x.down_periods.some((p: any) => Date.parse(p.start) <= at && at < Date.parse(p.end))) return "down";
    return x.status === "unknown" ? "unknown" : "up";
  };
  const option = useMemo(() => {
    const c = CHART_THEME[theme];
    const nodes: any[] = [], links: any[] = [], seen = new Set<string>(), pairs = new Set<string>();
    const col = (s: string) => (s === "up" ? "#10b981" : s === "down" ? "#ef4444" : "#64748b");
    for (const x of d.peers) {
      const fid = `fw:${x.firewall_id}`;
      if (!seen.has(fid)) { seen.add(fid); nodes.push({ id: fid, name: x.firewall_name, symbol: "roundRect", symbolSize: [Math.max(96, x.firewall_name.length * 7 + 20), 28], itemStyle: { color: PALETTES[theme][0] }, label: { show: true, position: "inside", color: "#fff", fontSize: 11 }, kind: "fw" }); }
      const s = stateAt(x);
      if (x.remote_firewall_id) {  // both ends monitored: one firewall-to-firewall link
        const key = [x.firewall_id, x.remote_firewall_id].sort().join("-") + ":" + [x.peer, x.local_ip].sort().join("-");
        if (pairs.has(key)) continue;
        pairs.add(key);
        links.push({ source: fid, target: `fw:${x.remote_firewall_id}`, peer: x, value: x.interface, lineStyle: { color: col(s), width: s === "down" ? 3 : 2, type: s === "up" ? "solid" : "dashed" } });
        continue;
      }
      const pid = `p:${x.firewall_id}:${x.peer}`;
      nodes.push({ id: pid, name: x.peer, peer: x, symbolSize: 12 + Math.min(18, Math.sqrt(x.prefixes || 1) * 1.5), itemStyle: { color: col(s) },
        label: { show: true, position: "right", color: c.strong, fontSize: 10, formatter: `${x.peer}${x.remote_as ? ` · AS${x.remote_as}` : ""}` }, kind: "peer" });
      links.push({ source: fid, target: pid, peer: x, value: x.interface, lineStyle: { color: col(s), width: s === "down" ? 3 : 1.5, type: s === "up" ? "solid" : "dashed" } });
    }
    return {
      tooltip: { trigger: "item", confine: true, formatter: (p: any) => {
        const x = p.data.peer;
        if (!x) return escHtml(p.data.name);
        return `<b>${escHtml(x.peer)}</b> on ${escHtml(x.firewall_name)}${x.remote_firewall_name ? ` ↔ ${escHtml(x.remote_firewall_name)}` : ""}<br/>` +
          `${escHtml(x.interface || "")} · AS ${x.remote_as ?? "?"} · ${x.prefixes ?? "?"} prefixes<br/>state ${escHtml(stateAt(x))} · ${x.flaps} drop(s) · availability ${x.availability ?? "—"}%`;
      } },
      series: [{ type: "graph", layout: "force", roam: true, draggable: true, force: { repulsion: 280, edgeLength: [80, 160], gravity: 0.1 },
        data: nodes, links, edgeLabel: { show: true, formatter: (p: any) => p.data.value || "", fontSize: 9, color: c.text },
        emphasis: { focus: "adjacency", lineStyle: { width: 4 } } }],
    };
  }, [d, theme, pos]);  // eslint-disable-line react-hooks/exhaustive-deps
  return <Card title="Topology" right={<span className="text-2xs text-muted">drag to rearrange · green established · red down · grey unknown</span>}>
    <Chart height={380} option={option} onClick={(p: any) => p.data?.peer && onSel(p.data.peer)} />
    <div className="flex items-center gap-3 mt-2">
      <span className="text-xs text-muted whitespace-nowrap">Replay</span>
      <input aria-label="Replay time" type="range" min={0} max={1000} value={pos} onChange={(e) => setPos(+e.target.value)} className="flex-1" />
      <span className="text-xs tabular-nums whitespace-nowrap w-40 text-right">{live ? "now (live state)" : new Date(at).toLocaleString(undefined, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false, timeZone: getTimezone() })}</span>
      {!live && <button className="btn py-0.5 text-xs" onClick={() => setPos(1000)}>Live</button>}
    </div>
  </Card>;
}

function EventTable({ rows, peerCol = true }: { rows: any[]; peerCol?: boolean }) {
  return <TableWrap maxH="max-h-[28rem]"><table className="tbl"><thead><tr><th>Time</th>{peerCol && <><th>Firewall</th><th>Neighbor</th></>}<th>Event</th><th>Prefix</th><th className="w-full">Detail</th><th>Source</th></tr></thead>
    <tbody>{rows.map((e: any, i: number) => <tr key={i}><td><Time v={e.t} /></td>
      {peerCol && <><td className="text-xs nowrap">{e.firewall_name}</td><td>{e.peer ? <IpLink ip={e.peer} /> : "—"}</td></>}
      <td><Kind k={e.kind} />{e.direction && <span className="text-2xs text-muted ml-1">({e.direction})</span>}</td>
      <td className="font-mono text-xs nowrap">{e.prefix || "—"}</td><td className="text-xs"><Trunc text={e.detail} max="max-w-[36rem]" /></td>
      <td className="text-2xs text-muted">{e.source}</td></tr>)}</tbody></table></TableWrap>;
}

// ------------------------------------------------------------------ drops & root cause
function Drops({ range, fw, onSel }: { range: string; fw: (string | number)[]; onSel: (x: any) => void }) {
  const q = useQuery({ queryKey: ["bgp-corr", range, fw], queryFn: () => api<any>("/bgp/correlation", { params: { range, firewall_id: fw } }), placeholderData: (p) => p });
  const d = q.data;
  return <>
    <Loading q={q} />
    {d && <div className="grid gap-4 xl:grid-cols-[1fr_3fr] min-w-0">
      <Card title="Likely causes"><ul className="text-sm space-y-1.5">{d.verdicts.map((v: any) => <li key={v.verdict} className="flex gap-2"><span className="flex-1">{v.verdict}</span><b className="tabular-nums">{v.count}</b></li>)}
        {!d.verdicts.length && <li className="text-muted">no drops</li>}</ul>
        <p className="text-2xs text-muted mt-3">Each drop is checked against the same firewall within ±2 min: restarts, ISP / SD-WAN outages, the IPsec tunnel carrying the session,
          ICMP targets going down, CPU ≥ 90 % and BFD. When none matches, the reason code decides: "Keepalive loss" (hold timer expired, the path
          broke without a logged tunnel/WAN event), "BGP-level reset" (a NOTIFICATION / FSM error from either side) or "BGP / peer side".</p></Card>
      <Card title={`Neighbor drops (${d.drops.length})`} bodyClass="p-0">
        {d.drops.length ? <TableWrap maxH="max-h-[36rem]"><table className="tbl"><thead><tr><th>Start</th><th>Firewall</th><th>Neighbor</th><th>Tunnel</th><th className="num">Duration</th>
          <th>Reason</th><th>Likely cause</th><th className="w-full">Evidence</th></tr></thead>
          <tbody>{d.drops.map((x: any, i: number) => <tr key={i} {...rowProps(() => onSel(x))}><td><Time v={x.start} /></td><td className="text-xs nowrap">{x.firewall_name}</td>
            <td><IpLink ip={x.peer} /></td><td className="font-mono text-xs nowrap">{x.interface || "—"}</td>
            <td className="num nowrap">{x.ongoing ? <span className="text-red-300">ongoing {dur(x.duration_s)}</span> : dur(x.duration_s)}</td>
            <td className="text-xs"><Trunc text={x.reason || "—"} /></td><td className="text-xs font-semibold nowrap">{x.verdict}</td>
            <td className="text-xs">{x.causes?.length ? x.causes.map((c: any) => c.detail).join(" · ") : <span className="text-muted">no underlay event found</span>}</td></tr>)}</tbody></table></TableWrap>
          : <Empty text="No neighbor drops in this range." />}
      </Card>
    </div>}
  </>;
}

// ------------------------------------------------------------------ prefixes & paths
function Prefixes({ range, fw }: { range: string; fw: (string | number)[] }) {
  const [filter, setFilter] = useState("");
  const q = useQuery({ queryKey: ["bgp-prefixes", range, fw], queryFn: () => api<any>("/bgp/prefixes", { params: { range, firewall_id: fw } }), placeholderData: (p) => p });
  const d = q.data;
  const rib = useMemo(() => (d?.rib || []).filter((r: any) => !filter || r.prefix.includes(filter) || r.paths.some((p: any) => (p.interface || "").includes(filter) || p.peer.includes(filter))), [d, filter]);
  return <>
    <Loading q={q} />
    {d && <>
      <div className="kpi-grid">
        <Kpi label="Installed BGP routes" value={fmtNum(d.totals.installed)} sub={`${fmtNum(d.totals.ecmp)} with ECMP`} />
        <Kpi label="Unstable prefixes" value={fmtNum(d.totals.unstable)} sub={`in ${range}`} tone={d.totals.unstable ? "warn" : "ok"} />
        <Kpi label="Would be dampened now" value={fmtNum(d.totals.suppressed_now)} tone={d.totals.suppressed_now ? "bad" : "ok"} sub="penalty ≥ 2000" />
        <Kpi label="Critical prefixes installed" value={d.critical.exists ? fmtNum(d.totals.critical_installed) : "—"} sub={d.critical.exists ? `watchlist ${d.critical.watchlist}` : "no watchlist"} />
      </div>
      {!d.critical.exists && <p className="text-xs text-muted">Create an IP watchlist named <span className="font-mono">{d.critical.watchlist}</span> (Watchlists page) with your critical
        subnets (data centre, payment, core sites) to highlight them here and alert when they are withdrawn or move to another path.</p>}
      {d.critical.exists && d.critical.events.length > 0 && <Card title={`Critical prefix changes (${d.critical.events.length})`} bodyClass="p-0">
        <EventTable rows={d.critical.events} /></Card>}
      <Card title="Most unstable prefixes" bodyClass="p-0" right={<span className="text-2xs text-muted">route-flap dampening: withdraw +1000, path change +500, half-life 15 min, suppress ≥ 2000</span>}>
        {d.unstable.length ? <TableWrap maxH="max-h-96"><table className="tbl"><thead><tr><th>Firewall</th><th>Prefix</th><th>Neighbors</th><th className="num">Withdrawn</th>
          <th className="num">Announced</th><th className="num">Path changes</th><th className="num">Penalty now / max</th><th className="num">Mean lifetime</th><th>Last change</th></tr></thead>
          <tbody>{d.unstable.slice(0, 200).map((x: any, i: number) => <tr key={i}><td className="text-xs nowrap">{x.firewall_name}</td>
            <td className="font-mono text-xs nowrap">{x.prefix}{x.critical && <span className="ml-1 text-red-300" title="critical prefix">★</span>}</td>
            <td className="text-xs">{x.peers.join(", ")}</td><td className="num">{x.withdrawals}</td><td className="num">{x.announcements}</td><td className="num">{x.path_changes}</td>
            <td className={`num ${x.suppressed ? "text-red-300 font-semibold" : x.would_have_been_suppressed ? "text-amber-300" : ""}`}>{fmtNum(x.penalty)} / {fmtNum(x.max_penalty)}</td>
            <td className="num text-xs">{dur(x.mean_lifetime_s)}</td><td><Time v={x.last_change} /></td></tr>)}</tbody></table></TableWrap>
          : <Empty text="No route changes in this range." />}
      </Card>
      <Card title={`Installed BGP routes (${fmtNum(rib.length)})`} bodyClass="p-0" right={<input aria-label="Filter routes" className="input py-0.5 text-xs w-56" placeholder="filter prefix / tunnel / neighbor" value={filter} onChange={(e) => setFilter(e.target.value)} />}>
        {rib.length ? <TableWrap maxH="max-h-[32rem]"><table className="tbl"><thead><tr><th>Firewall</th><th>Prefix</th><th className="w-full">Via (neighbor · tunnel · underlay gateway)</th>
          <th className="num">ECMP</th><th className="num">Route age</th><th className="num">Changes</th></tr></thead>
          <tbody>{rib.slice(0, 1000).map((r: any, i: number) => <tr key={i}><td className="text-xs nowrap">{r.firewall_name}</td>
            <td className="font-mono text-xs nowrap">{r.prefix}{r.critical && <span className="ml-1 text-red-300" title="critical prefix">★</span>}</td>
            <td className="text-xs">{r.paths.map((p: any, j: number) => <span key={j} className="mr-3 whitespace-nowrap"><span className="font-mono">{p.peer}</span>{p.interface && <> · {p.interface}</>}{p.gateway && p.gateway !== p.peer && <span className="text-muted"> · {p.gateway}</span>}</span>)}</td>
            <td className="num">{r.ecmp}</td><td className="num text-xs">{dur(r.age_s)}</td><td className="num">{r.changes || "—"}</td></tr>)}</tbody></table></TableWrap>
          : <Empty text="No installed BGP routes known yet (needs API polling)." />}
      </Card>
    </>}
  </>;
}

// ------------------------------------------------------------------ route security
function Security({ range, fw }: { range: string; fw: (string | number)[] }) {
  const r = range === "1h" || range === "24h" ? "7d" : range;
  const q = useQuery({ queryKey: ["bgp-sec", r, fw], queryFn: () => api<any>("/bgp/security", { params: { range: r, firewall_id: fw } }), placeholderData: (p) => p });
  const d = q.data;
  return <>
    <Loading q={q} />
    {d && <>
      <p className="text-xs text-muted">Signals raised when received prefixes change: a burst of never-seen prefixes (leak), a more-specific of this firewall's own networks (hijack), bogons,
        public prefixes over an internal (private-AS) session, default-route changes and new neighbors. Shown for the last {r === "7d" ? "7 days" : r}.</p>
      <div className="kpi-grid">{["leak_suspect", "more_specific", "bogon_prefix", "public_via_internal", "default_route", "new_peer", "new_prefix"].map((k) =>
        <Kpi key={k} label={KIND[k][0]} value={fmtNum(d.by_kind[k] || 0)} sub={d.present_by_kind[k] ? `${d.present_by_kind[k]} present now` : undefined}
          tone={(d.by_kind[k] || d.present_by_kind[k]) && k !== "new_prefix" ? "warn" : undefined} />)}</div>
      <Card title={`Signals (${d.events.length})`} bodyClass="p-0">{d.events.length ? <EventTable rows={d.events} /> : <Empty text="No route-security signals in this range." />}</Card>
      <Card title={`Present in received routes now (${d.present.length})`} bodyClass="p-0">
        {d.present.length ? <TableWrap maxH="max-h-96"><table className="tbl"><thead><tr><th>Firewall</th><th>Neighbor</th><th>Signal</th><th>Prefix</th><th className="w-full">Why</th></tr></thead>
          <tbody>{d.present.map((x: any, i: number) => <tr key={i}><td className="text-xs nowrap">{x.firewall_name}</td><td><IpLink ip={x.peer} /></td><td><Kind k={x.kind} /></td>
            <td className="font-mono text-xs">{x.prefix}</td><td className="text-xs">{x.detail}</td></tr>)}</tbody></table></TableWrap>
          : <Empty text="Nothing suspicious in the prefixes currently received." />}
      </Card>
    </>}
  </>;
}

// ------------------------------------------------------------------ config audit
function Audit({ fw }: { fw: (string | number)[] }) {
  const [open, setOpen] = useState<string | null>(null);
  const q = useQuery({ queryKey: ["bgp-audit", fw], queryFn: () => api<any>("/bgp/audit", { params: { firewall_id: fw } }), placeholderData: (p) => p });
  const d = q.data;
  return <>
    <Loading q={q} />
    {d && <>
      <div className="kpi-grid">{["high", "medium", "low", "info"].map((s) => <Kpi key={s} label={`${s} findings`} value={fmtNum(d.by_severity[s] || 0)}
        tone={s === "high" || s === "medium" ? (d.by_severity[s] ? "bad" : "ok") : undefined} />)}</div>
      {!d.firewalls.length && <Empty text="No BGP configuration read yet. It is read every 6 hours with the firewall's read-only API token." />}
      {d.firewalls.map((f: any) => <Card key={f.firewall_id} title={`${f.firewall_name} · AS ${f.local_as ?? "?"} · router-id ${f.router_id || "?"}`}
        right={<span className="text-2xs text-muted">read <Time v={f.config_polled_at} /></span>}>
        <div className="text-xs text-muted mb-2 flex flex-wrap gap-x-4 gap-y-1"><span>{f.neighbors} neighbor(s), {f.bfd_neighbors} with BFD</span>
          <span>hold / keepalive {f.holdtime ?? "?"} / {f.keepalive ?? "?"} s</span><span>graceful restart {f.graceful_restart ? "on" : "off"}</span>
          <span>dampening {f.dampening ? "on" : "off"}</span><span>networks: {f.networks.join(", ") || "none"}</span></div>
        {f.findings.length ? <TableWrap maxH="max-h-[28rem]"><table className="tbl"><thead><tr><th>Severity</th><th>Neighbor</th><th>Finding</th><th className="w-full">Why it matters</th><th>Fix</th></tr></thead>
          <tbody>{f.findings.map((x: any, i: number) => { const k = `${f.firewall_id}:${i}`; return <Fragment key={k}>
            <tr><td><Sev s={x.severity} /></td><td className="font-mono text-xs nowrap">{x.peer || "global"}</td><td className="text-xs nowrap">{x.title}</td>
              <td className="text-xs">{x.detail}</td><td>{x.cli && <button className="btn py-0.5 text-xs" onClick={() => setOpen(open === k ? null : k)}>{open === k ? "Hide" : "CLI"}</button>}</td></tr>
            {open === k && <tr><td colSpan={5}><pre className="text-xs font-mono bg-black/20 rounded p-2 overflow-x-auto">{x.cli}</pre>
              <p className="text-2xs text-muted">Review before applying. The SIEM never changes firewall configuration.</p></td></tr>}</Fragment>; })}</tbody></table></TableWrap>
          : <Empty text="No findings." />}
      </Card>)}
    </>}
  </>;
}

// ------------------------------------------------------------------ neighbor drawer
function PeerDrawer({ x, range, onClose }: { x: any; range: string; onClose: () => void }) {
  const { theme } = useTheme();
  const q = useQuery({ queryKey: ["bgp-peer", x.firewall_id, x.peer, range], queryFn: () => api<any>(`/bgp/peers/${x.firewall_id}/${encodeURIComponent(x.peer)}`, { params: { range } }) });
  const d = q.data;
  return (
    <Drawer title={`BGP ${x.peer} · ${x.firewall_name}`} onClose={onClose}>
      <Loading q={q} />
      {d && <div className="space-y-4">
        <div className="text-sm flex flex-wrap gap-x-3 gap-y-1"><Status s={d.status} /><span>state <b>{d.state || "—"}</b></span>
          {d.remote_as != null && <span>AS <b>{d.remote_as}</b></span>}{d.interface && <span>via <span className="font-mono">{d.interface}</span></span>}
          {d.local_ip && <span>local <span className="font-mono">{d.local_ip}</span></span>}{d.remote_firewall_name && <span>↔ <b>{d.remote_firewall_name}</b></span>}
          {d.since && <span>since <Time v={d.since} /></span>}</div>
        {d.state_hint && d.status !== "up" && <p className="text-xs text-amber-200">{d.state_hint}</p>}
        <div className="kpi-grid">
          <Kpi label="Availability" value={d.availability == null ? "—" : `${d.availability.toFixed(3)}%`} tone={d.availability != null && d.availability < 99.9 ? "bad" : "ok"} />
          <Kpi label="Drops" value={fmtNum(d.flaps)} sub={`flap score ${d.flap_score}/day`} />
          <Kpi label="MTBF / MTTR" value={`${dur(d.mtbf_s)} / ${dur(d.mttr_s)}`} sub={`longest ${dur(d.longest_s)}`} />
          <Kpi label="Prefixes" value={d.prefixes == null ? "—" : fmtNum(d.prefixes)} sub={d.baseline ? <>baseline <Baseline b={d.baseline} anomaly={d.prefix_anomaly} /></> : "no baseline yet"} tone={d.prefix_anomaly ? "bad" : undefined} />
        </div>
        {d.down_periods.length > 0 && <Card title={`Drops and likely cause (${d.down_periods.length})`} bodyClass="p-0">
          <TableWrap><table className="tbl"><thead><tr><th>Start</th><th>End</th><th className="num">Duration</th><th>Likely cause</th><th className="w-full">Evidence</th></tr></thead>
            <tbody>{[...d.down_periods].reverse().map((p: any, i: number) => <tr key={i}><td><Time v={p.start} /></td>
              <td>{p.ongoing ? <span className="text-red-300">ongoing</span> : <Time v={p.end} />}</td><td className="num">{dur(p.duration_s)}</td>
              <td className="text-xs font-semibold nowrap">{p.verdict}</td><td className="text-xs">{p.causes?.map((c: any) => c.detail).join(" · ") || p.reason || "—"}</td></tr>)}</tbody></table></TableWrap>
        </Card>}
        {d.time_in_state?.states?.length > 0 && <Card title="Time in each state (API polls)">
          <div className="flex h-3 rounded overflow-hidden mb-2">{d.time_in_state.states.map((s: any, i: number) =>
            <div key={s.state} style={{ width: `${s.pct}%`, background: s.state.toLowerCase() === "established" ? "#10b981" : PALETTES[theme][(i + 3) % 8] }} title={`${s.state} ${s.pct}%`} />)}</div>
          <ul className="text-xs space-y-1">{d.time_in_state.states.map((s: any) => <li key={s.state}><b>{s.state}</b> {dur(s.seconds)} ({s.pct}%){s.state.toLowerCase() !== "established" && s.hint && <span className="text-muted"> · {s.hint}</span>}</li>)}</ul>
        </Card>}
        {d.samples.length > 0 && <Card title="Prefixes received (API polls)"><Chart height={200} option={{
          tooltip: { trigger: "axis", confine: true }, grid: { left: 48, right: 16, top: 16, bottom: 28 }, xAxis: timeAxis,
          yAxis: { type: "value", minInterval: 1, ...axisStyle },
          series: [{ name: "prefixes", type: "line", step: "end", showSymbol: false, itemStyle: { color: PALETTES[theme][0] }, areaStyle: { opacity: 0.15 },
            data: d.samples.map((p: any) => [Date.parse(p.t), p.prefixes]),
            markLine: d.baseline ? { silent: true, symbol: "none", lineStyle: { type: "dashed" }, data: [{ yAxis: d.baseline.median, name: "7-day median" }] } : undefined }],
        }} /></Card>}
        {d.timeline.length > 0 && <Card title="Events over time"><EventChart timeline={d.timeline} bucket={d.bucket_seconds} /></Card>}
        {(d.audit.length > 0 || Object.keys(d.config).length > 0) && <Card title="Configuration">
          {Object.keys(d.config).length > 0 && <div className="text-xs text-muted mb-2 flex flex-wrap gap-x-4">
            <span>BFD {d.config.bfd ? "on" : "off"}</span><span>password {d.config.password ? "set" : "none"}</span>
            <span>hold timer {d.config.holdtime ?? "global"}</span><span>max-prefix {d.config.max_prefix || "none"}</span>
            <span>inbound filter {d.config.filter_in ? "yes" : "no"}</span><span>outbound filter {d.config.filter_out ? "yes" : "no"}</span></div>}
          <ul className="text-xs space-y-1">{d.audit.map((f: any, i: number) => <li key={i}><Sev s={f.severity} /> {f.title}<span className="text-muted"> · {f.detail}</span></li>)}</ul>
        </Card>}
        <div className="grid gap-4 md:grid-cols-2">
          <Card title={`Received (${fmtNum(d.received.length)})`}><div className="font-mono text-xs max-h-48 overflow-auto">{d.received.join(", ") || "—"}</div></Card>
          <Card title={`Installed via this neighbor (${fmtNum(d.installed.length)})`}><div className="font-mono text-xs max-h-48 overflow-auto">{d.installed.join(", ") || "—"}</div></Card>
        </div>
        <Card title={`Events (${fmtNum(d.events.length)})`} bodyClass="p-0">{d.events.length ? <EventTable rows={d.events.slice(0, 500)} peerCol={false} /> : <Empty text="No events." />}</Card>
      </div>}
    </Drawer>
  );
}
