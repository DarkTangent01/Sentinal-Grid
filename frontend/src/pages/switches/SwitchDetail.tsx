import { useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { useMe } from "../../lib/context";
import { fmtBytes, fmtNum } from "../../lib/format";
import { Card, Drawer, Empty, Kpi, Loading, Sev, TableWrap, Tabs, Time, Trunc, rowProps, useDebounced } from "../../components/ui";
import { Bps, Flags, Fresh, KV, MetricStatus, Oper, RangeSelect, Section, SeriesChart, StateDot, Util, fmtBps, fmtPctOrDash, fmtUptime, fmtWatts, statusTone } from "./common";
import { EventTable } from "./SwitchesPage";
import { SwitchForm } from "./Admin";

const ALL_TABS: [string, string, string | null][] = [["overview", "Overview", null], ["interfaces", "Interfaces", "interfaces"], ["vlans", "VLANs", "vlans"],
  ["macs", "MAC table", "mac_table"], ["stp", "STP", "stp"], ["lacp", "LACP / port-channels", "lacp"], ["neighbors", "Neighbors", "neighbors"], ["poe", "PoE", "poe"], ["hardware", "Hardware", "hw"],
  ["routing", "Routing", "routing"], ["events", "Events & alerts", null], ["health", "Monitoring health", null]];

export function SwitchDetail() {
  const { id } = useParams();
  const sid = Number(id);
  const me = useMe();
  const qc = useQueryClient();
  const [sp, setSp] = useSearchParams();
  const tab = sp.get("tab") || "overview";
  const [edit, setEdit] = useState(false);
  const q = useQuery({ queryKey: ["switch-detail", sid], queryFn: () => api<any>(`/switches/${sid}`), refetchInterval: 30_000 });
  const act = useMutation({ mutationFn: (path: string) => api<any>(`/switches/${sid}${path}`, { method: "POST" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["switch-detail", sid] }) });
  const d = q.data;
  if (!d) return <Loading q={q} />;
  const sec = d.sections || {};
  const hw = sec.environment || sec.stack || sec.inventory || sec.cpu_memory;
  const tabs = ALL_TABS.filter(([, , g]) => g === null || (g === "hw" ? hw : sec[g]));
  const go = (t: string, extra: Record<string, string> = {}) => setSp({ tab: t, ...extra });
  return <div className="space-y-4 min-w-0">
    <div className="flex flex-wrap items-center gap-3">
      <Link to="/switches?tab=inventory" className="link text-sm">← Switches</Link>
      <h1 className="text-lg font-bold">{d.name}</h1><StateDot s={d.state} monitoring={d.monitoring} />
      <span className="text-sm text-muted">{d.vendor} {d.model || d.family} · <span className="font-mono">{d.address}</span>{d.site && ` · ${d.site}`}</span>
      <span className="text-xs text-muted">last poll <Time v={d.last_success_at} /> <Fresh f={d.freshness} /></span>
      {me.role === "admin" && <div className="ml-auto flex flex-wrap gap-2">
        <button className="btn" disabled={act.isPending} onClick={() => act.mutate("/poll")}>{act.isPending ? "Working…" : "Poll now"}</button>
        <button className="btn" disabled={act.isPending} onClick={() => act.mutate("/test")}>Test</button>
        <button className="btn" disabled={act.isPending} onClick={() => act.mutate(`/monitoring/${d.monitoring === "paused" ? "resume" : "pause"}`)}>{d.monitoring === "paused" ? "Resume" : "Pause"}</button>
        <button className="btn" onClick={() => setEdit(true)}>Edit</button>
      </div>}
    </div>
    {act.error && <div role="alert" className="text-sm text-red-400">{(act.error as Error).message}</div>}
    {act.data && <div className="text-xs text-muted">{act.data.ok === false ? <span className="text-red-300">{act.data.stage || "poll"}: {act.data.error}</span>
      : act.data.identity ? `Test OK: ${act.data.identity.vendor} ${act.data.identity.model}, ${act.data.coverage?.supported} metrics supported (${act.data.duration_ms} ms)`
      : `Polled in ${act.data.duration_ms} ms, ${act.data.requests} SNMP requests${act.data.events?.length ? `, events: ${act.data.events.join(", ")}` : ""}`}</div>}
    {d.last_error && <div className="text-xs text-amber-300">Last collection problem ({d.last_error_kind}): {d.last_error}</div>}
    <Tabs value={tab} onChange={(t) => go(t)} tabs={tabs.map(([key, label]) => ({ key, label }))} />
    {tab === "overview" && <Overview d={d} go={go} />}
    {tab === "interfaces" && <Interfaces sid={sid} />}
    {tab === "vlans" && <Vlans sid={sid} />}
    {tab === "macs" && <Macs sid={sid} />}
    {tab === "stp" && <Stp d={d} sid={sid} />}
    {tab === "lacp" && <Lacp d={d} />}
    {tab === "neighbors" && <Neighbors sid={sid} site={d.site} />}
    {tab === "poe" && <Poe d={d} sid={sid} />}
    {tab === "hardware" && <Hardware d={d} sid={sid} />}
    {tab === "routing" && <Routing d={d} sid={sid} />}
    {tab === "events" && <EventsTab d={d} sid={sid} />}
    {tab === "health" && <Health sid={sid} />}
    {sp.get("if") && <InterfaceDrawer sid={sid} ifindex={Number(sp.get("if"))} onClose={() => { const n = new URLSearchParams(sp); n.delete("if"); setSp(n); }} />}
    {edit && <SwitchForm sw={d} onClose={() => { setEdit(false); qc.invalidateQueries({ queryKey: ["switch-detail", sid] }); }} />}
  </div>;
}

function useSeries(sid: number, metric: string, range: string) {
  return useQuery({ queryKey: ["switch-ts", sid, metric, range], queryFn: () => api<any>(`/switches/${sid}/timeseries`, { params: { metric, range } }), refetchInterval: 60_000 });
}

/** Flatten per-component series into chart points keyed by component. */
function multi(ts: any) {
  const by: Record<number, any> = {};
  for (const s of ts?.series || []) for (const p of s.points) { const t = Date.parse(p.t); by[t] = { ...(by[t] || { t: p.t }), [s.component || "value"]: p.v }; }
  return { points: Object.values(by).sort((a: any, b: any) => Date.parse(a.t) - Date.parse(b.t)), keys: (ts?.series || []).map((s: any) => s.component || "value") as string[] };
}

function Overview({ d, go }: { d: any; go: (t: string, e?: Record<string, string>) => void }) {
  const [range, setRange] = useState("24h");
  const cpu = useSeries(d.id, "cpu", range);
  const mem = useSeries(d.id, "memory", range);
  const c = multi(cpu.data), m = multi(mem.data);
  const h = d.health || {};
  const temps = (h.environment?.temperatures || []).filter((t: any) => t.celsius != null);
  const badEnv = [...(h.environment?.fans || []), ...(h.environment?.psus || [])].filter((x: any) => !["ok", "absent", "unknown"].includes(x.state)).length;
  return <div className="space-y-4">
    <div className="kpi-grid">
      <Kpi label="Reachability" value={d.state === "up" ? "Up" : d.state.replace("_", " ")} tone={d.state === "up" ? "ok" : "bad"} sub={<>since <Time v={d.state_since} /></>} />
      <Kpi label="Uptime" value={fmtUptime(d.uptime_s)} sub="SNMP agent uptime" />
      <Kpi label="CPU" value={fmtPctOrDash(d.cpu_pct, 0)} tone={statusTone(d.cpu_pct, 80, 90)} onClick={() => go("hardware")} />
      <Kpi label="Memory" value={fmtPctOrDash(d.mem_pct, 0)} tone={statusTone(d.mem_pct, 80, 90)} onClick={() => go("hardware")} />
      <Kpi label="Ports up" value={d.if_total == null ? "—" : `${d.if_up} / ${d.if_total}`} sub="physical" onClick={() => go("interfaces")} />
      <Kpi label="Interfaces with errors" value={d.if_errors ?? "—"} tone={d.if_errors ? "warn" : "ok"} onClick={() => go("interfaces")} />
      <Kpi label="Temperature (max)" value={d.temp_max_c == null ? "—" : `${d.temp_max_c} °C`} sub={`${temps.length} sensors`} onClick={() => go("hardware")} />
      <Kpi label="Fan / PSU problems" value={badEnv} tone={badEnv ? "bad" : "ok"} onClick={() => go("hardware")} />
      {d.poe_budget_w != null && <Kpi label="PoE" value={`${fmtWatts(d.poe_used_w)} / ${fmtWatts(d.poe_budget_w)}`} sub={fmtPctOrDash(d.poe_pct, 0)} tone={statusTone(d.poe_pct, 75, 90)} onClick={() => go("poe")} />}
      <Kpi label="Open alerts" value={d.alerts_open} tone={d.alerts_open ? "bad" : "ok"} onClick={() => go("events")} />
      <Kpi label="Metric coverage" value={d.coverage_pct == null ? "—" : `${d.coverage_pct.toFixed(0)}%`} sub={`${d.capability_summary?.supported || 0} supported metrics`} onClick={() => go("health")} />
    </div>
    <div className="grid gap-4 xl:grid-cols-2">
      <Card title="Device">
        <KV rows={[["Hostname", d.hostname], ["Model", `${d.model || "—"}${d.family ? ` (${d.family})` : ""}`], ["Software", `${d.os || ""} ${d.firmware || ""}`.trim() || "—"],
          ["Serial", d.serials?.length ? d.serials.join(", ") : "—"], ["SNMP", `${d.snmp_version || "—"} via ${d.credential || "—"}, port ${d.port}`],
          ["Location", d.location || "—"], ["Site / building / floor / rack", [d.site, d.building, d.floor, d.rack].filter(Boolean).join(" / ") || "—"], ["Role", d.role || "—"],
          ["sysObjectID", <span className="font-mono text-xs">{d.sys_object_id || "—"}</span>], ["sysDescr", <span className="text-xs">{d.sys_descr || "—"}</span>],
          ["Polling", `every ${d.poll_interval_seconds}s, timeout ${d.timeout_ms} ms × ${d.retries + 1}, last poll ${d.poll_duration_ms ?? "—"} ms`]]} />
      </Card>
      <Card title="Active alerts" bodyClass="p-0">
        {!d.alerts.filter((a: any) => a.status !== "resolved").length ? <Empty text="No open alerts for this switch." /> :
          <TableWrap maxH="max-h-72"><table className="tbl"><thead><tr><th>Severity</th><th>Alert</th><th>Last seen</th><th className="w-full">Explanation</th></tr></thead>
            <tbody>{d.alerts.filter((a: any) => a.status !== "resolved").map((a: any) => <tr key={a.id}><td><Sev s={a.severity} /></td>
              <td><Link className="link" to={`/alerts?id=${a.id}`}>{a.name}</Link></td><td><Time v={a.last_seen} /></td><td className="text-xs">{a.explanation}</td></tr>)}</tbody></table></TableWrap>}
        {d.site_context && <div className="p-3 border-t border-line text-xs">
          <b>Same site</b>: firewalls {d.site_context.firewalls.map((f: any) => f.name).join(", ")} ·{" "}
          {d.site_context.alerts.length ? <>{d.site_context.alerts.length} open firewall alert(s) in the last 24 h:{" "}
            {d.site_context.alerts.slice(0, 5).map((a: any) => <Link key={a.id} className="link mr-2" to={`/alerts?id=${a.id}`}>{a.name}</Link>)}</> : "no open firewall alerts in the last 24 h"}
        </div>}
      </Card>
    </div>
    <Card title="CPU and memory" right={<RangeSelect value={range} onChange={setRange} />}>
      <div className="grid gap-4 lg:grid-cols-2">
        <SeriesChart points={c.points} series={c.keys.map((k) => ({ key: k, name: `CPU ${k}` }))} unit="pct" yMax={100} bucket={cpu.data?.bucket_seconds} />
        <SeriesChart points={m.points} series={m.keys.map((k) => ({ key: k, name: "Memory" }))} unit="pct" yMax={100} bucket={mem.data?.bucket_seconds} />
      </div>
    </Card>
  </div>;
}

function Interfaces({ sid }: { sid: number }) {
  const [sp, setSp] = useSearchParams();
  const [q, setQ] = useState("");
  const [kind, setKind] = useState("");
  const [oper, setOper] = useState("");
  const [errs, setErrs] = useState(false);
  const dq = useDebounced(q, 300);  // one request when typing stops, not one per keystroke over up to 2000 rows
  const r = useQuery<any>({ queryKey: ["switch-if", sid, dq, kind, oper, errs], placeholderData: (p: any) => p, refetchInterval: 30_000,
    queryFn: ({ signal }) => api<any>(`/switches/${sid}/interfaces`, { signal, params: { q: dq || undefined, kind: kind || undefined, oper: oper || undefined, errors_only: errs || undefined, limit: 2000 } }) });
  const open = (ifx: number) => { const n = new URLSearchParams(sp); n.set("if", String(ifx)); setSp(n); };
  return <Card title={`Interfaces${r.data ? ` (${r.data.total})` : ""}`} bodyClass="p-0" right={<>
    <input aria-label="Filter" className="input py-1 w-40" placeholder="Name / description" value={q} onChange={(e) => setQ(e.target.value)} />
    <select aria-label="Kind" className="input py-1" value={kind} onChange={(e) => setKind(e.target.value)}><option value="">All kinds</option>{["physical", "lag", "svi", "virtual"].map((k) => <option key={k}>{k}</option>)}</select>
    <select aria-label="Link" className="input py-1" value={oper} onChange={(e) => setOper(e.target.value)}><option value="">Any link</option><option value="up">Up</option><option value="down">Down</option></select>
    <label className="text-xs flex items-center gap-1"><input type="checkbox" checked={errs} onChange={(e) => setErrs(e.target.checked)} /> errors only</label></>}>
    <Loading q={r} />
    {r.data && (!r.data.items.length ? <Empty text="No interfaces match." /> :
      <TableWrap><table className="tbl"><thead><tr><th className="num">ifIndex</th><th>Name</th><th>Description</th><th>Kind</th><th>Admin</th><th>Link</th><th className="num">Speed</th>
        <th>Duplex</th><th>VLAN</th><th>LAG</th><th className="num">RX</th><th className="num">TX</th><th className="num">RX util</th><th className="num">TX util</th><th className="num">In err</th>
        <th className="num">Out err</th><th className="num">CRC</th><th className="num">Discards</th><th className="num">Changes 24h</th><th>PoE</th><th>Last change</th><th>Sample</th></tr></thead>
        <tbody>{r.data.items.map((x: any) => <tr key={x.ifindex} {...rowProps(() => open(x.ifindex))}>
          <td className="num text-xs">{x.ifindex}</td><td className="font-mono text-xs whitespace-nowrap">{x.name}</td><td><Trunc text={x.alias} max="max-w-[12rem]" /></td>
          <td className="text-xs">{x.kind}</td><td className="text-xs">{x.admin}</td><td><Oper s={x.oper} /></td><td className="num text-xs"><Bps v={x.speed_bps} /></td><td className="text-xs">{x.duplex || "—"}</td>
          <td className="text-xs">{x.mode === "trunk" ? `trunk / ${x.native_vlan ?? "?"}` : x.access_vlan ?? "—"}</td><td className="text-xs">{x.lag_ifindex ?? "—"}</td>
          <td className="num"><Bps v={x.rx_bps} /></td><td className="num"><Bps v={x.tx_bps} /></td><td className="num"><Util v={x.rx_util} /></td><td className="num"><Util v={x.tx_util} /></td>
          <td className="num">{x.in_errors ?? "—"}</td><td className="num">{x.out_errors ?? "—"}</td><td className={`num ${x.crc ? "text-amber-300" : ""}`}>{x.crc ?? "—"}</td>
          <td className="num">{x.discards ?? "—"}</td><td className={`num ${x.changes_24h >= 4 ? "text-amber-300" : ""}`}>{x.changes_24h}</td>
          <td className="text-xs">{x.poe ? `${x.poe.status}${x.poe.power_w != null ? ` ${fmtWatts(x.poe.power_w)}` : ""}` : "—"}</td><td><Time v={x.last_change_at} /></td><td><Flags f={x.flags} /></td>
        </tr>)}</tbody></table></TableWrap>)}
    <p className="text-2xs text-muted p-2">Rates are deltas between the last two valid polls; errors / discards are increments in that interval. "—" means not reported or no valid sample (first poll,
      counter reset, restart). Click an interface for history.</p>
  </Card>;
}

function InterfaceDrawer({ sid, ifindex, onClose }: { sid: number; ifindex: number; onClose: () => void }) {
  const [range, setRange] = useState("24h");
  const q = useQuery({ queryKey: ["switch-ifd", sid, ifindex, range], queryFn: () => api<any>(`/switches/${sid}/interfaces/${ifindex}`, { params: { range } }), refetchInterval: 60_000 });
  const d = q.data;
  const x = d?.interface;
  const pts = d?.series?.points || [];
  const b = d?.series?.bucket_seconds || 60;
  return <Drawer title={x ? `${d.switch.name} · ${x.name}${x.alias ? ` (${x.alias})` : ""}` : "Interface"} onClose={onClose}>
    <Loading q={q} />
    {d && <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3 text-sm"><Oper s={x.oper} /><span>admin {x.admin}</span><span>{fmtBps(x.speed_bps)} ({x.speed_source || "speed unknown"})</span>
        <span>{x.duplex || "duplex —"}</span><span>MTU {x.mtu ?? "—"}</span><span>{x.hc_counters ? "64-bit counters" : "32-bit counters"}</span><Flags f={x.flags} />
        <span className="ml-auto"><RangeSelect value={range} onChange={setRange} /></span></div>
      <Section title="Throughput"><SeriesChart points={pts} unit="bps" bucket={b} series={[{ key: "rx_bps", name: "RX avg" }, { key: "tx_bps", name: "TX avg" },
        { key: "rx_bps_max", name: "RX peak", dashed: true }, { key: "tx_bps_max", name: "TX peak", dashed: true }]} /></Section>
      <Section title="Utilisation (peak per bucket)">{x.speed_bps ? <SeriesChart points={pts} unit="pct" yMax={100} bucket={b}
        series={[{ key: "rx_util", name: "RX %" }, { key: "tx_util", name: "TX %" }]} /> : <Empty text="No reliable interface speed: utilisation is not calculated." />}</Section>
      <Section title="Errors and discards (per bucket)"><SeriesChart points={pts} unit="count" bucket={b} series={[{ key: "in_errors", name: "In errors", bar: true, color: "alert" },
        { key: "out_errors", name: "Out errors", bar: true, color: "warn" }, { key: "crc", name: "CRC / FCS", bar: true }, { key: "in_discards", name: "In discards", bar: true, color: "muted" },
        { key: "out_discards", name: "Out discards", bar: true }]} /></Section>
      {pts.some((p: any) => p.rx_pps != null) && <Section title="Packet rate"><SeriesChart points={pts} unit="count" bucket={b} series={[{ key: "rx_pps", name: "RX pps" }, { key: "tx_pps", name: "TX pps" }]} /></Section>}
      <KV rows={[["Description", x.alias || "—"], ["ifDescr", x.descr], ["Kind / ifType", `${x.kind} / ${x.type ?? "—"}`], ["MAC", <span className="font-mono">{x.mac || "—"}</span>],
        ["VLANs", `${x.mode || "—"}${d.vlans.untagged.length ? ` · untagged ${d.vlans.untagged.join(", ")}` : ""}${d.vlans.tagged.length ? ` · tagged ${d.vlans.tagged.join(", ")}` : ""}`],
        ["LAG", d.lag ? `${d.lag.name}: ${d.lag.up_members}/${d.lag.total_members} members in bundle` : "—"],
        ["PoE", x.poe ? `${x.poe.status}, class ${x.poe.class ?? "—"}, ${fmtWatts(x.poe.power_w)} (allocated ${fmtWatts(x.poe.allocated_w)})` : "—"],
        ["MAC addresses learned", fmtNum(d.mac_count)], ["Last state change", <Time v={x.last_change_at} />], ["Last sample", <Time v={x.last_sample_at} />],
        ["Sample note", x.note || "—"]]} />
      <Section title={`Alerts (${d.alerts.length})`}>{!d.alerts.length ? <Empty text="No alerts for this interface." /> :
        <TableWrap><table className="tbl"><tbody>{d.alerts.map((a: any) => <tr key={a.id}><td><Sev s={a.severity} /></td><td>{a.name}</td><td>{a.status}</td><td><Time v={a.last_seen} /></td>
          <td className="text-xs">{a.explanation}</td></tr>)}</tbody></table></TableWrap>}</Section>
      <Section title={`State changes and events (${d.events.length})`}><EventTable rows={d.events} showSwitch={false} /></Section>
    </div>}
  </Drawer>;
}

function Vlans({ sid }: { sid: number }) {
  const q = useQuery({ queryKey: ["switch-vlans", sid], queryFn: () => api<any>(`/switches/${sid}/vlans`) });
  const ports = (l: any[]) => l.length ? <span className="text-xs font-mono">{l.slice(0, 24).map((p) => p.name).join(", ")}{l.length > 24 ? ` +${l.length - 24}` : ""}</span> : <span className="text-slate-600">—</span>;
  return <div className="space-y-4">
    <Card title={`VLANs${q.data ? ` (${q.data.items.filter((v: any) => v.present).length})` : ""}`} bodyClass="p-0">
      <Loading q={q} />
      {q.data && (!q.data.items.length ? <Empty text="No VLAN data collected yet." /> :
        <TableWrap><table className="tbl"><thead><tr><th className="num">VLAN</th><th>Name</th><th>State</th><th>SVI</th><th className="num">Untagged</th><th>Untagged ports</th>
          <th className="num">Tagged</th><th>Tagged (trunk) ports</th><th>First seen</th></tr></thead>
          <tbody>{q.data.items.map((v: any) => <tr key={v.vlan_id} className={v.present ? "" : "opacity-50"}><td className="num">{v.vlan_id}</td><td>{v.name || "—"}</td>
            <td className="text-xs">{v.present ? v.state : "removed"}</td><td className="text-xs">{v.svi ? <>{v.svi.name} <Oper s={v.svi.oper} /></> : "—"}</td>
            <td className="num">{v.untagged.length}</td><td>{ports(v.untagged)}</td><td className="num">{v.tagged.length}</td><td>{ports(v.tagged)}</td><td><Time v={v.first_seen} /></td></tr>)}
          </tbody></table></TableWrap>)}
      {q.data && <p className="text-2xs text-muted p-2">SVI mapping: {q.data.svi_mapping}.</p>}
    </Card>
    <Card title="VLAN changes" bodyClass="p-0"><EventTable rows={q.data?.changes || []} showSwitch={false} /></Card>
  </div>;
}

function Macs({ sid }: { sid: number }) {
  const [q, setQ] = useState("");
  const [vlan, setVlan] = useState("");
  const [page, setPage] = useState(0);
  const dq = useDebounced(q, 300);
  const r = useQuery<any>({ queryKey: ["switch-macs", sid, dq, vlan, page], placeholderData: (p: any) => p,
    queryFn: ({ signal }) => api<any>(`/switches/${sid}/macs`, { signal, params: { q: dq || undefined, vlan: vlan || undefined, limit: 200, offset: page * 200 } }) });
  return <div className="space-y-4">
    <Card title={`MAC address table${r.data ? ` (${r.data.total})` : ""}`} bodyClass="p-0" right={<>
      <input aria-label="MAC or port" className="input py-1 w-44" placeholder="MAC or port" value={q} onChange={(e) => { setQ(e.target.value); setPage(0); }} />
      <input aria-label="VLAN" className="input py-1 w-20" placeholder="VLAN" value={vlan} onChange={(e) => { setVlan(e.target.value.replace(/\D/g, "").slice(0, 4)); setPage(0); }} /></>}>
      <Loading q={r} />
      {r.data && (!r.data.items.length ? <Empty text="No MAC addresses (table not collected yet, not supported, or no match)." /> :
        <TableWrap><table className="tbl"><thead><tr><th>MAC</th><th className="num">VLAN</th><th>Port</th><th>Type</th><th className="num">Moves</th><th>First seen</th><th>Last seen</th></tr></thead>
          <tbody>{r.data.items.map((m: any) => <tr key={`${m.mac}-${m.vlan}`}><td className="font-mono text-xs">{m.mac}</td><td className="num">{m.vlan || "—"}</td><td className="font-mono text-xs">{m.port || "—"}</td>
            <td className="text-xs">{m.status}</td><td className={`num ${m.moves ? "text-amber-300" : ""}`}>{m.moves}</td><td><Time v={m.first_seen} /></td><td><Time v={m.last_seen} /></td></tr>)}</tbody></table></TableWrap>)}
      {r.data && r.data.total > 200 && <div className="flex gap-2 p-2"><button className="btn" disabled={!page} onClick={() => setPage(page - 1)}>Previous</button>
        <button className="btn" disabled={(page + 1) * 200 >= r.data.total} onClick={() => setPage(page + 1)}>Next</button></div>}
    </Card>
    <Card title="MAC movement and learning bursts" bodyClass="p-0"><EventTable rows={r.data?.moves || []} showSwitch={false} />
      <p className="text-2xs text-muted p-2">A move is a MAC seen on a different port than in the previous poll (moves between members of the same port-channel are ignored). One move is
        normal (a device re-plugged); repeated moves of one MAC or many MACs at once suggest a loop, a misconfigured LAG or spoofing — see the MAC movement alert rule thresholds.</p></Card>
  </div>;
}

function Stp({ d, sid }: { d: any; sid: number }) {
  const stp = d.health?.stp;
  const ev = useQuery({ queryKey: ["switch-ev-stp", sid], queryFn: () => api<any>("/switches/events", { params: { switch_id: sid, range: "7d", kind: ["stp_root_change", "stp_topology_change", "stp_port_state"], limit: 200 } }) });
  if (!stp) return <Card><Empty text="Spanning-tree data not available on this switch." /></Card>;
  return <div className="space-y-4">
    <div className="kpi-grid">
      <Kpi label="Mode" value={stp.mode || "—"} /><Kpi label="Root bridge" value={<span className="text-sm font-mono">{stp.root || "—"}</span>} sub={stp.is_root ? "this switch is root" : undefined} />
      <Kpi label="Topology changes (total)" value={stp.topology_changes == null ? "—" : fmtNum(stp.topology_changes)} /><Kpi label="Instances" value={Object.keys(stp.instances || {}).length} />
    </div>
    {Object.entries(stp.instances || {}).map(([k, inst]: [string, any]) => <Card key={k} title={k === "default" ? "Default instance (CST / VLAN 1 on PVST)" : k.replace("vlan", "VLAN ")} bodyClass="p-0"
      right={<span className="text-xs text-muted">root {inst.root} {inst.is_root ? "(this switch)" : `via ${inst.root_port_name || inst.root_port_ifindex || "—"}, cost ${inst.root_cost ?? "—"}`}
        · {inst.topology_changes ?? "—"} TCs · last {inst.since_topology_change_s == null ? "—" : fmtUptime(inst.since_topology_change_s)} ago</span>}>
      <TableWrap maxH="max-h-72"><table className="tbl"><thead><tr><th>Port</th><th className="num">Bridge port</th><th>Role</th><th>State</th><th className="num">Forward transitions</th></tr></thead>
        <tbody>{Object.values(inst.ports || {}).map((p: any) => <tr key={p.bridge_port}><td className="font-mono text-xs">{p.name}</td><td className="num">{p.bridge_port}</td>
          <td>{p.role}</td><td className={p.state === "blocking" || p.state === "broken" ? "text-amber-300" : ""}>{p.state}</td><td className="num">{p.forward_transitions ?? "—"}</td></tr>)}</tbody></table></TableWrap>
    </Card>)}
    <p className="text-2xs text-muted">Port roles are derived from BRIDGE-MIB (root port, designated bridge, state); BRIDGE-MIB has no role column.</p>
    <Card title="STP events (7 days)" bodyClass="p-0"><EventTable rows={ev.data?.items || []} showSwitch={false} /></Card>
  </div>;
}

function Neighbors({ sid, site }: { sid: number; site: string }) {
  const [sp, setSp] = useSearchParams();
  const q = useQuery({ queryKey: ["switch-nbr", sid], queryFn: () => api<any>(`/switches/${sid}/neighbors`), refetchInterval: 60_000 });
  const ev = useQuery({ queryKey: ["switch-ev-nbr", sid], queryFn: () => api<any>("/switches/events", { params: { switch_id: sid, range: "7d",
    kind: ["neighbor_added", "neighbor_removed", "neighbor_changed"], limit: 200 } }) });
  const open = (ifx: number) => { const n = new URLSearchParams(sp); n.set("if", String(ifx)); setSp(n); };
  return <div className="space-y-4">
    <Card title={`LLDP / CDP neighbors${q.data ? ` (${q.data.items.filter((x: any) => x.present).length})` : ""}`} bodyClass="p-0"
      right={<Link className="btn" to={`/switches?tab=topology${site ? `&site=${encodeURIComponent(site)}` : ""}`}>Show in topology</Link>}>
      <Loading q={q} />
      {q.data && (!q.data.items.length ? <Empty text="No neighbors reported: LLDP / CDP may be disabled, or the switch does not expose LLDP-MIB (see Monitoring health)." /> :
        <TableWrap><table className="tbl"><thead><tr><th>Local port</th><th>Link</th><th>Neighbor</th><th>Type</th><th>Remote port</th><th>Management IP</th><th>Protocol</th>
          <th>State</th><th>First seen</th><th>Last seen</th></tr></thead>
          <tbody>{q.data.items.map((n: any, i: number) => <tr key={i} className={n.present ? "" : "opacity-60"} {...(n.local_ifindex != null ? rowProps(() => open(n.local_ifindex)) : {})}>
            <td className="font-mono text-xs">{n.local_port}</td><td><Oper s={n.local_oper} /></td>
            <td>{n.matched_switch ? <Link className="link" to={`/switches/${n.matched_switch.id}?tab=neighbors`} onClick={(e) => e.stopPropagation()}>{n.remote_name}</Link> : n.remote_name || n.chassis_id}
              {n.remote_descr && <div className="text-2xs text-muted max-w-[18rem] truncate" title={n.remote_descr}>{n.remote_descr}</div>}</td>
            <td className="text-xs">{n.type}</td><td className="font-mono text-xs">{n.remote_port || "—"}{n.remote_port_desc && <div className="text-2xs text-muted">{n.remote_port_desc}</div>}</td>
            <td className="font-mono text-xs">{n.remote_mgmt_ip || "—"}</td><td className="text-xs">{n.protocol}</td>
            <td className={n.present ? "text-emerald-300" : "text-red-300"}>{n.present ? "present" : "lost"}</td><td><Time v={n.first_seen} /></td><td><Time v={n.last_seen} /></td></tr>)}</tbody></table></TableWrap>)}
    </Card>
    <Card title="Neighbor changes (7 days)" bodyClass="p-0"><EventTable rows={ev.data?.items || []} showSwitch={false} /></Card>
  </div>;
}

function Lacp({ d }: { d: any }) {
  const lags = Object.values(d.health?.lacp?.lags || {}) as any[];
  if (!lags.length) return <Card><Empty text="No link aggregation reported." /></Card>;
  return <div className="space-y-4">{lags.map((l) => <Card key={l.ifindex} title={`${l.name} · ${l.up_members}/${l.total_members} members in bundle`} bodyClass="p-0"
    right={<Oper s={l.oper} />}>
    <TableWrap><table className="tbl"><thead><tr><th>Member</th><th>Protocol</th><th>Link</th><th>In bundle</th><th className="w-full">LACP actor state</th></tr></thead>
      <tbody>{l.members.map((m: any) => <tr key={m.ifindex}><td className="font-mono text-xs">{m.name}</td><td className="text-xs">{m.protocol}</td><td><Oper s={m.oper} /></td>
        <td className={m.in_bundle === false ? "text-red-300" : "text-emerald-300"}>{m.in_bundle == null ? "n/a (not LACP)" : m.in_bundle ? "yes" : "no"}</td>
        <td className="text-xs">{Object.keys(m.state || {}).join(", ") || "—"}</td></tr>)}</tbody></table></TableWrap>
  </Card>)}</div>;
}

function Poe({ d, sid }: { d: any; sid: number }) {
  const [range, setRange] = useState("24h");
  const used = useSeries(sid, "poe_used", range);
  const ifs = useQuery({ queryKey: ["switch-if", sid, "poe"], queryFn: () => api<any>(`/switches/${sid}/interfaces`, { params: { limit: 2000 } }) });
  const ports = (ifs.data?.items || []).filter((x: any) => x.poe);
  const p = d.health?.poe;
  const u = multi(used.data);
  if (!p) return <Card><Empty text="This switch reports no PoE data." /></Card>;
  return <div className="space-y-4">
    <div className="kpi-grid">
      <Kpi label="Budget" value={fmtWatts(p.budget_w)} /><Kpi label="In use" value={fmtWatts(p.used_w)} sub={fmtPctOrDash(d.poe_pct, 0)} tone={statusTone(d.poe_pct, 75, 90)} />
      <Kpi label="Available" value={p.budget_w != null && p.used_w != null ? fmtWatts(p.budget_w - p.used_w) : "—"} />
      <Kpi label="Ports delivering" value={p.ports_delivering ?? "—"} /><Kpi label="Ports in fault" value={p.ports_fault ?? "—"} tone={p.ports_fault ? "bad" : "ok"} />
    </div>
    <Card title="Power units" bodyClass="p-0"><TableWrap><table className="tbl"><thead><tr><th>Unit</th><th className="num">Budget</th><th className="num">In use</th><th>Status</th><th>Source</th></tr></thead>
      <tbody>{p.units.map((x: any) => <tr key={x.unit}><td>{x.unit}</td><td className="num">{fmtWatts(x.budget_w)}</td><td className="num">{fmtWatts(x.used_w)}</td><td>{x.status}</td>
        <td className="text-xs text-muted">{x.source}</td></tr>)}</tbody></table></TableWrap></Card>
    <Card title="Power in use" right={<RangeSelect value={range} onChange={setRange} />}>
      <SeriesChart points={u.points} unit="w" bucket={used.data?.bucket_seconds} series={u.keys.map((k) => ({ key: k, name: k }))} /></Card>
    <Card title={`Ports (${ports.length})`} bodyClass="p-0">
      {!ports.length ? <Empty text="No per-port PoE data mapped to interfaces." /> :
        <TableWrap><table className="tbl"><thead><tr><th>Port</th><th>Description</th><th>Admin</th><th>Status</th><th className="num">Class</th><th>Priority</th><th className="num">Power</th>
          <th className="num">Allocated</th></tr></thead>
          <tbody>{ports.map((x: any) => <tr key={x.ifindex}><td className="font-mono text-xs">{x.name}</td><td><Trunc text={x.alias} max="max-w-[12rem]" /></td><td>{x.poe.admin || "—"}</td>
            <td className={x.poe.status?.includes("fault") ? "text-red-300" : ""}>{x.poe.status}</td><td className="num">{x.poe.class ?? "—"}</td><td>{x.poe.priority || "—"}</td>
            <td className="num">{fmtWatts(x.poe.power_w)}</td><td className="num">{fmtWatts(x.poe.allocated_w)}</td></tr>)}</tbody></table></TableWrap>}
      {!!p.ports_unmapped && <p className="text-2xs text-muted p-2">{p.ports_unmapped} PoE port(s) could not be mapped to an interface name and are not listed.</p>}
    </Card>
  </div>;
}

function Hardware({ d, sid }: { d: any; sid: number }) {
  const [range, setRange] = useState("24h");
  const t = useSeries(sid, "temperature", range);
  const tt = multi(t.data);
  const h = d.health || {};
  const env = h.environment || {};
  const st = (s: string) => <span className={s === "ok" ? "text-emerald-300" : ["absent", "unknown"].includes(s) ? "text-muted" : "text-red-300"}>{s}</span>;
  return <div className="space-y-4">
    <div className="grid gap-4 xl:grid-cols-2">
      <Card title="CPU" bodyClass="p-0">{!h.cpu ? <Empty text="CPU utilisation not reported by this switch." /> :
        <TableWrap><table className="tbl"><thead><tr><th>CPU</th><th className="num">5 s</th><th className="num">1 min</th><th className="num">5 min</th></tr></thead>
          <tbody>{h.cpu.cpus.map((c: any) => <tr key={c.id}><td>{c.name}</td><td className="num"><Util v={c.pct_5s} /></td><td className="num"><Util v={c.pct_1m} /></td><td className="num"><Util v={c.pct_5m} /></td></tr>)}</tbody></table></TableWrap>}
        {h.memory && <div className="p-3 text-sm">Memory {fmtPctOrDash(h.memory.pct)} used{h.memory.total_bytes ? ` of ${(h.memory.total_bytes / 2 ** 30).toFixed(2)} GiB` : ""}
          <span className="text-2xs text-muted"> · {h.memory.source}</span></div>}
        {h.cpu?.load && <div className="px-3 pb-3 text-sm">Load average {["1m", "5m", "15m"].map((k) => h.cpu.load[k] ?? "—").join(" / ")}
          <span className="text-2xs text-muted"> · 1 / 5 / 15 min (UCD-SNMP-MIB)</span></div>}</Card>
      <Card title="Stack / chassis" bodyClass="p-0">{!h.stack ? <Empty text="Not a stack, or stack data not reported." /> : <>
        <div className="p-3 text-sm">Topology {h.stack.topology || "—"}{h.stack.ring_redundant != null && ` · ring ${h.stack.ring_redundant ? "redundant" : "NOT redundant"}`}
          {h.stack.stack_ports_down != null && ` · stack ports down: ${h.stack.stack_ports_down}`}{h.stack.topology_source && <span className="text-2xs text-muted"> ({h.stack.topology_source})</span>}</div>
        <TableWrap><table className="tbl"><thead><tr><th className="num">Unit</th><th>Role</th><th>State</th><th className="num">Priority</th><th>MAC</th><th>Model / firmware</th></tr></thead>
          <tbody>{h.stack.members.map((m: any) => <tr key={m.unit}><td className="num">{m.unit}</td><td>{m.role}</td><td>{st(m.healthy ? "ok" : m.state)} <span className="text-2xs text-muted">{m.state}</span></td>
            <td className="num">{m.priority ?? "—"}</td><td className="font-mono text-xs">{m.mac || "—"}</td><td className="text-xs">{[m.model, m.firmware].filter(Boolean).join(" · ") || "—"}</td></tr>)}</tbody></table></TableWrap></>}</Card>
      <Card title="Power supplies and fans" bodyClass="p-0">{!env.psus?.length && !env.fans?.length ? <Empty text="Not reported by this switch." /> :
        <TableWrap><table className="tbl"><thead><tr><th>Component</th><th>Kind</th><th>State</th></tr></thead>
          <tbody>{[...(env.psus || []).map((x: any) => ({ ...x, k: "power supply" })), ...(env.fans || []).map((x: any) => ({ ...x, k: "fan" }))].map((x: any) =>
            <tr key={x.k + x.name}><td>{x.name}</td><td className="text-xs">{x.k}</td><td>{st(x.state)}</td></tr>)}</tbody></table></TableWrap>}</Card>
      <Card title="Temperature sensors" bodyClass="p-0">{!env.temperatures?.length ? <Empty text="Not reported by this switch." /> :
        <TableWrap><table className="tbl"><thead><tr><th>Sensor</th><th className="num">°C</th><th className="num">Threshold</th><th>State</th></tr></thead>
          <tbody>{env.temperatures.map((x: any) => <tr key={x.name}><td>{x.name}</td><td className="num">{x.celsius ?? "—"}</td><td className="num">{x.threshold ?? "—"}</td><td>{st(x.state)}</td></tr>)}</tbody></table></TableWrap>}</Card>
      <Card title="Disks, flash and file systems" bodyClass="p-0">{!h.storage?.length ? <Empty text="Not reported (HOST-RESOURCES-MIB hrStorage not exposed by this device)." /> :
        <TableWrap><table className="tbl"><thead><tr><th>Volume</th><th>Kind</th><th className="num">Size</th><th className="num">Used</th><th className="num">Used %</th></tr></thead>
          <tbody>{h.storage.map((v: any) => <tr key={v.index}><td className="font-mono text-xs">{v.name}</td><td className="text-xs">{v.kind.replace("_", " ")}</td>
            <td className="num">{fmtBytes(v.size_bytes)}</td><td className="num">{fmtBytes(v.used_bytes)}</td><td className="num"><Util v={v.pct} /></td></tr>)}</tbody></table></TableWrap>}</Card>
      {h.vendor && <VendorHealth v={h.vendor} />}
      {!!h.custom?.length && <Card title="Custom OIDs" bodyClass="p-0"><TableWrap maxH="max-h-72"><table className="tbl">
        <thead><tr><th>Item</th><th>Index</th><th className="num">Value</th><th>Raw</th><th>Status</th></tr></thead>
        <tbody>{h.custom.map((x: any, i: number) => <tr key={i}><td className="font-mono text-xs">{x.name}</td><td className="text-xs">{x.index || "—"}</td>
          <td className="num">{x.rate_per_s != null ? `${x.rate_per_s.toFixed(2)}/s` : x.value != null ? `${x.value}${x.unit ? " " + x.unit : ""}` : "—"}</td>
          <td className="font-mono text-2xs">{x.raw == null ? "—" : String(x.raw)}</td><td className="text-xs">{x.status}</td></tr>)}</tbody></table></TableWrap></Card>}
      {!!env.sensors?.length && <Card title="Other sensors (ENTITY-SENSOR-MIB)" bodyClass="p-0">
        <TableWrap><table className="tbl"><thead><tr><th>Sensor</th><th>Kind</th><th className="num">Value</th><th>State</th></tr></thead>
          <tbody>{env.sensors.map((x: any) => <tr key={x.kind + x.name}><td>{x.name}</td><td className="text-xs">{x.kind}</td><td className="num">{x.value} {x.unit}</td>
            <td>{st(x.state)}</td></tr>)}</tbody></table></TableWrap></Card>}
    </div>
    <Card title="Temperature history" right={<RangeSelect value={range} onChange={setRange} />}>
      <SeriesChart points={tt.points} unit="c" bucket={t.data?.bucket_seconds} series={tt.keys.map((k) => ({ key: k, name: k }))} /></Card>
    <Card title={`Hardware inventory (${(h.inventory || []).length})`} bodyClass="p-0">{!h.inventory?.length ? <Empty text="ENTITY-MIB inventory not reported." /> :
      <TableWrap maxH="max-h-96"><table className="tbl"><thead><tr><th>Class</th><th>Name</th><th>Model</th><th>Serial</th><th>HW</th><th>SW</th><th className="w-full">Description</th></tr></thead>
        <tbody>{h.inventory.map((i: any) => <tr key={String(i.index)}><td className="text-xs">{i.class}</td><td>{i.name}</td><td className="font-mono text-xs">{i.model || "—"}</td>
          <td className="font-mono text-xs">{i.serial || "—"}</td><td className="text-xs">{i.hw || "—"}</td><td className="text-xs">{i.sw || "—"}</td><td className="text-xs">{i.descr}</td></tr>)}</tbody></table></TableWrap>}</Card>
  </div>;
}

function Routing({ d, sid }: { d: any; sid: number }) {
  const r = d.health?.routing;
  const [range, setRange] = useState("24h");
  const rc = useSeries(sid, "routes", range);
  const rr = multi(rc.data);
  if (!r) return <Card><Empty text="No layer-3 data reported." /></Card>;
  return <div className="space-y-4">
    <div className="kpi-grid"><Kpi label="IP interfaces" value={r.ip_interfaces.length} /><Kpi label="Routes" value={r.route_count ?? "—"} />
      <Kpi label="OSPF neighbors" value={r.ospf.length ? `${r.ospf.filter((n: any) => n.state === "full").length} / ${r.ospf.length} full` : "—"} />
      <Kpi label="BGP peers" value={r.bgp.length ? `${r.bgp.filter((n: any) => n.state === "established").length} / ${r.bgp.length} up` : "—"} /></div>
    <div className="grid gap-4 xl:grid-cols-2">
      <Card title="IP interfaces" bodyClass="p-0">{!r.ip_interfaces.length ? <Empty text="None reported." /> :
        <TableWrap maxH="max-h-80"><table className="tbl"><thead><tr><th>Address</th><th>Mask</th><th className="num">ifIndex</th></tr></thead>
          <tbody>{r.ip_interfaces.map((i: any) => <tr key={i.ip}><td className="font-mono text-xs">{i.ip}</td><td className="font-mono text-xs">{i.mask}</td><td className="num">{i.ifindex}</td></tr>)}</tbody></table></TableWrap>}</Card>
      <Card title="Routing neighbors" bodyClass="p-0">{!r.ospf.length && !r.bgp.length ? <Empty text="No OSPF or BGP neighbors reported (not configured, or the MIB is not exposed)." /> :
        <TableWrap><table className="tbl"><thead><tr><th>Protocol</th><th>Neighbor</th><th>Router ID / AS</th><th>State</th></tr></thead>
          <tbody>{r.ospf.map((n: any) => <tr key={`o${n.neighbor}`}><td>OSPF</td><td className="font-mono text-xs">{n.neighbor}</td><td className="font-mono text-xs">{n.router_id}</td>
            <td className={n.state === "full" ? "text-emerald-300" : "text-amber-300"}>{n.state}</td></tr>)}
            {r.bgp.map((n: any) => <tr key={`b${n.peer}`}><td>BGP</td><td className="font-mono text-xs">{n.peer}</td><td>AS {n.remote_as ?? "—"}</td>
              <td className={n.state === "established" ? "text-emerald-300" : "text-amber-300"}>{n.state}{n.established_s != null && ` (${fmtUptime(n.established_s)})`}</td></tr>)}</tbody></table></TableWrap>}</Card>
    </div>
    {r.route_count != null && <Card title="Route table size" right={<RangeSelect value={range} onChange={setRange} />}>
      <SeriesChart points={rr.points} unit="count" bucket={rc.data?.bucket_seconds} series={[{ key: rr.keys[0] || "value", name: "routes" }]} /></Card>}
  </div>;
}

function EventsTab({ d, sid }: { d: any; sid: number }) {
  const [range, setRange] = useState("24h");
  const q = useQuery({ queryKey: ["switch-ev", sid, range], queryFn: () => api<any>("/switches/events", { params: { switch_id: sid, range, limit: 500 } }), refetchInterval: 30_000 });
  return <div className="space-y-4">
    <Card title={`Alerts (${d.alerts.length})`} bodyClass="p-0">{!d.alerts.length ? <Empty text="No alerts for this switch." /> :
      <TableWrap maxH="max-h-80"><table className="tbl"><thead><tr><th>Severity</th><th>Alert</th><th>Status</th><th>First seen</th><th>Last seen</th><th className="w-full">Explanation</th></tr></thead>
        <tbody>{d.alerts.map((a: any) => <tr key={a.id}><td><Sev s={a.severity} /></td><td><Link className="link" to={`/alerts?id=${a.id}`}>{a.name}</Link></td><td>{a.status}</td>
          <td><Time v={a.first_seen} /></td><td><Time v={a.last_seen} /></td><td className="text-xs">{a.explanation}</td></tr>)}</tbody></table></TableWrap>}</Card>
    <Card title={`Events${q.data ? ` (${q.data.total})` : ""}`} bodyClass="p-0" right={<RangeSelect value={range} onChange={setRange} />}>
      <Loading q={q} />{q.data && <EventTable rows={q.data.items} showSwitch={false} />}</Card>
  </div>;
}

function Health({ sid }: { sid: number }) {
  const caps = useQuery({ queryKey: ["switch-caps", sid], queryFn: () => api<any>(`/switches/${sid}/capabilities`), refetchInterval: 60_000 });
  const polls = useQuery({ queryKey: ["switch-polls", sid], queryFn: () => api<any>(`/switches/${sid}/polls`, { params: { limit: 200 } }), refetchInterval: 60_000 });
  const [range, setRange] = useState("24h");
  const dur = useSeries(sid, "poll_duration", range);
  const dd = multi(dur.data);
  const c = caps.data;
  return <div className="space-y-4">
    {c && <div className="kpi-grid">
      <Kpi label="Coverage" value={c.coverage.percent == null ? "—" : `${c.coverage.percent}%`} sub="healthy / supported" />
      {["healthy", "unavailable", "failed", "stale", "unsupported", "not_configured"].map((k) => <Kpi key={k} label={k.replace("_", " ")} value={c.coverage.counts[k] || 0}
        tone={k === "failed" && c.coverage.counts[k] ? "bad" : (k === "stale" || k === "unavailable") && c.coverage.counts[k] ? "warn" : undefined} />)}
      <Kpi label="Poll success" value={fmtPctOrDash(polls.data?.success_pct)} sub={`last ${polls.data?.items.length || 0} polls`} />
      <Kpi label="Avg poll duration" value={polls.data?.avg_duration_ms == null ? "—" : `${polls.data.avg_duration_ms} ms`} />
    </div>}
    <Card title="Collection groups" bodyClass="p-0">{c && <TableWrap><table className="tbl"><thead><tr><th>Group</th><th className="num">Interval</th><th>Last run</th><th>Result</th>
      <th className="num">Duration</th><th className="w-full">Error</th></tr></thead>
      <tbody>{c.groups.map((g: any) => <tr key={g.group}><td>{g.label}</td><td className="num">{g.interval_seconds ? `${g.interval_seconds}s` : "disabled"}</td><td><Time v={g.last_run} /></td>
        <td>{g.last_run == null ? "—" : g.skipped ? <span className="text-amber-300">skipped</span> : g.ok ? <span className="text-emerald-300">ok</span> : <span className="text-red-300">failed</span>}</td>
        <td className="num">{g.duration_ms == null ? "—" : `${g.duration_ms} ms`}</td><td className="text-xs text-red-300">{g.error || ""}</td></tr>)}</tbody></table></TableWrap>}</Card>
    <Card title="Metric capabilities" bodyClass="p-0">{c && <TableWrap maxH="max-h-[32rem]"><table className="tbl"><thead><tr><th>Metric</th><th>Category</th><th>Status</th><th>Source (MIB)</th>
      <th>OID</th><th>Type</th><th>Unit</th><th className="num">Every</th><th>Last success</th><th className="w-full">Reason / last error</th></tr></thead>
      <tbody>{c.metrics.map((m: any) => <tr key={m.metric}><td className="font-mono text-xs">{m.metric}</td><td className="text-xs">{m.category}</td><td><MetricStatus s={m.status} /></td>
        <td className="text-xs">{m.source}</td><td className="font-mono text-2xs">{m.oid}</td><td className="text-xs">{m.type}</td><td className="text-xs">{m.unit || ""}</td>
        <td className="num text-xs">{m.interval_seconds ? `${m.interval_seconds}s` : "off"}</td><td><Time v={m.last_success} /></td>
        <td className="text-xs">{m.reason || (m.last_error ? <span className="text-red-300">{m.last_error.message}</span> : m.note)}</td></tr>)}</tbody></table></TableWrap>}</Card>
    <Card title="Poll duration" right={<RangeSelect value={range} onChange={setRange} />}>
      <SeriesChart points={dd.points} unit="raw" bucket={dur.data?.bucket_seconds} series={[{ key: dd.keys[0] || "value", name: "seconds" }]} /></Card>
    <Card title="Collection history" bodyClass="p-0">{polls.data && <TableWrap maxH="max-h-96"><table className="tbl"><thead><tr><th>Started</th><th>Kind</th><th>Result</th>
      <th className="num">Duration</th><th className="num">Requests</th><th className="w-full">Failed groups / error</th></tr></thead>
      <tbody>{polls.data.items.map((p: any) => <tr key={p.id}><td><Time v={p.started_at} /></td><td className="text-xs">{p.kind}</td>
        <td>{p.ok ? <span className="text-emerald-300">ok</span> : <span className="text-red-300">{Object.keys(p.groups || {}).length ? "partial" : "failed"}</span>}</td>
        <td className="num">{p.duration_ms} ms</td><td className="num">{p.requests}</td><td className="text-xs">{p.error}</td></tr>)}</tbody></table></TableWrap>}</Card>
  </div>;
}


/** Vendor-specific state from the adapter (FortiGate HA / IPsec / SD-WAN / sessions; Junos alarms, components, SRX SPU). */
function VendorHealth({ v }: { v: any }) {
  const tone = (ok: boolean | null | undefined) => ok == null ? "text-muted" : ok ? "text-emerald-300" : "text-red-300";
  return <Card title={`Vendor health (${v.family})`} bodyClass="p-0" className="xl:col-span-2">
    <div className="p-3 text-sm space-y-1">
      {!v.alarms?.length ? <div className="text-emerald-300">No active vendor condition.</div> :
        v.alarms.map((a: any) => <div key={a.key}><Sev s={a.severity} /> <b>{a.component}</b>: {a.detail}</div>)}
      {v.sessions != null && <div>Sessions: {fmtNum(v.sessions)}{v.max_sessions ? ` of ${fmtNum(v.max_sessions)}` : ""}</div>}
      {v.ha && <div>HA: {v.ha.mode || "not reported"}{v.ha.members?.map((m: any) => <span key={m.serial} className={`ml-2 ${tone(m.synchronized)}`}>
        {m.hostname || m.serial}{m.serial === m.primary_serial ? " (primary)" : ""}: {m.synchronized == null ? "?" : m.synchronized ? "in sync" : "NOT in sync"}</span>)}</div>}
      {v.disk?.pct != null && <div>Log disk: {v.disk.pct}% of {fmtNum(v.disk.capacity_mb)} MB</div>}
      {v.alarm_counts && <div>Chassis alarms: <span className={tone(!v.alarm_counts.red)}>{v.alarm_counts.red ?? "?"} red</span>,{" "}
        <span className={tone(!v.alarm_counts.yellow)}>{v.alarm_counts.yellow ?? "?"} yellow</span></div>}
    </div>
    {!!v.vpn_tunnels?.length && <TableWrap maxH="max-h-64"><table className="tbl"><thead><tr><th>IPsec phase 1 / 2</th><th>Remote gateway</th><th>State</th>
      <th className="num">In / out bytes</th></tr></thead><tbody>{v.vpn_tunnels.map((t: any, i: number) => <tr key={i}><td className="text-xs">{t.phase1} / {t.phase2}</td>
        <td className="font-mono text-xs">{t.remote_gw || "—"}</td><td className={tone(t.state == null ? null : t.state === "up")}>{t.state || "?"}</td>
        <td className="num text-xs">{fmtBytes(t.in_octets)} / {fmtBytes(t.out_octets)}</td></tr>)}</tbody></table></TableWrap>}
    {!!v.sdwan?.length && <TableWrap maxH="max-h-64"><table className="tbl"><thead><tr><th>SD-WAN health check</th><th>Interface</th><th>State</th><th className="num">Latency</th>
      <th className="num">Jitter</th><th className="num">Loss</th></tr></thead><tbody>{v.sdwan.map((x: any, i: number) => <tr key={i}><td className="text-xs">{x.health_check}</td>
        <td className="text-xs">{x.interface}</td><td className={tone(x.state == null ? null : x.state === "alive")}>{x.state || "?"}</td>
        <td className="num">{x.latency_ms ?? "—"} ms</td><td className="num">{x.jitter_ms ?? "—"} ms</td><td className="num">{x.loss_pct ?? "—"}%</td></tr>)}</tbody></table></TableWrap>}
    {!!v.components?.length && <TableWrap maxH="max-h-64"><table className="tbl"><thead><tr><th>Component (jnxOperatingTable)</th><th>State</th></tr></thead>
      <tbody>{v.components.map((c: any, i: number) => <tr key={i}><td className="text-xs">{c.name}</td>
        <td className={tone(["running", "ready", "standby"].includes(c.state) ? true : c.state === "down" ? false : null)}>{c.state}</td></tr>)}</tbody></table></TableWrap>}
  </Card>;
}
