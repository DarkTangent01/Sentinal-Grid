import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useMe } from "../lib/context";
import { useTheme } from "../lib/theme";
import { fmtDuration, fmtNum, getTimezone } from "../lib/format";
import { Chart, PALETTES, SERIES_ROLE, axisStyle } from "../components/Chart";
import { Card, Drawer, Empty, Kpi, Loading, Modal, TableWrap, Time, rowProps } from "../components/ui";

const STATE: Record<string, [string, string]> = {
  up: ["bg-emerald-400", "Up"], down: ["bg-red-500 animate-pulse", "Down"], degraded: ["bg-amber-400", "Degraded"],
  unknown: ["bg-slate-500", "Pending"], disabled: ["bg-slate-700", "Disabled"],
};
const dur = (s?: number | null) => (!s ? "—" : s >= 86400 ? `${(s / 86400).toFixed(1)}d` : fmtDuration(s));
const ms = (v?: number | null) => (v == null ? "—" : `${v.toFixed(1)} ms`);

function Dot({ s }: { s: string }) {
  const [c, l] = STATE[s] || STATE.unknown;
  return <span className="inline-flex items-center gap-1.5 whitespace-nowrap"><span className={`h-2.5 w-2.5 rounded-full ${c}`} aria-hidden />{l}</span>;
}

const BLANK = { name: "", address: "", isp_name: "", isp_link_id: null as number | null, site: "", enabled: true, interval_seconds: 30, probes: 3,
  timeout_ms: 1000, down_after: 3, up_after: 2, rtt_warn_ms: 150, loss_warn_pct: 20 };

export function IcmpMonitor() {
  const me = useMe();
  const qc = useQueryClient();
  const [range, setRange] = useState("24h");
  const [edit, setEdit] = useState<any>(null);
  const [sel, setSel] = useState<any>(null);
  const q = useQuery({ queryKey: ["icmp", range], queryFn: () => api<any>("/isp/icmp/overview", { params: { range } }), refetchInterval: 15_000, placeholderData: (p) => p });
  const sugg = useQuery({ queryKey: ["icmp-sugg"], queryFn: () => api<any[]>("/isp/icmp/suggestions"), enabled: me.role === "admin" });
  const addSugg = useMutation({ mutationFn: async (list: any[]) => { for (const x of list) await api("/isp/icmp/targets", { method: "POST", body: { ...BLANK, name: x.name.slice(0, 128), address: x.address, isp_link_id: x.isp_link_id } }); },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["icmp"] }); qc.invalidateQueries({ queryKey: ["icmp-sugg"] }); } });
  const d = q.data;
  const t = d?.totals || {};
  return (
    <div className="space-y-4 min-w-0">
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-xs text-muted flex-1 min-w-[16rem]">The SIEM pings each address on its own interval, like an NMS. A target goes <b>down</b> only after its consecutive-failure
          threshold and comes back <b>up</b> after consecutive good checks, so single lost packets do not create outages. Reachable but slow or lossy targets are <b>degraded</b>.
          This measures reachability from the SIEM's network, independently of the firewalls' own SD-WAN checks.</p>
        <select aria-label="Range" className="input py-1" value={range} onChange={(e) => setRange(e.target.value)}>
          {[["1h", "Last hour"], ["24h", "Last 24 h"], ["7d", "Last 7 days"], ["30d", "Last 30 days"]].map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
        {me.role === "admin" && <button className="btn btn-primary" onClick={() => setEdit({ ...BLANK })}>+ Monitor an address</button>}
      </div>
      {me.role === "admin" && !!sugg.data?.length && <Card title="Suggested from ISP links">
        <div className="flex flex-wrap items-center gap-2 text-sm">
          {sugg.data.map((x) => <span key={x.address} className="pill bg-slate-800 text-slate-300">{x.name} · <span className="font-mono">{x.address}</span></span>)}
          <button className="btn ml-auto" disabled={addSugg.isPending} onClick={() => addSugg.mutate(sugg.data!)}>Monitor all {sugg.data.length}</button>
        </div>
      </Card>}
      <Loading q={q} />
      {d && <>
        <div className="kpi-grid">
          <Kpi label="Monitored" value={fmtNum(t.targets)} />
          <Kpi label="Down now" value={fmtNum(t.down)} tone={t.down ? "bad" : "ok"} />
          <Kpi label="Degraded now" value={fmtNum(t.degraded)} tone={t.degraded ? "warn" : undefined} />
          <Kpi label="Outages" value={fmtNum(t.outages)} sub={`in ${range}`} tone={t.outages ? "warn" : "ok"} />
          <Kpi label="Total downtime" value={dur(t.downtime_s)} />
        </div>
        <Card title="Targets" right={<span className="text-2xs text-muted">refreshes every 15 s · click a row for RTT / loss history</span>}>
          {!d.targets.length ? <Empty text="No addresses monitored yet. Add your ISP WAN IPs, gateways or an upstream resolver (8.8.8.8)." /> :
            <TableWrap><table className="tbl"><thead><tr><th>State</th><th>Name</th><th>Address</th><th>Provider</th><th>Since</th><th className="num">Availability</th>
              <th className="num">Outages</th><th className="num">Downtime</th><th className="num">Longest</th><th className="num">RTT now</th><th className="num">RTT avg / p95</th>
              <th className="num">Jitter</th><th className="num">Loss</th><th>Last check</th><th className="num">Every</th>{me.role === "admin" && <th />}</tr></thead>
              <tbody>{d.targets.map((x: any) => <tr key={x.id} {...rowProps(() => setSel(x))}>
                <td><Dot s={x.state} /></td><td className="font-medium">{x.name}{x.site && <div className="text-2xs text-muted">{x.site}</div>}</td>
                <td className="font-mono text-xs">{x.address}</td><td className="text-xs">{x.isp}</td><td><Time v={x.state_since} /></td>
                <td className={`num ${x.availability != null && x.availability < 99.9 ? "text-red-300" : "text-emerald-300"}`}>{x.availability == null ? "—" : `${x.availability.toFixed(3)}%`}</td>
                <td className="num">{fmtNum(x.outages)}</td><td className="num">{dur(x.downtime_s)}</td><td className="num">{dur(x.longest_s)}</td>
                <td className="num">{ms(x.last_rtt_ms)}</td><td className="num">{ms(x.rtt_ms)} / {ms(x.rtt_p95_ms)}</td><td className="num">{ms(x.jitter_ms)}</td>
                <td className={`num ${(x.loss_pct || 0) >= x.loss_warn_pct ? "text-amber-300" : ""}`}>{x.loss_pct == null ? "—" : `${x.loss_pct.toFixed(2)}%`}</td>
                <td><Time v={x.last_check} /></td><td className="num text-xs">{x.interval_seconds}s</td>
                {me.role === "admin" && <td><button className="btn" onClick={(e) => { e.stopPropagation(); setEdit(x); }}>Edit</button></td>}
              </tr>)}</tbody></table></TableWrap>}
        </Card>
        <Card title={`Up / down events (${d.events.length})`} bodyClass="p-0">
          {!d.events.length ? <Empty text="No state changes in this range." /> :
            <TableWrap maxH="max-h-96"><table className="tbl"><thead><tr><th>Time</th><th>Target</th><th>Change</th><th className="num">Previous state lasted</th><th className="w-full">Detail</th></tr></thead>
              <tbody>{d.events.map((e: any, i: number) => <tr key={i}><td><Time v={e.at} /></td><td>{e.name} <span className="font-mono text-2xs text-muted">{e.address}</span></td>
                <td className="nowrap"><Dot s={e.from} /> → <Dot s={e.to} /></td><td className="num">{dur(e.previous_duration_s)}</td><td className="text-xs">{e.detail}</td></tr>)}</tbody></table></TableWrap>}
        </Card>
      </>}
      {edit && <TargetForm t={edit} onClose={() => { setEdit(null); qc.invalidateQueries({ queryKey: ["icmp"] }); qc.invalidateQueries({ queryKey: ["icmp-sugg"] }); }} />}
      {sel && <TargetDrawer x={sel} range={range} admin={me.role === "admin"} onClose={() => setSel(null)} />}
    </div>
  );
}

function TargetDrawer({ x, range, admin, onClose }: { x: any; range: string; admin: boolean; onClose: () => void }) {
  const { theme } = useTheme();
  const q = useQuery({ queryKey: ["icmp-ts", x.id, range], queryFn: () => api<any>(`/isp/icmp/targets/${x.id}/timeseries`, { params: { range } }), refetchInterval: 30_000 });
  const probe = useMutation({ mutationFn: () => api<any>(`/isp/icmp/targets/${x.id}/probe`, { method: "POST" }) });
  const option = useMemo(() => {
    const p = q.data?.points || [];
    const sym = p.length < 40;  // a line with hidden markers draws nothing for a single point
    const fmt = (v: number) => new Date(v).toLocaleString(undefined, { hour: "2-digit", minute: "2-digit", month: range === "7d" || range === "30d" ? "short" : undefined,
      day: range === "7d" || range === "30d" ? "2-digit" : undefined, hour12: false, timeZone: getTimezone() });
    return {
      legend: { top: 0 }, tooltip: { trigger: "axis", confine: true },
      xAxis: { type: "time", ...axisStyle, axisLabel: { ...axisStyle.axisLabel, formatter: fmt } },
      yAxis: [{ type: "value", name: "ms", ...axisStyle }, { type: "value", name: "loss %", min: 0, max: 100, ...axisStyle, splitLine: { show: false } }],
      series: [
        { name: "RTT avg", type: "line", showSymbol: sym, itemStyle: { color: PALETTES[theme][0] }, data: p.map((r: any) => [Date.parse(r.t), r.rtt]) },
        { name: "RTT max", type: "line", showSymbol: sym, lineStyle: { width: 1, type: "dashed" }, itemStyle: { color: "#9c9c9c" }, data: p.map((r: any) => [Date.parse(r.t), r.rtt_max]) },
        { name: "Jitter", type: "line", showSymbol: sym, itemStyle: { color: PALETTES[theme][2] }, data: p.map((r: any) => [Date.parse(r.t), r.jitter]) },
        { name: "Loss %", type: "bar", yAxisIndex: 1, barMaxWidth: 6, itemStyle: { color: SERIES_ROLE[theme].alert }, data: p.map((r: any) => [Date.parse(r.t), r.loss]) },
      ],
    };
  }, [q.data, theme, range]);
  return (
    <Drawer title={`${x.name} · ${x.address}`} onClose={onClose}>
      <div className="space-y-4">
        <div className="text-sm flex flex-wrap gap-x-4 gap-y-1"><Dot s={x.state} /><span>since <Time v={x.state_since} /></span><span>provider {x.isp}</span>
          <span className="text-muted">{x.probes} probes every {x.interval_seconds}s · timeout {x.timeout_ms} ms · down after {x.down_after} failed checks · up after {x.up_after} good</span></div>
        {admin && <div className="flex flex-wrap items-center gap-2">
          <button className="btn" disabled={probe.isPending} onClick={() => probe.mutate()}>{probe.isPending ? "Pinging…" : "Ping now"}</button>
          {probe.data && <span className="text-sm">{probe.data.received}/{probe.data.sent} replies{probe.data.rtt_avg != null && `, avg ${probe.data.rtt_avg} ms`}
            {probe.data.rtts?.length > 0 && <span className="text-muted"> ({probe.data.rtts.join(" / ")} ms)</span>}{probe.data.error && <span className="text-red-300"> {probe.data.error}</span>}</span>}
        </div>}
        <Card title="Round-trip time, jitter and loss"><Loading q={q} />
          {q.data && (q.data.points.length ? <Chart height={260} option={option} ariaLabel={`RTT and loss for ${x.address}`} /> : <Empty text="No checks in this range yet." />)}</Card>
      </div>
    </Drawer>
  );
}

function TargetForm({ t, onClose }: { t: any; onClose: () => void }) {
  const [f, setF] = useState<any>({ ...BLANK, ...t });
  const links = useQuery({ queryKey: ["isp-links-lite"], queryFn: () => api<any>("/isp/overview", { params: { range: "24h" } }), staleTime: 300_000 });
  const num = ["interval_seconds", "probes", "timeout_ms", "down_after", "up_after", "rtt_warn_ms", "loss_warn_pct"];
  const body = () => ({ ...Object.fromEntries(Object.keys(BLANK).map((k) => [k, num.includes(k) ? Number(f[k]) : f[k]])), isp_link_id: f.isp_link_id || null });
  const save = useMutation({ mutationFn: () => api(t.id ? `/isp/icmp/targets/${t.id}` : "/isp/icmp/targets", { method: t.id ? "PUT" : "POST", body: body() }), onSuccess: onClose });
  const del = useMutation({ mutationFn: () => api(`/isp/icmp/targets/${t.id}`, { method: "DELETE" }), onSuccess: onClose });
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value });
  const inp = (k: string, l: string, p: any = {}) => <div><label className="label">{l}</label><input className="input w-full" value={f[k] ?? ""} onChange={set(k)} {...p} /></div>;
  return (
    <Modal title={t.id ? `Edit ${t.name}` : "Monitor an address"} onClose={onClose}>
      <div className="grid gap-2 sm:grid-cols-2">
        {inp("name", "Name", { placeholder: "Airtel WAN – GGN-01" })}{inp("address", "IP address or hostname", { placeholder: "125.19.104.6" })}
        <div><label className="label">ISP link (groups it with that provider)</label>
          <select className="input w-full" value={f.isp_link_id || ""} onChange={(e) => setF({ ...f, isp_link_id: e.target.value ? Number(e.target.value) : null })}>
            <option value="">— none —</option>{(links.data?.links || []).filter((l: any) => l.id).map((l: any) => <option key={l.id} value={l.id}>{l.isp_name} · {l.firewall_name} {l.interface}</option>)}</select></div>
        {inp("isp_name", "…or provider name", { placeholder: "Airtel" })}
        {inp("site", "Site")}{inp("interval_seconds", "Check every (seconds)", { type: "number", min: 10 })}
        {inp("probes", "Echo requests per check", { type: "number", min: 1, max: 10 })}{inp("timeout_ms", "Reply timeout (ms)", { type: "number", min: 100 })}
        {inp("down_after", "Down after N failed checks", { type: "number", min: 1 })}{inp("up_after", "Up after N good checks", { type: "number", min: 1 })}
        {inp("rtt_warn_ms", "Degraded when RTT ≥ (ms)", { type: "number" })}{inp("loss_warn_pct", "Degraded when loss ≥ (%)", { type: "number" })}
        <label className="text-sm flex items-center gap-2"><input type="checkbox" checked={f.enabled} onChange={set("enabled")} />Enabled</label>
      </div>
      <p className="text-2xs text-muted mt-2">With the defaults (3 probes every 30 s, down after 3 failed checks) an outage is declared after ~90 s of total silence and cleared after ~60 s of replies.
        A "Monitored public IP unreachable" alert is raised while it is down (Alerts → rules: icmp_down).</p>
      {(save.error || del.error) && <div role="alert" className="text-sm text-red-400 mt-2">{((save.error || del.error) as Error).message}</div>}
      <div className="flex gap-2 mt-3">
        <button className="btn btn-primary" disabled={!f.name || !f.address || save.isPending} onClick={() => save.mutate()}>Save</button>
        {t.id && <button className="btn btn-danger ml-auto" onClick={() => confirm(`Stop monitoring ${t.address}? Its history is removed.`) && del.mutate()}>Remove</button>}
      </div>
    </Modal>
  );
}
