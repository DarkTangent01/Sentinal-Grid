import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, downloadUrl } from "../lib/api";
import { useGlobal, useMe } from "../lib/context";
import { useTheme } from "../lib/theme";
import { escHtml, fmtBytes, fmtDuration, fmtNum, fmtTime, getTimezone } from "../lib/format";
import { CHART_THEME, Chart, PALETTES, SERIES_ROLE, axisStyle } from "../components/Chart";
import { Card, Drawer, Empty, Kpi, Loading, TableWrap, Tabs, Time, rowProps } from "../components/ui";
import { IcmpMonitor } from "./IcmpMonitor";

const TAB_KEY = "siem.isp.tab";

export function Isp() {
  const [tab, setTabS] = useState<string>(() => { try { return localStorage.getItem(TAB_KEY) || "sdwan"; } catch { return "sdwan"; } });
  const setTab = (t: string) => { setTabS(t); try { localStorage.setItem(TAB_KEY, t); } catch { /* ignore */ } };
  return (
    <div className="min-w-0">
      <Tabs value={tab} onChange={setTab} tabs={[{ key: "sdwan", label: "SD-WAN health checks" }, { key: "icmp", label: "ICMP monitoring (public IPs)" }]} />
      {tab === "sdwan" ? <IspSdwan /> : <IcmpMonitor />}
    </div>
  );
}

const STATUS: Record<string, [string, string]> = {
  up: ["bg-emerald-400", "Up"], down: ["bg-red-500 animate-pulse", "Down"], degraded: ["bg-amber-400", "Degraded"], no_data: ["bg-slate-500", "No data"],
};
const bps = (v?: number | null) => (v == null ? "—" : `${fmtBytes(v / 8).replace(/B$/, "B/s")}`);
const ms = (v?: number | null) => (v == null ? "—" : `${v.toFixed(1)} ms`);
const pct = (v?: number | null, d = 2) => (v == null ? "—" : `${v.toFixed(d)}%`);
const dur = (s?: number | null) => (!s ? "—" : s >= 86400 ? `${(s / 86400).toFixed(1)}d` : fmtDuration(s));

function Dot({ s }: { s: string }) {
  const [cls, label] = STATUS[s] || STATUS.no_data;
  return <span className="inline-flex items-center gap-1.5 whitespace-nowrap"><span className={`h-2.5 w-2.5 rounded-full ${cls}`} aria-hidden />{label}</span>;
}

function Avail({ v, target }: { v?: number | null; target: number }) {
  if (v == null) return <span className="text-slate-600">—</span>;
  const ok = v >= target;
  return <span className={`tabular-nums font-semibold ${ok ? "text-emerald-300" : "text-red-300"}`} title={`Target ${target}%`}>{v.toFixed(v === 100 ? 0 : 3)}%</span>;
}

function IspSdwan() {
  const g = useGlobal();
  const me = useMe();
  const qc = useQueryClient();
  const [range, setRange] = useState("7d");
  const [minOut, setMinOut] = useState(60);
  const [sel, setSel] = useState<any>(null);
  const fw = Array.isArray(g.params.firewall_id) ? g.params.firewall_id : [];
  const params = { range, min_outage_seconds: minOut, firewall_id: fw };
  const q = useQuery({ queryKey: ["isp", params], queryFn: () => api<any>("/isp/overview", { params }), refetchInterval: 60_000, placeholderData: (p) => p });
  const disc = useMutation({ mutationFn: () => api<any>("/isp/discover", { method: "POST" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["isp"] }) });
  const d = q.data;
  const t = d?.totals || {};
  return (
    <div className="space-y-4 min-w-0">
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-xs text-muted flex-1 min-w-[16rem]">Provider availability from FortiGate SD-WAN health checks. A link is <b>down</b> only when every health check on it fails at once;
          a single failing target (one SaaS endpoint) is shown as <b>partial</b>, not as a provider outage. Outages shorter than the threshold count as blips.</p>
        <select aria-label="Range" className="input py-1" value={range} onChange={(e) => setRange(e.target.value)}>
          {[["24h", "Last 24 h"], ["7d", "Last 7 days"], ["30d", "Last 30 days"]].map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
        <select aria-label="Minimum outage" className="input py-1" value={minOut} onChange={(e) => setMinOut(Number(e.target.value))}>
          {[[0, "Count every outage"], [30, "Outage ≥ 30 s"], [60, "Outage ≥ 1 min"], [300, "Outage ≥ 5 min"]].map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
        <a className="btn" href={downloadUrl("/isp/outages.csv", params)}>Export outages</a>
        {me.role === "admin" && <button className="btn" disabled={disc.isPending} title="Read interface aliases and SD-WAN gateways from the firewalls (GET only)"
          onClick={() => disc.mutate()}>{disc.isPending ? "Discovering…" : "Discover links"}</button>}
      </div>
      {disc.data && <div className="text-xs text-muted">Discovery: {Object.entries(disc.data).map(([k, v]) => `${k}: ${v}`).join(" · ")}</div>}
      <Loading q={q} />
      {d && !d.links.length && <Empty text={<>No SD-WAN health-check logs in this range. Enable <code className="font-mono">config log syslogd filter</code> event logs (SD-WAN) on the firewalls and configure SD-WAN health checks / performance SLAs.</>} />}
      {d && d.links.length > 0 && <>
        <div className="kpi-grid">
          <Kpi label="WAN links" value={fmtNum(t.links)} sub={`${d.isps.length} provider(s)`} />
          <Kpi label="Down now" value={fmtNum(t.down_now)} tone={t.down_now ? "bad" : "ok"} />
          <Kpi label="Degraded now" value={fmtNum(t.degraded_now)} tone={t.degraded_now ? "warn" : undefined} />
          <Kpi label="Outages" value={fmtNum(t.outages)} tone={t.outages ? "warn" : "ok"} sub={`in ${range}`} />
          <Kpi label="Total downtime" value={dur(t.downtime_s)} sub="all links" />
          <Kpi label="Avg availability" value={t.availability == null ? "—" : `${t.availability.toFixed(3)}%`} />
        </div>

        <Card title="Provider scorecard">
          <TableWrap><table className="tbl">
            <thead><tr><th>Provider</th><th>Sites</th><th className="num">Links</th><th className="num">Availability</th><th>SLA</th><th className="num">Outages</th><th className="num">Blips</th>
              <th className="num">Downtime</th><th className="num">MTTR</th><th className="num">Longest</th><th className="num">Latency</th><th className="num">Jitter</th><th className="num">Loss</th>
              <th className="num">SLA breaches</th><th className="num">Partial</th></tr></thead>
            <tbody>{d.isps.map((i: any) => <tr key={i.isp_name}>
              <td className="font-semibold">{i.isp_name}{i.down_now > 0 && <span className="pill bg-red-500/15 text-red-300 ml-1.5">{i.down_now} down</span>}</td>
              <td className="text-xs">{i.sites.join(", ")}</td><td className="num">{i.links}</td>
              <td className="num"><Avail v={i.availability} target={i.target_availability} /></td>
              <td><span className={`pill ${i.sla_met ? "bg-emerald-500/15 text-emerald-300" : "bg-red-500/15 text-red-300"}`}>{i.sla_met ? "met" : "missed"} · {i.target_availability}%</span></td>
              <td className="num">{fmtNum(i.outages)}</td><td className="num">{fmtNum(i.blips)}</td><td className="num">{dur(i.downtime_s)}</td>
              <td className="num">{dur(i.mttr_s)}</td><td className="num">{dur(i.longest_s)}</td><td className="num">{ms(i.latency_ms)}</td><td className="num">{ms(i.jitter_ms)}</td>
              <td className="num">{pct(i.packet_loss_pct)}</td><td className="num">{fmtNum(i.sla_breach_total)}</td><td className="num">{fmtNum(i.partial_events)}</td>
            </tr>)}</tbody></table></TableWrap>
        </Card>

        <div className="grid gap-4 xl:grid-cols-2 min-w-0">
          <Card title="Outage timeline"><Timeline d={d} onPick={(k) => setSel(d.links.find((l: any) => l.key === k))} /></Card>
          <Card title="Daily availability"><Heatmap d={d} onPick={(k) => setSel(d.links.find((l: any) => l.key === k))} /></Card>
        </div>

        <Card title="WAN links" right={<span className="text-2xs text-muted">click a link for quality charts, outage log and settings</span>}>
          <TableWrap><table className="tbl">
            <thead><tr><th>Status</th><th>Provider</th><th>Firewall · interface</th><th className="num">Availability</th><th className="num">Outages</th><th className="num">Downtime</th>
              <th className="num">Longest</th><th className="num">MTTR</th><th className="num">MTBF</th><th>Last outage</th><th className="num">Latency avg / p95</th><th className="num">Jitter</th>
              <th className="num">Loss</th><th className="num">MOS</th><th className="num">Peak in / out</th><th className="num">Flaps</th><th>Most failing check</th><th>Gateway</th></tr></thead>
            <tbody>{d.links.map((l: any) => <tr key={l.key} {...rowProps(() => setSel(l))}>
              <td><Dot s={l.status} /></td>
              <td className="min-w-[9rem]"><div className="font-medium">{l.isp_name}</div>{!l.named && <div className="text-2xs text-amber-300">unnamed{l.as_org ? ` · ${l.as_org}` : ""}</div>}{l.circuit_id && <div className="text-2xs text-muted">{l.circuit_id}</div>}</td>
              <td className="text-xs nowrap">{l.firewall_name}<div className="font-mono text-muted">{l.interface}{l.alias ? ` (${l.alias})` : ""}</div></td>
              <td className="num"><Avail v={l.availability} target={l.target_availability} /></td>
              <td className="num">{fmtNum(l.outages)}{l.blips > 0 && <span className="text-2xs text-muted"> +{l.blips} blip</span>}</td>
              <td className="num">{dur(l.downtime_s)}</td><td className="num">{dur(l.longest_s)}</td><td className="num">{dur(l.mttr_s)}</td><td className="num">{dur(l.mtbf_s)}</td>
              <td><Time v={l.last_outage} /></td>
              <td className="num">{ms(l.latency_ms)} / {ms(l.latency_p95_ms)}</td><td className="num">{ms(l.jitter_ms)}</td>
              <td className="num">{pct(l.packet_loss_pct)}</td><td className="num">{l.mos == null ? "—" : l.mos.toFixed(2)}</td>
              <td className="num text-xs">{bps(l.bw_in_peak_bps)} / {bps(l.bw_out_peak_bps)}{l.utilisation_peak_pct != null && <div className="text-muted">{l.utilisation_peak_pct}% of {l.bandwidth_mbps} Mb/s</div>}</td>
              <td className="num">{fmtNum(l.flaps)}</td>
              <td className="text-xs">{l.failing_checks[0] ? <span title={l.failing_checks.map((c: any) => `${c.check}: ${c.events}× ${dur(c.down_s)}`).join("\n")}>{l.failing_checks[0].check} · {l.failing_checks[0].events}×</span> : "—"}</td>
              <td className="font-mono text-xs">{l.gateway || "—"}</td>
            </tr>)}</tbody></table></TableWrap>
        </Card>
      </>}
      {sel && <LinkDrawer l={sel} range={range} minOut={minOut} admin={me.role === "admin"} onClose={() => { setSel(null); qc.invalidateQueries({ queryKey: ["isp"] }); }} />}
    </div>
  );
}

function axisTime(v: number, span: number) {
  const o: Intl.DateTimeFormatOptions = span > 2 * 86400 ? { month: "short", day: "2-digit" } : { hour: "2-digit", minute: "2-digit", hour12: false };
  return new Date(v).toLocaleString(undefined, { ...o, timeZone: getTimezone() });
}

function Timeline({ d, onPick }: { d: any; onPick: (key: string) => void }) {
  const { theme } = useTheme();
  const option = useMemo(() => {
    const rows = d.links.map((l: any) => l.key);
    const label = Object.fromEntries(d.links.map((l: any) => [l.key, `${l.isp_name} · ${l.interface}`]));
    const t0 = Date.parse(d.window.start), t1 = Date.parse(d.window.end);
    const red = SERIES_ROLE[theme].alert;
    return {
      grid: { left: 8, right: 16, top: 8, bottom: 8, containLabel: true },
      tooltip: { trigger: "item", confine: true, formatter: (p: any) => `<b>${escHtml(label[p.value[3]])}</b><br/>${fmtTime(new Date(p.value[1]))} → ${fmtTime(new Date(p.value[2]))}<br/>down ${dur(p.value[4])}` },
      xAxis: { type: "time", min: t0, max: t1, ...axisStyle, axisLabel: { ...axisStyle.axisLabel, formatter: (v: number) => axisTime(v, (t1 - t0) / 1000) } },
      yAxis: { type: "category", data: rows.map((k: string) => label[k]), ...axisStyle, axisLabel: { color: CHART_THEME[theme].strong, fontSize: 11, width: 170, overflow: "truncate" } },
      series: [{
        type: "custom", encode: { x: [1, 2], y: 0 },
        renderItem: (_: any, api: any) => {
          const y = api.value(0);
          const a = api.coord([api.value(1), y]), b = api.coord([api.value(2), y]);
          const h = api.size([0, 1])[1] * 0.55;
          return { type: "rect", shape: { x: a[0], y: a[1] - h / 2, width: Math.max(2, b[0] - a[0]), height: h }, style: { fill: red } };
        },
        data: d.timeline.map((o: any) => [rows.indexOf(o.key), Date.parse(o.start), Date.parse(o.end), o.key, o.duration_s]),
      }],
    };
  }, [d, theme]);
  if (!d.timeline.length) return <Empty text="No provider outages in this range." />;
  return <Chart option={option} height={Math.max(160, d.links.length * 34 + 40)} onClick={(p) => onPick(p.value?.[3])} ariaLabel="Outage timeline per WAN link" />;
}

function Heatmap({ d, onPick }: { d: any; onPick: (key: string) => void }) {
  const { theme } = useTheme();
  const days: string[] = d.links[0]?.daily.map((x: any) => x.day) || [];
  const option = useMemo(() => {
    const rows = d.links.map((l: any) => `${l.isp_name} · ${l.interface}`);
    const data = d.links.flatMap((l: any, i: number) => l.daily.map((x: any, j: number) => [j, i, x.availability, l.key, x.downtime_s, x.outages]));
    return {
      grid: { left: 8, right: 16, top: 8, bottom: 40, containLabel: true },
      tooltip: { confine: true, formatter: (p: any) => `<b>${escHtml(rows[p.value[1]])}</b><br/>${days[p.value[0]]}: ${p.value[2]?.toFixed(3)}%<br/>${p.value[5]} outage(s), down ${dur(p.value[4])}` },
      xAxis: { type: "category", data: days.map((x) => x.slice(5)), ...axisStyle, splitArea: { show: false } },
      yAxis: { type: "category", data: rows, ...axisStyle, axisLabel: { color: CHART_THEME[theme].strong, fontSize: 11, width: 170, overflow: "truncate" } },
      visualMap: { dimension: 2, min: 98, max: 100, calculable: false, orient: "horizontal", left: "center", bottom: 0, itemHeight: 120, textStyle: { color: CHART_THEME[theme].text },
        inRange: { color: [SERIES_ROLE[theme].alert, "#eda100", PALETTES[theme][2]] }, formatter: (v: number) => `${v.toFixed(1)}%` },
      series: [{ type: "heatmap", data, itemStyle: { borderColor: CHART_THEME[theme].surface, borderWidth: 2 } }],
    };
  }, [d, theme, days]);
  return <Chart option={option} height={Math.max(180, d.links.length * 30 + 70)} onClick={(p) => onPick(p.value?.[3])} ariaLabel="Daily availability per WAN link" />;
}

function LinkDrawer({ l, range, minOut, admin, onClose }: { l: any; range: string; minOut: number; admin: boolean; onClose: () => void }) {
  const { theme } = useTheme();
  const q = useQuery({ queryKey: ["isp-link", l.key, range, minOut], queryFn: () => api<any>(`/isp/links/${l.firewall_id}/${encodeURIComponent(l.interface)}`, { params: { range, min_outage_seconds: minOut } }) });
  const d = q.data;
  const line = (keys: [string, string, string?][], fmt: (v: number) => string) => d && ({
    legend: { top: 0 },
    xAxis: { type: "time", ...axisStyle, axisLabel: { ...axisStyle.axisLabel, formatter: (v: number) => axisTime(v, d.bucket_seconds * 100) } },
    yAxis: { type: "value", ...axisStyle, axisLabel: { ...axisStyle.axisLabel, formatter: fmt } },
    tooltip: { trigger: "axis", confine: true, valueFormatter: (v: number) => (v == null ? "—" : fmt(v)) },
    series: keys.map(([k, name, color], i) => ({ name, type: "line", showSymbol: false, smooth: true, connectNulls: false, lineStyle: { width: 2 },
      itemStyle: { color: color || PALETTES[theme][i] }, data: d.timeseries.map((r: any) => [Date.parse(r.t), r[k]]) })),
  });
  return (
    <Drawer title={`${l.isp_name} · ${l.firewall_name} ${l.interface}`} onClose={onClose}>
      <Loading q={q} />
      {d && <div className="space-y-4">
        <div className="kpi-grid">
          <Kpi label="Status" value={<Dot s={d.link.status} />} />
          <Kpi label="Availability" value={<Avail v={d.link.availability} target={d.link.target_availability} />} sub={`target ${d.link.target_availability}%`} />
          <Kpi label="Outages" value={fmtNum(d.link.outages)} sub={`${d.link.blips} blip(s)`} />
          <Kpi label="Downtime" value={dur(d.link.downtime_s)} sub={`longest ${dur(d.link.longest_s)}`} />
          <Kpi label="MTTR / MTBF" value={dur(d.link.mttr_s)} sub={`MTBF ${dur(d.link.mtbf_s)}`} />
          <Kpi label="SLA breaches" value={fmtNum(d.link.sla_breach_total)} sub={Object.entries(d.link.sla_breaches).map(([k, v]) => `${k} ${v}`).join(", ") || "none"} />
        </div>
        <div className="text-xs text-muted">Outage = all of: <span className="font-mono">{d.link.outage_checks.join(", ")}</span> · gateway <span className="font-mono">{d.link.gateway || "—"}</span>
          {d.link.as_org && <> · ASN {d.link.as_org}</>}{d.link.alias && <> · alias {d.link.alias}</>}{d.link.description && <> · {d.link.description}</>}</div>
        {d.timeseries.length > 0 ? <>
          <Card title="Latency & jitter"><Chart height={200} option={line([["latency", "latency avg"], ["latency_max", "latency max", "#9c9c9c"], ["jitter", "jitter"]], (v) => `${v.toFixed(0)} ms`)!} /></Card>
          <div className="grid gap-4 md:grid-cols-2">
            <Card title="Packet loss"><Chart height={180} option={line([["loss", "loss %", SERIES_ROLE[theme].alert]], (v) => `${v.toFixed(1)}%`)!} /></Card>
            <Card title="MOS (voice quality)"><Chart height={180} option={line([["mos", "MOS"]], (v) => v.toFixed(2))!} /></Card>
          </div>
          <Card title="Bandwidth used (peak per interval)"><Chart height={200} option={line([["bw_in", "in"], ["bw_out", "out"]], (v) => bps(v))!} /></Card>
        </> : <Empty text="No SLA samples (latency/jitter/loss) for this link — only state changes were logged. Add the health check to an SLA target to get quality metrics." />}
        <Card title={`Outage & partial log (${d.events.length})`} bodyClass="p-0">
          {d.events.length ? <TableWrap maxH="max-h-72"><table className="tbl"><thead><tr><th>Type</th><th>Start</th><th>End</th><th className="num">Duration</th><th className="w-full">Failed checks</th></tr></thead>
            <tbody>{d.events.map((e: any, i: number) => <tr key={i}>
              <td>{e.type === "outage" ? <span className="pill bg-red-500/15 text-red-300">outage</span> : <span className="pill bg-amber-500/15 text-amber-300">partial</span>}{e.ongoing && <span className="pill bg-red-500/25 text-red-200 ml-1">ongoing</span>}</td>
              <td><Time v={e.start} /></td><td>{e.ongoing ? "—" : <Time v={e.end} />}</td><td className="num">{dur(e.duration_s)}</td>
              <td className="text-xs font-mono cell-wrap">{e.checks.join(", ")}</td></tr>)}</tbody></table></TableWrap> : <Empty text="No outages or partial failures." />}
        </Card>
        <Card title="Health checks on this link" bodyClass="p-0">
          <TableWrap><table className="tbl"><thead><tr><th>Check</th><th className="num">Samples</th><th className="num">Latency</th><th className="num">Jitter</th><th className="num">Loss</th><th className="num">Down events</th><th className="num">Down time</th></tr></thead>
            <tbody>{d.checks.map((c: any) => <tr key={c.check}><td className="font-mono text-xs">{c.check}</td><td className="num">{fmtNum(c.n)}</td><td className="num">{ms(c.lat)}</td>
              <td className="num">{ms(c.jit)}</td><td className="num">{pct(c.loss)}</td><td className="num">{fmtNum(c.down_events)}</td><td className="num">{dur(c.down_s)}</td></tr>)}</tbody></table></TableWrap>
        </Card>
        {admin && l.id && <Settings l={l} checks={d.link.checks} onSaved={onClose} />}
      </div>}
    </Drawer>
  );
}

function Settings({ l, checks, onSaved }: { l: any; checks: string[]; onSaved: () => void }) {
  const [f, setF] = useState({ isp_name: l.named ? l.isp_name : "", circuit_id: l.circuit_id || "", bandwidth_mbps: l.bandwidth_mbps ?? "", target_availability: l.target_availability,
    outage_checks: (l.outage_checks?.length === checks.length ? [] : l.outage_checks) as string[], hidden: !!l.hidden, support_contact: l.support_contact || "", notes: l.notes || "" });
  const m = useMutation({ mutationFn: () => api(`/isp/config/${l.id}`, { method: "PUT", body: { ...f, bandwidth_mbps: f.bandwidth_mbps === "" ? null : Number(f.bandwidth_mbps),
    target_availability: Number(f.target_availability) } }), onSuccess: onSaved });
  return (
    <Card title="Link settings">
      <div className="grid gap-2 sm:grid-cols-3">
        <div><label className="label">Provider name</label><input className="input w-full" placeholder={l.as_org || "e.g. Airtel"} value={f.isp_name} onChange={(e) => setF({ ...f, isp_name: e.target.value })} /></div>
        <div><label className="label">Circuit ID</label><input className="input w-full" value={f.circuit_id} onChange={(e) => setF({ ...f, circuit_id: e.target.value })} /></div>
        <div><label className="label">Contracted bandwidth (Mb/s)</label><input type="number" min={0} className="input w-full" value={f.bandwidth_mbps} onChange={(e) => setF({ ...f, bandwidth_mbps: e.target.value })} /></div>
        <div><label className="label">SLA availability target (%)</label><input type="number" min={0} max={100} step={0.01} className="input w-full" value={f.target_availability} onChange={(e) => setF({ ...f, target_availability: Number(e.target.value) })} /></div>
        <div className="sm:col-span-2"><label className="label">Support contact</label><input className="input w-full" value={f.support_contact} onChange={(e) => setF({ ...f, support_contact: e.target.value })} placeholder="NOC phone / email / ticket portal" /></div>
        <div className="sm:col-span-3"><div className="label">Checks that define an outage (none selected = all checks must fail)</div>
          <div className="flex flex-wrap gap-x-4 gap-y-1">{checks.map((c) => <label key={c} className="text-xs flex items-center gap-1.5 font-mono"><input type="checkbox" checked={f.outage_checks.includes(c)}
            onChange={(e) => setF({ ...f, outage_checks: e.target.checked ? [...f.outage_checks, c] : f.outage_checks.filter((x) => x !== c) })} />{c}</label>)}</div></div>
        <div className="sm:col-span-3"><label className="label">Notes</label><textarea className="input w-full h-16" value={f.notes} onChange={(e) => setF({ ...f, notes: e.target.value })} /></div>
        <label className="text-sm flex items-center gap-2"><input type="checkbox" checked={f.hidden} onChange={(e) => setF({ ...f, hidden: e.target.checked })} />Hide (not an ISP link, e.g. VPN overlay)</label>
      </div>
      {m.error && <div role="alert" className="text-sm text-red-400 mt-2">{(m.error as Error).message}</div>}
      <button className="btn btn-primary mt-3" disabled={m.isPending} onClick={() => m.mutate()}>Save</button>
    </Card>
  );
}
