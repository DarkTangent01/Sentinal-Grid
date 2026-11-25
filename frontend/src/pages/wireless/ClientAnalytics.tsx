/** Wireless → WLAN / SSID: historical client analytics (daily SSID and per-AP statistics, hourly distribution, rankings,
 *  band distribution, roaming) and the client connection history used in the client drawer.
 *  Definitions (unique clients, sessions, peak / average concurrent) come from the API and are explained on screen. */
import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, downloadUrl } from "../../lib/api";
import { type Theme, useTheme } from "../../lib/theme";
import { fmtNum, getTimezone } from "../../lib/format";
import { Chart, PALETTES, SERIES_ROLE, axisStyle } from "../../components/Chart";
import { TopBar } from "../../components/charts";
import { Card, Empty, Kpi, Loading, rowProps, TableWrap, Time } from "../../components/ui";
import { Pager, SortTh } from "../wan/common";
import { Band, dash, dur } from "./common";
import { type AnalyticsFilters, METRICS, type Period, defaultRange, hourLabel, periodLabel, pivot, toParams } from "./analyticsModel";

const STALE = 60_000;
const HELP = "Unique clients: distinct devices (MACs) the controller listed. Sessions: associations (a reconnect or a move to another SSID is a new one; a roam is not). "
  + "Peak / average concurrent: clients listed at the same time, read every 5 minutes; the average is over the readings actually taken, so a collection gap is not counted as zero.";

function useAnalytics<T = any>(path: string, params: Record<string, any>) {
  return useQuery<T>({ queryKey: ["wl", "an", path, params], queryFn: () => api<T>(`/wireless/analytics/${path}`, { params }), staleTime: STALE,
    placeholderData: (p) => p });
}

export function ClientAnalytics() {
  const tz = getTimezone();
  const [period, setPeriod] = useState<Period>("day");
  const init = defaultRange("day", tz);
  const [f, setF] = useState<AnalyticsFilters>({ ...init, period: "day" });
  const set = (p: Partial<AnalyticsFilters>) => setF((x) => ({ ...x, ...p }));
  const opts = useQuery({ queryKey: ["wl", "an", "filters"], queryFn: () => api<any>("/wireless/analytics/filters"), staleTime: 300_000 });
  const o = opts.data;
  const params = useMemo(() => toParams(f), [f]);
  const aps = (o?.aps || []).filter((a: any) => (!f.controller || String(a.wlc_id) === f.controller) && (!f.site || a.site === f.site));
  return <div className="space-y-4 min-w-0">
    <Card title="Historical client analytics" right={<span className="text-2xs text-muted">days in {tz}</span>}>
      <div className="flex flex-wrap items-end gap-2 text-xs">
        <label className="flex flex-col gap-0.5">View<select aria-label="View" className="input py-1" value={period}
          onChange={(e) => { const p = e.target.value as Period; setPeriod(p); set({ period: p, ...defaultRange(p, tz) }); }}>
          <option value="day">Daily</option><option value="week">Weekly</option><option value="month">Monthly</option></select></label>
        <label className="flex flex-col gap-0.5">From<input aria-label="Start date" type="date" className="input py-1" value={f.start} max={f.end} onChange={(e) => e.target.value && set({ start: e.target.value })} /></label>
        <label className="flex flex-col gap-0.5">To<input aria-label="End date" type="date" className="input py-1" value={f.end} min={f.start} onChange={(e) => e.target.value && set({ end: e.target.value })} /></label>
        <label className="flex flex-col gap-0.5">Site<select aria-label="Site" className="input py-1" value={f.site || ""} onChange={(e) => set({ site: e.target.value, ap: "" })}>
          <option value="">All sites</option>{(o?.sites || []).map((s: string) => <option key={s}>{s}</option>)}</select></label>
        <label className="flex flex-col gap-0.5">Controller<select aria-label="Controller" className="input py-1" value={f.controller || ""} onChange={(e) => set({ controller: e.target.value, ap: "" })}>
          <option value="">All controllers</option>{(o?.controllers || []).map((c: any) => <option key={c.id} value={c.id}>{c.name}</option>)}</select></label>
        <label className="flex flex-col gap-0.5">SSID<select aria-label="SSID" className="input py-1" value={f.ssid || ""} onChange={(e) => set({ ssid: e.target.value })}>
          <option value="">All SSIDs</option>{(o?.ssids || []).map((s: string) => <option key={s}>{s}</option>)}</select></label>
        <label className="flex flex-col gap-0.5">Access point<select aria-label="Access point" className="input py-1 max-w-[14rem]" value={f.ap || ""} onChange={(e) => set({ ap: e.target.value })}>
          <option value="">All APs</option>{aps.map((a: any) => <option key={a.id} value={a.id}>{a.name}</option>)}</select></label>
        <label className="flex flex-col gap-0.5">Band<select aria-label="Band" className="input py-1" value={f.band || ""} onChange={(e) => set({ band: e.target.value })}>
          <option value="">All bands</option>{(o?.bands || ["2.4", "5", "6"]).map((b: string) => <option key={b} value={b}>{b} GHz</option>)}</select></label>
        {(f.ssid || f.ap || f.band || f.site || f.controller) && <button className="btn py-1" onClick={() => set({ ssid: "", ap: "", band: "", site: "", controller: "" })}>Clear filters</button>}
      </div>
      <p className="text-2xs text-muted mt-2">{HELP}</p>
    </Card>
    <h2 className="text-sm font-semibold text-slate-200 pt-2">Daily client connection analysis</h2>
    <SsidDaily params={params} period={f.period} onSsid={(ssid) => set({ ssid })} />
    <Hourly params={params} ssid={f.ssid} />
    <h2 className="text-sm font-semibold text-slate-200 pt-2">Access point client analytics</h2>
    <ApDaily params={params} period={f.period} onAp={(ap) => set({ ap: String(ap) })} />
    <Rankings params={params} onAp={(ap) => set({ ap: String(ap) })} />
    <Distribution params={params} onAp={(ap) => set({ ap: String(ap) })} />
    <Roaming params={params} />
  </div>;
}

function Coverage({ cov, days }: { cov?: Record<string, number>; days?: string[] }) {
  if (!cov || !days) return null;
  const missing = days.filter((d) => !cov[d]).length;
  return missing && days.length ? <p className="text-2xs text-amber-300/80">No client readings on {missing} of {days.length} days in this range (controller not polled or no data yet): those days are gaps, not zero clients.</p> : null;
}

function groupedOption(theme: Theme, piv: ReturnType<typeof pivot>, period: Period, metric: string) {
  const mlabel = METRICS.find(([k]) => k === metric)?.[1] || metric;
  return { legend: { top: 0, type: "scroll" }, grid: { left: 8, right: 16, top: 36, bottom: 8, containLabel: true },
    tooltip: { trigger: "axis", confine: true, axisPointer: { type: "shadow" }, formatter: (ps: any[]) => {
      const i = ps[0]?.dataIndex;
      return `<b>${periodLabel(piv.days[i], period)}</b> · ${mlabel}` + ps.map((p) => {
        const r = piv.series[p.seriesIndex]?.rows[i];
        return `<br/>${p.marker}${p.seriesName}: <b>${r ? Number(r[metric]).toLocaleString() : "—"}</b>`
          + (r ? ` <span style="opacity:.7">(${r.unique_clients} unique · ${r.sessions} sessions · peak ${r.peak_clients} · avg ${r.avg_clients})</span>` : "");
      }).join("");
    } },
    xAxis: { type: "category", data: piv.days.map((d) => periodLabel(d, period)), ...axisStyle },
    yAxis: { type: "value", minInterval: metric === "avg_clients" ? undefined : 1, ...axisStyle },
    series: piv.series.map((s, i) => ({ name: s.name, type: "bar", barMaxWidth: 18, data: s.data, itemStyle: { color: PALETTES[theme][i % 8] } })) };
}

function MetricSelect({ v, set }: { v: string; set: (m: string) => void }) {
  return <select aria-label="Metric" className="input py-0.5 text-xs" value={v} onChange={(e) => set(e.target.value)}>{METRICS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>;
}

function SsidDaily({ params, period, onSsid }: { params: any; period: Period; onSsid: (s: string) => void }) {
  const { theme } = useTheme();
  const [metric, setMetric] = useState("unique_clients");
  const [sort, setSort] = useState({ key: "date", desc: true });
  const [page, setPage] = useState(1);
  const chart = useAnalytics("ssid/daily", { ...params, sort: "date", order: "asc", page_size: 1000 });
  const tp = { ...params, sort: sort.key, order: sort.desc ? "desc" : "asc", page, page_size: 25 };
  const table = useAnalytics("ssid/daily", tp);
  const piv = useMemo(() => pivot(chart.data?.items || [], "ssid", metric), [chart.data, metric]);
  const option = useMemo(() => groupedOption(theme, piv, period, metric), [theme, piv, period, metric]);
  const srt = (s: any) => { setSort(s); setPage(1); };
  return <>
    <Card title={`${period === "day" ? "Daily" : period === "week" ? "Weekly" : "Monthly"} clients per SSID`} right={<MetricSelect v={metric} set={setMetric} />}>
      <Loading q={chart} />
      <Coverage cov={chart.data?.coverage} days={period === "day" ? chart.data?.days : undefined} />
      {chart.data && (piv.series.length ? <Chart height={300} option={option} ariaLabel="Clients per SSID per period" onClick={(p) => onSsid(p.seriesName)} />
        : <Empty text="No client readings in this range." />)}
      {piv.series.length > 0 && <p className="text-2xs text-muted">Click a bar to drill into that SSID.</p>}
    </Card>
    <Card title="SSID connection breakdown" bodyClass="p-0" right={<a className="btn py-0.5 text-xs" href={downloadUrl("/wireless/analytics/ssid/daily", { ...params, sort: sort.key, order: sort.desc ? "desc" : "asc", format: "csv" })}>Export CSV</a>}>
      <Loading q={table} />
      {table.data && (!table.data.items.length ? <Empty text="No client readings in this range." /> : <>
        <TableWrap><table className="tbl"><thead><tr>
          <SortTh k="date" label={period === "day" ? "Date" : period === "week" ? "Week of" : "Month"} sort={sort} setSort={srt} /><SortTh k="ssid" label="SSID" sort={sort} setSort={srt} />
          <SortTh k="unique_clients" label="Unique clients" sort={sort} setSort={srt} className="num" /><SortTh k="sessions" label="Total sessions" sort={sort} setSort={srt} className="num" />
          <SortTh k="peak_clients" label="Peak clients" sort={sort} setSort={srt} className="num" /><SortTh k="avg_clients" label="Average clients" sort={sort} setSort={srt} className="num" /></tr></thead>
          <tbody>{table.data.items.map((r: any) => <tr key={`${r.day}-${r.ssid}`} {...rowProps(() => onSsid(r.ssid))}>
            <td className="whitespace-nowrap">{periodLabel(r.day, period)}</td><td className="font-medium">{r.ssid || "(none)"}</td><td className="num">{fmtNum(r.unique_clients)}</td>
            <td className="num">{fmtNum(r.sessions)}</td><td className="num">{fmtNum(r.peak_clients)}</td><td className="num">{dash(r.avg_clients, "", 1)}</td></tr>)}</tbody></table></TableWrap>
        <Pager page={page} size={25} total={table.data.total} onPage={setPage} /></>)}
    </Card>
  </>;
}

function Hourly({ params, ssid }: { params: any; ssid?: string }) {
  const { theme } = useTheme();
  // one SSID (or a filter that leaves one series): add the usual range for each hour of the week (median of 4 previous weeks)
  const q = useAnalytics("hourly", { ...params, group: ssid ? "none" : "ssid", expected_weeks: ssid ? 4 : 0 });
  const d = q.data;
  const line = useMemo(() => d && ({ legend: { top: 0, type: "scroll" }, grid: { left: 8, right: 16, top: 36, bottom: 8, containLabel: true },
    tooltip: { trigger: "axis", confine: true }, xAxis: { type: "time", ...axisStyle }, yAxis: { type: "value", minInterval: 1, ...axisStyle },
    series: [...d.series.map((s: any, i: number) => ({ name: ssid || (s.key === "all" ? "All clients" : s.key || "(none)"), type: "line", showSymbol: false,
      itemStyle: { color: PALETTES[theme][i % 8] }, data: s.points.map((p: any) => [Date.parse(p.t), p.avg_clients]) })),
      ...(ssid && d.series[0]?.points.some((p: any) => p.expected != null) ? [
        { name: "usual low", type: "line", stack: "band", showSymbol: false, lineStyle: { opacity: 0 }, tooltip: { show: false },
          data: d.series[0].points.map((p: any) => [Date.parse(p.t), p.expected_low ?? null]) },
        { name: "Usual range", type: "line", stack: "band", showSymbol: false, lineStyle: { opacity: 0 }, areaStyle: { color: SERIES_ROLE[theme].muted, opacity: 0.18 },
          data: d.series[0].points.map((p: any) => [Date.parse(p.t), p.expected_high != null ? p.expected_high - p.expected_low : null]) },
        { name: "Usual", type: "line", showSymbol: false, lineStyle: { type: "dashed", width: 1 }, itemStyle: { color: SERIES_ROLE[theme].muted },
          data: d.series[0].points.map((p: any) => [Date.parse(p.t), p.expected ?? null]) }] : [])] }), [d, theme, ssid]);
  const prof = useMemo(() => d && ({ legend: { top: 0 }, grid: { left: 8, right: 16, top: 36, bottom: 8, containLabel: true },
    tooltip: { trigger: "axis", confine: true }, xAxis: { type: "category", data: d.profile.map((p: any) => hourLabel(p.hour)), ...axisStyle },
    yAxis: { type: "value", ...axisStyle },
    series: [{ name: "Average", type: "bar", barMaxWidth: 16, data: d.profile.map((p: any) => p.avg_clients), itemStyle: { color: SERIES_ROLE[theme].primary } },
      { name: "Peak", type: "line", data: d.profile.map((p: any) => p.peak_clients), itemStyle: { color: SERIES_ROLE[theme].warn } },
      { name: "Minimum", type: "line", lineStyle: { type: "dashed" }, data: d.profile.map((p: any) => p.min_clients), itemStyle: { color: SERIES_ROLE[theme].muted } }] }), [d, theme]);
  const pk = d?.profile?.find((p: any) => p.hour === d.peak_hour);
  const all = (d?.profile || []) as any[];
  return <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
    <Card title={`Hourly clients${ssid ? ` — ${ssid}` : " per SSID"}`}>
      <Loading q={q} />
      {d && (d.series.length ? <Chart height={260} option={line!} ariaLabel="Average concurrent clients per hour" /> : <Empty text="No client readings in this range." />)}
      <p className="text-2xs text-muted">Average concurrent clients in each hour.{ssid && " The shaded band is the usual range for that hour of the week (previous 4 weeks)."}</p>
    </Card>
    <Card title="24-hour connection pattern">
      {d && all.length > 0 && <div className="kpi-grid mb-2">
        <Kpi label="Peak hour" value={pk ? hourLabel(pk.hour) : "—"} sub={pk ? `avg ${pk.avg_clients} · peak ${pk.peak_clients}` : undefined} />
        <Kpi label="Highest concurrent" value={fmtNum(Math.max(...all.map((p) => p.peak_clients)))} />
        <Kpi label="Lowest concurrent" value={fmtNum(Math.min(...all.map((p) => p.min_clients)))} />
        <Kpi label="Average concurrent" value={(all.reduce((a, p) => a + p.avg_clients * p.hours_observed, 0) / Math.max(1, all.reduce((a, p) => a + p.hours_observed, 0))).toFixed(1)} />
      </div>}
      {d && (all.length ? <Chart height={220} option={prof!} ariaLabel="Clients by hour of day" /> : <Empty text="No client readings in this range." />)}
    </Card>
  </div>;
}

function ApDaily({ params, period, onAp }: { params: any; period: Period; onAp: (id: number) => void }) {
  const { theme } = useTheme();
  const [metric, setMetric] = useState("unique_clients");
  const [sort, setSort] = useState({ key: "date", desc: true });
  const [page, setPage] = useState(1);
  const chart = useAnalytics("ap/daily", { ...params, by_ssid: false, sort: "date", order: "asc", page_size: 1000 });
  const tp = { ...params, by_ssid: true, sort: sort.key, order: sort.desc ? "desc" : "asc", page, page_size: 25 };
  const table = useAnalytics("ap/daily", tp);
  const piv = useMemo(() => pivot(chart.data?.items || [], "ap_id", metric, 8, (r) => r.ap_name), [chart.data, metric]);
  const option = useMemo(() => groupedOption(theme, piv, period, metric), [theme, piv, period, metric]);
  const srt = (s: any) => { setSort(s); setPage(1); };
  return <>
    <Card title={`Clients per AP (top ${Math.min(8, piv.series.length) || 8})`} right={<MetricSelect v={metric} set={setMetric} />}>
      <Loading q={chart} />
      {chart.data && (piv.series.length ? <Chart height={300} option={option} ariaLabel="Clients per AP per period"
        onClick={(p) => { const s = piv.series[p.seriesIndex]; if (s) onAp(Number(s.key)); }} /> : <Empty text="No client readings in this range." />)}
      <p className="text-2xs text-muted">AP sessions = associations that began on the AP plus roams onto it. Select one AP in the filters to compare it alone.</p>
    </Card>
    <Card title="AP-wise breakdown" bodyClass="p-0" right={<a className="btn py-0.5 text-xs" href={downloadUrl("/wireless/analytics/ap/daily", { ...params, by_ssid: true, sort: sort.key, order: sort.desc ? "desc" : "asc", format: "csv" })}>Export CSV</a>}>
      <Loading q={table} />
      {table.data && (!table.data.items.length ? <Empty text="No client readings in this range." /> : <>
        <TableWrap><table className="tbl"><thead><tr>
          <SortTh k="date" label={period === "day" ? "Date" : period === "week" ? "Week of" : "Month"} sort={sort} setSort={srt} /><SortTh k="ap_name" label="AP name" sort={sort} setSort={srt} />
          <th>AP MAC</th><SortTh k="ssid" label="SSID" sort={sort} setSort={srt} />
          <SortTh k="unique_clients" label="Unique clients" sort={sort} setSort={srt} className="num" /><SortTh k="sessions" label="Sessions" sort={sort} setSort={srt} className="num" />
          <SortTh k="peak_clients" label="Peak clients" sort={sort} setSort={srt} className="num" /><SortTh k="avg_clients" label="Average clients" sort={sort} setSort={srt} className="num" /></tr></thead>
          <tbody>{table.data.items.map((r: any) => <tr key={`${r.day}-${r.ap_id}-${r.ssid}`} {...rowProps(() => onAp(r.ap_id))}>
            <td className="whitespace-nowrap">{periodLabel(r.day, period)}</td><td className="font-medium whitespace-nowrap">{r.ap_name || `AP ${r.ap_id}`}</td><td className="font-mono text-xs">{r.ap_mac}</td><td>{r.ssid || "(none)"}</td>
            <td className="num">{fmtNum(r.unique_clients)}</td><td className="num">{fmtNum(r.sessions)}</td><td className="num">{fmtNum(r.peak_clients)}</td>
            <td className="num">{dash(r.avg_clients, "", 1)}</td></tr>)}</tbody></table></TableWrap>
        <Pager page={page} size={25} total={table.data.total} onPage={setPage} /></>)}
    </Card>
  </>;
}

const RANKS: [string, string][] = [["unique_clients", "Most unique clients"], ["peak_clients", "Highest peak concurrent"], ["avg_clients", "Highest average load"],
  ["disconnects", "Most disconnections"], ["roams", "Most roaming activity"]];

function Rankings({ params, onAp }: { params: any; onAp: (id: number) => void }) {
  const q = useAnalytics("rankings", params);
  const d = q.data;
  return <Card title="AP ranking (top 10)">
    <Loading q={q} />
    {d && <div className="grid grid-cols-1 md:grid-cols-2 2xl:grid-cols-3 gap-4">
      {RANKS.map(([k, l]) => <div key={k}><div className="text-xs text-muted mb-1">{l}</div>
        {d.aps[k]?.some((r: any) => r[k] > 0) ? <TopBar rows={d.aps[k].filter((r: any) => r[k] > 0)} keyField="ap_id" valueField={k} height={230}
          labelFn={(r) => r.ap_name} onClick={(id) => onAp(Number(id))} /> : <Empty text="None in this range." />}</div>)}
      <div><div className="text-xs text-muted mb-1">SSIDs by unique clients</div>
        {d.ssids.unique_clients?.length ? <TableWrap><table className="tbl"><thead><tr><th>SSID</th><th className="num">Unique</th><th className="num">Sessions</th>
          <th className="num">Peak</th><th className="num">Avg</th></tr></thead><tbody>{d.ssids.unique_clients.map((r: any) => <tr key={r.ssid}><td>{r.ssid || "(none)"}</td>
          <td className="num">{fmtNum(r.unique_clients)}</td><td className="num">{fmtNum(r.sessions)}</td><td className="num">{fmtNum(r.peak_clients)}</td>
          <td className="num">{dash(r.avg_clients, "", 1)}</td></tr>)}</tbody></table></TableWrap> : <Empty text="None in this range." />}</div>
    </div>}
  </Card>;
}

function Distribution({ params, onAp }: { params: any; onAp: (id: number) => void }) {
  const { theme } = useTheme();
  const q = useAnalytics("ap/distribution", { ...params, limit: 25 });
  const items = (q.data?.items || []) as any[];
  const rows = useMemo(() => [...items].reverse(), [items]);
  const option = useMemo(() => ({ legend: { top: 0 }, grid: { left: 8, right: 24, top: 32, bottom: 8, containLabel: true },
    tooltip: { trigger: "axis", confine: true, axisPointer: { type: "shadow" }, formatter: (ps: any[]) => {
      const r = rows[ps[0]?.dataIndex];
      return r ? `<b>${r.ap_name}</b><br/>Unique clients: <b>${r.unique_clients}</b>${r.connected_now != null ? ` · connected now: ${r.connected_now}` : ""}`
        + ps.map((p) => `<br/>${p.marker}${p.seriesName}: ${p.value}`).join("") : "";
    } },
    xAxis: { type: "value", minInterval: 1, ...axisStyle },
    yAxis: { type: "category", data: rows.map((r) => r.ap_name), ...axisStyle, axisLabel: { width: 140, overflow: "truncate", fontSize: 11 } },
    // grouped, not stacked: per-band counts overlap (a client seen on two bands is in both), so a stack would overstate the total
    series: [["unique_clients", "All bands (unique)", SERIES_ROLE[theme].muted], ["clients_24", "2.4 GHz", PALETTES[theme][2]], ["clients_5", "5 GHz", PALETTES[theme][0]],
      ["clients_6", "6 GHz", PALETTES[theme][4]]]
      .filter(([k]) => k !== "clients_6" || rows.some((r) => r.clients_6 > 0))
      .map(([k, n, c]) => ({ name: n, type: "bar", barMaxWidth: 7, barGap: "10%", data: rows.map((r) => r[k]), itemStyle: { color: c } })) }), [rows, theme]);
  return <Card title="Client distribution across APs">
    <Loading q={q} />
    {q.data && (items.length ? <Chart height={Math.max(240, items.length * 36 + 50)} option={option} ariaLabel="Unique clients per AP by band"
      onClick={(p) => { const r = rows[p.dataIndex]; if (r) onAp(r.ap_id); }} /> : <Empty text="No client readings in this range." />)}
    <p className="text-2xs text-muted">Unique clients per AP over the selected range, overall and per band. A client that used two bands counts in both band bars but once in "All bands". 6 GHz appears when a controller reports it.</p>
  </Card>;
}

function Roaming({ params }: { params: any }) {
  const q = useAnalytics("roaming", params);
  const d = q.data;
  return <Card title="Roaming analysis">
    <Loading q={q} />
    {d && (!d.daily.length ? <Empty text="No roams detected in this range." /> : <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <div><div className="text-xs text-muted mb-1">Roams per day</div><TopBar rows={[...d.daily].reverse()} keyField="day" valueField="roams" height={200} /></div>
      <div><div className="text-xs text-muted mb-1">Most frequent AP transitions</div>
        <TableWrap maxH="max-h-56"><table className="tbl"><thead><tr><th>From AP</th><th>To AP</th><th className="num">Roams</th></tr></thead>
          <tbody>{d.pairs.map((r: any) => <tr key={`${r.from_ap_id}-${r.to_ap_id}`}><td>{r.from_ap}</td><td>{r.to_ap}</td><td className="num">{fmtNum(r.roams)}</td></tr>)}</tbody></table></TableWrap></div>
    </div>)}
    {d?.note && <p className="text-2xs text-muted mt-2">{d.note}</p>}
  </Card>;
}

/** Client connection history (sessions + association changes), for the client drawer. */
export function ClientHistory({ mac }: { mac: string }) {
  const tz = getTimezone();
  const [days, setDays] = useState(7);
  const [page, setPage] = useState(1);
  const params = { start_date: defaultRange("day", tz).end, end_date: defaultRange("day", tz).end, page, page_size: 20 };
  params.start_date = new Date(Date.parse(`${params.end_date}T00:00:00Z`) - (days - 1) * 86_400_000).toISOString().slice(0, 10);
  const q = useQuery({ queryKey: ["wl", "an", "client", mac, params], queryFn: () => api<any>(`/wireless/analytics/clients/${encodeURIComponent(mac)}/history`, { params }),
    staleTime: STALE, placeholderData: (p) => p });
  const d = q.data;
  return <Card title="Connection history" bodyClass="p-0" right={<select aria-label="History range" className="input py-0.5 text-xs" value={days}
    onChange={(e) => { setDays(Number(e.target.value)); setPage(1); }}>{[1, 7, 30, 90].map((n) => <option key={n} value={n}>{n === 1 ? "today" : `${n} days`}</option>)}</select>}>
    <Loading q={q} />
    {d && (!d.sessions.length ? <Empty text="No recorded sessions in this range (history starts when client tracking was deployed)." /> : <>
      <TableWrap maxH="max-h-80"><table className="tbl"><thead><tr><th>Connected</th><th>Disconnected</th><th className="num">Duration</th><th>SSID</th><th>Band</th>
        <th>AP(s)</th><th className="num">Roams</th><th>End</th></tr></thead>
        <tbody>{d.sessions.map((x: any) => <tr key={x.id}>
          <td className="text-xs whitespace-nowrap"><Time v={x.started_at} />{x.start_source !== "controller" && <span className="text-2xs text-muted" title="first poll that listed the client"> (seen)</span>}</td>
          <td className="text-xs whitespace-nowrap">{x.open ? <span className="text-emerald-300">connected</span> : <><Time v={x.ended_at} /><span className="text-2xs text-muted" title="last poll that listed the client"> (last seen)</span></>}</td>
          <td className="num">{dur(x.duration_s)}</td><td>{x.ssid}</td><td><Band b={x.band} /></td>
          <td className="text-xs">{x.aps.length ? x.aps.join(" → ") : x.last_ap || "—"}</td><td className="num">{x.roams}</td>
          <td className="text-xs">{x.open ? "—" : (x.end_reason || "").replace(/_/g, " ")}{x.disconnect_reason && ` · ${x.disconnect_reason}`}</td></tr>)}</tbody></table></TableWrap>
      <Pager page={page} size={20} total={d.total} onPage={setPage} />
      <p className="text-2xs text-muted px-3 pb-2">{d.note}</p></>)}
  </Card>;
}
