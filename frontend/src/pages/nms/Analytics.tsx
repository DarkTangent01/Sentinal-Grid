import { ReactNode, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { useTheme } from "../../lib/theme";
import { fmtNum } from "../../lib/format";
import { Chart, PALETTES, SEV_HEX, axisStyle } from "../../components/Chart";
import { Card, Empty, Kpi, Loading, TableWrap, Tabs } from "../../components/ui";
import { fmtBps } from "../switches/fmt";
import { GRADE_TONE, TONE_TEXT, availTone, daysTone, fmtAvail, fmtDaysLeft, fmtDur, scoreTone } from "./nms";

/** Sentinel NMS → Network Analytics: device health scores, availability / SLA, capacity forecasting, top-N and
 *  95th percentile, inventory and alert analytics. Everything is computed by /api/nms/analytics from data the
 *  collectors already store; a value that was never measured shows as "—", never as 0. */
export const ANALYTICS_TABS: [string, string][] = [["health", "Device Health"], ["availability", "Availability & SLA"], ["capacity", "Capacity Planning"],
  ["top", "Top-N & 95th Percentile"], ["inventory", "Inventory & Lifecycle"], ["alerts", "Alert Analytics"]];

export function NmsAnalytics() {
  const [sp, setSp] = useSearchParams();
  const tab = ANALYTICS_TABS.some(([k]) => k === sp.get("tab")) ? sp.get("tab")! : "health";
  const [scope, setScope] = useState<{ site?: string; vendor?: string; role?: string }>({});
  return <div className="min-w-0">
    <Tabs value={tab} onChange={(t) => setSp({ tab: t })} tabs={ANALYTICS_TABS.map(([key, label]) => ({ key, label }))} />
    {tab !== "alerts" && <ScopeBar value={scope} onChange={setScope} />}
    <div key={tab}>
      {tab === "health" && <Health scope={scope} />}
      {tab === "availability" && <Availability scope={scope} />}
      {tab === "capacity" && <Capacity scope={scope} />}
      {tab === "top" && <TopN scope={scope} />}
      {tab === "inventory" && <Inventory scope={scope} />}
      {tab === "alerts" && <AlertAnalytics />}
    </div>
  </div>;
}

function ScopeBar({ value, onChange }: { value: Record<string, string | undefined>; onChange: (v: any) => void }) {
  const f = useQuery({ queryKey: ["nms-filters"], queryFn: () => api<any>("/nms/analytics/filters"), staleTime: 300_000 });
  const sel = (k: string, label: string, opts: string[] = []) => (
    <label className="text-xs text-muted flex items-center gap-1">{label}
      <select className="input py-1" value={value[k] || ""} onChange={(e) => onChange({ ...value, [k]: e.target.value || undefined })}>
        <option value="">All</option>{opts.map((o) => <option key={o} value={o}>{o}</option>)}</select></label>);
  return <div className="flex flex-wrap items-center gap-3 mb-3">
    {sel("site", "Site", f.data?.sites)}{sel("vendor", "Vendor", f.data?.vendors)}{sel("role", "Role", f.data?.roles)}
  </div>;
}

function RangeSel({ value, onChange, opts = ["24h", "7d", "30d", "90d"] }: { value: string; onChange: (v: string) => void; opts?: string[] }) {
  return <select className="input py-1 text-xs" value={value} onChange={(e) => onChange(e.target.value)} aria-label="Time range">
    {opts.map((o) => <option key={o} value={o}>Last {o.replace("h", " hours").replace("d", " days")}</option>)}</select>;
}

const Tn = ({ tone, children }: { tone?: string; children: ReactNode }) => <span className={tone ? TONE_TEXT[tone] : "text-muted"}>{children}</span>;
const DevLink = ({ id, name }: { id: number; name: string }) => <Link className="link" to={`/switches/${id}`}>{name}</Link>;

// ------------------------------------------------------------------ health
function Health({ scope }: { scope: any }) {
  const q = useQuery({ queryKey: ["nms-health", scope], queryFn: () => api<any>("/nms/analytics/health", { params: scope }), refetchInterval: 60_000 });
  const d = q.data;
  const { theme } = useTheme();
  const opt = useMemo(() => d && {
    tooltip: { trigger: "item" }, grid: { left: 8, right: 16, top: 16, bottom: 8, containLabel: true },
    xAxis: { type: "category", data: ["0-39", "40-69", "70-89", "90-100"], ...axisStyle }, yAxis: { type: "value", minInterval: 1, ...axisStyle },
    series: [{ type: "bar", barMaxWidth: 48, data: [[0, 40], [40, 70], [70, 90], [90, 101]].map(([a, b], i) => ({
      value: d.devices.filter((x: any) => x.score != null && x.score >= a && x.score < b).length,
      itemStyle: { color: [SEV_HEX.critical, SEV_HEX.high, SEV_HEX.medium, PALETTES[theme][2]][i] } })) }],
  }, [d, theme]);
  return <div className="space-y-4">
    <p className="text-xs text-muted">Health score 0-100 per device: reachability, freshness, CPU, memory, failed fans / PSUs, temperature alarms, full storage,
      interface errors, stack state, open high / critical alerts and metric coverage. Every deduction is listed.</p>
    <Loading q={q} />
    {d && <>
      <div className="kpi-grid">
        <Kpi label="Fleet health" value={d.summary.average ?? "—"} tone={scoreTone(d.summary.average)} sub={`${fmtNum(d.summary.devices)} devices`} />
        {(["healthy", "fair", "poor", "critical"] as const).map((g) => <Kpi key={g} label={g[0].toUpperCase() + g.slice(1)} value={fmtNum(d.summary.grades[g] || 0)}
          tone={(d.summary.grades[g] || 0) && g !== "healthy" ? GRADE_TONE[g] : undefined} />)}
      </div>
      <div className="grid gap-4 xl:grid-cols-3">
        <Card title="Score distribution"><Chart option={opt} height={220} ariaLabel="Devices per health-score band" /></Card>
        <Card title="Sites (worst first)" bodyClass="p-0" className="xl:col-span-2">{!d.sites.length ? <Empty text="No scored devices." /> :
          <TableWrap maxH="max-h-64"><table className="tbl"><thead><tr><th>Site</th><th className="num">Devices</th><th className="num">Average</th><th className="num">Worst</th></tr></thead>
            <tbody>{d.sites.map((x: any) => <tr key={x.site}><td>{x.site}</td><td className="num">{x.devices}</td><td className="num"><Tn tone={scoreTone(x.average)}>{x.average}</Tn></td>
              <td className="num"><Tn tone={scoreTone(x.worst)}>{x.worst}</Tn></td></tr>)}</tbody></table></TableWrap>}</Card>
      </div>
      <Card title="Devices (lowest score first)" bodyClass="p-0">{!d.devices.length ? <Empty text="No monitored devices." /> :
        <TableWrap maxH="max-h-[36rem]"><table className="tbl"><thead><tr><th>Device</th><th>Site</th><th>Model</th><th className="num">Score</th><th>Grade</th><th>Why</th></tr></thead>
          <tbody>{d.devices.map((x: any) => <tr key={x.switch_id}><td><DevLink id={x.switch_id} name={x.name} /></td><td>{x.site || "—"}</td>
            <td className="text-xs">{[x.vendor, x.model].filter(Boolean).join(" ") || "—"}</td><td className="num font-semibold"><Tn tone={scoreTone(x.score)}>{x.score ?? "—"}</Tn></td>
            <td><Tn tone={GRADE_TONE[x.grade]}>{x.grade}</Tn></td><td className="text-xs text-muted">{x.reasons.join(" · ") || "no deductions"}</td></tr>)}</tbody></table></TableWrap>}</Card>
    </>}
  </div>;
}

// ------------------------------------------------------------------ availability
function Availability({ scope }: { scope: any }) {
  const [range, setRange] = useState("30d");
  const [sla, setSla] = useState(99.9);
  const q = useQuery({ queryKey: ["nms-avail", scope, range, sla], queryFn: () => api<any>("/nms/analytics/availability", { params: { ...scope, range, sla } }),
    placeholderData: (p) => p });
  const d = q.data;
  const s = d?.summary || {};
  return <div className="space-y-4">
    <div className="flex flex-wrap items-center gap-3">
      <p className="text-xs text-muted flex-1 min-w-[16rem]">Availability = share of SNMP polls the device answered (switch_up samples). Devices without samples in the range show "—".
        Service availability counts every non-critical check result as available.</p>
      <label className="text-xs text-muted flex items-center gap-1">SLA target
        <select className="input py-1" value={sla} onChange={(e) => setSla(+e.target.value)}>{[99, 99.5, 99.9, 99.95, 99.99].map((v) => <option key={v} value={v}>{v}%</option>)}</select></label>
      <RangeSel value={range} onChange={setRange} />
    </div>
    <Loading q={q} />
    {d && <>
      <div className="kpi-grid">
        <Kpi label="Fleet availability" value={fmtAvail(s.fleet_availability_pct)} tone={availTone(s.fleet_availability_pct, sla)} sub={`${s.measured} of ${s.devices} measured`} />
        <Kpi label="SLA breaches" value={fmtNum(s.sla_breaches)} tone={s.sla_breaches ? "bad" : "ok"} sub={`target ${sla}% · allows ${fmtDur(d.allowed_downtime_s)} down`} />
        <Kpi label="Outages" value={fmtNum(s.outages)} tone={s.outages ? "warn" : "ok"} sub={`${fmtDur(s.downtime_s)} total downtime`} />
        <Kpi label="Service availability" value={fmtAvail(s.services_availability_pct)} tone={availTone(s.services_availability_pct, sla)} sub={`${d.services.length} checks`} />
      </div>
      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="Sites" bodyClass="p-0">{!d.sites.length ? <Empty text="No monitored devices." /> :
          <TableWrap maxH="max-h-80"><table className="tbl"><thead><tr><th>Site</th><th className="num">Devices</th><th className="num">Availability</th><th className="num">Breaches</th>
            <th className="num">Outages</th><th className="num">Downtime</th></tr></thead>
            <tbody>{d.sites.map((x: any) => <tr key={x.site}><td>{x.site}</td><td className="num">{x.devices}</td>
              <td className="num"><Tn tone={availTone(x.availability_pct, sla)}>{fmtAvail(x.availability_pct)}</Tn></td><td className="num">{x.sla_breaches}</td>
              <td className="num">{x.outages}</td><td className="num">{fmtDur(x.downtime_s)}</td></tr>)}</tbody></table></TableWrap>}</Card>
        <Card title="Service checks" bodyClass="p-0" right={<Link className="link text-xs" to="/nms/services">Service checks →</Link>}>
          {!d.services.length ? <Empty text="No service checks defined yet." /> :
            <TableWrap maxH="max-h-80"><table className="tbl"><thead><tr><th>Check</th><th>Kind</th><th className="num">Availability</th><th className="num">Avg / p95 latency</th></tr></thead>
              <tbody>{d.services.map((x: any) => <tr key={x.service_id}><td>{x.name}</td><td className="text-xs uppercase">{x.kind}</td>
                <td className="num"><Tn tone={availTone(x.availability_pct, sla)}>{fmtAvail(x.availability_pct)}</Tn></td>
                <td className="num">{x.latency_avg_ms ?? "—"} / {x.latency_p95_ms ?? "—"} ms</td></tr>)}</tbody></table></TableWrap>}</Card>
      </div>
      <Card title="Devices (least available first)" bodyClass="p-0">
        <TableWrap maxH="max-h-[36rem]"><table className="tbl"><thead><tr><th>Device</th><th>Site</th><th>Role</th><th className="num">Availability</th><th>SLA</th>
          <th className="num">Outages</th><th className="num">Downtime</th><th className="num">Longest</th><th className="num">Samples</th></tr></thead>
          <tbody>{d.devices.map((x: any) => <tr key={x.switch_id}><td><DevLink id={x.switch_id} name={x.name} /></td><td>{x.site || "—"}</td><td>{x.role || "—"}</td>
            <td className="num"><Tn tone={availTone(x.availability_pct, sla)}>{fmtAvail(x.availability_pct)}</Tn></td>
            <td>{x.sla_met == null ? <span className="text-muted">no data</span> : x.sla_met ? <Tn tone="ok">met</Tn> : <Tn tone="bad">breached</Tn>}</td>
            <td className="num">{x.outages}</td><td className="num">{fmtDur(x.downtime_s)}</td><td className="num">{fmtDur(x.longest_outage_s || null)}</td>
            <td className="num text-muted">{fmtNum(x.samples)}</td></tr>)}</tbody></table></TableWrap></Card>
    </>}
  </div>;
}

// ------------------------------------------------------------------ capacity
function Capacity({ scope }: { scope: any }) {
  const [days, setDays] = useState(30);
  const [thrIf, setThrIf] = useState(80);
  const [thrDev, setThrDev] = useState(90);
  const q = useQuery({ queryKey: ["nms-cap", scope, days, thrIf, thrDev], placeholderData: (p) => p,
    queryFn: () => api<any>("/nms/analytics/capacity", { params: { ...scope, days, interface_threshold: thrIf, device_threshold: thrDev } }) });
  const d = q.data;
  const num = (v: number, set: (n: number) => void, label: string, opts: number[]) => <label className="text-xs text-muted flex items-center gap-1">{label}
    <select className="input py-1" value={v} onChange={(e) => set(+e.target.value)}>{opts.map((o) => <option key={o} value={o}>{o}</option>)}</select></label>;
  const Trend = ({ x }: { x: any }) => <><td className="num">{x.current ?? "—"}</td>
    <td className="num">{x.slope_per_day == null ? "—" : `${x.slope_per_day > 0 ? "+" : ""}${x.slope_per_day}/day`}</td>
    <td className="num font-semibold"><Tn tone={daysTone(x.days_left)}>{fmtDaysLeft(x.days_left)}</Tn></td>
    <td className="text-xs text-muted">{x.confidence}{x.r2 != null && ` (r² ${x.r2})`}</td></>;
  return <div className="space-y-4">
    <div className="flex flex-wrap items-center gap-3">
      <p className="text-xs text-muted flex-1 min-w-[16rem]">Linear trend over daily values (interfaces: daily peak utilisation; CPU / memory / storage: daily mean), projected to the
        threshold — the same idea as Zabbix timeleft(). Low-confidence trends (r² &lt; 0.4) are shown but should not drive purchases.</p>
      {num(days, setDays, "History (days)", [14, 30, 60, 90])}{num(thrIf, setThrIf, "Interface threshold %", [60, 70, 80, 90])}
      {num(thrDev, setThrDev, "Device threshold %", [70, 80, 90, 95])}
    </div>
    <Loading q={q} />
    {d && <>
      <div className="kpi-grid">
        <Kpi label="Interfaces over threshold" value={fmtNum(d.summary.interfaces_over_threshold)} tone={d.summary.interfaces_over_threshold ? "bad" : "ok"} />
        <Kpi label="Interfaces at risk ≤ 30 days" value={fmtNum(d.summary.interfaces_at_risk_30d)} tone={d.summary.interfaces_at_risk_30d ? "warn" : "ok"}
          sub={`${fmtNum(d.summary.interfaces_analysed)} interfaces analysed`} />
        <Kpi label="Device resources at risk ≤ 30 days" value={fmtNum(d.summary.devices_at_risk_30d)} tone={d.summary.devices_at_risk_30d ? "warn" : "ok"}
          sub={`${fmtNum(d.summary.device_series_analysed)} CPU / memory / storage series`} />
      </div>
      <Card title="Interfaces" bodyClass="p-0">{!d.interfaces.length ? <Empty text="No interface is over, or trending toward, the threshold." /> :
        <TableWrap maxH="max-h-[28rem]"><table className="tbl"><thead><tr><th>Device</th><th>Interface</th><th className="num">Speed</th><th className="num">Peak % now</th>
          <th className="num">Trend</th><th className="num">Reaches {d.interface_threshold_pct}%</th><th>Confidence</th></tr></thead>
          <tbody>{d.interfaces.map((x: any) => <tr key={`${x.switch_id}-${x.ifindex}`}><td><DevLink id={x.switch_id} name={x.switch} /></td>
            <td><Link className="link" to={`/switches/${x.switch_id}?tab=interfaces&if=${x.ifindex}`}>{x.name}</Link>{x.alias && <div className="text-2xs text-muted">{x.alias}</div>}</td>
            <td className="num">{x.speed_bps ? fmtBps(x.speed_bps) : "—"}</td><Trend x={x} /></tr>)}</tbody></table></TableWrap>}</Card>
      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="CPU, memory and storage" bodyClass="p-0">{!d.devices.length ? <Empty text="No device resource is trending toward the threshold." /> :
          <TableWrap maxH="max-h-96"><table className="tbl"><thead><tr><th>Device</th><th>Metric</th><th className="num">Now</th><th className="num">Trend</th>
            <th className="num">Reaches {d.device_threshold_pct}%</th><th>Confidence</th></tr></thead>
            <tbody>{d.devices.map((x: any) => <tr key={`${x.switch_id}-${x.metric}-${x.component}`}><td><DevLink id={x.switch_id} name={x.switch} /></td>
              <td>{x.metric}{x.component && <div className="text-2xs text-muted">{x.component}</div>}</td><Trend x={x} /></tr>)}</tbody></table></TableWrap>}</Card>
        <Card title="PoE budget headroom" bodyClass="p-0">{!d.poe.length ? <Empty text="No PoE-capable device reports a budget." /> :
          <TableWrap maxH="max-h-96"><table className="tbl"><thead><tr><th>Device</th><th className="num">Budget</th><th className="num">In use</th><th className="num">Headroom</th></tr></thead>
            <tbody>{d.poe.map((x: any) => <tr key={x.switch_id}><td><DevLink id={x.switch_id} name={x.switch} /></td><td className="num">{x.budget_w} W</td>
              <td className="num"><Tn tone={x.pct >= 90 ? "bad" : x.pct >= 75 ? "warn" : "ok"}>{x.used_w} W ({x.pct}%)</Tn></td><td className="num">{x.headroom_w} W</td></tr>)}</tbody></table></TableWrap>}</Card>
      </div>
    </>}
  </div>;
}

// ------------------------------------------------------------------ top-N
const IF_BY: [string, string][] = [["peak_util", "Peak utilisation"], ["avg_util", "Average utilisation"], ["p95", "95th percentile (billing)"],
  ["traffic", "Average traffic"], ["errors", "Errors + CRC"], ["discards", "Discards"], ["down", "Time down"]];
const DEV_BY: [string, string][] = [["cpu", "CPU"], ["memory", "Memory"], ["temperature", "Temperature"], ["storage", "Storage"], ["poll_time", "Poll duration"]];

function TopN({ scope }: { scope: any }) {
  const [range, setRange] = useState("24h");
  const [ifBy, setIfBy] = useState("peak_util");
  const [devBy, setDevBy] = useState("cpu");
  const qi = useQuery({ queryKey: ["nms-topi", scope, range, ifBy], placeholderData: (p) => p,
    queryFn: () => api<any>("/nms/analytics/top/interfaces", { params: { ...scope, range, by: ifBy, limit: 25 } }) });
  const qd = useQuery({ queryKey: ["nms-topd", scope, range, devBy], placeholderData: (p) => p,
    queryFn: () => api<any>("/nms/analytics/top/devices", { params: { ...scope, range, by: devBy, limit: 25 } }) });
  const fmtIf = (v: number) => ["peak_util", "avg_util"].includes(ifBy) ? `${v}%` : ["traffic", "p95"].includes(ifBy) ? fmtBps(v) : fmtNum(v);
  const unitDev = devBy === "temperature" ? " °C" : devBy === "poll_time" ? " s" : "%";
  const sel = (v: string, set: (s: string) => void, opts: [string, string][]) => <select className="input py-1 text-xs" value={v} onChange={(e) => set(e.target.value)}>
    {opts.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>;
  return <div className="space-y-4">
    <div className="flex flex-wrap items-center gap-3"><p className="text-xs text-muted flex-1 min-w-[16rem]">95th percentile uses raw per-poll samples (kept 35 days), nearest-rank on the
      larger of in / out, as transit billing does. Other rankings use the hourly rollups (kept 400 days).</p><RangeSel value={range} onChange={setRange} /></div>
    <Card title="Top interfaces" right={sel(ifBy, setIfBy, IF_BY)} bodyClass="p-0"><Loading q={qi} />
      {qi.data && (!qi.data.items.length ? <Empty text="No interface data in this range." /> :
        <TableWrap maxH="max-h-[30rem]"><table className="tbl"><thead><tr><th>#</th><th>Device</th><th>Interface</th><th className="num">Speed</th><th className="num">{qi.data.unit}</th>
          {ifBy === "p95" && <><th className="num">In p95</th><th className="num">Out p95</th><th className="num">p95 % of link</th><th className="num">Max</th></>}</tr></thead>
          <tbody>{qi.data.items.map((x: any, i: number) => <tr key={`${x.switch_id}-${x.ifindex}`}><td className="text-muted">{i + 1}</td><td><DevLink id={x.switch_id} name={x.switch} /></td>
            <td><Link className="link" to={`/switches/${x.switch_id}?tab=interfaces&if=${x.ifindex}`}>{x.name}</Link>{x.alias && <div className="text-2xs text-muted">{x.alias}</div>}</td>
            <td className="num">{x.speed_bps ? fmtBps(x.speed_bps) : "—"}</td><td className="num font-semibold">{fmtIf(x.value)}</td>
            {ifBy === "p95" && <><td className="num">{fmtBps(x.rx_p95_bps)}</td><td className="num">{fmtBps(x.tx_p95_bps)}</td>
              <td className="num">{x.p95_util_pct == null ? "—" : `${x.p95_util_pct}%`}</td><td className="num">{fmtBps(Math.max(x.rx_max_bps || 0, x.tx_max_bps || 0))}</td></>}</tr>)}</tbody></table></TableWrap>)}</Card>
    <Card title="Top devices" right={sel(devBy, setDevBy, DEV_BY)} bodyClass="p-0"><Loading q={qd} />
      {qd.data && (!qd.data.items.length ? <Empty text="No device data in this range (the metric may be unsupported by these devices)." /> :
        <TableWrap maxH="max-h-[30rem]"><table className="tbl"><thead><tr><th>#</th><th>Device</th><th>Site</th><th>Model</th><th>Component</th><th className="num">Average</th><th className="num">Peak</th></tr></thead>
          <tbody>{qd.data.items.map((x: any, i: number) => <tr key={x.switch_id}><td className="text-muted">{i + 1}</td><td><DevLink id={x.switch_id} name={x.switch} /></td>
            <td>{x.site || "—"}</td><td className="text-xs">{[x.vendor, x.model].filter(Boolean).join(" ") || "—"}</td><td className="text-xs">{x.component || "—"}</td>
            <td className="num">{x.avg}{unitDev}</td><td className="num font-semibold">{x.peak}{unitDev}</td></tr>)}</tbody></table></TableWrap>)}</Card>
  </div>;
}

// ------------------------------------------------------------------ inventory
function Inventory({ scope }: { scope: any }) {
  const [unused, setUnused] = useState(30);
  const q = useQuery({ queryKey: ["nms-inv", scope, unused], queryFn: () => api<any>("/nms/analytics/inventory", { params: { ...scope, unused_days: unused } }),
    placeholderData: (p) => p });
  const d = q.data;
  const { theme } = useTheme();
  const bars = (rows: any[], k: string) => ({
    tooltip: { trigger: "axis", confine: true }, grid: { left: 8, right: 16, top: 8, bottom: 8, containLabel: true },
    xAxis: { type: "value", minInterval: 1, ...axisStyle }, yAxis: { type: "category", inverse: true, data: rows.slice(0, 12).map((r) => r[k]), ...axisStyle },
    series: [{ type: "bar", barMaxWidth: 18, itemStyle: { color: PALETTES[theme][0] }, data: rows.slice(0, 12).map((r) => r.count) }],
  });
  const s = d?.summary || {};
  return <div className="space-y-4">
    <Loading q={q} />
    {d && <>
      <div className="kpi-grid">
        <Kpi label="Devices" value={fmtNum(s.devices)} sub={`${s.vendors} vendors · ${s.models} models`} />
        <Kpi label="Firmware versions" value={fmtNum(s.firmware_versions)} sub={`${s.models_with_firmware_drift} model(s) on mixed firmware`} tone={s.models_with_firmware_drift ? "warn" : "ok"} />
        <Kpi label="Physical ports" value={fmtNum(s.physical_ports)} sub={`${fmtNum(s.ports_up)} up · ${fmtNum(s.ports_admin_down)} admin down`} />
        <Kpi label={`Unused ports (> ${d.unused_days} days down)`} value={fmtNum(s.ports_unused)} sub="reclaimable before buying switches" />
        <Kpi label="Uptime > 1 year" value={fmtNum(s.long_uptime_devices)} tone={s.long_uptime_devices ? "warn" : undefined} sub="likely missing security patches" />
      </div>
      <div className="grid gap-4 xl:grid-cols-3">
        <Card title="Models"><Chart option={bars(d.by_model, "value")} height={260} ariaLabel="Devices per model" /></Card>
        <Card title="Firmware"><Chart option={bars(d.by_firmware, "value")} height={260} ariaLabel="Devices per firmware" /></Card>
        <Card title="Uptime"><Chart option={bars(d.uptime, "bucket")} height={260} ariaLabel="Devices per uptime bucket" /></Card>
      </div>
      <Card title="Firmware drift (same model, different software)" bodyClass="p-0">{!d.firmware_drift.length ? <Empty text="Every model runs a single firmware version." /> :
        <TableWrap maxH="max-h-80"><table className="tbl"><thead><tr><th>Model</th><th>Versions</th><th>Most common</th><th>Devices not on it</th></tr></thead>
          <tbody>{d.firmware_drift.map((x: any) => <tr key={x.model}><td className="font-medium">{x.model}</td>
            <td className="text-xs">{x.versions.map((v: any) => `${v.firmware} (${v.count})`).join(", ")}</td><td>{x.most_common}</td>
            <td className="text-xs">{x.outliers.map((o: any) => <Link key={o.switch_id} className="link mr-2" to={`/switches/${o.switch_id}`}>{o.name} ({o.firmware || "?"})</Link>)}</td></tr>)}</tbody></table></TableWrap>}</Card>
      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="Port usage per device" bodyClass="p-0">
          <TableWrap maxH="max-h-96"><table className="tbl"><thead><tr><th>Device</th><th className="num">Ports</th><th className="num">Up</th><th className="num">In use</th><th className="num">Unused</th></tr></thead>
            <tbody>{d.ports_by_device.map((x: any) => <tr key={x.switch_id}><td><DevLink id={x.switch_id} name={x.name} /></td><td className="num">{x.ports}</td><td className="num">{x.up}</td>
              <td className="num">{x.in_use_pct == null ? "—" : `${x.in_use_pct}%`}</td><td className="num">{x.unused}</td></tr>)}</tbody></table></TableWrap></Card>
        <Card title="Unused ports" bodyClass="p-0" right={<label className="text-xs text-muted flex items-center gap-1">Down for more than
          <select className="input py-1" value={unused} onChange={(e) => setUnused(+e.target.value)}>{[7, 30, 90, 180].map((v) => <option key={v} value={v}>{v} days</option>)}</select></label>}>
          {!d.unused_ports.length ? <Empty text="No port has been down that long." /> :
            <TableWrap maxH="max-h-96"><table className="tbl"><thead><tr><th>Device</th><th>Port</th><th>Down since</th></tr></thead>
              <tbody>{d.unused_ports.map((x: any) => <tr key={`${x.switch_id}-${x.ifindex}`}><td><DevLink id={x.switch_id} name={x.switch} /></td>
                <td>{x.name}{x.alias && <span className="text-2xs text-muted"> · {x.alias}</span>}</td><td className="text-xs">{x.down_since?.slice(0, 10)}</td></tr>)}</tbody></table></TableWrap>}</Card>
      </div>
    </>}
  </div>;
}

// ------------------------------------------------------------------ alerts
function AlertAnalytics() {
  const [range, setRange] = useState("7d");
  const q = useQuery({ queryKey: ["nms-alerts-an", range], queryFn: () => api<any>("/nms/analytics/alerts", { params: { range } }), placeholderData: (p) => p });
  const d = q.data;
  const opt = useMemo(() => d && {
    tooltip: { trigger: "axis", confine: true }, legend: { top: 0 }, grid: { left: 8, right: 16, top: 32, bottom: 8, containLabel: true },
    xAxis: { type: "category", data: d.per_day.map((x: any) => x.day.slice(5)), ...axisStyle }, yAxis: { type: "value", minInterval: 1, ...axisStyle },
    series: ["critical", "high", "medium", "low", "informational"].map((k) => ({ name: k, type: "bar", stack: "s", barMaxWidth: 28, itemStyle: { color: SEV_HEX[k] },
      data: d.per_day.map((x: any) => x[k]) })),
  }, [d]);
  const list = (rows: any[], k: string, label: string, to?: (x: any) => string) => <TableWrap maxH="max-h-80"><table className="tbl">
    <thead><tr><th>{label}</th><th className="num">Alerts</th></tr></thead>
    <tbody>{rows.map((x: any) => <tr key={x[k]}><td>{to ? <Link className="link" to={to(x)}>{x[k]}</Link> : x[k]}</td><td className="num">{x.count}</td></tr>)}</tbody></table></TableWrap>;
  return <div className="space-y-4">
    <div className="flex items-center gap-3"><p className="text-xs text-muted flex-1">Network alerts (switch, wireless, WAN, BGP, service checks…) by the day they opened.
      MTTR = first seen → last seen of resolved alerts.</p><RangeSel value={range} onChange={setRange} opts={["24h", "7d", "30d", "90d"]} /></div>
    <Loading q={q} />
    {d && <>
      <div className="kpi-grid">
        <Kpi label="Alerts opened" value={fmtNum(d.summary.alerts)} />
        <Kpi label="Still open" value={fmtNum(d.summary.open)} tone={d.summary.open ? "warn" : "ok"} />
        <Kpi label="Resolved" value={fmtNum(d.summary.resolved)} />
        <Kpi label="Mean time to resolve" value={fmtDur(d.summary.mttr_s)} />
        <Kpi label="Device events" value={fmtNum(d.summary.events)} />
      </div>
      <Card title="Alerts per day"><Chart option={opt} height={260} ariaLabel="Network alerts per day by severity" /></Card>
      <div className="grid gap-4 xl:grid-cols-3">
        <Card title="Noisiest rules" bodyClass="p-0">{!d.top_rules.length ? <Empty text="No alerts." /> :
          <TableWrap maxH="max-h-80"><table className="tbl"><thead><tr><th>Rule</th><th className="num">Alerts</th><th className="num">MTTR</th></tr></thead>
            <tbody>{d.top_rules.map((x: any) => <tr key={x.rule}><td><Link className="link" to={`/alerts?product=nms&rule=${x.rule}`}>{x.name}</Link></td>
              <td className="num">{x.count}</td><td className="num">{fmtDur(x.mttr_s)}</td></tr>)}</tbody></table></TableWrap>}</Card>
        <Card title="Devices / checks with most alerts" bodyClass="p-0">{!d.top_devices.length ? <Empty text="No alerts." /> : list(d.top_devices, "name", "Device")}</Card>
        <Card title="Sites" bodyClass="p-0">{!d.top_sites.length ? <Empty text="No alerts." /> : list(d.top_sites, "site", "Site")}</Card>
      </div>
      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="Flapping alerts (re-opened 2+ times)" bodyClass="p-0">{!d.flapping_alerts.length ? <Empty text="No alert re-opened repeatedly." /> :
          <TableWrap maxH="max-h-80"><table className="tbl"><thead><tr><th>Rule</th><th>Group</th><th className="num">Re-opened</th></tr></thead>
            <tbody>{d.flapping_alerts.map((x: any) => <tr key={x.rule + x.group_key}><td>{x.name}</td><td className="font-mono text-2xs">{x.group_key}</td>
              <td className="num">{x.reopened}</td></tr>)}</tbody></table></TableWrap>}</Card>
        <Card title="Device events by kind" bodyClass="p-0">{!d.event_kinds.length ? <Empty text="No events." /> : list(d.event_kinds, "kind", "Event")}</Card>
      </div>
    </>}
  </div>;
}
