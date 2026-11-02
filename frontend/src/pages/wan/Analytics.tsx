import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, downloadUrl } from "../../lib/api";
import { useMe } from "../../lib/context";
import { useTheme } from "../../lib/theme";
import { fmtNum, getTimezone } from "../../lib/format";
import { Chart, PALETTES, axisStyle } from "../../components/Chart";
import { Card, Empty, Kpi, Loading, Modal, TableWrap, Time } from "../../components/ui";
import { Avail, Dur, Field, Pager, RangePicker, StateDot, dur, useRange, useWanMeta } from "./common";
import { DailyChart, useGo } from "./Overview";

export function WanAnalytics() {
  const [r, setR, rp] = useRange("30d");
  const go = useGo();
  const tz = getTimezone();
  const { theme } = useTheme();
  const q = useQuery({ queryKey: ["wan-analytics", rp, tz], queryFn: () => api<any>("/wan/analytics", { params: { ...rp, tz } }), placeholderData: (p) => p });
  const d = q.data;
  const t = d?.totals || {};
  const rangeArgs = r.range === "custom" ? { start: rp.start, end: rp.end } : { range: r.range };
  const availOpt = useMemo(() => d?.availability_daily && ({
    tooltip: { trigger: "axis", confine: true }, grid: { left: 8, right: 16, top: 24, bottom: 8, containLabel: true },
    xAxis: { type: "category", data: d.availability_daily.map((x: any) => x.day), ...axisStyle },
    yAxis: { type: "value", name: "%", min: (v: any) => Math.max(0, Math.floor(v.min - 0.5)), max: 100, ...axisStyle },
    series: [{ name: "Availability (all circuits)", type: "line", connectNulls: false, itemStyle: { color: PALETTES[theme][0] }, data: d.availability_daily.map((x: any) => x.availability) }],
  }), [d, theme]);
  const monthOpt = useMemo(() => d && ({
    tooltip: { trigger: "axis", confine: true }, legend: { top: 0 }, grid: { left: 8, right: 16, top: 32, bottom: 8, containLabel: true },
    xAxis: { type: "category", data: d.monthly.map((x: any) => x.month), ...axisStyle },
    yAxis: [{ type: "value", name: "incidents", minInterval: 1, ...axisStyle }, { type: "value", name: "hours down", ...axisStyle, splitLine: { show: false } }],
    series: [{ name: "Incidents", type: "bar", barMaxWidth: 28, itemStyle: { color: PALETTES[theme][0] }, data: d.monthly.map((x: any) => x.incidents) },
      { name: "Downtime (h)", type: "line", yAxisIndex: 1, itemStyle: { color: PALETTES[theme][3] }, data: d.monthly.map((x: any) => +(x.downtime_s / 3600).toFixed(2)) }],
  }), [d, theme]);
  const Group = ({ title, rows, kind }: { title: string; rows: any[] | null; kind: "isp" | "site" | "circuit" }) => (
    <Card title={title} bodyClass="p-0">{!rows ? <Empty text={d?.note || "—"} /> : !rows.length ? <Empty text="No monitored circuits." /> :
      <TableWrap maxH="max-h-80"><table className="tbl"><thead><tr><th>{kind === "isp" ? "ISP" : kind === "site" ? "Site" : "Circuit"}</th><th>Now</th><th className="num">Outages</th>
        <th className="num">Downtime</th><th className="num">Longest</th><th className="num">Availability</th></tr></thead>
        <tbody>{rows.map((x: any) => <tr key={x.group} className="cursor-pointer hover:bg-white/5"
          onClick={() => go("incidents", { ...rangeArgs, ...(kind === "isp" ? { isp: x.isp || x.group } : kind === "site" ? { site: x.site || x.group } : { circuit_id: x.isp_link_id }) })}>
          <td className="font-medium">{x.group}{kind === "circuit" && <div className="text-2xs text-muted">{x.isp} · {x.site}</div>}</td><td><StateDot s={x.state} /></td>
          <td className="num">{fmtNum(x.outages)}</td><td className="num"><Dur s={x.downtime_s} /></td><td className="num"><Dur s={x.longest_s || null} /></td>
          <td className="num"><Avail v={x.availability} coverage={x.coverage_pct} /></td></tr>)}</tbody></table></TableWrap>}</Card>);
  return (
    <div className="space-y-4 min-w-0">
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-xs text-muted flex-1 min-w-[16rem]">Incidents count once each, in the period (and day, in {tz}) their first outage started. Time to detect = confirmation − first failed
          check; time to recover = first good check − first failed check; time to resolve = incident resolution − start.</p>
        <RangePicker value={r} onChange={setR} extra={[["90d", "Last 90 days"], ["365d", "Last 12 months"]]} />
        <a className="btn" href={downloadUrl("/wan/outages.csv", rp)}>Export outages (CSV)</a>
      </div>
      <Loading q={q} />
      {d && <>
        <div className="kpi-grid">
          <Kpi label="Incidents" value={fmtNum(t.incidents)} onClick={() => go("incidents", rangeArgs)} />
          <Kpi label="Open now" value={fmtNum(t.open)} tone={t.open ? "bad" : "ok"} onClick={() => go("incidents", { open_only: 1 })} />
          <Kpi label="Avg / median time to resolve" value={dur(t.avg_resolve_s)} sub={`median ${dur(t.median_resolve_s)} · ${t.resolved} resolved`} />
          <Kpi label="Mean time to detect" value={dur(t.mttd_s)} sub="first failure → confirmed" />
          <Kpi label="Mean time to recover" value={dur(t.mttr_s)} sub={`${fmtNum(t.outages)} outages`} />
          <Kpi label="Sites affected" value={fmtNum(t.sites_affected)} />
          <Kpi label="Missing root cause" value={fmtNum(t.missing_root_cause)} tone={t.missing_root_cause ? "bad" : "ok"} onClick={() => go("incidents", { ...rangeArgs, missing_root_cause: 1 })} />
          <Kpi label="Degradation episodes" value={fmtNum(t.degraded_episodes)} sub="RTT / loss / jitter over thresholds" />
          <Kpi label="Longest outage" value={t.longest_outage ? dur(t.longest_outage.duration_s) : "—"}
            sub={t.longest_outage ? `${t.longest_outage.target} · ${t.longest_outage.isp} ${t.longest_outage.site}${t.longest_outage.ongoing ? " (ongoing)" : ""}` : undefined} />
        </div>
        <DailyChart daily={d.daily} onPick={(day, isp) => go("incidents", { day, isp, tz })} />
        <div className="grid gap-4 xl:grid-cols-2">
          <Group title="Downtime by ISP" rows={d.by_isp} kind="isp" />
          <Group title="Downtime by location" rows={d.by_site} kind="site" />
        </div>
        <Group title="Downtime by circuit (top 50)" rows={d.by_circuit} kind="circuit" />
        <div className="grid gap-4 xl:grid-cols-2">
          <Card title="Availability trend (all circuits, observed time)">{availOpt ? <Chart height={240} option={availOpt} ariaLabel="Daily availability" /> : <Empty text={d.note} />}</Card>
          <Card title="Monthly trend">{d.monthly.length ? <Chart height={240} option={monthOpt!} ariaLabel="Monthly incidents and downtime" /> : <Empty text="No incidents in this range." />}</Card>
        </div>
        <Card title="Incidents by confirmed root cause" bodyClass="p-0">{!d.by_root_cause.length ? <Empty text="No incidents in this range." /> :
          <TableWrap><table className="tbl"><tbody>{d.by_root_cause.map((x: any) => <tr key={x.category} className="cursor-pointer hover:bg-white/5"
            onClick={() => go("incidents", x.category === "(not set)" ? { ...rangeArgs, missing_root_cause: 1 } : { ...rangeArgs, root_cause: x.category })}>
            <td>{x.category}</td><td className="num font-semibold">{x.incidents}</td></tr>)}</tbody></table></TableWrap>}</Card>
      </>}
    </div>
  );
}

export function WanEvents() {
  const [r, setR, rp] = useRange("24h");
  const [to, setTo] = useState("");
  const [page, setPage] = useState(1);
  const params = { ...rp, to_state: to || undefined, page, size: 100 };
  const q = useQuery({ queryKey: ["wan-events", params], queryFn: () => api<any>("/wan/events", { params }), refetchInterval: 30_000, placeholderData: (p) => p });
  return (
    <div className="space-y-4 min-w-0">
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-xs text-muted flex-1">Every state change of every monitored target, with how long the previous state lasted and the checks that caused it.</p>
        <RangePicker value={r} onChange={(x) => { setR(x); setPage(1); }} extra={[["90d", "Last 90 days"]]} />
        <select aria-label="New state" className="input py-1" value={to} onChange={(e) => { setTo(e.target.value); setPage(1); }}><option value="">Any change</option>
          {["down", "up", "degraded", "unknown", "paused"].map((x) => <option key={x} value={x}>→ {x}</option>)}</select>
      </div>
      <Loading q={q} />
      {q.data && <Card title={`Up / down events (${fmtNum(q.data.total)})`} bodyClass="p-0">
        {!q.data.items.length ? <Empty text="No state changes in this range." /> : <>
          <TableWrap><table className="tbl"><thead><tr><th>Time</th><th>Target</th><th>ISP</th><th>Site</th><th>Change</th><th className="num">Previous state lasted</th><th className="w-full">Detail</th></tr></thead>
            <tbody>{q.data.items.map((e: any) => <tr key={e.id}><td className="text-xs whitespace-nowrap"><Time v={e.at} /></td>
              <td>{e.target} <span className="font-mono text-2xs text-muted">{e.address}</span></td><td className="text-xs">{e.isp}</td><td className="text-xs">{e.site}</td>
              <td className="whitespace-nowrap"><StateDot s={e.from} /> → <StateDot s={e.to} /></td><td className="num"><Dur s={e.previous_duration_s} /></td>
              <td className="text-xs">{e.detail}</td></tr>)}</tbody></table></TableWrap>
          <Pager page={page} size={100} total={q.data.total} onPage={setPage} /></>}
      </Card>}
    </div>
  );
}

export function WanConfig() {
  const me = useMe();
  const admin = me.role === "admin";
  const qc = useQueryClient();
  const meta = useWanMeta();
  const s = useQuery({ queryKey: ["wan-settings"], queryFn: () => api<any>("/wan/settings") });
  const m = useQuery({ queryKey: ["wan-maint"], queryFn: () => api<any>("/wan/maintenance") });
  const [f, setF] = useState<any>(null);
  const [mw, setMw] = useState<any>(null);
  const cur = f || s.data;
  const save = useMutation({ mutationFn: () => api("/wan/settings", { method: "PUT", body: f }), onSuccess: () => { setF(null); qc.invalidateQueries({ queryKey: ["wan-settings"] }); qc.invalidateQueries({ queryKey: ["wan-meta"] }); } });
  const delM = useMutation({ mutationFn: (id: number) => api(`/wan/maintenance/${id}`, { method: "DELETE" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["wan-maint"] }) });
  const set = (k: string, v: any) => setF({ ...cur, [k]: v });
  return (
    <div className="space-y-4 min-w-0">
      <Loading q={s} />
      {cur && <Card title="Incident correlation and lifecycle">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <Field label="Group outages into incidents by" hint="Outages join an incident only while it still has an outage in progress (plus the merge gap).">
            <select className="input w-full" disabled={!admin} value={cur.correlation} onChange={(e) => set("correlation", e.target.value)}>
              <option value="target">Target (one incident per monitored address)</option><option value="circuit">Circuit (targets of one circuit together)</option>
              <option value="site">Site (all circuits of a site together)</option></select></Field>
          <Field label="Merge gap (seconds)" hint="0 = only overlapping outages merge"><input type="number" min={0} className="input w-full" disabled={!admin} value={cur.merge_gap_seconds}
            onChange={(e) => set("merge_gap_seconds", Number(e.target.value))} /></Field>
          <Field label="When every outage of an incident recovers" hint="An incident someone is investigating always moves to Monitoring, never to Resolved.">
            <select className="input w-full" disabled={!admin} value={cur.recovery_action} onChange={(e) => set("recovery_action", e.target.value)}>
              <option value="resolve">Resolve it (root cause still to be recorded)</option><option value="monitoring">Move it to Monitoring</option><option value="none">Leave it unchanged</option></select></Field>
          <Field label="Severity: primary circuits"><select className="input w-full" disabled={!admin} value={cur.severity_primary} onChange={(e) => set("severity_primary", e.target.value)}>
            {["low", "medium", "high", "critical"].map((x) => <option key={x}>{x}</option>)}</select></Field>
          <Field label="Severity: backup circuits"><select className="input w-full" disabled={!admin} value={cur.severity_backup} onChange={(e) => set("severity_backup", e.target.value)}>
            {["low", "medium", "high", "critical"].map((x) => <option key={x}>{x}</option>)}</select></Field>
          <Field label="Collector stale after (s)"><input type="number" min={30} className="input w-full" disabled={!admin} value={cur.stale_after_seconds} onChange={(e) => set("stale_after_seconds", Number(e.target.value))} /></Field>
          <Field label="Unobserved gap after (× interval)" hint="Longer pauses between checks are excluded from availability"><input type="number" min={2} max={20} className="input w-full" disabled={!admin}
            value={cur.gap_factor} onChange={(e) => set("gap_factor", Number(e.target.value))} /></Field>
          <label className="text-sm flex items-center gap-2"><input type="checkbox" disabled={!admin} checked={cur.degraded_incidents} onChange={(e) => set("degraded_incidents", e.target.checked)} />
            Open incidents for degradation episodes too</label>
        </div>
        <div className="mt-4"><div className="label">Root-cause categories (classification options a person confirms)</div>
          <div className="space-y-1">{cur.root_cause_categories.map((c: any, i: number) => <div key={i} className="flex gap-2">
            <input aria-label="Key" className="input w-44 font-mono text-xs" disabled={!admin} value={c.key} onChange={(e) => set("root_cause_categories", cur.root_cause_categories.map((x: any, j: number) => j === i ? { ...x, key: e.target.value } : x))} />
            <input aria-label="Label" className="input flex-1" disabled={!admin} value={c.label} onChange={(e) => set("root_cause_categories", cur.root_cause_categories.map((x: any, j: number) => j === i ? { ...x, label: e.target.value } : x))} />
            {admin && <button className="btn" onClick={() => set("root_cause_categories", cur.root_cause_categories.filter((_: any, j: number) => j !== i))}>Remove</button>}</div>)}</div>
          {admin && <button className="btn mt-2" onClick={() => set("root_cause_categories", [...cur.root_cause_categories, { key: "", label: "" }])}>+ Category</button>}</div>
        {save.error && <div role="alert" className="text-sm text-red-400 mt-2">{(save.error as Error).message}</div>}
        {admin && <div className="flex gap-2 mt-3"><button className="btn btn-primary" disabled={!f || save.isPending} onClick={() => save.mutate()}>Save settings</button>
          {f && <button className="btn" onClick={() => setF(null)}>Discard</button>}</div>}
      </Card>}
      <Card title="Maintenance windows" right={admin && <button className="btn" onClick={() => setMw({ name: "", scope: "site", scope_value: "", starts_at: "", ends_at: "", reason: "" })}>+ Schedule</button>} bodyClass="p-0">
        <p className="text-xs text-muted p-3">Outages inside a window are recorded but open no incident, send no notification and are excluded from availability and outage counts.</p>
        <Loading q={m} />
        {m.data && (!m.data.items.length ? <Empty text="No maintenance windows." /> :
          <TableWrap><table className="tbl"><thead><tr><th>Name</th><th>Applies to</th><th>From</th><th>To</th><th>Reason</th><th>By</th>{admin && <th />}</tr></thead>
            <tbody>{m.data.items.map((x: any) => <tr key={x.id}><td className="font-medium">{x.name}{x.active && <span className="pill bg-sky-500/15 text-sky-300 ml-1">active</span>}</td>
              <td className="text-xs">{x.scope}{x.scope_value && `: ${x.scope_value}`}</td><td className="text-xs"><Time v={x.starts_at} /></td><td className="text-xs"><Time v={x.ends_at} /></td>
              <td className="text-xs">{x.reason}</td><td className="text-xs">{x.created_by}</td>
              {admin && <td><button className="btn py-0.5 text-xs" onClick={() => confirm(`Delete maintenance window ${x.name}?`) && delM.mutate(x.id)}>Delete</button></td>}</tr>)}</tbody></table></TableWrap>)}
      </Card>
      <Card title="Alerts and notifications">
        <p className="text-sm">Confirmed outages and recoveries send the <b>wan.outage</b> / <b>wan.recovered</b> notifications (recovery messages include the outage duration):
          add those event types to a routing rule under Notifications. Sustained latency, loss, jitter, flapping, long outages, many incidents at a site, missing root causes,
          a stopped collector, low coverage and availability below target are alert rules (Detections → rules starting with "WAN:") with their own thresholds,
          cooldown and de-duplication.</p>
      </Card>
      {mw && <MaintenanceForm init={mw} meta={meta.data} onClose={() => { setMw(null); qc.invalidateQueries({ queryKey: ["wan-maint"] }); }} />}
    </div>
  );
}

function MaintenanceForm({ init, meta, onClose }: { init: any; meta: any; onClose: () => void }) {
  const [f, setF] = useState<any>(init);
  const circuits = useQuery({ queryKey: ["wan-circuits"], queryFn: () => api<any>("/wan/circuits") });
  const save = useMutation({ mutationFn: () => api("/wan/maintenance", { method: "POST", body: { ...f, starts_at: new Date(f.starts_at).toISOString(), ends_at: new Date(f.ends_at).toISOString() } }), onSuccess: onClose });
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.value });
  const opts: [string, string][] = f.scope === "site" ? (meta?.sites || []).map((x: string) => [x, x]) : f.scope === "isp" ? (meta?.isps || []).map((x: string) => [x, x]) :
    f.scope === "circuit" ? (circuits.data?.items || []).map((c: any) => [String(c.id), c.label]) : [];
  return (
    <Modal title="Schedule maintenance" onClose={onClose}>
      <div className="grid gap-2 sm:grid-cols-2">
        <Field label="Name"><input className="input w-full" value={f.name} onChange={set("name")} placeholder="TTSL fibre work" /></Field>
        <Field label="Applies to"><select className="input w-full" value={f.scope} onChange={(e) => setF({ ...f, scope: e.target.value, scope_value: "" })}>
          <option value="all">Everything</option><option value="site">A site</option><option value="isp">An ISP</option><option value="circuit">A circuit</option><option value="target">A target (id)</option></select></Field>
        {f.scope !== "all" && <Field label="Which">{opts.length ? <select className="input w-full" value={f.scope_value} onChange={set("scope_value")}><option value="">— choose —</option>
          {opts.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select> : <input className="input w-full" value={f.scope_value} onChange={set("scope_value")} />}</Field>}
        <Field label="From"><input type="datetime-local" className="input w-full" value={f.starts_at} onChange={set("starts_at")} /></Field>
        <Field label="To"><input type="datetime-local" className="input w-full" value={f.ends_at} onChange={set("ends_at")} /></Field>
        <div className="sm:col-span-2"><Field label="Reason"><textarea className="input w-full h-16" value={f.reason} onChange={set("reason")} /></Field></div>
      </div>
      {save.error && <div role="alert" className="text-sm text-red-400 mt-2">{(save.error as Error).message}</div>}
      <button className="btn btn-primary mt-3" disabled={!f.name || !f.starts_at || !f.ends_at || save.isPending} onClick={() => save.mutate()}>Schedule</button>
    </Modal>
  );
}
