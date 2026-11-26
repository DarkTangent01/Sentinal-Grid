/** Sentinel NMS → Network Compliance: read-only device checks mapped to CIS Controls v8, PCI DSS v4.0, NIST SP 800-53 r5 and
 *  ISO/IEC 27001:2022. Evidence comes from configuration backups, FortiGate snapshots, polling, TACACS+ and syslog; nothing
 *  is changed on a device (suggested CLI is for review). "No evidence" is never counted as met or not met. */
import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, downloadUrl } from "../../lib/api";
import { useMe } from "../../lib/context";
import { useTheme } from "../../lib/theme";
import { Chart, SERIES_ROLE, axisStyle } from "../../components/Chart";
import { Card, Drawer, Empty, Field, Kpi, Loading, Modal, rowProps, TableWrap, Tabs, Time, useDebounced } from "../../components/ui";

const TABS = [{ key: "overview", label: "Overview" }, { key: "controls", label: "Controls" }, { key: "checks", label: "Checks" },
  { key: "devices", label: "Devices" }, { key: "exceptions", label: "Exceptions" }];
const FW_KEYS = ["cis", "pci", "nist", "iso"];
const STATUS: Record<string, [string, string]> = {
  pass: ["Met", "text-emerald-300"], fail: ["Not met", "text-red-300"],
  not_evaluated: ["No evidence", "text-slate-300"], excepted: ["Excepted", "text-sky-300"],
  met: ["Met", "text-emerald-300"], partial: ["Partially met", "text-amber-300"],
  not_met: ["Not met", "text-red-300"], no_evidence: ["No evidence", "text-slate-300"],
};
const pct = (v: number | null | undefined) => (v == null ? "—" : `${v}%`);
const KIND: Record<string, string> = { switch: "Switch / router / WLC", firewall: "FortiGate" };

function Pill({ s }: { s: string }) {
  const [label, cls] = STATUS[s] || [s, "text-slate-300"];
  return <span className={`pill ${cls}`}>{label}</span>;
}

function SevText({ s }: { s: string }) {
  return <span className={`text-xs font-medium ${s === "high" ? "text-red-400" : s === "medium" ? "text-amber-300" : "text-muted"}`}>{s}</span>;
}

/** met / not met / no evidence / excepted as one stacked bar with the counts as text (colour is never the only cue) */
function Split({ x }: { x: { pass: number; fail: number; not_evaluated: number; excepted?: number } }) {
  const t = x.pass + x.fail + x.not_evaluated + (x.excepted || 0);
  if (!t) return <span className="text-muted text-xs">—</span>;
  const w = (n: number) => `${(100 * n) / t}%`;
  return <div className="min-w-[8rem]">
    <div className="flex h-1.5 rounded overflow-hidden bg-slate-800" aria-hidden>
      <div className="bg-emerald-500" style={{ width: w(x.pass) }} /><div className="bg-red-500" style={{ width: w(x.fail) }} />
      <div className="bg-sky-500" style={{ width: w(x.excepted || 0) }} /><div className="bg-slate-500/50" style={{ width: w(x.not_evaluated) }} /></div>
    <div className="text-2xs text-muted mt-0.5 tabular-nums">{x.pass} met · {x.fail} not met · {x.not_evaluated} no evidence{x.excepted ? ` · ${x.excepted} excepted` : ""}</div>
  </div>;
}

export function NetCompliancePage() {
  const [sp, setSp] = useSearchParams();
  const me = useMe();
  const admin = me?.role === "admin";
  const qc = useQueryClient();
  const tab = TABS.some((t) => t.key === sp.get("tab")) ? sp.get("tab")! : "overview";
  const fw = FW_KEYS.includes(sp.get("fw") || "") ? sp.get("fw")! : "";
  const set = (patch: Record<string, string | null>) => {
    const next = new URLSearchParams(sp);
    for (const [k, v] of Object.entries(patch)) v ? next.set(k, v) : next.delete(k);
    setSp(next);
  };
  const catalog = useQuery({ queryKey: ["nc-catalog"], queryFn: () => api<any>("/nms/compliance/catalog"), staleTime: 3600_000 });
  const sum = useQuery({ queryKey: ["nc-summary", fw], queryFn: () => api<any>("/nms/compliance/summary", { params: { framework: fw || undefined } }) });
  const run = useMutation({ mutationFn: () => api("/nms/compliance/run", { method: "POST" }), onSuccess: () => qc.invalidateQueries({ predicate: (q) => String(q.queryKey[0]).startsWith("nc-") }) });
  const r = sum.data?.run;
  return <div className="space-y-4 min-w-0">
    <p className="text-xs text-muted">Read-only checks of switches, routers, wireless controllers and FortiGates, using data Sentinel already collects:
      configuration backups (secrets masked), FortiGate configuration snapshots, SNMP polling, TACACS+ and syslog. Results support audits; they are not a
      certification. <b className="text-slate-300">No evidence</b> means the data needed is missing and is never counted as met or not met. Suggested CLI is for review: nothing is pushed to devices.</p>
    <div className="flex flex-wrap items-center gap-2">
      <select aria-label="Framework" className="input py-1" value={fw} onChange={(e) => set({ fw: e.target.value || null, control: null })}>
        <option value="">All frameworks</option>
        {FW_KEYS.map((k) => <option key={k} value={k}>{catalog.data?.frameworks?.[k]?.name || k}</option>)}
      </select>
      <span className="text-xs text-muted">{r ? <>Evaluated <Time v={r.started_at} /> · {r.devices} devices · {r.trigger === "manual" ? `run by ${r.triggered_by}` : r.trigger === "data" ? "after a configuration change" : "daily"}</>
        : sum.data ? "Not evaluated yet" : ""}</span>
      <span className="flex-1" />
      <a className="btn" href={downloadUrl("/nms/compliance/export.csv", { framework: fw || undefined })}>Export CSV</a>
      {admin && <button type="button" className="btn btn-primary" disabled={run.isPending} onClick={() => run.mutate()}>{run.isPending ? "Evaluating…" : "Evaluate now"}</button>}
    </div>
    {run.error && <div role="alert" className="text-sm text-red-400">Evaluation failed: {String((run.error as Error).message)}</div>}
    <Tabs value={tab} onChange={(t) => set({ tab: t })} tabs={TABS} />
    <Loading q={sum} />
    {sum.data && !r && <Card><Empty text={admin ? "No evaluation has run yet. Use “Evaluate now”, or wait for the worker (it runs once a day and after configuration changes)."
      : "No evaluation has run yet. The worker runs it once a day and after configuration changes."} /></Card>}
    {r && catalog.data && <>
      {tab === "overview" && <Overview d={sum.data} fw={fw} catalog={catalog.data} set={set} />}
      {tab === "controls" && <Controls fw={fw || "cis"} catalog={catalog.data} set={set} />}
      {tab === "checks" && <Checks d={sum.data} fw={fw} set={set} />}
      {tab === "devices" && <Devices fw={fw} set={set} />}
      {tab === "exceptions" && <Exceptions admin={admin} />}
    </>}
    {sp.get("device") && <DeviceDrawer id={sp.get("device")!} fw={fw} admin={admin} onClose={() => set({ device: null })} />}
    {sp.get("check") && <CheckDrawer id={sp.get("check")!} admin={admin} onClose={() => set({ check: null })} openDevice={(k, id) => set({ check: null, device: `${k}:${id}` })} />}
  </div>;
}

function Overview({ d, fw, catalog, set }: { d: any; fw: string; catalog: any; set: (p: Record<string, string | null>) => void }) {
  const { theme } = useTheme();
  const highFails = d.checks.filter((c: any) => c.severity === "high" && c.fail).length;
  const trend = useMemo(() => ({
    grid: { left: 8, right: 16, top: 28, bottom: 8, containLabel: true }, legend: { top: 0 }, tooltip: { trigger: "axis", confine: true },
    xAxis: { type: "time", ...axisStyle }, yAxis: { type: "value", min: 0, max: 100, ...axisStyle, axisLabel: { ...axisStyle.axisLabel, formatter: "{value}%" } },
    series: [{ name: "Score (met / evaluated)", type: "line", showSymbol: d.trend.length < 20, connectNulls: false, itemStyle: { color: SERIES_ROLE[theme].primary },
      data: d.trend.map((t: any) => [Date.parse(t.at), t.score]) },
    { name: "Evidence coverage", type: "line", showSymbol: false, lineStyle: { type: "dashed", width: 1.5 }, itemStyle: { color: SERIES_ROLE[theme].muted },
      data: d.trend.map((t: any) => [Date.parse(t.at), t.coverage]) }],
  }), [d.trend, theme]);
  return <>
    <div className="kpi-grid">
      <Kpi label={fw ? `${catalog.frameworks[fw].short} score` : "Overall score"} value={pct(d.overall.score)} sub="met ÷ (met + not met)"
        tone={d.overall.score == null ? undefined : d.overall.score >= 90 ? "ok" : d.overall.score >= 70 ? "warn" : "bad"} />
      <Kpi label="Evidence coverage" value={pct(d.overall.coverage)} sub={`${d.overall.not_evaluated} results without evidence`} />
      <Kpi label="Not met" value={d.overall.fail} sub={`${highFails} high-severity check(s) failing`} tone={d.overall.fail ? "bad" : "ok"} onClick={() => set({ tab: "checks" })} />
      <Kpi label="Devices" value={d.run.devices} sub={d.devices_by_kind ? `${d.devices_by_kind.switch || 0} switches / routers / WLCs · ${d.devices_by_kind.firewall || 0} FortiGates` : undefined}
        onClick={() => set({ tab: "devices" })} />
      <Kpi label="Active exceptions" value={d.exceptions_active} onClick={() => set({ tab: "exceptions" })} />
    </div>
    <div className="grid-cards md:grid-cols-2 xl:grid-cols-4">
      {FW_KEYS.map((k) => { const f = d.frameworks[k]; return (
        <button key={k} type="button" onClick={() => set({ fw: k, tab: "controls" })}
          className={`card p-4 text-left card-interactive ${fw === k ? "border-line-strong" : ""}`}>
          <div className="text-2xs uppercase tracking-wide text-muted font-semibold">{f.name}</div>
          <div className="text-2xl font-extrabold tabular-nums mt-1">{pct(f.score)}</div>
          <div className="text-2xs text-muted mb-2">coverage {pct(f.coverage)}</div>
          <Split x={f} />
        </button>); })}
    </div>
    <div className="grid-cards xl:grid-cols-2">
      <Card title="Trend">{d.trend.length > 1 ? <Chart height={220} option={trend} ariaLabel="Compliance score and evidence coverage over time" />
        : <Empty text="The trend appears after the second evaluation." />}</Card>
      <Card title="By severity" bodyClass="p-0"><TableWrap><table className="tbl"><thead><tr><th>Severity</th><th>Results</th><th className="num">Score</th></tr></thead>
        <tbody>{["high", "medium", "low"].map((s) => <tr key={s}><td><SevText s={s} /></td><td><Split x={d.by_severity[s]} /></td><td className="num">{pct(d.by_severity[s].score)}</td></tr>)}</tbody></table></TableWrap></Card>
    </div>
    <div className="grid-cards xl:grid-cols-2">
      <Card title="Most failed checks" bodyClass="p-0">{!d.checks.some((c: any) => c.fail) ? <Empty text="No check is failing." /> :
        <TableWrap><table className="tbl"><thead><tr><th>Check</th><th>Severity</th><th className="num">Devices not met</th></tr></thead>
          <tbody>{d.checks.filter((c: any) => c.fail).slice(0, 10).map((c: any) => <tr key={c.id} {...rowProps(() => set({ check: c.id }))}>
            <td><span className="font-mono text-xs text-muted mr-1.5">{c.id}</span>{c.title}</td><td><SevText s={c.severity} /></td><td className="num">{c.fail}</td></tr>)}</tbody></table></TableWrap>}</Card>
      <Card title="Devices with the most findings" bodyClass="p-0">{!d.worst_devices.length ? <Empty text="No device has a failing check." /> :
        <TableWrap><table className="tbl"><thead><tr><th>Device</th><th>Site</th><th className="num">High</th><th className="num">Not met</th><th className="num">Score</th></tr></thead>
          <tbody>{d.worst_devices.map((x: any) => <tr key={`${x.kind}${x.id}`} {...rowProps(() => set({ device: `${x.kind}:${x.id}` }))}>
            <td>{x.name}<div className="text-2xs text-muted">{KIND[x.kind]}</div></td><td>{x.site || "—"}</td>
            <td className={`num ${x.fail_high ? "text-red-400 font-semibold" : ""}`}>{x.fail_high}</td><td className="num">{x.fail}</td><td className="num">{pct(x.score)}</td></tr>)}</tbody></table></TableWrap>}</Card>
    </div>
  </>;
}

function Controls({ fw, catalog, set }: { fw: string; catalog: any; set: (p: Record<string, string | null>) => void }) {
  const q = useQuery({ queryKey: ["nc-controls", fw], queryFn: () => api<any>("/nms/compliance/controls", { params: { framework: fw } }) });
  const [open, setOpen] = useState<string | null>(null);
  const d = q.data;
  return <>
    <div className="flex flex-wrap items-center gap-2">
      <div className="flex flex-wrap gap-1" role="group" aria-label="Framework">{FW_KEYS.map((k) =>
        <button key={k} type="button" aria-pressed={fw === k} onClick={() => set({ fw: k })}
          className={`btn py-1 ${fw === k ? "border-line-strong text-slate-100 font-semibold" : ""}`}>{catalog.frameworks[k].short}</button>)}</div>
      {d && <span className="text-xs text-muted">{d.note}</span>}
    </div>
    <Loading q={q} />
    {d && <Card title={`${d.name}: ${d.items.length} controls with device evidence`} right={<span className="text-xs text-muted">score {pct(d.score)} · coverage {pct(d.coverage)}</span>} bodyClass="p-0">
      <TableWrap><table className="tbl"><thead><tr><th>Control</th><th>Title</th><th>Status</th><th>Results</th><th>Checks</th></tr></thead>
        <tbody>{d.items.map((c: any) => <ControlRow key={c.control} c={c} open={open === c.control} toggle={() => setOpen(open === c.control ? null : c.control)} set={set} />)}</tbody></table></TableWrap>
      <p className="text-2xs text-muted p-3">Controls that need process evidence (reviews, approvals, training, risk assessment) are not listed: no device check can show them.</p>
    </Card>}
  </>;
}

function ControlRow({ c, open, toggle, set }: { c: any; open: boolean; toggle: () => void; set: (p: Record<string, string | null>) => void }) {
  return <>
    <tr aria-expanded={open} {...rowProps(toggle)}><td className="font-mono text-xs nowrap">{c.control}</td><td className="cell-wrap min-w-[14rem]">{c.title}</td>
      <td><Pill s={c.status} /></td><td><Split x={c} /></td><td className="num">{c.checks.length} {open ? "▾" : "▸"}</td></tr>
    {open && <tr><td colSpan={5} className="bg-panel2">
      <ul className="space-y-1.5">{c.checks.map((k: any) => <li key={k.id} className="flex flex-wrap items-center gap-2">
        <button type="button" className="link" onClick={() => set({ check: k.id })}><span className="font-mono text-xs">{k.id}</span> {k.title}</button>
        <SevText s={k.severity} /><span className="ml-auto"><Split x={k} /></span></li>)}</ul></td></tr>}
  </>;
}

function Checks({ d, fw, set }: { d: any; fw: string; set: (p: Record<string, string | null>) => void }) {
  const [cat, setCat] = useState("");
  const cats = Array.from(new Set(d.checks.map((c: any) => c.category))).sort() as string[];
  const rows = d.checks.filter((c: any) => !cat || c.category === cat);
  return <Card title={`Checks${fw ? ` mapped to ${d.frameworks[fw].name}` : ""} (${rows.length})`} bodyClass="p-0"
    right={<select aria-label="Category" className="input py-1" value={cat} onChange={(e) => setCat(e.target.value)}><option value="">All categories</option>{cats.map((c) => <option key={c}>{c}</option>)}</select>}>
    <TableWrap><table className="tbl"><thead><tr><th>Check</th><th>Category</th><th>Severity</th><th>Applies to</th><th>Evidence from</th><th>Results</th><th className="num">Score</th></tr></thead>
      <tbody>{rows.map((c: any) => <tr key={c.id} {...rowProps(() => set({ check: c.id }))}>
        <td className="cell-wrap min-w-[16rem]"><span className="font-mono text-xs text-muted mr-1.5">{c.id}</span>{c.title}</td><td>{c.category}</td><td><SevText s={c.severity} /></td>
        <td className="text-xs">{c.kinds.map((k: string) => KIND[k]).join(", ")}</td><td className="text-xs">{c.source.replace("+", " + ")}</td><td><Split x={c} /></td><td className="num">{pct(c.score)}</td></tr>)}</tbody></table></TableWrap>
  </Card>;
}

function Devices({ fw, set }: { fw: string; set: (p: Record<string, string | null>) => void }) {
  const [f, setF] = useState({ kind: "", site: "", vendor: "", status: "", q: "" });
  const q = useDebounced(f.q, 300);
  const r = useQuery({ queryKey: ["nc-devices", fw, f.kind, f.site, f.vendor, f.status, q], queryFn: () => api<any>("/nms/compliance/devices",
    { params: { framework: fw || undefined, kind: f.kind || undefined, site: f.site || undefined, vendor: f.vendor || undefined, status: f.status || undefined, q: q || undefined } }) });
  const up = (k: string) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  return <>
    <div className="flex flex-wrap items-center gap-2">
      <input aria-label="Search devices" className="input py-1 w-56" placeholder="Device name" value={f.q} onChange={up("q")} />
      <select aria-label="Device kind" className="input py-1" value={f.kind} onChange={up("kind")}><option value="">All devices</option><option value="switch">Switches / routers / WLCs</option><option value="firewall">FortiGates</option></select>
      <select aria-label="Site" className="input py-1" value={f.site} onChange={up("site")}><option value="">All sites</option>{(r.data?.sites || []).map((s: string) => <option key={s}>{s}</option>)}</select>
      <select aria-label="Vendor" className="input py-1" value={f.vendor} onChange={up("vendor")}><option value="">All vendors</option>{(r.data?.vendors || []).map((s: string) => <option key={s}>{s}</option>)}</select>
      <select aria-label="Result" className="input py-1" value={f.status} onChange={up("status")}><option value="">Any result</option><option value="failing">With findings</option>
        <option value="passing">All evaluated checks met</option><option value="no_evidence">No evidence at all</option></select>
    </div>
    <Card bodyClass="p-0"><Loading q={r} />
      {r.data && (!r.data.items.length ? <Empty text="No device matches." /> :
        <TableWrap><table className="tbl"><thead><tr><th>Device</th><th>Type</th><th>Site</th><th>Vendor</th><th className="num">High</th><th className="num">Medium</th><th className="num">Low</th><th>Results</th><th className="num">Score</th></tr></thead>
          <tbody>{r.data.items.map((x: any) => <tr key={`${x.kind}${x.id}`} {...rowProps(() => set({ device: `${x.kind}:${x.id}` }))}>
            <td>{x.name}</td><td className="text-xs">{x.kind === "firewall" ? "FortiGate" : x.device_type || "—"}</td><td>{x.site || "—"}</td><td>{x.vendor || "—"}</td>
            <td className={`num ${x.fail_high ? "text-red-400 font-semibold" : ""}`}>{x.fail_high}</td><td className="num">{x.fail_medium}</td><td className="num">{x.fail_low}</td>
            <td><Split x={x} /></td><td className="num">{pct(x.score)}</td></tr>)}</tbody></table></TableWrap>)}</Card>
  </>;
}

function Refs({ refs }: { refs: Record<string, string[]> }) {
  return <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-xs">{FW_KEYS.map((k) => refs[k] && <div key={k} className="contents">
    <dt className="text-muted">{k === "cis" ? "CIS v8" : k === "pci" ? "PCI DSS" : k === "nist" ? "NIST 800-53" : "ISO 27001"}</dt><dd className="font-mono">{refs[k].join(", ")}</dd></div>)}</dl>;
}

function DeviceDrawer({ id, fw, admin, onClose }: { id: string; fw: string; admin: boolean; onClose: () => void }) {
  const [kind, num] = id.split(":");
  const q = useQuery({ queryKey: ["nc-device", kind, num, fw], queryFn: () => api<any>(`/nms/compliance/devices/${kind}/${num}`, { params: { framework: fw || undefined } }) });
  const [exc, setExc] = useState<any>(null);
  const d = q.data;
  return <Drawer title={d ? `${d.name}: compliance` : "Device compliance"} onClose={onClose}>
    <Loading q={q} />
    {d && <div className="space-y-3">
      <div className="kpi-grid"><Kpi label="Score" value={pct(d.score)} /><Kpi label="Not met" value={d.fail} tone={d.fail ? "bad" : "ok"} />
        <Kpi label="No evidence" value={d.not_evaluated} /><Kpi label="Excepted" value={d.excepted} /></div>
      <div className="text-xs text-muted">{KIND[d.kind]} · {d.vendor || "unknown vendor"}{d.site ? ` · ${d.site}` : ""} · evaluated <Time v={d.run.started_at} /></div>
      {d.findings.map((f: any) => <section key={f.id} className="border border-line rounded-lg p-3 space-y-2">
        <div className="flex flex-wrap items-center gap-2"><Pill s={f.status} /><span className="font-mono text-xs text-muted">{f.id}</span>
          <span className="font-medium">{f.title}</span><SevText s={f.severity} /></div>
        <p className="text-sm">{f.evidence}</p>
        {f.lines.length > 0 && <pre className="text-xs font-mono bg-panel2 border border-line rounded p-2 overflow-x-auto">{f.lines.join("\n")}</pre>}
        {f.lines_hidden && <p className="text-2xs text-muted">Configuration lines are shown to administrators.</p>}
        {f.exception && <p className="text-xs text-sky-300">Excepted until <Time v={f.exception.expires_at} /> by {f.exception.created_by}
          {f.exception.scope === "all" ? " (all devices)" : ""}: {f.exception.reason}</p>}
        {f.fix && <details><summary className="text-xs link">Suggested CLI (review before applying; nothing is pushed)</summary>
          <pre className="text-xs font-mono bg-panel2 border border-line rounded p-2 mt-1 overflow-x-auto">{f.fix}</pre></details>}
        <details><summary className="text-xs text-muted cursor-pointer">Why and framework mapping</summary><p className="text-xs text-muted my-1">{f.rationale}</p><Refs refs={f.refs} /></details>
        {admin && !f.exception && ["fail", "not_evaluated"].includes(f.raw_status) &&
          <button type="button" className="btn py-0.5 text-xs" aria-label={`Add exception for ${f.id} on ${d.name}`} onClick={() => setExc({ check_id: f.id, device_kind: d.kind, device_id: d.id, title: f.title, device: d.name })}>Add exception…</button>}
      </section>)}
    </div>}
    {exc && <ExceptionForm init={exc} onClose={() => setExc(null)} />}
  </Drawer>;
}

function CheckDrawer({ id, admin, onClose, openDevice }: { id: string; admin: boolean; onClose: () => void; openDevice: (k: string, id: number) => void }) {
  const q = useQuery({ queryKey: ["nc-check", id], queryFn: () => api<any>(`/nms/compliance/checks/${encodeURIComponent(id)}`) });
  const [exc, setExc] = useState<any>(null);
  const d = q.data;
  return <Drawer title={d ? `${d.id} ${d.title}` : id} onClose={onClose}>
    <Loading q={q} />
    {d && <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-3 text-xs"><SevText s={d.severity} /><span className="text-muted">{d.category}</span>
        <span className="text-muted">evidence: {d.source.replace("+", " + ")}</span><span className="text-muted">applies to: {d.kinds.map((k: string) => KIND[k]).join(", ")}</span></div>
      <p className="text-sm">{d.rationale}</p>
      <Refs refs={d.refs} />
      <Split x={d} />
      {Object.keys(d.fix).length > 0 && <details><summary className="text-xs link">Suggested CLI per vendor (review before applying)</summary>
        {Object.entries(d.fix).map(([v, cli]: any) => <div key={v} className="mt-2"><div className="text-2xs uppercase text-muted">{v}</div>
          <pre className="text-xs font-mono bg-panel2 border border-line rounded p-2 overflow-x-auto">{cli}</pre></div>)}</details>}
      {admin && <div className="flex flex-wrap gap-2">{d.kinds.map((k: string) => <button key={k} type="button" className="btn py-0.5 text-xs"
        onClick={() => setExc({ check_id: d.id, device_kind: k, device_id: null, title: d.title, device: `all ${KIND[k]} devices` })}>Except for all {KIND[k]} devices…</button>)}</div>}
      <TableWrap><table className="tbl"><thead><tr><th>Device</th><th>Result</th><th>Evidence</th></tr></thead>
        <tbody>{d.items.map((x: any) => <tr key={`${x.kind}${x.id}`} {...rowProps(() => openDevice(x.kind, x.id))}>
          <td className="nowrap">{x.name}<div className="text-2xs text-muted">{x.site || ""}</div></td><td><Pill s={x.status} /></td><td className="cell-wrap text-xs min-w-[16rem]">{x.evidence}</td></tr>)}</tbody></table></TableWrap>
    </div>}
    {exc && <ExceptionForm init={exc} onClose={() => setExc(null)} />}
  </Drawer>;
}

function ExceptionForm({ init, onClose }: { init: any; onClose: () => void }) {
  const qc = useQueryClient();
  const [reason, setReason] = useState("");
  const [days, setDays] = useState(90);
  const m = useMutation({ mutationFn: () => api("/nms/compliance/exceptions", { method: "POST", body: { check_id: init.check_id, device_kind: init.device_kind,
    device_id: init.device_id, reason, days } }), onSuccess: () => { qc.invalidateQueries({ predicate: (q) => String(q.queryKey[0]).startsWith("nc-") }); onClose(); } });
  return <Modal title={`Exception: ${init.check_id}`} onClose={onClose}>
    <div className="space-y-3">
      <p className="text-sm">{init.title} — {init.device}. The result stays as evaluated; reports show it as excepted until the exception expires.</p>
      <Field label="Reason (risk acceptance or compensating control, at least 10 characters)"><textarea className="input w-full h-24" value={reason} onChange={(e) => setReason(e.target.value)} /></Field>
      <Field label="Expires after"><select className="input" value={days} onChange={(e) => setDays(Number(e.target.value))}>{[30, 90, 180, 365].map((n) => <option key={n} value={n}>{n} days</option>)}</select></Field>
      {m.error && <div role="alert" className="text-sm text-red-400">{String((m.error as Error).message)}</div>}
      <div className="flex justify-end gap-2"><button type="button" className="btn" onClick={onClose}>Cancel</button>
        <button type="button" className="btn btn-primary" disabled={reason.trim().length < 10 || m.isPending} onClick={() => m.mutate()}>Add exception</button></div>
    </div>
  </Modal>;
}

function Exceptions({ admin }: { admin: boolean }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["nc-exceptions"], queryFn: () => api<any>("/nms/compliance/exceptions") });
  const [del, setDel] = useState<any>(null);
  const m = useMutation({ mutationFn: (id: number) => api(`/nms/compliance/exceptions/${id}`, { method: "DELETE" }),
    onSuccess: () => { qc.invalidateQueries({ predicate: (x) => String(x.queryKey[0]).startsWith("nc-") }); setDel(null); } });
  return <Card title="Exceptions (accepted risk)" bodyClass="p-0" right={<span className="text-xs text-muted">{admin ? "Add one from a device or check." : "Administrators manage exceptions."}</span>}>
    <Loading q={q} />
    {q.data && (!q.data.items.length ? <Empty text="No exceptions." /> :
      <TableWrap><table className="tbl"><thead><tr><th>Check</th><th>Scope</th><th>Reason</th><th>Expires</th><th>By</th>{admin && <th />}</tr></thead>
        <tbody>{q.data.items.map((e: any) => <tr key={e.id} className={e.expired ? "opacity-60" : ""}>
          <td className="cell-wrap min-w-[14rem]"><span className="font-mono text-xs text-muted mr-1.5">{e.check_id}</span>{e.check_title}</td>
          <td>{e.device_name}<div className="text-2xs text-muted">{KIND[e.device_kind]}</div></td><td className="cell-wrap min-w-[16rem] text-xs">{e.reason}</td>
          <td className="nowrap">{e.expired ? <span className="pill text-slate-300">expired</span> : <Time v={e.expires_at} />}</td><td>{e.created_by}</td>
          {admin && <td><button type="button" className="btn btn-danger py-0.5 text-xs" aria-label={`Remove exception ${e.check_id} on ${e.device_name}`} onClick={() => setDel(e)}>Remove</button></td>}</tr>)}</tbody></table></TableWrap>)}
    {del && <Modal title="Remove exception" onClose={() => setDel(null)}>
      <p className="text-sm mb-3">Remove the exception for {del.check_id} on {del.device_name}? The result counts again as {""}
        evaluated from now on.</p>
      {m.error && <div role="alert" className="text-sm text-red-400 mb-2">{String((m.error as Error).message)}</div>}
      <div className="flex justify-end gap-2"><button type="button" className="btn" onClick={() => setDel(null)}>Cancel</button>
        <button type="button" className="btn btn-danger" disabled={m.isPending} onClick={() => m.mutate(del.id)}>Remove</button></div>
    </Modal>}
  </Card>;
}
