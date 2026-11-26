/** Sentinel Grid SOC views: SOC overview (executive + operations), ATT&CK coverage, entity risk, response actions.
 *  Every figure comes from /api/soc, /api/mitre, /api/risk and /api/response (stored alerts, incidents, events);
 *  a figure that cannot be measured shows "—", never zero. */
import { useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useMe } from "../lib/context";
import { fmtNum } from "../lib/format";
import { useTheme } from "../lib/theme";
import { Chart, PALETTES, SEV_HEX, SERIES_ROLE, axisStyle } from "../components/Chart";
import { Card, Drawer, Empty, Field, Kpi, Loading, Modal, rowProps, Sev, TableWrap, Tabs, Time, Trunc } from "../components/ui";

export function dur(s: number | null | undefined): string {
  if (s == null) return "—";
  if (s < 90) return `${Math.round(s)} s`;
  if (s < 5400) return `${Math.round(s / 60)} min`;
  if (s < 172800) return `${(s / 3600).toFixed(1)} h`;
  return `${(s / 86400).toFixed(1)} d`;
}
const pct = (v: number | null | undefined) => (v == null ? "—" : `${v}%`);
const LEVEL: Record<string, string> = { critical: "text-red-300", high: "text-orange-300", medium: "text-amber-300",
  low: "text-sky-300", none: "text-slate-300" };

// ------------------------------------------------------------------ SOC overview
export function SocOverview() {
  const [sp, setSp] = useSearchParams();
  const tab = sp.get("tab") === "operations" ? "operations" : "executive";
  return <div className="space-y-4 min-w-0">
    <Tabs value={tab} onChange={(t) => setSp({ tab: t })} tabs={[{ key: "executive", label: "Executive overview" }, { key: "operations", label: "SOC operations" }]} />
    {tab === "executive" ? <Executive /> : <Operations />}
  </div>;
}

function Executive() {
  const { theme } = useTheme();
  const [days, setDays] = useState(7);
  const q = useQuery({ queryKey: ["soc-exec", days], queryFn: () => api<any>("/soc/executive", { params: { days } }) });
  const d = q.data;
  const trend = useMemo(() => d && ({
    legend: { top: 0 }, tooltip: { trigger: "axis", confine: true },
    xAxis: { type: "category", data: d.alerts_per_day.map((x: any) => x.day), ...axisStyle },
    yAxis: { type: "value", minInterval: 1, ...axisStyle },
    series: (["critical", "high", "medium", "low"] as const).map((sev) => ({ name: sev, type: "bar", stack: "a", barMaxWidth: 22, itemStyle: { color: SEV_HEX[sev] },
      data: d.alerts_per_day.map((x: any) => x[sev]) })),
  }), [d]);
  const inc = useMemo(() => d && ({
    legend: { top: 0 }, tooltip: { trigger: "axis", confine: true },
    xAxis: { type: "category", data: d.incident_trend.map((x: any) => x.day), ...axisStyle }, yAxis: { type: "value", minInterval: 1, ...axisStyle },
    series: [{ name: "opened", type: "line", itemStyle: { color: SERIES_ROLE[theme].alert }, data: d.incident_trend.map((x: any) => x.opened) },
      { name: "resolved", type: "line", lineStyle: { type: "dashed" }, itemStyle: { color: SERIES_ROLE[theme].primary }, data: d.incident_trend.map((x: any) => x.resolved) }],
  }), [d, theme]);
  return <>
    <div className="flex items-center gap-2"><span className="text-xs text-muted">Period</span>
      <select aria-label="Period" className="input py-1" value={days} onChange={(e) => setDays(Number(e.target.value))}>{[1, 7, 30, 90].map((n) => <option key={n} value={n}>{n} day{n > 1 ? "s" : ""}</option>)}</select></div>
    <Loading q={q} />
    {d && <>
      <div className="kpi-grid">
        <Kpi label="Security posture" value={d.posture.score} sub="100 minus the deductions below" tone={d.posture.score >= 85 ? "ok" : d.posture.score >= 60 ? "warn" : "bad"} />
        <Kpi label="Events" value={fmtNum(d.events_total)} sub={`last ${days} day(s)`} />
        <Kpi label="Open critical alerts" value={d.critical_alerts_open} tone={d.critical_alerts_open ? "bad" : "ok"} />
        <Kpi label="Open incidents" value={d.open_incidents} />
        <Kpi label="High-risk entities" value={(d.risk_distribution.critical || 0) + (d.risk_distribution.high || 0)} sub="risk score 50+" />
        <Kpi label="Threat-intel matches" value={fmtNum(d.ti.matches)} sub={`${d.ti.hosts} host(s), last ${d.ti.days} d`} tone={d.ti.matches ? "warn" : undefined} />
        <Kpi label="MTTD" value={dur(d.mttd.median_s)} sub={`median, ${d.mttd.n} alerts`} />
        <Kpi label="MTTR" value={dur(d.mttr.median_s)} sub={`median, ${d.mttr.n} incidents`} />
      </div>
      <div className="grid-cards xl:grid-cols-2">
        <Card title="Posture deductions">{d.posture.deductions.length ? <ul className="space-y-1.5 text-sm">{d.posture.deductions.map((x: any) =>
          <li key={x.why} className="flex justify-between gap-3"><span>{x.why}</span><span className="tabular-nums text-red-400">−{x.points}</span></li>)}</ul>
          : <Empty text="Nothing to deduct in this period." />}<p className="text-2xs text-muted mt-2">{d.posture.method}</p></Card>
        <Card title="Highest-risk entities" bodyClass="p-0">{!d.high_risk_entities.length ? <Empty text="No entity at risk score 25 or more." /> :
          <RiskTable rows={d.high_risk_entities} />}</Card>
      </div>
      <div className="grid-cards xl:grid-cols-2">
        <Card title="Alerts per day by severity">{d.alerts_per_day.length ? <Chart height={230} option={trend} ariaLabel="Alerts per day by severity" /> : <Empty text="No alerts in this period." />}</Card>
        <Card title="Incidents opened and resolved">{d.incident_trend.length ? <Chart height={230} option={inc} ariaLabel="Incidents opened and resolved per day" /> : <Empty text="No incidents in this period." />}</Card>
      </div>
    </>}
  </>;
}

function Operations() {
  const nav = useNavigate();
  const [days, setDays] = useState(30);
  const q = useQuery({ queryKey: ["soc-ops", days], queryFn: () => api<any>("/soc/metrics", { params: { days } }) });
  const d = q.data;
  return <>
    <div className="flex items-center gap-2"><span className="text-xs text-muted">Period</span>
      <select aria-label="Period" className="input py-1" value={days} onChange={(e) => setDays(Number(e.target.value))}>{[7, 30, 90, 365].map((n) => <option key={n} value={n}>{n} days</option>)}</select></div>
    <Loading q={q} />
    {d && <>
      <div className="kpi-grid">
        <Kpi label="Alerts" value={fmtNum(d.alerts.total)} sub={`${d.alerts.open} still open`} />
        <Kpi label="False-positive rate" value={pct(d.alerts.false_positive_pct)} sub={`of ${d.alerts.judged} judged alerts`} />
        <Kpi label="MTTD" value={dur(d.mttd.median_s)} sub={`median · p90 ${dur(d.mttd.p90_s)}`} />
        <Kpi label="MTTA" value={dur(d.mtta.median_s)} sub={`median · ${d.mtta.n} incidents`} />
        <Kpi label="MTTR" value={dur(d.mttr.median_s)} sub={`median · p90 ${dur(d.mttr.p90_s)}`} />
        <Kpi label="Open incidents" value={d.incidents.open} sub={`${d.incidents.unassigned} unassigned · ${d.incidents.escalated_open} escalated`} />
        <Kpi label="SLA breaches (open)" value={d.sla.ack_breached_open + d.sla.resolve_breached_open} tone={d.sla.ack_breached_open + d.sla.resolve_breached_open ? "bad" : "ok"}
          sub={`resolved within SLA: ${pct(d.sla.resolved_within_sla_pct)}`} />
      </div>
      <p className="text-2xs text-muted">MTTD: alert created − first matching event. MTTA: incident acknowledged − created. MTTR: incident resolved − created.</p>
      <div className="grid-cards xl:grid-cols-3">
        <Card title="Open incidents by stage">{Object.keys(d.incidents.by_stage).length ? <Bars data={d.incidents.by_stage}
          order={["new", "triage", "investigation", "containment", "eradication", "recovery"]} /> : <Empty text="No open incidents." />}</Card>
        <Card title="Open incidents by priority">{Object.keys(d.incidents.by_priority).length ? <Bars data={d.incidents.by_priority} order={["P1", "P2", "P3", "P4"]} /> : <Empty text="No open incidents." />}</Card>
        <Card title="Closure reasons">{Object.keys(d.incidents.closure).length ? <Bars data={d.incidents.closure} /> : <Empty text="Nothing resolved in this period." />}</Card>
      </div>
      <div className="grid-cards xl:grid-cols-2">
        <Card title="Analyst workload (open incidents)" bodyClass="p-0">{!d.workload.length ? <Empty text="No open incidents." /> :
          <TableWrap><table className="tbl"><thead><tr><th>Analyst</th><th className="num">Open</th><th className="num">P1 / P2</th><th className="num">SLA breached</th></tr></thead>
            <tbody>{d.workload.map((w: any) => <tr key={w.analyst}><td>{w.analyst}</td><td className="num">{w.open}</td><td className="num">{w.p1_p2}</td>
              <td className={`num ${w.breached ? "text-red-400 font-semibold" : ""}`}>{w.breached}</td></tr>)}</tbody></table></TableWrap>}</Card>
        <Card title="Noisiest rules" bodyClass="p-0">{!d.alerts.top_rules.length ? <Empty text="No alerts in this period." /> :
          <TableWrap><table className="tbl"><thead><tr><th>Rule</th><th className="num">Alerts</th></tr></thead>
            <tbody>{d.alerts.top_rules.map((r: any) => <tr key={r.rule_key}><td>{r.name}<div className="text-2xs text-muted font-mono">{r.rule_key}</div></td><td className="num">{fmtNum(r.count)}</td></tr>)}</tbody></table></TableWrap>}</Card>
      </div>
      <Card title={`Incidents breaching SLA (${d.sla.breaching.length})`} bodyClass="p-0">{!d.sla.breaching.length ? <Empty text="No open incident is past its SLA." /> :
        <TableWrap><table className="tbl"><thead><tr><th>Incident</th><th>Severity</th><th>Priority</th><th>Stage</th><th>Assignee</th><th>Breach</th><th>Resolve due</th></tr></thead>
          <tbody>{d.sla.breaching.map((i: any) => <tr key={i.id} {...rowProps(() => nav(`/incidents/${i.id}`))}><td className="cell-wrap min-w-[14rem]">#{i.id} {i.title}</td>
            <td><Sev s={i.severity} /></td><td>{i.priority}</td><td>{i.stage}</td><td>{i.assignee || "—"}</td>
            <td className="text-xs">{[i.ack_breached && "acknowledge", i.resolve_breached && "resolve"].filter(Boolean).join(", ")}</td><td><Time v={i.resolve_due} /></td></tr>)}</tbody></table></TableWrap>}</Card>
    </>}
  </>;
}

function Bars({ data, order }: { data: Record<string, number>; order?: string[] }) {
  const keys = (order || Object.keys(data)).filter((k) => data[k]);
  const max = Math.max(1, ...keys.map((k) => data[k]));
  return <ul className="space-y-1.5 text-sm">{keys.map((k) => <li key={k} className="grid grid-cols-[7rem_1fr_3rem] items-center gap-2">
    <span className="truncate">{k.replace(/_/g, " ")}</span><span className="h-2 rounded bg-slate-800"><span className="block h-2 rounded bg-slate-400" style={{ width: `${(100 * data[k]) / max}%` }} /></span>
    <span className="tabular-nums text-right">{data[k]}</span></li>)}</ul>;
}

// ------------------------------------------------------------------ entity risk
function RiskTable({ rows }: { rows: any[] }) {
  const [sel, setSel] = useState<any>(null);
  return <>
    <TableWrap><table className="tbl"><thead><tr><th>Entity</th><th>Type</th><th className="num">Score</th><th>Level</th><th className="num">Open alerts</th><th>Top factor</th><th>Tactics</th></tr></thead>
      <tbody>{rows.map((r) => <tr key={`${r.type}${r.entity}`} {...rowProps(() => setSel(r))}>
        <td className="font-mono text-xs nowrap">{r.entity}{r.hostname && <div className="text-2xs text-muted font-sans">{r.hostname}</div>}</td><td>{r.type === "ip" ? "host" : "user"}</td>
        <td className="num font-semibold">{r.score}</td><td><span className={`pill ${LEVEL[r.level]}`}>{r.level}</span></td><td className="num">{r.open_alerts}</td>
        <td className="cell-wrap min-w-[12rem] text-xs">{r.top_factor}</td><td className="text-xs">{r.tactics.join(", ") || "—"}</td></tr>)}</tbody></table></TableWrap>
    {sel && <RiskDrawer kind={sel.type} entity={sel.entity} onClose={() => setSel(null)} />}
  </>;
}

function RiskDrawer({ kind, entity, onClose }: { kind: string; entity: string; onClose: () => void }) {
  const q = useQuery({ queryKey: ["risk", kind, entity], queryFn: () => api<any>(`/risk/${kind}/${encodeURIComponent(entity)}`) });
  const d = q.data;
  return <Drawer title={`Risk: ${entity}`} onClose={onClose}>
    <Loading q={q} />
    {d && <div className="space-y-3 text-sm">
      <div className="kpi-grid"><Kpi label="Score" value={d.score} /><Kpi label="Level" value={d.level} /><Kpi label="Open alerts" value={d.open} />
        <Kpi label="Asset weight" value={`×${d.asset_weight}`} sub={d.asset?.criticality ? `criticality ${d.asset.criticality}` : "not in the asset inventory"} /></div>
      <p className="text-xs text-muted">{d.method}. A high score ranks where to look first; it is not proof of compromise.</p>
      <Card title="What adds up to the score" bodyClass="p-0"><TableWrap><table className="tbl"><thead><tr><th>Detection</th><th className="num">Alerts</th><th className="num">Points</th><th>Feedback</th></tr></thead>
        <tbody>{d.factors.map((f: any) => <tr key={f.rule_key}><td className="cell-wrap min-w-[12rem]">{f.name}<div className="text-2xs text-muted">{f.explanation}</div></td>
          <td className="num">{f.alerts}</td><td className="num font-semibold">{f.points}</td><td className="text-2xs">{f.feedback || "—"}</td></tr>)}</tbody></table></TableWrap></Card>
      <Card title="Alerts" bodyClass="p-0"><TableWrap maxH="max-h-80"><table className="tbl"><thead><tr><th>Alert</th><th>Severity</th><th>Status</th><th>Verdict</th><th>Last seen</th></tr></thead>
        <tbody>{d.alerts.map((a: any) => <tr key={a.id}><td><Link className="link" to={`/alerts?product=grid&id=${a.id}`}>{a.name}</Link></td><td><Sev s={a.severity} /></td>
          <td>{a.status}</td><td className="text-xs">{a.disposition?.replace("_", " ") || "—"}</td><td><Time v={a.last_seen} /></td></tr>)}</tbody></table></TableWrap></Card>
    </div>}
  </Drawer>;
}

export function RiskPage() {
  const [kind, setKind] = useState("");
  const [days, setDays] = useState(30);
  const q = useQuery({ queryKey: ["risk-entities", kind, days], queryFn: () => api<any>("/risk/entities", { params: { kind: kind || undefined, days, limit: 300 } }) });
  return <div className="space-y-4 min-w-0">
    <p className="text-xs text-muted">Hosts and users ranked by an explainable score built from their alerts: severity × rule confidence × recency, repeats of one rule count less,
      analyst verdicts lower or raise a rule's weight for that entity, and hosts are weighted by asset criticality. Unusual behaviour alone never raises a score
      without a detection behind it. Close alerts as false positive or true positive to teach it.</p>
    <div className="flex flex-wrap items-center gap-2">
      <select aria-label="Entity type" className="input py-1" value={kind} onChange={(e) => setKind(e.target.value)}><option value="">Hosts and users</option><option value="ip">Hosts</option><option value="user">Users</option></select>
      <select aria-label="Period" className="input py-1" value={days} onChange={(e) => setDays(Number(e.target.value))}>{[7, 30, 90].map((n) => <option key={n} value={n}>last {n} days</option>)}</select>
      {q.data && <span className="text-xs text-muted">{q.data.entities} entities with alerts · {Object.entries(q.data.distribution).map(([k, v]) => `${v} ${k}`).join(" · ")}</span>}
    </div>
    <Card bodyClass="p-0"><Loading q={q} />{q.data && (!q.data.items.length ? <Empty text="No entity has alerts in this period." /> : <RiskTable rows={q.data.items} />)}</Card>
  </div>;
}

// ------------------------------------------------------------------ ATT&CK coverage
export function AttackPage() {
  const { theme } = useTheme();
  const [days, setDays] = useState(30);
  const [status, setStatus] = useState("");
  const [tactic, setTactic] = useState("");
  const [sel, setSel] = useState<string | null>(null);
  const q = useQuery({ queryKey: ["mitre-cov", days], queryFn: () => api<any>("/mitre/coverage", { params: { days } }) });
  const d = q.data;
  const opt = useMemo(() => d && ({
    legend: { top: 0 }, tooltip: { trigger: "axis", confine: true, axisPointer: { type: "shadow" } }, grid: { left: 8, right: 16, top: 28, bottom: 8, containLabel: true },
    xAxis: { type: "value", minInterval: 1, ...axisStyle }, yAxis: { type: "category", data: d.tactics.map((t: any) => t.name).reverse(), ...axisStyle },
    series: [{ name: "covered techniques", type: "bar", stack: "t", itemStyle: { color: PALETTES[theme][2] }, data: d.tactics.map((t: any) => t.covered).reverse() },
      { name: "not covered", type: "bar", stack: "t", itemStyle: { color: SERIES_ROLE[theme].muted }, data: d.tactics.map((t: any) => t.techniques - t.covered).reverse() }],
  }), [d, theme]);
  const rows = (d?.techniques || []).filter((t: any) => (!status || t.status === status) && (!tactic || t.tactics.includes(tactic)));
  return <div className="space-y-4 min-w-0">
    <Loading q={q} />
    {d && <>
      <p className="text-xs text-muted">Catalogue: MITRE ATT&CK {d.catalog.version} ({d.catalog.source}, {d.catalog.techniques} techniques). Coverage is measured against techniques that
        network, identity and device telemetry can show; endpoint-only techniques are not listed. Precision = true positives ÷ judged alerts.</p>
      <div className="kpi-grid">
        <Kpi label="Coverage" value={pct(d.summary.coverage_pct)} sub={`${d.summary.covered} of ${d.summary.techniques} techniques`} />
        <Kpi label="Gaps" value={d.summary.gaps} sub="no rule at all" tone={d.summary.gaps ? "warn" : "ok"} onClick={() => setStatus("gap")} />
        <Kpi label="Rules mapped" value={d.summary.rules_mapped} sub={`${d.summary.rules_unmapped} enabled rule(s) without a technique`} />
      </div>
      <div className="grid-cards xl:grid-cols-2">
        <Card title="Coverage by tactic"><Chart height={360} option={opt} ariaLabel="ATT&CK coverage by tactic" /></Card>
        <Card title={`Alerts by tactic (last ${days} days)`} bodyClass="p-0"><TableWrap><table className="tbl"><thead><tr><th>Tactic</th><th className="num">Techniques</th><th className="num">Covered</th><th className="num">Alerts</th></tr></thead>
          <tbody>{d.tactics.map((t: any) => <tr key={t.id} {...rowProps(() => setTactic(t.id === tactic ? "" : t.id))} className={tactic === t.id ? "bg-hover" : ""}>
            <td>{t.name} <span className="text-2xs text-muted font-mono">{t.id}</span></td><td className="num">{t.techniques}</td><td className="num">{t.covered}</td><td className="num">{fmtNum(t.alerts)}</td></tr>)}</tbody></table></TableWrap></Card>
      </div>
      <Card title={`Techniques (${rows.length})`} bodyClass="p-0" right={<div className="flex flex-wrap gap-2">
        <select aria-label="Coverage status" className="input py-1" value={status} onChange={(e) => setStatus(e.target.value)}><option value="">Any status</option><option value="covered">Covered</option>
          <option value="disabled">Rule disabled</option><option value="gap">Gap</option></select>
        <select aria-label="Tactic" className="input py-1" value={tactic} onChange={(e) => setTactic(e.target.value)}><option value="">All tactics</option>{d.tactics.map((t: any) => <option key={t.id} value={t.id}>{t.name}</option>)}</select>
        <select aria-label="Period" className="input py-1" value={days} onChange={(e) => setDays(Number(e.target.value))}>{[7, 30, 90].map((n) => <option key={n} value={n}>alerts: {n} days</option>)}</select></div>}>
        <TableWrap><table className="tbl"><thead><tr><th>Technique</th><th>Status</th><th className="num">Rules</th><th className="num">Alerts</th><th className="num">Precision</th><th>Data sources here</th></tr></thead>
          <tbody>{rows.map((t: any) => <tr key={t.id} {...rowProps(() => setSel(t.id))}><td className="cell-wrap min-w-[16rem]"><span className="font-mono text-xs text-muted mr-1.5">{t.id}</span>{t.name}</td>
            <td><span className={`pill ${t.status === "covered" ? "text-emerald-300" : t.status === "disabled" ? "text-amber-300" : "text-slate-300"}`}>
              {t.status === "covered" ? (t.via ? "covered (sub-technique)" : "covered") : t.status === "disabled" ? "rule disabled" : "gap"}</span></td>
            <td className="num">{t.rules_enabled}/{t.rules.length}</td><td className="num">{fmtNum(t.alerts)}</td><td className="num">{t.precision == null ? "—" : `${t.precision}% (${t.judged})`}</td>
            <td className="cell-wrap text-xs min-w-[12rem]">{t.data_sources}</td></tr>)}</tbody></table></TableWrap></Card>
      {d.unmapped_rules.length > 0 && <Card title="Enabled rules without an ATT&CK technique"><p className="text-sm">{d.unmapped_rules.map((r: any) => r.name).join(" · ")}</p></Card>}
    </>}
    {sel && <TechniqueDrawer tid={sel} days={days} onClose={() => setSel(null)} />}
  </div>;
}

function TechniqueDrawer({ tid, days, onClose }: { tid: string; days: number; onClose: () => void }) {
  const q = useQuery({ queryKey: ["mitre-tech", tid, days], queryFn: () => api<any>(`/mitre/techniques/${tid}`, { params: { days } }) });
  const d = q.data;
  return <Drawer title={d ? `${d.id} ${d.name}` : tid} onClose={onClose}>
    <Loading q={q} />
    {d && <div className="space-y-3 text-sm">
      <p>Data sources here: {d.data_sources || "—"}. <a className="link" href={d.url} target="_blank" rel="noreferrer noopener">ATT&CK page ↗</a></p>
      <Card title="Rules" bodyClass="p-0">{!d.rules.length ? <Empty text="No rule detects this technique." /> :
        <TableWrap><table className="tbl"><thead><tr><th>Rule</th><th>Severity</th><th>Enabled</th></tr></thead>
          <tbody>{d.rules.map((r: any) => <tr key={r.key}><td>{r.name}<div className="text-2xs text-muted font-mono">{r.key}</div></td><td><Sev s={r.severity} /></td><td>{r.enabled ? "yes" : "no"}</td></tr>)}</tbody></table></TableWrap>}</Card>
      <Card title={`Alerts (last ${days} days)`} bodyClass="p-0">{!d.alerts.length ? <Empty text="No alert for this technique in the period." /> :
        <TableWrap maxH="max-h-96"><table className="tbl"><thead><tr><th>Alert</th><th>Source</th><th>Status</th><th>Verdict</th><th>Last seen</th></tr></thead>
          <tbody>{d.alerts.map((a: any) => <tr key={a.id}><td><Link className="link" to={`/alerts?product=grid&id=${a.id}`}>{a.name}</Link></td><td className="font-mono text-xs">{a.src_ip || "—"}</td>
            <td>{a.status}</td><td className="text-xs">{a.disposition?.replace("_", " ") || "—"}</td><td><Time v={a.last_seen} /></td></tr>)}</tbody></table></TableWrap>}</Card>
    </div>}
  </Drawer>;
}

// ------------------------------------------------------------------ response actions
const RSTATUS: Record<string, string> = { pending: "text-amber-300", approved: "text-sky-300", applied: "text-sky-300",
  verified: "text-emerald-300", not_verified: "text-red-300", rejected: "text-slate-300", done: "text-emerald-300",
  rolled_back: "text-slate-300", cancelled: "text-slate-300", failed: "text-red-300" };
const KIND_LABEL: Record<string, string> = { block_ip: "Block address", disable_account: "Disable account", isolate_host: "Isolate host", enrich_ip: "Enrich address",
  collect_evidence: "Collect evidence", notify: "Notify" };

export function ResponsePage() {
  const [status, setStatus] = useState("");
  const [sel, setSel] = useState<number | null>(null);
  const [create, setCreate] = useState(false);
  const q = useQuery({ queryKey: ["response", status], queryFn: () => api<any>("/response/actions", { params: { status: status ? [status] : undefined } }) });
  const items: any[] = q.data?.items || [];
  const cur = items.find((x) => x.id === sel);
  return <div className="space-y-4 min-w-0">
    <p className="text-xs text-muted">Containment (block an address, disable an account, isolate a host) is never executed by Sentinel. A second person approves; Sentinel then shows
      the exact commands and their rollback; an operator applies them and records it; Sentinel checks the effect in the logs. Enrichment, evidence collection and
      notification change nothing outside Sentinel and run at once. Every step is in the action's log and the audit log.</p>
    <div className="flex flex-wrap items-center gap-2">
      <select aria-label="Status" className="input py-1" value={status} onChange={(e) => setStatus(e.target.value)}><option value="">All actions</option>
        {Object.keys(RSTATUS).map((s) => <option key={s} value={s}>{s.replace("_", " ")} ({q.data?.counts?.[s] || 0})</option>)}</select>
      <span className="flex-1" /><button type="button" className="btn btn-primary" onClick={() => setCreate(true)}>New action…</button>
    </div>
    <Card bodyClass="p-0"><Loading q={q} />
      {q.data && (!items.length ? <Empty text="No response actions." /> :
        <TableWrap><table className="tbl"><thead><tr><th>Action</th><th>Target</th><th>Status</th><th>Requested</th><th>Approved / rejected</th><th>Incident</th><th>Reason</th></tr></thead>
          <tbody>{items.map((a) => <tr key={a.id} {...rowProps(() => setSel(a.id))}><td>{KIND_LABEL[a.kind]}{a.can_decide && <span className="pill text-amber-300 ml-1.5">needs you</span>}</td>
            <td className="font-mono text-xs nowrap">{a.target}</td><td><span className={`pill ${RSTATUS[a.status]}`}>{a.status.replace("_", " ")}</span></td>
            <td className="text-xs">{a.requested_by}<div><Time v={a.created_at} /></div></td><td className="text-xs">{a.decided_by || "—"}</td>
            <td>{a.incident_id ? <Link className="link" to={`/incidents/${a.incident_id}`} onClick={(e) => e.stopPropagation()}>#{a.incident_id}</Link> : "—"}</td>
            <td><Trunc text={a.reason} max="max-w-[20rem]" /></td></tr>)}</tbody></table></TableWrap>)}</Card>
    {cur && <ActionDrawer a={cur} onClose={() => setSel(null)} />}
    {create && <ActionForm firewalls={q.data?.firewalls || []} onClose={() => setCreate(false)} />}
  </div>;
}

export function ActionForm({ firewalls, onClose, init }: { firewalls: any[]; onClose: () => void; init?: { kind?: string; target?: string; incident_id?: number; alert_id?: number } }) {
  const qc = useQueryClient();
  const [f, setF] = useState({ kind: init?.kind || "block_ip", target: init?.target || "", reason: "", hours: "", firewall_ids: [] as number[] });
  const m = useMutation({ mutationFn: () => api<any>("/response/actions", { method: "POST", body: { kind: f.kind, target: f.target, reason: f.reason,
    incident_id: init?.incident_id, alert_id: init?.alert_id, firewall_ids: f.firewall_ids, hours: f.hours ? Number(f.hours) : undefined } }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["response"] }); onClose(); } });
  return <Modal title="New response action" onClose={onClose}>
    <div className="space-y-3">
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Action"><select className="input w-full" value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })}>{Object.entries(KIND_LABEL).map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></Field>
        <Field label={f.kind === "disable_account" ? "Account" : "Address or host"}><input className="input w-full font-mono" value={f.target} onChange={(e) => setF({ ...f, target: e.target.value })} /></Field>
      </div>
      {f.kind === "block_ip" && <>
        <div role="group" aria-label="Firewalls" className="text-sm"><span className="label">Firewalls (none ticked = every enabled firewall)</span>
          <div className="flex flex-wrap gap-3">{firewalls.map((fw) => <label key={fw.id} className="inline-flex items-center gap-1.5"><input type="checkbox" checked={f.firewall_ids.includes(fw.id)}
            onChange={(e) => setF({ ...f, firewall_ids: e.target.checked ? [...f.firewall_ids, fw.id] : f.firewall_ids.filter((x) => x !== fw.id) })} />{fw.name}</label>)}
            {!firewalls.length && <span className="text-muted">no firewall registered</span>}</div></div>
        <Field label="Temporary: remove after (hours, empty = permanent)"><input className="input w-40" type="number" min={1} max={2160} value={f.hours} onChange={(e) => setF({ ...f, hours: e.target.value })} /></Field>
      </>}
      <Field label="Reason (what evidence supports it)"><textarea className="input w-full h-20" value={f.reason} onChange={(e) => setF({ ...f, reason: e.target.value })} /></Field>
      {m.error && <div role="alert" className="text-sm text-red-400">{String((m.error as Error).message)}</div>}
      <div className="flex justify-end gap-2"><button type="button" className="btn" onClick={onClose}>Cancel</button>
        <button type="button" className="btn btn-primary" disabled={!f.target.trim() || f.reason.trim().length < 5 || m.isPending} onClick={() => m.mutate()}>
          {["block_ip", "disable_account", "isolate_host"].includes(f.kind) ? "Request (needs approval)" : "Run"}</button></div>
    </div>
  </Modal>;
}

function ActionDrawer({ a, onClose }: { a: any; onClose: () => void }) {
  const qc = useQueryClient();
  const me = useMe();
  const [note, setNote] = useState("");
  const done = { onSuccess: () => qc.invalidateQueries({ queryKey: ["response"] }) };
  const post = (path: string, body: any = {}) => api<any>(`/response/actions/${a.id}/${path}`, { method: "POST", body });
  const decide = useMutation({ mutationFn: (approve: boolean) => post("decision", { approve, comment: note }), ...done });
  const applied = useMutation({ mutationFn: () => post("applied", { note }), ...done });
  const verify = useMutation({ mutationFn: () => post("verify"), ...done });
  const rollback = useMutation({ mutationFn: () => post("rollback", { note }), ...done });
  const cancel = useMutation({ mutationFn: () => post("cancel"), ...done });
  const err = [decide, applied, verify, rollback, cancel].find((x) => x.error)?.error as Error | undefined;
  const p = a.plan || {};
  return <Drawer title={`${KIND_LABEL[a.kind]}: ${a.target}`} onClose={onClose}>
    <div className="space-y-3 text-sm">
      <div className="flex flex-wrap items-center gap-2"><span className={`pill ${RSTATUS[a.status]}`}>{a.status.replace("_", " ")}</span>
        <span className="text-xs text-muted">requested by {a.requested_by}</span>{a.expires_at && <span className="text-xs text-amber-300">temporary: remove after <Time v={a.expires_at} /></span>}</div>
      <p>{a.reason}</p>
      <Card title="Plan (dry run)"><p className="mb-2">{p.summary}</p>
        {p.prerequisites?.length > 0 && <><div className="label">Before applying</div><ul className="list-disc ml-5 mb-2">{p.prerequisites.map((x: string) => <li key={x}>{x}</li>)}</ul></>}
        {p.warnings?.length > 0 && <ul className="mb-2 text-amber-300">{p.warnings.map((x: string) => <li key={x}>⚠ {x}</li>)}</ul>}
        {(p.steps || []).map((st: any, i: number) => <div key={i} className="mb-3"><div className="label">{st.system}</div>
          <pre className="text-xs font-mono bg-panel2 border border-line rounded p-2 overflow-x-auto">{st.apply}</pre>
          <details className="mt-1"><summary className="text-xs link">Rollback</summary><pre className="text-xs font-mono bg-panel2 border border-line rounded p-2 overflow-x-auto mt-1">{st.rollback}</pre></details></div>)}
        {p.checks?.length > 0 && <><div className="label">How Sentinel verifies it</div><ul className="list-disc ml-5">{p.checks.map((x: string) => <li key={x}>{x}</li>)}</ul></>}</Card>
      {a.result && Object.keys(a.result).length > 0 && <Card title="Result"><pre className="text-xs overflow-x-auto">{JSON.stringify(a.result, null, 2)}</pre></Card>}
      {["pending", "approved", "applied", "verified", "not_verified"].includes(a.status) && <Field label="Comment / note"><textarea className="input w-full h-16" value={note} onChange={(e) => setNote(e.target.value)} /></Field>}
      <div className="flex flex-wrap gap-2">
        {a.can_decide && <><button type="button" className="btn btn-primary" onClick={() => decide.mutate(true)}>Approve</button><button type="button" className="btn btn-danger" onClick={() => decide.mutate(false)}>Reject</button></>}
        {a.status === "pending" && !a.can_decide && a.requires_approval && <span className="text-xs text-muted self-center">Waiting for approval by an administrator or a responder other than {a.requested_by}.</span>}
        {a.status === "approved" && <button type="button" className="btn btn-primary" onClick={() => applied.mutate()}>I applied it</button>}
        {["applied", "verified", "not_verified"].includes(a.status) && <><button type="button" className="btn" onClick={() => verify.mutate()}>Check effect in logs</button>
          <button type="button" className="btn" onClick={() => rollback.mutate()}>I rolled it back</button></>}
        {["pending", "approved"].includes(a.status) && (me.username === a.requested_by || me.role === "admin") && <button type="button" className="btn" onClick={() => cancel.mutate()}>Cancel</button>}
      </div>
      {err && <div role="alert" className="text-sm text-red-400">{err.message}</div>}
      <Card title="Log" bodyClass="p-0"><TableWrap><table className="tbl"><thead><tr><th>When</th><th>Who</th><th>Event</th><th>Detail</th></tr></thead>
        <tbody>{(a.log || []).map((l: any, i: number) => <tr key={i}><td><Time v={l.at} /></td><td>{l.who}</td><td>{l.event}</td><td className="cell-wrap text-xs">{l.detail || "—"}</td></tr>)}</tbody></table></TableWrap></Card>
    </div>
  </Drawer>;
}
