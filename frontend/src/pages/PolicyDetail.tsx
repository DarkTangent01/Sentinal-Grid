import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { fmtBytes, fmtNum } from "../lib/format";
import { Card, Empty, IpLink, Kpi, Loading, TableWrap, Time, rowProps, useExplore } from "../components/ui";
import { TimeChart } from "../components/charts";
import { Chart, axisStyle } from "../components/Chart";
import { Names, SHADOW_LABEL, STATE_LABEL, StateBadge } from "./Policies";
import { FindingCompare } from "./Shadow";

const NA = <span className="text-base text-slate-400">Not available</span>;

export function PolicyDetail() {
  const { fw = "", vdom = "", pid = "" } = useParams();
  const [win, setWin] = useState(30);
  const nav = useNavigate();
  const explore = useExplore();
  const [cmp, setCmp] = useState<any>(null);
  const q = useQuery({ queryKey: ["policy-detail", fw, vdom, pid, win], queryFn: () => api<any>(`/v1/policies/${fw}/${encodeURIComponent(vdom)}/${pid}`, { params: { window_days: win } }) });
  const d = q.data;
  const p = d?.policy;
  const cfg = d?.config || {};
  const evFilter = { policy_id: pid, firewall_id: [fw], start: new Date(Date.now() - win * 86400e3).toISOString(), end: new Date().toISOString() };
  return (
    <div className="space-y-4 min-w-0">
      <div className="flex flex-wrap items-end gap-3">
        <div className="min-w-0">
          <button className="link text-xs" onClick={() => nav("/policies")}>← Policy inventory</button>
          <h1 className="text-lg font-semibold break-words">Policy {pid}{p?.name ? ` — ${p.name}` : ""}</h1>
          {p && <div className="text-xs text-muted">{p.firewall} / {p.vdom} · sequence {p.seq} · UUID <span className="font-mono">{p.uuid || "n/a"}</span>{p.source === "demo" && <span className="pill bg-amber-600/30 text-amber-200 ml-1">demo</span>}{d?.deleted_at && <span className="text-red-400"> · deleted from firewall <Time v={d.deleted_at} /></span>}</div>}
        </div>
        <div className="flex-1" />
        <div><label className="label">Observation window</label><select className="input" value={win} onChange={(e) => setWin(Number(e.target.value))}>{[7, 30, 60, 90].map((x) => <option key={x} value={x}>{x} days</option>)}</select></div>
        <button className="btn" onClick={() => explore(evFilter)}>Related traffic logs →</button>
      </div>
      <Loading q={q} />
      {p && <>
        <div className="kpi-grid">
          <Kpi label="Assessment" value={<StateBadge a={p.assessment} />} sub={`${p.assessment.method} · confidence ${p.assessment.confidence}`} />
          <Kpi label={`Firewall hits (${win} d)`} value={p.firewall_hits == null ? NA : fmtNum(p.firewall_hits)} sub={p.firewall_hits == null ? (d.sync.counters_supported ? "no snapshots yet" : "counter API not available") : `cumulative ${fmtNum(p.firewall_counter_total)} · resets ${p.counter_resets}`} />
          <Kpi label={`SIEM matches (${win} d)`} value={p.siem_matches == null ? NA : fmtNum(p.siem_matches)} sub={p.log_coverage_since ? <>logs since <Time v={p.log_coverage_since} /></> : "no traffic logs from this firewall"} onClick={() => explore(evFilter)} />
          <Kpi label="Bytes" value={p.firewall_bytes != null ? fmtBytes(p.firewall_bytes) : p.siem_bytes ? fmtBytes(p.siem_bytes) : NA} sub={p.firewall_bytes != null ? "firewall counter" : p.siem_bytes ? "from SIEM logs" : ""} />
          <Kpi label="Last seen" value={p.last_seen ? <Time v={p.last_seen} /> : "never observed"} />
          <Kpi label="Logging" value={p.logtraffic} tone={p.logtraffic === "disable" ? "warn" : undefined} sub={p.logtraffic === "all" ? "every session logged" : p.logtraffic === "utm" ? "only security events logged" : "no traffic logs"} />
        </div>
        <Card title="Why this assessment"><ul className="text-sm list-disc pl-5 space-y-0.5">{(p.assessment.reasons || []).map((r: string, i: number) => <li key={i}>{r}</li>)}</ul>
          <p className="text-2xs text-muted mt-2">{Object.entries(d.metric_sources).map(([k, v]) => <span key={k} className="block"><b>{k}</b>: {v as string}</span>)}</p></Card>

        <div className="grid-cards xl:grid-cols-2">
          <Card title="Configuration (as collected)">
            <TableWrap><table className="tbl"><tbody>
              {[["Action", cfg.action], ["Status", cfg.status], ["Incoming interface", <Names list={cfg.srcintf} max={10} />], ["Outgoing interface", <Names list={cfg.dstintf} max={10} />],
                ["Source", <Names list={cfg.srcaddr} max={10} />], ["Destination", <Names list={cfg.dstaddr} max={10} />], ["Service", <Names list={cfg.service} max={10} />],
                ["Schedule", cfg.schedule], ["NAT", cfg.nat], ["Logging", cfg.logtraffic], ["UTM", cfg.utm_status],
                ["Profiles", Object.entries(cfg.profiles || {}).map(([k, v]) => `${k}: ${v}`).join(", ") || "—"],
                ["Identity / ISDB", [...(cfg.identity || []), ...(cfg.isdb || [])].join(", ") || "—"],
                ["Negation", Object.entries(cfg.negate || {}).filter(([, v]) => v).map(([k]) => k).join(", ") || "—"],
                ["Comments", cfg.comments || "—"], ["Collected", <Time v={d.sync.last_success} />]].map(([k, v], i) => (
                <tr key={i}><td className="text-muted text-xs w-40 nowrap">{k as string}</td><td className="text-sm cell-wrap">{v as any}</td></tr>))}
            </tbody></table></TableWrap>
            {Object.keys(d.sync.object_errors || {}).length > 0 && <p className="text-xs text-amber-300 mt-2">Some objects could not be read: {JSON.stringify(d.sync.object_errors)}. Shadow analysis may be limited.</p>}
          </Card>
          <Card title="Shadow / overlap relationships">
            {d.shadow.length ? <TableWrap><table className="tbl"><thead><tr><th>Relation</th><th>Other policy</th><th>Classification</th><th>Severity</th><th>Confidence</th></tr></thead>
              <tbody>{d.shadow.map((x: any) => <tr key={x.id} {...rowProps(() => setCmp(x))}>
                <td className="nowrap text-xs">{x.role === "later" ? "shadowed by" : "shadows"}</td>
                <td className="text-xs">#{x.other_policyid} {x.other_name}</td><td className="nowrap text-xs">{SHADOW_LABEL[x.classification]}</td>
                <td className="nowrap text-xs">{x.severity}</td><td className="nowrap text-xs">{x.confidence}</td></tr>)}</tbody></table></TableWrap>
              : <Empty text={p.analysis?.analysis === "unknown" ? `Not fully analysable: missing objects ${(p.analysis.missing || []).join(", ")}` : "No shadow or overlap detected by the current analysis."} />}
          </Card>
        </div>

        <div className="grid-cards xl:grid-cols-2">
          <Card title="Matched traffic logs over time (SIEM)"><TimeChart data={{ ...d.timeseries, data_start: p.log_coverage_since }} stack series={[{ key: "events", name: "Events", color: "primary" }]} /></Card>
          <Card title="Firewall hit counter (delta per snapshot)">
            {d.counter_series.length ? <Chart height={240} option={{
              xAxis: { type: "time", ...axisStyle }, yAxis: { type: "value", ...axisStyle },
              series: [{ type: "bar", name: "Hits", data: d.counter_series.map((c: any) => [Date.parse(c.t), c.hits]), itemStyle: { borderRadius: [4, 4, 0, 0] } }],
              tooltip: { trigger: "axis" } }} /> : <Empty text={d.sync.counters_supported ? "No counter snapshots in this window yet." : "Firewall hit counters are not available for this firewall/VDOM (API not exposed or not permitted)."} />}
            {d.counter_series.some((c: any) => c.reset) && <p className="text-xs text-amber-300 mt-1">Counter resets detected (reboot, counter clear or policy ID reuse); deltas restart from the new value.</p>}
          </Card>
        </div>

        <div className="grid-cards md:grid-cols-2 2xl:grid-cols-4">
          {[["Top sources", d.top_sources, true], ["Top destinations", d.top_destinations, true], ["Ports / protocols", d.top_ports, false], ["Applications", d.top_apps, false]].map(([title, rows, ip]) => (
            <Card key={title as string} title={title as string}>{(rows as any[]).length ? <TableWrap><table className="tbl"><thead><tr><th>Key</th><th className="num">Events</th><th className="num">Denied</th></tr></thead>
              <tbody>{(rows as any[]).map((r) => <tr key={r.key}><td className="text-xs">{ip ? <IpLink ip={r.key} /> : <span className="font-mono">{r.key}</span>}</td><td className="num">{fmtNum(r.events)}</td><td className="num text-red-400">{fmtNum(r.denied)}</td></tr>)}</tbody></table></TableWrap>
              : <Empty text="No matching logs." />}</Card>))}
        </div>

        <div className="grid-cards xl:grid-cols-3">
          <Card title="Related non-traffic events (same policy)">{d.related_events.length ? <ul className="text-sm space-y-1">{d.related_events.map((r: any) => (
            <li key={r.category}><button className="link" onClick={() => explore({ ...evFilter, category: [r.category] })}>{r.category}</button>: {fmtNum(r.events)}</li>))}</ul>
            : <Empty text="No UTM, web or DNS events referencing this policy." />}</Card>
          <Card title="Configuration changes">{d.changes.length ? <TableWrap maxH="max-h-72"><table className="tbl"><thead><tr><th>When</th><th>Change</th><th>Fields</th></tr></thead>
            <tbody>{d.changes.map((c: any, i: number) => <tr key={i}><td><Time v={c.observed_at} /></td><td className="nowrap text-xs">{c.change_type}</td>
              <td className="text-xs cell-wrap" title={JSON.stringify({ old: c.old, new: c.new })}>{c.changed_fields.join(", ") || "—"}</td></tr>)}</tbody></table></TableWrap>
            : <Empty text="No changes observed since collection started." />}</Card>
          <Card title="Assessment history">{d.assessment_history.length ? <TableWrap maxH="max-h-72"><table className="tbl"><thead><tr><th>When</th><th>State</th><th>Method</th></tr></thead>
            <tbody>{d.assessment_history.map((h: any, i: number) => <tr key={i}><td><Time v={h.observed_at} /></td><td className="nowrap text-xs">{STATE_LABEL[h.state]}</td><td className="text-xs">{h.method} ({h.window_days} d)</td></tr>)}</tbody></table></TableWrap>
            : <Empty />}</Card>
        </div>
        <Card title="Recommendations (verify in FortiGate before changing anything)">
          <ul className="text-sm list-disc pl-5 space-y-1">
            {p.assessment.state === "potentially_unused" && <li>No hits over the observation window with adequate telemetry. Confirm with the business owner and check FortiGate hit counters over a longer period before disabling.</li>}
            {p.assessment.state === "unknown" && <li>Usage cannot be assessed. Enable <code>set logtraffic all</code> on this policy and/or grant the API user permission to read policy statistics.</li>}
            {p.logtraffic !== "all" && <li>Logging is <b>{p.logtraffic}</b>: consider <code>logtraffic all</code> so every session is visible to the SIEM.</li>}
            {d.shadow.some((x: any) => x.role === "later" && ["full_shadow", "redundant"].includes(x.classification)) && <li>This policy appears unreachable behind an earlier policy. Verify with Policy Lookup and review ordering.</li>}
            {(cfg.srcaddr || []).includes("all") && (cfg.service || []).includes("ALL") && cfg.action === "accept" && <li>Broad match (source <b>all</b>, service <b>ALL</b>): review whether it can be narrowed.</li>}
            {p.status !== "enable" && <li>Disabled policy: review whether it is still required or can be removed.</li>}
          </ul>
        </Card>
      </>}
      {cmp && <FindingCompare f={{ ...cmp, earlier_policyid: cmp.role === "later" ? cmp.other_policyid : Number(pid), later_policyid: cmp.role === "later" ? Number(pid) : cmp.other_policyid }} onClose={() => setCmp(null)} />}
    </div>
  );
}
