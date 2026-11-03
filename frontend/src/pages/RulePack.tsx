import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, qs } from "../lib/api";
import { Card, Empty, Loading, Modal, Sev, TableWrap, Time } from "../components/ui";
import { fmtStats, fmtTimeframe } from "./ruleFormat";

/** YAML detection rules (backend/rules + administrator-authored): the declarative detection engine. Enable / disable
 *  and threshold use /api/alert-rules like every other rule; tests and dry runs never create alerts. */
export function YamlRules({ admin }: { admin: boolean }) {
  const qc = useQueryClient();
  const nav = useNavigate();
  const q = useQuery({ queryKey: ["yaml-rules"], queryFn: () => api<{ items: any[] }>("/detections/yaml") });
  const [view, setView] = useState<string | null>(null);
  const [editor, setEditor] = useState<string | null>(null);
  const toggle = useMutation({ mutationFn: (r: any) => api(`/alert-rules/${r.key}`, { method: "PUT", body: { enabled: !r.enabled } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["yaml-rules"] }) });
  return <Card title="Rule pack (YAML detections)" right={admin && <button className="btn btn-primary" onClick={() => setEditor("")}>+ New YAML rule</button>}>
    <p className="text-xs text-muted mb-2">Declarative rules from <span className="font-mono">backend/rules</span> plus your own. Each rule ships its data sources, false
      positives, investigation steps and test cases; tests run the same query the engine runs, against inline test events. A dry run replays the rule over
      real history without creating alerts. See docs/DETECTION_RULES.md for the format.</p>
    <Loading q={q} />
    {q.data && !q.data.items.length && <Empty text="No YAML rules loaded." />}
    {!!q.data?.items.length && <TableWrap><table className="tbl">
      <thead><tr><th>Rule</th><th>Severity</th><th>Source</th><th>Condition</th><th>ATT&CK</th><th>Last run</th><th>Enabled</th><th /></tr></thead>
      <tbody>{q.data.items.map((r) => <tr key={r.key}>
        <td className="min-w-[14rem]"><span className="font-mono text-xs">{r.id}</span> {r.name}
          <div className="text-2xs text-muted">{r.origin === "custom" ? "custom" : "built-in"} · v{r.version}{r.invalid && " · INVALID"}</div></td>
        <td><Sev s={r.severity} /></td>
        <td className="text-xs">{r.log_source?.category}{r.log_source?.event_type && ` / ${r.log_source.event_type}`}</td>
        <td className="text-xs nowrap">by {(r.group_by || []).join(", ")} · ≥ {r.threshold} in {fmtTimeframe(r.timeframe_s)}</td>
        <td className="text-xs">{r.mitre?.tactic ? `${r.mitre.tactic}${r.mitre.techniques?.length ? " · " + r.mitre.techniques.join(", ") : ""}` : "—"}</td>
        <td className="text-xs nowrap">{fmtStats(r.stats)}</td>
        <td>{admin && r.installed ? <input type="checkbox" aria-label={`Enable ${r.id}`} checked={!!r.enabled} onChange={() => toggle.mutate(r)} /> : r.enabled ? "yes" : "no"}</td>
        <td className="nowrap"><button className="btn" onClick={() => setView(r.key)}>Open</button>
          <button className="btn ml-1" onClick={() => nav(`/alerts${qs({ rule: r.key })}`)}>Alerts</button></td>
      </tr>)}</tbody></table></TableWrap>}
    {toggle.error && <div role="alert" className="text-sm text-red-300 mt-2">{(toggle.error as Error).message}</div>}
    {view && <RuleView k={view} admin={admin} onClose={() => setView(null)} onEdit={(y) => { setView(null); setEditor(y); }} />}
    {editor !== null && <RuleEditor initial={editor} onClose={() => { setEditor(null); qc.invalidateQueries({ queryKey: ["yaml-rules"] }); }} />}
  </Card>;
}

function TestResults({ data }: { data: any }) {
  if (!data) return null;
  return <div className="space-y-1">
    <div className={`text-sm font-medium ${data.passed ? "text-emerald-300" : "text-red-300"}`}>{data.passed ? "All tests passed" : "Some tests failed"}</div>
    <TableWrap><table className="tbl"><thead><tr><th>Test</th><th>Result</th><th className="num">Alerts / expected</th><th>Groups</th></tr></thead>
      <tbody>{data.results.map((t: any, i: number) => <tr key={i}><td className="text-xs">{t.name}</td>
        <td className={t.passed ? "text-emerald-300" : "text-red-300"}>{t.passed ? "pass" : "fail"}{t.error && <div className="text-2xs">{t.error}</div>}</td>
        <td className="num">{t.alerts ?? "—"} / {t.expected ?? "—"}</td>
        <td className="text-2xs font-mono">{(t.groups || []).map((g: any) => Object.values(g).join(" · ")).join("; ") || "—"}</td></tr>)}</tbody></table></TableWrap>
  </div>;
}

function RuleView({ k, admin, onClose, onEdit }: { k: string; admin: boolean; onClose: () => void; onEdit: (yaml: string) => void }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["yaml-rule", k], queryFn: () => api<any>(`/detections/yaml/${k}`) });
  const test = useMutation({ mutationFn: () => api<any>(`/detections/yaml/${k}/test`, { method: "POST" }) });
  const [hours, setHours] = useState(24);
  const dry = useMutation({ mutationFn: () => api<any>(`/detections/yaml/${k}/dry-run`, { method: "POST", params: { hours } }) });
  const rollback = useMutation({ mutationFn: (v: number) => api(`/detections/yaml/${k}/rollback/${v}`, { method: "POST" }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["yaml-rule", k] }); qc.invalidateQueries({ queryKey: ["yaml-rules"] }); } });
  const del = useMutation({ mutationFn: () => api(`/detections/yaml/${k}`, { method: "DELETE" }), onSuccess: () => { qc.invalidateQueries({ queryKey: ["yaml-rules"] }); onClose(); } });
  const r = q.data;
  return <Modal wide title={r ? `${r.id} ${r.name}` : "Rule"} onClose={onClose}>
    <Loading q={q} />
    {r && <div className="space-y-3 text-sm">
      <p>{r.description}</p>
      <div className="grid gap-3 md:grid-cols-3">
        <div><div className="label">Data sources</div><ul className="list-disc ml-4 text-xs">{r.data_sources.map((x: string) => <li key={x}>{x}</li>)}</ul></div>
        <div><div className="label">False positives</div><ul className="list-disc ml-4 text-xs">{r.falsepositives.map((x: string) => <li key={x}>{x}</li>)}</ul></div>
        <div><div className="label">Investigation</div><ol className="list-decimal ml-4 text-xs">{r.investigation.map((x: string) => <li key={x}>{x}</li>)}</ol></div>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <button className="btn" disabled={test.isPending} onClick={() => test.mutate()}>{test.isPending ? "Testing…" : `Run ${r.tests} test(s)`}</button>
        <label className="text-xs text-muted flex items-center gap-1">Dry run over the last
          <select className="input py-1" value={hours} onChange={(e) => setHours(+e.target.value)}>{[1, 6, 24, 72, 168].map((h) => <option key={h} value={h}>{h} h</option>)}</select></label>
        <button className="btn" disabled={dry.isPending} onClick={() => dry.mutate()}>{dry.isPending ? "Replaying…" : "Dry run"}</button>
        {admin && r.origin === "custom" && <>
          <button className="btn" onClick={() => onEdit(r.yaml)}>Edit</button>
          <button className="btn btn-danger" onClick={() => confirm(`Delete ${r.id}? Existing alerts are kept.`) && del.mutate()}>Delete</button></>}
        {admin && r.origin === "builtin" && <button className="btn" title="Copy into the editor under a new id" onClick={() => onEdit(r.yaml.replace(/^id: (\S+)/m, "id: CUST-1001"))}>Copy as custom</button>}
      </div>
      {[test.error, dry.error, rollback.error, del.error].filter(Boolean).map((e, i) => <div key={i} role="alert" className="text-red-300 text-sm">{(e as Error).message}</div>)}
      <TestResults data={test.data} />
      {dry.data && <div className="space-y-1">
        <div className="text-xs text-muted">{dry.data.groups} group(s) would have alerted in {dry.data.alerting_windows} window(s) of {fmtTimeframe(dry.data.window_s)} over
          {" "}{dry.data.hours} h (threshold {dry.data.threshold}, {dry.data.duration_ms} ms). {dry.data.note}.</div>
        {!dry.data.results.length ? <Empty text="Nothing would have alerted." /> :
          <TableWrap maxH="max-h-64"><table className="tbl"><thead><tr><th>Group</th><th className="num">Windows</th><th className="num">Max</th><th>First</th><th>Last</th></tr></thead>
            <tbody>{dry.data.results.map((h: any, i: number) => <tr key={i}><td className="text-xs font-mono">{Object.entries(h.group).map(([a, b]) => `${a}=${b}`).join(" ")}</td>
              <td className="num">{h.windows}</td><td className="num">{h.max_metric}</td><td className="text-xs"><Time v={h.first} /></td><td className="text-xs"><Time v={h.last} /></td></tr>)}</tbody></table></TableWrap>}
      </div>}
      {!!r.history?.length && <div><div className="label">Version history</div>
        <TableWrap><table className="tbl"><thead><tr><th className="num">Version</th><th>By</th><th>When</th><th /></tr></thead>
          <tbody>{r.history.map((h: any) => <tr key={h.version}><td className="num">{h.version}{h.rolled_back_to && <span className="text-2xs text-muted"> (from v{h.rolled_back_to})</span>}</td>
            <td className="text-xs">{h.by}</td><td className="text-xs"><Time v={h.at} /></td>
            <td>{admin && h.version !== r.version && <button className="link text-xs" onClick={() => rollback.mutate(h.version)}>Restore</button>}</td></tr>)}</tbody></table></TableWrap></div>}
      <div><div className="label">YAML (v{r.version}, sha256 {r.sha256})</div><pre className="text-xs font-mono bg-black/20 rounded p-2 overflow-auto max-h-80">{r.yaml}</pre></div>
    </div>}
  </Modal>;
}

const TEMPLATE = `id: CUST-1001
name: My detection
description: What this rule detects and why it matters.
version: 1
severity: medium
category: custom
log_source: {category: traffic}
detection:
  selection:
    src_ip: {internal: true}
    dst_port: [23]
  condition: {group_by: [src_ip], count: 1, timeframe: 15m}
data_sources: [FortiGate traffic logs]
falsepositives: [Describe known benign causes]
investigation: [First step an analyst should take]
tests:
  - name: telnet from an internal host
    events: [{src_ip: 10.1.1.5, dst_ip: 198.51.100.1, dst_port: 23, action: accept}]
    expect_alerts: 1
  - name: other ports do not match
    events: [{src_ip: 10.1.1.5, dst_ip: 198.51.100.1, dst_port: 443, action: accept}]
    expect_alerts: 0
`;

function RuleEditor({ initial, onClose }: { initial: string; onClose: () => void }) {
  const [text, setText] = useState(initial || TEMPLATE);
  const validate = useMutation({ mutationFn: () => api<any>("/detections/yaml/validate", { method: "POST", body: { yaml: text } }) });
  const test = useMutation({ mutationFn: () => api<any>("/detections/yaml/test", { method: "POST", body: { yaml: text } }) });
  const save = useMutation({ mutationFn: () => api<any>("/detections/yaml", { method: "POST", body: { yaml: text } }), onSuccess: onClose });
  const v = validate.data;
  return <Modal wide title="YAML detection rule" onClose={onClose}>
    <p className="text-xs text-muted mb-2">Saving requires every embedded test to pass; a changed rule needs a higher <span className="font-mono">version</span>.
      Fields, operators and the test format are documented in docs/DETECTION_RULES.md.</p>
    <textarea aria-label="Rule YAML" className="input w-full font-mono text-xs h-80" spellCheck={false} value={text} onChange={(e) => setText(e.target.value)} />
    <div className="flex gap-2 mt-2">
      <button className="btn" onClick={() => validate.mutate()} disabled={validate.isPending}>Validate</button>
      <button className="btn" onClick={() => test.mutate()} disabled={test.isPending}>Run tests</button>
      <button className="btn btn-primary ml-auto" onClick={() => save.mutate()} disabled={save.isPending}>{save.isPending ? "Saving…" : "Save rule"}</button>
    </div>
    {[validate.error, test.error, save.error].filter(Boolean).map((e, i) => <div key={i} role="alert" className="text-red-300 text-sm mt-2 whitespace-pre-wrap">{(e as Error).message}</div>)}
    {v && (v.valid ? <div className="mt-2 text-xs"><span className="text-emerald-300">Valid</span> · {v.id} v{v.version} · {v.tests} test(s)
      <pre className="font-mono bg-black/20 rounded p-2 mt-1 overflow-auto max-h-40">{v.sql}</pre></div>
      : <ul role="alert" className="mt-2 text-xs text-red-300 list-disc ml-4">{v.errors.map((e: string) => <li key={e}>{e}</li>)}</ul>)}
    <div className="mt-2"><TestResults data={test.data} /></div>
  </Modal>;
}
