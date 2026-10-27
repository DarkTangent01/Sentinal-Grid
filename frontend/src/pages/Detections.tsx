import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, qs } from "../lib/api";
import { useMe } from "../lib/context";
import { fmtNum } from "../lib/format";
import { Card, Empty, Loading, Modal, Sev, TableWrap, Time } from "../components/ui";

const OPS: [string, string][] = [["gt", ">"], ["ge", "≥"], ["eq", "="], ["ne", "≠"], ["lt", "<"], ["le", "≤"]];
const BLANK = { name: "", description: "", severity: "medium", enabled: true, query: "", lookback_minutes: 60, interval_minutes: 5,
  trigger_op: "gt", trigger_count: 0, grouping: "per_row", entity_fields: [] as string[], explanation: "", tactic: "", techniques: [] as string[] };
type Det = typeof BLANK & { id?: number; key?: string; alerts_7d?: number; last_alert?: string };

export function Detections() {
  const me = useMe();
  const qc = useQueryClient();
  const nav = useNavigate();
  const [sp, setSp] = useSearchParams();
  const q = useQuery({ queryKey: ["detections"], queryFn: () => api<Det[]>("/detections") });
  const [edit, setEdit] = useState<Det | null>(null);
  const [sigma, setSigma] = useState(false);
  useEffect(() => {
    const nq = sp.get("new");
    if (nq !== null) { setEdit({ ...BLANK, query: nq }); setSp({}, { replace: true }); }
  }, []);
  const toggle = useMutation({
    mutationFn: (d: Det) => api(`/detections/${d.id}`, { method: "PUT", body: { ...strip(d), enabled: !d.enabled } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["detections"] }),
  });
  const del = useMutation({ mutationFn: (id: number) => api(`/detections/${id}`, { method: "DELETE" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["detections"] }) });
  return (
    <div className="space-y-4 min-w-0">
      <p className="text-xs text-muted">Custom analytics rules run a pipeline query on a schedule over a look-back window. When the number of results meets the trigger,
        alerts are raised (one per result row, or one for the whole result) and flow through suppression, incident correlation, automation and notifications like the built-in rules.
        Built-in detections are tuned under <button className="link" onClick={() => nav("/alerts")}>Alerts → Rules</button>.</p>
      <Card title="Custom detections" right={me.role === "admin" && <>
        <button className="btn" onClick={() => setSigma(true)}>Import Sigma rule</button>
        <button className="btn btn-primary" onClick={() => setEdit({ ...BLANK })}>+ New detection</button></>}>
        <Loading q={q} />
        {q.data && !q.data.length && <Empty text="No custom detections yet. Write a query in Search and click Create detection, or start here." />}
        {!!q.data?.length && <TableWrap><table className="tbl">
          <thead><tr><th>Name</th><th>Severity</th><th className="w-full">Query</th><th>Schedule</th><th>Trigger</th><th>ATT&CK</th><th className="num">Alerts 7d</th><th>Last alert</th><th>Enabled</th><th /></tr></thead>
          <tbody>{q.data.map((d) => <tr key={d.id}>
            <td className="min-w-[10rem]">{d.name}{d.description && <div className="text-2xs text-muted">{d.description}</div>}</td>
            <td><Sev s={d.severity} /></td>
            <td className="font-mono text-xs cell-wrap min-w-[16rem]">{d.query}</td>
            <td className="text-xs nowrap">every {d.interval_minutes}m · last {d.lookback_minutes}m</td>
            <td className="text-xs nowrap">results {OPS.find((o) => o[0] === d.trigger_op)?.[1]} {d.trigger_count} · {d.grouping === "single" ? "one alert" : "per row"}</td>
            <td className="text-xs">{d.tactic ? <span title={(d.techniques || []).join(", ")}>{d.tactic}{d.techniques?.length ? ` · ${d.techniques.join(", ")}` : ""}</span> : "—"}</td>
            <td className="num">{d.alerts_7d ? <button className="link" onClick={() => nav(`/alerts${qs({ rule: d.key })}`)}>{fmtNum(d.alerts_7d)}</button> : "0"}</td>
            <td><Time v={d.last_alert} /></td>
            <td>{me.role === "admin" ? <input type="checkbox" aria-label={`Enable ${d.name}`} checked={d.enabled} onChange={() => toggle.mutate(d)} /> : d.enabled ? "yes" : "no"}</td>
            <td className="nowrap"><button className="btn" onClick={() => nav(`/search${qs({ q: d.query })}`)}>Run</button>
              <button className="btn ml-1" onClick={() => setEdit(d)}>{me.role === "admin" ? "Edit" : "View"}</button>
              {me.role === "admin" && <button className="btn btn-danger ml-1" onClick={() => confirm(`Delete detection "${d.name}"? Existing alerts are kept.`) && del.mutate(d.id!)}>Delete</button>}</td>
          </tr>)}</tbody></table></TableWrap>}
      </Card>
      <Tuning admin={me.role === "admin"} />
      {edit && <Editor d={edit} readOnly={me.role !== "admin"} onClose={() => { setEdit(null); qc.invalidateQueries({ queryKey: ["detections"] }); }} />}
      {sigma && <SigmaImport onClose={() => setSigma(false)} onConverted={(d) => { setSigma(false); setEdit({ ...BLANK, ...d }); }} />}
    </div>
  );
}

function strip(d: Det) {
  const { id, key, alerts_7d, last_alert, ...rest } = d as any;
  return rest;
}

function Editor({ d, readOnly, onClose }: { d: Det; readOnly: boolean; onClose: () => void }) {
  const [f, setF] = useState<Det>({ ...BLANK, ...d, entity_fields: d.entity_fields || [], techniques: d.techniques || [] });
  const tactics = useQuery({ queryKey: ["mitre-tactics"], queryFn: () => api<{ id: string; name: string }[]>("/mitre/tactics"), staleTime: Infinity });
  const set = (k: keyof Det, v: any) => setF({ ...f, [k]: v });
  const body = () => ({ ...strip(f), lookback_minutes: Number(f.lookback_minutes), interval_minutes: Number(f.interval_minutes), trigger_count: Number(f.trigger_count) });
  const preview = useMutation({ mutationFn: () => api<any>("/detections/preview", { method: "POST", body: { ...body(), name: f.name || "preview" } }) });
  const save = useMutation({
    mutationFn: () => api(d.id ? `/detections/${d.id}` : "/detections", { method: d.id ? "PUT" : "POST", body: body() }),
    onSuccess: onClose,
  });
  const p = preview.data;
  return (
    <Modal title={d.id ? `Detection: ${d.name}` : "New detection"} onClose={onClose} wide>
      <fieldset disabled={readOnly} className="grid gap-3 sm:grid-cols-4">
        <div className="sm:col-span-3"><label className="label">Name</label><input className="input w-full" value={f.name} onChange={(e) => set("name", e.target.value)} /></div>
        <div><label className="label">Severity</label><select className="input w-full" value={f.severity} onChange={(e) => set("severity", e.target.value)}>
          {["informational", "low", "medium", "high", "critical"].map((x) => <option key={x}>{x}</option>)}</select></div>
        <div className="sm:col-span-4"><label className="label">Description</label><input className="input w-full" value={f.description} onChange={(e) => set("description", e.target.value)} /></div>
        <div className="sm:col-span-4"><label className="label">Query (pipeline). Tip: aggregate with stats … by &lt;entity&gt; and filter with where, so each result row is one finding.</label>
          <textarea className="input w-full font-mono text-[13px] min-h-[6rem]" spellCheck={false} value={f.query} onChange={(e) => set("query", e.target.value)} /></div>
        <div><label className="label">Run every (minutes)</label><input type="number" min={1} max={1440} className="input w-full" value={f.interval_minutes} onChange={(e) => set("interval_minutes", e.target.value)} /></div>
        <div><label className="label">Look back (minutes)</label><input type="number" min={1} max={20160} className="input w-full" value={f.lookback_minutes} onChange={(e) => set("lookback_minutes", e.target.value)} /></div>
        <div><label className="label">Alert when results</label><div className="flex gap-1">
          <select className="input" value={f.trigger_op} onChange={(e) => set("trigger_op", e.target.value)}>{OPS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
          <input type="number" min={0} className="input w-full" value={f.trigger_count} onChange={(e) => set("trigger_count", e.target.value)} /></div></div>
        <div><label className="label">Alert grouping</label><select className="input w-full" value={f.grouping} onChange={(e) => set("grouping", e.target.value)}>
          <option value="per_row">One alert per result row</option><option value="single">One alert for all results</option></select></div>
        <div className="sm:col-span-2"><label className="label">Entity fields (comma-separated; default: src_ip, user, …)</label>
          <input className="input w-full font-mono" value={f.entity_fields.join(", ")} onChange={(e) => set("entity_fields", e.target.value.split(",").map((x) => x.trim()).filter(Boolean))} /></div>
        <div><label className="label">MITRE ATT&CK tactic</label><select className="input w-full" value={f.tactic} onChange={(e) => set("tactic", e.target.value)}>
          <option value="">—</option>{(tactics.data || []).map((t) => <option key={t.id} value={t.id}>{t.id} {t.name}</option>)}</select></div>
        <div><label className="label">Techniques</label><input className="input w-full font-mono" placeholder="T1021, T1110.001" value={f.techniques.join(", ")}
          onChange={(e) => set("techniques", e.target.value.split(",").map((x) => x.trim()).filter(Boolean))} /></div>
        <div className="sm:col-span-4"><label className="label">Alert explanation template — {"{field}"} is replaced from the result row</label>
          <input className="input w-full" placeholder="{src_ip} contacted {dsts} hosts on port 3389" value={f.explanation} onChange={(e) => set("explanation", e.target.value)} /></div>
        <label className="text-sm flex items-center gap-2"><input type="checkbox" checked={f.enabled} onChange={(e) => set("enabled", e.target.checked)} />Enabled</label>
      </fieldset>
      <div className="flex flex-wrap gap-2 mt-3">
        <button className="btn" disabled={!f.query || preview.isPending} onClick={() => preview.mutate()}>{preview.isPending ? "Testing…" : "Test against current data"}</button>
        {!readOnly && <button className="btn btn-primary" disabled={!f.name || !f.query || save.isPending} onClick={() => save.mutate()}>Save</button>}
      </div>
      {(preview.error || save.error) && <div role="alert" className="text-sm text-red-400 mt-2 font-mono whitespace-pre-wrap">{((preview.error || save.error) as Error).message}</div>}
      {p && <div className="mt-3 border border-line rounded-lg p-3 text-sm space-y-2">
        <div><b className={p.fired ? "text-red-300" : "text-emerald-300"}>{p.fired ? `Would raise ${p.alerts.length} alert(s)` : "Would not alert"}</b>
          <span className="text-muted"> · query returned {fmtNum(p.rows)}{p.truncated ? "+" : ""} row(s) in the last {f.lookback_minutes} min · {p.elapsed_ms} ms</span></div>
        {p.alerts.length > 0 && <TableWrap maxH="max-h-64"><table className="tbl"><thead><tr><th>Group</th><th className="num">Count</th><th>Explanation</th></tr></thead>
          <tbody>{p.alerts.map((a: any, i: number) => <tr key={i}><td className="font-mono text-xs cell-wrap">{a.group_key}</td><td className="num">{fmtNum(a.count)}</td><td className="text-xs cell-wrap">{a.explanation}</td></tr>)}</tbody></table></TableWrap>}
      </div>}
    </Modal>
  );
}

function SigmaImport({ onClose, onConverted }: { onClose: () => void; onConverted: (d: Partial<Det>) => void }) {
  const [text, setText] = useState("");
  const m = useMutation({ mutationFn: () => api<any>("/sigma/convert", { method: "POST", body: { yaml: text } }) });
  const r = m.data;
  return (
    <Modal title="Import Sigma rule" onClose={onClose} wide>
      <p className="text-xs text-muted mb-2">Paste one Sigma rule (YAML). Network, firewall, DNS, proxy and Windows authentication rules translate to a pipeline query;
        fields or modifiers with no FortiGate/Windows equivalent are rejected with a reason instead of being approximated.</p>
      <textarea aria-label="Sigma YAML" className="input w-full h-72 font-mono text-xs" spellCheck={false} value={text} onChange={(e) => setText(e.target.value)}
        placeholder={"title: Outbound RDP to the internet\nlogsource:\n  category: firewall\ndetection:\n  selection:\n    dst_port: 3389\n  filter:\n    dst_ip|cidr: 10.0.0.0/8\n  condition: selection and not filter\nlevel: high\ntags: [attack.lateral_movement, attack.t1021.001]"} />
      <div className="flex gap-2 mt-2">
        <button className="btn" disabled={!text.trim() || m.isPending} onClick={() => m.mutate()}>Convert</button>
        {r && <button className="btn btn-primary" onClick={() => onConverted({ name: r.name, description: r.description, severity: r.severity, query: r.query,
          tactic: r.tactic, techniques: r.techniques, grouping: r.grouping })}>Open as detection</button>}
      </div>
      {m.error && <div role="alert" className="text-sm text-red-400 mt-2">{(m.error as Error).message}</div>}
      {r && <div className="mt-3 text-sm space-y-1">
        <div><b>{r.name}</b> · {r.severity}{r.tactic && ` · ${r.tactic}`}{r.techniques.length > 0 && ` · ${r.techniques.join(", ")}`}</div>
        <div className="font-mono text-xs bg-panel2 p-2 rounded cell-wrap">{r.query}</div>
        {r.warnings.map((w: string) => <div key={w} className="text-xs text-amber-300">⚠ {w}</div>)}
      </div>}
    </Modal>
  );
}

const TUNE_LABEL: Record<string, string> = { raise_threshold: "Raise threshold", suppress_entity: "Suppress entity", review_rule: "Review rule", noisy_untriaged: "Untriaged noise" };

function Tuning({ admin }: { admin: boolean }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["tuning"], queryFn: () => api<any[]>("/tuning/suggestions", { params: { days: 90 } }) });
  const apply = useMutation({ mutationFn: (x: any) => api("/tuning/apply", { method: "POST", body: x.type === "raise_threshold"
      ? { type: x.type, rule_key: x.rule_key, param: x.param, value: x.proposed } : { type: x.type, rule_key: x.rule_key, group_key: x.group_key, hours: 24 * 30 } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["tuning"] }) });
  return (
    <Card title="Tuning suggestions (from analyst verdicts, 90 days)">
      <p className="text-xs text-muted mb-2">Based on incident/alert dispositions (true positive, false positive, benign). Close incidents with a disposition to improve these.
        Suppressions created here last 30 days; threshold changes apply to the built-in rule.</p>
      <Loading q={q} />
      {q.data && !q.data.length && <Empty text="No suggestions — not enough decided alerts yet, or the rules are already well tuned." />}
      {!!q.data?.length && <TableWrap><table className="tbl"><thead><tr><th>Suggestion</th><th>Rule</th><th className="w-full">Why</th><th>Effect</th><th /></tr></thead>
        <tbody>{q.data.map((x, i) => <tr key={i}>
          <td className="nowrap"><span className="pill bg-brand-500/10 text-brand-400">{TUNE_LABEL[x.type]}</span></td>
          <td className="text-xs">{x.rule}</td>
          <td className="text-xs">{x.reason}{x.type === "suppress_entity" && <div className="font-mono text-muted">{x.group_key}</div>}
            {x.type === "raise_threshold" && <div className="font-mono text-muted">{x.param}: {x.current} → {x.proposed}</div>}</td>
          <td className="text-xs">{x.impact}</td>
          <td>{admin && (x.type === "raise_threshold" || x.type === "suppress_entity") &&
            <button className="btn" disabled={apply.isPending} onClick={() => confirm(`${TUNE_LABEL[x.type]} for ${x.rule}?`) && apply.mutate(x)}>Apply</button>}</td>
        </tr>)}</tbody></table></TableWrap>}
      {apply.error && <div role="alert" className="text-sm text-red-400 mt-2">{(apply.error as Error).message}</div>}
    </Card>
  );
}
