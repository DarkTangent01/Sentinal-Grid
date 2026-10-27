import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useMe } from "../lib/context";
import { fmtNum } from "../lib/format";
import { Card, Empty, Loading, Modal, TableWrap, Tabs, Time } from "../components/ui";

interface Action { type: string; [k: string]: any }
interface Rule { id?: number; name: string; description: string; enabled: boolean; priority: number; trigger: string; conditions: Record<string, any>;
  actions: Action[]; stop_processing: boolean; run_count?: number; last_run?: string; created_by?: string }
interface Meta { triggers: string[]; actions: string[]; tactics: { id: string; name: string }[]; rules: { key: string; name: string }[]; users: string[];
  channels: { id: number; name: string }[]; watchlists: { id: number; name: string; kind: string }[] }

const SEV = ["informational", "low", "medium", "high", "critical"];
const TRIGGER_LABEL: Record<string, string> = { "alert.created": "Alert created", "incident.created": "Incident created", "incident.escalated": "Incident escalated" };
const ACTION_LABEL: Record<string, string> = {
  assign: "Assign to analyst", set_status: "Change status", set_severity: "Change severity", comment: "Add comment / note",
  notify: "Send notification", enrich: "Enrich entity (asset, threat intel, 24h activity, related alerts)", add_to_watchlist: "Add entity to watchlist",
  suggest_block: "Generate FortiOS block CLI (not applied)", run_query: "Run query and attach results",
};
const BLANK: Rule = { name: "", description: "", enabled: true, priority: 100, trigger: "incident.created", conditions: { min_severity: "high" },
  actions: [{ type: "enrich" }], stop_processing: false };

export function Automation() {
  const [tab, setTab] = useState("rules");
  return (
    <div className="space-y-3 min-w-0">
      <p className="text-xs text-muted">Automation rules are playbooks: when an alert or incident matches the conditions, the actions run in order.
        Actions only change SIEM data and send notifications — the SIEM never writes to a firewall. <b>Generate FortiOS block CLI</b> attaches commands for an analyst to review and apply.</p>
      <Tabs value={tab} onChange={setTab} tabs={[{ key: "rules", label: "Rules" }, { key: "runs", label: "Run history" }]} />
      {tab === "rules" ? <Rules /> : <Runs />}
    </div>
  );
}

function summarizeConditions(c: Record<string, any>) {
  const out = [];
  if (c.min_severity) out.push(`severity ≥ ${c.min_severity}`);
  if (c.rule_keys?.length) out.push(`rule in ${c.rule_keys.length}`);
  if (c.tactics?.length) out.push(`tactic ${c.tactics.join("/")}`);
  if (c.entity_types?.length) out.push(`entity ${c.entity_types.join("/")}`);
  if (c.asset_criticality?.length) out.push(`asset ${c.asset_criticality.join("/")}`);
  if (c.sites?.length) out.push(`site ${c.sites.join("/")}`);
  if (c.title_contains) out.push(`title ~ "${c.title_contains}"`);
  return out.join(" · ") || "always";
}

function Rules() {
  const me = useMe();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["automation"], queryFn: () => api<Rule[]>("/automation/rules") });
  const [edit, setEdit] = useState<Rule | null>(null);
  const [test, setTest] = useState<Rule | null>(null);
  const refresh = () => qc.invalidateQueries({ queryKey: ["automation"] });
  const toggle = useMutation({ mutationFn: (r: Rule) => api(`/automation/rules/${r.id}`, { method: "PUT", body: { ...payload(r), enabled: !r.enabled } }), onSuccess: refresh });
  const del = useMutation({ mutationFn: (id: number) => api(`/automation/rules/${id}`, { method: "DELETE" }), onSuccess: refresh });
  const admin = me.role === "admin";
  return (
    <Card title="Automation rules" right={admin && <button className="btn btn-primary" onClick={() => setEdit({ ...BLANK })}>+ New rule</button>}>
      <Loading q={q} />
      {q.data && !q.data.length && <Empty text="No automation rules. A good first playbook: on incident created with severity ≥ high → enrich, assign, notify." />}
      {!!q.data?.length && <TableWrap><table className="tbl">
        <thead><tr><th className="num">Order</th><th>Name</th><th>When</th><th>If</th><th className="w-full">Then</th><th className="num">Runs</th><th>Last run</th><th>Enabled</th><th /></tr></thead>
        <tbody>{q.data.map((r) => <tr key={r.id}>
          <td className="num">{r.priority}</td>
          <td className="min-w-[10rem]">{r.name}{r.stop_processing && <span className="pill bg-slate-800 text-slate-400 ml-1">stops</span>}{r.description && <div className="text-2xs text-muted">{r.description}</div>}</td>
          <td className="text-xs nowrap">{TRIGGER_LABEL[r.trigger] || r.trigger}</td>
          <td className="text-xs">{summarizeConditions(r.conditions)}</td>
          <td className="text-xs">{r.actions.map((a, i) => <span key={i} className="pill bg-slate-800 text-slate-300 mr-1 mb-0.5">{a.type}</span>)}</td>
          <td className="num">{fmtNum(r.run_count)}</td><td><Time v={r.last_run} /></td>
          <td>{admin ? <input type="checkbox" aria-label={`Enable ${r.name}`} checked={r.enabled} onChange={() => toggle.mutate(r)} /> : r.enabled ? "yes" : "no"}</td>
          <td className="nowrap">{admin && <>
            <button className="btn" onClick={() => setTest(r)}>Test</button>
            <button className="btn ml-1" onClick={() => setEdit(r)}>Edit</button>
            <button className="btn btn-danger ml-1" onClick={() => confirm(`Delete rule "${r.name}"?`) && del.mutate(r.id!)}>Delete</button></>}</td>
        </tr>)}</tbody></table></TableWrap>}
      {edit && <Editor r={edit} onClose={() => { setEdit(null); refresh(); }} />}
      {test && <TestModal r={test} onClose={() => { setTest(null); refresh(); }} />}
    </Card>
  );
}

function payload(r: Rule) {
  const { id, run_count, last_run, created_by, ...rest } = r as any;
  delete rest.updated_at;
  return rest;
}

function MultiCheck({ label, options, value, onChange }: { label: string; options: [string, string][]; value?: string[]; onChange: (v: string[]) => void }) {
  const v = value || [];
  return (
    <div><div className="label">{label}</div>
      <div className="border border-line rounded-lg p-2 max-h-36 overflow-auto space-y-0.5">
        {options.map(([k, l]) => <label key={k} className="flex items-center gap-2 text-xs"><input type="checkbox" checked={v.includes(k)}
          onChange={(e) => onChange(e.target.checked ? [...v, k] : v.filter((x) => x !== k))} /><span className="truncate" title={l}>{l}</span></label>)}
        {!options.length && <div className="text-2xs text-muted">none available</div>}
      </div></div>
  );
}

function Editor({ r, onClose }: { r: Rule; onClose: () => void }) {
  const meta = useQuery({ queryKey: ["automation-meta"], queryFn: () => api<Meta>("/automation/meta") });
  const [f, setF] = useState<Rule>(structuredClone(r));
  const [add, setAdd] = useState("");
  const c = f.conditions;
  const setC = (k: string, v: any) => setF({ ...f, conditions: { ...c, [k]: Array.isArray(v) ? (v.length ? v : undefined) : v || undefined } });
  const setA = (i: number, patch: Partial<Action>) => setF({ ...f, actions: f.actions.map((a, j) => (j === i ? { ...a, ...patch } : a)) });
  const move = (i: number, d: number) => {
    const a = [...f.actions];
    const j = i + d;
    if (j < 0 || j >= a.length) return;
    [a[i], a[j]] = [a[j], a[i]];
    setF({ ...f, actions: a });
  };
  const save = useMutation({ mutationFn: () => api(r.id ? `/automation/rules/${r.id}` : "/automation/rules", { method: r.id ? "PUT" : "POST",
    body: { ...payload(f), priority: Number(f.priority), conditions: Object.fromEntries(Object.entries(c).filter(([, v]) => v !== undefined && v !== "")) } }), onSuccess: onClose });
  const m = meta.data;
  const incident = f.trigger.startsWith("incident");
  return (
    <Modal title={r.id ? `Automation: ${r.name}` : "New automation rule"} onClose={onClose} wide>
      <Loading q={meta} />
      {m && <div className="space-y-4">
        <div className="grid gap-2 sm:grid-cols-4">
          <div className="sm:col-span-2"><label className="label">Name</label><input className="input w-full" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></div>
          <div><label className="label">Trigger</label><select className="input w-full" value={f.trigger} onChange={(e) => setF({ ...f, trigger: e.target.value })}>
            {m.triggers.map((t) => <option key={t} value={t}>{TRIGGER_LABEL[t] || t}</option>)}</select></div>
          <div><label className="label">Order (lower runs first)</label><input type="number" min={0} className="input w-full" value={f.priority} onChange={(e) => setF({ ...f, priority: Number(e.target.value) })} /></div>
          <div className="sm:col-span-4"><label className="label">Description</label><input className="input w-full" value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></div>
        </div>
        <fieldset className="border border-line rounded-lg p-3">
          <legend className="text-xs font-semibold px-1">Conditions (all must match; empty = any)</legend>
          <div className="grid gap-3 sm:grid-cols-3">
            <div><label className="label">Minimum severity</label><select className="input w-full" value={c.min_severity || ""} onChange={(e) => setC("min_severity", e.target.value)}>
              <option value="">any</option>{SEV.map((s) => <option key={s}>{s}</option>)}</select></div>
            <div><label className="label">Title contains</label><input className="input w-full" value={c.title_contains || ""} onChange={(e) => setC("title_contains", e.target.value)} /></div>
            <MultiCheck label="Entity type" options={[["ip", "IP"], ["user", "User"], ["firewall", "Firewall"], ["other", "Other"]]} value={c.entity_types} onChange={(v) => setC("entity_types", v)} />
            <MultiCheck label="Detection rule" options={m.rules.map((x) => [x.key, x.name])} value={c.rule_keys} onChange={(v) => setC("rule_keys", v)} />
            <MultiCheck label="ATT&CK tactic" options={m.tactics.map((t) => [t.id, `${t.id} ${t.name}`])} value={c.tactics} onChange={(v) => setC("tactics", v)} />
            <MultiCheck label="Asset criticality" options={[["critical", "critical"], ["high", "high"], ["normal", "normal"], ["low", "low"]]} value={c.asset_criticality} onChange={(v) => setC("asset_criticality", v)} />
          </div>
        </fieldset>
        <fieldset className="border border-line rounded-lg p-3 space-y-2">
          <legend className="text-xs font-semibold px-1">Actions (run in order)</legend>
          {f.actions.map((a, i) => (
            <div key={i} className="border border-line/70 rounded-lg p-2.5">
              <div className="flex items-center gap-2 mb-2">
                <span className="text-xs font-semibold flex-1">{i + 1}. {ACTION_LABEL[a.type] || a.type}</span>
                <button className="btn px-2 py-0.5" aria-label="Move up" onClick={() => move(i, -1)}>↑</button>
                <button className="btn px-2 py-0.5" aria-label="Move down" onClick={() => move(i, 1)}>↓</button>
                <button className="btn btn-danger px-2 py-0.5" aria-label="Remove action" onClick={() => setF({ ...f, actions: f.actions.filter((_, j) => j !== i) })}>✕</button>
              </div>
              <ActionFields a={a} m={m} incident={incident} set={(p) => setA(i, p)} />
            </div>
          ))}
          <div className="flex gap-2">
            <select aria-label="Add action" className="input" value={add} onChange={(e) => setAdd(e.target.value)}>
              <option value="">Add action…</option>{m.actions.map((t) => <option key={t} value={t}>{ACTION_LABEL[t] || t}</option>)}</select>
            <button className="btn" disabled={!add} onClick={() => { setF({ ...f, actions: [...f.actions, { type: add }] }); setAdd(""); }}>Add</button>
          </div>
        </fieldset>
        <div className="flex flex-wrap gap-4 items-center">
          <label className="text-sm flex items-center gap-2"><input type="checkbox" checked={f.enabled} onChange={(e) => setF({ ...f, enabled: e.target.checked })} />Enabled</label>
          <label className="text-sm flex items-center gap-2"><input type="checkbox" checked={f.stop_processing} onChange={(e) => setF({ ...f, stop_processing: e.target.checked })} />Stop processing later rules when this one matches</label>
        </div>
        {save.error && <div role="alert" className="text-sm text-red-400 font-mono">{(save.error as Error).message}</div>}
        <button className="btn btn-primary" disabled={!f.name || !f.actions.length || save.isPending} onClick={() => save.mutate()}>Save</button>
      </div>}
    </Modal>
  );
}

function ActionFields({ a, m, incident, set }: { a: Action; m: Meta; incident: boolean; set: (p: Partial<Action>) => void }) {
  const tpl = <span className="text-2xs text-muted">Placeholders: {"{title} {severity} {entity} {entity_type} {id} {type}"}</span>;
  switch (a.type) {
    case "assign":
      return <select aria-label="Analyst" className="input" value={a.user || ""} onChange={(e) => set({ user: e.target.value })}><option value="">Choose analyst…</option>{m.users.map((u) => <option key={u}>{u}</option>)}</select>;
    case "set_status":
      return <div className="flex flex-wrap gap-2">
        <select aria-label="Status" className="input" value={a.status || ""} onChange={(e) => set({ status: e.target.value })}><option value="">Choose…</option>
          {(incident ? ["in_progress", "resolved", "closed"] : ["investigating", "resolved", "suppressed"]).map((s) => <option key={s}>{s}</option>)}</select>
        {incident && ["resolved", "closed"].includes(a.status) && <select aria-label="Closure reason" className="input" value={a.closure_reason || ""} onChange={(e) => set({ closure_reason: e.target.value })}>
          <option value="">closure reason…</option>{["true_positive", "false_positive", "benign", "duplicate"].map((s) => <option key={s}>{s}</option>)}</select>}
      </div>;
    case "set_severity":
      return <select aria-label="Severity" className="input" value={a.severity || ""} onChange={(e) => set({ severity: e.target.value })}><option value="">Choose…</option>{SEV.map((s) => <option key={s}>{s}</option>)}</select>;
    case "comment":
      return <div><textarea aria-label="Comment" className="input w-full h-16" value={a.text || ""} onChange={(e) => set({ text: e.target.value })} />{tpl}</div>;
    case "notify":
      return <div className="grid gap-2 sm:grid-cols-2">
        <select aria-label="Channel" className="input" value={a.channel_id || ""} onChange={(e) => set({ channel_id: Number(e.target.value) || undefined })}>
          <option value="">Choose channel…</option>{m.channels.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}</select>
        <input aria-label="Notification title" className="input" placeholder="[{severity}] {title}" value={a.title || ""} onChange={(e) => set({ title: e.target.value })} />
        <div className="sm:col-span-2">{tpl}{!m.channels.length && <span className="text-2xs text-amber-300 ml-2">Create a channel under Notifications first.</span>}</div>
      </div>;
    case "add_to_watchlist":
      return <div className="grid gap-2 sm:grid-cols-3">
        <select aria-label="Watchlist" className="input" value={a.watchlist_id || ""} onChange={(e) => set({ watchlist_id: Number(e.target.value) || undefined })}>
          <option value="">Choose watchlist…</option>{m.watchlists.map((w) => <option key={w.id} value={w.id}>{w.name} ({w.kind})</option>)}</select>
        <input aria-label="Expire after hours" type="number" min={0} className="input" placeholder="expire after hours (0 = never)" value={a.ttl_hours ?? ""} onChange={(e) => set({ ttl_hours: Number(e.target.value) })} />
        <input aria-label="Label" className="input" placeholder="{type} #{id}: {title}" value={a.label || ""} onChange={(e) => set({ label: e.target.value })} />
      </div>;
    case "run_query":
      return <div className="space-y-1">
        <textarea aria-label="Query" className="input w-full h-16 font-mono text-xs" placeholder="src_ip:$entity$ | stats dc(dst_ip) as dsts, sum(sent_bytes) as sent by dst_port | sort -dsts | head 10"
          value={a.query || ""} onChange={(e) => set({ query: e.target.value })} />
        <div className="flex items-center gap-2"><select aria-label="Query range" className="input py-1" value={a.range || "24h"} onChange={(e) => set({ range: e.target.value })}>
          {["1h", "24h", "7d"].map((r) => <option key={r}>{r}</option>)}</select><span className="text-2xs text-muted">$entity$ is replaced with the alert/incident entity; the first 10 rows are attached.</span></div>
      </div>;
    case "suggest_block":
      return <p className="text-2xs text-muted">For IP entities: adds an address object + SIEM-BLOCKLIST group CLI as a comment. Nothing is sent to the firewall.</p>;
    default:
      return <p className="text-2xs text-muted">No settings.</p>;
  }
}

function TestModal({ r, onClose }: { r: Rule; onClose: () => void }) {
  const [t, setT] = useState({ target_type: r.trigger.startsWith("incident") ? "incident" : "alert", target_id: "" });
  const m = useMutation({ mutationFn: (apply: boolean) => api<any>(`/automation/rules/${r.id}/test`, { method: "POST", body: { ...t, target_id: Number(t.target_id), apply } }) });
  return (
    <Modal title={`Test: ${r.name}`} onClose={onClose}>
      <p className="text-xs text-muted mb-2">A dry run shows whether the conditions match and what each action would do, without changing anything.</p>
      <div className="flex flex-wrap gap-2 items-end">
        <div><label className="label">Target</label><select className="input" value={t.target_type} onChange={(e) => setT({ ...t, target_type: e.target.value })}><option value="incident">Incident</option><option value="alert">Alert</option></select></div>
        <div><label className="label">ID</label><input className="input w-28" inputMode="numeric" value={t.target_id} onChange={(e) => setT({ ...t, target_id: e.target.value.replace(/\D/g, "") })} /></div>
        <button className="btn" disabled={!t.target_id || m.isPending} onClick={() => m.mutate(false)}>Dry run</button>
        <button className="btn btn-primary" disabled={!t.target_id || m.isPending} onClick={() => confirm("Run the actions for real on this target?") && m.mutate(true)}>Run for real</button>
      </div>
      {m.error && <div role="alert" className="text-sm text-red-400 mt-2">{(m.error as Error).message}</div>}
      {m.data && <div className="mt-3 text-sm space-y-2">
        <div>Conditions: <b className={m.data.conditions_match ? "text-emerald-300" : "text-amber-300"}>{m.data.conditions_match ? "match" : `do not match (${m.data.reason})`}</b> · status <b>{m.data.status}</b></div>
        <ul className="text-xs space-y-1">{m.data.results.map((x: any, i: number) => <li key={i}><span className={x.ok ? "text-emerald-300" : "text-red-300"}>{x.ok ? "✓" : "✕"}</span> <b>{x.action}</b> — {x.detail}</li>)}</ul>
      </div>}
    </Modal>
  );
}

function Runs() {
  const nav = useNavigate();
  const [page, setPage] = useState(1);
  const q = useQuery({ queryKey: ["automation-runs", page], queryFn: () => api<any>("/automation/runs", { params: { page, size: 50 } }), refetchInterval: 30_000, placeholderData: (p) => p });
  const pages = q.data ? Math.max(1, Math.ceil(q.data.total / 50)) : 1;
  const STATUS: Record<string, string> = { ok: "bg-emerald-500/15 text-emerald-300", partial: "bg-amber-500/15 text-amber-300", error: "bg-red-500/15 text-red-300" };
  return (
    <Card title="Run history" right={<><button className="btn" disabled={page <= 1} onClick={() => setPage(page - 1)}>‹</button><span className="text-muted text-sm">{page}/{pages}</span>
      <button className="btn" disabled={page >= pages} onClick={() => setPage(page + 1)}>›</button></>}>
      <Loading q={q} />
      {q.data && !q.data.items.length && <Empty text="No automation runs yet." />}
      {!!q.data?.items.length && <TableWrap><table className="tbl"><thead><tr><th>When</th><th>Rule</th><th>Trigger</th><th>Target</th><th>Status</th><th className="w-full">Results</th></tr></thead>
        <tbody>{q.data.items.map((x: any) => <tr key={x.id}><td><Time v={x.at} /></td><td>{x.rule_name}</td><td className="text-xs">{TRIGGER_LABEL[x.trigger] || x.trigger}</td>
          <td>{x.target_type === "incident" ? <button className="link" onClick={() => nav(`/incidents/${x.target_id}`)}>incident #{x.target_id}</button>
            : <button className="link" onClick={() => nav(`/alerts?id=${x.target_id}`)}>alert #{x.target_id}</button>}</td>
          <td><span className={`pill ${STATUS[x.status] || "bg-slate-800 text-slate-300"}`}>{x.status}</span></td>
          <td className="text-xs">{x.results.map((r: any, i: number) => <div key={i}><span className={r.ok ? "text-emerald-300" : "text-red-300"}>{r.ok ? "✓" : "✕"}</span> {r.action}: {r.detail}</div>)}</td></tr>)}</tbody></table></TableWrap>}
    </Card>
  );
}
