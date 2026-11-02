import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, downloadUrl } from "../../lib/api";
import { Card, Empty, Loading, TableWrap, Time } from "../../components/ui";
import { Confirm, ErrorBox, LineDiff, Note, SevBadge, can, useAct, useMeta } from "./common";

const ESC: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;" };
const esc = (s: string) => s.replace(/[&<>]/g, (c) => ESC[c]);

/** Minimal YAML highlighter (comments, keys, strings, variables, numbers, list dashes). Output is escaped text. */
export function highlight(line: string): string {
  const hash = line.search(/(^|\s)#/);
  const code = hash >= 0 ? line.slice(0, hash) : line;
  const comment = hash >= 0 ? line.slice(hash) : "";
  let h = esc(code)
    .replace(/("[^"]*"|'[^']*')/g, '<span class="text-emerald-600 dark:text-emerald-400">$1</span>')
    .replace(/(\$\{[A-Za-z_][A-Za-z0-9_]*\})/g, '<span class="text-violet-600 dark:text-violet-400 font-semibold">$1</span>')
    .replace(/^(\s*-?\s*)([A-Za-z0-9_\-.]+)(:)(?=\s|$)/, '$1<span class="text-sky-700 dark:text-sky-400">$2</span>$3')
    .replace(/([{,]\s*)([A-Za-z0-9_\-.]+)(:)(?=\s)/g, '$1<span class="text-sky-700 dark:text-sky-400">$2</span>$3')
    .replace(/(:\s+)(-?\d+(?:\.\d+)?)(?=\s*(?:,|}|$))/g, '$1<span class="text-amber-700 dark:text-amber-400">$2</span>')
    .replace(/^(\s*)(-)(\s)/, '$1<span class="text-slate-400">$2</span>$3');
  if (comment) h += `<span class="text-slate-500 italic">${esc(comment)}</span>`;
  return h;
}

function Editor({ value, onChange, errorLines, readOnly, jump }: { value: string; onChange: (v: string) => void; errorLines: Set<number>; readOnly?: boolean; jump?: number }) {
  const ta = useRef<HTMLTextAreaElement>(null);
  const pre = useRef<HTMLPreElement>(null);
  const gutter = useRef<HTMLDivElement>(null);
  const lines = value.split("\n");
  useEffect(() => {
    if (!jump || !ta.current) return;
    const off = lines.slice(0, jump - 1).reduce((n, l) => n + l.length + 1, 0);
    ta.current.focus();
    ta.current.setSelectionRange(off, off + (lines[jump - 1]?.length || 0));
    ta.current.scrollTop = Math.max(0, (jump - 5) * 18);
  }, [jump]); // eslint-disable-line react-hooks/exhaustive-deps
  const sync = () => {
    if (!ta.current) return;
    if (pre.current) { pre.current.scrollTop = ta.current.scrollTop; pre.current.scrollLeft = ta.current.scrollLeft; }
    if (gutter.current) gutter.current.scrollTop = ta.current.scrollTop;
  };
  const common = "font-mono text-[12.5px] leading-[18px] p-2 whitespace-pre";
  return <div className="flex rounded-lg border border-line overflow-hidden bg-black/20 h-[32rem]">
    <div ref={gutter} aria-hidden className={`${common} select-none text-right text-slate-500 bg-white/5 overflow-hidden min-w-[3rem]`}>
      {lines.map((_, i) => <div key={i} className={errorLines.has(i + 1) ? "text-red-400 font-bold bg-red-500/20" : ""}>{i + 1}</div>)}</div>
    <div className="relative flex-1 min-w-0">
      <pre ref={pre} aria-hidden className={`${common} absolute inset-0 overflow-hidden pointer-events-none m-0`}
        dangerouslySetInnerHTML={{ __html: lines.map((l, i) => errorLines.has(i + 1) ? `<span class="bg-red-500/15">${highlight(l) || " "}</span>` : highlight(l)).join("\n") + "\n" }} />
      <textarea ref={ta} aria-label="Desired-state YAML" spellCheck={false} readOnly={readOnly} value={value} onScroll={sync}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => { if (e.key === "Tab" && !readOnly) { e.preventDefault(); const t = e.currentTarget, s = t.selectionStart;
          onChange(value.slice(0, s) + "  " + value.slice(t.selectionEnd)); requestAnimationFrame(() => t.setSelectionRange(s + 2, s + 2)); } }}
        className={`${common} absolute inset-0 w-full h-full resize-none bg-transparent text-transparent caret-sky-500 outline-none overflow-auto`} />
    </div>
  </div>;
}

export function Studio({ projectId, onPlan }: { projectId: number | null; onPlan: (planId: number) => void }) {
  const meta = useMeta().data;
  const draft = useQuery({ queryKey: ["iac-draft", projectId], queryFn: () => api<any>(`/iac/projects/${projectId}/draft`), enabled: !!projectId });
  const versions = useQuery({ queryKey: ["iac-versions", projectId], queryFn: () => api<any[]>(`/iac/projects/${projectId}/versions`), enabled: !!projectId });
  const devs = useQuery({ queryKey: ["iac-devices", projectId, "studio"], queryFn: () => api<any>("/iac/devices", { params: { project_id: projectId!, size: 200 } }), enabled: !!projectId });
  const [text, setText] = useState("");
  const [dirty, setDirty] = useState(false);
  const [report, setReport] = useState<any>(null);
  const [jump, setJump] = useState<number>();
  const [panel, setPanel] = useState<"problems" | "diff" | "versions" | "refs">("problems");
  const [commitOpen, setCommitOpen] = useState(false);
  const [msg, setMsg] = useState("");
  const [importOpen, setImportOpen] = useState(false);
  const [viewVer, setViewVer] = useState<any>(null);
  const [planFor, setPlanFor] = useState<any>(null);
  useEffect(() => { if (draft.data && !dirty) setText(draft.data.content); }, [draft.data]); // eslint-disable-line react-hooks/exhaustive-deps
  const validate = useAct(() => api(`/iac/projects/${projectId}/validate`, { method: "POST", body: { content: text } }), (r) => { setReport(r); setPanel("problems"); });
  const save = useAct(() => api(`/iac/projects/${projectId}/draft`, { method: "PUT", body: { content: text } }), () => setDirty(false));
  const commit = useAct(() => api<any>(`/iac/projects/${projectId}/versions`, { method: "POST", body: { content: text, message: msg } }),
    (r) => { setCommitOpen(false); setMsg(""); setDirty(false); setReport(r.validation); setPanel(r.valid ? "versions" : "problems"); });
  const plan = useAct((a: any) => api<any>(`/iac/projects/${projectId}/plans`, { method: "POST", body: a }), (r) => { setPlanFor(null); onPlan(r.id); });
  const errorLines = useMemo(() => new Set<number>((report?.errors || []).map((e: any) => e.line).filter(Boolean)), [report]);
  const editor = can(meta, "editor");
  if (!projectId) return <Empty text="Select or create a project to edit its desired configuration." />;
  return <div className="grid gap-4 2xl:grid-cols-[3fr_2fr] min-w-0">
    <Card title={<>Desired state (YAML){dirty && <span className="text-amber-300 text-xs ml-2">unsaved</span>}</>} right={<>
      <button className="btn py-1" disabled={!editor} title={editor ? "" : "IaC editor role required"} onClick={() => { setText(meta?.example || text); setDirty(true); }}>Insert example</button>
      <button className="btn py-1" disabled={!editor} onClick={() => setImportOpen(true)}>Import from device</button>
      <a className="btn py-1" href={downloadUrl(`/iac/projects/${projectId}/export`)}>Export</a>
      <button className="btn py-1" onClick={() => validate.mutate(undefined)} disabled={validate.isPending}>{validate.isPending ? "Validating…" : "Validate"}</button>
      <button className="btn py-1" disabled={!editor || !dirty || save.isPending} onClick={() => save.mutate(undefined)}>Save draft</button>
      <button className="btn btn-primary py-1" disabled={!editor} onClick={() => setCommitOpen(true)}>Commit version</button></>}>
      <Loading q={draft} />
      <ErrorBox error={validate.error || save.error} />
      <Editor value={text} onChange={(v) => { setText(v); setDirty(true); }} errorLines={errorLines} readOnly={!editor} jump={jump} />
      <p className="text-2xs text-muted mt-2">Variables: <span className="font-mono">${"{name}"}</span> (project → site → device). Types: {meta?.capabilities?.filter((c: any) => c.support === "managed").map((c: any) => c.type).join(", ")}.
        {draft.data?.updated_by && <> Draft saved by {draft.data.updated_by} <Time v={draft.data.updated_at} />.</>}</p>
    </Card>
    <div className="space-y-4 min-w-0">
      <div className="flex gap-1 flex-wrap">{(["problems", "refs", "diff", "versions"] as const).map((p) =>
        <button key={p} className={`btn py-1 ${panel === p ? "border-brand-500 text-brand-400" : ""}`} onClick={() => setPanel(p)}>
          {{ problems: `Problems${report ? ` (${(report.errors?.length || 0) + (report.findings?.length || 0)})` : ""}`, refs: "References", diff: "Diff vs approved", versions: "History" }[p]}</button>)}</div>
      {panel === "problems" && <Card title="Validation">
        {!report ? <Note>Run Validate (or commit) to check schema, references, variables and security rules. Nothing is sent to any device.</Note> : <>
          <div className="text-sm mb-2">{report.valid ? <span className="text-emerald-300">Schema valid</span> : <span className="text-red-300">Schema invalid</span>}
            {report.counts && <span className="text-muted text-xs ml-2">{Object.entries(report.counts).map(([k, v]) => `${v} ${k}`).join(" · ")}</span>}</div>
          {report.errors?.length > 0 && <ul className="text-xs space-y-1 mb-3">{report.errors.map((e: any, i: number) =>
            <li key={i}><button className="text-left hover:underline text-red-300" onClick={() => e.line && setJump(e.line)}>{e.line ? `line ${e.line}: ` : ""}{e.message}</button></li>)}</ul>}
          {report.findings?.length > 0 ? <ul className="text-xs space-y-2">{report.findings.map((f: any, i: number) => <li key={i} className="border-l-2 border-line pl-2">
            <div className="flex gap-2 items-center flex-wrap"><SevBadge s={f.severity} /><span className="font-mono">{f.rule_id}</span><span className="font-mono text-muted">{f.resource}</span>
              {f.blocks && <span className="text-red-300 font-semibold">blocks deployment</span>}{f.exception && <span className="text-sky-300">exception: {f.exception.owner}</span>}</div>
            <div>{f.explanation}</div><div className="text-muted">Fix: {f.remediation}</div></li>)}</ul> : report.valid && <Note>No security findings in the declared configuration.</Note>}
        </>}
      </Card>}
      {panel === "refs" && <Card title="References and dependencies">
        {!report?.references ? <Note>Validate a valid document to see which policies use each object.</Note> :
          <div className="text-xs space-y-3"><div><b>Addresses used by policies</b><ul>{Object.entries(report.references.address_used_by_policies).map(([a, ps]: any) => <li key={a}><span className="font-mono">{a}</span> → {ps.join(", ")}</li>)}</ul></div>
            <div><b>Services used by policies</b><ul>{Object.entries(report.references.service_used_by_policies).map(([a, ps]: any) => <li key={a}><span className="font-mono">{a}</span> → {ps.join(", ")}</li>)}</ul></div>
            <div><b>Groups</b><ul>{Object.entries(report.references.groups).map(([g, m]: any) => <li key={g}><span className="font-mono">{g}</span> = {m.join(", ")}</li>)}</ul></div></div>}
      </Card>}
      {panel === "diff" && <Card title={`Draft vs approved version${draft.data?.approved ? ` ${draft.data.approved.number}` : ""}`}>
        {draft.data?.approved ? <LineDiff a={draft.data.approved.content} b={text} /> : <Note>No approved version yet: a version becomes approved when one of its plans is approved.</Note>}
      </Card>}
      {panel === "versions" && <Card title="Version history" bodyClass="p-0">
        <Loading q={versions} />
        {versions.data?.length ? <TableWrap maxH="max-h-[30rem]"><table className="tbl"><thead><tr><th>#</th><th>Author</th><th className="w-full">Message</th><th>When</th><th>Status</th><th /></tr></thead>
          <tbody>{versions.data.map((v: any) => <tr key={v.id}><td className="font-mono">v{v.number}</td><td className="text-xs">{v.author}</td><td className="text-xs">{v.message}</td><td><Time v={v.created_at} /></td>
            <td className="text-xs whitespace-nowrap">{v.approved ? <span className="text-emerald-300">approved</span> : v.valid ? <span className="text-sky-300">valid</span> : <span className="text-red-300">invalid</span>}
              {v.findings ? <span className="text-muted"> · {v.findings} finding(s)</span> : ""}</td>
            <td className="whitespace-nowrap"><button className="btn py-0.5 text-xs" onClick={() => setViewVer(v)}>View</button>
              {v.valid && <button className="btn btn-primary py-0.5 text-xs ml-1" disabled={!editor} onClick={() => setPlanFor(v)}>Plan</button>}</td></tr>)}</tbody></table></TableWrap>
          : <Empty text="No committed versions yet." />}
      </Card>}
    </div>
    {commitOpen && <Confirm title="Commit a new version" confirmLabel="Commit" busy={commit.isPending} disabled={!msg.trim()} onClose={() => setCommitOpen(false)} onConfirm={() => commit.mutate(undefined)}>
      <p className="text-muted text-xs">Versions are immutable and identified by their SHA-256. Committing does not change any device.</p>
      <textarea aria-label="Commit message" className="input w-full h-20" placeholder="What changed and why (change ticket)…" value={msg} onChange={(e) => setMsg(e.target.value)} />
      <ErrorBox error={commit.error} /></Confirm>}
    {importOpen && <ImportDialog projectId={projectId} devices={devs.data?.items || []} onClose={() => setImportOpen(false)}
      onImported={(c) => { setText(c); setDirty(true); setImportOpen(false); }} />}
    {viewVer && <VersionView id={viewVer.id} current={text} onClose={() => setViewVer(null)} />}
    {planFor && <PlanDialog version={planFor} devices={devs.data?.items || []} busy={plan.isPending} error={plan.error} onClose={() => setPlanFor(null)}
      onPlan={(ids) => plan.mutate({ version_id: planFor.id, firewall_ids: ids })} />}
  </div>;
}

function ImportDialog({ projectId, devices, onClose, onImported }: { projectId: number; devices: any[]; onClose: () => void; onImported: (c: string) => void }) {
  const [fw, setFw] = useState<number | "">(devices[0]?.firewall_id ?? "");
  const TYPES = ["address", "address_group", "service", "service_group", "policy", "static_route", "system_global", "syslog"];
  const [types, setTypes] = useState<string[]>(TYPES.slice(0, 6));
  const imp = useAct(() => api<any>(`/iac/projects/${projectId}/import`, { method: "POST", body: { firewall_id: fw, types } }));
  return <Confirm title="Import from a managed firewall" confirmLabel={imp.data ? "Replace editor content" : "Read device"} busy={imp.isPending} disabled={!fw || !types.length}
    onClose={onClose} onConfirm={() => imp.data ? onImported(imp.data.content) : imp.mutate(undefined)}>
    <p className="text-xs text-muted">Reads the selected tables with GET requests only and converts them to desired-state YAML. Review before committing: undeclared defaults and unsupported resources are not imported.</p>
    <select aria-label="Device" className="input w-full" value={fw} onChange={(e) => setFw(Number(e.target.value))}>
      {devices.map((d) => <option key={d.firewall_id} value={d.firewall_id}>{d.name}</option>)}</select>
    {!devices.length && <Note tone="warn">Add a device to this project first (Devices tab).</Note>}
    <div className="flex flex-wrap gap-3 text-xs">{TYPES.map((t) => <label key={t} className="flex items-center gap-1"><input type="checkbox" checked={types.includes(t)}
      onChange={(e) => setTypes(e.target.checked ? [...types, t] : types.filter((x) => x !== t))} />{t}</label>)}</div>
    {imp.data && <><div className="text-xs">{Object.entries(imp.data.counts).map(([k, v]) => `${v} ${k}`).join(" · ")}</div>
      {Object.keys(imp.data.unreadable || {}).length > 0 && <Note tone="warn">Not readable: {Object.entries(imp.data.unreadable).map(([k, v]) => `${k} (${v})`).join(", ")}</Note>}
      {imp.data.skipped?.length > 0 && <Note tone="warn">
        <div>{imp.data.skipped.length} object(s) skipped because the IaC format cannot represent them. They are listed in <code>manage.ignore</code>, so plans leave them unchanged and drift checks ignore them.</div>
        <ul className="mt-1 max-h-32 overflow-auto font-mono">{imp.data.skipped.map((x: any) => <li key={`${x.type}:${x.key}`}>{x.type} {x.key}: {x.reason}</li>)}</ul>
      </Note>}
      <pre className="text-xs max-h-60 overflow-auto rounded border border-line p-2">{imp.data.content.slice(0, 4000)}</pre></>}
    <ErrorBox error={imp.error} />
  </Confirm>;
}

function VersionView({ id, current, onClose }: { id: number; current: string; onClose: () => void }) {
  const q = useQuery({ queryKey: ["iac-version", id], queryFn: () => api<any>(`/iac/versions/${id}`) });
  const [mode, setMode] = useState<"content" | "diff">("content");
  const v = q.data;
  return <Confirm title={v ? `Version ${v.number} · ${v.hash.slice(0, 12)}` : "Version"} confirmLabel="Close" onConfirm={onClose} onClose={onClose}>
    <Loading q={q} />
    {v && <><div className="text-xs text-muted">{v.author} · <Time v={v.created_at} /> · {v.message}</div>
      <div className="flex gap-1"><button className={`btn py-0.5 text-xs ${mode === "content" ? "border-brand-500" : ""}`} onClick={() => setMode("content")}>Content</button>
        <button className={`btn py-0.5 text-xs ${mode === "diff" ? "border-brand-500" : ""}`} onClick={() => setMode("diff")}>Diff vs editor</button></div>
      {mode === "content" ? <pre className="text-xs max-h-96 overflow-auto rounded border border-line p-2">{v.content}</pre> : <LineDiff a={v.content} b={current} />}
      {v.validation?.errors?.length > 0 && <Note tone="bad">{v.validation.errors.map((e: any) => e.message).join("; ")}</Note>}</>}
  </Confirm>;
}

function PlanDialog({ version, devices, busy, error, onClose, onPlan }: { version: any; devices: any[]; busy: boolean; error: unknown; onClose: () => void; onPlan: (ids: number[]) => void }) {
  const managed = devices.filter((d) => d.managed);
  const [sel, setSel] = useState<number[]>(managed.map((d) => d.firewall_id));
  return <Confirm title={`Plan version ${version.number}`} confirmLabel="Generate plan" busy={busy} disabled={!sel.length} onClose={onClose} onConfirm={() => onPlan(sel)}>
    <p className="text-xs text-muted">The plan reads each selected device (GET only), renders the configuration with its variables, and lists every create / update / delete / move with risk and validation results. Generating a plan changes nothing.</p>
    {managed.length ? <div className="space-y-1 text-sm">{managed.map((d) => <label key={d.firewall_id} className="flex gap-2 items-center"><input type="checkbox" checked={sel.includes(d.firewall_id)}
      onChange={(e) => setSel(e.target.checked ? [...sel, d.firewall_id] : sel.filter((x) => x !== d.firewall_id))} />{d.name}<span className="text-muted text-xs">{d.site}</span></label>)}</div>
      : <Note tone="warn">No managed devices in this project.</Note>}
    <ErrorBox error={error} />
  </Confirm>;
}

