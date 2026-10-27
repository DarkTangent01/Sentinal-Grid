import { KeyboardEvent, useEffect, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api, qs } from "../lib/api";
import { useGlobal, useMe } from "../lib/context";
import { fmtNum } from "../lib/format";
import { exportSearchCsv, PIPE_EXAMPLES, PIPE_HELP, runSearch, searchBody } from "../lib/search";
import { Card, Collapsible, Modal } from "../components/ui";
import { PipelineResult, ResultTable, ResultView, Viz, VIZ_OPTIONS, autoViz } from "../components/ResultView";

const HIST = "siem.search.history";
function history(): string[] { try { return JSON.parse(localStorage.getItem(HIST) || "[]"); } catch { return []; } }
function remember(q: string) {
  try { localStorage.setItem(HIST, JSON.stringify([q, ...history().filter((x) => x !== q)].slice(0, 12))); } catch { /* ignore */ }
}

export function Search() {
  const [sp, setSp] = useSearchParams();
  const g = useGlobal();
  const me = useMe();
  const nav = useNavigate();
  const [q, setQ] = useState(sp.get("q") || "");
  const [viz, setViz] = useState<Viz>((sp.get("viz") as Viz) || "auto");
  const [res, setRes] = useState<PipelineResult | null>(null);
  const [ran, setRan] = useState<{ query: string; body: Record<string, unknown> } | null>(null);
  const [modal, setModal] = useState<"" | "bookmark" | "workbook">("");
  const [hist, setHist] = useState(history);
  const ta = useRef<HTMLTextAreaElement>(null);
  const m = useMutation({
    mutationFn: (body: Record<string, unknown>) => runSearch(body),
    onSuccess: (r, body) => { setRes(r); setRan({ query: String(body.query), body }); },
  });
  const run = (query = q) => {
    const body = searchBody(g.params, query);
    if (query.trim()) { remember(query.trim()); setHist(history()); }
    setSp(query ? { q: query, ...(viz !== "auto" ? { viz } : {}) } : {}, { replace: true });
    m.mutate(body);
  };
  // run a query passed in the URL (from hunting, workbooks, detections) once
  const started = useRef(false);
  useEffect(() => { if (!started.current && sp.get("q")) { started.current = true; run(sp.get("q") || ""); } }, []);
  const onKey = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) { e.preventDefault(); run(); }
  };
  const effective = res ? (viz === "auto" ? autoViz(res) : viz) : "table";
  const [exportErr, setExportErr] = useState("");

  return (
    <div className="space-y-4 min-w-0">
      <AskAI onQuery={(query, v) => { setQ(query); if (v && v !== "auto") setViz(v as Viz); run(query); }} />
      <Card title="Search" right={<span className="text-2xs text-muted">Pipeline query language · Ctrl/⌘ + Enter to run · uses the time range and firewall selected above</span>}>
        <label htmlFor="pipeline-q" className="sr-only">Query</label>
        <textarea id="pipeline-q" ref={ta} className="input w-full font-mono text-[13px] leading-relaxed min-h-[5.5rem]" spellCheck={false} value={q}
          onChange={(e) => setQ(e.target.value)} onKeyDown={onKey}
          placeholder={'action:deny | stats count, dc(dst_port) as ports by src_ip | where ports > 20 | sort -count'} />
        <div className="flex flex-wrap items-center gap-2 mt-2">
          <button className="btn btn-primary" disabled={m.isPending} onClick={() => run()}>{m.isPending ? "Running…" : "Run"}</button>
          <select aria-label="Visualisation" className="input py-1" value={viz} onChange={(e) => setViz(e.target.value as Viz)}>
            {VIZ_OPTIONS.map((v) => <option key={v} value={v}>{v === "auto" ? "Visualisation: auto" : v}</option>)}
          </select>
          {hist.length > 0 && <select aria-label="Recent queries" className="input py-1 max-w-[16rem]" value="" onChange={(e) => { if (e.target.value) { setQ(e.target.value); ta.current?.focus(); } }}>
            <option value="">Recent queries…</option>{hist.map((h) => <option key={h} value={h}>{h.length > 90 ? h.slice(0, 90) + "…" : h}</option>)}
          </select>}
          <span className="flex-1" />
          {ran && <>
            <button className="btn" onClick={() => setModal("bookmark")}>Bookmark</button>
            <button className="btn" onClick={() => setModal("workbook")}>Add to workbook</button>
            {me.role === "admin" && <button className="btn" onClick={() => nav(`/detections${qs({ new: ran.query })}`)}>Create detection</button>}
            <button className="btn" onClick={() => { setExportErr(""); exportSearchCsv({ ...ran.body, max_rows: 10000 }).catch((e) => setExportErr(e.message)); }}>Export CSV</button>
          </>}
        </div>
        {(m.error || exportErr) && <div role="alert" className="text-sm text-red-400 mt-2 font-mono whitespace-pre-wrap">{exportErr || (m.error as Error).message}</div>}
        <div className="mt-3 grid gap-2 md:grid-cols-2">
          <Collapsible title="Command reference">
            <dl className="text-xs space-y-1.5">{PIPE_HELP.map(([k, v]) => <div key={k}><dt className="font-mono text-slate-200">{k}</dt><dd className="text-muted">{v}</dd></div>)}</dl>
          </Collapsible>
          <Collapsible title="Examples">
            <ul className="text-xs space-y-1.5">{PIPE_EXAMPLES.map(([t, x]) => <li key={t}><button className="link" onClick={() => { setQ(x); ta.current?.focus(); }}>{t}</button>
              <div className="font-mono text-muted cell-wrap">{x}</div></li>)}</ul>
          </Collapsible>
        </div>
      </Card>

      {res && <Card title={<span>{fmtNum(res.rows.length)} result{res.rows.length === 1 ? "" : "s"} <span className="text-muted font-normal text-xs">· {res.elapsed_ms} ms · {res.kind}</span></span>}
        right={res.truncated ? <span className="pill bg-amber-500/15 text-amber-300">Truncated — add | head N or aggregate with stats</span> : undefined}>
        <ResultView r={res} viz={viz} height={320} maxH="max-h-[60vh]" />
        {effective !== "table" && res.rows.length > 0 && <div className="mt-4"><Collapsible title="Data table"><ResultTable r={res} maxH="max-h-96" /></Collapsible></div>}
      </Card>}

      {modal === "bookmark" && ran && res && <BookmarkModal query={ran.query} res={res} onClose={() => setModal("")} />}
      {modal === "workbook" && ran && <AddToWorkbook query={ran.query} viz={viz} onClose={() => setModal("")} />}
    </div>
  );
}

export function BookmarkModal({ query, res, onClose }: { query: string; res: PipelineResult; onClose: () => void }) {
  const [f, setF] = useState({ name: "", notes: "", incident_id: "" });
  const m = useMutation({
    mutationFn: () => api("/bookmarks", { method: "POST", body: {
      name: f.name, query, notes: f.notes, columns: res.columns.slice(0, 100), rows: res.rows.slice(0, 100),
      window_start: res.window?.start, window_end: res.window?.end, incident_id: f.incident_id ? Number(f.incident_id) : null } }),
    onSuccess: onClose,
  });
  return (
    <Modal title="Bookmark results" onClose={onClose}>
      <p className="text-xs text-muted mb-2">Saves the query, time window and the first {Math.min(100, res.rows.length)} rows as evidence. Attaching to an incident adds it to the case evidence.</p>
      <div className="grid gap-2">
        <div><label className="label">Name</label><input className="input w-full" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></div>
        <div><label className="label">Notes</label><textarea className="input w-full h-20" value={f.notes} onChange={(e) => setF({ ...f, notes: e.target.value })} /></div>
        <div><label className="label">Attach to incident # (optional)</label><input className="input w-40" inputMode="numeric" value={f.incident_id} onChange={(e) => setF({ ...f, incident_id: e.target.value.replace(/\D/g, "") })} /></div>
      </div>
      {m.error && <div role="alert" className="text-sm text-red-400 mt-2">{(m.error as Error).message}</div>}
      <button className="btn btn-primary mt-3" disabled={!f.name || m.isPending} onClick={() => m.mutate()}>Save bookmark</button>
    </Modal>
  );
}

function AddToWorkbook({ query, viz, onClose }: { query: string; viz: Viz; onClose: () => void }) {
  const books = useQuery({ queryKey: ["workbooks"], queryFn: () => api<any[]>("/workbooks") });
  const editable = (books.data || []).filter((b) => b.can_edit);
  const [f, setF] = useState<{ id: string; title: string; viz: Viz; width: number }>({ id: "", title: "", viz: viz === "auto" ? "table" : viz, width: 6 });
  const nav = useNavigate();
  const m = useMutation({
    mutationFn: async () => {
      const panel = { id: `p${Date.now().toString(36)}`, title: f.title, query, viz: f.viz, width: Number(f.width) };
      if (f.id === "new") return api<any>("/workbooks", { method: "POST", body: { name: f.title, panels: [panel], shared: true } });
      const b = await api<any>(`/workbooks/${f.id}`);
      return api<any>(`/workbooks/${f.id}`, { method: "PUT", body: { name: b.name, description: b.description, range: b.range, shared: b.shared, panels: [...b.panels, panel] } });
    },
    onSuccess: (b) => { onClose(); nav(`/workbooks/${b.id}`); },
  });
  return (
    <Modal title="Add to workbook" onClose={onClose}>
      <div className="grid gap-2 sm:grid-cols-2">
        <div className="sm:col-span-2"><label className="label">Workbook</label>
          <select className="input w-full" value={f.id} onChange={(e) => setF({ ...f, id: e.target.value })}>
            <option value="">Choose…</option><option value="new">+ New workbook (named after the panel)</option>
            {editable.map((b) => <option key={b.id} value={b.id}>{b.name}</option>)}
          </select></div>
        <div className="sm:col-span-2"><label className="label">Panel title</label><input className="input w-full" value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} /></div>
        <div><label className="label">Visualisation</label><select className="input w-full" value={f.viz} onChange={(e) => setF({ ...f, viz: e.target.value as Viz })}>
          {VIZ_OPTIONS.filter((v) => v !== "auto").map((v) => <option key={v}>{v}</option>)}</select></div>
        <div><label className="label">Width (of 12)</label><select className="input w-full" value={f.width} onChange={(e) => setF({ ...f, width: Number(e.target.value) })}>
          {[3, 4, 6, 8, 12].map((w) => <option key={w} value={w}>{w}</option>)}</select></div>
      </div>
      {m.error && <div role="alert" className="text-sm text-red-400 mt-2">{(m.error as Error).message}</div>}
      <button className="btn btn-primary mt-3" disabled={!f.id || !f.title || m.isPending} onClick={() => m.mutate()}>Add panel</button>
    </Modal>
  );
}

function AskAI({ onQuery }: { onQuery: (q: string, viz?: string) => void }) {
  const st = useQuery({ queryKey: ["ai-status"], queryFn: () => api<any>("/ai/status"), staleTime: 300_000 });
  const [question, setQuestion] = useState("");
  const m = useMutation({ mutationFn: () => api<any>("/ai/query", { method: "POST", body: { question } }), onSuccess: (r) => onQuery(r.query, r.visualisation) });
  if (!st.data?.enabled) return null;
  return (
    <Card>
      <form className="flex flex-wrap gap-2 items-center" onSubmit={(e) => { e.preventDefault(); if (question.trim()) m.mutate(); }}>
        <span className="text-sm font-semibold text-brand-400">Ask</span>
        <input aria-label="Ask in plain English" className="input flex-1 min-w-[16rem]" value={question} onChange={(e) => setQuestion(e.target.value)}
          placeholder="e.g. which internal hosts sent the most data to other countries today?" />
        <button className="btn btn-primary" disabled={!question.trim() || m.isPending}>{m.isPending ? "Thinking…" : "Write the query"}</button>
      </form>
      {m.data && <p className="text-xs text-muted mt-2">{m.data.explanation} <span className="text-2xs">({m.data.model}; review the query before relying on it)</span></p>}
      {m.error && <div role="alert" className="text-sm text-red-400 mt-2">{(m.error as Error).message}</div>}
      <p className="text-2xs text-muted mt-1">Only your question and the field list are sent to the AI service — no log data.</p>
    </Card>
  );
}
