import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, qs } from "../lib/api";
import { useMe } from "../lib/context";
import { fmtNum } from "../lib/format";
import { Card, Empty, Loading, Modal, TableWrap, Tabs, Time } from "../components/ui";
import { ResultTable } from "../components/ResultView";

interface Hunt { id: number; key?: string; name: string; description: string; query: string; range: string; tactic: string; tactic_name: string;
  techniques: string[]; builtin: boolean; author: string; last_run?: string; last_count?: number | null; last_error?: string | null }
const RANGES = ["1h", "24h", "7d", "30d"];

export function Hunting() {
  const [sp] = useSearchParams();
  const [tab, setTab] = useState(sp.get("tab") === "bookmarks" ? "bookmarks" : "library");
  return (
    <div className="space-y-3 min-w-0">
      <Tabs value={tab} onChange={setTab} tabs={[{ key: "library", label: "Hunting queries" }, { key: "bookmarks", label: "Bookmarks" }]} />
      {tab === "library" ? <Library /> : <Bookmarks />}
    </div>
  );
}

function Library() {
  const me = useMe();
  const nav = useNavigate();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["hunts"], queryFn: () => api<Hunt[]>("/hunting") });
  const [range, setRange] = useState("");
  const [tactic, setTactic] = useState("");
  const [edit, setEdit] = useState<Partial<Hunt> | null>(null);
  const [running, setRunning] = useState<Set<number>>(new Set());
  const refresh = () => qc.invalidateQueries({ queryKey: ["hunts"] });
  const runAll = useMutation({ mutationFn: () => api<any[]>("/hunting/run-all", { method: "POST", params: { range: range || undefined } }), onSuccess: refresh });
  const runOne = async (h: Hunt) => {
    setRunning((s) => new Set(s).add(h.id));
    try { await api(`/hunting/${h.id}/run`, { method: "POST", params: { range: range || undefined } }); } finally {
      setRunning((s) => { const n = new Set(s); n.delete(h.id); return n; });
      refresh();
    }
  };
  const del = useMutation({ mutationFn: (id: number) => api(`/hunting/${id}`, { method: "DELETE" }), onSuccess: refresh });
  const tactics = Array.from(new Map((q.data || []).filter((h) => h.tactic).map((h) => [h.tactic, h.tactic_name])).entries());
  const rows = (q.data || []).filter((h) => !tactic || h.tactic === tactic);
  const hits = (q.data || []).filter((h) => (h.last_count || 0) > 0).length;
  return (
    <>
      <p className="text-xs text-muted">Proactive hunts mapped to MITRE ATT&CK. Run them to find activity that no detection alerted on; a non-zero result is a lead, not a verdict.
        Open a hunt in Search to pivot, then bookmark rows as evidence or turn the query into a detection.</p>
      <Card title={`Library${hits ? ` · ${hits} with results` : ""}`} right={<>
        <select aria-label="Filter by tactic" className="input py-1" value={tactic} onChange={(e) => setTactic(e.target.value)}>
          <option value="">All tactics</option>{tactics.map(([id, n]) => <option key={id} value={id}>{id} {n}</option>)}</select>
        <select aria-label="Hunt time range" className="input py-1" value={range} onChange={(e) => setRange(e.target.value)}>
          <option value="">Each hunt's range</option>{RANGES.map((r) => <option key={r} value={r}>Last {r}</option>)}</select>
        <button className="btn btn-primary" disabled={runAll.isPending} onClick={() => runAll.mutate()}>{runAll.isPending ? "Running all…" : "Run all"}</button>
        <button className="btn" onClick={() => setEdit({ name: "", description: "", query: "", range: "24h", tactic: "", techniques: [] })}>+ New hunt</button>
      </>}>
        <Loading q={q} />
        {runAll.error && <div role="alert" className="text-sm text-red-400 mb-2">{(runAll.error as Error).message}</div>}
        {q.data && !rows.length && <Empty text="No hunting queries." />}
        {!!rows.length && <TableWrap><table className="tbl">
          <thead><tr><th>Tactic</th><th className="w-full">Hunt</th><th>Techniques</th><th>Range</th><th>Last run</th><th className="num">Results</th><th /></tr></thead>
          <tbody>{rows.map((h) => <tr key={h.id}>
            <td className="text-xs nowrap" title={h.tactic_name}>{h.tactic ? <><span className="font-mono">{h.tactic}</span><div className="text-muted">{h.tactic_name}</div></> : "—"}</td>
            <td className="min-w-[16rem]"><div className="font-medium">{h.name}{!h.builtin && <span className="pill bg-slate-800 text-slate-400 ml-1">custom · {h.author}</span>}</div>
              <div className="text-xs text-muted">{h.description}</div>
              <div className="font-mono text-2xs text-muted mt-0.5 cell-wrap">{h.query}</div></td>
            <td className="text-xs font-mono">{h.techniques.join(", ") || "—"}</td>
            <td className="text-xs">{range || h.range}</td>
            <td><Time v={h.last_run} /></td>
            <td className="num">{running.has(h.id) ? <span className="text-muted animate-pulse">…</span> : h.last_error ? <span className="text-red-300" title={h.last_error}>error</span>
              : h.last_count == null ? "—" : <span className={h.last_count > 0 ? "pill bg-red-500/15 text-red-300" : "text-muted"}>{fmtNum(h.last_count)}</span>}</td>
            <td className="nowrap"><button className="btn" disabled={running.has(h.id)} onClick={() => runOne(h)}>Run</button>
              <button className="btn ml-1" onClick={() => nav(`/search${qs({ q: h.query })}`)}>Open</button>
              {!h.builtin && (h.author === me.username || me.role === "admin") && <>
                <button className="btn ml-1" onClick={() => setEdit(h)}>Edit</button>
                <button className="btn btn-danger ml-1" onClick={() => confirm(`Delete hunt "${h.name}"?`) && del.mutate(h.id)}>Delete</button></>}
              {h.builtin && <button className="btn ml-1" title="Copy into a custom hunt you can edit" onClick={() => setEdit({ ...h, id: undefined, name: `${h.name} (copy)` })}>Copy</button>}</td>
          </tr>)}</tbody></table></TableWrap>}
      </Card>
      {edit && <HuntEditor h={edit} onClose={() => { setEdit(null); refresh(); }} />}
    </>
  );
}

function HuntEditor({ h, onClose }: { h: Partial<Hunt>; onClose: () => void }) {
  const [f, setF] = useState({ name: h.name || "", description: h.description || "", query: h.query || "", range: h.range || "24h", tactic: h.tactic || "", techniques: (h.techniques || []).join(", ") });
  const tactics = useQuery({ queryKey: ["mitre-tactics"], queryFn: () => api<{ id: string; name: string }[]>("/mitre/tactics"), staleTime: Infinity });
  const m = useMutation({
    mutationFn: () => api(h.id ? `/hunting/${h.id}` : "/hunting", { method: h.id ? "PUT" : "POST",
      body: { ...f, techniques: f.techniques.split(",").map((x) => x.trim()).filter(Boolean) } }),
    onSuccess: onClose,
  });
  return (
    <Modal title={h.id ? `Edit hunt: ${h.name}` : "New hunt"} onClose={onClose}>
      <div className="grid gap-2 sm:grid-cols-3">
        <div className="sm:col-span-3"><label className="label">Name</label><input className="input w-full" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></div>
        <div className="sm:col-span-3"><label className="label">Description</label><input className="input w-full" value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></div>
        <div className="sm:col-span-3"><label className="label">Query</label><textarea className="input w-full font-mono text-[13px] min-h-[5rem]" spellCheck={false} value={f.query} onChange={(e) => setF({ ...f, query: e.target.value })} /></div>
        <div><label className="label">Default range</label><select className="input w-full" value={f.range} onChange={(e) => setF({ ...f, range: e.target.value })}>{RANGES.map((r) => <option key={r}>{r}</option>)}</select></div>
        <div><label className="label">Tactic</label><select className="input w-full" value={f.tactic} onChange={(e) => setF({ ...f, tactic: e.target.value })}>
          <option value="">—</option>{(tactics.data || []).map((t) => <option key={t.id} value={t.id}>{t.id} {t.name}</option>)}</select></div>
        <div><label className="label">Techniques</label><input className="input w-full font-mono" value={f.techniques} onChange={(e) => setF({ ...f, techniques: e.target.value })} placeholder="T1071.004" /></div>
      </div>
      {m.error && <div role="alert" className="text-sm text-red-400 mt-2 font-mono">{(m.error as Error).message}</div>}
      <button className="btn btn-primary mt-3" disabled={!f.name || !f.query || m.isPending} onClick={() => m.mutate()}>Save</button>
    </Modal>
  );
}

function Bookmarks() {
  const nav = useNavigate();
  const qc = useQueryClient();
  const me = useMe();
  const q = useQuery({ queryKey: ["bookmarks"], queryFn: () => api<any[]>("/bookmarks") });
  const [view, setView] = useState<any>(null);
  const del = useMutation({ mutationFn: (id: number) => api(`/bookmarks/${id}`, { method: "DELETE" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["bookmarks"] }) });
  return (
    <Card title="Bookmarks">
      <Loading q={q} />
      {q.data && !q.data.length && <Empty text="No bookmarks. Run a search or hunt and click Bookmark to keep the rows as evidence." />}
      {!!q.data?.length && <TableWrap><table className="tbl"><thead><tr><th>Name</th><th className="w-full">Query</th><th className="num">Rows</th><th>Incident</th><th>By</th><th>Created</th><th /></tr></thead>
        <tbody>{q.data.map((b) => <tr key={b.id}>
          <td className="min-w-[10rem]">{b.name}{b.notes && <div className="text-2xs text-muted line-clamp-2">{b.notes}</div>}</td>
          <td className="font-mono text-xs cell-wrap">{b.query || "(all events)"}</td><td className="num">{fmtNum(b.rows.length)}</td>
          <td>{b.incident_id ? <button className="link" onClick={() => nav(`/incidents/${b.incident_id}`)}>#{b.incident_id}</button> : "—"}</td>
          <td className="text-xs">{b.created_by}</td><td><Time v={b.created_at} /></td>
          <td className="nowrap"><button className="btn" onClick={() => setView(b)}>View</button>
            <button className="btn ml-1" onClick={() => nav(`/search${qs({ q: b.query })}`)}>Re-run</button>
            {(b.created_by === me.username || me.role === "admin") && <button className="btn btn-danger ml-1" onClick={() => confirm(`Delete bookmark "${b.name}"?`) && del.mutate(b.id)}>Delete</button>}</td>
        </tr>)}</tbody></table></TableWrap>}
      {view && <BookmarkView b={view} onClose={() => { setView(null); qc.invalidateQueries({ queryKey: ["bookmarks"] }); }} />}
    </Card>
  );
}

function BookmarkView({ b, onClose }: { b: any; onClose: () => void }) {
  const [notes, setNotes] = useState(b.notes || "");
  const [inc, setInc] = useState(b.incident_id ? String(b.incident_id) : "");
  const m = useMutation({ mutationFn: () => api(`/bookmarks/${b.id}`, { method: "PATCH", body: { notes, incident_id: inc ? Number(inc) : null } }), onSuccess: onClose });
  return (
    <Modal title={`Bookmark: ${b.name}`} onClose={onClose} wide>
      <div className="text-xs text-muted mb-2">Window <Time v={b.window_start} /> → <Time v={b.window_end} /> · by {b.created_by}</div>
      <div className="font-mono text-xs mb-3 cell-wrap">{b.query}</div>
      <ResultTable r={{ kind: "table", columns: b.columns, rows: b.rows, elapsed_ms: 0, truncated: false }} maxH="max-h-80" />
      <div className="grid gap-2 sm:grid-cols-[1fr_12rem] mt-3">
        <div><label className="label">Notes</label><textarea className="input w-full h-20" value={notes} onChange={(e) => setNotes(e.target.value)} /></div>
        <div><label className="label">Attach to incident #</label><input className="input w-full" inputMode="numeric" value={inc} onChange={(e) => setInc(e.target.value.replace(/\D/g, ""))} /></div>
      </div>
      {m.error && <div role="alert" className="text-sm text-red-400 mt-2">{(m.error as Error).message}</div>}
      <button className="btn btn-primary mt-3" disabled={m.isPending} onClick={() => m.mutate()}>Save</button>
    </Modal>
  );
}
