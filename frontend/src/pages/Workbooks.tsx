import { useEffect, useState } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, qs } from "../lib/api";
import { useGlobal } from "../lib/context";
import { fmtAgo } from "../lib/format";
import { runSearch, searchBody } from "../lib/search";
import { Card, Empty, Loading, Modal } from "../components/ui";
import { ResultView, Viz, VIZ_OPTIONS } from "../components/ResultView";

interface Panel { id: string; title: string; query: string; viz: Viz; width: number; range?: string | null }
interface Book { id: number; key?: string; name: string; description: string; range: string; panels: Panel[]; owner: string; shared: boolean;
  template: boolean; can_edit: boolean; updated_at: string }
const RANGES = ["5m", "15m", "1h", "24h", "7d", "30d"];
// literal class names so Tailwind generates them
const SPAN: Record<number, string> = { 2: "lg:col-span-2", 3: "lg:col-span-3", 4: "lg:col-span-4", 5: "lg:col-span-5", 6: "lg:col-span-6",
  7: "lg:col-span-7", 8: "lg:col-span-8", 9: "lg:col-span-9", 10: "lg:col-span-10", 11: "lg:col-span-11", 12: "lg:col-span-12" };

export function Workbooks() {
  const nav = useNavigate();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["workbooks"], queryFn: () => api<Book[]>("/workbooks") });
  const create = useMutation({
    mutationFn: () => api<Book>("/workbooks", { method: "POST", body: { name: "Untitled workbook", panels: [], shared: true } }),
    onSuccess: (b) => { qc.invalidateQueries({ queryKey: ["workbooks"] }); nav(`/workbooks/${b.id}?edit=1`); },
  });
  return (
    <div className="space-y-4 min-w-0">
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-xs text-muted flex-1">Workbooks are dashboards you build from pipeline queries. Templates are read-only; clone one to customise it.</p>
        <button className="btn btn-primary" disabled={create.isPending} onClick={() => create.mutate()}>+ New workbook</button>
      </div>
      <Loading q={q} />
      {q.data && !q.data.length && <Empty text="No workbooks." />}
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {(q.data || []).map((b) => (
          <button key={b.id} className="card p-4 text-left hover:border-brand-500/50 hover:shadow-md transition-shadow" onClick={() => nav(`/workbooks/${b.id}`)}>
            <div className="flex items-center gap-2 min-w-0">
              <span className="font-semibold text-slate-100 truncate">{b.name}</span>
              {b.template && <span className="pill bg-brand-500/10 text-brand-400">template</span>}
              {!b.shared && <span className="pill bg-slate-800 text-slate-400">private</span>}
            </div>
            <div className="text-xs text-muted mt-1 line-clamp-2 min-h-[2rem]">{b.description || "—"}</div>
            <div className="text-2xs text-muted mt-2">{b.panels.length} panel{b.panels.length === 1 ? "" : "s"} · {b.owner} · updated {fmtAgo(b.updated_at)}</div>
          </button>
        ))}
      </div>
    </div>
  );
}

export function WorkbookView() {
  const { id = "" } = useParams();
  const nav = useNavigate();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["workbook", id], queryFn: () => api<Book>(`/workbooks/${id}`) });
  const [draft, setDraft] = useState<Book | null>(null);
  const [range, setRange] = useState<string | null>(null);
  const [editPanel, setEditPanel] = useState<Panel | null>(null);
  const editing = !!draft;
  const b = draft || q.data;
  const [sp, setSp] = useSearchParams();
  useEffect(() => {  // /workbooks/:id?edit=1 opens a new workbook straight in edit mode
    if (q.data && sp.get("edit") === "1") {
      if (q.data.can_edit) setDraft(structuredClone(q.data));
      setSp({}, { replace: true });
    }
  }, [q.data]);
  const save = useMutation({
    mutationFn: (x: Book) => api<Book>(`/workbooks/${id}`, { method: "PUT", body: { name: x.name, description: x.description, range: x.range, shared: x.shared, panels: x.panels } }),
    onSuccess: (x) => { qc.setQueryData(["workbook", id], x); qc.invalidateQueries({ queryKey: ["workbooks"] }); setDraft(null); },
  });
  const clone = useMutation({ mutationFn: () => api<Book>(`/workbooks/${id}/clone`, { method: "POST" }), onSuccess: (x) => { qc.invalidateQueries({ queryKey: ["workbooks"] }); nav(`/workbooks/${x.id}`); } });
  const del = useMutation({ mutationFn: () => api(`/workbooks/${id}`, { method: "DELETE" }), onSuccess: () => { qc.invalidateQueries({ queryKey: ["workbooks"] }); nav("/workbooks"); } });
  if (!b) return <Loading q={q} />;
  const eff = range || b.range;
  const move = (i: number, d: number) => {
    const p = [...draft!.panels];
    const j = i + d;
    if (j < 0 || j >= p.length) return;
    [p[i], p[j]] = [p[j], p[i]];
    setDraft({ ...draft!, panels: p });
  };
  const upsert = (p: Panel) => {
    const panels = draft!.panels.some((x) => x.id === p.id) ? draft!.panels.map((x) => (x.id === p.id ? p : x)) : [...draft!.panels, p];
    setDraft({ ...draft!, panels });
    setEditPanel(null);
  };
  return (
    <div className="space-y-4 min-w-0">
      <div className="flex flex-wrap items-center gap-2">
        {editing ? <input aria-label="Workbook name" className="input text-lg font-semibold flex-1 min-w-[12rem]" value={draft!.name} onChange={(e) => setDraft({ ...draft!, name: e.target.value })} />
          : <h1 className="text-lg font-semibold flex-1 min-w-0 truncate">{b.name}{b.template && <span className="pill bg-brand-500/10 text-brand-400 ml-2 align-middle">template</span>}</h1>}
        <select aria-label="Workbook time range" className="input py-1" value={editing ? draft!.range : eff}
          onChange={(e) => editing ? setDraft({ ...draft!, range: e.target.value }) : setRange(e.target.value)}>
          {RANGES.map((r) => <option key={r} value={r}>{editing ? `Default range: ${r}` : `Range: ${r}`}</option>)}
        </select>
        {!editing && <button className="btn" onClick={() => qc.invalidateQueries({ queryKey: ["wb-panel", id] })}>Refresh</button>}
        {!editing && b.can_edit && <button className="btn" onClick={() => setDraft(structuredClone(b))}>Edit</button>}
        {!editing && <button className="btn" disabled={clone.isPending} onClick={() => clone.mutate()}>Clone</button>}
        {!editing && b.can_edit && <button className="btn btn-danger" onClick={() => confirm(`Delete workbook "${b.name}"?`) && del.mutate()}>Delete</button>}
        {editing && <>
          <label className="text-sm flex items-center gap-1.5"><input type="checkbox" checked={draft!.shared} onChange={(e) => setDraft({ ...draft!, shared: e.target.checked })} />Shared</label>
          <button className="btn" onClick={() => setEditPanel({ id: `p${Date.now().toString(36)}`, title: "", query: "", viz: "auto", width: 6 })}>+ Panel</button>
          <button className="btn" onClick={() => setDraft(null)}>Cancel</button>
          <button className="btn btn-primary" disabled={save.isPending || !draft!.name} onClick={() => save.mutate(draft!)}>Save</button>
        </>}
      </div>
      {editing ? <input aria-label="Description" className="input w-full text-sm" placeholder="Description" value={draft!.description} onChange={(e) => setDraft({ ...draft!, description: e.target.value })} />
        : b.description && <p className="text-xs text-muted -mt-2">{b.description}</p>}
      {save.error && <div role="alert" className="text-sm text-red-400">{(save.error as Error).message}</div>}
      {!b.panels.length && <Empty text={editing ? "Add a panel to get started." : "This workbook has no panels."} />}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {b.panels.map((p, i) => (
          <div key={p.id} className={`min-w-0 ${SPAN[p.width] || "lg:col-span-6"}`}>
            <PanelCard wb={id} p={p} range={p.range || (editing ? draft!.range : eff)} editing={editing}
              onEdit={() => setEditPanel(p)} onRemove={() => setDraft({ ...draft!, panels: draft!.panels.filter((x) => x.id !== p.id) })}
              onUp={() => move(i, -1)} onDown={() => move(i, 1)} />
          </div>
        ))}
      </div>
      {editPanel && <PanelEditor p={editPanel} onSave={upsert} onClose={() => setEditPanel(null)} />}
    </div>
  );
}

function PanelCard({ wb, p, range, editing, onEdit, onRemove, onUp, onDown }: { wb: string; p: Panel; range: string; editing: boolean;
  onEdit: () => void; onRemove: () => void; onUp: () => void; onDown: () => void }) {
  const g = useGlobal();
  const nav = useNavigate();
  const body = searchBody(g.params, p.query, range);
  const q = useQuery({ queryKey: ["wb-panel", wb, p.id, body], queryFn: () => runSearch(body), enabled: !!p.query, staleTime: 60_000,
    refetchInterval: g.refreshSec ? g.refreshSec * 1000 : false, placeholderData: (prev) => prev, retry: false });
  return (
    <Card title={p.title} className="h-full" right={editing ? <>
      <button className="btn px-2" aria-label="Move up" onClick={onUp}>↑</button><button className="btn px-2" aria-label="Move down" onClick={onDown}>↓</button>
      <button className="btn" onClick={onEdit}>Edit</button><button className="btn btn-danger" onClick={onRemove}>Remove</button></>
      : <button className="link text-xs" onClick={() => nav(`/search${qs({ q: p.query, viz: p.viz !== "auto" ? p.viz : undefined })}`)}>Open in Search</button>}>
      {q.isLoading && <div className="h-40 animate-pulse bg-slate-800/30 rounded" />}
      {q.error && <div role="alert" className="text-xs text-red-400 font-mono whitespace-pre-wrap">{(q.error as Error).message}</div>}
      {q.data && <ResultView r={q.data} viz={p.viz} height={p.viz === "kpi" ? 80 : 240} maxH="max-h-80" />}
      {q.data?.truncated && <div className="text-2xs text-amber-300 mt-1">Result truncated — aggregate or add | head N.</div>}
    </Card>
  );
}

function PanelEditor({ p, onSave, onClose }: { p: Panel; onSave: (p: Panel) => void; onClose: () => void }) {
  const [f, setF] = useState<Panel>({ ...p });
  const [err, setErr] = useState("");
  const check = async () => {
    const r = await api<any>("/search/validate", { method: "POST", body: { query: f.query } });
    if (!r.valid) { setErr(r.error); return; }
    onSave(f);
  };
  return (
    <Modal title={p.title ? `Panel: ${p.title}` : "New panel"} onClose={onClose}>
      <div className="grid gap-2 sm:grid-cols-3">
        <div className="sm:col-span-3"><label className="label">Title</label><input className="input w-full" value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} /></div>
        <div className="sm:col-span-3"><label className="label">Query</label><textarea className="input w-full font-mono text-[13px] min-h-[5rem]" spellCheck={false} value={f.query} onChange={(e) => setF({ ...f, query: e.target.value })} /></div>
        <div><label className="label">Visualisation</label><select className="input w-full" value={f.viz} onChange={(e) => setF({ ...f, viz: e.target.value as Viz })}>{VIZ_OPTIONS.map((v) => <option key={v}>{v}</option>)}</select></div>
        <div><label className="label">Width (of 12)</label><select className="input w-full" value={f.width} onChange={(e) => setF({ ...f, width: Number(e.target.value) })}>{[2, 3, 4, 6, 8, 9, 12].map((w) => <option key={w} value={w}>{w}</option>)}</select></div>
        <div><label className="label">Range override</label><select className="input w-full" value={f.range || ""} onChange={(e) => setF({ ...f, range: e.target.value || null })}>
          <option value="">Workbook range</option>{RANGES.map((r) => <option key={r}>{r}</option>)}</select></div>
      </div>
      {err && <div role="alert" className="text-sm text-red-400 mt-2 font-mono">{err}</div>}
      <button className="btn btn-primary mt-3" disabled={!f.title || !f.query} onClick={check}>Apply</button>
      <span className="text-2xs text-muted ml-2">Save the workbook to keep changes.</span>
    </Modal>
  );
}
