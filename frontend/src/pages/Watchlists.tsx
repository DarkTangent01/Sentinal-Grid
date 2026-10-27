import { ChangeEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, downloadUrl } from "../lib/api";
import { useMe } from "../lib/context";
import { fmtNum } from "../lib/format";
import { Card, Empty, Loading, Modal, TableWrap, Time, useDebounced } from "../components/ui";

interface WL { id: number; name: string; description: string; kind: string; items: number; created_by: string; updated_at: string }
const KIND_HINT: Record<string, string> = { ip: "IP addresses or CIDR ranges", domain: "domains (matches sub-domains too)", user: "user names (case-insensitive)", string: "any text (case-insensitive)" };

export function Watchlists() {
  const me = useMe();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["watchlists"], queryFn: () => api<WL[]>("/watchlists") });
  const [selId, setSelId] = useState<number | null>(null);
  const [create, setCreate] = useState(false);
  const sel = (q.data || []).find((w) => w.id === selId) || q.data?.[0];
  return (
    <div className="space-y-4 min-w-0">
      <p className="text-xs text-muted">Watchlists are named lookup lists — VIP hosts, jump servers, partner networks, known-bad domains, service accounts.
        Use them in Search and detections with <code className="font-mono">| lookup &lt;name&gt; src_ip</code> or <code className="font-mono">where inwatchlist(dst_ip, "&lt;name&gt;")</code>,
        and fill them automatically from automation rules.</p>
      <div className="grid gap-4 lg:grid-cols-[18rem_1fr] min-w-0">
        <Card title="Watchlists" right={me.role === "admin" && <button className="btn btn-primary" onClick={() => setCreate(true)}>+ New</button>} bodyClass="p-0">
          <Loading q={q} />
          {q.data && !q.data.length && <Empty text="No watchlists yet." />}
          <ul>{(q.data || []).map((w) => (
            <li key={w.id}><button className={`w-full text-left px-4 py-2.5 border-b border-line/60 hover:bg-slate-800/40 ${sel?.id === w.id ? "bg-brand-500/10" : ""}`} onClick={() => setSelId(w.id)}>
              <div className="font-mono text-sm text-slate-100 truncate">{w.name}</div>
              <div className="text-2xs text-muted">{w.kind} · {fmtNum(w.items)} item{w.items === 1 ? "" : "s"}</div>
            </button></li>))}</ul>
        </Card>
        {sel ? <Detail key={sel.id} w={sel} admin={me.role === "admin"} onDeleted={() => { setSelId(null); qc.invalidateQueries({ queryKey: ["watchlists"] }); }} />
          : q.data?.length === 0 ? null : <div />}
      </div>
      {create && <CreateModal onClose={(id) => { setCreate(false); qc.invalidateQueries({ queryKey: ["watchlists"] }); if (id) setSelId(id); }} />}
    </div>
  );
}

function Detail({ w, admin, onDeleted }: { w: WL; admin: boolean; onDeleted: () => void }) {
  const qc = useQueryClient();
  const [search, setSearch] = useState("");
  const dq = useDebounced(search);
  const [page, setPage] = useState(1);
  const [adding, setAdding] = useState(false);
  const items = useQuery({ queryKey: ["wl-items", w.id, dq, page], queryFn: () => api<any>(`/watchlists/${w.id}/items`, { params: { q: dq, page, size: 100 } }), placeholderData: (p) => p });
  const delItem = useMutation({ mutationFn: (iid: number) => api(`/watchlists/${w.id}/items/${iid}`, { method: "DELETE" }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["wl-items", w.id] }); qc.invalidateQueries({ queryKey: ["watchlists"] }); } });
  const del = useMutation({ mutationFn: () => api(`/watchlists/${w.id}`, { method: "DELETE" }), onSuccess: onDeleted });
  const pages = items.data ? Math.max(1, Math.ceil(items.data.total / 100)) : 1;
  return (
    <Card title={<span className="font-mono">{w.name}</span>} right={<>
      <a className="btn" href={downloadUrl(`/watchlists/${w.id}/export.csv`)}>Export CSV</a>
      {admin && <button className="btn btn-primary" onClick={() => setAdding(true)}>Add items</button>}
      {admin && <button className="btn btn-danger" onClick={() => confirm(`Delete watchlist "${w.name}" and its ${w.items} items? Queries that use it will fail.`) && del.mutate()}>Delete</button>}
    </>}>
      <div className="text-xs text-muted mb-3 space-y-1">
        {w.description && <p className="text-slate-300">{w.description}</p>}
        <p>Kind: <b>{w.kind}</b> — {KIND_HINT[w.kind]}. Created by {w.created_by}, updated <Time v={w.updated_at} />.</p>
        <p className="font-mono">| lookup {w.name} {w.kind === "domain" ? "dns_qname" : w.kind === "user" ? "user" : "src_ip"} | where {w.name}_match = 1</p>
      </div>
      <div className="flex flex-wrap items-center gap-2 mb-2">
        <input aria-label="Search items" className="input w-64" placeholder="Search value or label" value={search} onChange={(e) => { setSearch(e.target.value); setPage(1); }} />
        <span className="text-xs text-muted">{fmtNum(items.data?.total)} item(s)</span>
        <span className="flex-1" />
        <button className="btn" disabled={page <= 1} onClick={() => setPage(page - 1)}>‹</button><span className="text-muted text-sm">{page}/{pages}</span>
        <button className="btn" disabled={page >= pages} onClick={() => setPage(page + 1)}>›</button>
      </div>
      <Loading q={items} />
      {items.data && !items.data.items.length && <Empty text={dq ? "No items match." : "Empty watchlist."} />}
      {!!items.data?.items.length && <TableWrap maxH="max-h-[60vh]"><table className="tbl"><thead><tr><th>Value</th><th className="w-full">Label</th><th>Added by</th><th>Expires</th><th>Added</th>{admin && <th />}</tr></thead>
        <tbody>{items.data.items.map((i: any) => <tr key={i.id}><td className="font-mono text-xs nowrap">{i.value}</td><td className="text-xs cell-wrap">{i.label || "—"}</td>
          <td className="text-xs">{i.added_by}</td><td><Time v={i.expires_at} /></td><td><Time v={i.created_at} /></td>
          {admin && <td><button className="btn btn-danger py-0.5" aria-label={`Remove ${i.value}`} onClick={() => delItem.mutate(i.id)}>✕</button></td>}</tr>)}</tbody></table></TableWrap>}
      {adding && <AddItems w={w} onClose={() => { setAdding(false); qc.invalidateQueries({ queryKey: ["wl-items", w.id] }); qc.invalidateQueries({ queryKey: ["watchlists"] }); }} />}
    </Card>
  );
}

function AddItems({ w, onClose }: { w: WL; onClose: () => void }) {
  const [text, setText] = useState("");
  const [mode, setMode] = useState("append");
  const [ttl, setTtl] = useState(0);
  const m = useMutation({ mutationFn: () => api<any>(`/watchlists/${w.id}/items`, { method: "POST", body: { text, mode, ttl_hours: Number(ttl) } }) });
  const onFile = (e: ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (!f) return;
    if (f.size > 5_000_000) { alert("File is larger than 5 MB"); return; }
    f.text().then(setText);
  };
  return (
    <Modal title={`Add items to ${w.name}`} onClose={onClose}>
      <p className="text-xs text-muted mb-2">One item per line as <code className="font-mono">value</code> or <code className="font-mono">value,label</code> ({KIND_HINT[w.kind]}). A header row is skipped. You can also load a CSV file.</p>
      <textarea aria-label="Items" className="input w-full h-48 font-mono text-xs" value={text} onChange={(e) => setText(e.target.value)} placeholder={w.kind === "ip" ? "10.0.0.5,Domain controller\n192.168.50.0/24,Lab network" : w.kind === "domain" ? "example.org,Partner" : "value,label"} />
      <div className="flex flex-wrap items-end gap-3 mt-2">
        <input type="file" accept=".csv,.txt,text/csv,text/plain" aria-label="Load CSV file" className="text-xs" onChange={onFile} />
        <div><label className="label">Mode</label><select className="input" value={mode} onChange={(e) => setMode(e.target.value)}><option value="append">Append</option><option value="replace">Replace all items</option></select></div>
        <div><label className="label">Expire after (hours, 0 = never)</label><input type="number" min={0} className="input w-28" value={ttl} onChange={(e) => setTtl(Number(e.target.value))} /></div>
      </div>
      {m.error && <div role="alert" className="text-sm text-red-400 mt-2">{(m.error as Error).message}</div>}
      {m.data && <div className="text-sm mt-2"><b className="text-emerald-300">{fmtNum(m.data.added)} added</b>, {fmtNum(m.data.skipped_existing)} already present
        {m.data.error_count > 0 && <>, <span className="text-red-300">{m.data.error_count} rejected</span><ul className="text-xs text-red-300 font-mono max-h-32 overflow-auto mt-1">{m.data.errors.map((e: string) => <li key={e}>{e}</li>)}</ul></>}</div>}
      <div className="flex gap-2 mt-3">
        <button className="btn btn-primary" disabled={!text.trim() || m.isPending} onClick={() => (mode !== "replace" || confirm(`Replace all items in ${w.name}?`)) && m.mutate()}>Import</button>
        <button className="btn" onClick={onClose}>{m.data ? "Done" : "Cancel"}</button>
      </div>
    </Modal>
  );
}

function CreateModal({ onClose }: { onClose: (id?: number) => void }) {
  const [f, setF] = useState({ name: "", kind: "ip", description: "" });
  const m = useMutation({ mutationFn: () => api<WL>("/watchlists", { method: "POST", body: f }), onSuccess: (w) => onClose(w.id) });
  return (
    <Modal title="New watchlist" onClose={() => onClose()}>
      <div className="grid gap-2 sm:grid-cols-2">
        <div><label className="label">Name (letters, digits, _ — used in queries)</label><input className="input w-full font-mono" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="vip_hosts" /></div>
        <div><label className="label">Kind</label><select className="input w-full" value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })}>
          {Object.entries(KIND_HINT).map(([k, v]) => <option key={k} value={k}>{k} — {v}</option>)}</select></div>
        <div className="sm:col-span-2"><label className="label">Description</label><input className="input w-full" value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></div>
      </div>
      {m.error && <div role="alert" className="text-sm text-red-400 mt-2">{(m.error as Error).message}</div>}
      <button className="btn btn-primary mt-3" disabled={!f.name || m.isPending} onClick={() => m.mutate()}>Create</button>
    </Modal>
  );
}
