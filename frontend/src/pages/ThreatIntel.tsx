import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useData, useGlobal, useMe } from "../lib/context";
import { fmtNum } from "../lib/format";
import { Card, Empty, IpLink, Kpi, Loading, Modal, TableWrap, Tabs, Time, Trunc, useExplore } from "../components/ui";
import { Donut, TimeChart } from "../components/charts";

export function ThreatIntel() {
  const [tab, setTab] = useState("matches");
  return (
    <div className="space-y-4 min-w-0">
      <p className="text-xs text-muted">Events are matched against enabled feeds and the manual IOC list as they arrive (destination/source IP, CIDR, DNS query and web hostname, including parent domains). Matching events raise the <b>Traffic to/from threat-intel indicator</b> detection. Use Hunt to search past events for new indicators.</p>
      <Tabs value={tab} onChange={setTab} tabs={[{ key: "matches", label: "Matches" }, { key: "hunt", label: "Hunt" }, { key: "feeds", label: "Feeds" }, { key: "manual", label: "Manual IOCs" }]} />
      {tab === "matches" && <Matches />}
      {tab === "hunt" && <Hunt />}
      {tab === "feeds" && <Feeds />}
      {tab === "manual" && <Manual />}
    </div>
  );
}

function Matches() {
  const q = useData<any>("/ti/summary");
  const explore = useExplore();
  const d = q.data;
  const t = d?.totals || {};
  return (<>
    <Loading q={q} />
    <div className="kpi-grid">
      <Kpi label="Matching events" value={fmtNum(t.events)} tone={t.events ? "bad" : undefined} onClick={() => explore({ ql: "ti:*" })} />
      <Kpi label="Indicators hit" value={fmtNum(t.indicators)} />
      <Kpi label="Internal hosts involved" value={fmtNum(t.hosts)} tone={t.hosts ? "warn" : undefined} />
    </div>
    <div className="grid-cards xl:grid-cols-3">
      <Card title="Matches over time" className="xl:col-span-2"><TimeChart data={d?.timeseries} loading={q.isLoading} stack series={[{ key: "events", name: "Matches", color: "alert" }, { key: "blocked", name: "Blocked", color: "muted" }]} /></Card>
      <Card title="By category">{d?.categories?.length ? <Donut rows={d.categories} label="Category" height={200} /> : <Empty text="No matches in this range." />}</Card>
    </div>
    <Card title="Indicators">
      {d?.indicators?.length ? <TableWrap><table className="tbl"><thead><tr><th className="w-full">Indicator</th><th>Category</th><th>Feed</th><th className="num">Events</th><th className="num">Blocked</th><th className="num">Hosts</th><th>Last seen</th></tr></thead>
        <tbody>{d.indicators.map((r: any) => <tr key={r.indicator} tabIndex={0} onClick={() => explore({ ql: `ti:"${r.indicator}"` })} onKeyDown={(e) => e.key === "Enter" && explore({ ql: `ti:"${r.indicator}"` })}>
          <td className="font-mono text-xs cell-wrap">{r.indicator}</td><td className="nowrap text-xs">{r.category}</td><td className="text-xs"><Trunc text={r.feed} max="max-w-[14rem]" /></td>
          <td className="num">{fmtNum(r.events)}</td><td className="num">{fmtNum(r.blocked)}</td><td className="num">{fmtNum(r.hosts)}</td><td><Time v={r.last_seen} /></td></tr>)}</tbody></table></TableWrap>
        : <Empty text="No events matched threat intelligence in this range." />}
    </Card>
    <Card title="Internal hosts with matches">
      {d?.hosts?.length ? <TableWrap><table className="tbl"><thead><tr><th>Host</th><th className="num">Events</th><th className="num">Indicators</th><th>Last seen</th></tr></thead>
        <tbody>{d.hosts.map((r: any) => <tr key={r.src_ip}><td><IpLink ip={r.src_ip} /></td><td className="num">{fmtNum(r.events)}</td><td className="num">{fmtNum(r.indicators)}</td><td><Time v={r.last_seen} /></td></tr>)}</tbody></table></TableWrap>
        : <Empty />}
    </Card>
  </>);
}

function Hunt() {
  const g = useGlobal();
  const [text, setText] = useState("");
  const hunt = useMutation({ mutationFn: () => api<any>("/ti/hunt", { method: "POST", body: { indicators: text }, params: g.params }) });
  const r = hunt.data;
  return (<>
    <Card title="Retroactive IOC hunt (selected time range)">
      <textarea aria-label="Indicators" className="input w-full h-28 font-mono" placeholder={"One per line or comma-separated: IPs, CIDRs, domains\n198.51.100.23\n203.0.113.0/24\nbad.example.com"} value={text} onChange={(e) => setText(e.target.value)} />
      <div className="flex items-center gap-2 mt-2"><button className="btn btn-primary" disabled={!text.trim() || hunt.isPending} onClick={() => hunt.mutate()}>{hunt.isPending ? "Searching…" : "Hunt"}</button>
        {hunt.error && <span role="alert" className="text-sm text-red-400">{(hunt.error as Error).message}</span>}</div>
    </Card>
    {r && <Card title={`${fmtNum(r.total_events)} matching events (${r.indicators.ips} IPs, ${r.indicators.cidrs} CIDRs, ${r.indicators.domains} domains)`}>
      {r.matches.length ? <TableWrap><table className="tbl"><thead><tr><th>Type</th><th>Source</th><th>Destination</th><th>Port</th><th className="w-full">Host / query</th><th>Action</th><th className="num">Events</th><th>Last seen</th></tr></thead>
        <tbody>{r.matches.map((m: any, n: number) => <tr key={n}><td className="text-xs">{m.category}</td><td><IpLink ip={m.src_ip} /></td><td><IpLink ip={m.dst_ip} /></td><td className="font-mono text-xs">{m.dst_port ?? "—"}</td>
          <td className="font-mono text-xs cell-wrap">{m.hostname || m.dns_qname || "—"}</td><td className="text-xs">{m.action}</td><td className="num">{fmtNum(m.events)}</td><td><Time v={m.last_seen} /></td></tr>)}</tbody></table></TableWrap>
        : <Empty text="No stored events match these indicators in the selected range." />}
    </Card>}
  </>);
}

function Feeds() {
  const me = useMe();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["ti-feeds"], queryFn: () => api<any[]>("/ti/feeds"), refetchInterval: 30_000 });
  const [add, setAdd] = useState(false);
  const upd = useMutation({ mutationFn: ({ id, body }: any) => api(`/ti/feeds/${id}`, { method: "PUT", body }), onSuccess: () => qc.invalidateQueries({ queryKey: ["ti-feeds"] }) });
  const refresh = useMutation({ mutationFn: (id: number) => api(`/ti/feeds/${id}/refresh`, { method: "POST" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["ti-feeds"] }) });
  const del = useMutation({ mutationFn: (id: number) => api(`/ti/feeds/${id}`, { method: "DELETE" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["ti-feeds"] }) });
  return (
    <Card title="Feeds" right={me.role === "admin" && <button className="btn btn-primary" onClick={() => setAdd(true)}>+ Custom feed</button>}>
      <p className="text-xs text-muted mb-2">Feeds are downloaded by the worker over HTTPS (size-capped, parsed as text). The SIEM host needs outbound internet access to the feed URLs. If a refresh fails, the previous indicator list is kept.</p>
      <Loading q={q} />
      {!!q.data?.length && <TableWrap><table className="tbl"><thead><tr><th>Enabled</th><th className="w-full">Feed</th><th>Type</th><th>Category</th><th className="num">Indicators</th><th>Last success</th><th>Status</th><th /></tr></thead>
        <tbody>{q.data.map((f) => <tr key={f.id}>
          <td><input type="checkbox" aria-label={`Enable ${f.name}`} disabled={me.role !== "admin"} checked={f.enabled} onChange={(e) => upd.mutate({ id: f.id, body: { enabled: e.target.checked } })} /></td>
          <td className="min-w-[14rem]"><div className="text-sm">{f.name}</div>{f.url && <div className="text-2xs text-muted cell-trunc max-w-[28rem]" title={f.url}>{f.url}</div>}</td>
          <td className="text-xs nowrap">{f.kind}</td><td className="text-xs nowrap">{f.category}</td><td className="num">{fmtNum(f.indicator_count)}</td>
          <td><Time v={f.last_success} /></td>
          <td className={`text-xs ${f.last_status.startsWith("ok") ? "text-emerald-400" : f.last_status.startsWith("error") ? "text-red-400" : "text-muted"}`}><Trunc text={f.last_status} max="max-w-[16rem]" /></td>
          <td className="nowrap">{me.role === "admin" && f.kind !== "manual" && <button className="btn" disabled={refresh.isPending} onClick={() => refresh.mutate(f.id)}>Refresh</button>}
            {me.role === "admin" && !f.builtin && <button className="btn btn-danger ml-1" onClick={() => confirm(`Delete feed ${f.name}?`) && del.mutate(f.id)}>Delete</button>}</td>
        </tr>)}</tbody></table></TableWrap>}
      {add && <AddFeed onClose={() => { setAdd(false); qc.invalidateQueries({ queryKey: ["ti-feeds"] }); }} />}
    </Card>
  );
}

function AddFeed({ onClose }: { onClose: () => void }) {
  const [f, setF] = useState({ name: "", url: "https://", kind: "ip", category: "malicious", refresh_hours: 6 });
  const m = useMutation({ mutationFn: () => api("/ti/feeds", { method: "POST", body: { ...f, refresh_hours: Number(f.refresh_hours) } }), onSuccess: onClose });
  return (
    <Modal title="Add custom feed" onClose={onClose}>
      <div className="grid gap-2 sm:grid-cols-2">
        <div className="sm:col-span-2"><label className="label">Name</label><input className="input w-full" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></div>
        <div className="sm:col-span-2"><label className="label">HTTPS URL (plain text, CSV, hosts file or JSON lines)</label><input className="input w-full font-mono" value={f.url} onChange={(e) => setF({ ...f, url: e.target.value })} /></div>
        <div><label className="label">Indicator type</label><select className="input w-full" value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })}>{["ip", "cidr", "domain", "mixed"].map((k) => <option key={k}>{k}</option>)}</select></div>
        <div><label className="label">Category</label><input className="input w-full" value={f.category} onChange={(e) => setF({ ...f, category: e.target.value })} /></div>
        <div><label className="label">Refresh every (hours)</label><input type="number" min={1} max={168} className="input w-full" value={f.refresh_hours} onChange={(e) => setF({ ...f, refresh_hours: Number(e.target.value) })} /></div>
      </div>
      {m.error && <div role="alert" className="text-sm text-red-400 mt-2">{(m.error as Error).message}</div>}
      <button className="btn btn-primary mt-3" disabled={!f.name || !f.url.startsWith("https://")} onClick={() => m.mutate()}>Add feed</button>
    </Modal>
  );
}

function Manual() {
  const me = useMe();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["ti-manual"], queryFn: () => api<any[]>("/ti/manual") });
  const [text, setText] = useState("");
  const [note, setNote] = useState("");
  const add = useMutation({ mutationFn: () => api<any>("/ti/manual", { method: "POST", body: { indicators: text, note } }), onSuccess: () => { setText(""); qc.invalidateQueries({ queryKey: ["ti-manual"] }); } });
  const del = useMutation({ mutationFn: (id: number) => api(`/ti/manual/${id}`, { method: "DELETE" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["ti-manual"] }) });
  return (<>
    {me.role === "admin" && <Card title="Add indicators">
      <textarea aria-label="Indicators to add" className="input w-full h-24 font-mono" placeholder="IPs, CIDRs or domains — one per line or comma-separated" value={text} onChange={(e) => setText(e.target.value)} />
      <div className="flex flex-wrap gap-2 mt-2"><input aria-label="Note" className="input flex-1 min-w-[12rem]" placeholder="Note / source (e.g. CERT-In advisory, case #12)" value={note} onChange={(e) => setNote(e.target.value)} />
        <button className="btn btn-primary" disabled={!text.trim() || add.isPending} onClick={() => add.mutate()}>Add</button></div>
      {add.data && <p className="text-xs text-emerald-400 mt-1">Added {add.data.added}. {add.data.note}</p>}
    </Card>}
    <Card title={`Manual IOC list (${q.data?.length ?? 0})`}>
      {q.data?.length ? <TableWrap maxH="max-h-[28rem]"><table className="tbl"><thead><tr><th className="w-full">Indicator</th><th>Type</th><th>Note</th><th>Added</th><th /></tr></thead>
        <tbody>{q.data.map((r) => <tr key={r.id}><td className="font-mono text-xs cell-wrap">{r.indicator}</td><td className="text-xs">{r.type}</td><td className="text-xs"><Trunc text={r.note} /></td><td><Time v={r.added_at} /></td>
          <td>{me.role === "admin" && <button aria-label={`Remove ${r.indicator}`} className="text-muted hover:text-red-400 px-1" onClick={() => del.mutate(r.id)}>✕</button>}</td></tr>)}</tbody></table></TableWrap>
        : <Empty text="No manual indicators." />}
    </Card>
  </>);
}
