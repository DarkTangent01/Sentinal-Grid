import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useData, useGlobal, useMe } from "../lib/context";
import { fmtNum } from "../lib/format";
import { Card, Empty, IpLink, Kpi, Loading, Modal, Pager, rowProps, TableWrap, Tabs, Time, Trunc, useExplore } from "../components/ui";
import { Donut, TimeChart } from "../components/charts";

export function ThreatIntel() {
  const [tab, setTab] = useState("matches");
  return (
    <div className="space-y-4 min-w-0">
      <p className="text-xs text-muted">Events are matched against enabled feeds and the manual IOC list as they arrive (destination/source IP, CIDR, DNS query and web hostname, including parent domains). Matching events raise the <b>Traffic to/from threat-intel indicator</b> detection. Use Hunt to search past events for new indicators.</p>
      <Tabs value={tab} onChange={setTab} tabs={[{ key: "matches", label: "Matches" }, { key: "hunt", label: "Hunt" }, { key: "indicators", label: "Indicators" }, { key: "feeds", label: "Feeds" }, { key: "manual", label: "Manual IOCs" }]} />
      {tab === "matches" && <Matches />}
      {tab === "hunt" && <Hunt />}
      {tab === "indicators" && <Indicators />}
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
        <tbody>{d.indicators.map((r: any) => <tr key={r.indicator} {...rowProps(() => explore({ ql: `ti:"${r.indicator}"` }))}>
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
  const [f, setF] = useState({ name: "", url: "https://", kind: "ip", category: "malicious", refresh_hours: 6, auth_value: "", default_confidence: 50, expire_days: 0 });
  const connector = ["stix", "taxii", "misp", "otx"].includes(f.kind);
  const m = useMutation({ mutationFn: () => api("/ti/feeds", { method: "POST", body: { ...f, refresh_hours: Number(f.refresh_hours), default_confidence: Number(f.default_confidence),
    expire_days: Number(f.expire_days) } }), onSuccess: onClose });
  return (
    <Modal title="Add custom feed" onClose={onClose}>
      <div className="grid gap-2 sm:grid-cols-2">
        <label className="sm:col-span-2 block min-w-0"><span className="label">Name</span><input className="input w-full" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></label>
        <label className="block min-w-0"><span className="label">Source format</span><select className="input w-full" value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })}>
          {[["ip", "list: IP addresses"], ["cidr", "list: networks"], ["domain", "list: domains"], ["mixed", "list: mixed"], ["stix", "STIX 2.1 bundle"], ["taxii", "TAXII 2.1 collection"],
            ["misp", "MISP server"], ["otx", "AlienVault OTX"]].map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></label>
        <label className="block min-w-0"><span className="label">Default confidence (when the source gives none)</span><input type="number" min={0} max={100} className="input w-full" value={f.default_confidence} onChange={(e) => setF({ ...f, default_confidence: Number(e.target.value) })} /></label>
        <label className="sm:col-span-2 block min-w-0"><span className="label">{f.kind === "taxii" ? "Collection URL (https://server/api/collections/<id>)" : f.kind === "misp" ? "MISP base URL" : f.kind === "otx" ? "OTX base URL (https://otx.alienvault.com)" : "HTTPS URL (plain text, CSV, hosts file, JSON lines or STIX JSON)"}</span><input className="input w-full font-mono" value={f.url} onChange={(e) => setF({ ...f, url: e.target.value })} /></label>
        {connector && <label className="sm:col-span-2 block min-w-0"><span className="label">API key / token (stored encrypted, never shown again)</span><input type="password" autoComplete="off" className="input w-full" value={f.auth_value} onChange={(e) => setF({ ...f, auth_value: e.target.value })} /></label>}
        <label className="block min-w-0"><span className="label">Expire indicators after (days, 0 = when the feed drops them)</span><input type="number" min={0} max={3650} className="input w-full" value={f.expire_days} onChange={(e) => setF({ ...f, expire_days: Number(e.target.value) })} /></label>
        <label className="block min-w-0"><span className="label">Category</span><input className="input w-full" value={f.category} onChange={(e) => setF({ ...f, category: e.target.value })} /></label>
        <label className="block min-w-0"><span className="label">Refresh every (hours)</span><input type="number" min={1} max={168} className="input w-full" value={f.refresh_hours} onChange={(e) => setF({ ...f, refresh_hours: Number(e.target.value) })} /></label>
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

/** The indicator store: type, source attribution, confidence (from the source, else the feed default), first / last seen,
 *  expiry, and the analyst verdict. A false positive stops matching within 5 minutes and survives feed refreshes. */
function Indicators() {
  const qc = useQueryClient();
  const [f, setF] = useState({ q: "", type: "", fp: "" });
  const [page, setPage] = useState(1);
  const st = useQuery({ queryKey: ["ti-stats"], queryFn: () => api<any>("/ti/stats") });
  const q = useQuery({ queryKey: ["ti-ind", f, page], queryFn: () => api<any>("/ti/indicators", { params: { q: f.q || undefined, type: f.type || undefined,
    false_positive: f.fp === "" ? undefined : f.fp === "yes", page, size: 50 } }) });
  const m = useMutation({ mutationFn: ({ id, fp }: { id: number; fp: boolean }) => api(`/ti/indicators/${id}`, { method: "PATCH", body: { false_positive: fp } }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["ti-ind"] }); qc.invalidateQueries({ queryKey: ["ti-stats"] }); } });
  const s = st.data;
  return <div className="space-y-4">
    {s && <div className="kpi-grid"><Kpi label="Indicators" value={fmtNum(s.total)} sub={`${fmtNum(s.distinct)} distinct · ${fmtNum(s.in_several_feeds)} listed by several feeds`} />
      <Kpi label="Marked false positive" value={fmtNum(s.false_positives)} /><Kpi label="Expired" value={fmtNum(s.expired)} />
      {s.by_type.slice(0, 4).map((t: any) => <Kpi key={t.type} label={t.type} value={fmtNum(t.count)} />)}</div>}
    {s && <p className="text-2xs text-muted">{s.note}</p>}
    <div className="flex flex-wrap gap-2">
      <input aria-label="Search indicators" className="input py-1 w-64" placeholder="Indicator contains…" value={f.q} onChange={(e) => { setF({ ...f, q: e.target.value }); setPage(1); }} />
      <select aria-label="Type" className="input py-1" value={f.type} onChange={(e) => { setF({ ...f, type: e.target.value }); setPage(1); }}><option value="">All types</option>
        {["ip", "cidr", "domain", "url", "sha256", "sha1", "md5", "email", "asn"].map((t) => <option key={t}>{t}</option>)}</select>
      <select aria-label="Verdict" className="input py-1" value={f.fp} onChange={(e) => { setF({ ...f, fp: e.target.value }); setPage(1); }}><option value="">Any verdict</option><option value="no">Active</option><option value="yes">False positive</option></select>
    </div>
    <Card bodyClass="p-0"><Loading q={q} />
      {q.data && (!q.data.items.length ? <Empty text="No indicator matches." /> : <><TableWrap><table className="tbl">
        <thead><tr><th>Indicator</th><th>Type</th><th>Feed</th><th>Threat</th><th className="num">Confidence</th><th>First / last seen</th><th>Expires</th><th>Verdict</th></tr></thead>
        <tbody>{q.data.items.map((r: any) => <tr key={r.id} className={r.false_positive || r.expired ? "opacity-60" : ""}>
          <td className="font-mono text-xs"><Trunc text={r.indicator} /></td><td>{r.type}</td><td className="text-xs">{r.feed}<div className="text-2xs text-muted">{r.category}</div></td>
          <td className="text-xs"><Trunc text={r.threat || "—"} max="max-w-[12rem]" /></td>
          <td className="num">{r.confidence ?? "—"}{!r.confidence_from_source && r.confidence != null && <span className="text-2xs text-muted"> (default)</span>}</td>
          <td className="text-xs">{r.first_seen ? <Time v={r.first_seen} /> : "—"} / {r.last_seen ? <Time v={r.last_seen} /> : "—"}</td>
          <td>{r.expires_at ? <><Time v={r.expires_at} />{r.expired && <span className="text-2xs text-muted"> expired</span>}</> : "—"}</td>
          <td className="nowrap">{r.false_positive ? <><span className="text-xs">false positive ({r.fp_by})</span> <button type="button" className="btn py-0.5 text-xs" aria-label={`Restore ${r.indicator}`} onClick={() => m.mutate({ id: r.id, fp: false })}>Restore</button></>
            : <button type="button" className="btn py-0.5 text-xs" aria-label={`Mark ${r.indicator} as a false positive`} onClick={() => m.mutate({ id: r.id, fp: true })}>False positive</button>}</td></tr>)}</tbody></table></TableWrap>
        <Pager page={page} size={50} total={q.data.total} onPage={setPage} /></>)}</Card>
  </div>;
}
