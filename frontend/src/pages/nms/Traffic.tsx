/** Sentinel NMS → Application & Protocol Intelligence (backend: app/traffic, /api/nms/traffic). Everything shown comes
 *  from the flow records the devices export (NetFlow / IPFIX / sFlow); sampled data is labelled as an estimate. Filters,
 *  sorting and paging are server-side and live in the URL, so every drill-down is a link. */
import { Fragment, ReactNode, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, downloadUrl } from "../../lib/api";
import { fmtBytes, fmtNum } from "../../lib/format";
import { TimeChart, TopBar } from "../../components/charts";
import { Bar, Card, Drawer, Empty, Kpi, Loading, Pager, SortTh, TableWrap, Tabs, Time, rowProps } from "../../components/ui";
import { fmtBps } from "../switches/common";
import { CONFIDENCE, DIRECTIONS, RANGES, TABS, TabKey, TrafficFilters, activeFilterCount, apiParams, directionLabel, pivot, readFilters, withFilters } from "./traffic/model";
import { CollectorsTab, DetectionsTab, RulesTab, SettingsTab } from "./TrafficConfig";
import { NetworkContext } from "../../components/NetworkContext";

export type Opts = { devices: { exporter: string; name: string; site: string; kind: string }[]; sites: string[]; vlans: number[]; zones: string[];
  categories: string[]; applications: string[]; protocols: { proto: number; name: string }[];
  permissions: { detections: boolean; sensitive: boolean; export: boolean; rules: boolean; enrichment: boolean; collector: boolean } };

export interface Nav { f: TrafficFilters; go: (patch: Record<string, string | number | null | undefined>) => void; host: (ip: string) => void; opts?: Opts }

/** Query hook for one view: the page's filters + view-specific parameters. */
export function useT<T = any>(path: string, f: TrafficFilters, extra: Record<string, unknown> = {}, enabled = true) {
  const params = { ...apiParams(f), ...Object.fromEntries(Object.entries(extra).filter(([, v]) => v !== undefined && v !== "")) } as Record<string, string>;
  const short = ["5m", "15m", "1h"].includes(f.range || "");
  return useQuery<T>({ queryKey: ["traffic", path, params], queryFn: () => api<T>(`/nms/traffic/${path}`, { params }), enabled,
    placeholderData: (p) => p, refetchInterval: short ? 60_000 : false });
}

export function Conf({ c, evidence }: { c?: string; evidence?: string }) {
  const m = CONFIDENCE[c || "unknown"] || CONFIDENCE.unknown;
  return <span className={`pill ${m.cls}`} title={evidence || m.help}>{m.label}</span>;
}

export function Ip({ ip, nav }: { ip?: string | null; nav: Nav }) {
  if (!ip) return <span className="text-muted">—</span>;
  return <button type="button" className="link font-mono text-xs whitespace-nowrap" onClick={(e) => { e.stopPropagation(); nav.host(ip); }}>{ip}</button>;
}

function Source({ d }: { d?: { source?: string; start?: string; end?: string } }) {
  return d?.source ? <p className="text-2xs text-muted px-3 py-1.5">From {d.source}. Sampled exports are scaled by their sampling rate: those figures are estimates.</p> : null;
}

export function ExportLink({ view, f, nav, extra }: { view: string; f: TrafficFilters; nav: Nav; extra?: Record<string, string> }) {
  if (!nav.opts?.permissions.export) return null;
  return <a className="btn py-0.5 px-2 text-xs" href={downloadUrl(`/nms/traffic/export/${view}.csv`, { ...apiParams(f), ...(extra || {}) })}>Export CSV</a>;
}

function useSort(sp: URLSearchParams, setSp: (s: URLSearchParams) => void, def = "bytes") {
  const raw = sp.get("sort") || `-${def}`;
  const sort = { key: raw.replace(/^[-+]/, ""), desc: raw.startsWith("-") };
  const page = Math.max(1, Number(sp.get("page") || 1));
  const set = (patch: Record<string, string | null>) => {
    const n = new URLSearchParams(sp);
    for (const [k, v] of Object.entries(patch)) if (v === null) n.delete(k); else n.set(k, v);
    setSp(n);
  };
  return { sort, page, sortParam: raw, setSort: (s: { key: string; desc: boolean }) => set({ sort: `${s.desc ? "-" : ""}${s.key}`, page: null }),
    setPage: (p: number) => set({ page: String(p) }) };
}

const PAGE = 50;

export function TrafficPage() {
  const [sp, setSp] = useSearchParams();
  const tab = (TABS.find((t) => t.key === sp.get("tab"))?.key || "overview") as TabKey;
  const f = useMemo(() => readFilters(sp), [sp]);
  const opts = useQuery<Opts>({ queryKey: ["traffic-options"], queryFn: () => api<Opts>("/nms/traffic/options"), staleTime: 300_000 });
  const [host, setHost] = useState<string | null>(null);
  const nav: Nav = { f, opts: opts.data, host: setHost, go: (patch) => setSp(withFilters(sp, patch)) };
  const tabs = TABS.filter((t) => (t.key !== "domains" || opts.data?.permissions.sensitive !== false) && (t.key !== "detections" || opts.data?.permissions.detections !== false));
  return <div className="space-y-3 min-w-0">
    <FilterBar nav={nav} />
    <Tabs tabs={tabs as any} value={tab} onChange={(k) => setSp(withFilters(sp, { tab: k }))} />
    {tab === "overview" && <Overview nav={nav} />}
    {tab === "applications" && <Applications nav={nav} sp={sp} setSp={setSp} />}
    {tab === "protocols" && <Protocols nav={nav} />}
    {(tab === "sources" || tab === "destinations") && <Talkers key={tab} side={tab} nav={nav} sp={sp} setSp={setSp} />}
    {tab === "conversations" && <Conversations nav={nav} sp={sp} setSp={setSp} />}
    {tab === "flows" && <Flows nav={nav} sp={sp} setSp={setSp} />}
    {tab === "devices" && <Devices nav={nav} />}
    {tab === "vlans" && <Vlans nav={nav} />}
    {tab === "interfaces" && <Interfaces nav={nav} />}
    {tab === "domains" && <Domains nav={nav} sp={sp} setSp={setSp} />}
    {tab === "detections" && <DetectionsTab nav={nav} />}
    {tab === "rules" && <RulesTab nav={nav} />}
    {tab === "settings" && <SettingsTab nav={nav} />}
    {tab === "collectors" && <CollectorsTab />}
    {host && <HostDrawer ip={host} nav={nav} onClose={() => setHost(null)} />}
  </div>;
}

// ------------------------------------------------------------------ filters
function TextFilter({ label, value, onApply, placeholder, width = "w-36" }: { label: string; value?: string; onApply: (v: string) => void; placeholder?: string; width?: string }) {
  const [v, setV] = useState(value || "");
  useEffect(() => setV(value || ""), [value]);
  return <input aria-label={label} className={`input py-1 ${width}`} placeholder={placeholder || label} value={v} onChange={(e) => setV(e.target.value)}
    onBlur={() => v.trim() !== (value || "") && onApply(v.trim())} onKeyDown={(e) => e.key === "Enter" && onApply(v.trim())} />;
}

function FilterBar({ nav }: { nav: Nav }) {
  const { f, go, opts } = nav;
  const [cs, setCs] = useState(f.start?.slice(0, 16) || "");
  const [ce, setCe] = useState(f.end?.slice(0, 16) || "");
  const [custom, setCustom] = useState(f.range === "custom");
  const n = activeFilterCount(f);
  return <Card bodyClass="p-2">
    <div className="flex flex-wrap items-center gap-2">
      <select aria-label="Time range" className="input py-1" value={custom ? "custom" : f.range} onChange={(e) => {
        if (e.target.value === "custom") setCustom(true); else { setCustom(false); go({ range: e.target.value, start: null, end: null }); } }}>
        {RANGES.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
      {custom && <><input aria-label="Start" type="datetime-local" className="input py-1" value={cs} onChange={(e) => setCs(e.target.value)} />
        <span className="text-muted">→</span><input aria-label="End" type="datetime-local" className="input py-1" value={ce} onChange={(e) => setCe(e.target.value)} />
        <button type="button" className="btn py-1" disabled={!cs || !ce} onClick={() => go({ range: "custom", start: new Date(cs).toISOString(), end: new Date(ce).toISOString() })}>Apply</button></>}
      <select aria-label="Site" className="input py-1 max-w-[9rem]" value={f.site || ""} onChange={(e) => go({ site: e.target.value })}>
        <option value="">All sites</option>{(opts?.sites || []).map((s) => <option key={s}>{s}</option>)}</select>
      <select aria-label="Device" className="input py-1 max-w-[11rem]" value={f.exporter || ""} onChange={(e) => go({ exporter: e.target.value, interface: null })}>
        <option value="">All devices</option>{(opts?.devices || []).map((d) => <option key={d.exporter} value={d.exporter}>{d.name}</option>)}</select>
      {f.exporter && <TextFilter label="Interface (ifIndex)" value={f.interface} onApply={(v) => go({ interface: v })} width="w-28" />}
      <TextFilter label="VLAN" value={f.vlan} onApply={(v) => go({ vlan: v })} width="w-20" />
      <input aria-label="Application" list="traffic-apps" className="input py-1 w-40" placeholder="Application" defaultValue={f.app} key={f.app || "app"}
        onBlur={(e) => e.target.value !== (f.app || "") && go({ app: e.target.value })} onKeyDown={(e) => e.key === "Enter" && go({ app: (e.target as HTMLInputElement).value })} />
      <datalist id="traffic-apps">{(opts?.applications || []).map((a) => <option key={a} value={a} />)}</datalist>
      <select aria-label="Protocol" className="input py-1" value={f.proto || ""} onChange={(e) => go({ proto: e.target.value })}>
        <option value="">Any protocol</option>{(opts?.protocols || []).map((p) => <option key={p.proto} value={p.proto}>{p.name}</option>)}</select>
      <TextFilter label="Port" value={f.port} onApply={(v) => go({ port: v })} width="w-20" />
      <TextFilter label="Source IP / CIDR" value={f.src} onApply={(v) => go({ src: v })} />
      <TextFilter label="Destination IP / CIDR" value={f.dst} onApply={(v) => go({ dst: v })} />
      <TextFilter label="Either IP" value={f.ip} onApply={(v) => go({ ip: v })} width="w-32" />
      <select aria-label="Direction" className="input py-1" value={f.direction || ""} onChange={(e) => go({ direction: e.target.value })}>
        <option value="">Any direction</option>{DIRECTIONS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
      {n > 0 && <button type="button" className="btn py-1" onClick={() => go(Object.fromEntries(["site", "exporter", "interface", "vlan", "app", "category", "proto", "port", "src", "dst", "ip", "direction"].map((k) => [k, null])))}>
        Clear {n} filter{n > 1 ? "s" : ""}</button>}
    </div>
  </Card>;
}

// ------------------------------------------------------------------ overview
function Overview({ nav }: { nav: Nav }) {
  const { f, go } = nav;
  const [by, setBy] = useState("app");
  const q = useT<any>("overview", f);
  const tr = useT<any>("trends", f, { by });
  const apps = useT<any>("applications", f, { limit: 12 });
  const srcs = useT<any>("top-sources", f, { limit: 10 });
  const dsts = useT<any>("top-destinations", f, { limit: 10 });
  const col = useQuery<any>({ queryKey: ["traffic-collectors"], queryFn: () => api("/nms/traffic/collectors"), refetchInterval: 60_000 });
  const k = q.data?.kpis;
  const chart = useMemo(() => {
    if (!tr.data) return null;
    const { rows, series } = by === "none" ? { rows: tr.data.points, series: ["bps"] } : pivot(tr.data.points);
    return { data: { bucket_seconds: tr.data.bucket_seconds, points: rows }, series: by === "none" ? [{ key: "bps", name: "bit/s", color: "primary" }] : series.map((s) => ({ key: s, name: s })) };
  }, [tr.data, by]);
  return <div className="space-y-3">
    <Loading q={q} />
    {k && (k.bytes === 0 ? <Card><Empty text={<>No flow records match this window and filters. {col.data?.exporters?.length ? "" : "No device is exporting flows yet: see Collectors."}</>} /></Card> : <>
      <div className="kpi-grid">
        <Kpi label="Observed traffic" value={fmtBytes(k.bytes)} sub={k.sampled_bytes ? `${Math.round(100 * k.sampled_bytes / k.bytes)}% sampled (estimate)` : "measured (unsampled exports)"} />
        <Kpi label="Packets" value={fmtNum(k.packets)} />
        <Kpi label="Flow records" value={fmtNum(k.flows)} onClick={() => go({ tab: "flows" })} />
        <Kpi label="Unique sources" value={fmtNum(k.sources)} onClick={() => go({ tab: "sources" })} />
        <Kpi label="Unique destinations" value={fmtNum(k.destinations)} onClick={() => go({ tab: "destinations" })} />
        <Kpi label="Applications" value={fmtNum(k.applications)} onClick={() => go({ tab: "applications" })} />
        <Kpi label="Protocols" value={fmtNum(k.protocols)} onClick={() => go({ tab: "protocols" })} />
        <Kpi label="Average throughput" value={fmtBps(k.avg_bps)} />
        <Kpi label="Peak throughput" value={fmtBps(k.peak_bps)} sub={`per ${k.peak_bucket_seconds >= 3600 ? `${k.peak_bucket_seconds / 3600} h` : `${k.peak_bucket_seconds / 60} min`}`} />
        <Kpi label="Inbound" value={fmtBytes(k.inbound)} onClick={() => go({ tab: "conversations", direction: "inbound" })} />
        <Kpi label="Outbound" value={fmtBytes(k.outbound)} onClick={() => go({ tab: "conversations", direction: "outbound" })} />
        <Kpi label="Internal (east-west)" value={fmtBytes(k.internal)} onClick={() => go({ tab: "conversations", direction: "east_west" })} />
        <Kpi label="External" value={fmtBytes(k.external)} />
        <Kpi label="Unclassified" value={fmtBytes(k.unknown)} sub={k.bytes ? `${(100 * k.unknown / k.bytes).toFixed(1)}%` : ""} onClick={() => go({ tab: "conversations", app: "Unknown" })} />
        <Kpi label="Suspicious (open detections)" value={fmtNum(k.suspicious)} tone={k.suspicious ? "warn" : "ok"} onClick={() => go({ tab: "detections" })} />
      </div>
      {q.data.notes?.length > 0 && <ul className="text-2xs text-muted list-disc pl-5">{q.data.notes.map((x: string) => <li key={x}>{x}</li>)}</ul>}
      <Card title="Traffic trend" right={<select aria-label="Split by" className="input py-0.5 text-xs" value={by} onChange={(e) => setBy(e.target.value)}>
        <option value="none">Total</option><option value="app">By application</option><option value="direction">By direction</option>
        <option value="category">By category</option><option value="proto">By protocol</option></select>}>
        <Loading q={tr} />{chart && <TimeChart data={chart.data as any} series={chart.series} stack={by !== "none"} area height={240} />}
        <Source d={tr.data} /></Card>
      <div className="grid gap-3 lg:grid-cols-3">
        <Card title="Top applications"><Loading q={apps} />{apps.data && (apps.data.items.length ? <TopBar rows={apps.data.items.slice(0, 10)} keyField="app" valueField="bytes" bytes
          onClick={(a) => a && go({ tab: "conversations", app: a })} /> : <Empty text="No applications." />)}</Card>
        <Card title="Top sources"><Loading q={srcs} />{srcs.data && (srcs.data.items.length ? <TopBar rows={srcs.data.items} keyField="ip" valueField="bytes" bytes
          onClick={(ip) => ip && nav.host(ip)} /> : <Empty text="No sources." />)}</Card>
        <Card title="Top destinations"><Loading q={dsts} />{dsts.data && (dsts.data.items.length ? <TopBar rows={dsts.data.items} keyField="ip" valueField="bytes" bytes
          onClick={(ip) => ip && nav.host(ip)} /> : <Empty text="No destinations." />)}</Card>
      </div>
    </>)}
    <CollectorSummary d={col.data} onOpen={() => go({ tab: "collectors" })} />
  </div>;
}

function CollectorSummary({ d, onOpen }: { d?: any; onOpen: () => void }) {
  if (!d) return null;
  const ok = d.exporters.filter((x: any) => x.status === "ok").length;
  const c = d.collector;
  return <Card title="Telemetry collection" right={<button type="button" className="link text-xs" onClick={onOpen}>Details</button>}>
    <div className="flex flex-wrap gap-x-6 gap-y-1 text-xs">
      <span>Collector: <b className={c ? "text-emerald-300" : "text-amber-300"}>{d.collector_status}</b>{c && <> · last report <Time v={c.last} /></>}</span>
      <span>Exporters sending: <b>{ok}</b> of {d.exporters.length} seen in 24 h</span>
      {c && <span>Datagrams {fmtNum(c.datagrams)} · records {fmtNum(c.records)} · decode errors {fmtNum(c.decode_errors)} · dropped (queue) {fmtNum(c.dropped_queue_full)}
        · unknown senders {fmtNum(c.unknown_exporter)}</span>}
      {d.exporters[0] && <span>Last sample <Time v={d.exporters[0].last} /></span>}
    </div></Card>;
}

// ------------------------------------------------------------------ applications / protocols
function Applications({ nav, sp, setSp }: { nav: Nav; sp: URLSearchParams; setSp: (s: URLSearchParams) => void }) {
  const { f, go } = nav;
  const s = useSort(sp, setSp);
  const q = useT<any>("applications", f, { sort: s.sortParam, limit: PAGE, offset: (s.page - 1) * PAGE });
  const tr = useT<any>("trends", f, { by: "app" });
  const chart = useMemo(() => tr.data && pivot(tr.data.points), [tr.data]);
  const max = q.data?.items?.[0]?.bytes || 1;
  return <div className="space-y-3">
    <Card title="Applications over time"><Loading q={tr} />{chart && <TimeChart data={{ bucket_seconds: tr.data.bucket_seconds, points: chart.rows } as any}
      series={chart.series.map((x: string) => ({ key: x, name: x }))} stack area height={220} />}</Card>
    <Card bodyClass="p-0" title="Applications" right={<ExportLink view="applications" f={f} nav={nav} />}>
      <Loading q={q} />
      {q.data && (!q.data.items.length ? <Empty text="No traffic in this window." /> : <TableWrap maxH="max-h-[40rem]"><table className="tbl"><thead><tr>
        <SortTh k="app" label="Application" sort={s.sort} setSort={s.setSort} /><th>Category</th><th>Confidence</th>
        <SortTh k="bytes" label="Traffic" sort={s.sort} setSort={s.setSort} className="num" /><th>Share</th>
        <SortTh k="packets" label="Packets" sort={s.sort} setSort={s.setSort} className="num" /><SortTh k="flows" label="Flows" sort={s.sort} setSort={s.setSort} className="num" />
        <SortTh k="sources" label="Sources" sort={s.sort} setSort={s.setSort} className="num" /><SortTh k="destinations" label="Destinations" sort={s.sort} setSort={s.setSort} className="num" />
        <th className="num">Avg rate</th><th>Encrypted</th><th>Last seen</th></tr></thead>
        <tbody>{q.data.items.map((a: any) => <tr key={a.app}>
          <td><button type="button" className="link text-left" onClick={() => go({ tab: "conversations", app: a.app })}>{a.app}</button>
            {a.ambiguous && <span className="text-2xs text-muted block">port evidence only</span>}</td>
          <td className="text-xs">{a.category}</td><td><Conf c={a.confidence} evidence={a.description} /></td>
          <td className="num">{fmtBytes(a.bytes)}{a.sampled && <span className="text-2xs text-muted" title="sampled: estimate"> ≈</span>}</td>
          <td className="w-28"><Bar value={a.bytes} max={max} /><span className="text-2xs text-muted">{a.share}%</span></td>
          <td className="num">{fmtNum(a.packets)}</td><td className="num">{fmtNum(a.flows)}</td>
          <td className="num"><button type="button" className="link" onClick={() => go({ tab: "sources", app: a.app })}>{fmtNum(a.sources)}</button></td>
          <td className="num"><button type="button" className="link" onClick={() => go({ tab: "destinations", app: a.app })}>{fmtNum(a.destinations)}</button></td>
          <td className="num">{fmtBps(a.avg_bps)}</td><td className="text-xs">{a.encrypted === true ? "yes" : a.encrypted === false ? "no" : "depends"}</td>
          <td className="text-xs"><Time v={a.last} /></td></tr>)}</tbody></table></TableWrap>)}
      {q.data && <Pager page={s.page} size={PAGE} total={q.data.total} onPage={s.setPage} />}
      <Source d={q.data} />
      <p className="text-2xs text-muted px-3 pb-2">Confidence: confirmed (firewall application control or packet bytes), high (DNS name), probable (provider network),
        port-based (signature only). "(possible)" marks ports used by several applications. Nothing is attributed to a specific website from TCP/443 alone.</p>
    </Card>
  </div>;
}

function Protocols({ nav }: { nav: Nav }) {
  const { f, go } = nav;
  const q = useT<any>("protocols", f, { limit: 60 });
  const w = useT<any>("web", f);
  const chart = useMemo(() => w.data && pivot(w.data.points), [w.data]);
  return <div className="space-y-3">
    <div className="grid gap-3 lg:grid-cols-2">
      <Card bodyClass="p-0" title="IP protocols"><Loading q={q} />{q.data && (!q.data.protocols.length ? <Empty text="No traffic." /> :
        <TableWrap><table className="tbl"><thead><tr><th>Protocol</th><th className="num">Traffic</th><th className="num">Share</th><th className="num">Packets</th><th className="num">Flows</th>
          <th className="num">Sources</th></tr></thead><tbody>{q.data.protocols.map((p: any) => <tr key={p.proto}>
            <td><button type="button" className="link" onClick={() => go({ proto: p.proto })}>{p.name}</button> <span className="text-2xs text-muted">{p.proto}</span></td>
            <td className="num">{fmtBytes(p.bytes)}</td><td className="num">{p.share}%</td><td className="num">{fmtNum(p.packets)}</td><td className="num">{fmtNum(p.flows)}</td>
            <td className="num">{fmtNum(p.sources)}</td></tr>)}</tbody></table></TableWrap>)}<Source d={q.data} /></Card>
      <Card bodyClass="p-0" title="Services (protocol / port)">{q.data && <TableWrap maxH="max-h-96"><table className="tbl"><thead><tr><th>Service</th><th>Signature</th>
        <th className="num">Traffic</th><th className="num">Flows</th><th className="num">Sources</th></tr></thead><tbody>{q.data.services.map((x: any) => <tr key={`${x.proto}/${x.port}`}>
          <td><button type="button" className="link font-mono text-xs" onClick={() => go({ tab: "conversations", proto: x.proto, port: x.port })}>{x.name}/{x.port}</button></td>
          <td className="text-xs">{x.label}</td><td className="num">{fmtBytes(x.bytes)}</td><td className="num">{fmtNum(x.flows)}</td><td className="num">{fmtNum(x.sources)}</td></tr>)}</tbody></table></TableWrap>}</Card>
    </div>
    <Card title="Web transport: TCP/443 vs UDP/443 (QUIC / HTTP/3)"><Loading q={w} />
      {w.data && <>
        {chart && chart.rows.length > 0 && <TimeChart data={{ bucket_seconds: w.data.bucket_seconds, points: chart.rows } as any} series={chart.series.map((x: string) => ({ key: x, name: x }))} stack area height={200} />}
        <div className="grid gap-3 lg:grid-cols-3 mt-2">
          <TableWrap><table className="tbl"><thead><tr><th>Transport</th><th className="num">Traffic</th><th className="num">Flows</th><th className="num">Clients</th><th className="num">Servers</th></tr></thead>
            <tbody>{w.data.totals.map((t: any) => <tr key={t.series}><td className="text-xs">{t.series}</td><td className="num">{fmtBytes(t.bytes)}</td><td className="num">{fmtNum(t.flows)}</td>
              <td className="num">{fmtNum(t.sources)}</td><td className="num">{fmtNum(t.destinations)}</td></tr>)}
              <tr><td className="text-xs text-muted">HTTP/2 vs HTTP/1.1</td><td colSpan={4} className="text-2xs text-muted">not visible in flow records (TLS hides the negotiated protocol)</td></tr></tbody></table></TableWrap>
          <TableWrap><table className="tbl"><thead><tr><th>QUIC version (from samples)</th><th className="num">Traffic</th><th className="num">Flows</th></tr></thead>
            <tbody>{w.data.quic_versions.map((v: any) => <tr key={v.version}><td className="text-xs">{v.version}</td><td className="num">{fmtBytes(v.bytes)}</td><td className="num">{fmtNum(v.flows)}</td></tr>)}</tbody></table></TableWrap>
          <TableWrap><table className="tbl"><thead><tr><th>Top QUIC clients</th><th className="num">Traffic</th><th className="num">Servers</th></tr></thead>
            <tbody>{w.data.top_quic_clients.map((x: any) => <tr key={x.ip}><td><Ip ip={x.ip} nav={nav} /></td><td className="num">{fmtBytes(x.bytes)}</td><td className="num">{x.peers}</td></tr>)}</tbody></table></TableWrap>
        </div>
        <ul className="text-2xs text-muted list-disc pl-5 mt-2">{w.data.notes.map((x: string) => <li key={x}>{x}</li>)}</ul>
      </>}</Card>
  </div>;
}

// ------------------------------------------------------------------ talkers
function Talkers({ side, nav, sp, setSp }: { side: "sources" | "destinations"; nav: Nav; sp: URLSearchParams; setSp: (s: URLSearchParams) => void }) {
  const { f, go } = nav;
  const s = useSort(sp, setSp);
  const q = useT<any>(side === "sources" ? "top-sources" : "top-destinations", f, { sort: s.sortParam, limit: PAGE, offset: (s.page - 1) * PAGE });
  const sens = nav.opts?.permissions.sensitive;
  return <Card bodyClass="p-0" title={side === "sources" ? "Top sources" : "Top destinations"}
    right={<ExportLink view={side === "sources" ? "top-sources" : "top-destinations"} f={f} nav={nav} extra={{ sort: s.sortParam }} />}>
    <Loading q={q} />
    {q.data && (!q.data.items.length ? <Empty text="No traffic in this window." /> : <TableWrap maxH="max-h-[42rem]"><table className="tbl"><thead><tr>
      <th>{side === "sources" ? "Source" : "Destination"}</th><th>Host / device</th>{side === "sources" && sens && <th>MAC</th>}<th>VLAN · zone</th>
      <th>{side === "sources" ? "Switch port · site" : "Organisation · country"}</th><th>Top application</th>
      <SortTh k="bytes" label="Traffic" sort={s.sort} setSort={s.setSort} className="num" /><SortTh k="packets" label="Packets" sort={s.sort} setSort={s.setSort} className="num" />
      <SortTh k="flows" label="Flows" sort={s.sort} setSort={s.setSort} className="num" /><th className="num">Avg rate</th>
      <SortTh k="peak" label="Peak rate" sort={s.sort} setSort={s.setSort} className="num" /><SortTh k="peers" label={side === "sources" ? "Destinations" : "Sources"} sort={s.sort} setSort={s.setSort} className="num" />
      <SortTh k="last" label="Last seen" sort={s.sort} setSort={s.setSort} /></tr></thead>
      <tbody>{q.data.items.map((x: any) => <tr key={x.ip}>
        <td><Ip ip={x.ip} nav={nav} /><span className="text-2xs text-muted block">{x.direction_class}</span></td>
        <td className="text-xs">{x.device || x.hostname || (x.kind === "wireless-client" ? `Wi-Fi ${x.ssid}` : x.device_type || "—")}
          {(x.device_type || x.vendor) && (x.device || x.hostname || x.kind === "wireless-client") && <span className="text-2xs text-muted block">{[x.device_type, x.vendor].filter(Boolean).join(" · ")}</span>}
          {!x.device_type && x.vendor && <span className="text-2xs text-muted block">{x.vendor}</span>}
          {x.user && <span className="text-2xs text-muted block">{x.user}</span>}</td>
        {side === "sources" && sens && <td className="font-mono text-2xs" title="MAC seen with this address in samples (layer-2 next hop when routed)">{x.mac || "—"}</td>}
        <td className="text-xs">{x.vlan ? <button type="button" className="link" onClick={() => go({ vlan: x.vlan })}>{x.vlan}</button> : "—"}{x.zone && <span className="text-muted"> · {x.zone}</span>}</td>
        <td className="text-xs">{side === "sources" ? [x.switch && `${x.switch} ${x.port}`, x.site].filter(Boolean).join(" · ") || "—" : [x.as_org, x.country].filter(Boolean).join(" · ") || x.site || "—"}</td>
        <td className="text-xs">{x.top_app ? <button type="button" className="link" onClick={() => go({ tab: "conversations", app: x.top_app, [side === "sources" ? "src" : "dst"]: x.ip })}>{x.top_app}</button> : "—"}</td>
        <td className="num">{fmtBytes(x.bytes)}{x.sampled && <span className="text-2xs text-muted" title="sampled: estimate"> ≈</span>}</td>
        <td className="num">{fmtNum(x.packets)}</td><td className="num">{fmtNum(x.flows)}</td><td className="num">{fmtBps(x.avg_bps)}</td><td className="num">{fmtBps(x.peak_bps)}</td>
        <td className="num"><button type="button" className="link" onClick={() => go({ tab: "conversations", [side === "sources" ? "src" : "dst"]: x.ip })}>{fmtNum(x.peers)}</button></td>
        <td className="text-xs"><Time v={x.last} /></td></tr>)}</tbody></table></TableWrap>)}
    {q.data && <Pager page={s.page} size={PAGE} total={q.data.total} onPage={s.setPage} />}
    <Source d={q.data} />
  </Card>;
}

// ------------------------------------------------------------------ conversations / flows
function Conversations({ nav, sp, setSp }: { nav: Nav; sp: URLSearchParams; setSp: (s: URLSearchParams) => void }) {
  const { f, go } = nav;
  const s = useSort(sp, setSp);
  const q = useT<any>("conversations", f, { sort: s.sortParam, limit: PAGE, offset: (s.page - 1) * PAGE });
  const [sel, setSel] = useState<any>(null);
  return <Card bodyClass="p-0" title="Conversations" right={<ExportLink view="conversations" f={f} nav={nav} extra={{ sort: s.sortParam }} />}>
    <Loading q={q} />
    {q.data && (!q.data.items.length ? <Empty text="No conversations match these filters." /> : <TableWrap maxH="max-h-[42rem]"><table className="tbl"><thead><tr>
      <SortTh k="src" label="Source" sort={s.sort} setSort={s.setSort} /><th>Src VLAN</th><SortTh k="dst" label="Destination" sort={s.sort} setSort={s.setSort} /><th>Dst VLAN</th>
      <SortTh k="port" label="Service" sort={s.sort} setSort={s.setSort} /><SortTh k="app" label="Application" sort={s.sort} setSort={s.setSort} /><th>Confidence</th><th>Direction</th>
      <SortTh k="bytes" label="Traffic" sort={s.sort} setSort={s.setSort} className="num" /><SortTh k="packets" label="Packets" sort={s.sort} setSort={s.setSort} className="num" />
      <SortTh k="flows" label="Flows" sort={s.sort} setSort={s.setSort} className="num" /><SortTh k="peak" label="Peak rate" sort={s.sort} setSort={s.setSort} className="num" />
      <SortTh k="first" label="First" sort={s.sort} setSort={s.setSort} /><SortTh k="last" label="Last" sort={s.sort} setSort={s.setSort} /></tr></thead>
      <tbody>{q.data.items.map((c: any, i: number) => <tr key={i} {...rowProps(() => setSel(c))}>
        <td><Ip ip={c.src_ip} nav={nav} /><span className="text-2xs text-muted block">{c.src.device || c.src.hostname || c.src.network}</span></td>
        <td className="text-xs">{c.src_vlan ?? "—"}</td>
        <td><Ip ip={c.dst_ip} nav={nav} /><span className="text-2xs text-muted block">{c.dst.device || c.dst.hostname || c.dst.as_org || c.dst.network}</span></td>
        <td className="text-xs">{c.dst_vlan ?? "—"}</td><td className="font-mono text-xs">{c.proto_name}/{c.port}</td><td className="text-xs">{c.app}</td>
        <td><Conf c={c.confidence} /></td><td className="text-xs">{directionLabel(c.direction)}</td>
        <td className="num">{fmtBytes(c.bytes)}{c.sampled && <span className="text-2xs text-muted" title={`sampled 1:${c.sampling}: estimate`}> ≈</span>}</td>
        <td className="num">{fmtNum(c.packets)}</td><td className="num">{fmtNum(c.flows)}</td><td className="num">{fmtBps(c.peak_bps)}</td>
        <td className="text-xs"><Time v={c.first} /></td><td className="text-xs"><Time v={c.last} /></td></tr>)}</tbody></table></TableWrap>)}
    {q.data && <Pager page={s.page} size={PAGE} total={q.data.total} onPage={s.setPage} />}
    <Source d={q.data} />
    {sel && <Drawer title={`${sel.src_ip} → ${sel.dst_ip}`} onClose={() => setSel(null)}>
      <dl className="grid grid-cols-[9rem_1fr] gap-y-1 text-xs">
        {([["Service", `${sel.proto_name}/${sel.port}`], ["Application", sel.app], ["Category", sel.category], ["Confidence", CONFIDENCE[sel.confidence]?.label],
          ["Direction", directionLabel(sel.direction)], ["Traffic", fmtBytes(sel.bytes)], ["Packets", fmtNum(sel.packets)], ["Flows", fmtNum(sel.flows)],
          ["Average rate", fmtBps(sel.avg_bps)], ["Peak rate", fmtBps(sel.peak_bps)], ["Sampling", sel.sampled ? `1:${sel.sampling} (estimate)` : "unsampled / exact export"],
          ["Source", [sel.src.device, sel.src.hostname, sel.src.network, sel.src.site].filter(Boolean).join(" · ") || "—"],
          ["Source MAC / port", [sel.src.mac, sel.src.switch && `${sel.src.switch} ${sel.src.port}`].filter(Boolean).join(" · ") || "—"],
          ["Destination", [sel.dst.device, sel.dst.hostname, sel.dst.as_org, sel.dst.country, sel.dst.network].filter(Boolean).join(" · ") || "—"]] as [string, ReactNode][])
          .map(([k, v]) => <Fragment key={k}><dt className="text-muted">{k}</dt><dd>{v}</dd></Fragment>)}
      </dl>
      <div className="flex flex-wrap gap-2 mt-3">
        <button type="button" className="btn" onClick={() => { go({ tab: "flows", src: sel.src_ip, dst: sel.dst_ip, port: sel.port }); setSel(null); }}>Flow records</button>
        <button type="button" className="btn" onClick={() => { go({ src: sel.src_ip, dst: sel.dst_ip }); setSel(null); }}>Filter on this pair</button>
      </div>
    </Drawer>}
  </Card>;
}

function Flows({ nav, sp, setSp }: { nav: Nav; sp: URLSearchParams; setSp: (s: URLSearchParams) => void }) {
  const { f } = nav;
  const s = useSort(sp, setSp, "ts");
  const long = ["7d", "30d"].includes(f.range || "");
  const q = useT<any>("flows", f, { limit: 100, offset: (s.page - 1) * 100 }, !long);
  if (long) return <Card><Empty text="Individual flow records are listed for windows up to 24 hours. Choose a shorter range, or use Conversations." /></Card>;
  return <Card bodyClass="p-0" title="Flow records (newest first)">
    <Loading q={q} />
    {q.data && (!q.data.items.length ? <Empty text="No flow records match these filters." /> : <TableWrap maxH="max-h-[42rem]"><table className="tbl"><thead><tr>
      <th>Time</th><th>Device</th><th>In → out</th><th>Source</th><th>Destination</th><th>Proto</th><th>Application</th><th>Evidence</th><th className="num">Bytes</th>
      <th className="num">Packets</th><th>VLAN</th><th>Telemetry</th></tr></thead>
      <tbody>{q.data.items.map((r: any, i: number) => <tr key={i}>
        <td className="text-xs whitespace-nowrap"><Time v={r.ts} /></td><td className="text-xs">{r.device}</td><td className="text-xs font-mono">{r.in_if} → {r.out_if}</td>
        <td className="font-mono text-xs"><Ip ip={r.src_ip} nav={nav} />:{r.src_port}{r.src_mac && <span className="text-2xs text-muted block">{r.src_mac}</span>}</td>
        <td className="font-mono text-xs"><Ip ip={r.dst_ip} nav={nav} />:{r.dst_port}</td><td className="text-xs">{r.proto_name}</td>
        <td className="text-xs">{r.app} <Conf c={r.confidence} /></td><td className="text-2xs">{r.l7 || (r.tcp_flags ? `TCP flags 0x${r.tcp_flags.toString(16)}` : "—")}</td>
        <td className="num">{fmtBytes(r.bytes)}</td><td className="num">{fmtNum(r.packets)}</td><td className="text-xs">{r.vlan ?? "—"}</td>
        <td className="text-2xs">{r.version}{r.estimated ? ` · 1:${r.sampling} estimate` : " · exact"}</td></tr>)}</tbody></table></TableWrap>)}
    {q.data && <Pager page={s.page} size={100} hasMore={q.data.items.length === 100} onPage={s.setPage} />}
  </Card>;
}

// ------------------------------------------------------------------ VLANs / interfaces / domains
function Vlans({ nav }: { nav: Nav }) {
  const { f, go } = nav;
  const q = useT<any>("vlans", f);
  const m = useT<any>("vlan-matrix", f);
  const grid = useMemo(() => {
    const items = m.data?.items || [];
    const src = [...new Set(items.map((x: any) => x.src_vlan ?? 0))].slice(0, 20) as number[];
    const dst = [...new Set(items.map((x: any) => x.dst_vlan ?? 0))].slice(0, 20) as number[];
    const cell = new Map(items.map((x: any) => [`${x.src_vlan ?? 0}|${x.dst_vlan ?? 0}`, x]));
    const max = Math.max(1, ...items.map((x: any) => x.bytes));
    return { src, dst, cell, max };
  }, [m.data]);
  return <div className="space-y-3">
    <Card bodyClass="p-0" title="Traffic per VLAN" right={<ExportLink view="vlans" f={f} nav={nav} />}>
      <Loading q={q} />{q.data && (!q.data.items.length ? <Empty text="No traffic." /> : <TableWrap><table className="tbl"><thead><tr><th>VLAN</th><th>Name</th><th>Zone</th>
        <th className="num">Traffic</th><th className="num">East-west</th><th className="num">North-south</th><th className="num">Hosts</th><th className="num">Destinations</th><th>Top applications</th></tr></thead>
        <tbody>{q.data.items.map((v: any) => <tr key={v.vlan ?? 0}>
          <td>{v.vlan ? <button type="button" className="link" onClick={() => go({ vlan: v.vlan, tab: "conversations" })}>{v.vlan}</button> : <span className="text-muted">unknown</span>}</td>
          <td className="text-xs">{v.name || v.network || "—"}</td><td className="text-xs">{v.zone || "—"}</td><td className="num">{fmtBytes(v.bytes)}</td>
          <td className="num">{fmtBytes(v.east_west)}</td><td className="num">{fmtBytes(v.north_south)}</td><td className="num">{fmtNum(v.sources)}</td><td className="num">{fmtNum(v.destinations)}</td>
          <td className="text-xs">{v.top_apps.join(", ")}</td></tr>)}</tbody></table></TableWrap>)}
      {q.data && <ul className="text-2xs text-muted list-disc pl-8 py-2">{q.data.notes.map((x: string) => <li key={x}>{x}</li>)}</ul>}</Card>
    <Card title="Inter-VLAN communication matrix (source VLAN → destination VLAN)" right={<ExportLink view="vlan-matrix" f={f} nav={nav} />}>
      <Loading q={m} />
      {m.data && (!m.data.items.length ? <Empty text="No traffic between different VLANs in this window (or no VLAN information: configure network ranges with VLANs)." /> : <>
        <TableWrap><table className="tbl text-center"><thead><tr><th>from \ to</th>{grid.dst.map((d) => <th key={d}>{d || "no VLAN / external"}</th>)}</tr></thead>
          <tbody>{grid.src.map((sv) => <tr key={sv}><th className="text-left">{sv || "no VLAN"}</th>{grid.dst.map((dv) => {
            const c: any = grid.cell.get(`${sv}|${dv}`);
            if (!c) return <td key={dv} className="text-muted">·</td>;
            const deny = c.policy?.action === "deny";
            const alpha = 0.12 + 0.6 * (c.bytes / grid.max);
            return <td key={dv} title={`${fmtBytes(c.bytes)} · ${c.conversations} conversations · ${c.apps.join(", ")}${c.policy ? ` · policy: ${c.policy.name} (${c.policy.action})` : ""}`}
              style={{ background: deny ? `rgba(220,60,60,${alpha})` : `rgba(57,135,229,${alpha})` }}>
              <button type="button" className="text-xs w-full" onClick={() => go({ vlan: sv || null, tab: "conversations" })}>{fmtBytes(c.bytes)}{deny && " ⚠"}</button></td>;
          })}</tr>)}</tbody></table></TableWrap>
        <TableWrap maxH="max-h-80"><table className="tbl mt-3"><thead><tr><th>From</th><th>To</th><th className="num">Traffic</th><th className="num">Conversations</th><th>Applications</th><th>Policy</th><th>Last</th></tr></thead>
          <tbody>{m.data.items.map((x: any, i: number) => <tr key={i}><td className="text-xs">{x.src_vlan ?? "no VLAN"} {x.src_zone && <span className="text-muted">({x.src_zone})</span>}</td>
            <td className="text-xs">{x.dst_vlan ?? "no VLAN / external"} {x.dst_zone && <span className="text-muted">({x.dst_zone})</span>}</td><td className="num">{fmtBytes(x.bytes)}</td>
            <td className="num">{fmtNum(x.conversations)}</td><td className="text-xs">{x.apps.join(", ")}</td>
            <td className="text-xs">{x.policy ? <span className={x.policy.action === "deny" ? "text-red-300" : "text-emerald-300"}>{x.policy.action}: {x.policy.name}</span> : <span className="text-muted">no policy</span>}</td>
            <td className="text-xs"><Time v={x.last} /></td></tr>)}</tbody></table></TableWrap>
        <p className="text-2xs text-muted mt-1">Inter-VLAN traffic is normal; only pairs denied by a VLAN policy raise a detection.</p>
      </>)}</Card>
  </div>;
}

function Interfaces({ nav }: { nav: Nav }) {
  const { f, go } = nav;
  const q = useT<any>("interfaces", f);
  return <Card bodyClass="p-0" title="Interfaces (as each device reports them, not deduplicated)" right={<ExportLink view="interfaces" f={f} nav={nav} />}>
    <Loading q={q} />{q.data && (!q.data.items.length ? <Empty text="No interface information in the flow records of this window." /> :
      <TableWrap maxH="max-h-[42rem]"><table className="tbl"><thead><tr><th>Device</th><th>Interface</th><th>Description</th><th>Type</th><th className="num">Speed</th>
        <th className="num">Received</th><th className="num">Sent</th><th className="num">Avg in / out</th><th className="num">Utilisation</th><th className="num">Flows</th><th>Top applications</th><th>Counting</th></tr></thead>
        <tbody>{q.data.items.map((x: any) => <tr key={`${x.exporter}|${x.ifindex}`}>
          <td className="text-xs"><button type="button" className="link" onClick={() => go({ exporter: x.exporter })}>{x.device}</button>{x.site && <span className="text-muted"> · {x.site}</span>}</td>
          <td className="text-xs"><button type="button" className="link" onClick={() => go({ exporter: x.exporter, interface: x.ifindex, tab: "applications" })}>{x.name}</button></td>
          <td className="text-xs">{x.description || "—"}</td><td className="text-xs">{x.kind || "—"}</td><td className="num">{x.speed_bps ? fmtBps(x.speed_bps) : "—"}</td>
          <td className="num">{fmtBytes(x.rx_bytes)}</td><td className="num">{fmtBytes(x.tx_bytes)}</td><td className="num text-xs">{fmtBps(x.avg_rx_bps)} / {fmtBps(x.avg_tx_bps)}</td>
          <td className="num">{x.utilization_pct == null ? "—" : `${x.utilization_pct}%`}</td><td className="num">{fmtNum(x.flows)}</td>
          <td className="text-xs">{(x.top_apps || []).join(", ") || "—"}</td><td className="text-2xs text-muted">{x.counted || (x.sampled ? "sampled estimate" : "")}</td></tr>)}</tbody></table></TableWrap>)}
    {q.data && <p className="text-2xs text-muted px-3 pb-2">From {q.data.source}. LAG handling: {q.data.lag_mode === "members" ? "members counted, the LAG shows their sum" : "the logical LAG counted"}.
      Utilisation is the average over the window on the busier direction.</p>}
  </Card>;
}

function Domains({ nav, sp, setSp }: { nav: Nav; sp: URLSearchParams; setSp: (s: URLSearchParams) => void }) {
  const { f } = nav;
  const s = useSort(sp, setSp, "queries");
  const [search, setSearch] = useState("");
  const q = useT<any>("domains", f, { q: search, limit: PAGE, offset: (s.page - 1) * PAGE });
  return <Card bodyClass="p-0" title="DNS & domain intelligence" right={<input aria-label="Search domains" className="input py-0.5 text-xs w-48" placeholder="Search domain"
    onKeyDown={(e) => e.key === "Enter" && setSearch((e.target as HTMLInputElement).value.trim())} />}>
    <Loading q={q} />
    {q.data && !q.data.available && <Empty text={q.data.reason} />}
    {q.data?.available && (!q.data.items.length ? <Empty text="No DNS queries match." /> : <TableWrap maxH="max-h-[42rem]"><table className="tbl"><thead><tr><th>Domain</th><th>Application</th>
      <th className="num">Queries</th><th className="num">Clients</th><th>DNS servers</th><th>Types</th><th>Responses</th><th>Resolved addresses</th><th className="num">Associated traffic</th><th>Last</th></tr></thead>
      <tbody>{q.data.items.map((d: any) => <tr key={d.domain}><td className="font-mono text-xs break-all">{d.domain}</td><td className="text-xs">{d.app || "—"}</td>
        <td className="num">{fmtNum(d.queries)}</td><td className="num">{fmtNum(d.clients)}</td><td className="font-mono text-2xs">{d.servers.join(", ")}</td>
        <td className="text-2xs">{d.qtypes.join(", ")}</td><td className="text-2xs">{d.rcodes.join(", ")}</td>
        <td className="font-mono text-2xs">{d.resolved.slice(0, 4).map((ip: string) => <span key={ip} className="block"><Ip ip={ip} nav={nav} /></span>)}{d.resolved.length > 4 && `+${d.resolved.length - 4}`}</td>
        <td className="num">{fmtBytes(d.traffic_bytes)}{d.shared_addresses > 0 && <span className="text-2xs text-amber-300 block" title="shared CDN addresses: traffic counted for each name">shared</span>}</td>
        <td className="text-xs"><Time v={d.last} /></td></tr>)}</tbody></table></TableWrap>)}
    {q.data?.available && <Pager page={s.page} size={PAGE} total={q.data.total} onPage={s.setPage} />}
    {q.data?.notes && <ul className="text-2xs text-muted list-disc pl-8 py-2">{q.data.notes.map((x: string) => <li key={x}>{x}</li>)}</ul>}
  </Card>;
}

// ------------------------------------------------------------------ host drawer
function HostDrawer({ ip, nav, onClose }: { ip: string; nav: Nav; onClose: () => void }) {
  const q = useT<any>(`hosts/${encodeURIComponent(ip)}`, nav.f);
  const d = q.data;
  const chart = useMemo(() => d && pivot(d.trend.points), [d]);
  const id = d?.identity || {};
  const base = useQuery<any>({ queryKey: ["traffic-baseline", ip], queryFn: () => api(`/nms/traffic/baseline/${encodeURIComponent(ip)}`, { params: { hours: 48 } }),
    enabled: !!id.internal, staleTime: 300_000 });
  return <Drawer title={ip} onClose={onClose}>
    <Loading q={q} />
    {d && <div className="space-y-3 text-xs">
      {id.internal && <NetworkContext ip={ip} title="Identity" />}
      {base.data && base.data.points?.length > 0 && <Card title="Upload vs normal (by hour of day, 14-day baseline)">
        {base.data.learning ? <p className="text-muted">Learning: {base.data.history_days} of 5 days of history so far.</p> :
          <TimeChart data={{ bucket_seconds: 3600, points: base.data.points } as any} bytes height={170}
            series={[{ key: "bytes_out", name: "Upload", color: "primary" }, { key: "expected", name: "Usual (median)", color: "muted", dashed: true },
              { key: "expected_max", name: "Expected maximum", color: "warn", dashed: true }]} />}
      </Card>}
      <dl className="grid grid-cols-[8rem_1fr] gap-y-1">
        {([["Type", id.device_type || id.kind || (id.internal ? "internal host" : "external address")], ["Device / hostname", id.device || id.hostname || "—"],
          ["Manufacturer", id.randomized ? "private (randomised) MAC" : id.vendor || "—"], ["Site · network", [id.site, id.network].filter(Boolean).join(" · ") || "—"],
          ["VLAN · zone", [id.vlan, id.zone].filter(Boolean).join(" · ") || "—"], ["MAC", id.mac || "—"], ["Switch port", id.switch ? `${id.switch} ${id.port}` : "—"],
          ["Wireless", id.ssid ? `${id.ssid}${id.user ? ` · ${id.user}` : ""}` : "—"], ["ASN · organisation", id.asn ? `${id.asn} ${id.as_org}` : "—"], ["Country", id.country || "—"]] as [string, ReactNode][])
          .map(([k, v]) => <Fragment key={k}><dt className="text-muted">{k}</dt><dd>{v}</dd></Fragment>)}
      </dl>
      {d.enrichment && <Card title="Classification evidence"><p>{d.enrichment.app || "No application identified"} <Conf c={d.enrichment.confidence} /></p>
        <ul className="list-disc pl-5 mt-1">{(d.enrichment.evidence || []).map((e: string) => <li key={e}>{e}</li>)}</ul>
        {d.enrichment.domains?.length > 0 && <p className="text-2xs text-muted mt-1">Names: {d.enrichment.domains.slice(0, 8).join(", ")}</p>}</Card>}
      {chart && chart.rows.length > 0 && <TimeChart data={{ bucket_seconds: d.trend.bucket_seconds, points: chart.rows } as any} series={chart.series.map((x: string) => ({ key: x, name: x }))} stack area height={160} />}
      <MiniTable title="Applications" rows={d.applications} cols={[["app", "Application"], ["bytes", "Traffic"]]} />
      <MiniTable title="Talks to" rows={d.destinations} cols={[["ip", "Destination"], ["top_app", "Application"], ["bytes", "Traffic"]]} onIp={(x) => nav.host(x)} />
      <MiniTable title="Reached by" rows={d.sources} cols={[["ip", "Source"], ["top_app", "Application"], ["bytes", "Traffic"]]} onIp={(x) => nav.host(x)} />
      <div className="flex flex-wrap gap-2"><button type="button" className="btn" onClick={() => { nav.go({ ip, tab: "conversations" }); onClose(); }}>All conversations</button>
        <button type="button" className="btn" onClick={() => { nav.go({ ip, tab: "detections" }); onClose(); }}>Detections</button></div>
    </div>}
  </Drawer>;
}

function MiniTable({ title, rows, cols, onIp }: { title: string; rows: any[]; cols: [string, string][]; onIp?: (ip: string) => void }) {
  if (!rows?.length) return null;
  return <div><h3 className="font-semibold mb-1">{title}</h3><table className="tbl"><thead><tr>{cols.map(([, l]) => <th key={l}>{l}</th>)}</tr></thead>
    <tbody>{rows.slice(0, 8).map((r, i) => <tr key={i}>{cols.map(([k]) => <td key={k} className={k === "bytes" ? "num" : "text-xs"}>
      {k === "bytes" ? fmtBytes(r[k]) : k === "ip" && onIp ? <button type="button" className="link font-mono" onClick={() => onIp(r[k])}>{r[k]}</button> : r[k] || "—"}</td>)}</tr>)}</tbody></table></div>;
}

// ------------------------------------------------------------------ devices (shared identity index)
function Devices({ nav }: { nav: Nav }) {
  const [q, setQ] = useState("");
  const [type, setType] = useState("");
  const [page, setPage] = useState(1);
  const params: Record<string, any> = { q: q || undefined, device_type: type || undefined, vlan: nav.f.vlan || undefined, limit: PAGE, offset: (page - 1) * PAGE };
  const d = useQuery<any>({ queryKey: ["identity-devices", params], queryFn: () => api("/identities/devices", { params }), placeholderData: (p: any) => p });
  const types = Object.entries(d.data?.types || {}).sort((a: any, b: any) => b[1] - a[1]) as [string, number][];
  return <div className="space-y-3">
    {types.length > 0 && <div className="kpi-grid">{types.slice(0, 8).map(([t, n]) => <Kpi key={t} label={t} value={fmtNum(n)}
      onClick={() => { setType(t === "Unclassified" ? "" : t); setPage(1); }} />)}</div>}
    <Card bodyClass="p-0" title="Devices seen on the network" right={<div className="flex gap-2 items-center">
      <input aria-label="Search devices" className="input py-0.5 text-xs w-52" placeholder="Search vendor, type, IP, switch…" defaultValue={q}
        onKeyDown={(e) => { if (e.key === "Enter") { setQ((e.target as HTMLInputElement).value.trim()); setPage(1); } }} />
      {type && <button type="button" className="btn btn-sm" aria-label={`Clear filter ${type}`} onClick={() => setType("")}>{type} · clear</button>}</div>}>
      <Loading q={d} />
      {d.data && (!d.data.items.length ? <Empty text="No devices yet. The identity index fills every 5 minutes from wireless controllers, switch MAC tables, sFlow, FortiGate device detection, DHCP, VPN and logons." /> :
        <TableWrap maxH="max-h-[40rem]"><table className="tbl"><thead><tr><th>Device</th><th>Manufacturer</th><th>Last IP</th>{d.data.sensitive && <th>MAC</th>}
          <th>Connected to</th><th>VLAN</th><th>Site</th>{d.data.sensitive && <th>User / host</th>}<th>Evidence</th><th>Last seen</th></tr></thead>
          <tbody>{d.data.items.map((x: any, i: number) => <tr key={x.mac || i}>
            <td className="text-xs">{x.device_type || <span className="text-muted">Unclassified</span>} {x.confidence && <Conf c={x.confidence === "confirmed" ? "confirmed" : x.confidence === "high" ? "high" : "probable"}
              evidence={(x.evidence || []).join("; ")} />}</td>
            <td className="text-xs">{x.randomized ? <span className="text-muted">private MAC</span> : x.vendor || "—"}</td>
            <td><Ip ip={x.last_ip} nav={nav} /></td>
            {d.data.sensitive && <td className="mono">{x.mac}</td>}
            <td className="text-xs">{x.switch ? `${x.switch} · ${x.port}` : x.ssid ? `Wi-Fi ${x.ssid}${x.ap ? ` · ${x.ap}` : ""}` : "—"}</td>
            <td className="text-xs">{x.vlan ?? "—"}</td><td className="text-xs">{x.site || "—"}</td>
            {d.data.sensitive && <td className="text-xs">{[x.user, x.hostname].filter(Boolean).join(" · ") || "—"}</td>}
            <td className="text-2xs text-muted">{(x.sources || []).join(", ")}</td><td className="text-xs"><Time v={x.last_seen} /></td></tr>)}</tbody></table></TableWrap>)}
      {d.data && <Pager page={page} size={PAGE} total={d.data.total} onPage={setPage} />}
      <p className="text-2xs text-muted px-3 pb-2">Device types carry their evidence: confirmed (inventory), high (FortiGate device fingerprint), probable (manufacturer
        or behaviour). MACs that route for several addresses are network equipment and are never treated as a host.</p>
    </Card>
  </div>;
}
