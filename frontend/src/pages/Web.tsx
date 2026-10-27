import { useState } from "react";
import { useData, useGlobal } from "../lib/context";
import { downloadUrl } from "../lib/api";
import { fmtNum } from "../lib/format";
import { Card, IpLink, Kpi, LimitSelect, Loading, NoData, rowProps, useDebounced, useExplore } from "../components/ui";
import { Donut, TimeChart } from "../components/charts";

export function UrlCell({ r }: { r: any }) {
  if (r.url_is_full) return <span className="font-mono text-xs cell-wrap" title="Full URL as logged">{r.url}</span>;
  return (
    <span className="font-mono text-xs cell-wrap">
      <span>{r.hostname || <span className="text-slate-600">(no hostname)</span>}</span>
      {r.url ? <span className="text-slate-400" title="Path logged separately from hostname; not a reconstructed URL"> · path {r.url}</span>
        : <span className="pill bg-slate-800 text-slate-400 ml-1">hostname only</span>}
    </span>
  );
}

export function Web() {
  const [limit, setLimit] = useState(25);
  const [domain, setDomain] = useState("");
  const [src, setSrc] = useState("");
  const g = useGlobal();
  const dDomain = useDebounced(domain);
  const dSrc = useDebounced(src);
  const srcValid = !dSrc || /^[0-9a-fA-F:.]+(\/\d{1,3})?$/.test(dSrc);
  const q = useData<any>("/analytics/web", { limit, domain: dDomain || undefined, src_ip: srcValid ? dSrc || undefined : undefined });
  const explore = useExplore();
  const d = q.data;
  const t = d?.totals || {};
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2 items-end">
        <div><label className="label">Domain</label><input className="input" aria-label="Domain" placeholder="example.com" value={domain} onChange={(e) => setDomain(e.target.value.trim())} /></div>
        <div><label className="label">Source IP</label><input className={`input ${srcValid ? "" : "border-red-500"}`} aria-invalid={!srcValid} placeholder="10.0.0.5" value={src} onChange={(e) => setSrc(e.target.value.trim())} /></div>
        <LimitSelect value={limit} onChange={setLimit} />
        <a className="btn" href={downloadUrl("/events/export.csv", { ...g.params, category: "web", domain: dDomain || undefined, src_ip: srcValid ? dSrc || undefined : undefined })}>Export CSV</a>
      </div>
      <Loading q={q} />
      <div className="kpi-grid">
        <Kpi label="Web events" value={fmtNum(t.events)} />
        <Kpi label="Blocked" value={fmtNum(t.blocked)} tone="bad" onClick={() => explore({ category: "web", action: "block" })} />
        <Kpi label="Allowed" value={fmtNum(t.allowed)} tone="ok" />
        <Kpi label="Full URLs logged" value={fmtNum(t.full_urls)} />
        <Kpi label="Hostname + path" value={fmtNum(t.path_only)} sub="path logged separately" />
        <Kpi label="Hostname only" value={fmtNum(t.hostname_only)} />
      </div>
      <div className="grid-cards xl:grid-cols-5">
        <Card title="Blocked vs allowed web requests over time" className="xl:col-span-3"><TimeChart data={d?.timeseries} loading={q.isLoading} stack series={[{ key: "allowed", name: "Allowed", color: "primary" }, { key: "blocked", name: "Blocked", color: "alert" }]} /></Card>
        <Card title="URL category distribution" className="xl:col-span-2">{d?.categories?.length ? <Donut rows={d.categories} keyField="cat_name" label="Category" max={7}
          onClick={(c) => explore({ category: "web", url_category: c === "(uncategorized)" ? undefined : c })} /> : <NoData category="web" what="web-filter" />}</Card>
      </div>
      <Card title="Top accessed URLs / hostnames">
        {d?.top_urls?.length ? <div className="tbl-wrap"><table className="tbl">
          <thead><tr><th>URL (as logged)</th><th>Category</th><th className="num">Events</th><th className="num">Blocked</th><th className="num">Clients</th></tr></thead>
          <tbody>{d.top_urls.map((r: any, i: number) => (
            <tr key={`${r.hostname}|${r.url}|${i}`} {...rowProps(() => explore({ category: "web", domain: r.hostname || undefined }))}>
              <td className="min-w-[14rem]"><UrlCell r={r} /></td><td className="text-xs min-w-[8rem]">{r.url_cat || "—"}</td><td className="num">{fmtNum(r.events)}</td>
              <td className="num text-red-400">{fmtNum(r.blocked)}</td><td className="num">{fmtNum(r.clients)}</td></tr>))}</tbody>
        </table></div> : <NoData category="web" what="web-filter" />}
      </Card>
      <div className="grid-cards xl:grid-cols-2">
        <Card title="Top domains">{d?.top_domains?.length ? <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Domain</th><th className="num">Events</th><th className="num">Blocked</th><th className="num">Clients</th></tr></thead>
          <tbody>{d.top_domains.map((r: any) => <tr key={r.domain}><td className="font-mono cell-wrap"><button className="link" onClick={() => setDomain(r.domain)}>{r.domain}</button></td><td className="num">{fmtNum(r.events)}</td><td className="num text-red-400">{fmtNum(r.blocked)}</td><td className="num">{fmtNum(r.clients)}</td></tr>)}</tbody></table></div> : <NoData category="web" what="web-filter" />}</Card>
        <Card title="Top source IPs by web activity">{d?.top_sources?.length ? <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Source</th><th className="num">Events</th><th className="num">Blocked</th><th className="num">Hosts</th></tr></thead>
          <tbody>{d.top_sources.map((r: any) => <tr key={r.src_ip}><td><IpLink ip={r.src_ip} /> <button className="link text-xs ml-2" onClick={() => setSrc(r.src_ip)}>filter</button></td><td className="num">{fmtNum(r.events)}</td><td className="num text-red-400">{fmtNum(r.blocked)}</td><td className="num">{fmtNum(r.hosts)}</td></tr>)}</tbody></table></div> : <NoData category="web" what="web-filter" />}</Card>
      </div>
    </div>
  );
}
