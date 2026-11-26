/** All monitored interfaces across every device (/api/devices/interfaces): quick filters, search, filters, sorting,
 *  paging, column choice, bulk alert on / off and CSV export. Logical (LAG, VLAN, tunnel) and physical interfaces can be
 *  viewed apart, so aggregate and member traffic are never added together. */
import { useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, downloadUrl } from "../../lib/api";
import { useMe } from "../../lib/context";
import { Card, Empty, Loading, Pager, SortTh, TableWrap, Time, rowProps, useDebounced } from "../../components/ui";
import { Bps, Oper, Util } from "../switches/common";

const QUICK: [string, string][] = [["", "All"], ["down", "Down"], ["high_util", "High utilisation"], ["errors", "Errors"], ["discards", "Discards"],
  ["no_data", "No data"], ["changed", "Changed in 24 h"], ["unmonitored", "Alerts off"]];
const OPTIONAL: [string, string][] = [["site", "Site"], ["kind", "Kind"], ["speed", "Speed"], ["errors", "Errors"], ["discards", "Discards"], ["changed", "Last change"]];
const COLS_KEY = "sentinel.interfaces.cols";
const SIZE = 100;

function savedCols(): Set<string> {
  try { const v = JSON.parse(localStorage.getItem(COLS_KEY) || "null"); if (Array.isArray(v)) return new Set(v); } catch { /* default */ }
  return new Set(OPTIONAL.map(([k]) => k));
}

export function InterfacesPage() {
  const me = useMe();
  const nav = useNavigate();
  const qc = useQueryClient();
  const [sp, setSp] = useSearchParams();
  const set = (k: string, v: string) => { const n = new URLSearchParams(sp); if (v) n.set(k, v); else n.delete(k); n.delete("page"); setSp(n, { replace: true }); };
  const quick = sp.get("quick") || "", layer = sp.get("layer") || "", dtype = sp.get("type") || "", site = sp.get("site") || "";
  const page = Number(sp.get("page") || 1);
  const [q, setQ] = useState(sp.get("q") || "");
  const dq = useDebounced(q, 300);
  const [sort, setSort] = useState({ key: "util", desc: true });
  const [cols, setCols] = useState<Set<string>>(savedCols);
  const [sel, setSel] = useState<Set<string>>(new Set());
  const [colMenu, setColMenu] = useState(false);
  const meta = useQuery<any>({ queryKey: ["devices-meta"], queryFn: () => api("/devices/meta"), staleTime: 300_000 });
  const params = { q: dq || undefined, quick: quick || undefined, layer: layer || undefined, device_type: dtype || undefined, site: site || undefined };
  const r = useQuery<any>({ queryKey: ["all-ifs", params, sort, page], placeholderData: (p: any) => p, refetchInterval: 60_000,
    queryFn: ({ signal }) => api("/devices/interfaces", { signal, params: { ...params, sort: sort.key, desc: sort.desc, limit: SIZE, offset: (page - 1) * SIZE } }) });
  const sites = useMemo(() => [...new Set<string>((r.data?.items || []).map((x: any) => x.site).filter(Boolean))].sort(), [r.data]);
  const bulk = useMutation({ mutationFn: async (monitored: boolean) => { for (const k of sel) { const [s, i] = k.split(":"); await api(`/devices/${s}/interfaces/${i}`, { method: "PATCH", body: { monitored } }); } },
    onSuccess: () => { setSel(new Set()); qc.invalidateQueries({ queryKey: ["all-ifs"] }); } });
  const toggleCol = (k: string) => { const n = new Set(cols); if (n.has(k)) n.delete(k); else n.add(k); setCols(n); try { localStorage.setItem(COLS_KEY, JSON.stringify([...n])); } catch { /* ignore */ } };
  const items: any[] = r.data?.items || [];
  const key = (x: any) => `${x.switch_id}:${x.ifindex}`;
  const allOn = items.length > 0 && items.every((x) => sel.has(key(x)));
  const show = (k: string) => cols.has(k);
  return <div className="space-y-3 min-w-0">
    <div className="flex flex-wrap items-center gap-2">
      <h1 className="page-title mr-2">Interfaces</h1>
      <div className="flex flex-wrap gap-1" role="group" aria-label="Quick filters">{QUICK.map(([k, l]) =>
        <button key={k} type="button" className={`btn btn-sm ${quick === k ? "border-line-strong text-slate-100 bg-hover" : "text-muted"}`} aria-pressed={quick === k} onClick={() => set("quick", k)}>{l}</button>)}</div>
    </div>
    <Card bodyClass="p-0" title={`${r.data ? r.data.total.toLocaleString() : "…"} interfaces`} right={<>
      <input aria-label="Search interfaces" className="input py-1 w-44" placeholder="Name / description" value={q} onChange={(e) => { setQ(e.target.value); set("q", e.target.value); }} />
      <select aria-label="Layer" className="input py-1" value={layer} onChange={(e) => set("layer", e.target.value)}>
        <option value="">Physical and logical</option><option value="physical">Physical only</option><option value="logical">Logical only (LAG, VLAN, tunnel)</option></select>
      <select aria-label="Device type" className="input py-1" value={dtype} onChange={(e) => set("type", e.target.value)}>
        <option value="">All device types</option>{(meta.data?.device_types || []).map((t: any) => <option key={t.key} value={t.key}>{t.label}</option>)}</select>
      {sites.length > 1 && <select aria-label="Site" className="input py-1" value={site} onChange={(e) => set("site", e.target.value)}><option value="">All sites</option>{sites.map((s) => <option key={s}>{s}</option>)}</select>}
      <div className="relative"><button type="button" className="btn btn-sm" aria-expanded={colMenu} onClick={() => setColMenu(!colMenu)}>Columns</button>
        {colMenu && <div className="absolute right-0 z-20 mt-1 w-44 rounded-md border border-line bg-elevated p-2 shadow-pop">{OPTIONAL.map(([k, l]) =>
          <label key={k} className="flex items-center gap-2 py-0.5 text-xs"><input type="checkbox" checked={cols.has(k)} onChange={() => toggleCol(k)} />{l}</label>)}</div>}</div>
      <a className="btn btn-sm" href={downloadUrl("/devices/interfaces/export.csv", params)}>Export CSV</a></>}>
      {me.role === "admin" && sel.size > 0 && <div className="flex items-center gap-2 px-4 py-2 border-b border-line text-xs">
        <span>{sel.size} selected</span><button className="btn btn-sm" disabled={bulk.isPending} onClick={() => bulk.mutate(false)}>Turn alerts off</button>
        <button className="btn btn-sm" disabled={bulk.isPending} onClick={() => bulk.mutate(true)}>Turn alerts on</button>
        <button className="btn btn-ghost btn-sm" onClick={() => setSel(new Set())}>Clear</button>{bulk.error && <span className="text-red-400">{(bulk.error as Error).message}</span>}</div>}
      <Loading q={r} />
      {r.data && (!items.length ? <div className="p-4"><Empty text="No interfaces match these filters." /></div> :
        <TableWrap><table className="tbl"><thead><tr>
          {me.role === "admin" && <th className="w-8"><input type="checkbox" aria-label="Select all on this page" checked={allOn}
            onChange={() => setSel(allOn ? new Set() : new Set(items.map(key)))} /></th>}
          <SortTh k="device" label="Device" sort={sort} setSort={setSort} />{show("site") && <th>Site</th>}<SortTh k="name" label="Interface" sort={sort} setSort={setSort} />
          {show("kind") && <th>Kind</th>}<th>Status</th>{show("speed") && <SortTh k="speed" label="Speed" sort={sort} setSort={setSort} className="num" />}
          <SortTh k="traffic" label="In" sort={sort} setSort={setSort} className="num" /><th className="num">Out</th>
          <SortTh k="util" label="Util in" sort={sort} setSort={setSort} className="num" /><th className="num">Util out</th>
          {show("errors") && <SortTh k="errors" label="Errors" sort={sort} setSort={setSort} className="num" />}
          {show("discards") && <SortTh k="discards" label="Discards" sort={sort} setSort={setSort} className="num" />}
          {show("changed") && <SortTh k="changed" label="Last change" sort={sort} setSort={setSort} />}</tr></thead>
          <tbody>{items.map((x) => <tr key={key(x)} {...rowProps(() => nav(`/switches/${x.switch_id}/interfaces/${x.ifindex}`))}>
            {me.role === "admin" && <td onClick={(e) => e.stopPropagation()}><input type="checkbox" aria-label={`Select ${x.switch} ${x.name}`} checked={sel.has(key(x))}
              onChange={() => { const n = new Set(sel); if (n.has(key(x))) n.delete(key(x)); else n.add(key(x)); setSel(n); }} /></td>}
            <td className="whitespace-nowrap"><Link to={`/switches/${x.switch_id}`} className="link" onClick={(e) => e.stopPropagation()}>{x.switch}</Link></td>
            {show("site") && <td className="text-muted">{x.site || "—"}</td>}
            <td><span className="mono">{x.name}</span>{x.alias && <span className="text-subtle"> · {x.alias}</span>}{x.monitored === false && <span className="pill text-subtle ml-1">alerts off</span>}</td>
            {show("kind") && <td className="text-muted">{x.kind || "—"}{x.lag_ifindex ? " (member)" : ""}</td>}
            <td><Oper s={x.oper} /></td>{show("speed") && <td className="num"><Bps v={x.speed_bps} /></td>}
            <td className="num"><Bps v={x.rx_bps} /></td><td className="num"><Bps v={x.tx_bps} /></td><td className="num"><Util v={x.rx_util} /></td><td className="num"><Util v={x.tx_util} /></td>
            {show("errors") && <td className={`num ${(x.in_errors || 0) + (x.out_errors || 0) + (x.crc || 0) ? "text-amber-300" : ""}`}>{x.in_errors == null && x.out_errors == null ? "—" : (x.in_errors || 0) + (x.out_errors || 0) + (x.crc || 0)}</td>}
            {show("discards") && <td className="num">{x.discards ?? "—"}</td>}
            {show("changed") && <td><Time v={x.last_change_at} /></td>}
          </tr>)}</tbody></table></TableWrap>)}
      {r.data && <Pager page={page} size={SIZE} total={r.data.total} onPage={(p) => { const n = new URLSearchParams(sp); n.set("page", String(p)); setSp(n); }} />}
    </Card>
    <p className="text-2xs text-subtle">Rates are from the last two valid polls (64-bit counters where the device has them). "—" means no valid sample yet, a counter reset or
      an unknown speed. Logical interfaces (port-channels, VLAN interfaces, tunnels) carry the same traffic as their members: filter by layer instead of adding them up.</p>
  </div>;
}
