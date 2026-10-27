import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useMe } from "../lib/context";
import { fmtNum } from "../lib/format";
import { Card, Empty, Kpi, Loading, TableWrap, Time, Trunc, rowProps, useDebounced } from "../components/ui";
import { Donut, TopBar } from "../components/charts";

export const STATE_LABEL: Record<string, string> = {
  in_use: "In use", no_observed_hits: "No observed hits", potentially_unused: "Potentially unused",
  unknown: "Unknown", disabled: "Disabled", not_assessable: "Not assessable",
};
export const STATE_CLASS: Record<string, string> = {
  in_use: "bg-emerald-700/30 text-emerald-200", no_observed_hits: "bg-amber-600/20 text-amber-200",
  potentially_unused: "bg-orange-600/30 text-orange-200", unknown: "bg-slate-700 text-slate-300",
  disabled: "bg-slate-800 text-slate-400", not_assessable: "bg-slate-800 text-slate-400",
};
export const SHADOW_LABEL: Record<string, string> = {
  full_shadow: "Full shadow", redundant: "Redundant", partial_shadow: "Partial shadow", overlap: "Overlap (unverified)",
};
const NA = <span className="text-slate-400" title="Not available from this data source">Not available</span>;

export function StateBadge({ a }: { a?: any }) {
  if (!a?.state) return <span className="text-slate-600">—</span>;
  return <span className={`pill ${STATE_CLASS[a.state] || ""}`} title={`${a.method} · confidence ${a.confidence}\n${(a.reasons || []).join("\n")}`}>{STATE_LABEL[a.state] || a.state}</span>;
}

export function Names({ list, max = 3 }: { list?: string[]; max?: number }) {
  const l = list || [];
  if (!l.length) return <span className="text-slate-600">—</span>;
  const shown = l.slice(0, max).join(", ") + (l.length > max ? ` +${l.length - max}` : "");
  return <span className="cell-trunc max-w-[14rem] font-mono text-xs" title={l.join(", ")}>{shown}</span>;
}

export function useScopes() {
  return useQuery({ queryKey: ["policy-scopes"], queryFn: () => api<any[]>("/v1/policies/scopes"), refetchInterval: 60_000 });
}

export function ScopeBar({ scope, setScope, window, setWindow }: { scope: string; setScope: (s: string) => void; window: number; setWindow: (n: number) => void }) {
  const me = useMe();
  const qc = useQueryClient();
  const scopes = useScopes();
  const sel = scopes.data?.find((s) => `${s.firewall_id}|${s.vdom}` === scope);
  const sync = useMutation({ mutationFn: (fw: number) => api<any>(`/v1/policies/sync/${fw}`, { method: "POST" }), onSuccess: () => qc.invalidateQueries() });
  return (
    <div className="flex flex-wrap items-end gap-2">
      <div><label className="label">Firewall / VDOM</label>
        <select aria-label="Firewall and VDOM" className="input" value={scope} onChange={(e) => setScope(e.target.value)}>
          <option value="">All firewalls</option>
          {(scopes.data || []).map((s) => <option key={`${s.firewall_id}|${s.vdom}`} value={`${s.firewall_id}|${s.vdom}`}>{s.firewall} / {s.vdom}{s.is_demo ? " (demo)" : ""}</option>)}
        </select></div>
      <div><label className="label">Observation window</label>
        <select aria-label="Observation window" className="input" value={window} onChange={(e) => setWindow(Number(e.target.value))}>
          {[7, 30, 60, 90].map((d) => <option key={d} value={d}>{d} days</option>)}
        </select></div>
      <div className="flex-1" />
      <div className="text-xs text-muted space-y-0.5 text-right">
        {(sel ? [sel] : scopes.data || []).slice(0, 4).map((s) => (
          <div key={`${s.firewall_id}|${s.vdom}`}>
            <b className="text-slate-300">{s.firewall}/{s.vdom}</b>: sync <span className={s.status === "ok" ? "text-emerald-400" : s.status === "error" ? "text-red-400" : "text-amber-300"}>{s.status}</span>
            {" · "}<Time v={s.last_success} />{" · "}counters {s.counters_supported ? <span className="text-emerald-400">available</span> : <span className="text-amber-300">not available</span>}
            {s.error && <div className="text-red-400 cell-trunc max-w-[36rem] ml-auto" title={s.error}>{s.error}</div>}
            {me.role === "admin" && !s.is_demo && <button className="link ml-2" disabled={sync.isPending} onClick={() => sync.mutate(s.firewall_id)}>{sync.isPending ? "syncing…" : "sync now"}</button>}
          </div>))}
      </div>
    </div>
  );
}

export function scopeParams(scope: string) {
  if (!scope) return {};
  const [fw, vdom] = scope.split("|");
  return { firewall_id: Number(fw), vdom };
}

export function Policies() {
  const nav = useNavigate();
  const [scope, setScope] = useState("");
  const [win, setWin] = useState(30);
  const [f, setF] = useState<Record<string, string>>({});
  const df = useDebounced(f, 400);
  const [page, setPage] = useState(1);
  const [sort, setSort] = useState("seq");
  const [order, setOrder] = useState<"asc" | "desc">("asc");
  const sp = scopeParams(scope);
  const summary = useQuery({ queryKey: ["policy-summary", scope, win], queryFn: () => api<any>("/v1/policies/summary", { params: { window_days: win, ...sp } }) });
  const inv = useQuery({ queryKey: ["policy-inv", scope, win, df, page, sort, order],
    queryFn: () => api<any>("/v1/policies", { params: { window_days: win, ...sp, ...df, page, size: 50, sort, order } }), placeholderData: (p) => p });
  const s = summary.data || {};
  const setFilter = (k: string, v: string) => { setPage(1); setF((x) => ({ ...x, [k]: v })); };
  const assessDist = useMemo(() => {
    const rows = [["In use", s.in_use], ["No observed hits", (s.no_observed_hits || 0) - (s.potentially_unused || 0)], ["Potentially unused", s.potentially_unused],
      ["Unknown", s.unknown], ["Disabled", s.disabled]];
    return rows.filter(([, v]) => v).map(([key, events]) => ({ key, events }));
  }, [s]);
  const th = (k: string, label: string, cls = "") => (
    <th className={`cursor-pointer select-none ${cls}`} onClick={() => { if (sort === k) setOrder(order === "asc" ? "desc" : "asc"); else { setSort(k); setOrder(k === "seq" ? "asc" : "desc"); } }}>
      {label}{sort === k ? (order === "asc" ? " ▲" : " ▼") : ""}</th>);
  const pages = inv.data ? Math.max(1, Math.ceil(inv.data.total / inv.data.size)) : 1;

  return (
    <div className="space-y-4 min-w-0">
      <ScopeBar scope={scope} setScope={(v) => { setScope(v); setPage(1); }} window={win} setWindow={setWin} />
      <p className="text-xs text-muted">Read-only analysis. <b>Firewall hits</b> = FortiGate per-policy counters (deltas between snapshots). <b>SIEM matches</b> = ingested traffic logs whose policy ID/UUID match. The two describe the same traffic and are never added together. "Not available" means the source does not provide the value; it is not zero.</p>
      <Loading q={summary} />
      <div className="kpi-grid">
        <Kpi label="Configured policies" value={fmtNum(s.total)} />
        <Kpi label="Enabled" value={fmtNum(s.enabled)} tone="ok" onClick={() => setFilter("status", "enable")} />
        <Kpi label="Disabled" value={fmtNum(s.disabled)} onClick={() => setFilter("status", "disable")} />
        <Kpi label="With observed traffic" value={fmtNum(s.in_use)} tone="ok" onClick={() => setFilter("assessment", "in_use")} />
        <Kpi label={`No observed hits (${win} d)`} value={fmtNum(s.no_observed_hits)} tone={s.no_observed_hits ? "warn" : undefined} onClick={() => setFilter("assessment", "no_observed_hits")} sub={`${fmtNum(s.potentially_unused)} potentially unused`} />
        <Kpi label="Zero firewall counter" value={s.counters_available ? fmtNum(s.zero_counter) : "N/A"} sub={s.counters_available ? "enabled, no counted hits" : "counters not available"} />
        <Kpi label="No logging" value={fmtNum(s.no_logging)} tone={s.no_logging ? "warn" : undefined} onClick={() => setFilter("logging", "disable")} />
        <Kpi label="Potentially shadowed" value={fmtNum(s.shadowed)} tone={s.shadowed ? "bad" : undefined} sub={`${fmtNum(s.with_findings)} with any finding`} onClick={() => nav("/policies/shadow")} />
        <Kpi label={`Changed (${win} d)`} value={fmtNum(s.changed)} />
        <Kpi label="Insufficient telemetry" value={fmtNum(s.unknown)} onClick={() => setFilter("assessment", "unknown")} />
      </div>
      <div className="grid-cards lg:grid-cols-3">
        <Card title="Usage assessment">{assessDist.length ? <Donut rows={assessDist} label="Assessment" height={190} /> : <Empty />}</Card>
        <Card title="Top policies by observed log events (SIEM)">{s.top_by_events?.length ? <TopBar height={220} rows={s.top_by_events} labelFn={(r) => `#${r.policyid} ${r.name}`} /> : <Empty text="No matching traffic logs in this window." />}</Card>
        <Card title="Top policies by bytes">{s.top_by_bytes?.length ? <TopBar height={220} rows={s.top_by_bytes} bytes labelFn={(r) => `#${r.policyid} ${r.name}`} /> : <Empty />}
          {s.top_by_bytes?.length > 0 && <p className="text-2xs text-muted mt-1">Source per policy: {Array.from(new Set(s.top_by_bytes.map((r: any) => r.source))).join(", ")}</p>}</Card>
      </div>
      <Card title={`Policy inventory (${fmtNum(inv.data?.total)})`} right={
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <button className="btn" disabled={page <= 1} onClick={() => setPage(page - 1)}>‹</button><span className="text-muted">{page} / {pages}</span>
          <button className="btn" disabled={page >= pages} onClick={() => setPage(page + 1)}>›</button>
        </div>}>
        <div className="grid gap-2 grid-cols-2 md:grid-cols-4 xl:grid-cols-8 mb-3">
          {[["q", "ID / name / UUID"], ["srcintf", "Source interface"], ["dstintf", "Destination interface"], ["addr", "Address object"], ["service", "Service"]].map(([k, l]) => (
            <div key={k}><label className="label">{l}</label><input className="input w-full" value={f[k] || ""} onChange={(e) => setFilter(k, e.target.value)} /></div>))}
          {[["action", "Action", ["accept", "deny"]], ["status", "Status", ["enable", "disable"]], ["logging", "Logging", ["all", "utm", "disable"]],
            ["assessment", "Assessment", Object.keys(STATE_LABEL)], ["shadow", "Shadow", ["any", ...Object.keys(SHADOW_LABEL)]]].map(([k, l, opts]) => (
            <div key={k as string}><label className="label">{l as string}</label>
              <select className="input w-full" value={f[k as string] || ""} onChange={(e) => setFilter(k as string, e.target.value)}>
                <option value="">any</option>{(opts as string[]).map((o) => <option key={o} value={o}>{STATE_LABEL[o] || SHADOW_LABEL[o] || o}</option>)}
              </select></div>))}
          <div className="flex items-end"><button className="btn w-full justify-center" onClick={() => { setF({}); setPage(1); }}>Clear</button></div>
        </div>
        <Loading q={inv} />
        {inv.data && !inv.data.items.length && <Empty text={summary.data?.total ? "No policies match the filters." : "No policies collected yet. Policies are collected every 15 minutes from firewalls with an API token (read-only)."} />}
        {!!inv.data?.items.length && <TableWrap><table className="tbl">
          <thead><tr>{th("firewall", "Firewall / VDOM")}{th("seq", "Seq", "num")}{th("policyid", "ID", "num")}{th("name", "Name")}<th>Source</th><th>Destination</th><th>Service</th><th>Action</th><th>Status</th>
            {th("firewall_hits", "Firewall hits", "num")}{th("siem_matches", "SIEM matches", "num")}{th("last_seen", "Last seen")}<th>Logging</th><th>Assessment</th><th>Shadow</th></tr></thead>
          <tbody>{inv.data.items.map((r: any) => (
            <tr key={`${r.firewall_id}|${r.vdom}|${r.policyid}`} {...rowProps(() => nav(`/policies/${r.firewall_id}/${encodeURIComponent(r.vdom)}/${r.policyid}`))}>
              <td className="text-xs nowrap">{r.firewall}<div className="text-muted">{r.vdom}{r.source === "demo" && <span className="pill bg-amber-600/30 text-amber-200 ml-1">demo</span>}</div></td>
              <td className="num">{r.seq}</td><td className="num font-mono">{r.policyid}</td>
              <td className="min-w-[9rem]"><Trunc text={r.name || "(unnamed)"} max="max-w-[14rem]" /></td>
              <td><Names list={r.srcaddr} /><div className="text-2xs text-muted"><Names list={r.srcintf} max={2} /></div></td>
              <td><Names list={r.dstaddr} /><div className="text-2xs text-muted"><Names list={r.dstintf} max={2} /></div></td>
              <td><Names list={r.service} /></td>
              <td className={`nowrap font-medium ${r.action === "accept" ? "text-emerald-400" : "text-red-400"}`}>{r.action}</td>
              <td className="nowrap text-xs">{r.status === "enable" ? "enabled" : <span className="text-slate-400">disabled</span>}</td>
              <td className="num">{r.firewall_hits == null ? NA : fmtNum(r.firewall_hits)}</td>
              <td className="num">{r.siem_matches == null ? NA : fmtNum(r.siem_matches)}</td>
              <td className="text-xs">{r.last_seen ? <Time v={r.last_seen} /> : <span className="text-slate-400">never observed</span>}</td>
              <td className={`nowrap text-xs ${r.logtraffic === "disable" ? "text-amber-300" : ""}`}>{r.logtraffic}</td>
              <td className="nowrap"><StateBadge a={r.assessment} /></td>
              <td className="nowrap text-xs">{r.analysis?.worst ? <span className={r.analysis.worst === "full_shadow" ? "text-red-300" : "text-amber-200"}>{SHADOW_LABEL[r.analysis.worst]}</span> : r.analysis?.analysis === "unknown" ? <span className="text-slate-400">unknown</span> : "—"}</td>
            </tr>))}</tbody></table></TableWrap>}
      </Card>
    </div>
  );
}
