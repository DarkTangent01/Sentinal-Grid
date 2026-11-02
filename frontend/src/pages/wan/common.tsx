import { ReactNode, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { availText, dur, rangeParams, toLocalInput } from "./fmt";

export { availText, dur, ms, pct, rangeParams, stackedDaily, STATE_ORDER } from "./fmt";

export function useWanMeta() {
  return useQuery({ queryKey: ["wan-meta"], queryFn: () => api<any>("/wan/meta"), staleTime: 120_000 });
}

/** One palette for target / circuit state on every WAN page (live table, circuits, overview, history). */
const STATE: Record<string, [string, string]> = {
  up: ["bg-emerald-400", "Up"], down: ["bg-red-500 animate-pulse", "Down"], degraded: ["bg-amber-400", "Degraded"],
  unknown: ["bg-slate-500", "Unknown"], paused: ["bg-slate-700 ring-1 ring-slate-500", "Paused"], disabled: ["bg-slate-700", "Paused"],
};
export const STATE_HEX: Record<string, string> = { up: "#34d399", down: "#ef4444", degraded: "#fbbf24", unknown: "#64748b", paused: "#475569" };

export function StateDot({ s }: { s: string }) {
  const [c, l] = STATE[s] || STATE.unknown;
  return <span className="inline-flex items-center gap-1.5 whitespace-nowrap"><span className={`h-2.5 w-2.5 rounded-full ${c}`} aria-hidden />{l}</span>;
}

const INC: Record<string, string> = {
  open: "bg-red-500/15 text-red-300", in_progress: "bg-amber-500/15 text-amber-300", monitoring: "bg-sky-500/15 text-sky-300",
  resolved: "bg-emerald-500/15 text-emerald-300", closed: "bg-slate-700/60 text-slate-300",
};
const INC_LABEL: Record<string, string> = { open: "Open", in_progress: "Investigating", monitoring: "Monitoring", resolved: "Resolved", closed: "Closed" };
export function IncStatus({ s }: { s: string }) {
  return <span className={`pill ${INC[s] || INC.closed}`}>{INC_LABEL[s] || s}</span>;
}

export function Avail({ v, target, coverage }: { v?: number | null; target?: number | null; coverage?: number | null }) {
  if (v == null) return <span className="text-slate-600" title="no observations in this range">—</span>;
  const bad = target != null ? v < target : v < 99.9;
  const low = coverage != null && coverage < 90;
  return <span className={`tabular-nums ${bad ? "text-red-300" : "text-emerald-300"}`}
    title={`${target != null ? `target ${target}%; ` : ""}${coverage != null ? `observed ${coverage.toFixed(1)}% of the time` : ""}`}>
    {availText(v)}{low && <span className="text-amber-300 text-2xs" title="low coverage: part of the range was not observed">*</span>}</span>;
}

export function Dur({ s }: { s?: number | null }) {
  return s == null ? <span className="text-slate-600">—</span> : <span className="tabular-nums">{dur(s)}</span>;
}

export type Range = { range: string; start?: string; end?: string };
export const RANGE_OPTS: [string, string][] = [["1h", "Last hour"], ["6h", "Last 6 hours"], ["24h", "Last 24 hours"], ["7d", "Last 7 days"], ["30d", "Last 30 days"], ["custom", "Custom…"]];

export function RangePicker({ value, onChange, extra = [] }: { value: Range; onChange: (r: Range) => void; extra?: [string, string][] }) {
  const opts = [...RANGE_OPTS.slice(0, -1), ...extra, RANGE_OPTS[RANGE_OPTS.length - 1]];
  return <span className="inline-flex flex-wrap items-center gap-1">
    <select aria-label="Time range" className="input py-1" value={value.range}
      onChange={(e) => onChange(e.target.value === "custom" ? { range: "custom", start: toLocalInput(new Date(Date.now() - 86400e3).toISOString()), end: toLocalInput(new Date().toISOString()) } : { range: e.target.value })}>
      {opts.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
    {value.range === "custom" && <>
      <input aria-label="From" type="datetime-local" className="input py-1" value={value.start || ""} onChange={(e) => onChange({ ...value, start: e.target.value })} />
      <span className="text-muted text-xs">to</span>
      <input aria-label="To" type="datetime-local" className="input py-1" value={value.end || ""} onChange={(e) => onChange({ ...value, end: e.target.value })} />
    </>}
  </span>;
}

export function useRange(initial = "24h") {
  const [r, setR] = useState<Range>({ range: initial });
  return [r, setR, rangeParams(r)] as const;
}

export function SortTh({ k, label, sort, setSort, className = "" }: { k: string; label: ReactNode; sort: { key: string; desc: boolean }; setSort: (s: { key: string; desc: boolean }) => void; className?: string }) {
  const on = sort.key === k;
  return <th className={className} aria-sort={on ? (sort.desc ? "descending" : "ascending") : "none"}>
    <button className="inline-flex items-center gap-0.5 hover:text-slate-200" onClick={() => setSort({ key: k, desc: on ? !sort.desc : true })}>
      {label}<span className="text-2xs w-2">{on ? (sort.desc ? "▼" : "▲") : ""}</span></button></th>;
}

export function Pager({ page, size, total, onPage }: { page: number; size: number; total: number; onPage: (p: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / size));
  if (total <= size) return null;
  return <div className="flex items-center gap-2 justify-end text-xs p-2">
    <span className="text-muted">{(page - 1) * size + 1}–{Math.min(total, page * size)} of {total}</span>
    <button className="btn py-0.5" disabled={page <= 1} onClick={() => onPage(page - 1)}>‹</button>
    <span>{page} / {pages}</span>
    <button className="btn py-0.5" disabled={page >= pages} onClick={() => onPage(page + 1)}>›</button>
  </div>;
}

export function CollectorBadge({ c }: { c?: any }) {
  if (!c) return null;
  const cls = c.status === "ok" ? "bg-emerald-500/15 text-emerald-300" : c.status === "degraded" ? "bg-amber-500/15 text-amber-300" : "bg-red-500/15 text-red-300";
  const label = { ok: "Collector OK", degraded: "Collector degraded", stale: "Collector stale", never_ran: "Collector not started" }[c.status as string] || c.status;
  return <span className={`pill ${cls}`} title={c.detail}>{label}</span>;
}

export function StaleBanner({ c }: { c?: any }) {
  if (!c || c.status === "ok" || c.status === "degraded") return null;
  return <div role="alert" className="rounded-md border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-200">
    <b>Monitoring data is stale.</b> {c.detail}. States below are the last known values, not current measurements — they are not shown as up or down from new evidence.
  </div>;
}

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: ReactNode }) {
  return <div><label className="label">{label}</label>{children}{hint && <div className="text-2xs text-muted mt-0.5">{hint}</div>}</div>;
}
