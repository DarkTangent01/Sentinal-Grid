import { KeyboardEvent, ReactNode, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ACTION_COLORS, fmtAgo, fmtCompact, fmtTime, fmtTimeShort } from "../lib/format";
import { api, Params, qs } from "../lib/api";

export function Card({ title, right, children, className = "", bodyClass = "" }: { title?: ReactNode; right?: ReactNode; children: ReactNode; className?: string; bodyClass?: string }) {
  return (
    <section className={`card ${className}`}>
      {title && <header className="card-h"><h2 className="min-w-0 truncate">{title}</h2>{right && <div className="flex flex-wrap items-center gap-2">{right}</div>}</header>}
      <div className={`card-b ${bodyClass}`}>{children}</div>
    </section>
  );
}

export function Kpi({ label, value, sub, tone, onClick }: { label: string; value: ReactNode; sub?: ReactNode; tone?: "ok" | "bad" | "warn"; onClick?: () => void }) {
  const color = tone === "ok" ? "text-emerald-400" : tone === "bad" ? "text-red-400" : tone === "warn" ? "text-amber-300" : "text-slate-100";
  const Tag = onClick ? "button" : "div";
  return (
    <Tag className={`card px-4 py-3 text-left transition-shadow ${onClick ? "hover:border-brand-500/50 hover:shadow-md" : ""}`} onClick={onClick}>
      <div className="text-2xs font-semibold uppercase tracking-wide text-muted leading-tight line-clamp-2" title={label}>{label}</div>
      <div className={`text-xl xl:text-2xl font-extrabold tracking-tight mt-1 tabular-nums truncate ${color}`}>{value}</div>
      {sub && <div className="text-2xs text-muted mt-0.5 truncate" title={typeof sub === "string" ? sub : undefined}>{sub}</div>}
    </Tag>
  );
}

export function Sev({ s }: { s?: string }) {
  if (!s) return null;
  const k = ["critical", "high", "medium", "low"].includes(s) ? s : "informational";
  return <span className={`pill sev-${k}`}>{s}</span>;
}

export function Action({ a }: { a?: string }) {
  if (!a) return <span className="text-slate-600">—</span>;
  return <span className={`font-medium ${ACTION_COLORS[a] || "text-slate-300"}`}>{a}</span>;
}

/** Compact timestamp in the user's timezone with the full value as a tooltip. */
export function Time({ v }: { v: unknown }) {
  if (!v) return <span className="text-slate-600">—</span>;
  return <time className="whitespace-nowrap tabular-nums" title={`${fmtTime(v)} (${fmtAgo(v)})`}>{fmtTimeShort(v)}</time>;
}

/** Long strings: truncate to the column with the full text available as a tooltip. */
export function Trunc({ text, className = "", max = "max-w-[22rem]" }: { text?: string | null; className?: string; max?: string }) {
  if (!text) return <span className="text-slate-600">—</span>;
  return <span className={`cell-trunc ${max} ${className}`} title={text}>{text}</span>;
}

export function TableWrap({ children, maxH }: { children: ReactNode; maxH?: string }) {
  return <div className={`tbl-wrap ${maxH ? `${maxH} overflow-y-auto` : ""}`}>{children}</div>;
}

/** Keyboard-accessible clickable table rows. */
export function rowProps(onActivate: () => void) {
  return {
    tabIndex: 0, onClick: onActivate,
    onKeyDown: (e: KeyboardEvent) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onActivate(); } },
  };
}

export function Loading({ q }: { q: { isLoading: boolean; error: unknown } }) {
  if (q.isLoading) return <div className="text-sm text-muted p-4 animate-pulse">Loading…</div>;
  if (q.error) return <div role="alert" className="text-sm text-red-400 p-4">Failed to load: {String((q.error as Error).message)}</div>;
  return null;
}

export function Empty({ text = "No events in the selected time range." }: { text?: ReactNode }) {
  return <div className="text-sm text-muted p-4 text-center">{text}</div>;
}

export type Coverage = Record<string, { first_event: string; last_event: string; last_ingest: string; events: number; sources: string[] }>;

export function useCoverage() {
  return useQuery({ queryKey: ["coverage"], queryFn: () => api<Coverage>("/system/coverage"), staleTime: 60_000, refetchInterval: 60_000 });
}

const HINT: Record<string, string> = {
  web: "Enable a web-filter profile (log-all-url) on firewall policies and forward UTM logs via syslog.",
  dns: "Apply a DNS-filter profile with log-all-domain enabled and forward UTM logs via syslog.",
  traffic: "Set logtraffic all on policies and configure syslog forwarding.",
  security: "Enable IPS/AV/application-control logging and forward UTM logs via syslog.",
  system: "Forward event logs via syslog.",
};

/** Empty state that distinguishes "never collected" from "no events match the current filters". */
export function NoData({ category, what }: { category: string; what?: string }) {
  const cov = useCoverage();
  if (cov.isLoading) return <Empty text="Loading…" />;
  if (cov.error) return <Empty text={<span className="text-red-400">Could not check collection status.</span>} />;
  const c = cov.data?.[category];
  if (!c) return <Empty text={<><b className="text-slate-300">No {what || category} logs have been collected yet</b> from any firewall. {HINT[category]}</>} />;
  return <Empty text={<>No {what || category} events match the selected time range and filters. Last {what || category} event received <span title={fmtTime(c.last_event)}>{fmtAgo(c.last_event)}</span> (source: {c.sources.join(", ")}).</>} />;
}

export function useExplore() {
  const nav = useNavigate();
  return (f: Params) => nav(`/explorer${qs(f)}`);
}

export function IpLink({ ip }: { ip?: string | null }) {
  const nav = useNavigate();
  if (!ip) return <span className="text-slate-600">—</span>;
  return <button type="button" className="link font-mono whitespace-nowrap" title={`Investigate ${ip}`}
    onClick={(e) => { e.stopPropagation(); nav(`/investigate/${encodeURIComponent(ip)}`); }}>{ip}</button>;
}

export function LimitSelect({ value, onChange }: { value: number; onChange: (n: number) => void }) {
  return (
    <select aria-label="Result count" className="input py-1" value={value} onChange={(e) => onChange(Number(e.target.value))}>
      {[10, 25, 50, 100].map((n) => <option key={n} value={n}>Top {n}</option>)}
    </select>
  );
}

export function Tabs({ tabs, value, onChange }: { tabs: { key: string; label: string }[]; value: string; onChange: (k: string) => void }) {
  return (
    <div role="tablist" className="flex flex-wrap gap-x-1 border-b border-line mb-3">
      {tabs.map((t) => (
        <button key={t.key} role="tab" aria-selected={value === t.key} onClick={() => onChange(t.key)}
          className={`px-3 py-1.5 text-sm -mb-px border-b-2 whitespace-nowrap ${value === t.key ? "border-[#e23744] text-brand-400 font-semibold" : "border-transparent text-muted hover:text-slate-300"}`}>
          {t.label}
        </button>
      ))}
    </div>
  );
}

function useEscape(onClose: () => void) {
  useEffect(() => {
    const h = (e: globalThis.KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);
}

export function Modal({ title, onClose, children, wide }: { title: string; onClose: () => void; children: ReactNode; wide?: boolean }) {
  useEscape(onClose);
  return (
    <div className="fixed inset-0 z-50 bg-black/60 flex items-start justify-center p-2 sm:p-6 overflow-auto" onClick={onClose}>
      <div role="dialog" aria-modal="true" aria-label={title} className={`card w-full ${wide ? "max-w-5xl" : "max-w-2xl"} sm:mt-8`} onClick={(e) => e.stopPropagation()}>
        <div className="card-h"><h2 className="truncate">{title}</h2><button aria-label="Close" className="text-muted hover:text-white px-1" onClick={onClose}>✕</button></div>
        <div className="p-4">{children}</div>
      </div>
    </div>
  );
}

export function Drawer({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  useEscape(onClose);
  return (
    <div className="fixed inset-0 z-40 bg-black/50" onClick={onClose}>
      <aside role="dialog" aria-modal="true" aria-label={title} className="absolute right-0 top-0 bottom-0 w-full max-w-3xl bg-panel border-l border-line overflow-auto" onClick={(e) => e.stopPropagation()}>
        <div className="card-h sticky top-0 bg-panel z-10"><h2 className="truncate">{title}</h2><button aria-label="Close" className="text-muted hover:text-white px-1" onClick={onClose}>✕</button></div>
        <div className="p-4">{children}</div>
      </aside>
    </div>
  );
}

export function Bar({ value, max }: { value: number; max: number }) {
  return (
    <div className="h-1.5 bg-slate-800 rounded w-16 hidden md:inline-block align-middle ml-2" aria-hidden>
      <div className="h-1.5 bg-sky-500 rounded" style={{ width: `${max ? Math.max(2, (value / max) * 100) : 0}%` }} />
    </div>
  );
}

export function SortSelect({ value, onChange, options }: { value: string; onChange: (s: string) => void; options: [string, string][] }) {
  return (
    <select aria-label="Sort" className="input py-1" value={value} onChange={(e) => onChange(e.target.value)}>
      {options.map(([k, l]) => <option key={k} value={k}>Sort: {l}</option>)}
    </select>
  );
}

export function Collapsible({ title, children }: { title: string; children: ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="border border-line rounded">
      <button aria-expanded={open} className="w-full text-left px-3 py-1.5 text-sm text-muted hover:text-slate-200" onClick={() => setOpen(!open)}>
        {open ? "▾" : "▸"} {title}
      </button>
      {open && <div className="p-3 border-t border-line">{children}</div>}
    </div>
  );
}

/** Debounce a fast-changing value (search inputs) so each keystroke doesn't trigger a query. */
export function useDebounced<T>(value: T, ms = 400): T {
  const [v, setV] = useState(value);
  useEffect(() => { const t = setTimeout(() => setV(value), ms); return () => clearTimeout(t); }, [value, ms]);
  return v;
}

export const compact = fmtCompact;
