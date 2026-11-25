import { KeyboardEvent, ReactNode, RefObject, useEffect, useRef, useState } from "react";
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

const TONE_DOT = { ok: "dot-ok", bad: "dot-bad", warn: "dot-warn" } as const;
const TONE_TEXT = { ok: "Healthy", bad: "Critical", warn: "Warning" } as const;

/** Metric card: label, value (tabular), optional context line; a tone adds a status dot with a text equivalent
 *  (colour is never the only cue). Clickable cards drill down. */
export function Kpi({ label, value, sub, tone, onClick }: { label: string; value: ReactNode; sub?: ReactNode; tone?: "ok" | "bad" | "warn"; onClick?: () => void }) {
  const color = tone === "ok" ? "text-emerald-400" : tone === "bad" ? "text-red-400" : tone === "warn" ? "text-amber-300" : "text-slate-100";
  const Tag = onClick ? "button" : "div";
  return (
    <Tag type={onClick ? "button" : undefined} className={`card px-4 py-3 text-left ${onClick ? "card-interactive cursor-pointer focus-visible:border-brand-500" : ""}`} onClick={onClick}>
      <div className="flex items-start gap-2">
        <div className="eyebrow leading-tight line-clamp-2 flex-1" title={label}>{label}</div>
        {tone && <span className={`dot mt-0.5 ${TONE_DOT[tone]}`} role="img" aria-label={TONE_TEXT[tone]} />}
      </div>
      <div className={`metric mt-1.5 truncate ${color}`}>{value}</div>
      {sub && <div className="text-2xs text-subtle mt-1 truncate" title={typeof sub === "string" ? sub : undefined}>{sub}</div>}
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

/** Scroll container for tables: horizontal scroll inside the card; with maxH the header row stays visible. */
export function TableWrap({ children, maxH }: { children: ReactNode; maxH?: string }) {
  return <div className={`tbl-wrap ${maxH ? `${maxH} overflow-y-auto [&_thead_th]:sticky [&_thead_th]:top-0 [&_thead_th]:z-[1]` : ""}`}>{children}</div>;
}

/** Keyboard-accessible clickable table rows. */
export function rowProps(onActivate: () => void) {
  return {
    tabIndex: 0, onClick: onActivate,
    onKeyDown: (e: KeyboardEvent) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onActivate(); } },
  };
}

/** Loading (skeleton rows) and error states for a query. */
export function Loading({ q, rows = 3 }: { q: { isLoading: boolean; error: unknown }; rows?: number }) {
  if (q.isLoading) return (
    <div className="p-4 space-y-2.5" role="status" aria-live="polite">
      <span className="sr-only">Loading…</span>
      {Array.from({ length: rows }, (_, i) => <div key={i} className="skeleton h-3.5" style={{ width: `${92 - i * 14}%` }} />)}
    </div>);
  if (q.error) return (
    <div role="alert" className="m-3 flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2.5 text-sm text-red-300">
      <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" className="shrink-0 mt-0.5" aria-hidden><circle cx="12" cy="12" r="9" /><path d="M12 8v5M12 16h.01" /></svg>
      <span>Failed to load: {String((q.error as Error).message)}</span></div>);
  return null;
}

export function Empty({ text = "No events in the selected time range." }: { text?: ReactNode }) {
  return (
    <div className="px-4 py-8 text-center">
      <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" className="mx-auto mb-2 text-subtle" aria-hidden>
        <path d="M3 12h4l2 3h6l2-3h4" /><path d="M5.5 5h13L21 12v6a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1v-6z" /></svg>
      <div className="text-sm text-muted max-w-md mx-auto">{text}</div>
    </div>);
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

/** Tab bar (WAI-ARIA tabs): Left / Right / Home / End move between tabs. On phones the bar scrolls sideways in one
 *  row instead of wrapping into many rows; the selected tab is kept in view. */
export function Tabs({ tabs, value, onChange }: { tabs: { key: string; label: string }[]; value: string; onChange: (k: string) => void }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const strip = ref.current;
    const el = strip?.querySelector<HTMLElement>("[aria-selected=true]");
    if (!strip || !el) return;
    // keyboard navigation: focus follows the selected tab
    if (strip.contains(document.activeElement) && document.activeElement !== el) el.focus();
    // scroll the tab strip only (scrollIntoView would also scroll the page)
    if (strip.scrollWidth > strip.clientWidth) strip.scrollLeft = el.offsetLeft - strip.clientWidth / 2 + el.offsetWidth / 2;
  }, [value]);
  const onKey = (e: KeyboardEvent) => {
    const i = tabs.findIndex((t) => t.key === value);
    const next = e.key === "ArrowRight" ? i + 1 : e.key === "ArrowLeft" ? i - 1 : e.key === "Home" ? 0 : e.key === "End" ? tabs.length - 1 : null;
    if (next === null || !tabs.length) return;
    e.preventDefault();
    onChange(tabs[(next + tabs.length) % tabs.length].key);
  };
  return (
    <div ref={ref} role="tablist" onKeyDown={onKey}
      className="flex flex-nowrap sm:flex-wrap gap-x-1 border-b border-line mb-3 overflow-x-auto sm:overflow-visible [scrollbar-width:thin]">
      {tabs.map((t) => (
        <button key={t.key} type="button" role="tab" data-tab={t.key} aria-selected={value === t.key} tabIndex={value === t.key ? 0 : -1}
          onClick={() => onChange(t.key)}
          className={`shrink-0 px-3 py-2 text-[13px] -mb-px border-b-2 whitespace-nowrap transition-colors duration-150 ${value === t.key ? "border-brand-400 text-slate-100 font-medium" : "border-transparent text-muted hover:text-slate-200 hover:border-slate-600"}`}>
          {t.label}
        </button>
      ))}
    </div>
  );
}

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]):not([type=hidden]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/** Dialog behaviour shared by Modal and Drawer: Escape closes, focus moves into the dialog on open, Tab stays inside it,
 *  and focus returns to the element that opened it. */
// The element that opened a dialog: the last focus outside any dialog. Read at activation time, because opening a
// dialog often changes a URL parameter that re-renders the list (the clicked row is gone before the dialog mounts).
// Also recorded on keydown / pointerdown: those always reach the element that activates the dialog.
let lastFocus: HTMLElement | null = null;
if (typeof document !== "undefined") {
  const note = (e: Event) => {
    const t = (e.target as HTMLElement)?.closest?.<HTMLElement>(`${FOCUSABLE}, tr[tabindex]`);
    if (t && !t.closest("[role=dialog]")) lastFocus = t;
  };
  for (const ev of ["focusin", "keydown", "pointerdown"]) document.addEventListener(ev, note, true);
}

function useDialog(ref: RefObject<HTMLElement>, onClose: () => void) {
  const close = useRef(onClose);
  close.current = onClose;
  useEffect(() => {
    const active = document.activeElement as HTMLElement | null;
    const opener = active && active !== document.body && !active.closest("[role=dialog]") ? active : lastFocus;
    const el = ref.current;
    // first form field if there is one, else the dialog itself (not the close button: Enter would dismiss it)
    const first = el?.querySelector<HTMLElement>("input:not([type=hidden]), select, textarea");
    (first || el)?.focus({ preventScroll: true });
    const h = (e: globalThis.KeyboardEvent) => {
      if (e.key === "Escape") { close.current(); return; }
      if (e.key !== "Tab" || !el) return;
      const items = [...el.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((x) => x.offsetParent !== null);
      if (!items.length) return;
      const [a, z] = [items[0], items[items.length - 1]];
      if (e.shiftKey && (document.activeElement === a || document.activeElement === el)) { e.preventDefault(); z.focus(); }
      else if (!e.shiftKey && document.activeElement === z) { e.preventDefault(); a.focus(); }
    };
    window.addEventListener("keydown", h);
    const twin = opener && { tag: opener.tagName, text: opener.textContent, label: opener.getAttribute("aria-label") };
    return () => {
      window.removeEventListener("keydown", h);
      // the opener itself, or, when the list re-rendered (closing changed a URL parameter), the element that replaced
      // it (same tag, text and label). Retried for a moment: the re-render can land after the first attempt.
      const restore = () => {
        // focus already somewhere (the opener, a dialog that opened meanwhile, or where the user moved it): leave it
        if (document.activeElement && document.activeElement !== document.body) return;
        const target = opener?.isConnected ? opener : twin && [...document.querySelectorAll<HTMLElement>(`${twin.tag}[tabindex], button, a[href]`)]
          .find((x) => x.tagName === twin.tag && x.textContent === twin.text && x.getAttribute("aria-label") === twin.label);
        target?.focus({ preventScroll: true });      };
      for (const ms of [0, 150, 500]) setTimeout(restore, ms);
    };
  }, [ref]);
}

const CloseButton = ({ onClose }: { onClose: () => void }) => (
  <button type="button" aria-label="Close" className="shrink-0 rounded-md p-1 text-muted hover:text-slate-100 hover:bg-slate-800/70 transition-colors" onClick={onClose}>
    <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden><path d="M6 6l12 12M18 6L6 18" /></svg></button>
);

export function Modal({ title, onClose, children, wide }: { title: string; onClose: () => void; children: ReactNode; wide?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  useDialog(ref, onClose);
  return (
    <div className="fixed inset-0 z-50 bg-scrim/65 backdrop-blur-[2px] flex items-start justify-center p-2 sm:p-6 overflow-auto animate-fade-in" onClick={onClose}>
      <div ref={ref} tabIndex={-1} role="dialog" aria-modal="true" aria-label={title} className={`card bg-elevated shadow-pop w-full outline-none animate-pop-in ${wide ? "max-w-5xl" : "max-w-2xl"} sm:mt-10`} onClick={(e) => e.stopPropagation()}>
        <div className="card-h"><h2 className="truncate">{title}</h2><CloseButton onClose={onClose} /></div>
        <div className="p-4">{children}</div>
      </div>
    </div>
  );
}

export function Drawer({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  const ref = useRef<HTMLElement>(null);
  useDialog(ref, onClose);
  return (
    <div className="fixed inset-0 z-40 bg-scrim/55 backdrop-blur-[1px] animate-fade-in" onClick={onClose}>
      <aside ref={ref} tabIndex={-1} role="dialog" aria-modal="true" aria-label={title} className="absolute right-0 top-0 bottom-0 w-full max-w-3xl bg-panel border-l border-line shadow-pop overflow-auto outline-none animate-slide-in" onClick={(e) => e.stopPropagation()}>
        <div className="card-h sticky top-0 bg-panel/95 backdrop-blur z-10 !py-3"><h2 className="truncate text-[15px]">{title}</h2><CloseButton onClose={onClose} /></div>
        <div className="p-4">{children}</div>
      </aside>
    </div>
  );
}

export function Bar({ value, max }: { value: number; max: number }) {
  return (
    <div className="h-1.5 bg-slate-800 rounded-full w-16 hidden md:inline-block align-middle ml-2 overflow-hidden" aria-hidden>
      <div className="h-1.5 bg-brand-400 rounded-full" style={{ width: `${max ? Math.max(2, (value / max) * 100) : 0}%` }} />
    </div>
  );
}

/** Form field: the caption is a real <label> around the control, so screen readers announce it and a click on the
 *  caption focuses the control. Use for exactly one input / select / textarea. */
export function Field({ label, hint, children, className = "" }: { label: ReactNode; hint?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <label className={`block min-w-0 ${className}`}>
      <span className="label">{label}</span>
      {children}
      {hint && <span className="block text-2xs text-muted mt-0.5">{hint}</span>}
    </label>
  );
}

/** Sortable column header: a button inside <th> with aria-sort. The first click sorts descending (largest first). */
export function SortTh({ k, label, sort, setSort, className = "" }: { k: string; label: ReactNode; sort: { key: string; desc: boolean };
  setSort: (s: { key: string; desc: boolean }) => void; className?: string }) {
  const on = sort.key === k;
  return <th className={className} aria-sort={on ? (sort.desc ? "descending" : "ascending") : "none"}>
    <button type="button" className="inline-flex items-center gap-0.5 uppercase tracking-wide hover:text-slate-200" onClick={() => setSort({ key: k, desc: on ? !sort.desc : true })}>
      {label}<span className="text-2xs w-2" aria-hidden>{on ? (sort.desc ? "▼" : "▲") : ""}</span></button></th>;
}

/** Pagination for every list: 1-based page, "first–last of total", Previous / Next.
 *  Pass `total` when the API returns it; when it does not, pass `hasMore` instead (the range then shows no total).
 *  Hidden when everything fits on one page. */
export function Pager({ page, size, total, hasMore, onPage, className = "p-2" }: { page: number; size: number; total?: number; hasMore?: boolean;
  onPage: (p: number) => void; className?: string }) {
  const known = total !== undefined && total !== null;
  const pages = known ? Math.max(1, Math.ceil(total / size)) : null;
  const next = known ? page < (pages as number) : !!hasMore;
  if (page <= 1 && !next) return null;
  const first = (page - 1) * size + 1;
  const last = known ? Math.min(total, page * size) : page * size;
  return (
    <nav aria-label="Pagination" className={`flex flex-wrap items-center justify-end gap-2 text-xs ${className}`}>
      <span className="text-muted tabular-nums">{first.toLocaleString()}–{last.toLocaleString()}{known && <> of {total.toLocaleString()}</>}</span>
      <button type="button" className="btn py-0.5 px-2" aria-label="Previous page" disabled={page <= 1} onClick={() => onPage(page - 1)}>‹<span className="hidden sm:inline"> Previous</span></button>
      {pages !== null && <span className="tabular-nums" aria-current="page">{page} / {pages}</span>}
      <button type="button" className="btn py-0.5 px-2" aria-label="Next page" disabled={!next} onClick={() => onPage(page + 1)}><span className="hidden sm:inline">Next </span>›</button>
    </nav>
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
