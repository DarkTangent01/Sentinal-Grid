import { FormEvent, ReactNode, useEffect, useRef, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { RangeKey, useGlobal, useLastUpdated, useMe } from "../lib/context";
import { fmtTime, fmtTimeShort } from "../lib/format";
import { ThemeToggle } from "../lib/theme";
import { ICONS, Sidebar, useSidebarCollapsed } from "./Sidebar";
import { ADMIN, NAV, PRODUCT, Product, activeItem } from "../lib/products";

const RANGES: [RangeKey, string][] = [["5m", "Last 5 min"], ["15m", "Last 15 min"], ["1h", "Last hour"], ["24h", "Last 24 h"], ["7d", "Last 7 days"], ["custom", "Custom…"]];
/** Pages with their own scope / time controls: the global filter row is not shown (they ignore it). */
const OWN_FILTERS = ["/nms/traffic"];

const REFRESH = <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
  <path d="M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7" /></svg>;
const MENU = <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden><path d="M4 6h16M4 12h16M4 18h16" /></svg>;
const FILTER = <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="M3 5h18l-7 8v6l-4-2v-4z" /></svg>;

/** Product › section › page, from the navigation definition (one source of truth for names). */
function useCrumbs(product: Product): { group: string; label: string; icon?: string } | null {
  const loc = useLocation();
  const groups = [...NAV[product], ADMIN];
  const to = activeItem(groups, loc.pathname, loc.search);
  for (const g of groups) for (const it of g.items) if (it.to === to) return { group: g.title, label: it.label, icon: it.icon };
  return null;
}

export function Layout({ children, onLogout, product }: { children: ReactNode; onLogout: () => void; product: Product }) {
  const g = useGlobal();
  const me = useMe();
  const qc = useQueryClient();
  const [cs, setCs] = useState(g.start);
  const [ce, setCe] = useState(g.end);
  const fws = useQuery({ queryKey: ["firewalls"], queryFn: () => api<any[]>("/firewalls"), staleTime: 60_000 });
  const sys = useQuery({ queryKey: ["system-status"], queryFn: () => api<any>("/system/status"), refetchInterval: 60_000 });
  const demo = sys.data && (sys.data.demo_mode || sys.data.sources_24h?.some((s: any) => s.source === "demo"));
  const sites = Array.from(new Set((fws.data || []).map((f) => f.site).filter(Boolean)));
  const [navOpen, setNavOpen] = useState(false);
  // phones: the scope filters and search sit behind one "Filters" button; from sm up they are always inline
  const [moreOpen, setMoreOpen] = useState(false);
  const loc = useLocation();
  useEffect(() => { setNavOpen(false); setMoreOpen(false); }, [loc.pathname]);
  const scoped = Number(!!g.firewallId) + Number(!!g.site);
  const more = moreOpen ? "flex w-full flex-wrap items-center gap-2 sm:contents" : "hidden sm:contents";
  const [collapsed, setCollapsed] = useSidebarCollapsed();
  const lastIngest = (sys.data?.sources_24h || []).map((x: any) => String(x.last_ingest)).sort().pop() || null;
  const crumbs = useCrumbs(product);
  const scopeBar = !OWN_FILTERS.some((p) => loc.pathname === p || loc.pathname.startsWith(p + "/"));
  useEffect(() => { document.title = crumbs ? `${crumbs.label} · ${PRODUCT[product].name}` : PRODUCT[product].name; }, [crumbs?.label, product]);

  return (
    <div className="flex h-full min-w-0">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 btn btn-primary">Skip to content</a>
      {navOpen && <div className="fixed inset-0 z-30 bg-scrim/60 backdrop-blur-[1px] lg:hidden animate-fade-in" onClick={() => setNavOpen(false)} aria-hidden />}
      <Sidebar me={me} product={product} open={navOpen} collapsed={collapsed} setCollapsed={setCollapsed} onLogout={onLogout} lastIngest={lastIngest} />
      <div className="flex-1 flex flex-col min-w-0 h-full">
        {demo && (
          <div role="status" className="bg-amber-500/10 border-b border-amber-500/30 text-amber-200 text-xs px-4 py-1.5 flex items-center gap-2">
            <span className="dot dot-warn" aria-hidden />DEMO MODE — synthetic sanitized events from demo firewalls (source = <b>demo</b>) are present. They are not live telemetry.
          </div>
        )}
        <header className="border-b border-line bg-panel2/80 backdrop-blur supports-[backdrop-filter]:bg-panel2/70 sticky top-0 z-20">
          <div className="flex items-center gap-2 px-3 sm:px-5 h-12">
            <button type="button" className="btn btn-ghost btn-icon lg:hidden" aria-label="Open navigation" aria-controls="sidebar" aria-expanded={navOpen} onClick={() => setNavOpen(true)}>{MENU}</button>
            <nav aria-label="Breadcrumb" className="min-w-0 flex-1">
              <ol className="flex items-center gap-1.5 text-[13px] min-w-0">
                <li className="hidden sm:flex items-center gap-1.5 text-subtle shrink-0">
                  <Link to={PRODUCT[product].home} className="hover:text-slate-200 transition-colors">{PRODUCT[product].name}</Link>
                  <span aria-hidden>/</span></li>
                {crumbs && <li className="hidden md:flex items-center gap-1.5 text-subtle shrink-0"><span>{crumbs.group}</span><span aria-hidden>/</span></li>}
                <li className="flex items-center gap-2 min-w-0" aria-current="page">
                  {crumbs?.icon && <span className="text-brand-400 shrink-0">{ICONS[crumbs.icon]}</span>}
                  <span className="font-semibold text-slate-100 truncate">{crumbs?.label || PRODUCT[product].name}</span></li>
              </ol>
            </nav>
            <LastUpdated />
            {scopeBar && <button type="button" className="btn btn-ghost btn-icon sm:hidden relative" aria-expanded={moreOpen} aria-controls="hdr-scope" aria-label="Filters"
              onClick={() => setMoreOpen(!moreOpen)}>{FILTER}{scoped > 0 && <span className="absolute -top-0.5 -right-0.5 rounded-full bg-solid-brand text-solid-on text-[9px] font-bold px-1 leading-4">{scoped}</span>}</button>}
            <button type="button" className="btn btn-ghost btn-icon" aria-label="Refresh data" title="Refresh data" onClick={() => qc.invalidateQueries()}>{REFRESH}</button>
            <ThemeToggle />
          </div>
          {scopeBar && <div id="hdr-scope" className={`${moreOpen ? "flex" : "hidden sm:flex"} flex-wrap items-center gap-2 px-3 sm:px-5 pb-2.5 -mt-0.5`}>
            <select aria-label="Time range" className="input py-1" value={g.range} onChange={(e) => g.setRange(e.target.value as RangeKey)}>
              {RANGES.map(([k, l]) => <option key={k} value={k}>{l}</option>)}
            </select>
            {g.range === "custom" && (
              <>
                <input aria-label="Start" type="datetime-local" className="input py-1" value={cs} onChange={(e) => setCs(e.target.value)} />
                <span className="text-subtle">→</span>
                <input aria-label="End" type="datetime-local" className="input py-1" value={ce} onChange={(e) => setCe(e.target.value)} />
                <button type="button" className="btn" onClick={() => g.setCustom(cs, ce)} disabled={!cs || !ce}>Apply</button>
              </>
            )}
            <div className={more}>
              <select aria-label="Firewall" className="input py-1 max-w-[11rem]" value={g.firewallId} onChange={(e) => g.setFirewallId(e.target.value)}>
                <option value="">All firewalls</option>
                {(fws.data || []).map((f) => <option key={f.id} value={f.id}>{f.name}</option>)}
              </select>
              <select aria-label="Site" className="input py-1 max-w-[11rem]" value={g.site} onChange={(e) => g.setSite(e.target.value)}>
                <option value="">All sites</option>
                {sites.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
              {me.products.includes("grid") && <GlobalSearch />}
            </div>
            <span className="flex-1" />
            <select aria-label="Auto-refresh" className={`input py-1 ${moreOpen ? "" : "hidden sm:block"}`} value={g.refreshSec} onChange={(e) => g.setRefreshSec(Number(e.target.value))}>
              <option value={0}>Auto-refresh off</option><option value={15}>Every 15 s</option>
              <option value={30}>Every 30 s</option><option value={60}>Every 1 min</option><option value={300}>Every 5 min</option>
            </select>
          </div>}
        </header>
        <main id="main" tabIndex={-1} className="flex-1 overflow-auto p-3 sm:p-5 min-w-0 focus:outline-none">{children}</main>
      </div>
    </div>
  );
}

const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6 = /^[0-9a-f:]+:[0-9a-f:]*$/i;
const DOMAIN = /^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}\.?$/i;

/** One box for everything: IP / domain → entity graph, #123 → incident, user:name → user graph, anything else → Search.
 *  Press "/" anywhere to focus it. */
function GlobalSearch() {
  const nav = useNavigate();
  const [v, setV] = useState("");
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => {
    const h = (e: globalThis.KeyboardEvent) => {
      const t = e.target as HTMLElement;
      if (e.key === "/" && !["INPUT", "TEXTAREA", "SELECT"].includes(t.tagName) && !t.isContentEditable) { e.preventDefault(); ref.current?.focus(); }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, []);
  const go = (e: FormEvent) => {
    e.preventDefault();
    const q = v.trim();
    if (!q) return;
    const inc = q.match(/^#?(\d{1,9})$/);
    const user = q.match(/^user:(\S+)$/i);
    if (inc && !IPV4.test(q)) nav(`/incidents/${inc[1]}`);
    else if (IPV4.test(q) || (IPV6.test(q) && q.includes(":") && !q.includes(" "))) nav(`/graph?kind=ip&value=${encodeURIComponent(q)}`);
    else if (user) nav(`/graph?kind=user&value=${encodeURIComponent(user[1])}`);
    else if (DOMAIN.test(q)) nav(`/graph?kind=domain&value=${encodeURIComponent(q.toLowerCase())}`);
    else nav(`/search?q=${encodeURIComponent(/[:|]/.test(q) ? q : `"${q.replace(/"/g, "")}"`)}`);
    setV("");
    ref.current?.blur();
  };
  return (
    <form onSubmit={go} role="search" className="min-w-0 w-full sm:w-auto">
      <input ref={ref} aria-label="Search IP, domain, user:name, #incident or query" className="input w-full sm:w-56 2xl:w-72"
        placeholder="Search IP, domain, #incident, query…  ( / )" value={v} onChange={(e) => setV(e.target.value)} />
    </form>
  );
}

/** Own component: it re-renders on every query success without re-rendering the header or the page. */
function LastUpdated() {
  const t = useLastUpdated();
  // compact (time only for today) so the header fits one row at 1366 px; the full timestamp is the tooltip
  return <span className="text-xs text-muted whitespace-nowrap hidden hd:inline tabular-nums" title={t ? `Last data refresh ${fmtTime(new Date(t))}` : undefined}>
    Updated {t ? fmtTimeShort(new Date(t)) : "—"}</span>;
}
