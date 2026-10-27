import { FormEvent, ReactNode, useEffect, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { RangeKey, useGlobal, useMe } from "../lib/context";
import { fmtTime } from "../lib/format";
import { ThemeToggle } from "../lib/theme";
import { Sidebar, useSidebarCollapsed } from "./Sidebar";

const RANGES: [RangeKey, string][] = [["5m", "Last 5 min"], ["15m", "Last 15 min"], ["1h", "Last hour"], ["24h", "Last 24 h"], ["7d", "Last 7 days"], ["custom", "Custom…"]];

export function Layout({ children, onLogout }: { children: ReactNode; onLogout: () => void }) {
  const g = useGlobal();
  const me = useMe();
  const qc = useQueryClient();
  const [cs, setCs] = useState(g.start);
  const [ce, setCe] = useState(g.end);
  const fws = useQuery({ queryKey: ["firewalls-lite"], queryFn: () => api<any[]>("/firewalls"), staleTime: 60_000 });
  const sys = useQuery({ queryKey: ["system-status"], queryFn: () => api<any>("/system/status"), refetchInterval: 60_000 });
  const demo = sys.data && (sys.data.demo_mode || sys.data.sources_24h?.some((s: any) => s.source === "demo"));
  const sites = Array.from(new Set((fws.data || []).map((f) => f.site).filter(Boolean)));
  const [navOpen, setNavOpen] = useState(false);
  const loc = useLocation();
  useEffect(() => setNavOpen(false), [loc.pathname]);
  const [collapsed, setCollapsed] = useSidebarCollapsed();
  const lastIngest = (sys.data?.sources_24h || []).map((x: any) => String(x.last_ingest)).sort().pop() || null;

  return (
    <div className="flex h-full min-w-0">
      {navOpen && <div className="fixed inset-0 z-30 bg-black/50 lg:hidden" onClick={() => setNavOpen(false)} aria-hidden />}
      <Sidebar me={me} open={navOpen} collapsed={collapsed} setCollapsed={setCollapsed} onLogout={onLogout} lastIngest={lastIngest} />
      <div className="flex-1 flex flex-col min-w-0 h-full">
        {demo && (
          <div className="bg-amber-500/15 border-b border-amber-600/50 text-amber-200 text-xs px-4 py-1.5">
            DEMO MODE — synthetic sanitized events from demo firewalls (source = <b>demo</b>) are present. They are not live telemetry.
          </div>
        )}
        <header className="flex flex-wrap items-center gap-2 px-3 sm:px-5 py-2.5 min-h-16 border-b border-line bg-panel">
          <button className="btn lg:hidden px-2" aria-label="Open navigation" aria-controls="sidebar" aria-expanded={navOpen} onClick={() => setNavOpen(true)}>☰</button>
          <select aria-label="Time range" className="input" value={g.range} onChange={(e) => g.setRange(e.target.value as RangeKey)}>
            {RANGES.map(([k, l]) => <option key={k} value={k}>{l}</option>)}
          </select>
          {g.range === "custom" && (
            <>
              <input aria-label="Start" type="datetime-local" className="input" value={cs} onChange={(e) => setCs(e.target.value)} />
              <span className="text-muted">→</span>
              <input aria-label="End" type="datetime-local" className="input" value={ce} onChange={(e) => setCe(e.target.value)} />
              <button className="btn" onClick={() => g.setCustom(cs, ce)} disabled={!cs || !ce}>Apply</button>
            </>
          )}
          <select aria-label="Firewall" className="input max-w-[11rem]" value={g.firewallId} onChange={(e) => g.setFirewallId(e.target.value)}>
            <option value="">All firewalls</option>
            {(fws.data || []).map((f) => <option key={f.id} value={f.id}>{f.name}</option>)}
          </select>
          <select aria-label="Site" className="input max-w-[11rem]" value={g.site} onChange={(e) => g.setSite(e.target.value)}>
            <option value="">All sites</option>
            {sites.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <GlobalSearch />
          <div className="flex-1" />
          <span className="text-xs text-muted whitespace-nowrap hidden sm:inline">Updated: {g.lastUpdated ? fmtTime(g.lastUpdated) : "—"}</span>
          <select aria-label="Auto-refresh" className="input" value={g.refreshSec} onChange={(e) => g.setRefreshSec(Number(e.target.value))}>
            <option value={0}>Auto-refresh off</option><option value={15}>Every 15 s</option>
            <option value={30}>Every 30 s</option><option value={60}>Every 1 min</option><option value={300}>Every 5 min</option>
          </select>
          <button className="btn" onClick={() => qc.invalidateQueries()}>↻ Refresh</button>
          <ThemeToggle />
        </header>
        <main className="flex-1 overflow-auto p-3 sm:p-5 min-w-0">{children}</main>
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
    <form onSubmit={go} role="search" className="min-w-0">
      <input ref={ref} aria-label="Search IP, domain, user:name, #incident or query" className="input w-56 lg:w-72"
        placeholder="Search IP, domain, #incident, query…  ( / )" value={v} onChange={(e) => setV(e.target.value)} />
    </form>
  );
}
