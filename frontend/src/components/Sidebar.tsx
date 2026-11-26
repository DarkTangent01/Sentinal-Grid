import { ReactNode, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { Me } from "../lib/context";
import { fmtAgo } from "../lib/format";
import { ADMIN, NAV, PRODUCT, Product, activeItem, lastPathOf } from "../lib/products";
import { SentinelMark } from "./Brand";

// 24×24 stroke icons (inline, no icon dependency)
const I = (d: ReactNode) => (
  <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden>{d}</svg>
);
export const ICONS: Record<string, ReactNode> = {
  dashboard: I(<><rect x="3" y="3" width="7" height="9" rx="1.5" /><rect x="14" y="3" width="7" height="5" rx="1.5" /><rect x="14" y="12" width="7" height="9" rx="1.5" /><rect x="3" y="16" width="7" height="5" rx="1.5" /></>),
  alerts: I(<><path d="M6 8a6 6 0 1 1 12 0c0 7 3 9 3 9H3s3-2 3-9" /><path d="M10.3 21a1.9 1.9 0 0 0 3.4 0" /></>),
  sources: I(<><circle cx="6" cy="12" r="2.5" /><path d="M8.5 12H21M17 8l4 4-4 4" /></>),
  destinations: I(<><path d="M3 12h12.5M12 8l4 4-4 4" /><circle cx="19" cy="12" r="2.5" /></>),
  ports: I(<><rect x="3" y="6" width="18" height="12" rx="2" /><path d="M7 10v4M11 10v4M15 10v4" /></>),
  web: I(<><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18" /></>),
  dns: I(<><rect x="3" y="4" width="18" height="7" rx="1.5" /><rect x="3" y="13" width="18" height="7" rx="1.5" /><path d="M7 7.5h.01M7 16.5h.01" /></>),
  security: I(<><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z" /><path d="M12 8v4M12 15.5h.01" /></>),
  explorer: I(<><circle cx="11" cy="11" r="7" /><path d="M21 21l-4.5-4.5M8 11h6M11 8v6" /></>),
  firewalls: I(<><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M3 9h18M3 14.5h18M9 4v5M15 9v5.5M9 14.5V20" /></>),
  policies: I(<><path d="M8 6h13M8 12h13M8 18h13" /><path d="M3.5 6l1 1 2-2M3.5 12l1 1 2-2M3.5 18l1 1 2-2" /></>),
  shadow: I(<><rect x="3" y="3" width="12" height="12" rx="2" /><rect x="9" y="9" width="12" height="12" rx="2" strokeDasharray="3 2.5" /></>),
  hardening: I(<><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z" /><path d="M8.5 12l2.5 2.5 4.5-5" /></>),
  settings: I(<><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z" /></>),
  incidents: I(<><rect x="3" y="7" width="18" height="13" rx="2" /><path d="M8 7V5a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2M3 13h18" /></>),
  geo: I(<><circle cx="12" cy="12" r="9" /><path d="M3.6 9h16.8M3.6 15h16.8M12 3c2.5 2.7 2.5 15.3 0 18M12 3c-2.5 2.7-2.5 15.3 0 18" /></>),
  ti: I(<><circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="5" /><circle cx="12" cy="12" r="1.2" fill="currentColor" /></>),
  vpn: I(<><rect x="5" y="11" width="14" height="10" rx="2" /><path d="M8 11V7a4 4 0 0 1 8 0v4M12 15v2" /></>),
  searches: I(<><path d="M6 3h12a1 1 0 0 1 1 1v17l-7-4-7 4V4a1 1 0 0 1 1-1z" /></>),
  assets: I(<><rect x="3" y="4" width="18" height="12" rx="2" /><path d="M8 20h8M12 16v4" /></>),
  drift: I(<><circle cx="6" cy="6" r="2.5" /><circle cx="18" cy="18" r="2.5" /><path d="M6 8.5V14a4 4 0 0 0 4 4h5.5M18 15.5V10a4 4 0 0 0-4-4H8.5" /></>),
  compliance: I(<><rect x="5" y="4" width="14" height="17" rx="2" /><path d="M9 4V3h6v1M9 12l2 2 4-4" /></>),
  reports: I(<><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" /><path d="M14 3v5h5M9 13h6M9 17h6" /></>),
  notifications: I(<><path d="M3 11v2a1 1 0 0 0 1 1h3l5 4V6L7 10H4a1 1 0 0 0-1 1z" /><path d="M16 9a3 3 0 0 1 0 6M18.5 6.5a7 7 0 0 1 0 11" /></>),
  search: I(<><path d="M4 6h10M4 12h7M4 18h5" /><circle cx="16.5" cy="15.5" r="3.5" /><path d="M19 18l2.5 2.5" /></>),
  hunting: I(<><circle cx="12" cy="12" r="8" /><path d="M12 2v4M12 18v4M2 12h4M18 12h4" /><circle cx="12" cy="12" r="1.5" fill="currentColor" /></>),
  workbooks: I(<><rect x="3" y="3" width="18" height="18" rx="2" /><path d="M7 16v-3M11 16V9M15 16v-5M3 7h18" /></>),
  detections: I(<><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z" /><circle cx="12" cy="11" r="2.5" /><path d="M14 13l2.5 2.5" /></>),
  watchlists: I(<><path d="M9 6h12M9 12h12M9 18h12" /><circle cx="4.5" cy="6" r="1.2" fill="currentColor" /><circle cx="4.5" cy="12" r="1.2" fill="currentColor" /><circle cx="4.5" cy="18" r="1.2" fill="currentColor" /></>),
  automation: I(<><path d="M13 3L5 13h6l-1 8 8-10h-6z" /></>),
  graph: I(<><circle cx="12" cy="12" r="2.5" /><circle cx="5" cy="5" r="2" /><circle cx="19" cy="6" r="2" /><circle cx="6" cy="19" r="2" /><circle cx="19" cy="18" r="2" /><path d="M10.2 10.2L6.4 6.4M13.8 10.9l3.6-3.4M10.3 13.8l-2.9 3.7M14 13.6l3.4 3.2" /></>),
  isp: I(<><path d="M5 12.5a10 10 0 0 1 14 0M8.5 16a5 5 0 0 1 7 0" /><circle cx="12" cy="19.5" r="1.2" fill="currentColor" /><path d="M2 9a14.5 14.5 0 0 1 20 0" /></>),
  health: I(<><path d="M3 12h4l2-6 4 12 2-6h6" /></>),
  bgp: I(<><circle cx="5" cy="6" r="2.2" /><circle cx="19" cy="6" r="2.2" /><circle cx="12" cy="18.5" r="2.2" /><path d="M7.2 6h9.6M6.1 8l4.8 8.6M17.9 8l-4.8 8.6" /></>),
  identity: I(<><circle cx="9" cy="8" r="3.2" /><path d="M3.5 19a5.5 5.5 0 0 1 11 0" /><path d="M16 11.5l1.6 1.6 3.4-3.6" /></>),
  iac: I(<><path d="M8 7l-5 5 5 5M16 7l5 5-5 5" /><path d="M13.5 4.5l-3 15" /></>),
  aaa: I(<><path d="M12 3l7 3v5c0 4.5-3 8.3-7 10-4-1.7-7-5.5-7-10V6l7-3z" /><circle cx="12" cy="10" r="2" /><path d="M12 12v4" /></>),
  terminal: I(<><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M7 9l3 3-3 3M12.5 15H17" /></>),
  switch: I(<><rect x="2.5" y="8" width="19" height="8" rx="1.5" /><path d="M6 12h.01M9 12h.01M12 12h.01M15 12h.01M18 12h.01M6 16v3M18 16v3" /></>),
  tunnel: I(<><path d="M3 18V10a9 9 0 0 1 18 0v8" /><path d="M7 18v-7a5 5 0 0 1 10 0v7M3 18h18" /></>),
  logsrc: I(<><path d="M4 6h16M4 12h16M4 18h10" /><circle cx="19" cy="18" r="2" /></>),
  logout: I(<><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9" /></>),
  chevron: I(<path d="M15 18l-6-6 6-6" />),
  wifi: I(<><path d="M2 8.5a15 15 0 0 1 20 0M5 12a10 10 0 0 1 14 0M8.5 15.5a5 5 0 0 1 7 0" /><circle cx="12" cy="19" r="1.2" fill="currentColor" /></>),
  wifi_ap: I(<><rect x="4" y="13" width="16" height="7" rx="2" /><path d="M8 9a5.5 5.5 0 0 1 8 0M5.5 6.5a9 9 0 0 1 13 0" /><path d="M8 16.5h.01M12 16.5h.01" /></>),
};

const KEY = "siem.sidebar.collapsed";
const GKEY = "siem.sidebar.groupstate.";

export function useSidebarCollapsed(): [boolean, (v: boolean) => void] {
  const [c, setC] = useState<boolean>(() => { try { return localStorage.getItem(KEY) === "1"; } catch { return false; } });
  return [c, (v) => { setC(v); try { localStorage.setItem(KEY, v ? "1" : "0"); } catch { /* ignore */ } }];
}

/** Explicit open/closed choices per group; a group without one is open only while it holds the current page. */
function useGroupState(product: Product): [Record<string, boolean>, (t: string, open: boolean) => void] {
  const [f, setF] = useState<Record<string, boolean>>(() => { try { return JSON.parse(localStorage.getItem(GKEY + product) || "{}"); } catch { return {}; } });
  return [f, (t, open) => setF((cur) => {
    const n = { ...cur, [t]: open };
    try { localStorage.setItem(GKEY + product, JSON.stringify(n)); } catch { /* ignore */ }
    return n;
  })];
}

/** Product glyphs for menus (the platform mark stays the same; this marks the product's domain). */
export function ProductMark({ product, size = 18 }: { product: Product; size?: number }) {
  return <SentinelMark size={size} tone={product} />;
}

const CHEVRON = <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="M6 9l6 6 6-6" /></svg>;

export function Sidebar({ me, product, open, collapsed, setCollapsed, onLogout, lastIngest }: {
  me: Me; product: Product; open: boolean; collapsed: boolean; setCollapsed: (v: boolean) => void; onLogout: () => void; lastIngest?: string | null;
}) {
  const loc = useLocation();
  const nav = useNavigate();
  const grid = me.products.includes("grid");
  const nms = me.products.includes("nms");
  const gAlerts = useQuery({ queryKey: ["open-alert-count", "grid"], queryFn: () => api<any>("/alerts", { params: { status: ["new", "investigating"], size: 1, product: "grid" } }),
    refetchInterval: 60_000, staleTime: 30_000, enabled: grid && product === "grid" });
  const nAlerts = useQuery({ queryKey: ["open-alert-count", "nms"], queryFn: () => api<any>("/alerts", { params: { status: ["new", "investigating"], size: 1, product: "nms" } }),
    refetchInterval: 60_000, staleTime: 30_000, enabled: nms && product === "nms" });
  const incidents = useQuery({ queryKey: ["open-incident-count"], queryFn: () => api<any>("/incidents", { params: { status: ["open", "in_progress"], size: 1 } }),
    refetchInterval: 60_000, staleTime: 30_000, enabled: grid && product === "grid" });
  const wanInc = useQuery({ queryKey: ["open-wan-incident-count"], queryFn: () => api<any>("/wan/incidents", { params: { open_only: true, size: 1 } }),
    refetchInterval: 60_000, staleTime: 30_000, enabled: nms && product === "nms" });
  const badges: Record<string, number> = { grid_alerts: gAlerts.data?.total ?? 0, nms_alerts: nAlerts.data?.total ?? 0,
    incidents: incidents.data?.total ?? 0, wan_incidents: wanInc.data?.total ?? 0 };
  const [gstate, setGroup] = useGroupState(product);
  const [menu, setMenu] = useState(false);
  // collapsed rail applies on desktop only; the mobile drawer is always full width
  const rail = collapsed;
  const ingestAge = lastIngest ? (Date.now() - Date.parse(lastIngest.replace(" ", "T") + (/[zZ+]/.test(lastIngest.slice(19)) ? "" : "Z"))) / 1000 : null;
  const live = ingestAge !== null && ingestAge < 180;
  const initials = me.username.slice(0, 2).toUpperCase();
  const groups = [...NAV[product], ADMIN];
  const active = activeItem(groups, loc.pathname, loc.search);
  const others = me.products.filter((p) => p !== product);
  const sw = (p: Product) => { setMenu(false); nav(lastPathOf(p)); };
  const status = product === "grid" ? (live ? "Ingesting events" : lastIngest ? `Last event ${fmtAgo(lastIngest)}` : "No recent events") : PRODUCT[product].kind;

  return (
    <aside id="sidebar" aria-label="Sidebar"
      className={`fixed inset-y-0 left-0 z-40 shrink-0 bg-panel2 border-r border-line flex flex-col transition-[transform,width] duration-200 ease-out
        w-60 lg:static lg:translate-x-0 ${rail ? "lg:w-[4rem]" : "lg:w-60"} ${open ? "translate-x-0 shadow-pop" : "-translate-x-full"}`}>
      {/* brand + product switcher */}
      <div className={`relative flex items-center gap-2.5 h-14 px-3.5 border-b border-line ${rail ? "lg:justify-center lg:px-0" : ""}`}>
        <SentinelMark size={22} tone={product} />
        <div className={`min-w-0 flex-1 ${rail ? "lg:hidden" : ""}`}>
          <div className="font-semibold tracking-[-0.01em] text-[14px] text-slate-100 leading-tight truncate">Sentinel {PRODUCT[product].accent}</div>
          <div className="text-[10.5px] text-subtle flex items-center gap-1.5 truncate mt-0.5" title={product === "grid" && lastIngest ? `Last event ingested ${fmtAgo(lastIngest)}` : status}>
            {product === "grid" && <span className={`dot !h-1.5 !w-1.5 ${live ? "dot-ok" : "dot-warn"}`} aria-hidden />}
            <span className="truncate">{status}</span>
          </div>
        </div>
        {others.length > 0 && <button type="button" className={`btn-ghost btn btn-icon !p-1 shrink-0 text-subtle ${rail ? "lg:hidden" : ""}`}
          aria-label="Switch product" aria-haspopup="menu" aria-expanded={menu} onClick={() => setMenu(!menu)} title="Switch product">
          <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden><path d="M7 10l5-5 5 5M7 14l5 5 5-5" /></svg></button>}
        {menu && <>
          <div className="fixed inset-0 z-40" onClick={() => setMenu(false)} aria-hidden />
          <div role="menu" aria-label="Products" className="absolute left-2.5 right-2.5 top-12 z-50 rounded-lg border border-line bg-elevated shadow-pop p-1 animate-pop-in"
            onKeyDown={(e) => { if (e.key === "Escape") setMenu(false); }}>
            <div className="eyebrow px-2 py-1.5">Switch product</div>
            {me.products.map((p) => <button key={p} type="button" role="menuitemradio" aria-checked={p === product} autoFocus={p === others[0]}
              className={`w-full flex items-center gap-2.5 rounded-md px-2 py-2 text-left text-[13px] hover:bg-slate-800/70 focus-visible:outline-none focus-visible:bg-slate-800/70 ${p === product ? "text-slate-100" : "text-slate-300"}`}
              onClick={() => sw(p)}>
              <SentinelMark size={20} tone={p} />
              <span className="flex-1 min-w-0">{PRODUCT[p].name}<span className="block text-2xs text-subtle truncate">{PRODUCT[p].kind}</span></span>
              {p === product && <span className="pill bg-slate-800 text-muted">current</span>}</button>)}
            <div className="my-1 border-t border-line" />
            <button type="button" role="menuitem" className="w-full rounded-md px-2 py-1.5 text-left text-xs text-muted hover:bg-slate-800/70 hover:text-slate-200"
              onClick={() => { setMenu(false); nav("/select-product"); }}>All products…</button>
          </div></>}
      </div>

      {/* navigation */}
      <nav aria-label={`${PRODUCT[product].name} navigation`} className="flex-1 overflow-y-auto overflow-x-hidden py-3 px-2 space-y-1">
        {groups.map((g) => {
          const items = g.items.filter((it) => !it.admin || me.role === "admin");
          if (!items.length) return null;
          const holdsActive = items.some((it) => it.to === active);
          const isFolded = !rail && !(gstate[g.title] ?? holdsActive);
          const gid = `nav-${product}-${g.title.replace(/\W+/g, "-")}`;
          return (
          <div key={g.title}>
            <button type="button" className={`group/g w-full flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-medium ${holdsActive ? "text-slate-300" : "text-subtle"} hover:text-slate-200 transition-colors ${rail ? "lg:hidden" : ""}`}
              aria-expanded={!isFolded} aria-controls={gid} onClick={() => setGroup(g.title, isFolded)}>
              <span className="flex-1 text-left truncate">{g.title}</span>
              <span className={`opacity-60 group-hover/g:opacity-100 transition-transform duration-150 ${isFolded ? "-rotate-90" : ""}`}>{CHEVRON}</span></button>
            {rail && <div className="hidden lg:block mx-3 mb-2 border-t border-line" aria-hidden />}
            {!isFolded && <ul id={gid} className="space-y-px mt-0.5 mb-2">
              {items.map((it) => {
                const isActive = it.to === active;
                if (it.planned) return (
                  <li key={it.to}><span title={it.planned} aria-disabled="true"
                    className={`flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-[13px] text-subtle/70 cursor-not-allowed ${rail ? "lg:justify-center lg:px-0" : ""}`}>
                    <span className="shrink-0">{ICONS[it.icon]}</span><span className={`truncate flex-1 ${rail ? "lg:hidden" : ""}`}>{it.label}</span>
                    <span className={`pill bg-slate-800 text-subtle ${rail ? "lg:hidden" : ""}`}>planned</span></span></li>);
                const n = it.badge ? badges[it.badge] : 0;
                return (
                <li key={it.to}>
                  <Link to={it.to} aria-current={isActive ? "page" : undefined} aria-label={rail ? `${it.label}${n ? `, ${n} open` : ""}` : undefined}
                    title={rail ? it.label : undefined}
                    className={`group relative flex items-center gap-2.5 rounded-md px-2.5 py-[5px] text-[13px] transition-colors duration-100
                      ${rail ? "lg:justify-center lg:px-0 lg:py-2" : ""}
                      ${isActive ? "bg-hover text-slate-100 font-medium" : "text-slate-400 hover:bg-hover/60 hover:text-slate-100"}`}>
                    {isActive && <span className="absolute -left-2 top-2 bottom-2 w-[2px] rounded-r bg-brand-400" aria-hidden />}
                    <span className={`shrink-0 ${isActive ? "text-slate-100" : "text-subtle group-hover:text-slate-300"}`}>{ICONS[it.icon]}</span>
                    <span className={`truncate flex-1 ${rail ? "lg:hidden" : ""}`}>{it.label}</span>
                    {n > 0 && (
                      <span aria-label={rail ? undefined : `${n} open`}
                        className={`rounded bg-slate-800 text-red-400 text-[10px] font-semibold tabular-nums px-1.5 py-0.5 leading-none
                          ${rail ? "lg:absolute lg:top-0.5 lg:right-1 lg:px-1" : ""}`}>{n > 99 ? "99+" : n}</span>
                    )}
                  </Link>
                </li>);
              })}
            </ul>}
          </div>);
        })}
      </nav>

      {/* collapse (desktop) */}
      <button type="button" onClick={() => setCollapsed(!collapsed)} aria-label={rail ? "Expand sidebar" : "Collapse sidebar"} aria-expanded={!rail}
        className={`hidden lg:flex items-center gap-2 mx-2 mb-2 rounded-md px-2.5 py-1.5 text-xs text-subtle hover:bg-hover hover:text-slate-200 transition-colors ${rail ? "justify-center px-0" : ""}`}>
        <span className={`transition-transform duration-200 ${rail ? "rotate-180" : ""}`}>{ICONS.chevron}</span>
        {!rail && <span>Collapse</span>}
      </button>

      {/* user */}
      <div className={`border-t border-line p-3 flex items-center gap-2.5 ${rail ? "lg:flex-col lg:px-0" : ""}`}>
        <div className="h-8 w-8 shrink-0 rounded-full bg-slate-800 text-slate-300 flex items-center justify-center text-xs font-semibold"
          title={`${me.username} (${me.role})`} aria-hidden>{initials}</div>
        <div className={`min-w-0 flex-1 ${rail ? "lg:hidden" : ""}`}>
          <div className="flex items-center gap-1.5">
            <span className="text-[13px] font-medium text-slate-200 truncate">{me.username}</span>
            <span className="pill text-muted">{me.role}</span>
          </div>
          <div className="text-2xs text-subtle truncate" title="Display timezone (Settings → Preferences)">{me.timezone}</div>
        </div>
        <button type="button" onClick={onLogout} aria-label="Sign out" data-tip={rail ? "Sign out" : undefined}
          className="tip shrink-0 rounded-md p-1.5 text-subtle hover:bg-hover hover:text-slate-100 transition-colors">{ICONS.logout}</button>
      </div>
    </aside>
  );
}
