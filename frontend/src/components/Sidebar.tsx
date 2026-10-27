import { ReactNode, useState } from "react";
import { NavLink } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { Me } from "../lib/context";
import { fmtAgo } from "../lib/format";

// 24×24 stroke icons (inline, no icon dependency)
const I = (d: ReactNode) => (
  <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden>{d}</svg>
);
const ICONS: Record<string, ReactNode> = {
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
  tunnel: I(<><path d="M3 18V10a9 9 0 0 1 18 0v8" /><path d="M7 18v-7a5 5 0 0 1 10 0v7M3 18h18" /></>),
  logsrc: I(<><path d="M4 6h16M4 12h16M4 18h10" /><circle cx="19" cy="18" r="2" /></>),
  logout: I(<><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9" /></>),
  chevron: I(<path d="M15 18l-6-6 6-6" />),
};

interface Item { to: string; label: string; icon: string; end?: boolean; badge?: "alerts" | "incidents"; admin?: boolean }
const GROUPS: { title: string; items: Item[] }[] = [
  { title: "Overview", items: [{ to: "/", label: "Dashboard", icon: "dashboard", end: true }, { to: "/incidents", label: "Incidents", icon: "incidents", badge: "incidents" },
    { to: "/alerts", label: "Alerts", icon: "alerts", badge: "alerts" }] },
  { title: "Traffic", items: [{ to: "/sources", label: "Top Sources", icon: "sources" }, { to: "/destinations", label: "Top Destinations", icon: "destinations" },
    { to: "/ports", label: "Top Ports", icon: "ports" }, { to: "/web", label: "Web / URL", icon: "web" }, { to: "/dns", label: "DNS", icon: "dns" },
    { to: "/geo", label: "Geography", icon: "geo" }, { to: "/isp", label: "ISP / WAN", icon: "isp" }] },
  { title: "Threats", items: [{ to: "/security", label: "Security Events", icon: "security" }, { to: "/threat-intel", label: "Threat Intel", icon: "ti" },
    { to: "/vpn", label: "VPN & Users", icon: "vpn" }, { to: "/identity", label: "Users & Identity", icon: "identity" }, { to: "/explorer", label: "Event Explorer", icon: "explorer" }, { to: "/searches", label: "Saved Searches", icon: "searches" }] },
  { title: "Hunt & Automate", items: [{ to: "/search", label: "Search", icon: "search" }, { to: "/hunting", label: "Hunting", icon: "hunting" },
    { to: "/graph", label: "Entity Graph", icon: "graph" }, { to: "/workbooks", label: "Workbooks", icon: "workbooks" },
    { to: "/detections", label: "Detections", icon: "detections" }, { to: "/watchlists", label: "Watchlists", icon: "watchlists" },
    { to: "/automation", label: "Automation", icon: "automation" }] },
  { title: "Assets & Firewalls", items: [{ to: "/assets", label: "Assets", icon: "assets" }, { to: "/firewalls", label: "Firewalls", icon: "firewalls" },
    { to: "/fw-health", label: "Firewall Health", icon: "health" }, { to: "/vpn-tunnels", label: "VPN Tunnels", icon: "tunnel" }, { to: "/bgp", label: "BGP", icon: "bgp" },
    { to: "/policies", label: "Policy Analytics", icon: "policies", end: true }, { to: "/policies/shadow", label: "Shadow Analysis", icon: "shadow" },
    { to: "/drift", label: "Config Drift", icon: "drift" }, { to: "/hardening", label: "Hardening", icon: "hardening" }] },
  { title: "Governance", items: [{ to: "/compliance", label: "Compliance", icon: "compliance" }, { to: "/reports", label: "Reports", icon: "reports" }] },
  { title: "Administration", items: [{ to: "/log-sources", label: "Log Sources", icon: "logsrc" }, { to: "/notifications", label: "Notifications", icon: "notifications", admin: true }, { to: "/settings", label: "Settings", icon: "settings" }] },
];

const KEY = "siem.sidebar.collapsed";

export function useSidebarCollapsed(): [boolean, (v: boolean) => void] {
  const [c, setC] = useState<boolean>(() => { try { return localStorage.getItem(KEY) === "1"; } catch { return false; } });
  return [c, (v) => { setC(v); try { localStorage.setItem(KEY, v ? "1" : "0"); } catch { /* ignore */ } }];
}

export function Sidebar({ me, open, collapsed, setCollapsed, onLogout, lastIngest }: {
  me: Me; open: boolean; collapsed: boolean; setCollapsed: (v: boolean) => void; onLogout: () => void; lastIngest?: string | null;
}) {
  const alerts = useQuery({ queryKey: ["open-alert-count"], queryFn: () => api<any>("/alerts", { params: { status: ["new", "investigating"], size: 1 } }),
    refetchInterval: 60_000, staleTime: 30_000 });
  const openAlerts: number = alerts.data?.total ?? 0;
  const incidents = useQuery({ queryKey: ["open-incident-count"], queryFn: () => api<any>("/incidents", { params: { status: ["open", "in_progress"], size: 1 } }),
    refetchInterval: 60_000, staleTime: 30_000 });
  const openIncidents: number = incidents.data?.total ?? 0;
  const badges = { alerts: openAlerts, incidents: openIncidents };
  // collapsed rail applies on desktop only; the mobile drawer is always full width
  const rail = collapsed;
  const ingestAge = lastIngest ? (Date.now() - Date.parse(lastIngest.replace(" ", "T") + (/[zZ+]/.test(lastIngest.slice(19)) ? "" : "Z"))) / 1000 : null;
  const live = ingestAge !== null && ingestAge < 180;
  const initials = me.username.slice(0, 2).toUpperCase();

  return (
    <aside id="sidebar" aria-label="Sidebar"
      className={`fixed inset-y-0 left-0 z-40 shrink-0 bg-panel border-r border-line flex flex-col transition-[transform,width] duration-200
        w-60 lg:static lg:translate-x-0 ${rail ? "lg:w-16" : "lg:w-60"} ${open ? "translate-x-0" : "-translate-x-full"}`}>
      {/* brand */}
      <div className={`flex items-center gap-2.5 h-16 px-4 border-b border-line ${rail ? "lg:justify-center lg:px-0" : ""}`}>
        <div className="h-9 w-9 shrink-0 rounded-xl bg-[#e23744] flex items-center justify-center text-[#ffffff] shadow-[0_4px_12px_-4px_rgb(226_55_68/0.6)]">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
            <path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z" /><path d="M8 12h2l1.5-3 2 6 1.5-3h1" />
          </svg>
        </div>
        <div className={`min-w-0 ${rail ? "lg:hidden" : ""}`}>
          <div className="font-extrabold tracking-tight text-[15px] text-slate-100 leading-tight truncate">Sentinel <span className="text-brand-400">Grid</span></div>
          <div className="text-2xs text-muted flex items-center gap-1.5" title={lastIngest ? `Last event ingested ${fmtAgo(lastIngest)}` : "No recent ingestion"}>
            <span className={`h-1.5 w-1.5 rounded-full ${live ? "bg-emerald-400 animate-pulse" : "bg-amber-400"}`} aria-hidden />
            {live ? "Ingesting" : lastIngest ? `Last event ${fmtAgo(lastIngest)}` : "No recent events"}
          </div>
        </div>
      </div>

      {/* navigation */}
      <nav aria-label="Main" className="flex-1 overflow-y-auto overflow-x-hidden py-3 px-2 space-y-4">
        {GROUPS.map((g) => (
          <div key={g.title}>
            <div className={`px-3 mb-1.5 text-[10px] font-bold uppercase tracking-[0.1em] text-slate-500 ${rail ? "lg:hidden" : ""}`}>{g.title}</div>
            {rail && <div className="hidden lg:block mx-3 mb-2 border-t border-line" aria-hidden />}
            <ul className="space-y-0.5">
              {g.items.filter((it) => !it.admin || me.role === "admin").map((it) => (
                <li key={it.to}>
                  <NavLink to={it.to} end={it.end} title={rail ? it.label : undefined}
                    className={({ isActive }) => `group relative flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors
                      ${rail ? "lg:justify-center lg:px-0" : ""}
                      ${isActive ? "bg-brand-500/10 text-brand-400 font-semibold" : "text-slate-400 hover:bg-slate-800/60 hover:text-slate-100"}`}>
                    {({ isActive }) => (<>
                      {isActive && <span className="absolute left-0 top-1.5 bottom-1.5 w-[3px] rounded-r bg-[#e23744]" aria-hidden />}
                      <span className={`shrink-0 ${isActive ? "text-brand-400" : "text-slate-500 group-hover:text-slate-300"}`}>{ICONS[it.icon]}</span>
                      <span className={`truncate flex-1 ${rail ? "lg:hidden" : ""}`}>{it.label}</span>
                      {it.badge && badges[it.badge] > 0 && (
                        <span aria-label={`${badges[it.badge]} open ${it.badge}`}
                          className={`rounded-full bg-[#cb202d] text-[#ffffff] text-[10px] font-bold tabular-nums px-1.5 py-0.5 leading-none
                            ${rail ? "lg:absolute lg:top-0.5 lg:right-1.5 lg:px-1" : ""}`}>{badges[it.badge] > 99 ? "99+" : badges[it.badge]}</span>
                      )}
                    </>)}
                  </NavLink>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>

      {/* collapse (desktop) */}
      <button onClick={() => setCollapsed(!collapsed)} aria-label={rail ? "Expand sidebar" : "Collapse sidebar"} aria-expanded={!rail}
        className={`hidden lg:flex items-center gap-2 mx-2 mb-2 rounded-md px-2.5 py-1.5 text-xs text-slate-400 hover:bg-slate-800/60 hover:text-slate-200 ${rail ? "justify-center px-0" : ""}`}>
        <span className={`transition-transform ${rail ? "rotate-180" : ""}`}>{ICONS.chevron}</span>
        {!rail && <span>Collapse</span>}
      </button>

      {/* user */}
      <div className={`border-t border-line p-3 flex items-center gap-2.5 ${rail ? "lg:flex-col lg:px-0" : ""}`}>
        <div className="h-8 w-8 shrink-0 rounded-full bg-brand-500/15 text-brand-400 flex items-center justify-center text-xs font-bold" title={`${me.username} (${me.role})`} aria-hidden>{initials}</div>
        <div className={`min-w-0 flex-1 ${rail ? "lg:hidden" : ""}`}>
          <div className="flex items-center gap-1.5">
            <span className="text-sm text-slate-200 truncate">{me.username}</span>
            <span className={`pill ${me.role === "admin" ? "bg-brand-500/10 text-brand-400" : "bg-slate-700/60 text-slate-300"}`}>{me.role}</span>
          </div>
          <div className="text-2xs text-muted truncate" title="Display timezone (Settings → Preferences)">{me.timezone}</div>
        </div>
        <button onClick={onLogout} aria-label="Sign out" title="Sign out"
          className="shrink-0 rounded-lg p-1.5 text-slate-500 hover:bg-brand-500/10 hover:text-brand-400">{ICONS.logout}</button>
      </div>
    </aside>
  );
}
