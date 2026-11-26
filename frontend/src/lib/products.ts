// Product registry: Sentinel Grid (SIEM) and Sentinel NMS (network monitoring) share one app, session and API.
// Which page belongs to which product, each product's navigation, and active-item matching live here (pure, tested in
// products.test.ts). The backend enforces the same boundary (backend/app/products.py); this file only shapes the UI.

export type Product = "grid" | "nms";
export const ALL_PRODUCTS: Product[] = ["grid", "nms"];

/** Build-time product (npm run build:grid | build:nms set VITE_PRODUCT): that product's app alone, served on its
 *  own address with its own API (docs/architecture/FRONTEND_SEPARATION.md). null = the combined app with both. */
export const BUILD_PRODUCT: Product | null = toProduct(import.meta.env.VITE_PRODUCT);

export function toProduct(v: string | undefined | null): Product | null {
  return v === "grid" || v === "nms" ? v : null;
}

/** The products this build offers to an account: its allowed products, narrowed to the build's product. */
export function buildProducts(allowed: Product[], build: Product | null = BUILD_PRODUCT): Product[] {
  return build ? allowed.filter((p) => p === build) : allowed;
}

/** Pages shared in the combined app whose API belongs to Sentinel Grid (assets inventory, log sources): a
 *  Sentinel NMS build leaves them out. */
export const GRID_SERVED = ["/assets", "/log-sources"];

export function servedBy(path: string, build: Product | null = BUILD_PRODUCT): boolean {
  const p = path.split("?")[0];
  if (build === "nms" && GRID_SERVED.some((x) => p === x || p.startsWith(x + "/"))) return false;
  const owner = productOfLocation(p);
  return !build || !owner || owner === build;
}

export function filterNav(groups: NavGroup[], build: Product | null = BUILD_PRODUCT): NavGroup[] {
  return groups.map((g) => ({ ...g, items: g.items.filter((it) => servedBy(it.to, build)) })).filter((g) => g.items.length);
}

export const PRODUCT: Record<Product, { name: string; accent: string; kind: string; tagline: string; home: string; features: string[] }> = {
  grid: {
    name: "Sentinel Grid", accent: "Grid", kind: "Security Intelligence Platform", home: "/grid",
    tagline: "Security monitoring, threat detection, incident response, security analytics and threat hunting.",
    features: ["Alerts & incidents", "Threat intelligence", "Hunting & search", "Identity security", "Compliance evidence"],
  },
  nms: {
    name: "Sentinel NMS", accent: "NMS", kind: "Network Monitoring & Intelligence", home: "/nms",
    tagline: "Network visibility, ISP / WAN monitoring, device health, traffic intelligence, configuration management and network operations.",
    features: ["ISP / WAN & SD-WAN", "Traffic & application intelligence", "Wireless (Cisco WLC)", "Cisco, Fortinet, Juniper, Ruckus & any SNMP device",
      "Service checks & SLA analytics", "BGP, VPN tunnels & TACACS+", "Policy & config management"],
  },
};

export interface NavItem { to: string; label: string; icon: string; end?: boolean; badge?: string; admin?: boolean; planned?: string;
  primary?: boolean }  // primary: highlighted when the path matches but no item's ?tab does
export interface NavGroup { title: string; items: NavItem[] }

const ALL_NAV: Record<Product, NavGroup[]> = {
  grid: [
    { title: "Overview", items: [{ to: "/grid", label: "Dashboard", icon: "dashboard", end: true }, { to: "/soc", label: "SOC Overview", icon: "workbooks" },
      { to: "/incidents", label: "Incidents", icon: "incidents", badge: "incidents" },
      { to: "/alerts?product=grid", label: "Alerts", icon: "alerts", badge: "grid_alerts" }] },
    { title: "Security Analytics", items: [{ to: "/sources", label: "Top Sources", icon: "sources" }, { to: "/destinations", label: "Top Destinations", icon: "destinations" },
      { to: "/ports", label: "Top Ports", icon: "ports" }, { to: "/web", label: "Web / URL", icon: "web" }, { to: "/dns", label: "DNS", icon: "dns" },
      { to: "/geo", label: "Geography", icon: "geo" }, { to: "/network-security", label: "Network Security (Zeek)", icon: "web" },
      { to: "/explorer", label: "Event Explorer", icon: "explorer" }] },
    { title: "Threat Detection", items: [{ to: "/security", label: "Security Events", icon: "security" }, { to: "/threat-intel", label: "Threat Intel", icon: "ti" },
      { to: "/detections", label: "Detections", icon: "detections" }, { to: "/attack", label: "ATT&CK Coverage", icon: "compliance" },
      { to: "/risk", label: "Entity Risk", icon: "identity" }, { to: "/watchlists", label: "Watchlists", icon: "watchlists" },
      { to: "/searches", label: "Saved Searches", icon: "searches" }] },
    { title: "Security Operations", items: [{ to: "/search", label: "Search", icon: "search" }, { to: "/hunting", label: "Hunting", icon: "hunting" },
      { to: "/graph", label: "Entity Graph", icon: "graph" }, { to: "/workbooks", label: "Workbooks", icon: "workbooks" },
      { to: "/automation", label: "Automation", icon: "automation" }, { to: "/response", label: "Response Actions", icon: "security" }] },
    { title: "Identity & Access Security", items: [{ to: "/vpn", label: "VPN & Users", icon: "vpn" }, { to: "/identity", label: "Users & Identity", icon: "identity" }] },
    { title: "Governance", items: [{ to: "/compliance", label: "Compliance", icon: "compliance" }, { to: "/reports", label: "Security Reports", icon: "reports" }] },
  ],
  nms: [
    { title: "Network Overview", items: [{ to: "/nms", label: "Network Dashboard", icon: "dashboard", end: true },
      { to: "/isp?tab=incidents", label: "Network Incidents", icon: "incidents", badge: "wan_incidents" },
      { to: "/alerts?product=nms", label: "Network Alerts", icon: "alerts", badge: "nms_alerts" }] },
    { title: "Network Analytics", items: [{ to: "/nms/analytics?tab=health", label: "Device Health Scores", icon: "health", primary: true },
      { to: "/nms/analytics?tab=availability", label: "Availability & SLA", icon: "compliance" }, { to: "/nms/analytics?tab=capacity", label: "Capacity Planning", icon: "workbooks" },
      { to: "/nms/analytics?tab=top", label: "Top-N & 95th Percentile", icon: "ports" }, { to: "/nms/analytics?tab=inventory", label: "Inventory & Lifecycle", icon: "assets" },
      { to: "/nms/analytics?tab=alerts", label: "Alert Analytics", icon: "alerts" }] },
    { title: "Application & Protocol Intelligence", items: [{ to: "/nms/traffic?tab=overview", label: "Traffic Overview", icon: "explorer", primary: true },
      { to: "/nms/traffic?tab=applications", label: "Applications", icon: "web" }, { to: "/nms/traffic?tab=protocols", label: "Protocols & QUIC", icon: "ports" },
      { to: "/nms/traffic?tab=sources", label: "Top Talkers", icon: "sources" }, { to: "/nms/traffic?tab=conversations", label: "Conversations", icon: "graph" },
      { to: "/nms/traffic?tab=devices", label: "Device Intelligence", icon: "assets" },
      { to: "/nms/traffic?tab=vlans", label: "VLAN Intelligence", icon: "switch" }, { to: "/nms/traffic?tab=interfaces", label: "Interface Traffic", icon: "health" },
      { to: "/nms/traffic?tab=domains", label: "DNS & Domains", icon: "dns" }, { to: "/nms/traffic?tab=detections", label: "Traffic Detections", icon: "alerts" },
      { to: "/nms/traffic?tab=rules", label: "Traffic Rules", icon: "policies" }, { to: "/nms/traffic?tab=collectors", label: "Flow Collectors", icon: "compliance" }] },
    { title: "Devices & Interfaces", items: [{ to: "/switches?tab=inventory", label: "Devices", icon: "switch", primary: true },
      { to: "/nms/interfaces", label: "Interfaces", icon: "ports" }, { to: "/switches?tab=overview", label: "Device Overview", icon: "health" },
      { to: "/switches?tab=topology", label: "Topology", icon: "graph" }, { to: "/switches?tab=templates", label: "Monitoring Templates", icon: "workbooks", admin: true },
      { to: "/switches?tab=settings", label: "SNMP Profiles & Discovery", icon: "policies", admin: true }] },
    { title: "SNMP Monitoring", items: [{ to: "/snmp?tab=vendors", label: "Vendor & Device Overview", icon: "switch", primary: true },
      { to: "/snmp?tab=health", label: "Polling Health", icon: "health" }, { to: "/snmp?tab=traps", label: "SNMP Traps", icon: "alerts" },
      { to: "/snmp?tab=registry", label: "MIB / OID Registry", icon: "searches" }, { to: "/snmp?tab=custom", label: "Custom OIDs", icon: "workbooks" },
      { to: "/snmp?tab=mibs", label: "MIB Modules", icon: "policies" }, { to: "/snmp?tab=matrix", label: "Support Matrix", icon: "compliance" }] },
    { title: "Monitoring Operations", items: [{ to: "/nms/services", label: "Service Checks", icon: "web" },
      { to: "/nms/maintenance", label: "Maintenance Windows", icon: "searches" }, { to: "/nms/dependencies", label: "Device Dependencies", icon: "graph" },
      { to: "/nms/configs", label: "Config Changes", icon: "policies" }, { to: "/nms/monitoring", label: "NMS Self-Monitoring", icon: "health" }] },
    { title: "Device Access", items: [{ to: "/nms/access?tab=devices", label: "Device Access & SSH", icon: "terminal", primary: true },
      { to: "/nms/access?tab=bulk", label: "Bulk Diagnostics", icon: "automation" }, { to: "/nms/access?tab=automation", label: "Ansible Automation", icon: "iac" },
      { to: "/nms/access?tab=consoles", label: "Console Servers", icon: "terminal" }, { to: "/nms/access?tab=changes", label: "Change Requests", icon: "policies" },
      { to: "/nms/access?tab=sessions", label: "Access Sessions", icon: "identity" }, { to: "/nms/access?tab=vault", label: "Credential Vault", icon: "vpn" },
      { to: "/nms/access?tab=audit", label: "Access Audit", icon: "searches" }, { to: "/nms/access?tab=roles", label: "NMS Roles", icon: "aaa", admin: true }] },
    { title: "ISP & WAN Monitoring", items: [{ to: "/isp?tab=overview", label: "ISP / WAN", icon: "isp", primary: true }, { to: "/isp?tab=sdwan", label: "SD-WAN Health", icon: "health" },
      { to: "/isp?tab=live", label: "WAN Performance", icon: "explorer" }, { to: "/isp?tab=circuits", label: "Circuit Availability", icon: "ports" },
      { to: "/isp?tab=analytics", label: "ISP Incident Analytics", icon: "workbooks" }] },
    { title: "Wireless Analysis", items: [{ to: "/wireless?tab=overview", label: "Wireless Overview", icon: "wifi", primary: true },
      { to: "/wireless?tab=controllers", label: "WLC Inventory", icon: "firewalls" }, { to: "/wireless?tab=aps", label: "Access Points", icon: "wifi_ap" },
      { to: "/wireless?tab=clients", label: "Wireless Clients", icon: "identity" },
      { to: "/wireless?tab=wlans", label: "WLAN / SSID Analytics", icon: "web" }, { to: "/wireless?tab=roaming", label: "Roaming Analysis", icon: "graph" }, { to: "/wireless?tab=floors", label: "Floor Experience", icon: "health" },
      { to: "/wireless?tab=rogues", label: "Rogue APs", icon: "alerts" },
      { to: "/wireless?tab=events", label: "Wireless Events", icon: "searches" }, { to: "/alerts?product=nms&rule_prefix=wireless_", label: "Wireless Alerts", icon: "alerts" },
      { to: "/wireless?tab=troubleshoot", label: "Wireless Troubleshooting", icon: "hunting" }, { to: "/wireless?tab=health", label: "Monitoring Health", icon: "compliance" },
      { to: "/wireless?tab=integrations", label: "Controller & Cloud Integrations", icon: "graph" }] },
    { title: "RF & Frequency Monitoring", items: [{ to: "/wireless?tab=rf-overview", label: "RF Overview", icon: "wifi", primary: true },
      { to: "/wireless?tab=rf-frequency", label: "Frequency Distribution", icon: "ports" }, { to: "/wireless?tab=rf-heatmap", label: "Utilisation Heatmap", icon: "health" },
      { to: "/wireless?tab=rf-radios", label: "AP Radio Details", icon: "wifi_ap" }, { to: "/wireless?tab=rf-events", label: "RF Events", icon: "searches" },
      { to: "/wireless?tab=rf-findings", label: "RF Findings & Troubleshooting", icon: "hunting" }] },
    { title: "Network Infrastructure", items: [{ to: "/assets", label: "Assets", icon: "assets" }, { to: "/firewalls", label: "Firewalls", icon: "firewalls" },
      { to: "/fw-health", label: "Firewall Health", icon: "health" }, { to: "/vpn-tunnels", label: "VPN Tunnels", icon: "tunnel" }, { to: "/bgp", label: "BGP", icon: "bgp" },
      { to: "/switches?tab=events", label: "Device Events", icon: "searches" }] },
    { title: "Network Access & AAA", items: [{ to: "/tacacs", label: "TACACS+ AAA", icon: "aaa" },
      { to: "/tacacs?tab=identity", label: "Network User Access", icon: "identity" }, { to: "/tacacs?tab=clients", label: "Network Device Authentication", icon: "firewalls" }] },
    { title: "Configuration & Policy", items: [{ to: "/policies", label: "Policy Analytics", icon: "policies", end: true }, { to: "/policies/shadow", label: "Shadow Analysis", icon: "shadow" },
      { to: "/drift", label: "Config Drift", icon: "drift" }, { to: "/iac", label: "Infrastructure as Code", icon: "iac" }, { to: "/hardening", label: "Hardening", icon: "hardening" }] },
    { title: "Network Governance", items: [{ to: "/reports", label: "Network Reports", icon: "reports" }, { to: "/iac?tab=audit", label: "Configuration Audit", icon: "searches" },
      { to: "/network-compliance", label: "Network Compliance", icon: "compliance" }] },
  ],
};

/** Shared administration, shown in both products according to the user's role. */
const ALL_ADMIN: NavGroup = {
  title: "Administration", items: [{ to: "/log-sources", label: "Log Sources", icon: "logsrc" }, { to: "/notifications", label: "Notifications", icon: "notifications", admin: true },
    { to: "/settings", label: "Settings", icon: "settings" }],
};

const OWN: Record<Product, string[]> = {
  grid: ["/grid", "/incidents", "/sources", "/destinations", "/ports", "/web", "/dns", "/geo", "/explorer", "/security", "/threat-intel", "/detections",
    "/watchlists", "/searches", "/search", "/hunting", "/graph", "/workbooks", "/automation", "/vpn", "/identity", "/compliance", "/investigate",
    "/soc", "/attack", "/risk", "/response", "/network-security"],
  nms: ["/nms", "/snmp", "/isp", "/wireless", "/firewalls", "/fw-health", "/vpn-tunnels", "/bgp", "/switches", "/tacacs", "/policies", "/drift", "/iac", "/hardening", "/network-compliance"],
};

const under = (path: string, p: string) => path === p || path.startsWith(p + "/");

/** Product that owns a page; null for shared pages (alerts, reports, assets, administration) unless the URL says. */
export function productOfLocation(pathname: string, search = ""): Product | null {
  for (const p of ALL_PRODUCTS) if (OWN[p].some((x) => under(pathname, x))) return p;
  if (under(pathname, "/alerts")) {
    const v = new URLSearchParams(search).get("product");
    return v === "grid" || v === "nms" ? v : null;
  }
  return null;
}

/** The nav item to highlight: an item whose query (e.g. ?tab=sdwan) matches beats a plain path match; longest path wins. */
export function activeItem(groups: NavGroup[], pathname: string, search: string): string | null {
  const sp = new URLSearchParams(search);
  let best: { to: string; score: number } | null = null;
  for (const g of groups) for (const it of g.items) {
    if (it.planned) continue;
    const [path, qs] = it.to.split("?");
    if (!(it.end ? pathname === path : under(pathname, path))) continue;
    let score = path.length * 10;
    if (qs) {
      const want = new URLSearchParams(qs);
      const ok = [...want.entries()].every(([k, v]) => sp.get(k) === v);
      if (!ok) continue;
      score += 5 * [...want.keys()].length;  // the more specific query wins (/alerts?product=nms&rule_prefix=… over ?product=nms)
    }
    if (!best || score > best.score) best = { to: it.to, score };
  }
  if (best) return best.to;
  // e.g. /isp with no tab: the path's primary item, else its first item
  const cands = groups.flatMap((g) => g.items).filter((it) => !it.planned && under(pathname, it.to.split("?")[0]));
  return (cands.find((it) => it.primary) || cands[0])?.to ?? null;
}

/** Where to land after sign-in at "/": selector, the only product, or the user's chosen default. */
export function entryTarget(me: { products: Product[]; default_product?: Product | null }): string {
  if (!me.products.length) return "/no-access";
  if (me.products.length === 1) return PRODUCT[me.products[0]].home;
  if (me.default_product && me.products.includes(me.default_product)) return PRODUCT[me.default_product].home;
  return "/select-product";
}

const LAST = "siem.product.last";
const LAST_PATH = "siem.product.lastPath.";
export function rememberProduct(p: Product, path?: string) {
  try { sessionStorage.setItem(LAST, p); if (path) sessionStorage.setItem(LAST_PATH + p, path); } catch { /* ignore */ }
}
export function lastProduct(allowed: Product[]): Product | null {
  try { const v = sessionStorage.getItem(LAST) as Product | null; if (v && allowed.includes(v)) return v; } catch { /* ignore */ }
  return allowed[0] ?? null;
}
export function forgetProducts() {
  try { for (const k of Object.keys(sessionStorage)) if (k.startsWith("siem.product.")) sessionStorage.removeItem(k); } catch { /* ignore */ }
}
/** Last page visited in a product during this session (the switcher returns there), else its dashboard. */
export function lastPathOf(p: Product): string {
  try {
    const v = sessionStorage.getItem(LAST_PATH + p);
    if (v && productOfLocation(v.split("?")[0], v.includes("?") ? v.slice(v.indexOf("?")) : "") === p) return v;
  } catch { /* ignore */ }
  return PRODUCT[p].home;
}

// after OWN / under: the filters read them
export const NAV: Record<Product, NavGroup[]> = { grid: filterNav(ALL_NAV.grid), nms: filterNav(ALL_NAV.nms) };
export const ADMIN: NavGroup = filterNav([ALL_ADMIN])[0];
