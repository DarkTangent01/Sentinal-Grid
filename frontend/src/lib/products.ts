// Product registry: Sentinel Grid (SIEM) and Sentinel NMS (network monitoring) share one app, session and API.
// Which page belongs to which product, each product's navigation, and active-item matching live here (pure, tested in
// products.test.ts). The backend enforces the same boundary (backend/app/products.py); this file only shapes the UI.

export type Product = "grid" | "nms";
export const ALL_PRODUCTS: Product[] = ["grid", "nms"];

export const PRODUCT: Record<Product, { name: string; accent: string; kind: string; tagline: string; home: string; features: string[] }> = {
  grid: {
    name: "Sentinel Grid", accent: "Grid", kind: "Security Information and Event Management", home: "/grid",
    tagline: "Centralized security monitoring, threat detection, incident response, security analytics and threat hunting.",
    features: ["Alerts & incidents", "Threat intelligence", "Hunting & search", "Identity security", "Compliance evidence"],
  },
  nms: {
    name: "Sentinel NMS", accent: "NMS", kind: "Network Monitoring System", home: "/nms",
    tagline: "Network infrastructure visibility, ISP / WAN monitoring, device health, performance analytics, configuration management and network operations.",
    features: ["ISP / WAN & SD-WAN", "Wireless (Cisco WLC)", "Cisco, Fortinet, Juniper, Ruckus & any SNMP device", "Service checks & SLA analytics", "BGP & VPN tunnels",
      "TACACS+ AAA", "Policy & config management"],
  },
};

export interface NavItem { to: string; label: string; icon: string; end?: boolean; badge?: string; admin?: boolean; planned?: string;
  primary?: boolean }  // primary: highlighted when the path matches but no item's ?tab does
export interface NavGroup { title: string; items: NavItem[] }

export const NAV: Record<Product, NavGroup[]> = {
  grid: [
    { title: "Overview", items: [{ to: "/grid", label: "Dashboard", icon: "dashboard", end: true }, { to: "/incidents", label: "Incidents", icon: "incidents", badge: "incidents" },
      { to: "/alerts?product=grid", label: "Alerts", icon: "alerts", badge: "grid_alerts" }] },
    { title: "Security Analytics", items: [{ to: "/sources", label: "Top Sources", icon: "sources" }, { to: "/destinations", label: "Top Destinations", icon: "destinations" },
      { to: "/ports", label: "Top Ports", icon: "ports" }, { to: "/web", label: "Web / URL", icon: "web" }, { to: "/dns", label: "DNS", icon: "dns" },
      { to: "/geo", label: "Geography", icon: "geo" }, { to: "/explorer", label: "Event Explorer", icon: "explorer" }] },
    { title: "Threat Detection", items: [{ to: "/security", label: "Security Events", icon: "security" }, { to: "/threat-intel", label: "Threat Intel", icon: "ti" },
      { to: "/detections", label: "Detections", icon: "detections" }, { to: "/watchlists", label: "Watchlists", icon: "watchlists" },
      { to: "/searches", label: "Saved Searches", icon: "searches" }] },
    { title: "Security Operations", items: [{ to: "/search", label: "Search", icon: "search" }, { to: "/hunting", label: "Hunting", icon: "hunting" },
      { to: "/graph", label: "Entity Graph", icon: "graph" }, { to: "/workbooks", label: "Workbooks", icon: "workbooks" },
      { to: "/automation", label: "Automation", icon: "automation" }] },
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
    { title: "SNMP Monitoring", items: [{ to: "/snmp?tab=vendors", label: "Vendor & Device Overview", icon: "switch", primary: true },
      { to: "/snmp?tab=health", label: "Polling Health", icon: "health" }, { to: "/snmp?tab=traps", label: "SNMP Traps", icon: "alerts" },
      { to: "/snmp?tab=registry", label: "MIB / OID Registry", icon: "searches" }, { to: "/snmp?tab=custom", label: "Custom OIDs", icon: "workbooks" },
      { to: "/snmp?tab=mibs", label: "MIB Modules", icon: "policies" }, { to: "/snmp?tab=matrix", label: "Support Matrix", icon: "compliance" }] },
    { title: "Monitoring Operations", items: [{ to: "/nms/services", label: "Service Checks", icon: "web" },
      { to: "/nms/maintenance", label: "Maintenance Windows", icon: "searches" }, { to: "/nms/dependencies", label: "Device Dependencies", icon: "graph" }] },
    { title: "ISP & WAN Monitoring", items: [{ to: "/isp?tab=overview", label: "ISP / WAN", icon: "isp", primary: true }, { to: "/isp?tab=sdwan", label: "SD-WAN Health", icon: "health" },
      { to: "/isp?tab=live", label: "WAN Performance", icon: "explorer" }, { to: "/isp?tab=circuits", label: "Circuit Availability", icon: "ports" },
      { to: "/isp?tab=analytics", label: "ISP Incident Analytics", icon: "workbooks" }] },
    { title: "Wireless Analysis", items: [{ to: "/wireless?tab=overview", label: "Wireless Overview", icon: "wifi", primary: true },
      { to: "/wireless?tab=controllers", label: "WLC Inventory", icon: "firewalls" }, { to: "/wireless?tab=aps", label: "Access Points", icon: "wifi_ap" },
      { to: "/wireless?tab=clients", label: "Wireless Clients", icon: "identity" },
      { to: "/wireless?tab=wlans", label: "WLAN / SSID Analytics", icon: "web" }, { to: "/wireless?tab=roaming", label: "Roaming Analysis", icon: "graph" },
      { to: "/wireless?tab=events", label: "Wireless Events", icon: "searches" }, { to: "/alerts?product=nms&rule_prefix=wireless_", label: "Wireless Alerts", icon: "alerts" },
      { to: "/wireless?tab=troubleshoot", label: "Wireless Troubleshooting", icon: "hunting" }, { to: "/wireless?tab=health", label: "Monitoring Health", icon: "compliance" }] },
    { title: "RF & Frequency Monitoring", items: [{ to: "/wireless?tab=rf-overview", label: "RF Overview", icon: "wifi", primary: true },
      { to: "/wireless?tab=rf-frequency", label: "Frequency Distribution", icon: "ports" }, { to: "/wireless?tab=rf-heatmap", label: "Utilisation Heatmap", icon: "health" },
      { to: "/wireless?tab=rf-radios", label: "AP Radio Details", icon: "wifi_ap" }, { to: "/wireless?tab=rf-events", label: "RF Events", icon: "searches" },
      { to: "/wireless?tab=rf-findings", label: "RF Findings & Troubleshooting", icon: "hunting" }] },
    { title: "Network Infrastructure", items: [{ to: "/assets", label: "Assets", icon: "assets" }, { to: "/firewalls", label: "Firewalls", icon: "firewalls" },
      { to: "/fw-health", label: "Firewall Health", icon: "health" }, { to: "/vpn-tunnels", label: "VPN Tunnels", icon: "tunnel" }, { to: "/bgp", label: "BGP", icon: "bgp" },
      { to: "/switches", label: "Switch & Device Monitoring", icon: "switch" }] },
    { title: "Network Access & AAA", items: [{ to: "/tacacs", label: "TACACS+ AAA", icon: "aaa" },
      { to: "/tacacs?tab=identity", label: "Network User Access", icon: "identity" }, { to: "/tacacs?tab=clients", label: "Network Device Authentication", icon: "firewalls" }] },
    { title: "Configuration & Policy", items: [{ to: "/policies", label: "Policy Analytics", icon: "policies", end: true }, { to: "/policies/shadow", label: "Shadow Analysis", icon: "shadow" },
      { to: "/drift", label: "Config Drift", icon: "drift" }, { to: "/iac", label: "Infrastructure as Code", icon: "iac" }, { to: "/hardening", label: "Hardening", icon: "hardening" }] },
    { title: "Network Governance", items: [{ to: "/reports", label: "Network Reports", icon: "reports" }, { to: "/iac?tab=audit", label: "Configuration Audit", icon: "searches" },
      { to: "/network-compliance", label: "Network Compliance", icon: "compliance", planned: "Planned: network compliance frameworks are not implemented yet. Firewall hardening checks are under Hardening." }] },
  ],
};

/** Shared administration, shown in both products according to the user's role. */
export const ADMIN: NavGroup = {
  title: "Administration", items: [{ to: "/log-sources", label: "Log Sources", icon: "logsrc" }, { to: "/notifications", label: "Notifications", icon: "notifications", admin: true },
    { to: "/settings", label: "Settings", icon: "settings" }],
};

const OWN: Record<Product, string[]> = {
  grid: ["/grid", "/incidents", "/sources", "/destinations", "/ports", "/web", "/dns", "/geo", "/explorer", "/security", "/threat-intel", "/detections",
    "/watchlists", "/searches", "/search", "/hunting", "/graph", "/workbooks", "/automation", "/vpn", "/identity", "/compliance", "/investigate"],
  nms: ["/nms", "/snmp", "/isp", "/wireless", "/firewalls", "/fw-health", "/vpn-tunnels", "/bgp", "/switches", "/tacacs", "/policies", "/drift", "/iac", "/hardening"],
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
