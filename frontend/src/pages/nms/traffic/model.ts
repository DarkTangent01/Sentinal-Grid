/** Application & Protocol Intelligence — pure helpers (unit-tested in model.test.ts): URL filter state, series pivoting,
 *  labels. Every filter lives in the URL, so a drill-down is a link and the API receives exactly what the page shows. */

export const TABS = [
  { key: "overview", label: "Overview" }, { key: "applications", label: "Applications" }, { key: "protocols", label: "Protocols & QUIC" },
  { key: "sources", label: "Top Sources" }, { key: "destinations", label: "Top Destinations" }, { key: "conversations", label: "Conversations" },
  { key: "flows", label: "Flow Records" }, { key: "devices", label: "Devices" }, { key: "vlans", label: "VLAN Intelligence" }, { key: "interfaces", label: "Interfaces" },
  { key: "domains", label: "DNS & Domains" }, { key: "detections", label: "Detections" }, { key: "rules", label: "Rules & Signatures" },
  { key: "settings", label: "Networks & Settings" }, { key: "collectors", label: "Collectors" },
] as const;
export type TabKey = (typeof TABS)[number]["key"];

export const RANGES: [string, string][] = [["5m", "Last 5 minutes"], ["15m", "Last 15 minutes"], ["1h", "Last hour"], ["6h", "Last 6 hours"],
  ["24h", "Last 24 hours"], ["7d", "Last 7 days"], ["30d", "Last 30 days"], ["custom", "Custom range…"]];
export const DIRECTIONS: [string, string][] = [["east_west", "Internal (east-west)"], ["outbound", "Outbound"], ["inbound", "Inbound"], ["transit", "Transit"]];
export const FILTER_KEYS = ["range", "start", "end", "site", "exporter", "interface", "vlan", "app", "category", "proto", "port", "src", "dst", "ip", "direction"] as const;
export type FilterKey = (typeof FILTER_KEYS)[number];
export type TrafficFilters = Partial<Record<FilterKey, string>>;

const INT_KEYS = new Set<FilterKey>(["interface", "vlan", "proto", "port"]);

/** Filters from the URL: unknown keys are ignored, numbers must be whole numbers, custom ranges need both ends. */
export function readFilters(sp: URLSearchParams): TrafficFilters {
  const out: TrafficFilters = {};
  for (const k of FILTER_KEYS) {
    const v = (sp.get(k) || "").trim();
    if (!v) continue;
    if (INT_KEYS.has(k) && !/^\d+$/.test(v)) continue;
    out[k] = v;
  }
  if (!out.range || !RANGES.some(([r]) => r === out.range)) out.range = "1h";
  if (out.range === "custom" && !(out.start && out.end)) out.range = "1h";
  if (out.range !== "custom") { delete out.start; delete out.end; }
  if (out.interface && !out.exporter) delete out.interface;
  return out;
}

/** API query parameters: "custom" becomes start / end (ISO with zone), the range otherwise. */
export function apiParams(f: TrafficFilters): Record<string, string> {
  const out: Record<string, string> = {};
  for (const k of FILTER_KEYS) {
    const v = f[k];
    if (!v || k === "range") continue;
    if ((k === "start" || k === "end") && f.range !== "custom") continue;
    out[k] = k === "start" || k === "end" ? new Date(v).toISOString() : v;
  }
  if (f.range && f.range !== "custom") out.range = f.range;
  return out;
}

/** The URL after changing some filters (empty values remove the key; page / sort reset when filters change). */
export function withFilters(sp: URLSearchParams, patch: Record<string, string | number | null | undefined>, keep: string[] = ["tab"]): URLSearchParams {
  const next = new URLSearchParams();
  for (const [k, v] of sp.entries()) if ((FILTER_KEYS as readonly string[]).includes(k) || keep.includes(k)) next.set(k, v);
  for (const [k, v] of Object.entries(patch)) {
    if (v === null || v === undefined || v === "") next.delete(k);
    else next.set(k, String(v));
  }
  return next;
}

export function activeFilterCount(f: TrafficFilters): number {
  return FILTER_KEYS.filter((k) => !["range", "start", "end"].includes(k) && f[k]).length;
}

/** [{t, series, bps}] → [{t, <series>: bps}] plus the series names in first-seen order (for multi-series charts). */
export function pivot(points: { t: string; series: string; [k: string]: unknown }[], value = "bps"): { rows: Record<string, unknown>[]; series: string[] } {
  const by = new Map<string, Record<string, unknown>>();
  const names: string[] = [];
  for (const p of points) {
    if (!names.includes(p.series)) names.push(p.series);
    const row = by.get(p.t) || { t: p.t };
    row[p.series] = ((row[p.series] as number) || 0) + Number(p[value] || 0);
    by.set(p.t, row);
  }
  const rows = [...by.values()].sort((a, b) => String(a.t).localeCompare(String(b.t)));
  for (const r of rows) for (const n of names) if (r[n] === undefined) r[n] = 0;
  return { rows, series: names };
}

export const CONFIDENCE: Record<string, { label: string; cls: string; help: string }> = {
  confirmed: { label: "Confirmed", cls: "bg-emerald-500/15 text-emerald-300", help: "Firewall application control, or packet bytes in a sample prove the protocol" },
  high: { label: "High", cls: "bg-sky-500/15 text-sky-300", help: "The server address was resolved from a matching DNS name (not a shared address)" },
  probable: { label: "Probable", cls: "bg-indigo-500/15 text-indigo-300", help: "The server is in the provider's network (ASN); the application is not identified" },
  "port-based": { label: "Port-based", cls: "bg-amber-500/15 text-amber-300", help: "Protocol and port match a signature; nothing about the payload is known" },
  unknown: { label: "Unknown", cls: "bg-slate-700/60 text-slate-300", help: "No signature or evidence" },
  observed: { label: "Observed", cls: "bg-slate-700/60 text-slate-200", help: "Measured traffic pattern" },
};

export function directionLabel(d: string | null | undefined): string {
  return DIRECTIONS.find(([k]) => k === d)?.[1] || d || "—";
}

export function shortNum(n: number | null | undefined): string {
  if (n == null || !isFinite(n)) return "—";
  const a = Math.abs(n);
  return a >= 1e9 ? `${(n / 1e9).toFixed(1)}B` : a >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : a >= 1e3 ? `${(n / 1e3).toFixed(1)}k` : String(Math.round(n));
}

/** Detection-rule parameter editing: the value typed in the form, parsed as the default's type (null when invalid). */
export function parseParam(def: unknown, text: string): unknown {
  if (typeof def === "boolean") return text === "true";
  if (typeof def === "number") return /^\d+$/.test(text.trim()) ? Number(text.trim()) : null;
  if (Array.isArray(def)) return text.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
  return text;
}

export function paramText(v: unknown): string {
  return Array.isArray(v) ? v.join(", ") : v === undefined || v === null ? "" : String(v);
}
