import { useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";

export function useWlMeta() {
  return useQuery({ queryKey: ["wl", "meta"], queryFn: () => api<any>("/wireless/meta"), staleTime: 60_000 });
}

/** Navigate inside the Wireless page (tab + filters in the URL, so every count / chart click is a shareable view). */
export function useWlGo() {
  const [, setSp] = useSearchParams();
  return (tab: string, params: Record<string, string | number | undefined> = {}) =>
    setSp(Object.fromEntries(Object.entries({ tab, ...params }).filter(([, v]) => v !== undefined && v !== "").map(([k, v]) => [k, String(v)])));
}

const ST: Record<string, [string, string]> = {
  up: ["bg-emerald-400", "Up"], down: ["bg-red-500 animate-pulse", "Down"], degraded: ["bg-amber-400", "Degraded"], unknown: ["bg-slate-500", "Unknown"],
  maintenance: ["bg-sky-400", "Maintenance"], disabled: ["bg-slate-600", "Disabled"], auth_failed: ["bg-red-400", "Auth failed"], paused: ["bg-slate-700", "Paused"],
};
export function WState({ s }: { s?: string }) {
  const [c, l] = ST[s || "unknown"] || ST.unknown;
  return <span className="inline-flex items-center gap-1.5 whitespace-nowrap"><span className={`h-2.5 w-2.5 rounded-full ${c}`} aria-hidden />{l}</span>;
}

export function Band({ b }: { b?: string | null }) {
  if (!b) return <span className="text-slate-600">—</span>;
  const c = b === "2.4" ? "bg-amber-500/15 text-amber-300" : b === "6" ? "bg-sky-500/15 text-sky-300" : "bg-teal-500/15 text-teal-300";
  return <span className={`pill ${c}`}>{b} GHz</span>;
}

export const dash = (v: any, unit = "", d = 0) => (v == null || v === "" ? "—" : `${typeof v === "number" ? v.toFixed(d) : v}${unit}`);
export const dbm = (v?: number | null) => dash(v, " dBm");
export const pctv = (v?: number | null) => dash(v, "%");

export function Score({ e }: { e?: any }) {
  if (!e || e.score == null) return <span className="text-slate-600" title={e?.note || "no RF measurement"}>—</span>;
  const c = e.grade === "good" ? "text-emerald-300" : e.grade === "fair" ? "text-amber-300" : "text-red-300";
  return <span className={`tabular-nums font-semibold ${c}`} title={`${e.factors.map((f: any) => `${f.label} ${f.value}${f.unit === "%" ? "%" : " " + f.unit}: ${f.points}/100 (weight ${f.weight})`).join("\n")}\nconfidence ${Math.round(e.confidence * 100)}%`}>
    {e.score.toFixed(0)}<span className="text-2xs text-muted font-normal"> /100{e.confidence < 1 && ` · ${Math.round(e.confidence * 100)}% data`}</span></span>;
}

const FLAG: Record<string, string> = { high_utilization: "busy channel", wifi_interference: "802.11 interference", high_noise: "high noise", high_retries: "retries", down: "down" };
export function RfFlags({ f }: { f?: string[] }) {
  if (!f?.length) return null;
  return <span className="inline-flex flex-wrap gap-1">{f.map((x) => <span key={x} className="pill bg-red-500/10 text-red-300">{FLAG[x] || x}</span>)}</span>;
}

export const dur = (s?: number | null) => {
  if (s == null) return "—";
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`;
};
export const bytes = (v?: number | null) => (v == null ? "—" : v >= 1e9 ? `${(v / 1e9).toFixed(1)} GB` : v >= 1e6 ? `${(v / 1e6).toFixed(1)} MB` : `${(v / 1e3).toFixed(0)} kB`);
