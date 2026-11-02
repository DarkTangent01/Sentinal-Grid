import { Fragment, ReactNode, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { useTheme } from "../../lib/theme";
import { escHtml, fmtTime, getTimezone } from "../../lib/format";
import { Chart, PALETTES, SERIES_ROLE, axisStyle } from "../../components/Chart";
import { Empty } from "../../components/ui";
import { fmtBps, pairs } from "./fmt";

export { fmtBps, fmtPctOrDash, fmtUptime, fmtWatts, pairs, statusTone } from "./fmt";

export const RANGES: [string, string][] = [["15m", "15 min"], ["1h", "1 hour"], ["6h", "6 hours"], ["24h", "24 hours"], ["7d", "7 days"], ["30d", "30 days"]];

export function useSwitchMeta() {
  return useQuery({ queryKey: ["switch-meta"], queryFn: () => api<any>("/switches/meta"), staleTime: 300_000 });
}

const STATE: Record<string, [string, string]> = {
  up: ["bg-emerald-400", "Up"], down: ["bg-red-500 animate-pulse", "Down"], auth_failed: ["bg-red-400", "Auth failed"],
  unknown: ["bg-slate-500", "Pending"], paused: ["bg-slate-700", "Paused"],
};

export function StateDot({ s, monitoring }: { s: string; monitoring?: string }) {
  const [c, l] = STATE[monitoring === "paused" ? "paused" : s] || STATE.unknown;
  return <span className="inline-flex items-center gap-1.5 whitespace-nowrap"><span className={`h-2.5 w-2.5 rounded-full ${c}`} aria-hidden />{l}</span>;
}

const MSTATUS: Record<string, string> = {
  healthy: "bg-emerald-500/15 text-emerald-300", unavailable: "bg-amber-500/15 text-amber-300", unsupported: "bg-slate-700/60 text-slate-400",
  failed: "bg-red-500/15 text-red-300", stale: "bg-amber-500/15 text-amber-300", not_configured: "bg-slate-700/60 text-slate-300",
  pending: "bg-slate-700/40 text-slate-400",
};

export function MetricStatus({ s }: { s: string }) {
  return <span className={`pill ${MSTATUS[s] || MSTATUS.pending}`}>{s.replace("_", " ")}</span>;
}

export function Fresh({ f }: { f: string }) {
  const c = f === "fresh" ? "text-emerald-300" : f === "stale" ? "text-amber-300" : "text-muted";
  return <span className={`text-2xs ${c}`}>{f}</span>;
}

export function Oper({ s }: { s?: string }) {
  if (!s) return <span className="text-slate-600">—</span>;
  const c = s === "up" ? "text-emerald-300" : s === "down" || s === "lower_layer_down" ? "text-red-300" : "text-muted";
  return <span className={c}>{s.replace(/_/g, " ")}</span>;
}

export function Flags({ f }: { f?: string[] }) {
  if (!f?.length) return null;
  return <span className="inline-flex flex-wrap gap-1">{f.map((x) => <span key={x} title={x} className="pill bg-slate-700/60 text-slate-300 text-2xs">{x.replace(/_/g, " ")}</span>)}</span>;
}

export function Util({ v }: { v?: number | null }) {
  if (v == null) return <span className="text-slate-600" title="no utilisation: speed unknown, virtual interface or no valid sample">—</span>;
  const c = v >= 90 ? "text-red-300" : v >= 70 ? "text-amber-300" : "";
  return <span className={`tabular-nums ${c}`}>{v.toFixed(v < 10 ? 1 : 0)}%</span>;
}

export function Bps({ v }: { v?: number | null }) {
  return v == null ? <span className="text-slate-600">—</span> : <span className="tabular-nums">{fmtBps(v)}</span>;
}

export function RangeSelect({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return <select aria-label="Time range" className="input py-1" value={value} onChange={(e) => onChange(e.target.value)}>
    {RANGES.map(([k, l]) => <option key={k} value={k}>Last {l}</option>)}</select>;
}

export function Section({ title, children, right }: { title: string; children: ReactNode; right?: ReactNode }) {
  return <section className="space-y-2"><div className="flex items-center gap-2"><h3 className="text-sm font-semibold">{title}</h3><div className="ml-auto">{right}</div></div>{children}</section>;
}

/** Line chart that keeps missing samples as gaps (null), so "not measured" never looks like zero. */
export function SeriesChart({ points, series, unit, height = 220, bucket = 60, yMax }: {
  points: any[]; series: { key: string; name: string; color?: string; dashed?: boolean; bar?: boolean }[]; unit: "bps" | "pct" | "count" | "w" | "c" | "raw";
  height?: number; bucket?: number; yMax?: number;
}) {
  const { theme } = useTheme();
  const fmt = (v: number) => unit === "bps" ? fmtBps(v) : unit === "pct" ? `${v.toFixed(0)}%` : unit === "w" ? `${v.toFixed(0)} W` : unit === "c" ? `${v.toFixed(0)} °C` : Number(v).toLocaleString();
  const option = useMemo(() => ({
    legend: { top: 0 },
    xAxis: { type: "time", ...axisStyle, axisLabel: { ...axisStyle.axisLabel, formatter: (v: number) => new Date(v).toLocaleString(undefined, {
      hour: "2-digit", minute: "2-digit", hour12: false, timeZone: getTimezone(), ...(bucket >= 3600 ? { month: "short", day: "2-digit" } : {}) }) } },
    yAxis: { type: "value", ...axisStyle, max: yMax, min: 0, axisLabel: { ...axisStyle.axisLabel, formatter: fmt } },
    tooltip: { trigger: "axis", confine: true, formatter: (ps: any[]) => !ps?.length ? "" : `<b>${fmtTime(new Date(ps[0].value[0]))}</b>` +
      ps.map((p) => `<br/>${p.marker}${escHtml(p.seriesName)}: <b>${p.value[1] == null ? "no sample" : escHtml(fmt(p.value[1]))}</b>`).join("") },
    series: series.map((s, i) => ({
      name: s.name, type: s.bar ? "bar" : "line", showSymbol: points.length < 30, connectNulls: false, barMaxWidth: 8,
      itemStyle: { color: s.color && s.color in SERIES_ROLE[theme] ? (SERIES_ROLE[theme] as any)[s.color] : s.color || PALETTES[theme][i % 8] },
      lineStyle: { width: s.dashed ? 1 : 2, type: s.dashed ? "dashed" : "solid" }, data: pairs(points, s.key),
    })),
  }), [points, series, theme, unit, bucket, yMax]);
  if (!points.length) return <div style={{ height }} className="flex items-center justify-center"><Empty text="No samples in this range yet." /></div>;
  return <Chart height={height} option={option} />;
}

export function KV({ rows }: { rows: [string, ReactNode][] }) {
  return <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">{rows.map(([k, v]) => <Fragment key={k}><dt className="text-muted">{k}</dt><dd className="min-w-0 break-words">{v ?? "—"}</dd></Fragment>)}</dl>;
}
