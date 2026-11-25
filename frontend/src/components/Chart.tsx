import { useEffect, useRef } from "react";
import { echarts } from "../lib/echarts";
import { Theme, useTheme } from "../lib/theme";

/** Categorical slots, assigned in this fixed order (never cycled past 8: fold the rest into "Other"). The Sentinel
 *  chart palette leads with the two product accents and keeps clear of the status hues (no pure green / red / amber),
 *  so a categorical series is never mistaken for "healthy" or "down". */
export const PALETTES: Record<Theme, string[]> = {
  dark: ["#38bdf8", "#a78bfa", "#2dd4bf", "#f472b6", "#fbbf24", "#818cf8", "#fb923c", "#94a3b8"],
  light: ["#0284c7", "#7c3aed", "#0d9488", "#db2777", "#d97706", "#4f46e5", "#ea580c", "#64748b"],
};
/** Severity, identical in every module (docs/design-system.md). */
export const SEV_HEX: Record<string, string> = { critical: "#ef4444", high: "#f97316", medium: "#f59e0b", low: "#38bdf8", informational: "#64748b" };

/** The product accent as a hex colour (from --chart-primary, set by <html data-product>). */
function cssColor(name: string, fallback: string): string {
  try {
    const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    const p = v.split(/\s+/).map(Number);
    if (p.length === 3 && p.every((n) => Number.isFinite(n))) return "#" + p.map((n) => n.toString(16).padStart(2, "0")).join("");
  } catch { /* no DOM (tests) */ }
  return fallback;
}

/** Semantic series colours. primary = the product's own volume / traffic series (Sentinel NMS cyan, Sentinel Grid
 *  violet), alert = denied / blocked / threat / down, warn = degraded (draw it dashed beside alert: the amber / red pair
 *  needs a second cue for colour-blind readers), muted = secondary context. */
export type SeriesRole = "primary" | "alert" | "warn" | "muted";
export const SERIES_ROLE: Record<Theme, Record<SeriesRole, string>> = {
  light: { get primary() { return cssColor("--chart-primary", "#0284c7"); }, alert: "#dc2626", warn: "#d97706", muted: "#94a3b8" },
  dark: { get primary() { return cssColor("--chart-primary", "#38bdf8"); }, alert: "#ef4444", warn: "#f59e0b", muted: "#64748b" },
};
/** Operational state colours for charts, graphs and status bars (one definition for every module).
 *  ok = up / established / healthy, warn = degraded, bad = down / failed / lost, unknown = no data, paused = not monitored.
 *  Pair ok with bad only alongside a second cue (label, icon or dash): the green / red pair alone fails for CVD. */
export type StatusKey = "ok" | "warn" | "bad" | "unknown" | "paused";
export const STATUS_HEX: Record<Theme, Record<StatusKey, string>> = {
  light: { ok: "#16a34a", warn: "#d97706", bad: "#dc2626", unknown: "#94a3b8", paused: "#cbd5e1" },
  dark: { ok: "#22c55e", warn: "#f59e0b", bad: "#ef4444", unknown: "#64748b", paused: "#334155" },
};
const STATUS_OF: Record<string, StatusKey> = {
  up: "ok", ok: "ok", established: "ok", healthy: "ok", passed: "ok", reachable: "ok",
  degraded: "warn", warning: "warn", flapping: "warn",
  down: "bad", failed: "bad", lost: "bad", auth_failed: "bad", unreachable: "bad", critical: "bad",
  paused: "paused", maintenance: "paused",
};
/** Colour for a state string from any module (unrecognised states read as "unknown"). */
export const statusColor = (theme: Theme, state?: string | null) => STATUS_HEX[theme][STATUS_OF[String(state || "").toLowerCase()] || "unknown"];
export const seriesColor =(theme: Theme, color: string | undefined, i: number) =>
  (color && color in SERIES_ROLE[theme] ? SERIES_ROLE[theme][color as SeriesRole] : color) ?? PALETTES[theme][i % 8];
/** Sequential (magnitude) ramp, one hue, low → high. */
export const SEQUENTIAL: Record<Theme, string[]> = { light: ["#e0f2fe", "#38bdf8", "#075985"], dark: ["#0c3a5a", "#0ea5e9", "#bae6fd"] };

/** Neutral chart chrome per theme. Mirrors the --chart-* tokens in index.css. */
export const CHART_THEME: Record<Theme, { text: string; strong: string; axis: string; split: string; tooltip: string; tooltipBorder: string; surface: string; land: string }> = {
  dark: { text: "#94a3b8", strong: "#f1f5f9", axis: "#263449", split: "#1a263a", tooltip: "#162238", tooltipBorder: "#263449", surface: "#111c2e", land: "#1c2a40" },
  light: { text: "#475569", strong: "#0f172a", axis: "#cbd5e1", split: "#eef2f7", tooltip: "#ffffff", tooltipBorder: "#e2e8f0", surface: "#ffffff", land: "#e2e8f0" },
};

for (const [name, c] of Object.entries(CHART_THEME) as [Theme, (typeof CHART_THEME)[Theme]][]) {
  const axis = { axisLine: { lineStyle: { color: c.axis } }, axisTick: { lineStyle: { color: c.axis } },
    splitLine: { lineStyle: { color: c.split } }, axisLabel: { color: c.text } };
  echarts.registerTheme(`siem-${name}`, {
    color: PALETTES[name], backgroundColor: "transparent", textStyle: { color: c.text, fontFamily: "Inter Variable, Inter, system-ui, sans-serif" },
    legend: { textStyle: { color: c.text }, pageTextStyle: { color: c.text } },
    tooltip: { backgroundColor: c.tooltip, borderColor: c.tooltipBorder, textStyle: { color: c.strong },
      extraCssText: "border-radius:8px;box-shadow:0 12px 32px -12px rgba(2,6,23,.45);font-variant-numeric:tabular-nums;" },
    categoryAxis: axis, valueAxis: axis, timeAxis: axis, logAxis: axis,
  });
}

/** ECharts wrapper. The container is width:100% + min-width:0 so it always takes its size from the card,
 *  and a ResizeObserver keeps the canvas in sync after navigation, filtering and viewport changes.
 *  Switching day/night re-creates the instance with the matching registered theme. */
export function Chart({ option, height = 260, onClick, ariaLabel }: { option: echarts.EChartsCoreOption; height?: number;
  onClick?: (p: any) => void; ariaLabel?: string }) {
  const { theme } = useTheme();
  const ref = useRef<HTMLDivElement>(null);
  const inst = useRef<echarts.ECharts | null>(null);
  const clickRef = useRef(onClick);
  clickRef.current = onClick;
  const optRef = useRef(option);
  optRef.current = option;

  const applied = useRef<echarts.EChartsCoreOption | null>(null);
  const apply = (c: echarts.ECharts, opt: echarts.EChartsCoreOption) => (applied.current = opt, c.setOption({
    grid: { left: 8, right: 16, top: 32, bottom: 8, containLabel: true },
    tooltip: { trigger: "axis", confine: true },
    aria: { enabled: true },
    ...opt,
  }, true));

  useEffect(() => {
    if (!ref.current) return;
    const c = echarts.init(ref.current, `siem-${theme}`, { renderer: "canvas" });
    inst.current = c;
    c.on("click", (p) => clickRef.current?.(p));
    apply(c, optRef.current);
    let frame = 0;
    const ro = new ResizeObserver(() => { cancelAnimationFrame(frame); frame = requestAnimationFrame(() => c.resize()); });
    ro.observe(ref.current);
    return () => { cancelAnimationFrame(frame); ro.disconnect(); c.dispose(); inst.current = null; };
  }, [theme]);

  useEffect(() => {
    if (inst.current && applied.current !== option) apply(inst.current, option);  // init already drew this option
  }, [option]);

  return <div ref={ref} role="img" aria-label={ariaLabel} style={{ height, width: "100%", minWidth: 0, cursor: onClick ? "pointer" : "default" }} />;
}

// colours come from the registered theme; only behaviour is set here
export const axisStyle = { axisLabel: { hideOverlap: true } };
