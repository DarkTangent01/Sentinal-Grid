import { useEffect, useRef } from "react";
import * as echarts from "echarts";
import { Theme, useTheme } from "../lib/theme";

/** Categorical slots, assigned in this fixed order (never cycled past 8: fold the rest into "Other").
 *  Validated per theme surface (lightness band, chroma, adjacent-pair CVD and normal-vision separation, contrast).
 *  Zomato red is deliberately not a categorical slot: in a SIEM red means "denied / threat" (see SERIES_ROLE). */
export const PALETTES: Record<Theme, string[]> = {
  light: ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"],
  dark: ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#008300", "#9085e9", "#e66767"],
};
export const SEV_HEX: Record<string, string> = { critical: "#d03b3b", high: "#ec835a", medium: "#eda100", low: "#2a78d6", informational: "#8f8f8f" };

/** Semantic series colours. primary = neutral traffic/volume, alert = denied/blocked/threat (Zomato red),
 *  warn = degraded (draw it dashed when shown beside alert: the amber/red pair needs a second cue for CVD),
 *  muted = secondary context. */
export type SeriesRole = "primary" | "alert" | "warn" | "muted";
export const SERIES_ROLE: Record<Theme, Record<SeriesRole, string>> = {
  light: { primary: "#2a78d6", alert: "#e23744", warn: "#c98500", muted: "#9c9c9c" },
  dark: { primary: "#3987e5", alert: "#ef4f5f", warn: "#c98500", muted: "#737373" },
};
export const seriesColor = (theme: Theme, color: string | undefined, i: number) =>
  (color && color in SERIES_ROLE[theme] ? SERIES_ROLE[theme][color as SeriesRole] : color) ?? PALETTES[theme][i % 8];
/** Sequential (magnitude) ramp, one hue, low → high. */
export const SEQUENTIAL: Record<Theme, string[]> = { light: ["#cde2fb", "#5598e7", "#104281"], dark: ["#184f95", "#3987e5", "#b7d3f6"] };

/** Neutral chart chrome per theme. Mirrors --chart-* tokens in index.css. */
export const CHART_THEME: Record<Theme, { text: string; strong: string; axis: string; split: string; tooltip: string; tooltipBorder: string; surface: string }> = {
  dark: { text: "#a3a3a3", strong: "#f0f0f0", axis: "#404040", split: "#262626", tooltip: "#1c1c1c", tooltipBorder: "#2e2e2e", surface: "#1c1c1c" },
  light: { text: "#696969", strong: "#1c1c1c", axis: "#d6d6d6", split: "#f0f0f0", tooltip: "#ffffff", tooltipBorder: "#e8e8e8", surface: "#ffffff" },
};

for (const [name, c] of Object.entries(CHART_THEME) as [Theme, (typeof CHART_THEME)[Theme]][]) {
  const axis = { axisLine: { lineStyle: { color: c.axis } }, axisTick: { lineStyle: { color: c.axis } },
    splitLine: { lineStyle: { color: c.split } }, axisLabel: { color: c.text } };
  echarts.registerTheme(`siem-${name}`, {
    color: PALETTES[name], backgroundColor: "transparent", textStyle: { color: c.text },
    legend: { textStyle: { color: c.text }, pageTextStyle: { color: c.text } },
    tooltip: { backgroundColor: c.tooltip, borderColor: c.tooltipBorder, textStyle: { color: c.strong },
      extraCssText: "border-radius:10px;box-shadow:0 6px 20px -8px rgba(28,28,28,.25);" },
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

  const apply = (c: echarts.ECharts, opt: echarts.EChartsCoreOption) => c.setOption({
    grid: { left: 8, right: 16, top: 32, bottom: 8, containLabel: true },
    tooltip: { trigger: "axis", confine: true },
    aria: { enabled: true },
    ...opt,
  }, true);

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
    if (inst.current) apply(inst.current, option);
  }, [option]);

  return <div ref={ref} role="img" aria-label={ariaLabel} style={{ height, width: "100%", minWidth: 0, cursor: onClick ? "pointer" : "default" }} />;
}

// colours come from the registered theme; only behaviour is set here
export const axisStyle = { axisLabel: { hideOverlap: true } };
