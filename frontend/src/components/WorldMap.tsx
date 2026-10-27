import { useMemo } from "react";
import * as echarts from "echarts";
import { feature } from "topojson-client";
import world from "world-atlas/countries-110m.json";
import { Chart, CHART_THEME, SEQUENTIAL } from "./Chart";
import { useTheme } from "../lib/theme";
import { escHtml, fmtNum } from "../lib/format";

// FortiGate / MaxMind country names → Natural Earth (world-atlas) names
const ALIAS: Record<string, string> = {
  "United States": "United States of America", "Russian Federation": "Russia", "Korea, Republic of": "South Korea",
  "Korea, Democratic People's Republic of": "North Korea", "Viet Nam": "Vietnam", "Iran, Islamic Republic of": "Iran",
  "Czech Republic": "Czechia", "Syrian Arab Republic": "Syria", "Lao People's Democratic Republic": "Laos",
  "Moldova, Republic of": "Moldova", "Tanzania, United Republic of": "Tanzania", "Bolivia, Plurinational State of": "Bolivia",
  "Venezuela, Bolivarian Republic of": "Venezuela", "Congo, The Democratic Republic of the": "Dem. Rep. Congo",
  "Democratic Republic of the Congo": "Dem. Rep. Congo", "Republic of the Congo": "Congo", "Bosnia and Herzegovina": "Bosnia and Herz.",
  "Dominican Republic": "Dominican Rep.", "Central African Republic": "Central African Rep.", "South Sudan": "S. Sudan",
  "Macedonia, The Former Yugoslav Republic of": "Macedonia", "North Macedonia": "Macedonia", "Taiwan, Province of China": "Taiwan",
  "Côte d'Ivoire": "Côte d'Ivoire", "Cote D'Ivoire": "Côte d'Ivoire", "Equatorial Guinea": "Eq. Guinea", "Eswatini": "eSwatini",
  "Falkland Islands (Malvinas)": "Falkland Is.", "Solomon Islands": "Solomon Is.", "Western Sahara": "W. Sahara",
};
let registered = false;
function ensureMap() {
  if (registered) return;
  const geo = feature(world as any, (world as any).objects.countries) as any;
  echarts.registerMap("world", geo);
  registered = true;
}

export const mapName = (country: string) => ALIAS[country] || country;

export function WorldMap({ rows, metric = "events", height = 360, onClick, label = "Events" }: {
  rows: { country: string; [k: string]: any }[]; metric?: string; height?: number; onClick?: (country: string) => void; label?: string;
}) {
  ensureMap();
  const { theme } = useTheme();
  const c = CHART_THEME[theme];
  const option = useMemo(() => {
    const data = rows.map((r) => ({ name: mapName(r.country), value: Number(r[metric] || 0), orig: r.country }));
    const max = Math.max(1, ...data.map((d) => d.value));
    return {
      tooltip: { trigger: "item", confine: true, formatter: (p: any) => p.data ? `${escHtml(p.data.orig)}<br/>${escHtml(label)}: <b>${fmtNum(p.data.value)}</b>` : `${escHtml(p.name)}<br/>no traffic` },
      visualMap: { min: 0, max, left: 8, bottom: 8, calculable: true, text: ["high", "low"], textStyle: { color: c.text },
        inRange: { color: SEQUENTIAL[theme] } },
      series: [{ type: "map", map: "world", roam: true, scaleLimit: { min: 1, max: 8 }, data, emphasis: { label: { show: false } },
        itemStyle: { areaColor: theme === "light" ? "#f0f0f0" : "#2a2a2a", borderColor: c.surface, borderWidth: 0.5 },
        nameProperty: "name" }],
    };
  }, [rows, metric, theme, label]);
  return <Chart height={height} option={option} ariaLabel="World map by country" onClick={onClick ? (p) => p.data?.orig && onClick(p.data.orig) : undefined} />;
}
