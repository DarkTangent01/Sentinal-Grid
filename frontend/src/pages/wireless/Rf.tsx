import { Fragment, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { useTheme } from "../../lib/theme";
import { escHtml, fmtNum, getTimezone } from "../../lib/format";
import { CHART_THEME, Chart, PALETTES, axisStyle } from "../../components/Chart";
import { Card, Drawer, Empty, Kpi, Loading, Sev, TableWrap, Time, rowProps } from "../../components/ui";
import { KV, SeriesChart } from "../switches/common";
import { Band, WState, dash, dbm, pctv, useWlGo, useWlMeta } from "./common";

/** Frequency label: primary channel frequency, plus the bonded-block center when it differs. Unknown stays "—". */
export function freqLabel(r: { frequency_mhz?: number | null; center_frequency_mhz?: number | null }): string {
  if (r.frequency_mhz == null) return "—";
  return r.center_frequency_mhz != null && r.center_frequency_mhz !== r.frequency_mhz ? `${r.frequency_mhz} MHz (center ${r.center_frequency_mhz})` : `${r.frequency_mhz} MHz`;
}

/** Severity bucket for channel utilisation against the radio's band threshold; null (not measured) is its own state. */
export function utilLevel(v: number | null | undefined, threshold = 80): "none" | "ok" | "elevated" | "high" {
  if (v == null) return "none";
  if (v >= threshold) return "high";
  if (v >= threshold - 20) return "elevated";
  return "ok";
}
const LEVEL_TXT = { none: "text-muted", ok: "text-emerald-300", elevated: "text-amber-300", high: "text-red-300" };
const RULE_LABEL: Record<string, string> = {
  high_channel_utilization: "High channel utilisation", channel_contention: "Channel contention", cochannel_interference: "Co-channel interference",
  adjacent_channel_interference: "Adjacent-channel interference", high_noise: "High noise floor", poor_client_snr: "Poor client SNR",
  excessive_retries: "Excessive retries", uneven_client_distribution: "Uneven client distribution", repeated_channel_changes: "Repeated channel changes",
  radio_failure: "Radio failure",
};
const EVENT_LABEL: Record<string, string> = {
  channel_change: "Channel change", dfs_radar: "DFS radar", radio_up: "Radio up", radio_down: "Radio down", radio_disabled: "Radio disabled",
  tx_power_change: "Tx power change", radio_link_change: "Radio link change", wireless_channel_utilization: "High utilisation alert",
  wireless_interference: "Interference alert", wireless_noise_high: "Noise alert", wireless_retry_high: "Retry alert", wireless_low_snr: "Low SNR alert",
  wireless_radio_down: "Radio down alert", wireless_channel_changes: "Channel changes alert",
};

function useFilters() {
  const [sp, setSp] = useSearchParams();
  const get = (k: string) => sp.get(k) || "";
  const set = (k: string, v: string) => setSp((p) => { if (v) p.set(k, v); else p.delete(k); return p; });
  return { site: get("site"), wlc: get("wlc"), band: get("band"), range: get("range") || "24h", ap: get("ap"), set };
}

function Filters({ f, band = true, range = false }: { f: ReturnType<typeof useFilters>; band?: boolean; range?: boolean }) {
  const meta = useWlMeta();
  return <div className="flex flex-wrap gap-2 items-center text-sm">
    <select aria-label="Site" className="input py-1" value={f.site} onChange={(e) => f.set("site", e.target.value)}><option value="">All sites</option>
      {(meta.data?.sites || []).map((x: string) => <option key={x}>{x}</option>)}</select>
    <select aria-label="Controller" className="input py-1" value={f.wlc} onChange={(e) => f.set("wlc", e.target.value)}><option value="">All controllers</option>
      {(meta.data?.controllers || []).map((c: any) => <option key={c.id} value={c.id}>{c.name}</option>)}</select>
    {band && <select aria-label="Band" className="input py-1" value={f.band} onChange={(e) => f.set("band", e.target.value)}><option value="">All bands</option>
      {["2.4", "5", "6"].map((b) => <option key={b} value={b}>{b} GHz</option>)}</select>}
    {range && <select aria-label="Time range" className="input py-1" value={f.range} onChange={(e) => f.set("range", e.target.value)}>
      {[["1h", "1 hour"], ["6h", "6 hours"], ["24h", "24 hours"], ["7d", "7 days"], ["30d", "30 days"]].map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>}
  </div>;
}

const params = (f: ReturnType<typeof useFilters>, extra: Record<string, any> = {}) =>
  ({ site: f.site || undefined, wlc_id: f.wlc ? [f.wlc] : undefined, band: f.band || undefined, ...extra });

// ------------------------------------------------------------------ A. RF overview
export function RfOverview() {
  const f = useFilters();
  const go = useWlGo();
  const q = useQuery({ queryKey: ["wlrf", "overview", f.site, f.wlc, f.band], queryFn: () => api<any>("/wireless/rf/overview", { params: params(f) }), refetchInterval: 60_000 });
  const d = q.data;
  return <div className="space-y-4 min-w-0">
    <div className="flex flex-wrap gap-2 items-center"><p className="text-xs text-muted flex-1 min-w-[16rem]">RF measurements exactly as the controller reports them over SNMP.
      Values a controller release does not expose show “—”, never zero. Monitoring is read-only: no channel, power or RF-profile change is ever made.</p><Filters f={f} /></div>
    {!d ? <Loading q={q} /> : <>
      <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-7 gap-3">
        <Kpi label="Monitored APs" value={fmtNum(d.cards.monitored_aps)} sub={`${d.cards.radios} radios`} />
        <Kpi label="Operational radios" value={fmtNum(d.cards.operational_radios)} tone="ok" onClick={() => go("rf-radios")} />
        <Kpi label="Offline radios" value={fmtNum(d.cards.offline_radios)} tone={d.cards.offline_radios ? "bad" : "ok"}
          sub={d.cards.disabled_radios || d.cards.unknown_radios ? `${d.cards.disabled_radios} disabled · ${d.cards.unknown_radios} unknown` : undefined} />
        <Kpi label="Avg channel utilisation" value={pctv(d.cards.avg_channel_util_pct)} sub={`${d.cards.util_measured_radios} radios measured`} />
        <Kpi label="High-utilisation radios" value={fmtNum(d.cards.high_util_radios)} tone={d.cards.high_util_radios ? "warn" : "ok"}
          onClick={() => go("rf-findings", { rule: "high_channel_utilization" })} />
        <Kpi label="Radios with poor RF" value={fmtNum(d.cards.poor_rf_radios)} tone={d.cards.poor_rf_radios ? "warn" : "ok"} onClick={() => go("rf-findings")} />
        <Kpi label="Radios on DFS channels" value={fmtNum(d.cards.dfs_radios)} />
      </div>
      <div className="grid xl:grid-cols-2 gap-4">
        <Card title="By band" bodyClass="p-0"><TableWrap><table className="tbl"><thead><tr><th>Band</th><th className="num">Radios</th><th className="num">Up</th><th className="num">Avg util</th></tr></thead>
          <tbody>{d.by_band.map((b: any) => <tr key={b.band} {...rowProps(() => go("rf-frequency", { band: b.band }))}><td><Band b={b.band} /></td><td className="num">{b.radios}</td>
            <td className="num">{b.up}</td><td className="num">{pctv(b.avg_util)}</td></tr>)}</tbody></table></TableWrap></Card>
        <Card title="RF findings" bodyClass="p-0"><TableWrap><table className="tbl"><thead><tr><th>Finding</th><th className="num">Radios</th></tr></thead>
          <tbody>{Object.entries(d.findings).map(([k, v]: any) => <tr key={k} {...rowProps(() => go("rf-findings", { rule: k }))}><td>{RULE_LABEL[k] || k}</td>
            <td className={`num ${v ? "text-amber-300" : ""}`}>{v}</td></tr>)}</tbody></table></TableWrap></Card>
      </div>
      <Card title="Telemetry coverage"><p className="text-xs text-muted mb-2">Radios for which the controller returned each measurement. Analytics that need a missing input produce no finding for that radio.</p>
        <KV rows={[["Channel utilisation", `${d.collection.util} of ${d.cards.radios}`], ["Noise floor", `${d.collection.noise} of ${d.cards.radios}`],
          ["RRM neighbour list (RF proximity)", `${d.collection.neighbors} of ${d.cards.radios}`], ["Transmit power in dBm", `${d.collection.tx_power_dbm} of ${d.cards.radios}`],
          ["Country / regulatory", `${d.collection.country} of ${d.cards.radios}`],
          ["Radios without history yet", String(d.coverage.radios_without_history)]]} /></Card>
    </>}
  </div>;
}

// ------------------------------------------------------------------ B. frequency distribution
export function RfFrequency() {
  const f = useFilters();
  const { theme } = useTheme();
  const q = useQuery({ queryKey: ["wlrf", "dist", f.site, f.wlc], queryFn: () => api<any>("/wireless/rf/distribution", { params: params(f, { band: undefined }) }) });
  const d = q.data;
  const bands: string[] = (d?.bands || []).filter((b: string) => !f.band || b === f.band);
  return <div className="space-y-4 min-w-0">
    <Filters f={f} />
    {!d ? <Loading q={q} /> : !bands.length ? <Empty text="No radios with a known channel in scope." /> : <>
      {bands.map((b) => {
        const rows = d.channels.filter((c: any) => c.band === b);
        const ct = CHART_THEME[theme];
        const option = { grid: { left: 8, right: 16, top: 24, bottom: 8, containLabel: true }, tooltip: { trigger: "axis", confine: true,
          formatter: (ps: any[]) => { const c = rows[ps[0].dataIndex]; return `<b>Channel ${c.channel}</b> · ${c.frequency_mhz ?? "?"} MHz${c.dfs ? " · DFS" : ""}<br/>${c.radios} radio(s), ${c.clients} client(s)<br/>avg util ${c.avg_util ?? "—"}%`; } },
          xAxis: { type: "category", data: rows.map((c: any) => `${c.channel}${c.dfs ? "*" : ""}`), ...axisStyle, axisLabel: { color: ct.text } },
          yAxis: { type: "value", minInterval: 1, ...axisStyle }, series: [{ type: "bar", data: rows.map((c: any) => c.radios), itemStyle: { color: PALETTES[theme][b === "2.4" ? 1 : b === "5" ? 0 : 2] }, barMaxWidth: 28 }] };
        return <Card key={b} title={<span>{b} GHz channels <span className="text-xs text-muted">(* DFS channel)</span></span>}><Chart option={option} height={220} ariaLabel={`${b} GHz channel distribution`} />
          <TableWrap><table className="tbl"><thead><tr><th className="num">Channel</th><th className="num">Frequency</th><th>DFS</th><th className="num">AP radios</th><th className="num">Clients</th><th className="num">Avg util</th></tr></thead>
            <tbody>{rows.map((c: any) => <tr key={c.channel}><td className="num">{c.channel}</td><td className="num">{c.frequency_mhz ?? "—"} MHz</td><td>{c.dfs ? "yes" : ""}</td>
              <td className="num">{c.radios}</td><td className="num">{c.clients}</td><td className="num">{pctv(c.avg_util)}</td></tr>)}</tbody></table></TableWrap></Card>;
      })}
      <div className="grid xl:grid-cols-2 gap-4">
        <Card title="Channel width" bodyClass="p-0"><TableWrap><table className="tbl"><thead><tr><th>Band</th><th className="num">Width</th><th className="num">Radios</th></tr></thead>
          <tbody>{d.widths.filter((w: any) => bands.includes(w.band)).map((w: any) => <tr key={`${w.band}-${w.width_mhz}`}><td><Band b={w.band} /></td>
            <td className="num">{w.width_mhz ? `${w.width_mhz} MHz` : "not reported"}</td><td className="num">{w.radios}</td></tr>)}</tbody></table></TableWrap></Card>
        <Card title="Frequency use by site" bodyClass="p-0"><TableWrap maxH="max-h-[22rem]"><table className="tbl"><thead><tr><th>Site</th><th>Band</th><th className="num">Channel</th><th className="num">Frequency</th><th className="num">Radios</th></tr></thead>
          <tbody>{d.by_site.filter((x: any) => bands.includes(x.band)).map((x: any) => <tr key={`${x.site}-${x.band}-${x.channel}`}><td>{x.site}</td><td><Band b={x.band} /></td>
            <td className="num">{x.channel}</td><td className="num">{x.frequency_mhz ?? "—"} MHz</td><td className="num">{x.radios}</td></tr>)}</tbody></table></TableWrap></Card>
      </div>
      {d.radios_without_channel > 0 && <p className="text-xs text-muted">{d.radios_without_channel} radio(s) without a reported channel or with an ambiguous 5/6 GHz band are not counted.</p>}
    </>}
  </div>;
}

// ------------------------------------------------------------------ C. utilisation heatmap
export function RfHeatmap() {
  const f = useFilters();
  const { theme } = useTheme();
  const [metric, setMetric] = useState("channel_util_pct");
  const [apq, setApq] = useState("");
  const q = useQuery({ queryKey: ["wlrf", "heat", f.site, f.wlc, f.band, f.range, metric], placeholderData: (p) => p,
    queryFn: () => api<any>("/wireless/rf/heatmap", { params: params(f, { range: f.range, metric }) }) });
  const d = q.data;
  const option = useMemo(() => {
    if (!d) return null;
    const rows = d.rows.filter((r: any) => !apq || r.ap.toLowerCase().includes(apq.toLowerCase()));
    const times = [...new Set<string>(d.cells.map((c: any) => c.t))].sort();
    const ri = new Map(rows.map((r: any, i: number) => [r.radio_id, i]));
    const ti = new Map(times.map((t, i) => [t, i]));
    const data = d.cells.filter((c: any) => ri.has(c.radio_id)).map((c: any) => [ti.get(c.t), ri.get(c.radio_id), c.value ?? "-"]);
    const ct = CHART_THEME[theme];
    const util = metric === "channel_util_pct";
    const pieces = util ? [{ lt: 50, color: "#1baf7a", label: "< 50%" }, { gte: 50, lt: 70, color: "#c9b400", label: "50-70%" }, { gte: 70, lt: 80, color: "#eb6834", label: "70-80%" },
      { gte: 80, color: "#e23744", label: "≥ 80%" }] : undefined;
    return { tooltip: { confine: true, formatter: (p: any) => { const r = rows[p.value[1]]; return `<b>${escHtml(r.ap)}</b> radio ${r.slot} (${r.band} GHz, ch ${r.channel ?? "?"})<br/>${escHtml(times[p.value[0]])}<br/>${p.value[2] === "-" ? "no data" : p.value[2]}`; } },
      grid: { left: 8, right: 16, top: 8, bottom: 56, containLabel: true },
      xAxis: { type: "category", data: times.map((t) => new Date(t).toLocaleString(undefined, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false })), axisLabel: { color: ct.text } },
      yAxis: { type: "category", data: rows.map((r: any) => `${r.ap} / ${r.slot} (${r.band})`), axisLabel: { color: ct.text, fontSize: 10 } },
      visualMap: util ? { type: "piecewise", pieces, orient: "horizontal", left: "center", bottom: 0, textStyle: { color: ct.text } }
        : { type: "continuous", min: metric === "noise_dbm" ? -100 : 0, max: metric === "noise_dbm" ? -60 : metric === "clients" ? 50 : 100, orient: "horizontal", left: "center", bottom: 0, calculable: true, textStyle: { color: ct.text } },
      series: [{ type: "heatmap", data, emphasis: { itemStyle: { borderColor: "#fff", borderWidth: 1 } } }] };
  }, [d, theme, metric, apq]);
  const nrows = d ? d.rows.filter((r: any) => !apq || r.ap.toLowerCase().includes(apq.toLowerCase())).length : 0;
  return <div className="space-y-3 min-w-0">
    <div className="flex flex-wrap gap-2 items-center"><Filters f={f} range />
      <select aria-label="Metric" className="input py-1 text-sm" value={metric} onChange={(e) => setMetric(e.target.value)}>
        {[["channel_util_pct", "Channel utilisation"], ["noise_dbm", "Noise floor (dBm)"], ["interference_pct", "802.11 interference"], ["retry_pct", "Retry %"], ["clients", "Clients"]].map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
      <input aria-label="Filter AP" className="input py-1 text-sm w-44" placeholder="AP name…" value={apq} onChange={(e) => setApq(e.target.value)} /></div>
    <Card bodyClass="p-0">{!d ? <Loading q={q} /> : !d.cells.length ? <Empty text="No RF samples in this range yet (history starts with the first poll after this feature was deployed)." />
      : <Chart option={option!} height={Math.max(260, 60 + nrows * 18)} ariaLabel="RF heatmap" />}</Card>
    <p className="text-xs text-muted">Grey cells mean no valid sample in that interval (not collected, unsupported or invalid), never zero. Utilisation colours use 80 % as the high level; each radio's own band threshold applies to findings and alerts.</p>
  </div>;
}

// ------------------------------------------------------------------ D. AP radio details
export function RfRadios() {
  const f = useFilters();
  const [sel, setSel] = useState<number | null>(null);
  const [qq, setQq] = useState("");
  const q = useQuery({ queryKey: ["wlrf", "radios", f.site, f.wlc, f.band], queryFn: () => api<any>("/wireless/rf/radios", { params: params(f) }), refetchInterval: 60_000 });
  const items = (q.data?.items || []).filter((r: any) => !qq || (r.ap || "").toLowerCase().includes(qq.toLowerCase()) || String(r.channel) === qq);
  return <div className="space-y-3 min-w-0">
    <div className="flex flex-wrap gap-2 items-center"><Filters f={f} /><input aria-label="Search" className="input py-1 text-sm w-48" placeholder="AP name or channel…" value={qq} onChange={(e) => setQq(e.target.value)} /></div>
    <Card bodyClass="p-0">{!q.data ? <Loading q={q} /> : !items.length ? <Empty text="No radios in scope." /> : <TableWrap maxH="max-h-[40rem]"><table className="tbl">
      <thead><tr><th>AP</th><th>Site</th><th className="num">Slot</th><th>Band</th><th>State</th><th className="num">Channel</th><th>Frequency</th><th className="num">Width</th><th className="num">Tx power</th>
        <th className="num">Util</th><th className="num">Noise</th><th className="num">Interf.</th><th className="num">Clients</th><th className="num">Retry</th></tr></thead>
      <tbody>{items.map((r: any) => <tr key={r.id} {...rowProps(() => setSel(r.id))}><td>{r.ap}</td><td>{r.site}</td><td className="num">{r.slot}</td><td><Band b={r.band} /></td>
        <td><WState s={r.state} /></td><td className="num">{dash(r.channel)}{r.dfs ? " DFS" : ""}</td><td className="text-xs">{freqLabel(r)}</td><td className="num">{dash(r.channel_width_mhz, " MHz")}</td>
        <td className="num">{r.tx_power_dbm != null ? `${r.tx_power_dbm} dBm` : r.tx_power_level != null ? `level ${r.tx_power_level}` : "—"}</td>
        <td className={`num ${LEVEL_TXT[utilLevel(r.channel_util_pct, r.util_threshold ?? 80)]}`}>{pctv(r.channel_util_pct)}</td><td className="num">{dbm(r.noise_dbm)}</td>
        <td className="num">{pctv(r.interference_pct)}</td><td className="num">{dash(r.clients)}</td><td className="num">{dash(r.retry_pct, "%", 1)}</td></tr>)}</tbody></table></TableWrap>}</Card>
    {sel != null && <Drawer title="AP radio details" onClose={() => setSel(null)}><RadioDetail id={sel} onRadio={setSel} /></Drawer>}
  </div>;
}

export function RadioDetail({ id, onRadio }: { id: number; onRadio?: (id: number) => void }) {
  const [range, setRange] = useState("24h");
  const q = useQuery({ queryKey: ["wlrf", "radio", id], queryFn: () => api<any>(`/wireless/rf/radios/${id}`) });
  const d = q.data;
  if (!d) return <Loading q={q} />;
  const byBand = (b: string) => d.siblings.filter((x: any) => (b === "other" ? !["2.4", "5"].includes(x.band) : x.band === b));
  return <div className="space-y-4 text-sm">
    <div className="flex flex-wrap gap-3 items-center"><b>{d.ap?.name}</b><span className="text-muted">{d.ap?.model} · {d.ap?.ip} · site {d.ap?.site || "—"} · {d.controller?.name} ({d.controller?.firmware || "software ?"})</span>
      <span className="flex-1" /><select aria-label="Trend range" className="input py-1" value={range} onChange={(e) => setRange(e.target.value)}>
        {["1h", "6h", "24h", "7d", "30d"].map((r) => <option key={r}>{r}</option>)}</select></div>
    {(["2.4", "5", "other"] as const).map((b) => byBand(b).length > 0 && <div key={b} className="space-y-3">
      <h3 className="font-medium">{b === "other" ? "Other radios" : `${b} GHz radio`}</h3>
      {byBand(b).map((r: any) => <RadioSection key={r.id} r={r} current={r.id === id} range={range} onSelect={() => onRadio?.(r.id)} />)}
    </div>)}
    <Card title={`RRM neighbours heard by radio ${d.radio.slot} (${d.neighbors.length})`} bodyClass="p-0">{!d.neighbors.length
      ? <Empty text={d.radio.neighbors_collected_at ? "No neighbours reported." : "The controller has not returned the RRM neighbour table (bsnAPIfRxNeighborsTable) for this radio."} />
      : <TableWrap maxH="max-h-[18rem]"><table className="tbl"><thead><tr><th>Neighbour</th><th className="num">Slot</th><th className="num">Channel</th><th className="num">Width</th><th className="num">RSSI</th><th>Site</th></tr></thead>
        <tbody>{d.neighbors.map((n: any) => <tr key={`${n.mac}-${n.slot}`}><td>{n.ap_name || <span className="font-mono text-xs">{n.mac}</span>}{!n.ap_id && <span className="text-xs text-muted"> (not in inventory)</span>}</td>
          <td className="num">{dash(n.slot)}</td><td className="num">{dash(n.channel)}</td><td className="num">{dash(n.width_mhz, " MHz")}</td><td className="num">{dbm(n.rssi_dbm)}</td><td>{n.site}</td></tr>)}</tbody></table></TableWrap>}</Card>
    {d.radar.length > 0 && <Card title="DFS radar detections"><ul className="text-xs list-disc pl-5">{d.radar.map((x: any) => <li key={x.channel}>channel {x.channel}: heard {x.last_heard_s ?? "?"} s before <Time v={x.seen_at} /></li>)}</ul></Card>}
    <Card title={`Findings (${d.findings.length})`} bodyClass="p-0">{!d.findings.length ? <Empty text="No RF findings for this AP." /> : <FindingList items={d.findings} />}</Card>
    <Card title="Recent RF events" bodyClass="p-0">{!d.events.length ? <Empty text="No RF events for this radio." /> : <EventTable items={d.events} />}</Card>
  </div>;
}

function RadioSection({ r, current, range, onSelect }: { r: any; current: boolean; range: string; onSelect: () => void }) {
  const h = useQuery({ queryKey: ["wlrf", "hist", r.id, range], queryFn: () => api<any>(`/wireless/rf/radios/${r.id}/history`, { params: { range } }) });
  const s = h.data?.series || {};
  const merge = (keys: string[]) => {
    const m = new Map<string, any>();
    keys.forEach((k) => (s[k] || []).forEach((p: any) => m.set(p.t, { ...(m.get(p.t) || { t: p.t }), [k]: p.v })));
    return [...m.values()].sort((a, b) => a.t.localeCompare(b.t));
  };
  return <div className={`rounded-lg border p-3 space-y-3 ${current ? "border-sky-500/60" : "border-line"}`}>
    <div className="flex items-center gap-2"><b>Slot {r.slot}</b><Band b={r.band} /><WState s={r.state} />{!current && <button className="btn py-0.5 text-xs" onClick={onSelect}>Focus</button>}</div>
    <div className="grid md:grid-cols-2 gap-4">
      <KV rows={[["Frequency", freqLabel(r)], ["Channel", `${dash(r.channel)}${r.dfs ? " (DFS)" : ""}${r.channel_assignment ? ` · ${r.channel_assignment === "automatic" ? "RRM assigned" : "static"}` : ""}`],
        ["Channel width", dash(r.channel_width_mhz, " MHz")], ["Transmit power", r.tx_power_dbm != null ? `${r.tx_power_dbm} dBm (level ${r.tx_power_level})` : r.tx_power_level != null ? `level ${r.tx_power_level} of 8 (dBm not reported)` : "—"],
        ["Country / domain", r.country ? `${r.country}${r.environment && r.environment !== "all" ? ` (${r.environment})` : ""}` : "—"],
        ["RRM recommended channel", dash(r.recommended_channel)], ["Radio MAC", r.radio_mac || "—"], ["Link changes", dash(r.link_changes)],
        ["Last channel change", r.last_channel_change_at ? <Time v={r.last_channel_change_at} /> : "—"]]} />
      <KV rows={[["Channel utilisation", <span className={LEVEL_TXT[utilLevel(r.channel_util_pct, r.util_threshold ?? 80)]}>{pctv(r.channel_util_pct)} (threshold {dash(r.util_threshold, "%")})</span>],
        ["Tx / Rx utilisation", `${pctv(r.tx_util_pct)} / ${pctv(r.rx_util_pct)}`], ["Noise floor", dbm(r.noise_dbm)], ["802.11 interference", `${pctv(r.interference_pct)} · ${dbm(r.interference_dbm)}`],
        ["Connected clients", dash(r.clients)], ["Poor-SNR clients", dash(r.poor_snr_clients)], ["Retry percentage", dash(r.retry_pct, "%", 1)],
        ["RF data collected", r.rf_collected_at ? <Time v={r.rf_collected_at} /> : "not yet"]]} />
    </div>
    <div className="grid lg:grid-cols-2 gap-3">
      <SeriesChart points={merge(["channel_util_pct", "tx_util_pct", "rx_util_pct"])} series={[{ key: "channel_util_pct", name: "Channel util" }, { key: "tx_util_pct", name: "Tx", dashed: true },
        { key: "rx_util_pct", name: "Rx", dashed: true }]} unit="pct" yMax={100} bucket={h.data?.bucket_seconds} height={180} />
      <SeriesChart points={merge(["clients", "retry_pct"])} series={[{ key: "clients", name: "Clients" }, { key: "retry_pct", name: "Retry %" }]} unit="count" bucket={h.data?.bucket_seconds} height={180} />
      <DbmChart points={merge(["noise_dbm"])} />
      <SeriesChart points={merge(["interference_pct"])} series={[{ key: "interference_pct", name: "802.11 interference %" }]} unit="pct" yMax={100} bucket={h.data?.bucket_seconds} height={160} />
    </div>
  </div>;
}

/** Noise floor on a dBm axis (negative values; gaps stay gaps). */
function DbmChart({ points }: { points: any[] }) {
  const { theme } = useTheme();
  const option = useMemo(() => ({
    legend: { top: 0 }, grid: { left: 8, right: 16, top: 32, bottom: 8, containLabel: true },
    tooltip: { trigger: "axis", confine: true, valueFormatter: (v: any) => (v == null ? "no sample" : `${v} dBm`) },
    xAxis: { type: "time", ...axisStyle, axisLabel: { ...axisStyle.axisLabel, formatter: (v: number) => new Date(v).toLocaleString(undefined, {
      hour: "2-digit", minute: "2-digit", hour12: false, timeZone: getTimezone() }) } }, yAxis: { type: "value", min: -110, max: -40, ...axisStyle, axisLabel: { formatter: (v: number) => `${v} dBm` } },
    series: [{ name: "Noise floor", type: "line", connectNulls: false, showSymbol: points.length < 30, itemStyle: { color: PALETTES[theme][0] },
      data: points.map((p) => [Date.parse(p.t), p.noise_dbm ?? null]) }],
  }), [points, theme]);
  if (!points.length) return <div style={{ height: 160 }} className="flex items-center justify-center"><Empty text="No noise samples in this range." /></div>;
  return <Chart option={option} height={160} ariaLabel="Noise floor trend" />;
}

// ------------------------------------------------------------------ E. RF events
function EventTable({ items }: { items: any[] }) {
  return <TableWrap maxH="max-h-[34rem]"><table className="tbl"><thead><tr><th>Time</th><th>Event</th><th>AP</th><th className="w-full">Detail</th><th>Source</th></tr></thead>
    <tbody>{items.map((e: any) => <tr key={e.id}><td><Time v={e.at} /></td><td className="text-xs whitespace-nowrap"><Sev s={e.severity} /> {EVENT_LABEL[e.kind] || e.kind}</td><td>{e.ap || e.component}</td>
      <td className="text-xs">{e.detail}{e.data?.reason_confidence && <span className="text-muted"> · reason confidence {e.data.reason_confidence}</span>}</td>
      <td className="text-xs">{e.source === "alert" ? `alert (${e.status})` : "telemetry"}</td></tr>)}</tbody></table></TableWrap>;
}

export function RfEvents() {
  const f = useFilters();
  const [kind, setKind] = useState("");
  const [hours, setHours] = useState(24);
  const q = useQuery({ queryKey: ["wlrf", "events", f.site, f.wlc, kind, hours], refetchInterval: 60_000,
    queryFn: () => api<any>("/wireless/rf/events", { params: params(f, { band: undefined, kind: kind ? [kind] : undefined, hours }) }) });
  return <div className="space-y-3 min-w-0">
    <div className="flex flex-wrap gap-2 items-center"><Filters f={f} band={false} />
      <select aria-label="Event type" className="input py-1 text-sm" value={kind} onChange={(e) => setKind(e.target.value)}><option value="">All RF events</option>
        {["channel_change", "dfs_radar", "radio_down", "radio_up", "tx_power_change", "radio_link_change", "alert"].map((k) => <option key={k} value={k}>{k === "alert" ? "RF alerts" : EVENT_LABEL[k]}</option>)}</select>
      <select aria-label="Period" className="input py-1 text-sm" value={hours} onChange={(e) => setHours(Number(e.target.value))}>{[[24, "24 hours"], [168, "7 days"], [720, "30 days"]].map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></div>
    <Card bodyClass="p-0">{!q.data ? <Loading q={q} /> : !q.data.items.length ? <Empty text="No RF events in this period." /> : <EventTable items={q.data.items} />}</Card>
    <p className="text-xs text-muted">Channel-change reasons are inferred from what the controller reports (radar detections, RRM assignment mode); SNMP does not carry the DCA trigger, so each reason shows its confidence.</p>
  </div>;
}

// ------------------------------------------------------------------ findings and troubleshooting
function FindingList({ items }: { items: any[] }) {
  const [open, setOpen] = useState<string | null>(null);
  return <TableWrap maxH="max-h-[40rem]"><table className="tbl"><thead><tr><th>Severity</th><th>Finding</th><th>Site / AP / radio</th><th>Channel / frequency</th><th className="num">Observed</th>
    <th className="num">Threshold</th><th>Duration</th><th>Confidence</th></tr></thead>
    <tbody>{items.map((x: any) => <Fragment key={x.id}><tr {...rowProps(() => setOpen(open === x.id ? null : x.id))}><td><Sev s={x.severity} /></td><td>{RULE_LABEL[x.rule] || x.rule}<div className="text-xs text-muted">{x.title}</div></td>
      <td className="text-xs">{x.site || "—"} / {x.ap} / {x.slot} <Band b={x.band} /></td><td className="text-xs">ch {dash(x.channel)}{x.width_mhz ? ` · ${x.width_mhz} MHz` : ""} · {freqLabel(x)}</td>
      <td className="num">{dash(x.observed.value)}{x.observed.unit && x.observed.value !== "down" ? ` ${x.observed.unit}` : ""}</td><td className="num">{dash(x.threshold)}</td>
      <td className="text-xs">{x.duration_s != null ? `${Math.round(x.duration_s / 60)} min` : x.persistence ? "persistence not established" : "—"}</td>
      <td className={x.confidence === "high" ? "text-emerald-300" : x.confidence === "medium" ? "text-sky-300" : "text-muted"}>{x.confidence}</td></tr>
      {open === x.id && <tr><td colSpan={8} className="bg-white/5"><div className="grid md:grid-cols-2 gap-4 p-2 text-sm">
        <div><b>Evidence</b><ul className="list-disc pl-5 text-xs">{x.evidence.map((e: string, i: number) => <li key={i}>{e}</li>)}</ul>
          {x.history && <p className="text-xs mt-2">Historical comparison: 7-day average {dash(x.history.avg_7d)}{x.observed.unit ? ` ${x.observed.unit}` : ""} over {x.history.samples_7d} sample(s){x.history.avg_7d == null ? " (no earlier history)" : ""}.</p>}
          {x.since && <p className="text-xs">Condition held since <Time v={x.since} />.</p>}</div>
        <div><b>Possible root causes</b> <span className="text-xs text-muted">({x.engine} engine)</span><ul className="list-disc pl-5 text-xs">{x.possible_causes.map((c: string, i: number) => <li key={i}>{c}</li>)}</ul>
          <b className="block mt-2">Recommended troubleshooting steps</b><ol className="list-decimal pl-5 text-xs">{x.steps.map((c: string, i: number) => <li key={i}>{c}</li>)}</ol></div>
      </div></td></tr>}</Fragment>)}</tbody></table></TableWrap>;
}

export function RfFindings() {
  const f = useFilters();
  const [sp, setSp] = useSearchParams();
  const rule = sp.get("rule") || "";
  const q = useQuery({ queryKey: ["wlrf", "findings", f.site, f.wlc, f.band, rule], refetchInterval: 60_000,
    queryFn: () => api<any>("/wireless/rf/findings", { params: params(f, { rule: rule ? [rule] : undefined }) }) });
  const d = q.data;
  return <div className="space-y-3 min-w-0">
    <div className="flex flex-wrap gap-2 items-center"><Filters f={f} />
      <select aria-label="Finding" className="input py-1 text-sm" value={rule} onChange={(e) => setSp((p) => { if (e.target.value) p.set("rule", e.target.value); else p.delete("rule"); return p; })}>
        <option value="">All findings</option>{Object.keys(RULE_LABEL).map((k) => <option key={k} value={k}>{RULE_LABEL[k]}</option>)}</select></div>
    <p className="text-xs text-muted">Explainable rule-based analysis of collected telemetry. Interference findings need an RRM neighbour heard above the RSSI threshold, real spectral overlap and a measured
      utilisation or interference impact; a shared channel number alone is never reported. Click a row for evidence, history, possible causes and next steps.</p>
    <Card bodyClass="p-0">{!d ? <Loading q={q} /> : !d.findings.length ? <Empty text="No RF findings for the current telemetry." /> : <FindingList items={d.findings} />}</Card>
    {d && <p className="text-xs text-muted">Inputs unavailable: {d.coverage.radios_without_history} radio(s) without history, {d.coverage.radios_without_neighbor_data} without RRM neighbour data,
      {" "}{d.coverage.radios_without_noise} without noise, {d.coverage.radios_without_retry_rate} without a retry rate. No finding is produced from missing data.</p>}
  </div>;
}
