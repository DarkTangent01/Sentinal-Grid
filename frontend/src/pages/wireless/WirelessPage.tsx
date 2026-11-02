import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { useMe } from "../../lib/context";
import { fmtNum } from "../../lib/format";
import { Card, Empty, Kpi, Loading, Modal, TableWrap, Tabs, Time } from "../../components/ui";
import { MetricStatus } from "../switches/common";
import { SwitchForm } from "../switches/Admin";
import { Band, RfFlags, WState, dash, dbm, dur, pctv, useWlGo, useWlMeta } from "./common";
import { ApsTab } from "./Aps";
import { RfEvents, RfFindings, RfFrequency, RfHeatmap, RfOverview, RfRadios } from "./Rf";
import { ClientsTab, EventsTab, RoamingTab, TroubleshootTab, WlansTab } from "./Clients";

export const RF_TABS: [string, string][] = [["rf-overview", "RF Overview"], ["rf-frequency", "Frequency Distribution"], ["rf-heatmap", "Utilisation Heatmap"],
  ["rf-radios", "AP Radio Details"], ["rf-events", "RF Events"], ["rf-findings", "RF Findings"]];
export const WL_TABS: [string, string][] = [["overview", "Wireless Overview"], ["controllers", "WLC Inventory"], ["aps", "Access Points"], ...RF_TABS,
  ["clients", "Clients"], ["wlans", "WLAN / SSID"], ["roaming", "Roaming"], ["events", "Events"], ["troubleshoot", "Troubleshooting"], ["health", "Monitoring Health"]];

export function Wireless() {
  const [sp, setSp] = useSearchParams();
  const req = sp.get("tab") === "rf" ? "rf-overview" : sp.get("tab");   // "Radio & RF" moved into RF & Frequency Monitoring
  const tab = WL_TABS.some(([k]) => k === req) ? req! : "overview";
  return <div className="min-w-0">
    <Tabs value={tab} onChange={(t) => setSp({ tab: t })} tabs={WL_TABS.map(([key, label]) => ({ key, label }))} />
    <div key={sp.toString()}>
      {tab === "overview" && <Overview />}
      {tab === "controllers" && <Controllers />}
      {tab === "aps" && <ApsTab />}
      {tab === "rf-overview" && <RfOverview />}
      {tab === "rf-frequency" && <RfFrequency />}
      {tab === "rf-heatmap" && <RfHeatmap />}
      {tab === "rf-radios" && <RfRadios />}
      {tab === "rf-events" && <RfEvents />}
      {tab === "rf-findings" && <RfFindings />}
      {tab === "clients" && <ClientsTab />}
      {tab === "wlans" && <WlansTab />}
      {tab === "roaming" && <RoamingTab />}
      {tab === "events" && <EventsTab />}
      {tab === "troubleshoot" && <TroubleshootTab />}
      {tab === "health" && <Health />}
    </div>
  </div>;
}

function Filters({ wlc, setWlc, site, setSite }: { wlc: string; setWlc: (v: string) => void; site: string; setSite: (v: string) => void }) {
  const meta = useWlMeta();
  return <>
    <select aria-label="Controller" className="input py-1" value={wlc} onChange={(e) => setWlc(e.target.value)}><option value="">All controllers</option>
      {(meta.data?.controllers || []).map((c: any) => <option key={c.id} value={c.id}>{c.name}</option>)}</select>
    <select aria-label="Site" className="input py-1" value={site} onChange={(e) => setSite(e.target.value)}><option value="">All sites</option>
      {(meta.data?.sites || []).map((x: string) => <option key={x}>{x}</option>)}</select>
  </>;
}

function Overview() {
  const go = useWlGo();
  const [wlc, setWlc] = useState("");
  const [site, setSite] = useState("");
  const params = { wlc_id: wlc ? [wlc] : undefined, site: site || undefined };
  const q = useQuery({ queryKey: ["wl", "overview", params], queryFn: () => api<any>("/wireless/overview", { params }), refetchInterval: 60_000, placeholderData: (p) => p });
  const d = q.data;
  const c = d?.cards || {};
  return <div className="space-y-4 min-w-0">
    <div className="flex flex-wrap items-center gap-2">
      <p className="text-xs text-muted flex-1 min-w-[16rem]">Read-only monitoring of Cisco wireless controllers over SNMP: APs, radios, WLANs and clients exactly as the controller reports them.
        A metric this controller release does not expose shows “—”, never zero (see Monitoring Health).</p>
      <Filters wlc={wlc} setWlc={setWlc} site={site} setSite={setSite} />
    </div>
    <Loading q={q} />
    {d && (!d.controllers.length ? <Card><Empty text={<>No wireless controller yet. Add your Catalyst 9800 under <b>WLC Inventory</b> (an SNMPv3 read-only user is recommended).</>} /></Card> : <>
      <div className="kpi-grid">
        <Kpi label="Controllers" value={`${fmtNum(c.wlcs_online)} / ${fmtNum(c.wlcs)}`} sub="online / total" tone={c.wlcs_online < c.wlcs ? "bad" : "ok"} onClick={() => go("controllers")} />
        <Kpi label="Managed APs" value={fmtNum(c.aps)} sub={`${fmtNum(c.aps_online)} online`} onClick={() => go("aps")} />
        <Kpi label="APs offline" value={fmtNum(c.aps_offline)} tone={c.aps_offline ? "bad" : "ok"} onClick={() => go("aps", { state: "down" })} />
        <Kpi label="APs degraded" value={fmtNum(c.aps_degraded)} tone={c.aps_degraded ? "warn" : "ok"} onClick={() => go("aps", { state: "degraded" })} />
        <Kpi label="Wireless clients" value={fmtNum(c.clients)} onClick={() => go("clients")} />
        <Kpi label="Active SSIDs" value={fmtNum(c.ssids)} onClick={() => go("wlans")} />
        <Kpi label="Unhealthy radios" value={fmtNum(c.unhealthy_radios)} tone={c.unhealthy_radios ? "warn" : "ok"} onClick={() => go("rf-radios")} />
        <Kpi label="High-utilisation radios" value={fmtNum(c.high_util_radios)} tone={c.high_util_radios ? "warn" : "ok"} onClick={() => go("rf-findings", { rule: "high_channel_utilization" })} />
        <Kpi label="Clients with poor signal" value={fmtNum(c.poor_signal_clients)} tone={c.poor_signal_clients ? "warn" : "ok"} onClick={() => go("clients", { problem: "poor_rssi" })} />
        <Kpi label="Association failures" value={fmtNum(c.assoc_failures)} sub="since previous poll" tone={c.assoc_failures ? "warn" : "ok"} />
        <Kpi label="Roaming anomalies (24 h)" value={fmtNum(c.roaming_anomalies)} tone={c.roaming_anomalies ? "warn" : "ok"} onClick={() => go("roaming")} />
        <Kpi label="Wireless alerts" value={fmtNum(c.alerts)} tone={c.alerts ? "bad" : "ok"} />
        <Kpi label="Disconnects (24 h)" value={fmtNum(c.disconnects_24h)} onClick={() => go("events", { kind: "client_disconnected" })} />
        <Kpi label="AP down events (24 h)" value={fmtNum(c.ap_down_events_24h)} tone={c.ap_down_events_24h ? "warn" : "ok"} onClick={() => go("events", { kind: "ap_down" })} />
      </div>
      <Card title="Controller health" bodyClass="p-0"><ControllerTable rows={d.controllers} /></Card>
      <div className="grid gap-4 xl:grid-cols-3">
        <Card title="AP status by site" bodyClass="p-0">{!d.ap_status_by_site.length ? <Empty text="No APs." /> :
          <TableWrap><table className="tbl"><thead><tr><th>Site</th><th className="num">Up</th><th className="num">Degraded</th><th className="num">Down</th><th className="num">Other</th></tr></thead>
            <tbody>{d.ap_status_by_site.map((r: any) => <tr key={r.site} className="cursor-pointer hover:bg-white/5" onClick={() => go("aps", { site: r.site })}><td>{r.site}</td>
              <td className="num">{r.up || 0}</td><td className="num">{r.degraded || 0}</td><td className="num text-red-300">{r.down || 0}</td>
              <td className="num">{(r.unknown || 0) + (r.maintenance || 0)}</td></tr>)}</tbody></table></TableWrap>}</Card>
        <Card title="Clients by SSID" bodyClass="p-0"><Dist rows={d.clients_by_ssid} k="ssid" onPick={(v) => go("clients", { ssid: v })} /></Card>
        <Card title="Clients by band / site" bodyClass="p-0"><Dist rows={d.clients_by_band.map((x: any) => ({ ...x, band: `${x.band} GHz` }))} k="band"
          onPick={(v) => go("clients", { band: v.replace(" GHz", "") })} /><Dist rows={d.clients_by_site} k="site" onPick={(v) => go("clients", { site: v })} /></Card>
      </div>
      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="RF health by band" bodyClass="p-0">{!d.rf_by_band.length ? <Empty text="No radio data." /> :
          <TableWrap><table className="tbl"><thead><tr><th>Band</th><th className="num">Radios up</th><th className="num">High util.</th><th className="num">Avg util.</th>
            <th className="num">Avg noise</th><th className="num">Avg 802.11 interference</th></tr></thead>
            <tbody>{d.rf_by_band.map((r: any) => <tr key={r.band} className="cursor-pointer hover:bg-white/5" onClick={() => go("rf-frequency", { band: r.band })}><td><Band b={r.band} /></td>
              <td className="num">{r.up} / {r.radios}</td><td className="num">{r.high_util}</td><td className="num">{pctv(r.avg_util)}</td><td className="num">{dbm(r.avg_noise_dbm)}</td>
              <td className="num">{pctv(r.avg_interference_pct)}</td></tr>)}</tbody></table></TableWrap>}</Card>
        <Card title="Worst RF conditions" bodyClass="p-0">{!d.worst_radios.length ? <Empty text="No radio is past an RF threshold." /> :
          <TableWrap><table className="tbl"><thead><tr><th>AP / radio</th><th>Band</th><th className="num">Ch</th><th className="num">Util.</th><th className="num">Noise</th><th>Issues</th></tr></thead>
            <tbody>{d.worst_radios.map((r: any) => <tr key={r.id} className="cursor-pointer hover:bg-white/5" onClick={() => go("aps", { ap: r.ap_id })}>
              <td>{r.ap} <span className="text-muted text-2xs">slot {r.slot}</span></td><td><Band b={r.band} /></td><td className="num">{dash(r.channel)}</td>
              <td className="num">{pctv(r.channel_util_pct)}</td><td className="num">{dbm(r.noise_dbm)}</td><td><RfFlags f={r.flags} /></td></tr>)}</tbody></table></TableWrap>}</Card>
      </div>
      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="Client experience" bodyClass="p-0"><TableWrap><table className="tbl"><tbody>
          {([["Poor RSSI", "poor_rssi", d.client_experience.poor_rssi], ["Low SNR", "low_snr", d.client_experience.low_snr],
            ["On a radio with high retries", "", d.client_experience.high_retry_radio_clients], ["Repeated disconnects (≥ 3)", "disconnects", d.client_experience.repeat_disconnects],
            ["Frequent roaming (24 h)", "roaming", d.client_experience.frequent_roamers]] as [string, string, number][]).map(([l, p, v]) =>
            <tr key={l} className={p ? "cursor-pointer hover:bg-white/5" : ""} onClick={() => p && go(p === "roaming" ? "roaming" : "clients", p === "roaming" ? {} : { problem: p })}>
              <td>{l}</td><td className="num font-semibold">{fmtNum(v)}</td></tr>)}</tbody></table></TableWrap></Card>
        <Card title="Recent wireless events" bodyClass="p-0" right={<button className="link text-xs" onClick={() => go("events")}>All events →</button>}>
          {!d.recent_events.length ? <Empty text="No events yet." /> : <TableWrap maxH="max-h-72"><table className="tbl"><tbody>{d.recent_events.map((e: any) =>
            <tr key={e.id}><td className="text-xs whitespace-nowrap"><Time v={e.at} /></td><td className="text-xs">{e.kind.replace(/_/g, " ")}</td><td className="text-xs">{e.detail}</td></tr>)}</tbody></table></TableWrap>}
        </Card>
      </div>
    </>)}
  </div>;
}

function Dist({ rows, k, onPick }: { rows: any[]; k: string; onPick: (v: string) => void }) {
  if (!rows.length) return <Empty text="No clients." />;
  const max = Math.max(...rows.map((r) => r.clients));
  return <TableWrap maxH="max-h-60"><table className="tbl"><tbody>{rows.map((r) => <tr key={r[k]} className="cursor-pointer hover:bg-white/5" onClick={() => onPick(r[k])}>
    <td className="w-1/2 truncate">{r[k]}</td><td><div className="h-2 rounded bg-teal-500/60" style={{ width: `${Math.max(4, (100 * r.clients) / max)}%` }} /></td>
    <td className="num">{r.clients}</td></tr>)}</tbody></table></TableWrap>;
}

export function ControllerTable({ rows }: { rows: any[] }) {
  if (!rows.length) return <Empty text="No controllers." />;
  return <TableWrap><table className="tbl"><thead><tr><th>Controller</th><th>State</th><th>Model / release</th><th>Site</th><th className="num">CPU</th><th className="num">Memory</th>
    <th className="num">Uptime</th><th className="num">APs (up / down)</th><th className="num">Clients</th><th className="num">WLANs</th><th>Last poll</th><th>Collection</th></tr></thead>
    <tbody>{rows.map((w) => <tr key={w.id}>
      <td className="font-medium"><Link className="link" to={`/switches/${w.id}`}>{w.name}</Link><div className="text-2xs text-muted font-mono">{w.address}</div></td>
      <td><WState s={w.monitoring === "paused" ? "paused" : w.state} /></td><td className="text-xs">{w.model || "—"}<div className="text-muted">{w.firmware}</div></td>
      <td className="text-xs">{w.site || "—"}</td><td className="num">{pctv(w.cpu_pct)}</td><td className="num">{pctv(w.mem_pct)}</td><td className="num">{dur(w.uptime_s)}</td>
      <td className="num">{dash(w.aps)} <span className="text-muted text-xs">({dash(w.aps_up)} / <span className={w.aps_down ? "text-red-300" : ""}>{dash(w.aps_down)}</span>)</span></td>
      <td className="num">{dash(w.clients)}{w.clients_truncated && <span className="text-amber-300" title="client table larger than the per-poll limit">*</span>}</td>
      <td className="num">{dash(w.wlans)}</td><td className="text-xs"><Time v={w.last_success_at} /></td>
      <td className="text-xs">{w.stale_groups.length ? <span className="text-amber-300">stale: {w.stale_groups.map((g: string) => g.replace("wireless_", "")).join(", ")}</span> :
        w.failing_groups.length ? <span className="text-red-300">failing: {w.failing_groups.map((g: string) => g.replace("wireless_", "")).join(", ")}</span> :
        w.ap_table_ok === false ? <span className="text-amber-300">AP table empty</span> : <span className="text-emerald-300">OK</span>}</td></tr>)}</tbody></table></TableWrap>;
}

function Controllers() {
  const me = useMe();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["wl", "controllers"], queryFn: () => api<any>("/wireless/controllers"), refetchInterval: 60_000 });
  const [add, setAdd] = useState(false);
  const [th, setTh] = useState<any>(null);
  return <div className="space-y-4 min-w-0">
    <div className="flex flex-wrap items-center gap-2">
      <p className="text-xs text-muted flex-1 min-w-[16rem]">A wireless controller is a monitored network device with the role <b>wlc</b>: it uses the same SNMP credential profiles, authorised networks,
        polling and audit as switch monitoring. “Test” runs the wireless capability scan and shows which MIB objects this controller release actually returns.</p>
      {me.role === "admin" && <button className="btn btn-primary" onClick={() => setAdd(true)}>+ Add controller</button>}
    </div>
    <Loading q={q} />
    {q.data && <Card bodyClass="p-0"><ControllerTable rows={q.data.items} /></Card>}
    {q.data?.items?.length > 0 && me.role === "admin" && <Card title="Thresholds (per controller)">
      <div className="flex flex-wrap gap-2">{q.data.items.map((w: any) => <button key={w.id} className="btn" onClick={() => setTh(w)}>{w.name}</button>)}</div>
      <p className="text-2xs text-muted mt-2">Overrides apply to that controller's APs (one controller per site is the usual layout). Channel utilisation is set per band.</p></Card>}
    {add && <SwitchForm sw={null} initial={{ role: "wlc", poll_interval_seconds: 60, timeout_ms: 5000, retries: 1 }} onClose={() => { setAdd(false); qc.invalidateQueries({ queryKey: ["wl"] }); }} />}
    {th && <ThresholdForm w={th} onClose={() => setTh(null)} />}
  </div>;
}

function ThresholdForm({ w, onClose }: { w: any; onClose: () => void }) {
  const meta = useWlMeta();
  const d = meta.data?.thresholds || {};
  const [v, setV] = useState<any>({});
  const save = useMutation({ mutationFn: () => api(`/wireless/controllers/${w.id}/thresholds`, { method: "PUT", body: { thresholds: v } }), onSuccess: onClose });
  const fields: [string, string][] = [["rssi_poor_dbm", "Poor RSSI (dBm)"], ["snr_poor_db", "Low SNR (dB)"], ["interference_pct", "802.11 interference (%)"], ["noise_dbm", "Noise floor (dBm)"],
    ["retry_pct", "Retry rate (%)"], ["ap_clients_max", "AP client overload"], ["roams_per_hour", "Roams per hour"], ["rate_poor_mbps", "Low data rate (Mbit/s)"]];
  return <Modal title={`Wireless thresholds — ${w.name}`} onClose={onClose}>
    <div className="grid gap-2 sm:grid-cols-2">
      {fields.map(([k, l]) => <div key={k}><label className="label">{l} <span className="text-muted">(default {d[k]})</span></label>
        <input className="input w-full" type="number" placeholder={String(d[k] ?? "")} onChange={(e) => setV({ ...v, [k]: e.target.value === "" ? undefined : Number(e.target.value) })} /></div>)}
      {["2.4", "5", "6"].map((b) => <div key={b}><label className="label">Channel utilisation {b} GHz (%) <span className="text-muted">(default {d.channel_util_pct?.[b]})</span></label>
        <input className="input w-full" type="number" onChange={(e) => setV({ ...v, channel_util_pct: { ...(v.channel_util_pct || {}), [b]: Number(e.target.value) } })} /></div>)}
    </div>
    {save.error && <div role="alert" className="text-sm text-red-400 mt-2">{(save.error as Error).message}</div>}
    <button className="btn btn-primary mt-3" disabled={save.isPending} onClick={() => save.mutate()}>Save</button>
  </Modal>;
}

function Health() {
  const q = useQuery({ queryKey: ["wl", "health"], queryFn: () => api<any>("/wireless/health"), refetchInterval: 60_000 });
  return <div className="space-y-4 min-w-0">
    <p className="text-xs text-muted">What each controller actually returns, per metric and collection group. “Unsupported” means this controller release never answered the object (it is
      not shown as zero anywhere); “stale” means it was collected before but not within 3 intervals.</p>
    <Loading q={q} />
    {q.data && !q.data.items.length && <Card><Empty text="No wireless controller yet." /></Card>}
    {(q.data?.items || []).map((h: any) => <Card key={h.controller.id} title={`${h.controller.name} — ${h.controller.model || "controller"} ${h.controller.firmware || ""}`} bodyClass="p-0">
      <TableWrap><table className="tbl"><thead><tr><th>Group</th><th className="num">Every</th><th>Last run</th><th>Result</th><th className="w-full">Error</th></tr></thead>
        <tbody>{h.groups.map((g: any) => <tr key={g.group}><td className="whitespace-nowrap">{g.label}</td><td className="num">{g.interval_seconds}s</td><td className="text-xs"><Time v={g.last_run} /></td>
          <td>{g.ok == null ? "—" : g.ok ? <span className="text-emerald-300">ok</span> : <span className="text-red-300">failed</span>}</td><td className="text-xs text-red-300">{g.error}</td></tr>)}</tbody></table></TableWrap>
      <TableWrap maxH="max-h-96"><table className="tbl"><thead><tr><th>Metric</th><th>Status</th><th>Source (MIB object)</th><th>OID</th><th>Unit</th><th>Last success</th><th className="w-full">Reason / note</th></tr></thead>
        <tbody>{h.metrics.map((m: any) => <tr key={m.metric}><td className="font-mono text-xs">{m.metric}</td><td><MetricStatus s={m.status} /></td><td className="text-xs">{m.source}</td>
          <td className="font-mono text-2xs">{m.oid}</td><td className="text-xs">{m.unit}</td><td className="text-xs"><Time v={m.last_success} /></td>
          <td className="text-xs text-muted">{m.reason || m.note}</td></tr>)}</tbody></table></TableWrap>
    </Card>)}
  </div>;
}
