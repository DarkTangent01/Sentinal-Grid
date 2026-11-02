import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { useTheme } from "../../lib/theme";
import { fmtNum } from "../../lib/format";
import { Chart, PALETTES, axisStyle } from "../../components/Chart";
import { Card, Drawer, Empty, Kpi, Loading, Sev, TableWrap, Time, useDebounced } from "../../components/ui";
import { SeriesChart } from "../switches/common";
import { Pager, SortTh } from "../wan/common";
import { Band, Score, WState, bytes, dash, dbm, dur, useWlGo, useWlMeta } from "./common";

const PROBLEMS: [string, string][] = [["", "All clients"], ["poor_score", "Poor experience score"], ["poor_rssi", "Poor RSSI"], ["low_snr", "Low SNR"], ["low_rate", "Low data rate"],
  ["disconnects", "Repeated disconnects"], ["roaming", "Frequent roaming"]];

export function ClientsTab() {
  const [sp, setSp] = useSearchParams();
  const meta = useWlMeta();
  const [q, setQ] = useState("");
  const [ssid, setSsid] = useState(sp.get("ssid") || "");
  const [band, setBand] = useState(sp.get("band") || "");
  const [site, setSite] = useState(sp.get("site") || "");
  const [problem, setProblem] = useState(sp.get("problem") || "");
  const [sort, setSort] = useState<{ key: string; desc: boolean }>({ key: "", desc: false });
  const [page, setPage] = useState(1);
  const qd = useDebounced(q, 300);
  const params = { q: qd || undefined, ssid: ssid || undefined, band: band || undefined, site: site || undefined, problem: problem || undefined,
    ap_id: sp.get("ap") || undefined, sort: sort.key || undefined, desc: sort.desc, page, size: 100 };
  const r = useQuery({ queryKey: ["wl", "clients", params], queryFn: () => api<any>("/wireless/clients", { params }), refetchInterval: 60_000, placeholderData: (p) => p });
  const sel = sp.get("client");
  const open = (m: string | null) => { const n = new URLSearchParams(sp); if (m) n.set("client", m); else n.delete("client"); setSp(n); };
  const S = (k: string, l: string, c = "num") => <SortTh k={k} label={l} sort={sort} setSort={(s) => { setSort(s); setPage(1); }} className={c} />;
  const d = r.data;
  return <div className="space-y-4 min-w-0">
    <div className="flex flex-wrap items-center gap-2">
      <p className="text-xs text-muted flex-1 min-w-[16rem]">Clients as the controller reports them. RSSI / SNR are client-side measurements reported by the controller; the experience score uses only measured
        values (hover it for the components and confidence). Usernames are visible to administrators only.</p>
      <input aria-label="Search clients" className="input py-1 w-48" placeholder="MAC or IP" value={q} onChange={(e) => { setQ(e.target.value); setPage(1); }} />
      <select aria-label="Problem" className="input py-1" value={problem} onChange={(e) => { setProblem(e.target.value); setPage(1); }}>{PROBLEMS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
      <select aria-label="SSID" className="input py-1" value={ssid} onChange={(e) => { setSsid(e.target.value); setPage(1); }}><option value="">All SSIDs</option>
        {(meta.data?.ssids || []).map((x: string) => <option key={x}>{x}</option>)}</select>
      <select aria-label="Band" className="input py-1" value={band} onChange={(e) => { setBand(e.target.value); setPage(1); }}><option value="">All bands</option>
        {["2.4", "5", "6"].map((b) => <option key={b} value={b}>{b} GHz</option>)}</select>
      <select aria-label="Site" className="input py-1" value={site} onChange={(e) => { setSite(e.target.value); setPage(1); }}><option value="">All sites</option>
        {(meta.data?.sites || []).map((x: string) => <option key={x}>{x}</option>)}</select>
    </div>
    <Loading q={r} />
    {d && <Card title={`Clients (${fmtNum(d.total)})`} bodyClass="p-0" right={<span className="text-2xs text-muted">{d.summary.scored} scored · average {dash(d.summary.avg_score)}</span>}>
      {!d.items.length ? <Empty text="No clients match." /> : <>
        <TableWrap><table className="tbl"><thead><tr>{S("mac", "Client", "")}{S("username", "User", "")}{S("ap", "AP", "")}{S("ssid", "SSID", "")}<th>Band</th>
          {S("rssi_dbm", "RSSI")}{S("snr_db", "SNR")}{S("tx_rate_mbps", "Rate")}{S("session_s", "Connected")}{S("roams", "Roams")}{S("disconnects", "Drops")}{S("score", "Experience")}</tr></thead>
          <tbody>{d.items.map((c: any) => <tr key={`${c.wlc_id}${c.mac}`} className="cursor-pointer hover:bg-white/5" onClick={() => open(c.mac)}>
            <td className="font-mono text-xs">{c.mac}<div className="text-muted">{c.ip || "—"}{c.vlan != null && ` · VLAN ${c.vlan}`}</div></td><td className="text-xs">{c.username || "—"}</td>
            <td className="text-xs">{c.ap || "—"}</td><td className="text-xs">{c.ssid || "—"}</td><td><Band b={c.band} /></td><td className="num">{dbm(c.rssi_dbm)}</td>
            <td className="num">{dash(c.snr_db, " dB")}</td><td className="num">{dash(c.tx_rate_mbps, " Mb/s")}</td><td className="num">{dur(c.session_s)}</td>
            <td className="num">{c.roams}</td><td className="num">{c.disconnects}</td><td><Score e={c.experience} /></td></tr>)}</tbody></table></TableWrap>
        <Pager page={page} size={100} total={d.total} onPage={setPage} /></>}
    </Card>}
    {sel && <ClientDrawer mac={sel} onClose={() => open(null)} />}
  </div>;
}

function ClientDrawer({ mac, onClose }: { mac: string; onClose: () => void }) {
  const go = useWlGo();
  const [range, setRange] = useState("24h");
  const q = useQuery({ queryKey: ["wl", "client", mac, range], queryFn: () => api<any>(`/wireless/clients/${mac}`, { params: { range } }), refetchInterval: 60_000 });
  const d = q.data;
  const c = d?.client;
  return <Drawer title={`Client ${mac}`} onClose={onClose}>
    <Loading q={q} />
    {d && <div className="space-y-4">
      <div className="text-sm flex flex-wrap gap-x-4 gap-y-1"><span>{c.present ? "associated" : "no longer listed"} · status {c.status || "—"}</span><span>{c.ssid}</span>
        <Band b={c.band} /><span>AP {c.ap || "—"} (slot {dash(c.slot)})</span><span className="font-mono text-xs">{c.ip}</span>{c.username && <span>user {c.username}</span>}</div>
      <div className="kpi-grid">
        <Kpi label="Experience" value={<Score e={c.experience} />} sub={c.experience.factors.map((f: any) => `${f.label} ${f.points}`).join(" · ") || c.experience.note} />
        <Kpi label="RSSI / SNR" value={`${dbm(c.rssi_dbm)} / ${dash(c.snr_db, " dB")}`} sub="client-side, reported by the controller" />
        <Kpi label="Data rate" value={dash(c.tx_rate_mbps, " Mbit/s")} sub={c.protocol} />
        <Kpi label="Connected" value={dur(c.session_s)} sub={`${c.roams} roams · ${c.disconnects} drops seen`} />
        <Kpi label="Traffic" value={`${bytes(c.rx_bytes)} / ${bytes(c.tx_bytes)}`} sub="received / sent since association" />
      </div>
      {d.radio && <div className="text-xs text-muted">Serving radio: channel {dash(d.radio.channel)} ({d.radio.band} GHz), utilisation {dash(d.radio.channel_util_pct, "%")},
        noise {dbm(d.radio.noise_dbm)}, retries {dash(d.radio.retry_pct, "%", 1)} — AP-side measurements.</div>}
      <div className="flex items-center gap-2"><select aria-label="Range" className="input py-1" value={range} onChange={(e) => setRange(e.target.value)}>{["1h", "6h", "24h", "7d"].map((x) => <option key={x}>{x}</option>)}</select>
        <button className="btn" onClick={() => go("troubleshoot", { scenario: "frequent_disconnects", mac })}>Troubleshoot this client</button></div>
      <Card title="Signal history">{d.history.length ? <SeriesChart points={d.history} bucket={d.bucket_seconds} unit="raw"
        series={[{ key: "rssi", name: "RSSI (dBm)" }, { key: "snr", name: "SNR (dB)" }, { key: "rate", name: "Rate (Mbit/s)", dashed: true }]} /> : <Empty text="No samples in this range." />}</Card>
      <Card title={`Roaming and association timeline (${d.events.length})`} bodyClass="p-0">
        <p className="text-2xs text-muted px-3 pt-2">Roams are inferred when the controller reports a different AP in consecutive polls; times are poll times, not measured roam durations.
          {d.roaming.rows?.[0]?.flags?.length > 0 && <span className="text-amber-300"> Flags: {d.roaming.rows[0].flags.join(", ").replace(/_/g, " ")}</span>}</p>
        {!d.events.length ? <Empty text="No association events recorded." /> : <TableWrap maxH="max-h-80"><table className="tbl"><tbody>{d.events.map((e: any) =>
          <tr key={e.id}><td className="text-xs whitespace-nowrap"><Time v={e.at} /></td><td className="text-xs">{e.kind.replace("client_", "").replace(/_/g, " ")}</td>
            <td className="text-xs">{e.detail}</td></tr>)}</tbody></table></TableWrap>}</Card>
      <div className="text-2xs text-muted">Sources: {c.sources.join(", ") || "—"}</div>
    </div>}
  </Drawer>;
}

export function WlansTab() {
  const go = useWlGo();
  const { theme } = useTheme();
  const [range, setRange] = useState("24h");
  const q = useQuery({ queryKey: ["wl", "wlans", range], queryFn: () => api<any>("/wireless/wlans", { params: { range } }), refetchInterval: 120_000, placeholderData: (p) => p });
  const d = q.data;
  const trend = useMemo(() => {
    if (!d?.trend?.length) return null;
    const ids = [...new Set(d.trend.map((x: any) => x.wlan_id))] as number[];
    const name = (id: number) => d.items.find((w: any) => w.wlan_id === id)?.ssid || `WLAN ${id}`;
    return { legend: { top: 0 }, tooltip: { trigger: "axis" }, grid: { left: 8, right: 16, top: 32, bottom: 8, containLabel: true },
      xAxis: { type: "time", ...axisStyle }, yAxis: { type: "value", minInterval: 1, ...axisStyle },
      series: ids.map((id, i) => ({ name: name(id), type: "line", showSymbol: false, itemStyle: { color: PALETTES[theme][i % 8] },
        data: d.trend.filter((x: any) => x.wlan_id === id).map((x: any) => [Date.parse(x.t), x.clients]) })) };
  }, [d, theme]);
  return <div className="space-y-4 min-w-0">
    <div className="flex flex-wrap items-center gap-2"><p className="text-xs text-muted flex-1 min-w-[16rem]">WLANs configured on the controllers. Only a security summary is shown; keys and PSKs are never requested.
      {d?.note && ` ${d.note}`}</p>
      <select aria-label="Range" className="input py-1" value={range} onChange={(e) => setRange(e.target.value)}>{["6h", "24h", "7d", "30d"].map((x) => <option key={x}>{x}</option>)}</select></div>
    <Loading q={q} />
    {d && <>
      <Card bodyClass="p-0">{!d.items.length ? <Empty text="No WLANs reported." /> : <TableWrap><table className="tbl"><thead><tr><th>ID</th><th>SSID</th><th>Profile</th><th>Controller</th><th>State</th>
        <th>Security</th><th className="num">Clients</th><th className="num">APs / radios</th><th>Bands</th><th className="num">Avg RSSI</th><th className="num">Traffic (rx / tx)</th><th>Top APs</th></tr></thead>
        <tbody>{d.items.map((w: any) => <tr key={w.id} className="cursor-pointer hover:bg-white/5" onClick={() => go("clients", { ssid: w.ssid })}><td>{w.wlan_id}</td>
          <td className="font-medium">{w.ssid}</td><td className="text-xs">{w.profile}</td><td className="text-xs">{w.wlc}</td><td><WState s={!w.present ? "unknown" : w.enabled ? "up" : "disabled"} /></td>
          <td className="text-xs">{w.security || "—"}</td><td className="num">{dash(w.clients)}</td><td className="num">{dash(w.aps)} / {dash(w.radios)}</td>
          <td className="text-xs">{Object.entries(w.bands).map(([b, n]) => `${b}: ${n}`).join(" · ") || "—"}</td><td className="num">{dbm(w.avg_rssi_dbm)}</td>
          <td className="num text-xs">{bytes(w.rx_bytes)} / {bytes(w.tx_bytes)}</td><td className="text-xs">{w.top_aps.map(([a, n]: any) => `${a} (${n})`).join(", ") || "—"}</td></tr>)}</tbody></table></TableWrap>}</Card>
      <Card title="Clients per SSID over time">{trend ? <Chart height={260} option={trend} ariaLabel="Clients per SSID" /> : <Empty text="No client-count history in this range." />}</Card>
    </>}
  </div>;
}

export function RoamingTab() {
  const go = useWlGo();
  const [hours, setHours] = useState(24);
  const q = useQuery({ queryKey: ["wl", "roaming", hours], queryFn: () => api<any>("/wireless/roaming", { params: { hours } }), refetchInterval: 120_000 });
  const d = q.data;
  return <div className="space-y-4 min-w-0">
    <div className="flex flex-wrap items-center gap-2"><p className="text-xs text-muted flex-1 min-w-[16rem]">{d?.note || "Roaming inferred between polls."} Ping-pong = back to the previous AP within 10 minutes.</p>
      <select aria-label="Window" className="input py-1" value={hours} onChange={(e) => setHours(Number(e.target.value))}>{[1, 6, 24, 72, 168].map((h) => <option key={h} value={h}>{h} h</option>)}</select></div>
    <Loading q={q} />
    {d && <>
      <div className="kpi-grid"><Kpi label="Roams" value={fmtNum(d.roams)} /><Kpi label="Roaming clients" value={fmtNum(d.clients)} />
        <Kpi label="Clients with anomalies" value={fmtNum(d.anomalies)} tone={d.anomalies ? "warn" : "ok"} /><Kpi label="Excessive-roaming threshold" value={`${d.threshold_roams} roams`} sub={`in ${d.window_hours} h`} /></div>
      <Card bodyClass="p-0">{!d.rows.length ? <Empty text="No roams observed in this window." /> : <TableWrap><table className="tbl"><thead><tr><th>Client</th><th className="num">Roams</th>
        <th className="num">Ping-pong</th><th className="num">Drop after roam</th><th>Flags</th><th>APs visited</th><th>Last</th></tr></thead>
        <tbody>{d.rows.map((r: any) => <tr key={r.mac} className="cursor-pointer hover:bg-white/5" onClick={() => go("clients", { client: r.mac })}><td className="font-mono text-xs">{r.mac}</td>
          <td className="num">{r.roams}</td><td className="num">{r.ping_pong}</td><td className="num">{r.disconnect_after_roam}</td>
          <td>{r.flags.map((f: string) => <span key={f} className="pill bg-amber-500/15 text-amber-300 mr-1">{f.replace(/_/g, " ")}</span>)}</td>
          <td className="text-xs font-mono">{r.aps.join(", ")}</td><td className="text-xs"><Time v={r.last} /></td></tr>)}</tbody></table></TableWrap>}</Card>
    </>}
  </div>;
}

const KINDS = ["ap_down", "ap_reconnected", "ap_joined", "ap_reboot", "ap_degraded", "ap_software_change", "radio_down", "radio_up", "radio_disabled", "channel_change",
  "client_associated", "client_disconnected", "client_roam", "client_churn"];

export function EventsTab() {
  const [sp] = useSearchParams();
  const [kind, setKind] = useState(sp.get("kind") || "");
  const [hours, setHours] = useState(24);
  const [page, setPage] = useState(1);
  const params = { kind: kind ? [kind] : undefined, hours, page, size: 100, ap_id: sp.get("ap") || undefined };
  const q = useQuery({ queryKey: ["wl", "events", params], queryFn: () => api<any>("/wireless/events", { params }), refetchInterval: 60_000, placeholderData: (p) => p });
  const d = q.data;
  return <div className="space-y-4 min-w-0">
    <div className="flex flex-wrap items-center gap-2"><p className="text-xs text-muted flex-1 min-w-[16rem]">State changes observed between controller polls. Authentication / EAP / RADIUS details are not in the
      SNMP MIBs; ingest the controller's syslog for those.</p>
      <select aria-label="Event type" className="input py-1" value={kind} onChange={(e) => { setKind(e.target.value); setPage(1); }}><option value="">All events</option>
        {KINDS.map((k) => <option key={k} value={k}>{k.replace(/_/g, " ")}{d?.kinds?.[k] ? ` (${d.kinds[k]})` : ""}</option>)}</select>
      <select aria-label="Window" className="input py-1" value={hours} onChange={(e) => { setHours(Number(e.target.value)); setPage(1); }}>{[1, 6, 24, 168, 720].map((h) => <option key={h} value={h}>{h} h</option>)}</select></div>
    <Loading q={q} />
    {d && <Card bodyClass="p-0">{!d.items.length ? <Empty text="No events." /> : <>
      <TableWrap><table className="tbl"><thead><tr><th>Time</th><th>Event</th><th>Severity</th><th>AP</th><th>Client</th><th className="w-full">Detail</th></tr></thead>
        <tbody>{d.items.map((e: any) => <tr key={e.id}><td className="text-xs whitespace-nowrap"><Time v={e.at} /></td><td className="text-xs">{e.kind.replace(/_/g, " ")}</td><td><Sev s={e.severity} /></td>
          <td className="text-xs">{e.ap || "—"}</td><td className="font-mono text-xs">{e.client_mac || "—"}</td><td className="text-xs">{e.detail}</td></tr>)}</tbody></table></TableWrap>
      <Pager page={page} size={100} total={d.total} onPage={setPage} /></>}</Card>}
  </div>;
}

export function TroubleshootTab() {
  const [sp] = useSearchParams();
  const meta = useWlMeta();
  const [scenario, setScenario] = useState(sp.get("scenario") || "poor_performance");
  const [ap, setAp] = useState(sp.get("ap") || "");
  const [mac, setMac] = useState(sp.get("mac") || "");
  const [ssid, setSsid] = useState("");
  const aps = useQuery({ queryKey: ["wl", "aps-lite"], queryFn: () => api<any>("/wireless/aps", { params: { size: 1000 } }) });
  const run = useMutation({ mutationFn: () => api<any>("/wireless/troubleshoot", { method: "POST", body: { scenario, ap_id: ap ? Number(ap) : null, mac: mac || null, ssid: ssid || null } }) });
  const r = run.data;
  return <div className="space-y-4 min-w-0">
    <p className="text-xs text-muted">Rule-based checks over what the controller and switch monitoring report. Results list the evidence behind each finding; probable causes are correlations, not a
      determined root cause. Nothing is changed on any device.</p>
    <Card><div className="grid gap-2 sm:grid-cols-4">
      <div><label className="label">Scenario</label><select className="input w-full" value={scenario} onChange={(e) => setScenario(e.target.value)}>
        {Object.entries(meta.data?.scenarios || {}).map(([k, l]) => <option key={k} value={k}>{l as string}</option>)}</select></div>
      <div><label className="label">Access point</label><select className="input w-full" value={ap} onChange={(e) => setAp(e.target.value)}><option value="">—</option>
        {(aps.data?.items || []).map((a: any) => <option key={a.id} value={a.id}>{a.name} ({a.state})</option>)}</select></div>
      <div><label className="label">Client MAC</label><input className="input w-full font-mono" value={mac} onChange={(e) => setMac(e.target.value)} placeholder="aa:bb:cc:dd:ee:ff" /></div>
      <div><label className="label">SSID</label><input className="input w-full" value={ssid} onChange={(e) => setSsid(e.target.value)} placeholder="for “client cannot connect”" /></div>
    </div>
      {run.error && <div role="alert" className="text-sm text-red-400 mt-2">{(run.error as Error).message}</div>}
      <button className="btn btn-primary mt-3" disabled={run.isPending} onClick={() => run.mutate()}>{run.isPending ? "Analysing…" : "Analyse"}</button></Card>
    {r && <Card title={`${r.label} — ${r.target.ap || r.target.client || r.target.ssid || ""}`} right={<span className="text-xs">severity <Sev s={r.severity} /> · confidence {r.confidence}</span>}>
      <div className="space-y-3">
        <div><div className="label">Probable causes</div><ol className="list-decimal pl-5 text-sm space-y-0.5">{r.probable_causes.map((c: string) => <li key={c}>{c}</li>)}</ol></div>
        <div><div className="label">Evidence ({r.failed_checks} of {r.measured_checks} measured checks outside thresholds)</div>
          <TableWrap><table className="tbl"><tbody>{r.evidence.map((e: any, i: number) => <tr key={i}><td className={e.ok == null ? "text-muted" : e.ok ? "text-emerald-300" : "text-red-300"}>
            {e.ok == null ? "•" : e.ok ? "✓" : "✗"}</td><td className="text-sm">{e.text}{e.threshold != null && <span className="text-muted text-xs"> (threshold {e.threshold})</span>}</td>
            <td className="text-2xs text-muted">{e.source}</td></tr>)}</tbody></table></TableWrap></div>
        <div><div className="label">Recommended investigation</div><ul className="list-disc pl-5 text-sm">{r.next_steps.map((s: string) => <li key={s}>{s}</li>)}</ul></div>
        <p className="text-2xs text-muted">{r.note}</p>
      </div></Card>}
  </div>;
}
