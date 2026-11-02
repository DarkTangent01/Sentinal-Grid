import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { fmtNum, fmtTime } from "../../lib/format";
import { Card, Drawer, Empty, Kpi, Loading, TableWrap, Tabs, Time, useDebounced } from "../../components/ui";
import { SeriesChart } from "../switches/common";
import { Pager, SortTh } from "../wan/common";
import { Band, RfFlags, Score, WState, bytes, dash, dbm, dur, pctv, useWlGo, useWlMeta } from "./common";

export function ApsTab() {
  const [sp, setSp] = useSearchParams();
  const meta = useWlMeta();
  const [q, setQ] = useState(sp.get("q") || "");
  const [state, setState] = useState(sp.get("state") || "");
  const [site, setSite] = useState(sp.get("site") || "");
  const [wlc, setWlc] = useState(sp.get("wlc") || "");
  const [sort, setSort] = useState<{ key: string; desc: boolean }>({ key: "", desc: false });
  const [page, setPage] = useState(1);
  const qd = useDebounced(q, 300);
  const params = { q: qd || undefined, state: state ? [state] : undefined, site: site || undefined, wlc_id: wlc ? [wlc] : undefined, sort: sort.key || undefined,
    desc: sort.desc, page, size: 100 };
  const r = useQuery({ queryKey: ["wl", "aps", params], queryFn: () => api<any>("/wireless/aps", { params }), refetchInterval: 60_000, placeholderData: (p) => p });
  const sel = sp.get("ap");
  const open = (id: number | null) => { const n = new URLSearchParams(sp); if (id) n.set("ap", String(id)); else n.delete("ap"); setSp(n); };
  const S = (k: string, l: string, c = "") => <SortTh k={k} label={l} sort={sort} setSort={(s) => { setSort(s); setPage(1); }} className={c} />;
  const d = r.data;
  return <div className="space-y-4 min-w-0">
    <div className="flex flex-wrap items-center gap-2">
      <p className="text-xs text-muted flex-1 min-w-[16rem]">APs are discovered from the controller. An AP is <b>down</b> only when it is missing from two consecutive successful AP-table polls;
        if the controller's table cannot be read the AP stays as it was (a collection problem, not an outage).</p>
      <input aria-label="Search APs" className="input py-1 w-52" placeholder="Name, MAC, IP, serial, site" value={q} onChange={(e) => { setQ(e.target.value); setPage(1); }} />
      <select aria-label="State" className="input py-1" value={state} onChange={(e) => { setState(e.target.value); setPage(1); }}><option value="">Any state</option>
        {["up", "degraded", "down", "unknown", "maintenance"].map((x) => <option key={x}>{x}</option>)}</select>
      <select aria-label="Site" className="input py-1" value={site} onChange={(e) => { setSite(e.target.value); setPage(1); }}><option value="">All sites</option>
        {(meta.data?.sites || []).map((x: string) => <option key={x}>{x}</option>)}</select>
      <select aria-label="Controller" className="input py-1" value={wlc} onChange={(e) => { setWlc(e.target.value); setPage(1); }}><option value="">All controllers</option>
        {(meta.data?.controllers || []).map((c: any) => <option key={c.id} value={c.id}>{c.name}</option>)}</select>
    </div>
    <Loading q={r} />
    {d && <Card title={`Access points (${fmtNum(d.total)})`} bodyClass="p-0" right={<span className="text-2xs text-muted">
      {Object.entries(d.states).filter(([, v]) => v).map(([k, v]) => `${v} ${k}`).join(" · ")}</span>}>
      {!d.items.length ? <Empty text="No APs match." /> : <>
        <TableWrap><table className="tbl"><thead><tr>{S("state", "State")}{S("name", "AP")}<th>Model</th>{S("ip", "IP")}{S("site", "Site")}<th>Controller</th>
          {S("clients", "Clients", "num")}<th className="num">Radios</th><th>Bands</th>{S("max_util", "Max util.", "num")}{S("cpu_pct", "CPU", "num")}{S("uptime_s", "Uptime", "num")}
          <th>Uplink (CDP)</th>{S("last_seen", "Last seen")}<th className="num">Alerts</th></tr></thead>
          <tbody>{d.items.map((a: any) => <tr key={a.id} className="cursor-pointer hover:bg-white/5" onClick={() => open(a.id)}>
            <td><WState s={a.state} /></td><td className="font-medium">{a.name}<div className="text-2xs text-muted font-mono">{a.mac}</div></td><td className="text-xs">{a.model || "—"}</td>
            <td className="font-mono text-xs">{a.ip || "—"}</td><td className="text-xs">{a.site || "—"}</td><td className="text-xs">{a.wlc}</td><td className="num">{dash(a.clients)}</td>
            <td className="num">{a.radios_total ? `${a.radios_up}/${a.radios_total}` : "—"}</td><td><span className="inline-flex gap-1">{a.bands.map((b: string) => <Band key={b} b={b} />)}</span></td>
            <td className="num">{pctv(a.max_util)}</td><td className="num">{pctv(a.cpu_pct)}</td><td className="num">{dur(a.uptime_s)}</td>
            <td className="text-xs">{a.uplink?.switch ? <>{a.uplink.switch.split(".")[0]} <span className="text-muted">{a.uplink.port}</span></> : "—"}</td>
            <td className="text-xs"><Time v={a.last_seen} /></td><td className="num">{a.alerts ? <span className="text-red-300">{a.alerts}</span> : 0}</td></tr>)}</tbody></table></TableWrap>
        <Pager page={page} size={100} total={d.total} onPage={setPage} /></>}
    </Card>}
    {sel && <ApDrawer id={Number(sel)} onClose={() => open(null)} />}
  </div>;
}

const AP_TABS = [["overview", "Overview"], ["radios", "Radios"], ["clients", "Connected clients"], ["traffic", "Traffic"], ["events", "Events"], ["history", "Health history"]];

export function ApDrawer({ id, onClose }: { id: number; onClose: () => void }) {
  const [tab, setTab] = useState("overview");
  const [range, setRange] = useState("24h");
  const go = useWlGo();
  const q = useQuery({ queryKey: ["wl", "ap", id], queryFn: () => api<any>(`/wireless/aps/${id}`), refetchInterval: 60_000 });
  const h = useQuery({ queryKey: ["wl", "ap-hist", id, range], queryFn: () => api<any>(`/wireless/aps/${id}/history`, { params: { range } }),
    enabled: tab === "history" || tab === "traffic" || tab === "radios" });
  const d = q.data;
  const a = d?.ap;
  return <Drawer title={a ? `${a.name} · ${a.model || "AP"}` : "Access point"} onClose={onClose}>
    <Loading q={q} />
    {d && <div className="space-y-4">
      <div className="text-sm flex flex-wrap gap-x-4 gap-y-1"><WState s={a.state} /><span>since <Time v={a.state_since} /></span><span>controller {a.wlc}</span>
        <span className="font-mono text-xs">{a.mac}</span>{a.ip && <span className="font-mono text-xs">{a.ip}</span>}<span>{a.site}</span></div>
      <Tabs value={tab} onChange={setTab} tabs={AP_TABS.map(([key, label]) => ({ key, label }))} />
      {tab === "overview" && <>
        <div className="kpi-grid">
          <Kpi label="Clients" value={dash(a.clients)} onClick={() => setTab("clients")} />
          <Kpi label="Radios up" value={`${d.radios.filter((r: any) => r.state === "up").length} / ${d.radios.length}`} onClick={() => setTab("radios")} />
          <Kpi label="CPU / memory" value={`${pctv(a.cpu_pct)} / ${pctv(a.mem_pct)}`} sub="CISCO-LWAPP-AP-MIB" />
          <Kpi label="Uptime" value={dur(a.uptime_s)} sub={`joined ${dur(a.join_uptime_s)} ago`} />
          <Kpi label="Active alerts" value={fmtNum(d.alerts.length)} tone={d.alerts.length ? "bad" : "ok"} />
        </div>
        <Card title="Identity"><dl className="grid grid-cols-2 sm:grid-cols-3 gap-x-4 gap-y-1 text-sm">
          {([["Serial", a.serial], ["Software", a.software], ["Location", a.location], ["Tags", Object.entries(a.tags).map(([k, v]) => `${k}: ${v}`).join(" · ")],
            ["Last reboot reason", a.last_reboot_reason], ["Power", a.power_status], ["Last poll", fmtTime(a.last_seen)], ["Sources", a.sources.join(", ")]] as [string, any][])
            .map(([k, v]) => <div key={k}><dt className="text-2xs text-muted">{k}</dt><dd>{v || "—"}</dd></div>)}</dl></Card>
        <Card title="Uplink switch port">{!d.switch_port ? <Empty text="The controller's CDP cache does not name this AP's switch port (CISCO-LWAPP-CDP-MIB); the port is never guessed from the AP's IP." /> :
          <div className="text-sm space-y-1"><div>CDP neighbour <b>{d.switch_port.cdp.switch}</b> port <b>{d.switch_port.cdp.port}</b> <span className="text-muted">({d.switch_port.cdp.platform})</span></div>
            {!d.switch_port.monitored ? <div className="text-muted">That switch is not monitored by Sentinel NMS, so port / PoE state is unavailable.</div> : <>
              <div>Switch <Link className="link" to={`/switches/${d.switch_port.switch?.id}`}>{d.switch_port.switch?.name}</Link> is <WState s={d.switch_port.switch?.state} /></div>
              {d.switch_port.port ? <div>Port {d.switch_port.port.name}: oper <b>{d.switch_port.port.oper}</b>, admin {d.switch_port.port.admin}
                {d.switch_port.port.poe && <>, PoE <b>{d.switch_port.port.poe.status}</b> {d.switch_port.port.poe.power_w != null && `${d.switch_port.port.poe.power_w} W`}</>}
                {d.switch_port.port.access_vlan != null && <>, VLAN {d.switch_port.port.access_vlan}</>}{d.switch_port.port.crc_delta ? <span className="text-amber-300">, {d.switch_port.port.crc_delta} CRC errors</span> : null}</div>
                : <div className="text-muted">Port {d.switch_port.cdp.port} was not found in that switch's interface list.</div>}</>}</div>}</Card>
        {d.alerts.length > 0 && <Card title="Active alerts" bodyClass="p-0"><TableWrap><table className="tbl"><tbody>{d.alerts.map((x: any) =>
          <tr key={x.id}><td><Link className="link" to={`/alerts?id=${x.id}`}>{x.name}</Link></td><td className="text-xs"><Time v={x.last_seen} /></td></tr>)}</tbody></table></TableWrap></Card>}
        <button className="btn" onClick={() => go("troubleshoot", { scenario: a.state === "down" ? "ap_offline" : "poor_performance", ap: a.id })}>Troubleshoot this AP</button>
      </>}
      {tab === "radios" && <><RadioTable rows={d.radios} />
        {h.data?.radios?.length > 0 && [...new Set(h.data.radios.map((p: any) => p.slot))].map((slot: any) => <Card key={slot} title={`Radio ${slot}: channel utilisation and interference`}>
          <SeriesChart points={h.data.radios.filter((p: any) => p.slot === slot)} bucket={h.data.bucket_seconds} unit="pct" yMax={100}
            series={[{ key: "wireless_radio_channel_utilization_percent", name: "Channel util." }, { key: "wireless_radio_tx_utilization_percent", name: "Tx util.", dashed: true },
              { key: "wireless_radio_rx_utilization_percent", name: "Rx util.", dashed: true }, { key: "wireless_radio_interference_percent", name: "802.11 interference" },
              { key: "wireless_radio_retry_percent", name: "Retries %" }]} /></Card>)}</>}
      {tab === "clients" && <ClientMini rows={d.clients} />}
      {tab === "traffic" && <Card title="Traffic"><p className="text-xs text-muted mb-2">Per-client byte counters reported by the controller (AIRESPACE bsnMobileStationStatsTable). They are
        totals since association, not RF airtime or wired bandwidth.</p>
        <TableWrap><table className="tbl"><thead><tr><th>Client</th><th>SSID</th><th className="num">Received</th><th className="num">Sent</th></tr></thead>
          <tbody>{[...d.clients].sort((x: any, y: any) => (y.rx_bytes || 0) + (y.tx_bytes || 0) - (x.rx_bytes || 0) - (x.tx_bytes || 0)).map((c: any) =>
            <tr key={c.mac}><td className="font-mono text-xs">{c.mac}</td><td>{c.ssid}</td><td className="num">{bytes(c.rx_bytes)}</td><td className="num">{bytes(c.tx_bytes)}</td></tr>)}</tbody></table></TableWrap>
        {h.data?.radios?.length > 0 && <SeriesChart points={h.data.radios} bucket={h.data.bucket_seconds} unit="count" series={[{ key: "wireless_radio_client_count", name: "Clients per radio" }]} />}</Card>}
      {tab === "events" && <Card bodyClass="p-0">{!d.events.length ? <Empty text="No events for this AP." /> :
        <TableWrap maxH="max-h-[32rem]"><table className="tbl"><tbody>{d.events.map((e: any) => <tr key={e.id}><td className="text-xs whitespace-nowrap"><Time v={e.at} /></td>
          <td className="text-xs">{e.kind.replace(/_/g, " ")}</td><td className="text-xs">{e.detail}</td></tr>)}</tbody></table></TableWrap>}</Card>}
      {tab === "history" && <>
        <select aria-label="Range" className="input py-1" value={range} onChange={(e) => setRange(e.target.value)}>{["1h", "6h", "24h", "7d", "30d"].map((x) => <option key={x}>{x}</option>)}</select>
        <Loading q={h} />
        {h.data && (!h.data.ap.length ? <Empty text="No history in this range." /> : <>
          <Card title="Clients, CPU and memory"><SeriesChart points={h.data.ap} bucket={h.data.bucket_seconds} unit="raw"
            series={[{ key: "wireless_ap_client_count", name: "Clients" }, { key: "wireless_ap_cpu_percent", name: "CPU %" }, { key: "wireless_ap_memory_percent", name: "Memory %" }]} /></Card>
          <Card title="Availability (1 = joined)"><SeriesChart points={h.data.ap} bucket={h.data.bucket_seconds} unit="raw" yMax={1} series={[{ key: "wireless_ap_up", name: "AP up", bar: true }]} /></Card>
        </>)}
      </>}
    </div>}
  </Drawer>;
}

export function RadioTable({ rows }: { rows: any[] }) {
  if (!rows.length) return <Empty text="No radios reported." />;
  return <TableWrap><table className="tbl"><thead><tr><th>Slot</th><th>Band</th><th>State</th><th className="num">Channel</th><th className="num">Width</th><th className="num" title="power level 1-8, 1 = highest; not dBm">Tx level</th>
    <th className="num">Util.</th><th className="num">Tx / Rx</th><th className="num">Noise</th><th className="num">802.11 interf.</th><th className="num">Retries</th><th className="num">Clients</th>
    <th>WLANs</th><th>Issues</th></tr></thead>
    <tbody>{rows.map((r) => <tr key={r.id}><td>{r.slot}</td><td><Band b={r.band} /></td><td><WState s={r.state} /></td><td className="num">{dash(r.channel)}</td>
      <td className="num">{dash(r.channel_width_mhz, " MHz")}</td><td className="num">{dash(r.tx_power_level)}</td>
      <td className={`num ${r.channel_util_pct != null && r.channel_util_pct >= r.util_threshold ? "text-red-300" : ""}`}>{pctv(r.channel_util_pct)}</td>
      <td className="num text-xs">{pctv(r.tx_util_pct)} / {pctv(r.rx_util_pct)}</td><td className="num">{dbm(r.noise_dbm)}</td><td className="num">{pctv(r.interference_pct)}</td>
      <td className="num">{dash(r.retry_pct, "%", 1)}</td><td className="num">{dash(r.clients)}</td><td className="text-xs">{r.wlans.map((w: any) => w.ssid).join(", ") || "—"}</td>
      <td><RfFlags f={r.flags} /></td></tr>)}</tbody></table></TableWrap>;
}

function ClientMini({ rows }: { rows: any[] }) {
  const go = useWlGo();
  if (!rows.length) return <Empty text="No associated clients." />;
  return <TableWrap><table className="tbl"><thead><tr><th>Client</th><th>SSID</th><th>Band</th><th className="num">RSSI</th><th className="num">SNR</th><th className="num">Rate</th>
    <th className="num">Connected</th><th>Experience</th></tr></thead>
    <tbody>{rows.map((c) => <tr key={c.mac} className="cursor-pointer hover:bg-white/5" onClick={() => go("clients", { client: c.mac })}>
      <td className="font-mono text-xs">{c.mac}<div className="text-muted">{c.ip}</div></td><td>{c.ssid}</td><td><Band b={c.band} /></td><td className="num">{dbm(c.rssi_dbm)}</td>
      <td className="num">{dash(c.snr_db, " dB")}</td><td className="num">{dash(c.tx_rate_mbps, " Mb/s")}</td><td className="num">{dur(c.session_s)}</td><td><Score e={c.experience} /></td></tr>)}</tbody></table></TableWrap>;
}

