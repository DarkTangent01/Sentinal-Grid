import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, downloadUrl } from "../../lib/api";
import { useMe } from "../../lib/context";
import { fmtNum } from "../../lib/format";
import { Card, Empty, Kpi, Loading, Sev, TableWrap, Tabs, Time, Trunc, rowProps, useDebounced } from "../../components/ui";
import { Bps, Flags, Fresh, Oper, RangeSelect, StateDot, Util, fmtPctOrDash, fmtUptime, fmtWatts, statusTone } from "./common";
import { AddSwitch, SwitchSettings } from "./Admin";
import { Topology } from "./Topology";

const TABS: [string, string][] = [["overview", "Overview"], ["inventory", "Inventory"], ["topology", "Topology"], ["interfaces", "Interfaces"], ["events", "Events"],
  ["settings", "Settings"]];

/** Filters live in the URL so every tile opens a shareable, filtered detail view. */
function useFilters() {
  const [sp, setSp] = useSearchParams();
  const get = (k: string) => sp.get(k) || "";
  const set = (patch: Record<string, string | null>) => {
    const n = new URLSearchParams(sp);
    for (const [k, v] of Object.entries(patch)) (v ? n.set(k, v) : n.delete(k));
    setSp(n, { replace: false });
  };
  return { tab: get("tab") || "overview", site: get("site"), vendor: get("vendor"), model: get("model"), q: get("q"), range: get("range") || "24h",
    state: get("state"), view: get("view"), sort: get("sort"), set };
}

export function Switches() {
  const f = useFilters();
  const me = useMe();
  const meta = useQuery({ queryKey: ["switch-filters"], queryFn: () => api<any>("/switches/overview", { params: { range: "15m" } }), staleTime: 60_000 });
  const opts = meta.data?.filters || { sites: [], vendors: [], models: [] };
  const [qText, setQText] = useState(f.q);
  const dq = useDebounced(qText, 400);
  useEffect(() => { if (dq !== f.q) f.set({ q: dq || null }); }, [dq]);  // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <div className="space-y-4 min-w-0">
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-xs text-muted flex-1 min-w-[16rem]">Cisco and Ruckus ICX switches over read-only SNMP (SNMPv3 preferred). Every metric is discovered per device:
          anything a switch does not report is shown as <b>unsupported</b> or <b>—</b>, never as zero. Nothing in this module writes to a switch.</p>
        {me.role === "admin" && <AddSwitch />}
      </div>
      <Tabs value={f.tab} onChange={(t) => f.set({ tab: t, view: null })} tabs={TABS.filter(([k]) => k !== "settings" || me.role === "admin").map(([key, label]) => ({ key, label }))} />
      {f.tab !== "settings" && <div className="flex flex-wrap items-center gap-2">
        <input aria-label="Search switches" className="input py-1 w-56" placeholder="Name, IP, model, serial…" value={qText} onChange={(e) => setQText(e.target.value)} />
        <select aria-label="Site" className="input py-1" value={f.site} onChange={(e) => f.set({ site: e.target.value || null })}>
          <option value="">All sites</option>{opts.sites.map((s: string) => <option key={s}>{s}</option>)}</select>
        <select aria-label="Vendor" className="input py-1" value={f.vendor} onChange={(e) => f.set({ vendor: e.target.value || null })}>
          <option value="">All vendors</option>{["cisco", "fortinet", "juniper", "ruckus", "generic", "unknown"].map((s) => <option key={s} value={s}>{s}</option>)}</select>
        <select aria-label="Model" className="input py-1" value={f.model} onChange={(e) => f.set({ model: e.target.value || null })}>
          <option value="">All models</option>{opts.models.map((s: string) => <option key={s}>{s}</option>)}</select>
        {(f.tab === "overview" || f.tab === "events") && <RangeSelect value={f.range} onChange={(v) => f.set({ range: v })} />}
        {(f.site || f.vendor || f.model || f.q || f.state || f.view) && <button className="btn" onClick={() => { setQText(""); f.set({ site: null, vendor: null, model: null, q: null, state: null, view: null }); }}>Clear filters</button>}
      </div>}
      {f.tab === "overview" && <Overview f={f} />}
      {f.tab === "inventory" && <Inventory f={f} />}
      {f.tab === "topology" && <Topology site={f.site} />}
      {f.tab === "interfaces" && <AllInterfaces f={f} />}
      {f.tab === "events" && <Events f={f} />}
      {f.tab === "settings" && me.role === "admin" && <SwitchSettings />}
    </div>
  );
}

type F = ReturnType<typeof useFilters>;
const common = (f: F) => ({ site: f.site || undefined, vendor: f.vendor || undefined, model: f.model || undefined, q: f.q || undefined });

function Overview({ f }: { f: F }) {
  const nav = useNavigate();
  const q = useQuery({ queryKey: ["switch-overview", f.site, f.vendor, f.model, f.q, f.range], refetchInterval: 30_000, placeholderData: (p) => p,
    queryFn: () => api<any>("/switches/overview", { params: { ...common(f), range: f.range } }) });
  const d = q.data;
  const t = d?.totals || {};
  const go = (patch: Record<string, string | null>) => f.set(patch);
  if (!d) return <Loading q={q} />;
  if (!t.switches) return <Card><Empty text={<>No switches are monitored yet. An administrator adds an authorised management network and an SNMPv3 credential profile under
    <b> Settings</b>, then onboards switches (one by one, CSV import, or discovery inside the authorised network).</>} /></Card>;
  return <div className="space-y-4">
    <div className="kpi-grid">
      <Kpi label="Switches" value={fmtNum(t.switches)} sub={`${t.monitored} monitored${t.paused ? `, ${t.paused} paused` : ""}`} onClick={() => go({ tab: "inventory", state: null })} />
      <Kpi label="Online" value={fmtNum(t.online)} tone="ok" onClick={() => go({ tab: "inventory", state: "up" })} />
      <Kpi label="Offline" value={fmtNum(t.offline + t.auth_failed)} sub={t.auth_failed ? `${t.auth_failed} credential failures` : undefined}
        tone={t.offline + t.auth_failed ? "bad" : "ok"} onClick={() => go({ tab: "inventory", state: "down" })} />
      <Kpi label="With critical / high alerts" value={fmtNum(t.critical_alerts)} tone={t.critical_alerts ? "bad" : "ok"} onClick={() => go({ tab: "inventory", sort: "alerts" })} />
      <Kpi label="CPU avg / max" value={t.cpu_avg == null ? "—" : `${t.cpu_avg}% / ${t.cpu_max}%`} sub={`${t.cpu_over_80} over 80%`} tone={statusTone(t.cpu_max, 80, 90)}
        onClick={() => go({ tab: "inventory", sort: "cpu" })} />
      <Kpi label="Memory avg" value={fmtPctOrDash(t.mem_avg)} sub={`${t.mem_over_80} over 80%`} tone={statusTone(t.mem_avg, 80, 90)} onClick={() => go({ tab: "inventory", sort: "mem" })} />
      <Kpi label="Interfaces over 80%" value={fmtNum(t.interfaces_over_80)} tone={t.interfaces_over_80 ? "warn" : "ok"} onClick={() => go({ tab: "interfaces", sort: "util" })} />
      <Kpi label="Interfaces with errors" value={fmtNum(t.interfaces_with_errors)} sub="last poll" tone={t.interfaces_with_errors ? "warn" : "ok"} onClick={() => go({ tab: "interfaces", view: "errors" })} />
      <Kpi label="Flapping interfaces" value={fmtNum(t.interfaces_flapping)} sub={`in ${f.range}`} tone={t.interfaces_flapping ? "warn" : "ok"}
        onClick={() => go({ tab: "events", view: "flaps" })} />
      <Kpi label="PoE max budget use" value={fmtPctOrDash(t.poe_max_pct, 0)} tone={statusTone(t.poe_max_pct, 75, 90)} onClick={() => document.getElementById("sw-poe")?.scrollIntoView()} />
      <Kpi label="Environment alarms" value={fmtNum(t.env_alarms)} tone={t.env_alarms ? "bad" : "ok"} onClick={() => document.getElementById("sw-env")?.scrollIntoView()} />
      <Kpi label="STP / LACP / stack issues" value={fmtNum(t.stp_lacp_issues)} tone={t.stp_lacp_issues ? "warn" : "ok"} onClick={() => document.getElementById("sw-stp")?.scrollIntoView()} />
      <Kpi label="Stale metrics" value={fmtNum(t.stale)} tone={t.stale ? "warn" : "ok"} onClick={() => go({ tab: "inventory", sort: "last_poll" })} />
      <Kpi label="Polling success" value={fmtPctOrDash(t.polling_success_pct)} sub={`${fmtNum(t.polls)} polls in ${f.range}`} tone={statusTone(t.polling_success_pct == null ? null : 100 - t.polling_success_pct, 2, 10)} />
    </div>
    <div className="grid gap-4 xl:grid-cols-2">
      <Card title="Highest interface utilisation (last poll)" bodyClass="p-0">
        <IfTable rows={d.top_utilization} empty={t.stale ? "No fresh utilisation samples: some switches have stale metrics (see Stale metrics)." : "No interface with a known speed is carrying traffic."} />
      </Card>
      <Card title="Interfaces with errors (last poll)" bodyClass="p-0">
        <IfTable rows={d.interface_errors} empty="No CRC, input or output errors in the last poll." errors />
      </Card>
      <Card title={`Sites (${d.sites.length})`} bodyClass="p-0">
        <TableWrap maxH="max-h-80"><table className="tbl"><thead><tr><th>Site</th><th className="num">Switches</th><th className="num">Offline</th><th className="num">Open alerts</th>
          <th className="num">Medium+ events ({f.range})</th></tr></thead>
          <tbody>{d.sites.map((s: any) => <tr key={s.site} {...rowProps(() => go({ tab: "inventory", site: s.site === "(no site)" ? null : s.site }))}>
            <td className="font-medium">{s.site}</td><td className="num">{s.switches}</td><td className={`num ${s.down ? "text-red-300" : ""}`}>{s.down}</td>
            <td className="num">{s.alerts}</td><td className="num">{s.events}</td></tr>)}</tbody></table></TableWrap>
      </Card>
      <Card title="PoE budget" bodyClass="p-0"><div id="sw-poe" />
        {!d.poe.length ? <Empty text="No PoE-capable switch reported a power budget." /> :
          <TableWrap maxH="max-h-80"><table className="tbl"><thead><tr><th>Switch</th><th className="num">In use</th><th className="num">Budget</th><th className="num">Use</th></tr></thead>
            <tbody>{d.poe.map((p: any) => <tr key={p.switch_id} {...rowProps(() => nav(`/switches/${p.switch_id}?tab=poe`))}><td>{p.switch}</td>
              <td className="num">{fmtWatts(p.used_w)}</td><td className="num">{fmtWatts(p.budget_w)}</td><td className="num"><Util v={p.pct} /></td></tr>)}</tbody></table></TableWrap>}
      </Card>
      <Card title="Environment alarms" bodyClass="p-0"><div id="sw-env" />
        {!d.environment.length ? <Empty text="All reported fans, power supplies and temperature sensors are normal." /> :
          <TableWrap maxH="max-h-80"><table className="tbl"><thead><tr><th>Switch</th><th>Component</th><th>Kind</th><th>State</th></tr></thead>
            <tbody>{d.environment.map((e: any, i: number) => <tr key={i} {...rowProps(() => nav(`/switches/${e.switch_id}?tab=hardware`))}><td>{e.switch}</td>
              <td>{e.component}</td><td>{e.kind}</td><td className="text-red-300">{e.state}</td></tr>)}</tbody></table></TableWrap>}
      </Card>
      <Card title="STP, LACP and stack issues" bodyClass="p-0"><div id="sw-stp" />
        {!d.stp_lacp.length ? <Empty text={`No root bridge changes, degraded port-channels or stack problems in ${f.range}.`} /> :
          <TableWrap maxH="max-h-80"><table className="tbl"><thead><tr><th>Switch</th><th>Kind</th><th>Component</th><th className="w-full">Detail</th></tr></thead>
            <tbody>{d.stp_lacp.map((e: any, i: number) => <tr key={i} {...rowProps(() => nav(`/switches/${e.switch_id}?tab=${e.kind === "stack" ? "hardware" : e.kind}`))}>
              <td>{e.switch}</td><td>{e.kind.toUpperCase()}</td><td>{e.component}</td><td className="text-xs">{e.detail}</td></tr>)}</tbody></table></TableWrap>}
      </Card>
    </div>
    <Card title={`Recent events (${d.events.length})`} bodyClass="p-0" right={<button className="btn" onClick={() => go({ tab: "events" })}>All events</button>}>
      <EventTable rows={d.events.slice(0, 25)} />
    </Card>
  </div>;
}

function IfTable({ rows, empty, errors }: { rows: any[]; empty: string; errors?: boolean }) {
  const nav = useNavigate();
  if (!rows.length) return <Empty text={empty} />;
  return <TableWrap maxH="max-h-80"><table className="tbl"><thead><tr><th>Switch</th><th>Interface</th>{errors ? <><th className="num">Errors</th><th className="num">CRC</th>
    <th className="num">Discards</th></> : <><th className="num">RX</th><th className="num">TX</th><th className="num">RX util</th><th className="num">TX util</th></>}</tr></thead>
    <tbody>{rows.map((r) => <tr key={`${r.switch_id}-${r.ifindex}`} {...rowProps(() => nav(`/switches/${r.switch_id}?tab=interfaces&if=${r.ifindex}`))}>
      <td>{r.switch}</td><td><span className="font-mono text-xs">{r.name}</span> <Trunc text={r.alias} max="max-w-[10rem]" className="text-muted text-xs" /></td>
      {errors ? <><td className="num text-amber-300">{fmtNum(r.errors)}</td><td className="num">{r.crc == null ? "—" : fmtNum(r.crc)}</td><td className="num">{r.discards == null ? "—" : fmtNum(r.discards)}</td></>
        : <><td className="num"><Bps v={r.rx_bps} /></td><td className="num"><Bps v={r.tx_bps} /></td><td className="num"><Util v={r.rx_util} /></td><td className="num"><Util v={r.tx_util} /></td></>}
    </tr>)}</tbody></table></TableWrap>;
}

export function EventTable({ rows, showSwitch = true }: { rows: any[]; showSwitch?: boolean }) {
  const nav = useNavigate();
  if (!rows.length) return <Empty text="No events in this range." />;
  return <TableWrap maxH="max-h-[32rem]"><table className="tbl"><thead><tr><th>Time</th>{showSwitch && <th>Switch</th>}<th>Severity</th><th>Event</th><th>Component</th>
    <th className="w-full">Detail</th></tr></thead>
    <tbody>{rows.map((e) => <tr key={e.id} {...(showSwitch ? rowProps(() => nav(`/switches/${e.switch_id}?tab=events`)) : {})}><td><Time v={e.at} /></td>
      {showSwitch && <td className="whitespace-nowrap">{e.switch}</td>}<td><Sev s={e.severity} /></td><td className="whitespace-nowrap">{e.kind.replace(/_/g, " ")}</td>
      <td><Trunc text={e.component} max="max-w-[14rem]" /></td><td className="text-xs">{e.detail}</td></tr>)}</tbody></table></TableWrap>;
}

function Inventory({ f }: { f: F }) {
  const nav = useNavigate();
  const [page, setPage] = useState(0);
  const sort = f.sort || "name";
  const q = useQuery({ queryKey: ["switch-inv", f.site, f.vendor, f.model, f.q, f.state, sort, page], refetchInterval: 30_000, placeholderData: (p) => p,
    queryFn: () => api<any>("/switches", { params: { ...common(f), state: f.state === "down" ? ["down", "auth_failed"] : f.state || undefined, sort, limit: 100, offset: page * 100 } }) });
  return <Card title={`Switches${q.data ? ` (${q.data.total})` : ""}`} bodyClass="p-0" right={<>
    <select aria-label="Sort" className="input py-1" value={sort} onChange={(e) => f.set({ sort: e.target.value })}>
      {[["name", "Name"], ["state", "State"], ["site", "Site"], ["cpu", "CPU"], ["mem", "Memory"], ["errors", "Interfaces with errors"], ["coverage", "Coverage (lowest)"],
        ["last_poll", "Last poll (oldest)"], ["alerts", "Open alerts"]].map(([k, l]) => <option key={k} value={k}>Sort: {l}</option>)}</select>
    <a className="btn" href={downloadUrl("/switches/export.csv")}>Export CSV</a></>}>
    <Loading q={q} />
    {q.data && (!q.data.items.length ? <Empty text="No switches match the filters." /> :
      <TableWrap><table className="tbl"><thead><tr><th>State</th><th>Name</th><th>Management IP</th><th>Vendor / model</th><th>Firmware</th><th>Serial</th><th>Site</th>
        <th>Location</th><th>SNMP</th><th className="num">Uptime</th><th>Last poll</th><th className="num">Ports up</th><th className="num">Errors</th><th className="num">CPU</th>
        <th className="num">Memory</th><th className="num">PoE</th><th className="num">Alerts</th><th className="num">Coverage</th></tr></thead>
        <tbody>{q.data.items.map((r: any) => <tr key={r.id} {...rowProps(() => nav(`/switches/${r.id}`))}>
          <td><StateDot s={r.state} monitoring={r.monitoring} /></td>
          <td className="font-medium">{r.name}{r.hostname && r.hostname !== r.name && <div className="text-2xs text-muted">{r.hostname}</div>}</td>
          <td className="font-mono text-xs">{r.address}</td>
          <td className="whitespace-nowrap">{r.vendor === "unknown" ? <span className="text-muted">not identified yet</span> : <>{r.vendor} <span className="text-muted">{r.model || r.family}</span></>}</td>
          <td className="text-xs">{r.firmware || "—"}</td><td className="text-xs font-mono">{r.serial || "—"}{r.serials.length > 1 && <span className="text-muted"> +{r.serials.length - 1}</span>}</td>
          <td>{r.site || "—"}</td><td className="text-xs">{[r.building, r.floor, r.rack].filter(Boolean).join(" / ") || "—"}{r.role && <div className="text-2xs text-muted">{r.role}</div>}</td>
          <td className="text-xs">{r.snmp_version || "—"}</td><td className="num">{fmtUptime(r.uptime_s)}</td>
          <td><Time v={r.last_success_at} /> <Fresh f={r.freshness} />{r.last_error_kind && <div className="text-2xs text-amber-300" title={r.last_error}>{r.last_error_kind}</div>}</td>
          <td className="num">{r.if_total == null ? "—" : `${r.if_up} / ${r.if_total}`}</td><td className={`num ${r.if_errors ? "text-amber-300" : ""}`}>{r.if_errors ?? "—"}</td>
          <td className="num"><Util v={r.cpu_pct} /></td><td className="num"><Util v={r.mem_pct} /></td>
          <td className="num text-xs">{r.poe_budget_w == null ? "—" : `${fmtWatts(r.poe_used_w)} / ${fmtWatts(r.poe_budget_w)}`}</td>
          <td className="num">{r.alerts_open ? <Sev s={r.alert_severity} /> : "0"}</td>
          <td className="num">{r.coverage_pct == null ? "—" : `${r.coverage_pct.toFixed(0)}%`}</td>
        </tr>)}</tbody></table></TableWrap>)}
    {q.data && q.data.total > 100 && <div className="flex gap-2 p-2"><button className="btn" disabled={!page} onClick={() => setPage(page - 1)}>Previous</button>
      <button className="btn" disabled={(page + 1) * 100 >= q.data.total} onClick={() => setPage(page + 1)}>Next</button></div>}
  </Card>;
}

function AllInterfaces({ f }: { f: F }) {
  const nav = useNavigate();
  const [kind, setKind] = useState("");
  const [oper, setOper] = useState("");
  const [vlan, setVlan] = useState("");
  const [page, setPage] = useState(0);
  const sort = f.sort && ["util", "errors", "discards", "name", "traffic"].includes(f.sort) ? f.sort : f.view === "errors" ? "errors" : "util";
  const q = useQuery({ queryKey: ["switch-ifs", f.site, f.vendor, f.q, kind, oper, vlan, sort, f.view, page], placeholderData: (p) => p, refetchInterval: 30_000,
    queryFn: () => api<any>("/switches/interfaces", { params: { site: f.site || undefined, vendor: f.vendor || undefined, q: f.q || undefined, kind: kind || undefined,
      oper: oper || undefined, vlan: vlan || undefined, sort, errors_only: f.view === "errors" || undefined, limit: 100, offset: page * 100 } }) });
  return <Card title={`Interfaces${q.data ? ` (${q.data.total})` : ""}`} bodyClass="p-0" right={<>
    <select aria-label="Kind" className="input py-1" value={kind} onChange={(e) => setKind(e.target.value)}><option value="">All kinds</option>
      {["physical", "lag", "svi", "virtual"].map((k) => <option key={k}>{k}</option>)}</select>
    <select aria-label="Link" className="input py-1" value={oper} onChange={(e) => setOper(e.target.value)}><option value="">Any link state</option><option value="up">Up</option><option value="down">Down</option></select>
    <input aria-label="VLAN" className="input py-1 w-24" placeholder="VLAN" inputMode="numeric" value={vlan} onChange={(e) => setVlan(e.target.value.replace(/\D/g, "").slice(0, 4))} />
    <select aria-label="Sort" className="input py-1" value={sort} onChange={(e) => f.set({ sort: e.target.value })}>
      {[["util", "Utilisation"], ["traffic", "Traffic"], ["errors", "Errors"], ["discards", "Discards"], ["name", "Name"]].map(([k, l]) => <option key={k} value={k}>Sort: {l}</option>)}</select>
    <label className="text-xs flex items-center gap-1"><input type="checkbox" checked={f.view === "errors"} onChange={(e) => f.set({ view: e.target.checked ? "errors" : null })} /> errors only</label></>}>
    <Loading q={q} />
    {q.data && (!q.data.items.length ? <Empty text="No interfaces match." /> :
      <TableWrap><table className="tbl"><thead><tr><th>Switch</th><th>Interface</th><th>Description</th><th>Kind</th><th>Link</th><th className="num">Speed</th><th>Duplex</th>
        <th>VLAN</th><th className="num">RX</th><th className="num">TX</th><th className="num">RX util</th><th className="num">TX util</th><th className="num">Errors</th>
        <th className="num">CRC</th><th className="num">Discards</th><th>Sample</th></tr></thead>
        <tbody>{q.data.items.map((r: any) => <tr key={`${r.switch_id}-${r.ifindex}`} {...rowProps(() => nav(`/switches/${r.switch_id}?tab=interfaces&if=${r.ifindex}`))}>
          <td className="whitespace-nowrap">{r.switch}</td><td className="font-mono text-xs whitespace-nowrap">{r.name}</td><td><Trunc text={r.alias} max="max-w-[12rem]" /></td>
          <td className="text-xs">{r.kind}</td><td><Oper s={r.oper} /></td><td className="num text-xs"><Bps v={r.speed_bps} /></td><td className="text-xs">{r.duplex || "—"}</td>
          <td className="text-xs">{r.mode === "trunk" ? `trunk (native ${r.native_vlan ?? "?"})` : r.access_vlan ?? "—"}</td>
          <td className="num"><Bps v={r.rx_bps} /></td><td className="num"><Bps v={r.tx_bps} /></td><td className="num"><Util v={r.rx_util} /></td><td className="num"><Util v={r.tx_util} /></td>
          <td className="num">{r.in_errors == null && r.out_errors == null ? "—" : fmtNum((r.in_errors || 0) + (r.out_errors || 0))}</td>
          <td className="num">{r.crc == null ? "—" : fmtNum(r.crc)}</td><td className="num">{r.discards == null ? "—" : fmtNum(r.discards)}</td><td><Flags f={r.flags} /></td>
        </tr>)}</tbody></table></TableWrap>)}
    {q.data && q.data.total > 100 && <div className="flex gap-2 p-2"><button className="btn" disabled={!page} onClick={() => setPage(page - 1)}>Previous</button>
      <button className="btn" disabled={(page + 1) * 100 >= q.data.total} onClick={() => setPage(page + 1)}>Next</button></div>}
  </Card>;
}

const EVENT_VIEWS: Record<string, string[]> = {
  flaps: ["port_up", "port_down", "port_flap"], reachability: ["unreachable", "reachable", "auth_failure", "poll_error"],
  stp: ["stp_root_change", "stp_topology_change", "stp_port_state"], lacp: ["lacp_member_down", "lacp_member_up", "lacp_member_removed"],
  hardware: ["power_supply_failure", "power_supply_recovered", "fan_failure", "fan_recovered", "temperature_alarm", "stack_member_failure", "stack_member_added",
    "stack_member_recovered", "stack_role_change", "stack_ring_broken", "poe_fault"],
  mac: ["mac_move", "mac_learning_burst"], topology: ["neighbor_added", "neighbor_removed", "neighbor_changed"], changes: ["restart", "firmware_change", "vendor_change", "vlan_added", "vlan_removed", "vlan_renamed", "speed_change", "duplex_change"],
};

function Events({ f }: { f: F }) {
  const [sev, setSev] = useState("");
  const [page, setPage] = useState(0);
  const q = useQuery({ queryKey: ["switch-events", f.range, f.view, sev, f.q, page], placeholderData: (p) => p, refetchInterval: 30_000,
    queryFn: () => api<any>("/switches/events", { params: { range: f.range, kind: f.view ? EVENT_VIEWS[f.view] : undefined, severity: sev || undefined, q: f.q || undefined,
      limit: 200, offset: page * 200 } }) });
  return <Card title={`Events${q.data ? ` (${q.data.total})` : ""}`} bodyClass="p-0" right={<>
    <select aria-label="Event type" className="input py-1" value={f.view} onChange={(e) => f.set({ view: e.target.value || null })}><option value="">All event types</option>
      {Object.keys(EVENT_VIEWS).map((k) => <option key={k} value={k}>{k}</option>)}</select>
    <select aria-label="Severity" className="input py-1" value={sev} onChange={(e) => setSev(e.target.value)}><option value="">Any severity</option>
      {["informational", "low", "medium", "high", "critical"].map((k) => <option key={k}>{k}</option>)}</select></>}>
    <Loading q={q} />
    {q.data && <EventTable rows={q.data.items} />}
    {q.data && q.data.total > 200 && <div className="flex gap-2 p-2"><button className="btn" disabled={!page} onClick={() => setPage(page - 1)}>Previous</button>
      <button className="btn" disabled={(page + 1) * 200 >= q.data.total} onClick={() => setPage(page + 1)}>Next</button></div>}
  </Card>;
}
