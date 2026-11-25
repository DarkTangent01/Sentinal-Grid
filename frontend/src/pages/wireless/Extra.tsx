/** Wireless → Rogue APs and Floor Experience (SLA). */
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { Card, Empty, Kpi, Loading, TableWrap, Time } from "../../components/ui";
import { dash, dbm } from "./common";

export function RoguesTab() {
  const [flagged, setFlagged] = useState(true);
  const q = useQuery({ queryKey: ["wl", "rogues", flagged], queryFn: () => api<any>("/wireless/rogues", { params: { flagged } }), refetchInterval: 120_000, placeholderData: (p) => p });
  const d = q.data;
  return <div className="space-y-4 min-w-0">
    <div className="flex flex-wrap items-center gap-2"><p className="text-xs text-muted flex-1 min-w-[16rem]">{d?.note} Flagged: classified malicious by the controller, broadcasting one of
      your SSIDs, or seen on the wired network. Rogues the controller marks known / acknowledged / friendly are not flagged. Nothing here contains or classifies a rogue.</p>
      <label className="text-xs flex items-center gap-1"><input type="checkbox" checked={flagged} onChange={(e) => setFlagged(e.target.checked)} /> flagged only</label></div>
    <Loading q={q} />
    {d && <>
      <div className="kpi-grid"><Kpi label={flagged ? "Flagged rogues" : "Rogues heard"} value={d.items.length} tone={d.flagged ? "bad" : "ok"} />
        <Kpi label="Spoofing our SSIDs" value={d.items.filter((x: any) => x.spoofs_ssid).length} tone={d.items.some((x: any) => x.spoofs_ssid) ? "bad" : "ok"} />
        <Kpi label="On the wired network" value={d.items.filter((x: any) => x.on_network).length} tone={d.items.some((x: any) => x.on_network) ? "bad" : "ok"} /></div>
      <Card bodyClass="p-0">{!d.items.length ? <Empty text={flagged ? "No flagged rogue AP." : "No rogue AP reported by the controllers."} /> :
        <TableWrap maxH="max-h-[36rem]"><table className="tbl"><thead><tr><th>BSSID</th><th>SSID</th><th>Why flagged</th><th className="num">Ch</th><th className="num">Strongest</th>
          <th>Heard by</th><th className="num">Clients</th><th>Controller class / state</th><th>Controller</th><th>First seen</th></tr></thead>
          <tbody>{d.items.map((r: any) => <tr key={r.id}><td className="font-mono text-xs">{r.mac}</td><td>{r.ssid || <span className="text-muted">hidden</span>}</td>
            <td className="text-xs text-red-300">{r.reasons.join(", ") || "—"}</td><td className="num">{dash(r.channel)}</td><td className="num">{dbm(r.rssi_dbm)}</td>
            <td className="text-xs">{r.detecting_ap || "—"}{r.detecting_aps > 1 && ` +${r.detecting_aps - 1}`}</td><td className="num">{dash(r.clients)}</td>
            <td className="text-xs">{r.class_type || "—"} / {r.state || "—"}</td><td className="text-xs">{r.wlc}</td><td className="text-xs whitespace-nowrap"><Time v={r.first_seen} /></td></tr>)}</tbody></table></TableWrap>}</Card>
    </>}
  </div>;
}

export function FloorsTab() {
  const [target, setTarget] = useState(80);
  const q = useQuery({ queryKey: ["wl", "floors", target], queryFn: () => api<any>("/wireless/floors", { params: { target_pct: target } }), refetchInterval: 120_000, placeholderData: (p) => p });
  const d = q.data;
  return <div className="space-y-4 min-w-0">
    <div className="flex flex-wrap items-center gap-2"><p className="text-xs text-muted flex-1 min-w-[16rem]">{d?.note}</p>
      <label className="text-xs text-muted flex items-center gap-1">Target<select className="input py-1" value={target} onChange={(e) => setTarget(Number(e.target.value))}>
        {[60, 70, 80, 90, 95].map((x) => <option key={x} value={x}>{x}% good</option>)}</select></label></div>
    <Loading q={q} />
    {d && <>
      <div className="kpi-grid"><Kpi label="Floors" value={d.items.length} />
        <Kpi label="Breaching the SLA" value={d.items.filter((x: any) => x.sla === "breach").length} tone={d.items.some((x: any) => x.sla === "breach") ? "bad" : "ok"} /></div>
      <Card bodyClass="p-0">{!d.items.length ? <Empty text="No clients on APs with a site / building / floor." /> :
        <TableWrap><table className="tbl"><thead><tr><th>Site</th><th>Building</th><th>Floor</th><th className="num">APs</th><th className="num">Clients</th>
          <th className="num">Good experience</th><th className="num">Avg score</th><th>SLA</th><th>Signal OK per day (7 d)</th></tr></thead>
          <tbody>{d.items.map((f: any, i: number) => <tr key={i}><td>{f.site || "—"}</td><td>{f.building || "—"}</td><td>{f.floor || "—"}</td><td className="num">{f.aps}</td>
            <td className="num">{f.clients}</td><td className="num">{f.good_pct == null ? "—" : `${f.good_pct}%`}</td><td className="num">{dash(f.avg_score, "", 1)}</td>
            <td className={f.sla === "breach" ? "text-red-300 font-semibold" : f.sla === "met" ? "text-emerald-300" : "text-muted"}>{f.sla || "no score"}</td>
            <td className="text-2xs whitespace-nowrap">{f.trend.length ? f.trend.map((t: any) => `${t.day.slice(5)} ${t.signal_ok_pct ?? "—"}%`).join(" · ") : "—"}</td></tr>)}</tbody></table></TableWrap>}</Card>
    </>}
  </div>;
}
