/** Who and what is behind an IP address — the shared identity index (/api/identities), used by both products:
 *  Sentinel Grid investigations get network context (device, switch port, VLAN, AP, user), Sentinel NMS host views get
 *  identity. Personal data (MAC, user, host name) is withheld by the API for accounts without access to it. */
import { Fragment, ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { Card, Loading, Time } from "./ui";

const CONF: Record<string, string> = {
  confirmed: "text-emerald-300", high: "text-sky-300", probable: "text-slate-300",
};
const SOURCE: Record<string, string> = {
  wireless: "Wireless controller", switch_mac: "Switch MAC table", sflow: "sFlow", fortigate: "FortiGate device detection", dhcp: "DHCP",
  vpn: "VPN login", vpn_remote: "VPN (remote address)", windows: "Windows logon", tacacs: "TACACS+",
};

export function sourceLabel(s: string) { return SOURCE[s] || s; }

export function NetworkContext({ ip, title = "Network context", compact = false }: { ip: string; title?: string; compact?: boolean }) {
  const q = useQuery<any>({ queryKey: ["identity", ip], queryFn: () => api(`/identities/ip/${encodeURIComponent(ip)}`), staleTime: 60_000 });
  const c = q.data?.current;
  const tl = q.data?.timeline;
  const rows: [string, ReactNode][] = c ? [
    ["Device", c.device_type ? <span className="inline-flex flex-wrap items-center gap-1.5">{c.device_type}
      {c.confidence && <span className={`pill ${CONF[c.confidence] || "bg-slate-800 text-muted"}`} title={(c.evidence || []).join("; ")}>{c.confidence}</span>}</span> : "Unclassified"],
    ["Manufacturer", c.randomized ? "Private (randomised) MAC" : c.vendor || "—"],
    ["MAC", c.mac ? <span className="mono">{c.mac}</span> : "—"],
    ["Host name / OS", [c.hostname, c.os].filter(Boolean).join(" · ") || "—"],
    ["User", c.user ? <>{c.user} <span className="text-2xs text-subtle">{sourceLabel(c.user_source)}</span></> : "—"],
    ["Switch port", c.switch ? `${c.switch} · ${c.port}` : "—"],
    ["VLAN", c.vlan ?? "—"],
    ["Wireless", c.ssid ? `${c.ssid}${c.ap ? ` · ${c.ap}` : ""}` : "—"],
    ["Site", c.site || "—"],
    ["Evidence from", (c.sources || []).map(sourceLabel).join(", ") || sourceLabel(c.mac_source) || "—"],
  ] : [];
  return (
    <Card title={title}>
      <Loading q={q} rows={4} />
      {q.data && !c && <p className="text-sm text-muted">No identity evidence for {ip} yet: it has not appeared in wireless, switch, sFlow, FortiGate, DHCP, VPN or
        logon data in the last 30 days.</p>}
      {c && <dl className="grid grid-cols-[8.5rem_1fr] gap-x-3 gap-y-1.5 text-[13px]">
        {rows.map(([k, v]) => <Fragment key={k}><dt className="text-subtle">{k}</dt><dd className="min-w-0 cell-wrap">{v}</dd></Fragment>)}
      </dl>}
      {!compact && tl && (tl.macs.length > 1 || tl.users.length > 0) && <div className="mt-3 pt-3 border-t border-line">
        <div className="eyebrow mb-1.5">Who held this address (7 days)</div>
        <ul className="space-y-1 text-xs">
          {tl.macs.slice(0, 6).map((m: any, i: number) => <li key={`m${i}`} className="flex flex-wrap gap-x-2">
            <span className="mono">{m.mac || "device"}</span><span className="text-muted">{m.device_type || m.vendor || ""}</span>
            <span className="text-subtle">{sourceLabel(m.source)}</span><span className="ml-auto text-subtle"><Time v={m.first_seen} /> → <Time v={m.last_seen} /></span></li>)}
          {tl.users.slice(0, 6).map((u: any, i: number) => <li key={`u${i}`} className="flex flex-wrap gap-x-2">
            <span className="font-medium">{u.user}</span><span className="text-subtle">{sourceLabel(u.source)}</span>
            <span className="ml-auto text-subtle"><Time v={u.first_seen} /> → <Time v={u.last_seen} /></span></li>)}
        </ul>
      </div>}
    </Card>
  );
}
