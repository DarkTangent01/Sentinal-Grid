/** Layer-3 / WAN topology: OSPF and BGP adjacencies, IPsec tunnels and ISP circuits (GET /api/switches/topology/l3).
 *  Every link says which source reported it and how its far end was matched to the inventory. */
import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { useTheme } from "../../lib/theme";
import { escHtml } from "../../lib/format";
import { Chart, CHART_THEME, PALETTES, SERIES_ROLE, statusColor } from "../../components/Chart";
import { Card, Empty, Kpi, Loading, TableWrap } from "../../components/ui";

const TYPES = ["switch", "router", "firewall", "wlc", "as", "ospf_router", "vpn_peer", "isp", "site"];
const LABEL: Record<string, string> = { switch: "Switch", router: "Router", firewall: "Firewall", wlc: "Controller", as: "BGP AS", ospf_router: "OSPF router",
  vpn_peer: "VPN peer", isp: "ISP", site: "Site" };
const SYMBOL: Record<string, string> = { firewall: "diamond", as: "rect", isp: "rect", vpn_peer: "triangle", site: "roundRect" };
const PROTOS = ["ospf", "bgp", "ipsec", "isp"];

export function L3Topology({ site }: { site: string }) {
  const { theme } = useTheme();
  const [protos, setProtos] = useState<string[]>(PROTOS);
  const [sel, setSel] = useState<any>(null);
  const q = useQuery({ queryKey: ["switch-topo-l3", site], refetchInterval: 60_000, placeholderData: (p) => p,
    queryFn: () => api<any>("/switches/topology/l3", { params: { site: site || undefined } }) });
  const d = q.data;
  const edges = useMemo(() => (d?.edges || []).filter((e: any) => protos.includes(e.protocol)), [d, protos]);
  const nodes = useMemo(() => {
    const used = new Set(edges.flatMap((e: any) => [e.a, e.b]));
    return (d?.nodes || []).filter((n: any) => used.has(n.id));
  }, [d, edges]);
  const label = (id: string) => d?.nodes.find((n: any) => n.id === id)?.label || id;
  const option = useMemo(() => {
    if (!d) return null;
    const ct = CHART_THEME[theme];
    const role = SERIES_ROLE[theme];
    return {
      tooltip: { trigger: "item", confine: true, formatter: (p: any) => {
        if (p.dataType === "node") {
          const n = p.data.raw;
          return `<b>${escHtml(n.label)}</b><br/>${escHtml(LABEL[n.type] || n.type)}${n.managed ? "" : " · not in inventory"}${n.address ? `<br/>${escHtml(n.address)}` : ""}`;
        }
        const e = p.data.raw;
        return `<b>${escHtml(e.protocol.toUpperCase())}</b> ${escHtml(e.detail || "")}: ${escHtml(e.state)}<br/>source: ${escHtml(e.source)}<br/>far end: ${escHtml(e.matched_by)}`;
      } },
      legend: { top: 0, data: TYPES.map((t) => LABEL[t]), textStyle: { color: ct.text } },
      series: [{
        type: "graph", layout: "force", roam: true, draggable: true, top: 30, force: { repulsion: 360, edgeLength: [90, 200], gravity: 0.06 },
        categories: TYPES.map((t, i) => ({ name: LABEL[t], itemStyle: { color: PALETTES[theme][i % 8] } })),
        label: { show: true, position: "bottom", color: ct.text, fontSize: 11 },
        data: nodes.map((n: any) => ({ id: n.id, name: n.label, category: Math.max(0, TYPES.indexOf(n.type)), symbol: SYMBOL[n.type] || "circle", raw: n,
          symbolSize: n.managed ? 30 : 20, itemStyle: n.managed ? { color: n.status === "up" ? statusColor(theme, "up") : n.status === "down" ? role.alert : undefined,
            borderColor: ct.strong, borderWidth: 1.5 } : undefined })),
        links: edges.map((e: any) => ({ source: e.a, target: e.b, raw: e, label: { show: true, formatter: e.protocol, color: ct.text, fontSize: 10 },
          lineStyle: { color: statusColor(theme, e.state === "up" ? "up" : e.state === "down" ? "down" : "unknown"), width: e.layer === "wan" ? 3 : 2,
            type: e.matched_by === "configured" ? "dotted" : "solid", curveness: 0.08 } })),
        emphasis: { focus: "adjacency", lineStyle: { width: 5 } },
      }],
    };
  }, [d, nodes, edges, theme]);
  if (!d) return <Loading q={q} />;
  const sum = d.summary || {};
  return <div className="space-y-4">
    <div className="flex flex-wrap items-center gap-3">
      <p className="text-xs text-muted flex-1 min-w-[16rem]">Routing and WAN relationships from data Sentinel already collects: OSPF and BGP neighbours of polled devices (SNMP),
        BGP peers of FortiGates (API), IPsec tunnels (FortiGate VPN logs, last 24 h) and ISP circuits (inventory, dotted; red while an outage is open). A far end that is not
        a monitored device or registered firewall appears as an external node.</p>
      {PROTOS.map((p) => <label key={p} className="text-xs flex items-center gap-1"><input type="checkbox" checked={protos.includes(p)}
        onChange={() => setProtos(protos.includes(p) ? protos.filter((x) => x !== p) : [...protos, p])} />{p.toUpperCase()}</label>)}
    </div>
    <div className="kpi-grid">
      {PROTOS.map((p) => <Kpi key={p} label={p.toUpperCase()} value={sum[p]?.total ?? 0} sub={sum[p]?.down ? `${sum[p].down} down` : "all up"}
        tone={sum[p]?.down ? "bad" : sum[p]?.total ? "ok" : undefined} />)}
      <Kpi label="External nodes" value={d.external} />
    </div>
    <Card bodyClass="p-0">
      {!edges.length ? <Empty text="No routing adjacencies, tunnels or circuits to show. OSPF / BGP come from polled devices' routing tables, tunnels from FortiGate VPN logs, circuits from ISP / WAN." />
        : option && <Chart option={option} height={560} ariaLabel="Layer 3 and WAN topology" onClick={(p) => setSel(p.data?.raw)} />}
    </Card>
    {sel && <Card title={sel.protocol ? `${sel.protocol.toUpperCase()} ${sel.detail || ""}` : sel.label} right={<button className="btn py-0.5" onClick={() => setSel(null)}>Close</button>}>
      <pre className="text-xs font-mono whitespace-pre-wrap">{JSON.stringify(sel.protocol ? { ...sel, a: label(sel.a), b: label(sel.b) } : sel, null, 2)}</pre></Card>}
    {!!edges.length && <Card title="Links" bodyClass="p-0"><TableWrap maxH="max-h-96"><table className="tbl"><thead><tr><th>Protocol</th><th>From</th><th>To</th><th>Detail</th>
      <th>State</th><th>Source</th><th>Far end matched by</th></tr></thead>
      <tbody>{edges.map((e: any, i: number) => <tr key={i}><td>{e.protocol.toUpperCase()}</td><td>{label(e.a)}</td><td>{label(e.b)}</td><td className="text-xs font-mono">{e.detail}</td>
        <td className={e.state === "up" ? "text-emerald-300" : e.state === "down" ? "text-red-300" : "text-muted"}>{e.state}{e.peer_state && e.peer_state !== e.state ? ` (${e.peer_state})` : ""}</td>
        <td className="text-xs">{e.source}</td><td className="text-xs">{e.matched_by}</td></tr>)}</tbody></table></TableWrap></Card>}
  </div>;
}
