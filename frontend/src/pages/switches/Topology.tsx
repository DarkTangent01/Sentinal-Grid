import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { useTheme } from "../../lib/theme";
import { escHtml } from "../../lib/format";
import { CHART_THEME, Chart, PALETTES, SERIES_ROLE } from "../../components/Chart";
import { Card, Empty, Kpi, Loading, TableWrap, Time, rowProps } from "../../components/ui";
import { Util, fmtBps } from "./common";
import { groupLinks, worstStatus } from "./fmt";

const TYPES = ["switch", "firewall", "router", "ap", "phone", "host", "device"];
const TYPE_LABEL: Record<string, string> = { switch: "Switch", firewall: "Firewall", router: "Router", ap: "Access point", phone: "Phone", host: "Host", device: "Other device" };
const SYMBOL: Record<string, string> = { switch: "roundRect", firewall: "diamond", router: "circle", ap: "triangle", phone: "pin", host: "circle", device: "circle" };
const STATUS_TXT: Record<string, string> = { up: "text-emerald-300", degraded: "text-amber-300", down: "text-red-300", lost: "text-red-300", unknown: "text-muted" };

export function Topology({ site }: { site: string }) {
  const nav = useNavigate();
  const { theme } = useTheme();
  const [endpoints, setEndpoints] = useState(false);
  const [lost, setLost] = useState(24);
  const [sel, setSel] = useState<any>(null);
  const [src, setSrc] = useState("");
  const [dst, setDst] = useState("");
  const q = useQuery({ queryKey: ["switch-topo", site, endpoints, lost], refetchInterval: 60_000, placeholderData: (p) => p,
    queryFn: () => api<any>("/switches/topology", { params: { site: site || undefined, endpoints, lost_hours: lost } }) });
  const pq = useQuery({ queryKey: ["switch-path", site, src, dst], enabled: !!src && !!dst && src !== dst,
    queryFn: () => api<any>("/switches/topology/path", { params: { src, dst, site: site || undefined } }) });
  const d = q.data;
  const groups = useMemo(() => groupLinks(d?.links || []), [d]);
  const onPath = useMemo(() => new Set<string>((pq.data?.connected ? pq.data.hops : pq.data?.via_any_link?.hops || []).map((h: any) => h.link)), [pq.data]);
  const option = useMemo(() => {
    if (!d) return null;
    const ct = CHART_THEME[theme];
    const role = SERIES_ROLE[theme];
    const edgeColor: Record<string, string> = { up: "#1baf7a", degraded: role.warn, down: role.alert, lost: role.alert, unknown: role.muted };
    const nodeColor = (n: any) => !n.managed ? PALETTES[theme][TYPES.indexOf(n.type) % 8] : n.status === "up" ? "#1baf7a"
      : ["down", "auth_failed"].includes(n.status) ? role.alert : role.muted;
    return {
      tooltip: { trigger: "item", confine: true, formatter: (p: any) => {
        if (p.dataType === "node") {
          const n = p.data.raw;
          return `<b>${escHtml(n.label)}</b><br/>${escHtml(TYPE_LABEL[n.type] || n.type)}${n.managed ? ` · ${escHtml(n.status || "")}` : " · not monitored"}` +
            `${n.address ? `<br/>${escHtml(n.address)}` : ""}${n.model ? `<br/>${escHtml(n.vendor)} ${escHtml(n.model)}` : ""}${n.site ? `<br/>site ${escHtml(n.site)}` : ""}<br/>${n.degree} link(s)`;
        }
        const g = p.data.raw;
        return g.links.map((l: any) => `${escHtml(l.a.port)} ↔ ${escHtml(l.b.port)}: <b>${escHtml(l.status)}</b>${l.speed_bps ? ` · ${escHtml(fmtBps(l.speed_bps))}` : ""}` +
          `${l.util != null ? ` · ${l.util}%` : ""}`).join("<br/>");
      } },
      legend: { top: 0, data: TYPES.map((t) => TYPE_LABEL[t]), textStyle: { color: ct.text } },
      series: [{
        type: "graph", layout: "force", roam: true, draggable: true, top: 30, force: { repulsion: 320, edgeLength: [80, 180], gravity: 0.06 },
        categories: TYPES.map((t, i) => ({ name: TYPE_LABEL[t], itemStyle: { color: PALETTES[theme][i % 8] } })),
        label: { show: true, position: "bottom", color: ct.text, fontSize: 11 },
        data: d.nodes.map((n: any) => ({ id: n.id, name: n.label, category: TYPES.indexOf(n.type), symbol: SYMBOL[n.type] || "circle", raw: n,
          symbolSize: (n.managed ? 30 : 18) + Math.min(16, (n.degree || 0) * 2),
          itemStyle: { color: nodeColor(n), borderColor: [src, dst].includes(n.id) ? "#3987e5" : n.managed ? ct.strong : "transparent", borderWidth: [src, dst].includes(n.id) ? 4 : n.managed ? 1.5 : 0 } })),
        links: groups.map((g: any) => {
          const hot = g.links.some((l: any) => onPath.has(l.id));
          return { source: g.a, target: g.b, raw: g, label: { show: g.links.length > 1, formatter: `${g.links.length}×`, color: ct.text },
            lineStyle: { color: hot ? "#3987e5" : edgeColor[g.status], width: hot ? 5 : 1.5 + Math.min(4, g.links.length), type: g.status === "lost" ? "dashed" : "solid",
              opacity: g.status === "lost" ? 0.8 : 0.9, curveness: 0.05 } };
        }),
        emphasis: { focus: "adjacency", lineStyle: { width: 5 } },
      }],
    };
  }, [d, groups, theme, onPath, src, dst]);
  const onClick = (p: any) => {
    if (p.dataType === "node") {
      if (p.data.raw.switch_id) nav(`/switches/${p.data.raw.switch_id}?tab=neighbors`);
      else setSel({ node: p.data.raw });
    } else if (p.dataType === "edge") setSel({ group: p.data.raw });
  };
  if (!d) return <Loading q={q} />;
  const t = d.totals;
  const label = (id: string) => d.nodes.find((n: any) => n.id === id)?.label || id;
  return <div className="space-y-4">
    <div className="flex flex-wrap items-center gap-2">
      <p className="text-xs text-muted flex-1 min-w-[16rem]">Built from the LLDP (and Cisco CDP) neighbor tables of the monitored switches. A cable seen from both ends is one link.
        Link colours: green up, amber degraded (≥ 80 % utilisation or errors), red down, red dashed lost (neighbor disappeared in the last {lost} h), grey unknown.
        Click a switch to open it, a link or another device for details.</p>
      <label className="text-xs flex items-center gap-1"><input type="checkbox" checked={endpoints} onChange={(e) => setEndpoints(e.target.checked)} /> show APs, phones and hosts</label>
      <select aria-label="Lost link window" className="input py-1" value={lost} onChange={(e) => setLost(Number(e.target.value))}>
        {[1, 6, 24, 72, 168].map((h) => <option key={h} value={h}>Lost links: last {h < 48 ? `${h} h` : `${h / 24} days`}</option>)}</select>
    </div>
    <div className="kpi-grid">
      <Kpi label="Devices" value={t.nodes} sub={`${t.external} not monitored${t.hidden_endpoints ? `, ${t.hidden_endpoints} endpoints hidden` : ""}`} />
      <Kpi label="Links" value={t.links} />
      <Kpi label="Up" value={t.up} tone="ok" />
      <Kpi label="Degraded" value={t.degraded} tone={t.degraded ? "warn" : "ok"} />
      <Kpi label="Down" value={t.down} tone={t.down ? "bad" : "ok"} />
      <Kpi label="Lost" value={t.lost} tone={t.lost ? "bad" : "ok"} sub={`last ${lost} h`} />
      <Kpi label="Switches without neighbors" value={t.switches_without_neighbors} tone={t.switches_without_neighbors ? "warn" : "ok"}
        onClick={() => document.getElementById("sw-nolldp")?.scrollIntoView()} />
    </div>
    <Card title="Connectivity check" right={<span className="text-2xs text-muted">shortest path over links that are up or degraded</span>}>
      <div className="flex flex-wrap items-center gap-2">
        <select aria-label="From" className="input py-1 max-w-[16rem]" value={src} onChange={(e) => setSrc(e.target.value)}><option value="">From…</option>
          {d.nodes.map((n: any) => <option key={n.id} value={n.id}>{n.label}</option>)}</select>
        <span className="text-muted">→</span>
        <select aria-label="To" className="input py-1 max-w-[16rem]" value={dst} onChange={(e) => setDst(e.target.value)}><option value="">To…</option>
          {d.nodes.map((n: any) => <option key={n.id} value={n.id}>{n.label}</option>)}</select>
        {(src || dst) && <button className="btn" onClick={() => { setSrc(""); setDst(""); }}>Clear</button>}
        {pq.data && (pq.data.connected
          ? <span className="text-sm text-emerald-300">Connected: {[src, ...pq.data.hops.map((h: any) => h.to)].map(label).join(" → ")} ({pq.data.hops.length} hop{pq.data.hops.length === 1 ? "" : "s"}
            {pq.data.hops.some((h: any) => h.status === "degraded") ? ", via a degraded link" : ""})</span>
          : <span className="text-sm text-red-300">No working path. {pq.data.via_any_link?.connected
            ? <>The topology path is {[src, ...pq.data.via_any_link.hops.map((h: any) => h.to)].map(label).join(" → ")}, broken at{" "}
              {pq.data.via_any_link.hops.filter((h: any) => !["up", "degraded"].includes(h.status)).map((h: any) => `${label(h.from)} ↔ ${label(h.to)} (${h.status})`).join(", ")}.</>
            : "The two devices are not linked in the discovered topology (LLDP may be off on a link in between)."}</span>)}
        {pq.error && <span className="text-sm text-red-400">{(pq.error as Error).message}</span>}
      </div>
    </Card>
    <Card title="Topology" bodyClass="p-0">
      {!d.nodes.length ? <Empty text="No switches in scope." /> : !d.links.length ? <Empty text="No LLDP / CDP neighbors collected yet. Enable LLDP on the switches (Cisco: lldp run; Ruckus: lldp run) — the neighbors group polls every 5 minutes." />
        : <Chart option={option!} height={600} onClick={onClick} ariaLabel="Switch topology graph" />}
    </Card>
    {sel && <Card title={sel.node ? sel.node.label : `${label(sel.group.a)} ↔ ${label(sel.group.b)}`} right={<button className="btn" onClick={() => setSel(null)}>Close</button>}>
      {sel.node ? <div className="text-sm space-y-1"><div>{TYPE_LABEL[sel.node.type]} · not monitored{sel.node.address && <> · <span className="font-mono">{sel.node.address}</span></>}</div>
        {sel.node.chassis_id && <div className="text-xs text-muted">chassis {sel.node.chassis_id}</div>}{sel.node.descr && <div className="text-xs text-muted">{sel.node.descr}</div>}
        {sel.node.capabilities?.length > 0 && <div className="text-xs">capabilities: {sel.node.capabilities.join(", ")}</div>}
        {sel.node.firewall_id && <button className="btn" onClick={() => nav("/firewalls")}>Open firewalls</button>}</div>
        : <LinkTable links={sel.group.links} label={label} />}
    </Card>}
    <Card title={`Links (${d.links.length})`} bodyClass="p-0"><LinkTable links={d.links} label={label} /></Card>
    {!!d.without_neighbors.length && <Card title="Switches without LLDP / CDP neighbors" bodyClass="p-0"><div id="sw-nolldp" />
      <TableWrap><table className="tbl"><thead><tr><th>Switch</th><th className="w-full">Reason</th></tr></thead>
        <tbody>{d.without_neighbors.map((x: any) => <tr key={x.switch_id} {...rowProps(() => nav(`/switches/${x.switch_id}?tab=health`))}><td>{x.switch}</td><td className="text-xs">{x.reason}</td></tr>)}</tbody></table></TableWrap></Card>}
  </div>;
}

function LinkTable({ links, label }: { links: any[]; label: (id: string) => string }) {
  const nav = useNavigate();
  if (!links.length) return <Empty text="No links." />;
  const sw = (id: string) => id.startsWith("sw:") ? Number(id.slice(3)) : null;
  return <TableWrap maxH="max-h-[28rem]"><table className="tbl"><thead><tr><th>Status</th><th>Device A</th><th>Port A</th><th>Device B</th><th>Port B</th><th className="num">Speed</th>
    <th className="num">Util</th><th className="num">Errors</th><th>Seen by</th><th>Protocol</th><th>Last seen</th></tr></thead>
    <tbody>{links.map((l) => {
      const ifx = l.a.interface?.ifindex;
      const errs = [l.a.interface?.errors, l.b.interface?.errors].filter((x) => x != null);
      return <tr key={l.id} {...(sw(l.a.node) && ifx != null ? rowProps(() => nav(`/switches/${sw(l.a.node)}?tab=interfaces&if=${ifx}`)) : {})}>
        <td className={STATUS_TXT[l.status]}>{l.status}</td><td>{label(l.a.node)}</td><td className="font-mono text-xs">{l.a.port}{l.a.interface && l.a.interface.oper !== "up" && <span className="text-red-300"> ({l.a.interface.oper})</span>}</td>
        <td>{label(l.b.node)}</td><td className="font-mono text-xs">{l.b.port}{l.b.interface && l.b.interface.oper !== "up" && <span className="text-red-300"> ({l.b.interface.oper})</span>}</td>
        <td className="num text-xs">{l.speed_bps ? fmtBps(l.speed_bps) : "—"}</td><td className="num"><Util v={l.util} /></td>
        <td className="num">{errs.length ? errs.reduce((a: number, b: number) => a + b, 0) : "—"}</td><td className="text-xs">{l.bidirectional ? "both ends" : "one end"}</td>
        <td className="text-xs">{l.protocols.join(", ")}</td><td><Time v={l.last_seen} /></td></tr>;
    })}</tbody></table></TableWrap>;
}

export { worstStatus };
