import { FormEvent, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, qs } from "../lib/api";
import { useTheme } from "../lib/theme";
import { escHtml, fmtBytes, fmtNum } from "../lib/format";
import { CHART_THEME, Chart, PALETTES, SEV_HEX } from "../components/Chart";
import { Card, Empty, Loading, TableWrap } from "../components/ui";
import { CRIT_CLS } from "./Assets";

const TYPES = ["ip", "domain", "user", "firewall", "alert", "incident"] as const;
const TYPE_LABEL: Record<string, string> = { ip: "IP address", domain: "Domain", user: "User", firewall: "Firewall", alert: "Alert", incident: "Incident" };

export function EntityGraph() {
  const [sp, setSp] = useSearchParams();
  const nav = useNavigate();
  const { theme } = useTheme();
  const kind = sp.get("kind") || "ip";
  const value = sp.get("value") || "";
  const range = sp.get("range") || "24h";
  const [form, setForm] = useState({ kind, value, range });
  const q = useQuery({ queryKey: ["entity-graph", kind, value, range], queryFn: () => api<any>("/entity/graph", { params: { kind, value, range } }), enabled: !!value, retry: false });
  const submit = (e: FormEvent) => { e.preventDefault(); if (form.value.trim()) setSp({ kind: form.kind, value: form.value.trim(), range: form.range }); };
  const color = (n: any) => {
    if (n.type === "alert" || n.type === "incident") return SEV_HEX[n.severity] || SEV_HEX.informational;
    return PALETTES[theme][TYPES.indexOf(n.type) % 8];
  };
  const option = useMemo(() => {
    if (!q.data) return null;
    const max = Math.max(1, ...q.data.nodes.map((n: any) => n.weight || 1));
    const t = CHART_THEME[theme];
    return {
      tooltip: { trigger: "item", confine: true, formatter: (p: any) => p.dataType === "edge"
        ? `${escHtml(p.data.sourceLabel)} → ${escHtml(p.data.targetLabel)}<br/>${escHtml(p.data.label || "")} · <b>${fmtNum(p.data.weight)}</b> events${p.data.denied ? ` · ${fmtNum(p.data.denied)} denied` : ""}${p.data.bytes ? ` · ${fmtBytes(p.data.bytes)} sent` : ""}`
        : `<b>${escHtml(p.data.full)}</b><br/>${TYPE_LABEL[p.data.kind]}${p.data.weight ? ` · ${fmtNum(p.data.weight)} events` : ""}${p.data.country ? ` · ${escHtml(p.data.country)}` : ""}${p.data.status ? ` · ${escHtml(p.data.status)}` : ""}` },
      legend: { data: TYPES.map((x) => TYPE_LABEL[x]), top: 0, textStyle: { color: t.text } },
      series: [{
        type: "graph", layout: "force", roam: true, draggable: true, top: 30,
        force: { repulsion: 260, edgeLength: [70, 170], gravity: 0.08 },
        categories: TYPES.map((x) => ({ name: TYPE_LABEL[x], itemStyle: { color: PALETTES[theme][TYPES.indexOf(x) % 8] } })),
        label: { show: true, position: "right", color: t.strong, fontSize: 11, formatter: (p: any) => p.data.short },
        lineStyle: { color: t.axis, curveness: 0.12, opacity: 0.9 },
        emphasis: { focus: "adjacency", lineStyle: { width: 3 } },
        edgeSymbol: ["none", "arrow"], edgeSymbolSize: 6,
        data: q.data.nodes.map((n: any) => ({
          id: n.id, name: n.id, full: n.label, short: n.label.length > 28 ? n.label.slice(0, 27) + "…" : n.label, kind: n.type,
          category: TYPES.indexOf(n.type), weight: n.weight, country: n.country, status: n.status, ref: n.ref,
          symbolSize: n.root ? 46 : 14 + 22 * Math.sqrt((n.weight || 1) / max), itemStyle: { color: color(n), borderColor: n.root ? t.strong : "transparent", borderWidth: n.root ? 3 : 0 },
          symbol: n.type === "alert" ? "triangle" : n.type === "incident" ? "diamond" : n.type === "firewall" ? "rect" : "circle",
        })),
        links: q.data.edges.map((e: any) => ({ source: e.source, target: e.target, label: e.label, weight: e.weight, denied: e.denied, bytes: e.bytes,
          sourceLabel: q.data.nodes.find((n: any) => n.id === e.source)?.label, targetLabel: q.data.nodes.find((n: any) => n.id === e.target)?.label,
          lineStyle: { width: 1 + 3 * Math.sqrt(e.weight / max), color: e.denied ? "#e23744" : undefined } })),
      }],
    };
  }, [q.data, theme]);
  const onClick = (p: any) => {
    if (p.dataType !== "node") return;
    const d = p.data;
    if (d.kind === "incident") nav(`/incidents/${d.ref}`);
    else if (d.kind === "alert") nav(`/alerts?id=${d.ref}`);
    else if (["ip", "domain", "user"].includes(d.kind) && d.full !== value) {
      setForm({ kind: d.kind, value: d.full, range });
      setSp({ kind: d.kind, value: d.full, range });
    }
  };
  const root = q.data?.nodes.find((n: any) => n.root);
  return (
    <div className="space-y-4 min-w-0">
      <form onSubmit={submit} className="flex flex-wrap gap-2 items-end">
        <div><label className="label" htmlFor="eg-kind">Entity</label><select id="eg-kind" className="input" value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })}>
          <option value="ip">IP address</option><option value="domain">Domain</option><option value="user">User</option></select></div>
        <div className="flex-1 min-w-[14rem]"><label className="label" htmlFor="eg-value">Value</label><input id="eg-value" className="input w-full font-mono" value={form.value}
          onChange={(e) => setForm({ ...form, value: e.target.value })} placeholder={form.kind === "ip" ? "10.0.0.5" : form.kind === "domain" ? "example.com" : "jdoe"} /></div>
        <div><label className="label" htmlFor="eg-range">Range</label><select id="eg-range" className="input" value={form.range} onChange={(e) => setForm({ ...form, range: e.target.value })}>
          {["1h", "24h", "7d", "30d"].map((r) => <option key={r}>{r}</option>)}</select></div>
        <button className="btn btn-primary" type="submit">Investigate</button>
      </form>
      {!value && <Empty text="Enter an IP address, domain or user to draw who it talked to, what it resolved, the users and firewalls involved, and related alerts and incidents. Click a node to pivot." />}
      <Loading q={q} />
      {q.data && <div className="grid gap-4 xl:grid-cols-[1fr_20rem] min-w-0">
        <Card title={<span>Graph · <span className="font-mono">{value}</span></span>} right={<span className="text-2xs text-muted">drag to rearrange · scroll to zoom · click to pivot · red links had denied traffic</span>}>
          {q.data.nodes.length <= 1 ? <Empty text="No activity or related records for this entity in the selected range." />
            : <Chart option={option!} height={560} onClick={onClick} ariaLabel={`Relationship graph for ${value}`} />}
        </Card>
        <div className="space-y-4 min-w-0">
          <Card title="Entity">
            <div className="text-sm space-y-1.5">
              <div className="font-mono break-all">{value}</div>
              {root?.hostname && <div><span className="text-muted">Host:</span> {root.hostname}</div>}
              {root?.criticality && <div><span className="text-muted">Criticality:</span> <span className={`pill ${CRIT_CLS[root.criticality]}`}>{root.criticality}</span></div>}
              {root?.owner && <div><span className="text-muted">Owner:</span> {root.owner}</div>}
              <div><span className="text-muted">Watchlists:</span> {root?.watchlists?.length ? root.watchlists.map((w: string) => <span key={w} className="pill bg-brand-500/10 text-brand-400 mr-1">{w}</span>) : "none"}</div>
              <div className="flex flex-wrap gap-2 pt-2">
                {kind === "ip" && <button className="btn" onClick={() => nav(`/investigate/${encodeURIComponent(value)}`)}>IP details</button>}
                <button className="btn" onClick={() => nav(`/search${qs({ q: kind === "ip" ? `ip:${value}` : kind === "domain" ? `domain:${value}` : `user:"${value}"` })}`)}>Search events</button>
              </div>
            </div>
          </Card>
          <Card title="Relationships" bodyClass="p-0">
            <TableWrap maxH="max-h-[380px]"><table className="tbl"><thead><tr><th>Peer</th><th>Type</th><th className="num">Events</th></tr></thead>
              <tbody>{q.data.edges.map((e: any, i: number) => {
                const other = q.data.nodes.find((n: any) => n.id === (e.source === q.data.root ? e.target : e.source));
                return <tr key={i}><td className="font-mono text-xs cell-wrap">{other?.label}</td><td className="text-xs">{TYPE_LABEL[other?.type]}{e.label ? ` · ${e.label}` : ""}</td><td className="num">{fmtNum(e.weight)}</td></tr>;
              })}</tbody></table></TableWrap>
          </Card>
        </div>
      </div>}
    </div>
  );
}
