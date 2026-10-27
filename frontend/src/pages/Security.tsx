import { useData } from "../lib/context";
import { fmtNum } from "../lib/format";
import { Card, Loading, NoData, Sev, TableWrap, Trunc, rowProps, useExplore } from "../components/ui";
import { Donut } from "../components/charts";
import { EventTable } from "./Explorer";

export function Security() {
  const q = useData<any>("/analytics/security");
  const explore = useExplore();
  const rows: any[] = q.data?.by_severity_type || [];
  const bySev = Object.entries(rows.reduce((a: any, r) => ({ ...a, [r.severity]: (a[r.severity] || 0) + Number(r.events) }), {})).map(([key, events]) => ({ key, events }));
  const byType = Object.entries(rows.reduce((a: any, r) => ({ ...a, [r.event_subtype || "(none)"]: (a[r.event_subtype || "(none)"] || 0) + Number(r.events) }), {})).map(([key, events]) => ({ key, events }));
  return (
    <div className="space-y-4">
      <p className="text-xs text-muted">Shows FortiGate UTM logs (IPS, antivirus, application control, …) and event logs (admin, config, VPN, system) that were actually collected. Event types that are not configured for logging will not appear.</p>
      <Loading q={q} />
      {/* Charts sit side by side at their natural height; the signature table gets the full width it needs. */}
      <div className="grid-cards md:grid-cols-2">
        <Card title="By severity">{bySev.length ? <Donut rows={bySev} label="Severity" height={200} onClick={(s) => explore({ category: ["security", "system"], severity: s })} /> : <NoData category="security" />}</Card>
        <Card title="By type">{byType.length ? <Donut rows={byType} label="Type" height={200} onClick={(s) => explore({ category: ["security", "system"], event_subtype: s })} /> : <NoData category="security" />}</Card>
      </div>
      <Card title="Top threats / signatures">
        {q.data?.top_threats?.length ? <TableWrap maxH="max-h-[28rem]"><table className="tbl">
          <thead className="sticky top-0 bg-panel"><tr><th className="w-full">Threat / signature</th><th>Type</th><th>Severity</th><th className="num">Events</th><th className="num">Sources</th></tr></thead>
          <tbody>{q.data.top_threats.map((r: any, i: number) => <tr key={`${r.threat}|${r.severity}|${i}`} {...rowProps(() => explore({ category: ["security"], q: r.threat }))}>
            <td className="font-mono text-xs"><Trunc text={r.threat} max="max-w-[40rem]" /></td>
            <td className="nowrap text-xs">{r.event_subtype || "—"}</td>
            <td className="nowrap"><Sev s={r.severity} /></td>
            <td className="num">{fmtNum(r.events)}</td><td className="num">{fmtNum(r.sources)}</td></tr>)}</tbody></table></TableWrap>
          : <NoData category="security" />}
      </Card>
      <Card title="Recent security and system events"><EventTable fixed={{ category: ["security", "system"] }} /></Card>
    </div>
  );
}
