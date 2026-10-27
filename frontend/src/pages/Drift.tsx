import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { Card, Drawer, Empty, Loading, Sev, TableWrap, Time, rowProps } from "../components/ui";

function Val({ v }: { v: any }) {
  if (v === null || v === undefined || v === "") return <span className="text-slate-400">—</span>;
  return <span className="font-mono text-xs cell-wrap">{Array.isArray(v) ? v.join(", ") : typeof v === "object" ? JSON.stringify(v) : String(v)}</span>;
}

export function Drift() {
  const q = useQuery({ queryKey: ["drift"], queryFn: () => api<any>("/drift"), refetchInterval: 60_000 });
  const [sel, setSel] = useState<number | null>(null);
  return (
    <div className="space-y-4 min-w-0">
      <p className="text-xs text-muted">Read-only snapshots of interfaces (management access), administrators (trusted hosts, 2FA), global admin settings, SSL-VPN settings and firewall policies, taken with each policy sync (every 15 min). A snapshot is stored only when something changed; risky changes raise the <b>Risky firewall configuration change</b> alert. Passwords and keys are never collected.</p>
      <Loading q={q} />
      {q.data && !q.data.current.length && <Card><Empty text="No snapshots yet. They are collected from firewalls with an API token (read access to system and network objects)." /></Card>}
      {q.data?.current.map((c: any) => (
        <Card key={`${c.firewall_id}|${c.vdom}`} title={`${c.firewall} / ${c.vdom}: current risky settings (${c.risks.length})`} right={<span className="text-xs text-muted">snapshot <Time v={c.collected_at} /></span>}>
          {c.risks.length ? <TableWrap><table className="tbl"><thead><tr><th>Severity</th><th>Area</th><th className="w-full">Finding</th></tr></thead>
            <tbody>{c.risks.map((r: any, n: number) => <tr key={n}><td className="nowrap"><Sev s={r.severity} /></td><td className="text-xs nowrap">{r.table}{r.key ? ` · ${r.key}` : ""}</td>
              <td className="text-sm">{r.title}{r.detail && <div className="text-xs text-muted">{r.detail}</div>}</td></tr>)}</tbody></table></TableWrap>
            : <Empty text="No risky settings detected in the latest snapshot." />}
          {Object.keys(c.errors || {}).length > 0 && <p className="text-xs text-amber-300 mt-2">Not readable with the current API permissions: {Object.keys(c.errors).join(", ")}.</p>}
        </Card>))}
      {!!q.data?.snapshots.length && <Card title="Change history">
        <TableWrap maxH="max-h-[28rem]"><table className="tbl"><thead><tr><th>Collected</th><th>Firewall</th><th>VDOM</th><th className="num">Changes</th><th className="num">New risks</th><th /></tr></thead>
          <tbody>{q.data.snapshots.map((s: any) => <tr key={s.id} {...rowProps(() => setSel(s.id))}><td><Time v={s.collected_at} /></td><td>{s.firewall}</td><td className="text-xs">{s.vdom}</td>
            <td className="num">{s.baseline ? <span className="text-xs text-muted">baseline</span> : s.changes}</td><td className={`num ${s.risks ? "text-red-400" : ""}`}>{s.risks}</td><td className="text-xs link">details</td></tr>)}</tbody></table></TableWrap>
      </Card>}
      {sel && <SnapshotDetail id={sel} onClose={() => setSel(null)} />}
    </div>
  );
}

function SnapshotDetail({ id, onClose }: { id: number; onClose: () => void }) {
  const q = useQuery({ queryKey: ["drift", id], queryFn: () => api<any>(`/drift/${id}`) });
  const d = q.data;
  return (
    <Drawer title={`Configuration snapshot #${id}`} onClose={onClose}>
      <Loading q={q} />
      {d && <div className="space-y-4">
        <div className="text-xs text-muted">Collected <Time v={d.collected_at} /> · tables: {Object.entries(d.tables).map(([k, v]) => `${k} (${v})`).join(", ")}</div>
        {d.risks.length > 0 && <Card title="Risks">{d.risks.map((r: any, n: number) => <div key={n} className="text-sm mb-1"><Sev s={r.severity} /> {r.title}{r.baseline && <span className="text-2xs text-muted ml-1">(baseline)</span>}</div>)}</Card>}
        <Card title={`Changes (${d.changes.length})`}>
          {d.changes.length ? <div className="space-y-3">{d.changes.map((c: any, n: number) => (
            <div key={n} className="border border-line rounded p-2">
              <div className="text-sm"><span className={`pill ${c.change === "added" ? "bg-emerald-500/15 text-emerald-300" : c.change === "removed" ? "bg-red-500/15 text-red-300" : "bg-amber-500/15 text-amber-300"}`}>{c.change}</span> <b>{c.table}</b> {c.key}</div>
              {c.fields && <table className="tbl mt-1"><thead><tr><th>Field</th><th>Before</th><th>After</th></tr></thead><tbody>{Object.entries(c.fields).map(([f, [a, b]]: any) => (
                <tr key={f}><td className="text-xs nowrap">{f}</td><td><Val v={a} /></td><td><Val v={b} /></td></tr>))}</tbody></table>}
              {c.new && <pre className="text-xs bg-panel2 rounded p-2 mt-1 whitespace-pre-wrap">{JSON.stringify(c.new, null, 1)}</pre>}
              {c.old && <pre className="text-xs bg-panel2 rounded p-2 mt-1 whitespace-pre-wrap">{JSON.stringify(c.old, null, 1)}</pre>}
            </div>))}</div> : <Empty text="First (baseline) snapshot: no previous configuration to compare." />}
        </Card>
      </div>}
    </Drawer>
  );
}
