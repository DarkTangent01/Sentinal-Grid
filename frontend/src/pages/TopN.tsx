import { useState } from "react";
import { useData } from "../lib/context";
import { fmtBytes, fmtNum } from "../lib/format";
import { Bar, Card, IpLink, LimitSelect, Loading, NoData, SortSelect, rowProps, useExplore } from "../components/ui";

const SORTS: [string, string][] = [["count", "Event count"], ["bytes", "Traffic volume"], ["unique", "Unique peers"], ["denied", "Denied"]];

function Controls({ sort, setSort, limit, setLimit, extra }: any) {
  return <div className="flex flex-wrap gap-2 items-center">{extra}<SortSelect value={sort} onChange={setSort} options={SORTS} /><LimitSelect value={limit} onChange={setLimit} /></div>;
}

const Chips = ({ items }: { items?: any[] }) => (
  <span className="flex flex-wrap gap-1">{(items || []).filter((x) => x !== "" && x !== null).map((x, i) => <span key={i} className="pill bg-slate-800 text-slate-300 font-mono">{String(x)}</span>)}</span>
);

export function Sources() {
  const [sort, setSort] = useState("count");
  const [limit, setLimit] = useState(25);
  const q = useData<any[]>("/analytics/sources", { sort, limit });
  const explore = useExplore();
  const max = Math.max(1, ...(q.data || []).map((r) => Number(r.events)));
  return (
    <Card title="Top source IPs (traffic logs)" right={<Controls {...{ sort, setSort, limit, setLimit }} />}>
      <Loading q={q} />
      {q.data && !q.data.length && <NoData category="traffic" />}
      {!!q.data?.length && (
        <div className="tbl-wrap"><table className="tbl">
          <thead><tr><th>Source IP</th><th className="num">Events</th><th className="num">Sessions</th><th className="num">Unique dst IPs</th><th className="num">Unique dst ports</th><th className="num">Sent</th><th className="num">Received</th><th className="num">Denied</th><th>Top destinations</th><th>Firewall / site</th></tr></thead>
          <tbody>{q.data.map((r) => (
            <tr key={r.src_ip}>
              <td><IpLink ip={r.src_ip} /></td>
              <td className="num">{fmtNum(r.events)}<Bar value={Number(r.events)} max={max} /></td>
              <td className="num">{fmtNum(r.sessions)}</td><td className="num">{fmtNum(r.uniq_peer)}</td>
              <td className="num">{fmtNum(r.uniq_dst_ports)}</td><td className="num">{fmtBytes(r.bytes_sent)}</td><td className="num">{fmtBytes(r.bytes_rcvd)}</td>
              <td className="num">{r.denied ? <button className="link text-red-400" onClick={() => explore({ src_ip: r.src_ip, verdict: "denied", category: "traffic" })}>{fmtNum(r.denied)}</button> : fmtNum(r.denied)}</td>
              <td className="min-w-[12rem]"><Chips items={r.top_destinations} /></td>
              <td className="text-xs text-muted min-w-[9rem]">{(r.firewalls || []).join(", ")}<br />{(r.sites || []).filter(Boolean).join(", ")}</td>
            </tr>))}</tbody>
        </table></div>
      )}
    </Card>
  );
}

export function Destinations() {
  const [sort, setSort] = useState("count");
  const [limit, setLimit] = useState(25);
  const [rdns, setRdns] = useState(false);
  const q = useData<any[]>("/analytics/destinations", { sort, limit, rdns });
  const explore = useExplore();
  return (
    <Card title="Top destination IPs (traffic logs)" right={<Controls {...{ sort, setSort, limit, setLimit }} extra={
      <label className="text-xs text-muted flex items-center gap-1"><input type="checkbox" checked={rdns} onChange={(e) => setRdns(e.target.checked)} />Reverse DNS (PTR lookup by SIEM)</label>} />}>
      <Loading q={q} />
      {q.data && !q.data.length && <NoData category="traffic" />}
      {!!q.data?.length && (
        <div className="tbl-wrap"><table className="tbl">
          <thead><tr><th>Destination IP</th>{rdns && <th>PTR</th>}<th className="num">Events</th><th className="num">Unique sources</th><th className="num">Volume</th><th className="num">Denied</th><th>Common ports</th><th>Common applications</th><th>Firewall / site</th></tr></thead>
          <tbody>{q.data.map((r) => (
            <tr key={r.dst_ip}>
              <td><IpLink ip={r.dst_ip} /></td>{rdns && <td className="text-xs">{r.ptr || <span className="text-slate-600">unresolved</span>}</td>}
              <td className="num"><button className="link" onClick={() => explore({ dst_ip: r.dst_ip, category: "traffic" })}>{fmtNum(r.events)}</button></td>
              <td className="num">{fmtNum(r.uniq_peer)}</td><td className="num">{fmtBytes(r.bytes_total)}</td><td className="num">{fmtNum(r.denied)}</td>
              <td className="min-w-[8rem]"><Chips items={r.top_ports} /></td><td className="min-w-[10rem]"><Chips items={r.top_apps} /></td>
              <td className="text-xs text-muted min-w-[9rem]">{(r.firewalls || []).join(", ")}<br />{(r.sites || []).filter(Boolean).join(", ")}</td>
            </tr>))}</tbody>
        </table></div>
      )}
    </Card>
  );
}

export function Ports() {
  const [sort, setSort] = useState("count");
  const [limit, setLimit] = useState(25);
  const q = useData<any[]>("/analytics/ports", { sort, limit });
  const explore = useExplore();
  return (
    <Card title="Top destination ports (observed in traffic logs)" right={<Controls {...{ sort, setSort, limit, setLimit }} />}>
      <p className="text-xs text-muted mb-2">Service names are shown only when FortiGate logged them; applications are never inferred from port numbers.</p>
      <Loading q={q} />
      {q.data && !q.data.length && <NoData category="traffic" />}
      {!!q.data?.length && (
        <div className="tbl-wrap"><table className="tbl">
          <thead><tr><th>Port</th><th>Protocol</th><th>Logged service</th><th className="num">Events</th><th className="num">Sessions</th><th className="num">Unique sources</th><th className="num">Unique destinations</th><th className="num">Bytes</th><th className="num">Allowed</th><th className="num">Denied</th></tr></thead>
          <tbody>{q.data.map((r) => (
            <tr key={`${r.dst_port}/${r.proto_name}`} {...rowProps(() => explore({ dst_port: r.dst_port, category: "traffic" }))}>
              <td className="font-mono text-sky-400">{r.dst_port}</td><td>{r.proto_name || "—"}</td><td>{r.service || <span className="text-slate-600">not logged</span>}</td>
              <td className="num">{fmtNum(r.events)}</td><td className="num">{fmtNum(r.sessions)}</td>
              <td className="num">{fmtNum(r.uniq_peer)}</td><td className="num">{fmtNum(r.uniq_dst)}</td><td className="num">{fmtBytes(r.bytes_total)}</td>
              <td className="num text-emerald-400">{fmtNum(r.allowed)}</td><td className="num text-red-400">{fmtNum(r.denied)}</td>
            </tr>))}</tbody>
        </table></div>
      )}
    </Card>
  );
}
