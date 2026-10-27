import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useData } from "../lib/context";
import { fmtBytes, fmtNum, fmtPct0 } from "../lib/format";
import { Card, Empty, Kpi, Loading, TableWrap, Tabs, Trunc, useExplore } from "../components/ui";
import { WorldMap } from "../components/WorldMap";

export function Geo() {
  const q = useData<any>("/geo/summary");
  const st = useQuery({ queryKey: ["geo-status"], queryFn: () => api<any>("/geo/status"), staleTime: 300_000 });
  const explore = useExplore();
  const [dir, setDir] = useState("dst");
  const [metric, setMetric] = useState("events");
  const d = q.data;
  const cov = d?.coverage || {};
  const rows = (dir === "dst" ? d?.dst : d?.src) || [];
  return (
    <div className="space-y-4 min-w-0">
      <p className="text-xs text-muted">Countries come from FortiGate's own <code>srccountry</code>/<code>dstcountry</code> log fields{st.data?.available ? `, plus GeoIP database (${st.data.files.join(", ")}) for gaps, ASN and coordinates` : ""}.
        {st.data && !st.data.available && <> No GeoIP database configured: add GeoLite2/DB-IP <code>.mmdb</code> files to <code>{st.data.dir}</code> for ASN data and VPN coordinates.</>}</p>
      <Loading q={q} />
      <div className="kpi-grid">
        <Kpi label="Destination countries" value={fmtNum(d?.dst?.length)} />
        <Kpi label="Source countries" value={fmtNum(d?.src?.length)} sub="inbound / external sources" />
        <Kpi label="Traffic with country" value={cov.events ? fmtPct0((cov.with_country / cov.events) * 100) : "—"} sub={`${fmtNum(cov.with_country)} of ${fmtNum(cov.events)} events`} />
        <Kpi label="Traffic with ASN" value={cov.events ? fmtPct0((cov.with_asn / cov.events) * 100) : "—"} sub={st.data?.available ? "from GeoIP ASN database" : "needs a GeoIP ASN database"} />
      </div>
      <Card title="Traffic by country" right={<div className="flex flex-wrap gap-2">
        <Tabs value={dir} onChange={setDir} tabs={[{ key: "dst", label: "Destinations" }, { key: "src", label: "Sources" }]} />
        <select aria-label="Map metric" className="input py-1" value={metric} onChange={(e) => setMetric(e.target.value)}>
          <option value="events">Events</option><option value="denied">Denied</option>{dir === "dst" && <option value="bytes">Bytes</option>}</select></div>}>
        {rows.length ? <WorldMap rows={rows} metric={metric} label={metric} onClick={(c) => explore({ ql: `${dir}_country:"${c}"` })} /> : <Empty text="No country information in this range." />}
      </Card>
      <div className="grid-cards xl:grid-cols-2">
        <Card title={dir === "dst" ? "Destination countries" : "Source countries"}>
          {rows.length ? <TableWrap maxH="max-h-96"><table className="tbl"><thead><tr><th className="w-full">Country</th><th className="num">Events</th><th className="num">Denied</th>{dir === "dst" ? <><th className="num">Bytes</th><th className="num">Hosts</th></> : <th className="num">Sources</th>}</tr></thead>
            <tbody>{rows.map((r: any) => <tr key={r.country} tabIndex={0} onClick={() => explore({ ql: `${dir}_country:"${r.country}"` })}>
              <td>{r.country}</td><td className="num">{fmtNum(r.events)}</td><td className="num text-red-400">{fmtNum(r.denied)}</td>
              {dir === "dst" ? <><td className="num">{fmtBytes(r.bytes)}</td><td className="num">{fmtNum(r.hosts)}</td></> : <td className="num">{fmtNum(r.sources)}</td>}</tr>)}</tbody></table></TableWrap> : <Empty />}
        </Card>
        <Card title="Top destination networks (ASN)">
          {d?.asn?.length ? <TableWrap maxH="max-h-96"><table className="tbl"><thead><tr><th>ASN</th><th className="w-full">Organisation</th><th className="num">Bytes</th><th className="num">Events</th><th className="num">Hosts</th></tr></thead>
            <tbody>{d.asn.map((r: any) => <tr key={r.asn} tabIndex={0} onClick={() => explore({ ql: `asn:${r.asn}` })}><td className="font-mono text-xs">AS{r.asn}</td><td><Trunc text={r.org} max="max-w-[20rem]" /></td>
              <td className="num">{fmtBytes(r.bytes)}</td><td className="num">{fmtNum(r.events)}</td><td className="num">{fmtNum(r.hosts)}</td></tr>)}</tbody></table></TableWrap>
            : <Empty text={st.data?.available ? "No ASN data in this range." : "ASN data needs a GeoIP ASN database (GeoLite2-ASN or DB-IP ASN Lite)."} />}
        </Card>
      </div>
    </div>
  );
}
