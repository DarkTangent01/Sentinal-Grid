import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { useTheme } from "../../lib/theme";
import { escHtml, fmtNum, getTimezone } from "../../lib/format";
import { Chart, PALETTES, axisStyle } from "../../components/Chart";
import { Card, Empty, Kpi, Loading, TableWrap, useDebounced } from "../../components/ui";
import { Avail, CollectorBadge, Dur, Pager, RangePicker, SortTh, StaleBanner, StateDot, dur, stackedDaily, useRange, useWanMeta } from "./common";

export function useGo() {
  const [, setSp] = useSearchParams();
  return (tab: string, params: Record<string, string | number | boolean | undefined> = {}) =>
    setSp(Object.fromEntries(Object.entries({ tab, ...params }).filter(([, v]) => v !== undefined && v !== "").map(([k, v]) => [k, String(v)])));
}

export function WanOverview() {
  const [r, setR, rp] = useRange("30d");
  const [site, setSite] = useState("");
  const [isp, setIsp] = useState("");
  const meta = useWanMeta();
  const go = useGo();
  const tz = getTimezone();
  const params = { ...rp, site: site || undefined, isp: isp || undefined, tz };
  const q = useQuery({ queryKey: ["wan-overview", params], queryFn: () => api<any>("/wan/overview", { params }), refetchInterval: 60_000, placeholderData: (p) => p });
  const d = q.data;
  const t = d?.totals || {};
  const rangeArgs = r.range === "custom" ? { start: rp.start, end: rp.end } : { range: r.range };
  return (
    <div className="space-y-4 min-w-0">
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-xs text-muted flex-1 min-w-[16rem]">Current state and history are separate: a circuit can be <b>up now</b> and still have had outages in the range.
          Every count and downtime figure comes from the same outage records the live monitoring page uses.</p>
        <RangePicker value={r} onChange={setR} />
        <select aria-label="Site" className="input py-1" value={site} onChange={(e) => setSite(e.target.value)}><option value="">All sites</option>
          {(meta.data?.sites || []).map((x: string) => <option key={x}>{x}</option>)}</select>
        <select aria-label="ISP" className="input py-1" value={isp} onChange={(e) => setIsp(e.target.value)}><option value="">All ISPs</option>
          {(meta.data?.isps || []).map((x: string) => <option key={x}>{x}</option>)}</select>
      </div>
      <StaleBanner c={d?.collector} />
      <Loading q={q} />
      {d && <>
        <div className="kpi-grid">
          <Kpi label="Open incidents" value={fmtNum(t.open)} tone={t.open ? "bad" : "ok"} onClick={() => go("incidents", { open_only: 1, site, isp })} />
          <Kpi label="Incidents" value={fmtNum(t.incidents)} sub="started in range" onClick={() => go("incidents", { ...rangeArgs, site, isp })} />
          <Kpi label="Avg time to resolve" value={dur(t.avg_resolve_s)} sub={t.median_resolve_s != null ? `median ${dur(t.median_resolve_s)}` : "no resolved incidents"} />
          <Kpi label="Sites affected" value={fmtNum(t.sites_affected)} />
          <Kpi label="Missing root cause" value={fmtNum(t.missing_root_cause)} tone={t.missing_root_cause ? "bad" : "ok"}
            onClick={() => go("incidents", { ...rangeArgs, missing_root_cause: 1, site, isp })} />
          <Kpi label="Circuits monitored" value={fmtNum(t.circuits)} sub={`${t.up} up · ${t.unknown + t.paused} unknown/paused`} onClick={() => go("live")} />
          <Kpi label="Down now" value={fmtNum(t.down)} tone={t.down ? "bad" : "ok"} onClick={() => go("live", { state: "down" })} />
          <Kpi label="Degraded now" value={fmtNum(t.degraded)} tone={t.degraded ? "warn" : undefined} onClick={() => go("live", { state: "degraded" })} />
          <Kpi label="Total downtime" value={dur(t.downtime_s)} sub={`${fmtNum(t.outages)} circuit outage(s)`} />
          <Kpi label="Monitoring health" value={<CollectorBadge c={d.collector} />} sub={d.collector?.last_success_at ? <>last collection {new Date(d.collector.last_success_at).toLocaleTimeString(undefined, { timeZone: tz })}</> : d.collector?.detail} />
        </div>
        <div className="grid gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
          <IspTable rp={rp} site={site} isp={isp} go={go} rangeArgs={rangeArgs} />
          <Card title="By location" right={<span className="text-2xs text-muted">incidents started in range · click to filter</span>} bodyClass="p-0">
            {!d.by_location.length ? <Empty text="No ISP incidents in this range." /> :
              <TableWrap maxH="max-h-96"><table className="tbl"><tbody>{d.by_location.map((x: any) => (
                <tr key={x.site} className="cursor-pointer hover:bg-white/5" onClick={() => go("incidents", { ...rangeArgs, site: x.site })}>
                  <td>{x.site}</td><td className="num font-semibold">{x.incidents}</td></tr>))}</tbody></table></TableWrap>}
          </Card>
        </div>
        <DailyChart daily={d.daily} onPick={(day, isp_) => go("incidents", { day, isp: isp_, tz, site })} />
      </>}
    </div>
  );
}

function IspTable({ rp, site, isp, go, rangeArgs }: { rp: any; site: string; isp: string; go: ReturnType<typeof useGo>; rangeArgs: any }) {
  const [group, setGroup] = useState("isp_site");
  const [qtext, setQ] = useState("");
  const [sort, setSort] = useState({ key: "downtime_s", desc: true });
  const [page, setPage] = useState(1);
  const qd = useDebounced(qtext, 300);
  const params = { ...rp, group, q: qd || undefined, site: site || undefined, isp: isp || undefined, sort: sort.key, desc: sort.desc, page, size: 15 };
  const q = useQuery({ queryKey: ["wan-summary", params], queryFn: () => api<any>("/wan/summary", { params }), placeholderData: (p) => p, refetchInterval: 60_000 });
  const S = (k: string, l: string, c = "num") => <SortTh k={k} label={l} sort={sort} setSort={(s) => { setSort(s); setPage(1); }} className={c} />;
  return (
    <Card title="ISP name with location" bodyClass="p-0" right={<span className="flex flex-wrap items-center gap-1">
      <select aria-label="Group by" className="input py-0.5 text-xs" value={group} onChange={(e) => { setGroup(e.target.value); setPage(1); }}>
        {[["isp_site", "ISP + site"], ["isp", "ISP"], ["site", "Site"], ["circuit", "Circuit"], ["firewall", "Firewall"]].map(([k, l]) => <option key={k} value={k}>By {l}</option>)}</select>
      <input aria-label="Search" className="input py-0.5 text-xs w-36" placeholder="Search circuit, ISP, site" value={qtext} onChange={(e) => { setQ(e.target.value); setPage(1); }} /></span>}>
      <Loading q={q} />
      {q.data && (!q.data.items.length ? <Empty text="No monitored circuits match." /> : <>
        <TableWrap><table className="tbl"><thead><tr>
          {group === "isp_site" ? <><SortTh k="isp" label="ISP" sort={sort} setSort={setSort} /><SortTh k="site" label="Location" sort={sort} setSort={setSort} /></> :
            <SortTh k="group" label={{ isp: "ISP", site: "Location", circuit: "Circuit", firewall: "Firewall" }[group] || "Group"} sort={sort} setSort={setSort} />}
          <th>Status</th>{S("outages", "Outages")}{S("downtime_s", "Total downtime")}{S("avg_outage_s", "Avg outage")}{S("longest_s", "Longest")}
          {S("availability", "Availability")}{S("open_incidents", "Open inc.")}</tr></thead>
          <tbody>{q.data.items.map((x: any) => {
            const filt = group === "circuit" ? { circuit_id: x.isp_link_id } : { site: x.site || undefined, isp: x.isp || undefined };
            return <tr key={x.group} className="cursor-pointer hover:bg-white/5" onClick={() => go(group === "circuit" ? "live" : "incidents", group === "circuit" ? { q: x.name } : { ...rangeArgs, ...filt })}>
              {group === "isp_site" ? <><td className="font-medium">{x.isp}</td><td>{x.site}</td></> :
                <td className="font-medium">{x.group}{group === "circuit" && x.isp && <div className="text-2xs text-muted">{x.isp} · {x.site}</div>}</td>}
              <td><StateDot s={x.state} /></td><td className="num">{fmtNum(x.outages)}</td><td className="num"><Dur s={x.downtime_s} /></td>
              <td className="num"><Dur s={x.avg_outage_s} /></td><td className="num"><Dur s={x.longest_s || null} /></td>
              <td className="num"><Avail v={x.availability} coverage={x.coverage_pct} /></td>
              <td className="num">{x.open_incidents ? <span className="text-red-300 font-semibold">{x.open_incidents}</span> : 0}</td></tr>;
          })}</tbody></table></TableWrap>
        <Pager page={page} size={15} total={q.data.total} onPage={setPage} /></>)}
    </Card>
  );
}

export function DailyChart({ daily, onPick, title = "ISP incidents per day" }: { daily: any; onPick?: (day: string, isp: string) => void; title?: string }) {
  const { theme } = useTheme();
  const opt = useMemo(() => {
    const sd = stackedDaily(daily, PALETTES[theme]);
    return {
      _total: sd.total,
      legend: { bottom: 0, type: "scroll" }, grid: { left: 8, right: 12, top: 16, bottom: 34, containLabel: true },
      tooltip: { trigger: "item", confine: true, formatter: (p: any) => `<b>${escHtml(p.name)}</b><br/>${p.marker}${escHtml(p.seriesName)}: <b>${p.value}</b> incident(s)` +
        (p.data?.sites?.length ? `<br/><span style="opacity:.7">${p.data.sites.map(escHtml).join(", ")}</span>` : "") },
      xAxis: { type: "category", data: sd.categories, ...axisStyle, axisLabel: { ...axisStyle.axisLabel, rotate: sd.categories.length > 14 ? 45 : 0,
        formatter: (v: string) => new Date(`${v}T12:00:00Z`).toLocaleDateString(undefined, { day: "2-digit", month: "short", timeZone: "UTC" }) } },
      yAxis: { type: "value", minInterval: 1, ...axisStyle }, series: sd.series,
    };
  }, [daily, theme]);
  return (
    <Card title={title} right={<span className="text-2xs text-muted">one colour per ISP · days in {getTimezone()} · click a bar for its incidents</span>}>
      {!opt._total ? <Empty text="No ISP incidents in this range." /> :
        <Chart height={300} option={opt} ariaLabel="ISP incidents per day, stacked by ISP" onClick={onPick ? (p: any) => p?.name && p?.seriesName && onPick(p.name, p.seriesName) : undefined} />}
    </Card>
  );
}
