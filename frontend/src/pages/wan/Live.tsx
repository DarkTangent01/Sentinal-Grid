import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { useMe } from "../../lib/context";
import { useTheme } from "../../lib/theme";
import { escHtml, fmtNum, fmtTime, getTimezone } from "../../lib/format";
import { Chart, PALETTES, SERIES_ROLE, axisStyle } from "../../components/Chart";
import { Card, Drawer, Empty, Kpi, Loading, Modal, TableWrap, Time, useDebounced } from "../../components/ui";
import { Avail, CollectorBadge, Dur, Field, Pager, RangePicker, STATE_HEX, SortTh, StaleBanner, StateDot, dur, ms, pct, rangeParams, useRange, useWanMeta } from "./common";

const BLANK = { name: "", address: "", isp_name: "", isp_link_id: null as number | null, site: "", enabled: true, interval_seconds: 30, probes: 3,
  timeout_ms: 1000, retries: 0, down_after: 3, up_after: 2, degrade_after: 3, clear_after: 2, rtt_warn_ms: 150, loss_warn_pct: 20, jitter_warn_ms: null as number | null };

export function WanLive() {
  const me = useMe();
  const admin = me.role === "admin";
  const qc = useQueryClient();
  const [sp] = useSearchParams();
  const meta = useWanMeta();
  const [r, setR, rp] = useRange("24h");
  const [qtext, setQ] = useState(sp.get("q") || "");
  const [state, setState] = useState(sp.get("state") || "");
  const [isp, setIsp] = useState(sp.get("isp") || "");
  const [site, setSite] = useState(sp.get("site") || "");
  const [maxAvail, setMaxAvail] = useState("");
  const [sort, setSort] = useState<{ key: string; desc: boolean }>({ key: "", desc: false });
  const [page, setPage] = useState(1);
  const [refresh, setRefresh] = useState(15);
  const [edit, setEdit] = useState<any>(null);
  const [sel, setSel] = useState<any>(null);
  const qd = useDebounced(qtext, 300);
  const params = { ...rp, q: qd || undefined, state: state ? [state] : undefined, isp: isp || undefined, site: site || undefined,
    max_availability: maxAvail || undefined, sort: sort.key || undefined, desc: sort.desc, page, size: 50 };
  const q = useQuery({ queryKey: ["wan-targets", params], queryFn: () => api<any>("/wan/targets", { params }), refetchInterval: refresh ? refresh * 1000 : false,
    placeholderData: (p) => p });
  const sugg = useQuery({ queryKey: ["icmp-sugg"], queryFn: () => api<any[]>("/isp/icmp/suggestions"), enabled: admin });
  const addSugg = useMutation({ mutationFn: async (list: any[]) => { for (const x of list) await api("/isp/icmp/targets", { method: "POST", body: { ...BLANK, name: x.name.slice(0, 128), address: x.address, isp_link_id: x.isp_link_id } }); },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["wan-targets"] }); qc.invalidateQueries({ queryKey: ["icmp-sugg"] }); } });
  const act = useMutation({ mutationFn: ({ id, a }: { id: number; a: "pause" | "resume" }) => api(`/wan/targets/${id}/${a}`, { method: "POST", body: a === "pause" ? { reason: prompt("Reason for pausing (shown in the event history)") || "" } : undefined }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["wan-targets"] }) });
  const d = q.data;
  const t = d?.totals || {};
  const setS = (s: { key: string; desc: boolean }) => { setSort(s); setPage(1); };
  const S = (k: string, l: string, c = "num") => <SortTh k={k} label={l} sort={sort} setSort={setS} className={c} />;
  return (
    <div className="space-y-4 min-w-0">
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-xs text-muted flex-1 min-w-[16rem]">The SIEM pings each address on its own interval. A target goes <b>down</b> only after its consecutive-failure threshold
          and comes back <b>up</b> after its consecutive-success threshold, so single lost packets never create outages. Reachable but slow, lossy or jittery targets are <b>degraded</b>.
          Missing measurements show as “—”, never as zero.</p>
        <RangePicker value={r} onChange={(x) => { setR(x); setPage(1); }} />
        <select aria-label="Auto refresh" className="input py-1" value={refresh} onChange={(e) => setRefresh(Number(e.target.value))}>
          {[[0, "No auto refresh"], [15, "Refresh 15 s"], [30, "Refresh 30 s"], [60, "Refresh 1 min"]].map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select>
        {admin && <button className="btn btn-primary" onClick={() => setEdit({ ...BLANK })}>+ Monitor an address</button>}
      </div>
      <StaleBanner c={d?.collector} />
      {admin && !!sugg.data?.length && <Card title="Suggested from SD-WAN links">
        <div className="flex flex-wrap items-center gap-2 text-sm">
          {sugg.data.map((x) => <span key={x.address} className="pill bg-slate-800 text-slate-300">{x.name} · <span className="font-mono">{x.address}</span></span>)}
          <button className="btn ml-auto" disabled={addSugg.isPending} onClick={() => addSugg.mutate(sugg.data!)}>Monitor all {sugg.data.length}</button>
        </div></Card>}
      <Loading q={q} />
      {d && <>
        <div className="kpi-grid">
          <Kpi label="Monitored" value={fmtNum(t.targets)} sub={`${t.paused} paused · ${t.unknown} unknown`} onClick={() => setState("")} />
          <Kpi label="Up now" value={fmtNum(t.up)} tone="ok" onClick={() => setState("up")} />
          <Kpi label="Degraded now" value={fmtNum(t.degraded)} tone={t.degraded ? "warn" : undefined} onClick={() => setState("degraded")} />
          <Kpi label="Down now" value={fmtNum(t.down)} tone={t.down ? "bad" : "ok"} onClick={() => setState("down")} />
          <Kpi label="Outages" value={fmtNum(t.outages)} sub="started in range" tone={t.outages ? "warn" : "ok"} />
          <Kpi label="Total downtime" value={dur(t.downtime_s)} sub="observed time only" />
          <Kpi label="Monitoring worker" value={<CollectorBadge c={d.collector} />} sub={d.collector?.last_duration_ms != null ? `cycle ${d.collector.last_duration_ms} ms · ${d.collector.last_errors} probe error(s)` : d.collector?.detail} />
          <Kpi label="Last collection" value={d.collector?.last_success_at ? <Time v={d.collector.last_success_at} /> : "—"} sub={t.local_errors ? `${fmtNum(t.local_errors)} local probe errors in range` : undefined} />
        </div>
        <Card title="Targets" bodyClass="p-0" right={<span className="flex flex-wrap items-center gap-1">
          <input aria-label="Search targets" className="input py-0.5 text-xs w-44" placeholder="Search name, IP, ISP, site, firewall" value={qtext} onChange={(e) => { setQ(e.target.value); setPage(1); }} />
          <select aria-label="State" className="input py-0.5 text-xs" value={state} onChange={(e) => { setState(e.target.value); setPage(1); }}><option value="">Any state</option>
            {["up", "degraded", "down", "unknown", "paused"].map((x) => <option key={x} value={x}>{x}</option>)}</select>
          <select aria-label="ISP" className="input py-0.5 text-xs" value={isp} onChange={(e) => { setIsp(e.target.value); setPage(1); }}><option value="">Any ISP</option>
            {(meta.data?.isps || []).map((x: string) => <option key={x}>{x}</option>)}</select>
          <select aria-label="Site" className="input py-0.5 text-xs" value={site} onChange={(e) => { setSite(e.target.value); setPage(1); }}><option value="">Any site</option>
            {(meta.data?.sites || []).map((x: string) => <option key={x}>{x}</option>)}</select>
          <select aria-label="Availability" className="input py-0.5 text-xs" value={maxAvail} onChange={(e) => { setMaxAvail(e.target.value); setPage(1); }}>
            <option value="">Any availability</option><option value="99.9">≤ 99.9%</option><option value="99">≤ 99%</option><option value="95">≤ 95%</option></select></span>}>
          {!d.items.length ? <Empty text={t.targets ? "No targets match the filters." : "No addresses monitored yet. Add ISP gateways, WAN IPs or an upstream resolver."} /> : <>
            <TableWrap><table className="tbl"><thead><tr>
              {S("state", "State", "")}{S("name", "Target", "")}{S("address", "Address", "")}{S("isp", "ISP", "")}<th className="hidden 2xl:table-cell">Circuit ID</th>
              {S("state_since", "Since", "")}{S("availability", "Availability")}{S("outages", "Outages")}{S("downtime_s", "Downtime")}
              <th className="num hidden xl:table-cell">Longest</th>{S("last_rtt_ms", "RTT now")}{S("rtt_ms", "Avg / P95")}{S("jitter_ms", "Jitter")}{S("loss_pct", "Loss")}
              {S("last_check", "Last check", "")}<th className="num hidden xl:table-cell">Every</th><th /></tr></thead>
              <tbody>{d.items.map((x: any) => <tr key={x.id} className="cursor-pointer hover:bg-white/5" onClick={() => setSel(x)}>
                <td><StateDot s={x.state} /></td>
                <td className="font-medium">{x.name}<div className="text-2xs text-muted">{x.site}{x.firewall && ` · ${x.firewall}`}</div></td>
                <td className="font-mono text-xs">{x.address}</td><td className="text-xs">{x.isp}{x.role === "backup" && <span className="text-muted"> (backup)</span>}</td>
                <td className="text-xs font-mono hidden 2xl:table-cell">{x.circuit_id || "—"}</td>
                <td className="text-xs"><Time v={x.state_since} /></td>
                <td className="num"><Avail v={x.availability} coverage={x.coverage_pct} /></td><td className="num">{fmtNum(x.outages)}</td>
                <td className="num"><Dur s={x.availability == null ? null : x.downtime_s} /></td><td className="num hidden xl:table-cell"><Dur s={x.longest_s || null} /></td>
                <td className="num">{ms(x.last_rtt_ms)}</td><td className="num whitespace-nowrap">{ms(x.rtt_ms)} / {ms(x.rtt_p95_ms)}</td>
                <td className={`num ${x.jitter_warn_ms && (x.jitter_ms || 0) >= x.jitter_warn_ms ? "text-amber-300" : ""}`}>{ms(x.jitter_ms)}</td>
                <td className={`num ${(x.loss_pct || 0) >= x.loss_warn_pct ? "text-amber-300" : ""}`}>{pct(x.loss_pct)}</td>
                <td className="text-xs"><Time v={x.last_check} />{x.last_error && <div className="text-2xs text-red-300 truncate max-w-[10rem]" title={x.last_error}>{x.last_error}</div>}</td>
                <td className="num text-xs hidden xl:table-cell">{x.interval_seconds}s</td>
                <td className="whitespace-nowrap" onClick={(e) => e.stopPropagation()}>{admin && <>
                  <button className="btn py-0.5 text-xs" onClick={() => setEdit(x)}>Edit</button>{" "}
                  {x.state === "paused" ? <button className="btn py-0.5 text-xs" onClick={() => act.mutate({ id: x.id, a: "resume" })}>Resume</button> :
                    <button className="btn py-0.5 text-xs" onClick={() => act.mutate({ id: x.id, a: "pause" })}>Pause</button>}</>}</td>
              </tr>)}</tbody></table></TableWrap>
            <Pager page={page} size={50} total={d.total} onPage={setPage} /></>}
        </Card>
        <p className="text-2xs text-muted">Availability = observed time without confirmed outages ÷ observed time; paused time, maintenance and unobserved gaps are excluded
          (<span className="text-amber-300">*</span> = less than 90% of the range observed). RTT statistics use every reply; P95 is the nearest-rank percentile; jitter is the mean
          change between consecutive replies within a check; loss excludes local probe errors on the SIEM.</p>
      </>}
      {edit && <TargetForm t={edit} onClose={() => { setEdit(null); qc.invalidateQueries({ queryKey: ["wan-targets"] }); qc.invalidateQueries({ queryKey: ["icmp-sugg"] }); }} />}
      {sel && <TargetDetail x={sel} r={r} admin={admin} onClose={() => setSel(null)} />}
    </div>
  );
}

// ------------------------------------------------------------------ per-target history
export function TargetDetail({ x, r, admin, onClose }: { x: any; r: any; admin: boolean; onClose: () => void }) {
  const { theme } = useTheme();
  const rp = rangeParams(r);
  const q = useQuery({ queryKey: ["wan-history", x.id, rp], queryFn: () => api<any>(`/wan/targets/${x.id}/history`, { params: rp }), refetchInterval: 30_000 });
  const inv = useQuery({ queryKey: ["wan-inv", x.id], queryFn: () => api<any>("/wan/investigate", { params: { target_id: x.id } }) });
  const test = useMutation({ mutationFn: () => api<any>(`/wan/targets/${x.id}/test`, { method: "POST" }) });
  const [obs, setObs] = useState<{ start: string; end: string } | null>(null);
  const d = q.data;
  const tgt = d?.target || x;
  const chart = useMemo(() => {
    const p = d?.points || [];
    const sym = p.length < 40;
    const t = (v: any) => Date.parse(v.t);
    const marks = (d?.outages || []).filter((o: any) => o.kind === "down").map((o: any) => [{ xAxis: Date.parse(o.started_at), itemStyle: { color: "rgba(239,68,68,0.12)" } },
      { xAxis: o.recovered_at ? Date.parse(o.recovered_at) : Date.now() }]);
    const maint = (d?.maintenance || []).map((m: any) => [{ xAxis: Date.parse(m.start), itemStyle: { color: "rgba(148,163,184,0.12)" }, name: m.name }, { xAxis: Date.parse(m.end) }]);
    const fmt = (v: number) => new Date(v).toLocaleString(undefined, { hour: "2-digit", minute: "2-digit", hour12: false, timeZone: getTimezone(),
      ...((d?.bucket_seconds || 0) >= 3600 ? { month: "short", day: "2-digit" } : {}) });
    return {
      legend: { top: 0 }, grid: { left: 8, right: 16, top: 32, bottom: 8, containLabel: true },
      tooltip: { trigger: "axis", confine: true, formatter: (ps: any[]) => !ps?.length ? "" : `<b>${escHtml(fmtTime(new Date(ps[0].value[0])))}</b>` +
        ps.map((s) => `<br/>${s.marker}${escHtml(s.seriesName)}: <b>${s.value[1] == null ? "no data" : s.value[1].toFixed(1)}</b>`).join("") + "<br/><i>click for the raw checks</i>" },
      xAxis: { type: "time", ...axisStyle, axisLabel: { ...axisStyle.axisLabel, formatter: fmt } },
      yAxis: [{ type: "value", name: "ms", min: 0, ...axisStyle }, { type: "value", name: "loss %", min: 0, max: 100, ...axisStyle, splitLine: { show: false } }],
      series: [
        { name: "RTT avg", type: "line", showSymbol: sym, connectNulls: false, itemStyle: { color: PALETTES[theme][0] }, data: p.map((v: any) => [t(v), v.rtt]),
          markArea: { silent: true, data: [...marks, ...maint] } },
        { name: "RTT P95", type: "line", showSymbol: sym, connectNulls: false, lineStyle: { width: 1, type: "dashed" }, itemStyle: { color: PALETTES[theme][1] }, data: p.map((v: any) => [t(v), v.rtt_p95]) },
        { name: "Jitter", type: "line", showSymbol: sym, connectNulls: false, itemStyle: { color: PALETTES[theme][2] }, data: p.map((v: any) => [t(v), v.jitter]) },
        { name: "Loss %", type: "bar", yAxisIndex: 1, barMaxWidth: 6, itemStyle: { color: SERIES_ROLE[theme].alert }, data: p.map((v: any) => [t(v), v.loss]) },
      ],
    };
  }, [d, theme]);
  const pick = (p: any) => {
    const ts = Array.isArray(p?.value) ? p.value[0] : null;
    if (ts && d) setObs({ start: new Date(ts).toISOString(), end: new Date(ts + d.bucket_seconds * 1000).toISOString() });
  };
  const span = d?.timeline?.length ? Date.parse(d.timeline[d.timeline.length - 1].end) - Date.parse(d.timeline[0].start) : 0;
  return (
    <Drawer title={`${tgt.name} · ${tgt.address}`} onClose={onClose}>
      <div className="space-y-4">
        <div className="text-sm flex flex-wrap gap-x-4 gap-y-1"><StateDot s={tgt.state} /><span>since <Time v={tgt.state_since} /></span>
          <span>{tgt.isp} · {tgt.site}</span>{tgt.circuit && <span>circuit {tgt.circuit}{tgt.circuit_id && ` (${tgt.circuit_id})`}</span>}
          <span className="text-muted">{tgt.probes} probes every {tgt.interval_seconds}s · timeout {tgt.timeout_ms} ms · {tgt.retries} retr{tgt.retries === 1 ? "y" : "ies"} ·
            down after {tgt.down_after} failed checks · up after {tgt.up_after} good · degraded after {tgt.degrade_after} poor · cleared after {tgt.clear_after} healthy</span></div>
        {tgt.state === "paused" && tgt.paused_reason && <div className="text-sm text-muted">Paused: {tgt.paused_reason}</div>}
        {admin && <div className="flex flex-wrap items-center gap-2">
          <button className="btn" disabled={test.isPending} onClick={() => test.mutate()}>{test.isPending ? "Testing…" : "Test now"}</button>
          {test.data && <span className="text-sm">{test.data.received}/{test.data.sent} replies{test.data.rtt_avg != null && `, avg ${test.data.rtt_avg} ms`}
            {test.data.rtts?.length > 0 && <span className="text-muted"> ({test.data.rtts.join(" / ")} ms)</span>}
            {test.data.error && <span className="text-red-300"> {test.data.error}{test.data.error_class === "local" && " (local error on the SIEM, not packet loss)"}</span>}</span>}
          <span className="text-2xs text-muted">one-off check; does not change state or history</span></div>}
        <Loading q={q} />
        {d && <>
          <div className="kpi-grid">
            <Kpi label="Availability" value={<Avail v={tgt.availability} coverage={tgt.coverage_pct} />} sub={tgt.coverage_pct != null ? `${tgt.coverage_pct.toFixed(1)}% observed` : "no observations"} />
            <Kpi label="Outages" value={fmtNum(tgt.outages)} sub={`down ${dur(tgt.downtime_s)} · longest ${dur(tgt.longest_s)}`} />
            <Kpi label="RTT avg / P95 / P99" value={`${ms(tgt.rtt_ms)} / ${ms(tgt.rtt_p95_ms)}`} sub={`P99 ${tgt.rtt_p99_ms != null ? ms(tgt.rtt_p99_ms) : "needs ≥100 samples"} · ${fmtNum(tgt.rtt_samples)} replies`} />
            <Kpi label="Loss / jitter" value={`${pct(tgt.loss_pct)} / ${ms(tgt.jitter_ms)}`} sub={`${fmtNum(tgt.probes_sent)} probes · ${fmtNum(tgt.local_errors)} local errors`} />
          </div>
          <Card title="State timeline">
            {!d.timeline.length ? <Empty text="No state history in this range." /> : <>
              <div className="flex h-5 w-full overflow-hidden rounded" role="img" aria-label="State timeline">
                {d.timeline.map((s: any, i: number) => <div key={i} title={`${s.state}: ${fmtTime(s.start)} → ${fmtTime(s.end)} (${dur(s.duration_s)})`}
                  style={{ width: `${span ? (100 * (Date.parse(s.end) - Date.parse(s.start))) / span : 100}%`, background: STATE_HEX[s.state] || STATE_HEX.unknown }} />)}</div>
              <div className="flex justify-between text-2xs text-muted mt-1"><span>{fmtTime(d.timeline[0].start)}</span><span>{fmtTime(d.timeline[d.timeline.length - 1].end)}</span></div></>}
          </Card>
          <Card title="Round-trip time, jitter and loss" right={<span className="text-2xs text-muted">red bands: outages · grey: maintenance · gaps: no checks</span>}>
            {d.points.some((p: any) => !p.gap) ? <Chart height={280} option={chart} onClick={pick} ariaLabel={`RTT, jitter and loss for ${tgt.address}`} /> : <Empty text="No checks in this range yet." />}
          </Card>
          {obs && <Observations tid={x.id} start={obs.start} end={obs.end} onClose={() => setObs(null)} />}
          {inv.data && <Card title={`Investigation: ${inv.data.label}`}><p className="text-sm">{inv.data.explanation}</p>
            <ul className="text-xs mt-2 space-y-0.5">{inv.data.evidence.map((e: any, i: number) => <li key={i} className={e.ok ? "text-emerald-300" : "text-red-300"}>{e.ok ? "✓" : "✗"} {e.text}</li>)}</ul>
            <p className="text-2xs text-muted mt-2">{inv.data.note}</p></Card>}
          <Card title={`Outages (${d.outages.length})`} bodyClass="p-0">
            {!d.outages.length ? <Empty text="No outages in this range." /> :
              <TableWrap maxH="max-h-72"><table className="tbl"><thead><tr><th>Kind</th><th>Last healthy</th><th>First failure</th><th>Confirmed</th><th>Recovered</th>
                <th className="num">Duration</th><th>Incident</th></tr></thead>
                <tbody>{d.outages.map((o: any) => <tr key={o.id} className="cursor-pointer hover:bg-white/5" onClick={() => setObs({ start: o.last_ok_at || o.started_at, end: o.recovery_detected_at || new Date().toISOString() })}>
                  <td>{o.kind}{o.maintenance_id && <span className="pill bg-slate-700/60 text-slate-300 ml-1">maintenance</span>}</td>
                  <td className="text-xs"><Time v={o.last_ok_at} /></td><td className="text-xs"><Time v={o.started_at} /></td><td className="text-xs"><Time v={o.detected_at} /></td>
                  <td className="text-xs">{o.ongoing ? <span className="text-red-300">ongoing</span> : <Time v={o.recovered_at} />}</td>
                  <td className="num"><Dur s={o.duration_s} /></td><td>{o.incident_id ? `#${o.incident_id}` : "—"}</td></tr>)}</tbody></table></TableWrap>}
          </Card>
          {d.sdwan_outages.length > 0 && <Card title="SD-WAN outages on the same circuit" bodyClass="p-0">
            <TableWrap maxH="max-h-48"><table className="tbl"><thead><tr><th>Start</th><th>End</th><th className="num">Duration</th><th>Checks</th></tr></thead>
              <tbody>{d.sdwan_outages.map((o: any) => <tr key={o.id}><td><Time v={o.started_at} /></td><td>{o.ongoing ? "ongoing" : <Time v={o.recovered_at} />}</td>
                <td className="num"><Dur s={o.duration_s} /></td><td className="text-xs">{(o.evidence.checks || []).join(", ")}</td></tr>)}</tbody></table></TableWrap></Card>}
          <Card title={`State changes (${d.events.length})`} bodyClass="p-0">
            {!d.events.length ? <Empty text="No state changes in this range." /> :
              <TableWrap maxH="max-h-60"><table className="tbl"><thead><tr><th>Time</th><th>Change</th><th className="num">Previous lasted</th><th className="w-full">Detail</th></tr></thead>
                <tbody>{d.events.map((e: any, i: number) => <tr key={i}><td className="text-xs"><Time v={e.at} /></td><td className="whitespace-nowrap"><StateDot s={e.from} /> → <StateDot s={e.to} /></td>
                  <td className="num"><Dur s={e.previous_duration_s} /></td><td className="text-xs">{e.detail}</td></tr>)}</tbody></table></TableWrap>}
          </Card>
        </>}
      </div>
    </Drawer>
  );
}

function Observations({ tid, start, end, onClose }: { tid: number; start: string; end: string; onClose: () => void }) {
  const q = useQuery({ queryKey: ["wan-obs", tid, start, end], queryFn: () => api<any>(`/wan/targets/${tid}/observations`, { params: { start, end, limit: 500 } }) });
  return (
    <Card title={`Raw checks ${fmtTime(start)} → ${fmtTime(end)}`} right={<button className="btn py-0.5 text-xs" onClick={onClose}>Close</button>} bodyClass="p-0">
      <Loading q={q} />
      {q.data && (!q.data.items.length ? <Empty text="No checks in this interval (unobserved)." /> :
        <TableWrap maxH="max-h-72"><table className="tbl"><thead><tr><th>Observed</th><th>Replies</th><th>RTTs (ms)</th><th className="num">Jitter</th><th>State</th><th>Error</th>
          <th className="num">Sched. delay</th></tr></thead>
          <tbody>{q.data.items.map((o: any, i: number) => <tr key={i} className={o.up ? "" : "bg-red-500/5"}>
            <td className="text-xs whitespace-nowrap">{fmtTime(o.ts)}</td><td>{o.received}/{o.sent}{o.attempts > 1 && <span className="text-muted text-2xs"> ({o.attempts} tries)</span>}</td>
            <td className="font-mono text-xs">{o.rtts.length ? o.rtts.join(" / ") : "—"}</td><td className="num">{ms(o.jitter)}</td><td><StateDot s={o.state} /></td>
            <td className="text-xs">{o.error ? <span className={o.error_class === "local" ? "text-amber-300" : "text-red-300"}>{o.error_class === "local" && "local: "}{o.error}</span> : ""}</td>
            <td className="num text-xs">{o.sched_delay_ms ? `${(o.sched_delay_ms / 1000).toFixed(1)} s` : "—"}</td></tr>)}</tbody></table></TableWrap>)}
      {q.data?.truncated && <div className="text-2xs text-muted p-2">First 500 checks shown.</div>}
    </Card>
  );
}

// ------------------------------------------------------------------ add / edit target
function TargetForm({ t, onClose }: { t: any; onClose: () => void }) {
  const [f, setF] = useState<any>({ ...BLANK, ...t, isp_name: t.isp_name ?? "", site: t.site_override ?? t.site ?? "", enabled: t.state !== "paused" && t.enabled !== false });
  const circuits = useQuery({ queryKey: ["wan-circuits"], queryFn: () => api<any>("/wan/circuits"), staleTime: 60_000 });
  const num = ["interval_seconds", "probes", "timeout_ms", "retries", "down_after", "up_after", "degrade_after", "clear_after", "rtt_warn_ms", "loss_warn_pct"];
  const body = () => ({ ...Object.fromEntries(Object.keys(BLANK).map((k) => [k, num.includes(k) ? Number(f[k]) : f[k]])), isp_link_id: f.isp_link_id || null,
    jitter_warn_ms: f.jitter_warn_ms === "" || f.jitter_warn_ms == null ? null : Number(f.jitter_warn_ms) });
  const save = useMutation({ mutationFn: () => api(t.id ? `/isp/icmp/targets/${t.id}` : "/isp/icmp/targets", { method: t.id ? "PUT" : "POST", body: body() }), onSuccess: onClose });
  const del = useMutation({ mutationFn: () => api(`/isp/icmp/targets/${t.id}`, { method: "DELETE" }), onSuccess: onClose });
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value });
  const inp = (k: string, l: string, p: any = {}, hint?: string) => <Field label={l} hint={hint}><input className="input w-full" value={f[k] ?? ""} onChange={set(k)} {...p} /></Field>;
  return (
    <Modal title={t.id ? `Edit ${t.name}` : "Monitor an address"} onClose={onClose} wide>
      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
        {inp("name", "Name", { placeholder: "TTSL gateway – ASF Gurugram" })}{inp("address", "IP address or hostname", { placeholder: "182.156.1.33" })}
        <Field label="Circuit" hint="ISP, site and circuit ID come from the circuit">
          <select className="input w-full" value={f.isp_link_id || ""} onChange={(e) => setF({ ...f, isp_link_id: e.target.value ? Number(e.target.value) : null })}>
            <option value="">— not linked —</option>{(circuits.data?.items || []).map((c: any) => <option key={c.id} value={c.id}>{c.label} · {c.isp_name || c.as_org || "?"} · {c.effective_site || "no site"}</option>)}</select></Field>
        {inp("isp_name", "Provider (when not linked)", { placeholder: "Airtel" })}{inp("site", "Site override", {}, "empty: the circuit's site")}
        {inp("interval_seconds", "Check every (s)", { type: "number", min: 10 })}
        {inp("probes", "Echo requests per check", { type: "number", min: 1, max: 10 })}{inp("timeout_ms", "Reply timeout (ms)", { type: "number", min: 100 })}
        {inp("retries", "Retries before a check fails", { type: "number", min: 0, max: 3 })}
        {inp("down_after", "Down after N failed checks", { type: "number", min: 1 })}{inp("up_after", "Up after N good checks", { type: "number", min: 1 })}
        {inp("rtt_warn_ms", "Degraded when RTT ≥ (ms)", { type: "number" })}{inp("loss_warn_pct", "Degraded when loss ≥ (%)", { type: "number" })}
        {inp("jitter_warn_ms", "Degraded when jitter ≥ (ms)", { type: "number", placeholder: "off" })}
        {inp("degrade_after", "Degraded after N poor checks", { type: "number", min: 1, max: 20 }, "consecutive checks over a threshold")}
        {inp("clear_after", "Healthy again after N good checks", { type: "number", min: 1, max: 20 })}
        <label className="text-sm flex items-center gap-2"><input type="checkbox" checked={f.enabled} onChange={set("enabled")} />Monitoring enabled (unticked = paused)</label>
      </div>
      <p className="text-2xs text-muted mt-2">With the defaults (3 probes every 30 s, down after 3 failed checks, up after 2 good) an outage is confirmed after ~90 s of total silence and
        recovery after ~60 s of replies; degraded needs 3 poor checks in a row and 2 healthy ones to clear, so one slow check never flips the state.
        The outage is recorded from the first failed check; the last healthy check is kept as evidence.</p>
      {(save.error || del.error) && <div role="alert" className="text-sm text-red-400 mt-2">{((save.error || del.error) as Error).message}</div>}
      <div className="flex gap-2 mt-3">
        <button className="btn btn-primary" disabled={!f.name || !f.address || save.isPending} onClick={() => save.mutate()}>Save</button>
        {t.id && <button className="btn btn-danger ml-auto" onClick={() => confirm(`Stop monitoring ${t.address}? Its outage records stay; its check history is removed.`) && del.mutate()}>Remove</button>}
      </div>
    </Modal>
  );
}
