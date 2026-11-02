import { createContext, ReactNode, useContext, useEffect, useMemo, useState } from "react";
import { useQuery, useQueryClient, UseQueryOptions } from "@tanstack/react-query";
import { api, Params } from "./api";

export type RangeKey = "5m" | "15m" | "1h" | "24h" | "7d" | "custom";

interface GlobalFilter {
  range: RangeKey; setRange: (r: RangeKey) => void;
  start: string; end: string; setCustom: (s: string, e: string) => void;
  refreshSec: number; setRefreshSec: (n: number) => void;
  firewallId: string; setFirewallId: (s: string) => void;
  site: string; setSite: (s: string) => void;
  params: Params;
}

const Ctx = createContext<GlobalFilter | null>(null);

function load<T>(k: string, d: T): T {
  try { const v = localStorage.getItem(k); return v ? (JSON.parse(v) as T) : d; } catch { return d; }
}
function save(k: string, v: unknown) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* ignore */ } }

export function FilterProvider({ children }: { children: ReactNode }) {
  const [range, setRangeS] = useState<RangeKey>(load("siem.range", "24h"));
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [refreshSec, setRefreshS] = useState<number>(load("siem.refresh", 0));
  const [firewallId, setFirewallId] = useState("");
  const [site, setSite] = useState("");

  const params = useMemo<Params>(() => {
    const p: Params = {};
    if (range === "custom" && start && end) {
      p.start = new Date(start).toISOString();
      p.end = new Date(end).toISOString();
    } else p.range = range === "custom" ? "24h" : range;
    if (firewallId) p.firewall_id = [firewallId];
    if (site) p.site = [site];
    return p;
  }, [range, start, end, firewallId, site]);

  // memoised: a new object every render re-rendered every page and chart under the provider
  const v = useMemo<GlobalFilter>(() => ({
    range, setRange: (r) => { setRangeS(r); save("siem.range", r); },
    start, end, setCustom: (s, e) => { setStart(s); setEnd(e); setRangeS("custom"); },
    refreshSec, setRefreshSec: (n) => { setRefreshS(n); save("siem.refresh", n); },
    firewallId, setFirewallId, site, setSite, params,
  }), [range, start, end, refreshSec, firewallId, site, params]);
  return <Ctx.Provider value={v}>{children}</Ctx.Provider>;
}

export function useGlobal() {
  const c = useContext(Ctx);
  if (!c) throw new Error("FilterProvider missing");
  return c;
}

/** Query bound to the global time range / firewall filter, with auto-refresh. */
export function useData<T = any>(path: string, extra?: Params, opts?: Partial<UseQueryOptions<T>>) {
  const g = useGlobal();
  const params = { ...g.params, ...(extra || {}) };
  return useQuery<T>({
    queryKey: [path, params],
    queryFn: ({ signal }) => api<T>(path, { params, signal }),  // signal: a superseded range/filter aborts the old request
    refetchInterval: g.refreshSec ? g.refreshSec * 1000 : false,
    placeholderData: (prev) => prev,
    ...(opts as object),
  });
}

export interface Me { id: number; username: string; role: "admin" | "analyst"; timezone: string;
  products: ("grid" | "nms")[]; default_product?: "grid" | "nms" | null }
export const MeCtx = createContext<Me | null>(null);
export const useMe = () => useContext(MeCtx)!;

/** Time of the newest successful query. Reads the query cache instead of global state, so a query finishing
 *  re-renders only the component that shows this, not the whole app. */
export function useLastUpdated(): number | null {
  const qc = useQueryClient();
  const [t, setT] = useState<number | null>(null);
  useEffect(() => qc.getQueryCache().subscribe((e) => {
    if (e.type === "updated" && e.action.type === "success") setT(e.query.state.dataUpdatedAt);
  }), [qc]);
  return t;
}
