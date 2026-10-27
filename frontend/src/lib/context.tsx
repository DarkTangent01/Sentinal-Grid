import { createContext, ReactNode, useContext, useMemo, useState } from "react";
import { useQuery, UseQueryOptions } from "@tanstack/react-query";
import { api, Params } from "./api";

export type RangeKey = "5m" | "15m" | "1h" | "24h" | "7d" | "custom";

interface GlobalFilter {
  range: RangeKey; setRange: (r: RangeKey) => void;
  start: string; end: string; setCustom: (s: string, e: string) => void;
  refreshSec: number; setRefreshSec: (n: number) => void;
  firewallId: string; setFirewallId: (s: string) => void;
  site: string; setSite: (s: string) => void;
  lastUpdated: Date | null; markUpdated: () => void;
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
  const [lastUpdated, setLast] = useState<Date | null>(null);

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

  const v: GlobalFilter = {
    range, setRange: (r) => { setRangeS(r); save("siem.range", r); },
    start, end, setCustom: (s, e) => { setStart(s); setEnd(e); setRangeS("custom"); },
    refreshSec, setRefreshSec: (n) => { setRefreshS(n); save("siem.refresh", n); },
    firewallId, setFirewallId, site, setSite,
    lastUpdated, markUpdated: () => setLast(new Date()), params,
  };
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
    queryFn: async () => {
      const r = await api<T>(path, { params });
      g.markUpdated();
      return r;
    },
    refetchInterval: g.refreshSec ? g.refreshSec * 1000 : false,
    placeholderData: (prev) => prev,
    ...(opts as object),
  });
}

export interface Me { id: number; username: string; role: "admin" | "analyst"; timezone: string }
export const MeCtx = createContext<Me | null>(null);
export const useMe = () => useContext(MeCtx)!;
