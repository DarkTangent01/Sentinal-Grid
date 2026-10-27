import { useEffect, useState } from "react";
import { Route, Routes } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "./lib/api";
import { FilterProvider, Me, MeCtx } from "./lib/context";
import { setTimezone } from "./lib/format";
import { Layout } from "./components/Layout";
import { Login } from "./pages/Login";
import { Dashboard } from "./pages/Dashboard";
import { Sources, Destinations, Ports } from "./pages/TopN";
import { Web } from "./pages/Web";
import { Dns } from "./pages/Dns";
import { Security } from "./pages/Security";
import { Alerts } from "./pages/Alerts";
import { Explorer } from "./pages/Explorer";
import { Investigate } from "./pages/Investigate";
import { Firewalls } from "./pages/Firewalls";
import { Settings } from "./pages/Settings";
import { Hardening } from "./pages/Hardening";
import { Policies } from "./pages/Policies";
import { PolicyDetail } from "./pages/PolicyDetail";
import { Shadow } from "./pages/Shadow";
import { IncidentDetail, Incidents } from "./pages/Incidents";
import { ThreatIntel } from "./pages/ThreatIntel";
import { Assets } from "./pages/Assets";
import { Geo } from "./pages/Geo";
import { Vpn } from "./pages/Vpn";
import { Compliance } from "./pages/Compliance";
import { Drift } from "./pages/Drift";
import { Notifications } from "./pages/Notifications";
import { Searches } from "./pages/Searches";
import { Reports } from "./pages/Reports";
import { Search } from "./pages/Search";
import { Detections } from "./pages/Detections";
import { WorkbookView, Workbooks } from "./pages/Workbooks";
import { Watchlists } from "./pages/Watchlists";
import { Hunting } from "./pages/Hunting";
import { Automation } from "./pages/Automation";
import { EntityGraph } from "./pages/EntityGraph";
import { Isp } from "./pages/Isp";
import { FirewallHealth } from "./pages/FirewallHealth";
import { VpnTunnels } from "./pages/VpnTunnels";
import { Bgp } from "./pages/Bgp";
import { Identity } from "./pages/Identity";
import { LogSources } from "./pages/LogSources";

export default function App() {
  const [me, setMe] = useState<Me | null | undefined>(undefined);
  const qc = useQueryClient();
  const loadMe = () => api<Me>("/auth/me").then((m) => { setTimezone(m.timezone); setMe(m); }).catch(() => setMe(null));
  useEffect(() => {
    loadMe();
    const h = () => setMe(null);
    window.addEventListener("siem:unauthorized", h);
    return () => window.removeEventListener("siem:unauthorized", h);
  }, []);
  if (me === undefined) return <div className="p-6 text-muted">Loading…</div>;
  if (me === null) return <Login onLogin={loadMe} />;
  const logout = async () => { await api("/auth/logout", { method: "POST" }).catch(() => null); qc.clear(); setMe(null); };
  return (
    <MeCtx.Provider value={me}>
      <FilterProvider>
        <Layout onLogout={logout}>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/sources" element={<Sources />} />
            <Route path="/destinations" element={<Destinations />} />
            <Route path="/ports" element={<Ports />} />
            <Route path="/web" element={<Web />} />
            <Route path="/dns" element={<Dns />} />
            <Route path="/security" element={<Security />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/explorer" element={<Explorer />} />
            <Route path="/investigate/:ip" element={<Investigate />} />
            <Route path="/firewalls" element={<Firewalls />} />
            <Route path="/hardening" element={<Hardening />} />
            <Route path="/policies" element={<Policies />} />
            <Route path="/policies/shadow" element={<Shadow />} />
            <Route path="/policies/:fw/:vdom/:pid" element={<PolicyDetail />} />
            <Route path="/incidents" element={<Incidents />} />
            <Route path="/incidents/:id" element={<IncidentDetail />} />
            <Route path="/threat-intel" element={<ThreatIntel />} />
            <Route path="/assets" element={<Assets />} />
            <Route path="/geo" element={<Geo />} />
            <Route path="/vpn" element={<Vpn />} />
            <Route path="/compliance" element={<Compliance />} />
            <Route path="/drift" element={<Drift />} />
            <Route path="/notifications" element={<Notifications />} />
            <Route path="/searches" element={<Searches />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/search" element={<Search />} />
            <Route path="/hunting" element={<Hunting />} />
            <Route path="/detections" element={<Detections />} />
            <Route path="/workbooks" element={<Workbooks />} />
            <Route path="/workbooks/:id" element={<WorkbookView />} />
            <Route path="/watchlists" element={<Watchlists />} />
            <Route path="/automation" element={<Automation />} />
            <Route path="/graph" element={<EntityGraph />} />
            <Route path="/isp" element={<Isp />} />
            <Route path="/fw-health" element={<FirewallHealth />} />
            <Route path="/vpn-tunnels" element={<VpnTunnels />} />
            <Route path="/bgp" element={<Bgp />} />
            <Route path="/identity" element={<Identity />} />
            <Route path="/log-sources" element={<LogSources />} />
            <Route path="/settings" element={<Settings onMeChange={loadMe} />} />
          </Routes>
        </Layout>
      </FilterProvider>
    </MeCtx.Provider>
  );
}
