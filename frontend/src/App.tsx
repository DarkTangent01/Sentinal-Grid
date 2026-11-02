import { ComponentType, lazy, ReactNode, Suspense, useEffect, useState } from "react";
import { Link, Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "./lib/api";
import { FilterProvider, Me, MeCtx } from "./lib/context";
import { setTimezone } from "./lib/format";
import { Layout } from "./components/Layout";
import { Login } from "./pages/Login";
const Dashboard = page(() => import("./pages/Dashboard"), "Dashboard");
const Sources = page(() => import("./pages/TopN"), "Sources");
const Destinations = page(() => import("./pages/TopN"), "Destinations");
const Ports = page(() => import("./pages/TopN"), "Ports");
const Web = page(() => import("./pages/Web"), "Web");
const Dns = page(() => import("./pages/Dns"), "Dns");
const Security = page(() => import("./pages/Security"), "Security");
const Alerts = page(() => import("./pages/Alerts"), "Alerts");
const Explorer = page(() => import("./pages/Explorer"), "Explorer");
const Investigate = page(() => import("./pages/Investigate"), "Investigate");
const Firewalls = page(() => import("./pages/Firewalls"), "Firewalls");
const Settings = page(() => import("./pages/Settings"), "Settings");
const Hardening = page(() => import("./pages/Hardening"), "Hardening");
const Policies = page(() => import("./pages/Policies"), "Policies");
const PolicyDetail = page(() => import("./pages/PolicyDetail"), "PolicyDetail");
const Shadow = page(() => import("./pages/Shadow"), "Shadow");
const IncidentDetail = page(() => import("./pages/Incidents"), "IncidentDetail");
const Incidents = page(() => import("./pages/Incidents"), "Incidents");
const ThreatIntel = page(() => import("./pages/ThreatIntel"), "ThreatIntel");
const Assets = page(() => import("./pages/Assets"), "Assets");
const Geo = page(() => import("./pages/Geo"), "Geo");
const Vpn = page(() => import("./pages/Vpn"), "Vpn");
const Compliance = page(() => import("./pages/Compliance"), "Compliance");
const Drift = page(() => import("./pages/Drift"), "Drift");
const Notifications = page(() => import("./pages/Notifications"), "Notifications");
const Searches = page(() => import("./pages/Searches"), "Searches");
const Reports = page(() => import("./pages/Reports"), "Reports");
const Search = page(() => import("./pages/Search"), "Search");
const Detections = page(() => import("./pages/Detections"), "Detections");
const WorkbookView = page(() => import("./pages/Workbooks"), "WorkbookView");
const Workbooks = page(() => import("./pages/Workbooks"), "Workbooks");
const Watchlists = page(() => import("./pages/Watchlists"), "Watchlists");
const Hunting = page(() => import("./pages/Hunting"), "Hunting");
const Automation = page(() => import("./pages/Automation"), "Automation");
const EntityGraph = page(() => import("./pages/EntityGraph"), "EntityGraph");
const Isp = page(() => import("./pages/Isp"), "Isp");
const FirewallHealth = page(() => import("./pages/FirewallHealth"), "FirewallHealth");
const VpnTunnels = page(() => import("./pages/VpnTunnels"), "VpnTunnels");
const Bgp = page(() => import("./pages/Bgp"), "Bgp");
const Identity = page(() => import("./pages/Identity"), "Identity");
const Iac = page(() => import("./pages/iac/IacPage"), "Iac");
const LogSources = page(() => import("./pages/LogSources"), "LogSources");
const Switches = page(() => import("./pages/switches/SwitchesPage"), "Switches");
const SwitchDetail = page(() => import("./pages/switches/SwitchDetail"), "SwitchDetail");
const Tacacs = page(() => import("./pages/tacacs/TacacsPage"), "Tacacs");
const NmsDashboard = page(() => import("./pages/nms/NmsDashboard"), "NmsDashboard");
const NmsAnalytics = page(() => import("./pages/nms/Analytics"), "NmsAnalytics");
const DependenciesPage = page(() => import("./pages/nms/Operations"), "DependenciesPage");
const MaintenancePage = page(() => import("./pages/nms/Operations"), "MaintenancePage");
const ServicesPage = page(() => import("./pages/nms/Operations"), "ServicesPage");
const SnmpPage = page(() => import("./pages/snmp/SnmpPage"), "SnmpPage");
const Wireless = page(() => import("./pages/wireless/WirelessPage"), "Wireless");
import { NoAccess, ProductSelect } from "./pages/ProductSelect";
import { PRODUCT, Product, entryTarget, forgetProducts, lastProduct, productOfLocation, rememberProduct } from "./lib/products";

/** Route-level code splitting: a page, and the chart/map libraries only it uses, load on its first visit. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function page(load: () => Promise<Record<string, any>>, name: string) {
  return lazy(() => load().then((m) => ({ default: m[name] as ComponentType<any> })));
}

export default function App() {
  const [me, setMe] = useState<Me | null | undefined>(undefined);
  const qc = useQueryClient();
  const navigate = useNavigate();
  const loadMe = () => api<Me>("/auth/me").then((m) => { setTimezone(m.timezone); setMe(m); }).catch(() => setMe(null));
  useEffect(() => {
    loadMe();
    const h = () => setMe(null);
    window.addEventListener("siem:unauthorized", h);
    return () => window.removeEventListener("siem:unauthorized", h);
  }, []);
  if (me === undefined) return <div className="p-6 text-muted">Loading…</div>;
  if (me === null) return <Login onLogin={loadMe} />;
  const logout = async () => {
    await api("/auth/logout", { method: "POST" }).catch(() => null);
    qc.clear();
    forgetProducts();                                         // last product / page belong to this session only
    navigate("/", { replace: true });                          // the next sign-in starts at the product gate
    setMe(null);
  };
  return (
    <MeCtx.Provider value={me}>
      <Routes>
        <Route path="/" element={<Navigate to={entryTarget(me)} replace />} />
        <Route path="/select-product" element={!me.products.length ? <Navigate to="/no-access" replace /> : <ProductSelect me={me} onMeChange={loadMe} onLogout={logout} />} />
        <Route path="/no-access" element={me.products.length ? <Navigate to={entryTarget(me)} replace /> : <NoAccess me={me} onLogout={logout} />} />
        <Route path="*" element={!me.products.length ? <Navigate to="/no-access" replace /> : <Shell me={me} onLogout={logout} loadMe={loadMe} />} />
      </Routes>
    </MeCtx.Provider>
  );
}

/** Product shell: the URL decides the product (shared pages keep the last product of this session); a page of a
 *  product the account may not use is refused here and, independently, by the API (backend/app/products.py). */
function Shell({ me, onLogout, loadMe }: { me: Me; onLogout: () => void; loadMe: () => void }) {
  const loc = useLocation();
  const owner = productOfLocation(loc.pathname, loc.search);
  const product: Product = owner && me.products.includes(owner) ? owner : lastProduct(me.products)!;
  useEffect(() => { if (owner && me.products.includes(owner)) rememberProduct(owner, loc.pathname + loc.search); }, [owner, loc.pathname, loc.search, me.products]);
  useEffect(() => { document.title = PRODUCT[product].name; }, [product]);
  return (
    <FilterProvider>
      <Layout onLogout={onLogout} product={product}>
        {owner && !me.products.includes(owner) ? <ProductDenied want={owner} have={product} /> : <Pages loadMe={loadMe} />}
      </Layout>
    </FilterProvider>
  );
}

function ProductDenied({ want, have }: { want: Product; have: Product }) {
  return <Notice title={`No access to ${PRODUCT[want].name}`}>
    This page belongs to {PRODUCT[want].name}, which your account cannot use. Ask an administrator for access, or return to{" "}
    <Link className="link" to={PRODUCT[have].home}>{PRODUCT[have].name}</Link>.</Notice>;
}

function Notice({ title, children }: { title: string; children: ReactNode }) {
  return <div role="alert" className="card !block max-w-xl mx-auto mt-10 p-6 text-center"><h1 className="text-lg font-bold mb-2">{title}</h1>
    <p className="text-sm text-muted">{children}</p></div>;
}

function Pages({ loadMe }: { loadMe: () => void }) {
  return (
        <Suspense fallback={<div role="status" className="p-6 text-sm text-muted">Loading…</div>}>
          <Routes>
            <Route path="/grid" element={<Dashboard />} />
            <Route path="/nms" element={<NmsDashboard />} />
            <Route path="/nms/analytics" element={<NmsAnalytics />} />
            <Route path="/nms/services" element={<ServicesPage />} />
            <Route path="/nms/maintenance" element={<MaintenancePage />} />
            <Route path="/nms/dependencies" element={<DependenciesPage />} />
            <Route path="/snmp" element={<SnmpPage />} />
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
            <Route path="/wireless" element={<Wireless />} />
            <Route path="/fw-health" element={<FirewallHealth />} />
            <Route path="/vpn-tunnels" element={<VpnTunnels />} />
            <Route path="/bgp" element={<Bgp />} />
            <Route path="/identity" element={<Identity />} />
            <Route path="/iac" element={<Iac />} />
            <Route path="/switches" element={<Switches />} />
            <Route path="/switches/:id" element={<SwitchDetail />} />
            <Route path="/tacacs" element={<Tacacs />} />
            <Route path="/log-sources" element={<LogSources />} />
            <Route path="/settings" element={<Settings onMeChange={loadMe} />} />
            <Route path="*" element={<Notice title="Page not found">This address does not exist. Use the sidebar to continue.</Notice>} />
          </Routes>
        </Suspense>
  );
}
