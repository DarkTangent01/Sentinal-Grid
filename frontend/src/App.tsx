import { ComponentType, lazy, ReactNode, Suspense, useEffect, useState } from "react";
import { Link, Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "./lib/api";
import { FilterProvider, Me, MeCtx } from "./lib/context";
import { setTimezone } from "./lib/format";
import { Layout } from "./components/Layout";
import { Login } from "./pages/Login";
import { SplashScreen } from "./components/Brand";
const Dashboard = /*#__PURE__*/ page(() => import("./pages/Dashboard"), "Dashboard");
const Sources = /*#__PURE__*/ page(() => import("./pages/TopN"), "Sources");
const Destinations = /*#__PURE__*/ page(() => import("./pages/TopN"), "Destinations");
const Ports = /*#__PURE__*/ page(() => import("./pages/TopN"), "Ports");
const Web = /*#__PURE__*/ page(() => import("./pages/Web"), "Web");
const Dns = /*#__PURE__*/ page(() => import("./pages/Dns"), "Dns");
const Security = /*#__PURE__*/ page(() => import("./pages/Security"), "Security");
const Alerts = /*#__PURE__*/ page(() => import("./pages/Alerts"), "Alerts");
const Explorer = /*#__PURE__*/ page(() => import("./pages/Explorer"), "Explorer");
const Investigate = /*#__PURE__*/ page(() => import("./pages/Investigate"), "Investigate");
const Firewalls = /*#__PURE__*/ page(() => import("./pages/Firewalls"), "Firewalls");
const Settings = /*#__PURE__*/ page(() => import("./pages/Settings"), "Settings");
const Hardening = /*#__PURE__*/ page(() => import("./pages/Hardening"), "Hardening");
const Policies = /*#__PURE__*/ page(() => import("./pages/Policies"), "Policies");
const PolicyDetail = /*#__PURE__*/ page(() => import("./pages/PolicyDetail"), "PolicyDetail");
const Shadow = /*#__PURE__*/ page(() => import("./pages/Shadow"), "Shadow");
const IncidentDetail = /*#__PURE__*/ page(() => import("./pages/Incidents"), "IncidentDetail");
const Incidents = /*#__PURE__*/ page(() => import("./pages/Incidents"), "Incidents");
const ThreatIntel = /*#__PURE__*/ page(() => import("./pages/ThreatIntel"), "ThreatIntel");
const Assets = /*#__PURE__*/ page(() => import("./pages/Assets"), "Assets");
const Geo = /*#__PURE__*/ page(() => import("./pages/Geo"), "Geo");
const Vpn = /*#__PURE__*/ page(() => import("./pages/Vpn"), "Vpn");
const Compliance = /*#__PURE__*/ page(() => import("./pages/Compliance"), "Compliance");
const Drift = /*#__PURE__*/ page(() => import("./pages/Drift"), "Drift");
const Notifications = /*#__PURE__*/ page(() => import("./pages/Notifications"), "Notifications");
const Searches = /*#__PURE__*/ page(() => import("./pages/Searches"), "Searches");
const Reports = /*#__PURE__*/ page(() => import("./pages/Reports"), "Reports");
const Search = /*#__PURE__*/ page(() => import("./pages/Search"), "Search");
const Detections = /*#__PURE__*/ page(() => import("./pages/Detections"), "Detections");
const WorkbookView = /*#__PURE__*/ page(() => import("./pages/Workbooks"), "WorkbookView");
const Workbooks = /*#__PURE__*/ page(() => import("./pages/Workbooks"), "Workbooks");
const Watchlists = /*#__PURE__*/ page(() => import("./pages/Watchlists"), "Watchlists");
const Hunting = /*#__PURE__*/ page(() => import("./pages/Hunting"), "Hunting");
const Automation = /*#__PURE__*/ page(() => import("./pages/Automation"), "Automation");
const EntityGraph = /*#__PURE__*/ page(() => import("./pages/EntityGraph"), "EntityGraph");
const Isp = /*#__PURE__*/ page(() => import("./pages/Isp"), "Isp");
const FirewallHealth = /*#__PURE__*/ page(() => import("./pages/FirewallHealth"), "FirewallHealth");
const VpnTunnels = /*#__PURE__*/ page(() => import("./pages/VpnTunnels"), "VpnTunnels");
const Bgp = /*#__PURE__*/ page(() => import("./pages/Bgp"), "Bgp");
const Identity = /*#__PURE__*/ page(() => import("./pages/Identity"), "Identity");
const Iac = /*#__PURE__*/ page(() => import("./pages/iac/IacPage"), "Iac");
const LogSources = /*#__PURE__*/ page(() => import("./pages/LogSources"), "LogSources");
const Switches = /*#__PURE__*/ page(() => import("./pages/switches/SwitchesPage"), "Switches");
const SwitchDetail = /*#__PURE__*/ page(() => import("./pages/switches/SwitchDetail"), "SwitchDetail");
const Deployments = /*#__PURE__*/ page(() => import("./pages/Deployments"), "Deployments");
const InterfaceDetail = /*#__PURE__*/ page(() => import("./pages/devices/InterfaceDetail"), "InterfaceDetail");
const InterfacesPage = /*#__PURE__*/ page(() => import("./pages/devices/InterfacesPage"), "InterfacesPage");
const Tacacs = /*#__PURE__*/ page(() => import("./pages/tacacs/TacacsPage"), "Tacacs");
const NmsDashboard = /*#__PURE__*/ page(() => import("./pages/nms/NmsDashboard"), "NmsDashboard");
const NmsAnalytics = /*#__PURE__*/ page(() => import("./pages/nms/Analytics"), "NmsAnalytics");
const DependenciesPage = /*#__PURE__*/ page(() => import("./pages/nms/Operations"), "DependenciesPage");
const SocOverview = /*#__PURE__*/ page(() => import("./pages/Soc"), "SocOverview");
const AttackPage = /*#__PURE__*/ page(() => import("./pages/Soc"), "AttackPage");
const RiskPage = /*#__PURE__*/ page(() => import("./pages/Soc"), "RiskPage");
const ResponsePage = /*#__PURE__*/ page(() => import("./pages/Soc"), "ResponsePage");
const NetworkSecurity = /*#__PURE__*/ page(() => import("./pages/NetworkSecurity"), "NetworkSecurity");
const ConfigsPage = /*#__PURE__*/ page(() => import("./pages/nms/Configs"), "ConfigsPage");
const NetCompliancePage = /*#__PURE__*/ page(() => import("./pages/nms/NetCompliance"), "NetCompliancePage");
const TrafficPage = /*#__PURE__*/ page(() => import("./pages/nms/Traffic"), "TrafficPage");
const SelfMonPage = /*#__PURE__*/ page(() => import("./pages/nms/SelfMon"), "SelfMonPage");
const AccessPage = /*#__PURE__*/ page(() => import("./pages/nms/Access"), "AccessPage");
const MaintenancePage = /*#__PURE__*/ page(() => import("./pages/nms/Operations"), "MaintenancePage");
const ServicesPage = /*#__PURE__*/ page(() => import("./pages/nms/Operations"), "ServicesPage");
const SnmpPage = /*#__PURE__*/ page(() => import("./pages/snmp/SnmpPage"), "SnmpPage");
const Wireless = /*#__PURE__*/ page(() => import("./pages/wireless/WirelessPage"), "Wireless");
import { NoAccess, ProductSelect } from "./pages/ProductSelect";
import { PRODUCT, Product, buildProducts, entryTarget, forgetProducts, lastProduct, productOfLocation, rememberProduct } from "./lib/products";

// Build-time product (npm run build:grid | build:nms set VITE_PRODUCT): literal comparisons, so the bundler drops the other product's
// routes and, with them, its lazily loaded pages (the page() calls are marked pure). Ownership: lib/products.ts OWN.
const WITH_GRID = import.meta.env.VITE_PRODUCT !== "nms";
const WITH_NMS = import.meta.env.VITE_PRODUCT !== "grid";

/** Route-level code splitting: a page, and the chart/map libraries only it uses, load on its first visit. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function page(load: () => Promise<Record<string, any>>, name: string) {
  return lazy(() => load().then((m) => ({ default: m[name] as ComponentType<any> })));
}

export default function App() {
  const [me, setMe] = useState<Me | null | undefined>(undefined);
  const qc = useQueryClient();
  const navigate = useNavigate();
  // a single-product build (BUILD_PRODUCT) offers only its product: the gate, switcher and start setting follow from this
  const loadMe = () => api<Me>("/auth/me").then((m) => { setTimezone(m.timezone); setMe({ ...m, products: buildProducts(m.products) }); }).catch(() => setMe(null));
  useEffect(() => {
    loadMe();
    const h = () => setMe(null);
    window.addEventListener("siem:unauthorized", h);
    return () => window.removeEventListener("siem:unauthorized", h);
  }, []);
  if (me === undefined) return <SplashScreen />;
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
  // the product accent (sky for Sentinel NMS, violet for Sentinel Grid) follows the product on screen (index.css tokens)
  useEffect(() => {
    document.documentElement.dataset.product = product;
    return () => { delete document.documentElement.dataset.product; };
  }, [product]);
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
            {WITH_GRID && <Route path="/grid" element={<Dashboard />} />}
            {WITH_NMS && <Route path="/nms" element={<NmsDashboard />} />}
            {WITH_NMS && <Route path="/nms/analytics" element={<NmsAnalytics />} />}
            {WITH_NMS && <Route path="/nms/access" element={<AccessPage />} />}
            {WITH_NMS && <Route path="/nms/services" element={<ServicesPage />} />}
            {WITH_NMS && <Route path="/nms/maintenance" element={<MaintenancePage />} />}
            {WITH_NMS && <Route path="/nms/dependencies" element={<DependenciesPage />} />}
            {WITH_NMS && <Route path="/nms/configs" element={<ConfigsPage />} />}
            {WITH_NMS && <Route path="/network-compliance" element={<NetCompliancePage />} />}
            {WITH_GRID && <Route path="/soc" element={<SocOverview />} />}
            {WITH_GRID && <Route path="/attack" element={<AttackPage />} />}
            {WITH_GRID && <Route path="/risk" element={<RiskPage />} />}
            {WITH_GRID && <Route path="/response" element={<ResponsePage />} />}
            {WITH_GRID && <Route path="/network-security" element={<NetworkSecurity />} />}
            {WITH_NMS && <Route path="/nms/traffic" element={<TrafficPage />} />}
            {WITH_NMS && <Route path="/nms/flows" element={<Navigate to="/nms/traffic" replace />} />}
            {WITH_NMS && <Route path="/nms/monitoring" element={<SelfMonPage />} />}
            {WITH_NMS && <Route path="/snmp" element={<SnmpPage />} />}
            {WITH_GRID && <Route path="/sources" element={<Sources />} />}
            {WITH_GRID && <Route path="/destinations" element={<Destinations />} />}
            {WITH_GRID && <Route path="/ports" element={<Ports />} />}
            {WITH_GRID && <Route path="/web" element={<Web />} />}
            {WITH_GRID && <Route path="/dns" element={<Dns />} />}
            {WITH_GRID && <Route path="/security" element={<Security />} />}
            <Route path="/alerts" element={<Alerts />} />
            {WITH_GRID && <Route path="/explorer" element={<Explorer />} />}
            {WITH_GRID && <Route path="/investigate/:ip" element={<Investigate />} />}
            {WITH_NMS && <Route path="/firewalls" element={<Firewalls />} />}
            {WITH_NMS && <Route path="/hardening" element={<Hardening />} />}
            {WITH_NMS && <Route path="/policies" element={<Policies />} />}
            {WITH_NMS && <Route path="/policies/shadow" element={<Shadow />} />}
            {WITH_NMS && <Route path="/policies/:fw/:vdom/:pid" element={<PolicyDetail />} />}
            {WITH_GRID && <Route path="/incidents" element={<Incidents />} />}
            {WITH_GRID && <Route path="/incidents/:id" element={<IncidentDetail />} />}
            {WITH_GRID && <Route path="/threat-intel" element={<ThreatIntel />} />}
            {WITH_GRID && <Route path="/assets" element={<Assets />} />}
            {WITH_GRID && <Route path="/geo" element={<Geo />} />}
            {WITH_GRID && <Route path="/vpn" element={<Vpn />} />}
            {WITH_GRID && <Route path="/compliance" element={<Compliance />} />}
            {WITH_NMS && <Route path="/drift" element={<Drift />} />}
            <Route path="/notifications" element={<Notifications />} />
            {WITH_GRID && <Route path="/searches" element={<Searches />} />}
            <Route path="/reports" element={<Reports />} />
            {WITH_GRID && <Route path="/search" element={<Search />} />}
            {WITH_GRID && <Route path="/hunting" element={<Hunting />} />}
            {WITH_GRID && <Route path="/detections" element={<Detections />} />}
            {WITH_GRID && <Route path="/workbooks" element={<Workbooks />} />}
            {WITH_GRID && <Route path="/workbooks/:id" element={<WorkbookView />} />}
            {WITH_GRID && <Route path="/watchlists" element={<Watchlists />} />}
            {WITH_GRID && <Route path="/automation" element={<Automation />} />}
            {WITH_GRID && <Route path="/graph" element={<EntityGraph />} />}
            {WITH_NMS && <Route path="/isp" element={<Isp />} />}
            {WITH_NMS && <Route path="/wireless" element={<Wireless />} />}
            {WITH_NMS && <Route path="/fw-health" element={<FirewallHealth />} />}
            {WITH_NMS && <Route path="/vpn-tunnels" element={<VpnTunnels />} />}
            {WITH_NMS && <Route path="/bgp" element={<Bgp />} />}
            {WITH_GRID && <Route path="/identity" element={<Identity />} />}
            {WITH_NMS && <Route path="/iac" element={<Iac />} />}
            {WITH_NMS && <Route path="/switches" element={<Switches />} />}
            {WITH_NMS && <Route path="/switches/:id" element={<SwitchDetail />} />}
            {WITH_NMS && <Route path="/switches/:id/interfaces/:ifindex" element={<InterfaceDetail />} />}
            {WITH_NMS && <Route path="/nms/interfaces" element={<InterfacesPage />} />}
            {WITH_NMS && <Route path="/tacacs" element={<Tacacs />} />}
            {WITH_GRID && <Route path="/log-sources" element={<LogSources />} />}
            <Route path="/settings" element={<Settings onMeChange={loadMe} />} />
            <Route path="/admin/deployments" element={<Deployments />} />
            <Route path="*" element={<Notice title="Page not found">This address does not exist. Use the sidebar to continue.</Notice>} />
          </Routes>
        </Suspense>
  );
}
