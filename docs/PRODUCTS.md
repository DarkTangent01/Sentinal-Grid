# Products: Sentinel Grid and Sentinel NMS

The application ships as two products: **Sentinel Grid** (SIEM) and **Sentinel NMS** (network monitoring). They share
one sign-in, session, API, database, worker and set of integrations. The split covers navigation, landing pages and
authorization; it does not duplicate data or services.

```
Login (shared) → /  ──▶ entry gate ──┬─▶ /select-product   (account has both products, no saved default)
                                     ├─▶ /grid or /nms      (one product, or a saved default)
                                     └─▶ /no-access         (no product assigned)
```

## Access model

| Permission | Where it comes from |
|---|---|
| `grid.access` | `"grid"` in `users.products` |
| `nms.access` | `"nms"` in `users.products` |
| `admin.access` | `users.role = admin`. Administrators can use every product, whatever `users.products` says. |

The fine-grained permissions are unchanged: admin-only configuration, IaC roles (`iac_roles`) and TACACS+ roles
(`tacacs_roles`) still apply inside a product.

**Migration `0020_product_access`:**

- Every existing account receives both products. Before the split every account could open every page, so nobody
  loses access.
- Accounts created afterwards get **no** product unless an administrator assigns one: in Settings → Users, or
  `products` on `POST /api/users`.
- An account without a product can sign in, but sees only the "no product access" page.
- Changing an account's products takes effect on its next request. The session is not ended.

**Start preference:** `users.default_product` is the user's "Start in" choice, set in Settings → Preferences or with
"Remember my choice" on the selector.

- It is ignored if the account loses that product.
- An account with both products sees the selector after each sign-in unless it has set a default.

## Backend enforcement

`backend/app/products.py` maps API prefixes to products. The check runs inside `current_user`, so every authenticated
API call goes through it. Prefixes match on a path-segment boundary, so `/api/vpn` (Grid) does not match
`/api/vpn-tunnels` (NMS).

- Refused calls return 403 ("your account has no access to Sentinel NMS") and write a `product_access_denied` audit
  entry.
- `test_every_api_route_is_classified` fails if a new router is not assigned to a product or declared shared.
- **Alerts** are shared but scoped. An account sees, triages and opens only the alerts of products it can use.
  `GET /api/alerts?product=grid|nms` narrows the list further; asking for another product never widens access.
  - Network-operations rules are NMS: `isp_outage`, `icmp_down`, `fw_*`, `log_feed_gap`, `vpn_tunnel_down`, `bgp_*`,
    `switch_*`, `wan_*`, `iac_drift`, and the TACACS+ server-health rules.
  - Every other rule is Grid.
- **Security incidents** (`/api/incidents`) are Grid. ISP incidents (`/api/wan/incidents`) are NMS. They are rows of
  the same table with different `category` values, so nothing is duplicated.

## Module classification

| Product | Group | Pages (existing routes kept) | API |
|---|---|---|---|
| Grid | Overview | Dashboard `/grid`, Incidents `/incidents[/:id]`, Alerts `/alerts?product=grid` | analytics, incidents, alerts (scoped) |
| Grid | Security Analytics | Top Sources / Destinations / Ports, Web / URL, DNS, Geography, Event Explorer | analytics, events, geo |
| Grid | Threat Detection | Security Events, Threat Intel, Detections, Watchlists, Saved Searches | analytics, ti, detections, watchlists, searches |
| Grid | Security Operations | Search, Hunting, Entity Graph, Workbooks, Automation, Investigate `/investigate/:ip` | search, hunting, entity, workbooks, automation, investigate |
| Grid | Identity & Access Security | VPN & Users, Users & Identity | vpn, identity |
| Grid | Governance | Compliance, Security Reports `/reports` | compliance, reports (shared) |
| NMS | Network Overview | Network Dashboard `/nms` (new: existing module overviews), Network Incidents `/isp?tab=incidents`, Network Alerts `/alerts?product=nms` | wan, switches, fwhealth, vpn-tunnels, bgp, tacacs, alerts (scoped) |
| NMS | ISP & WAN Monitoring | ISP / WAN, SD-WAN Health, WAN Performance, Circuit Availability, ISP Incident Analytics (tabs of `/isp`) | isp, wan |
| NMS | Network Infrastructure | Assets, Firewalls, Firewall Health, VPN Tunnels, BGP, Switch Monitoring | assets (shared), firewalls (writes NMS), fwhealth, vpn-tunnels, bgp, switches |
| NMS | Network Access & AAA | TACACS+ AAA, Network User Access (`/tacacs?tab=identity`), Network Device Authentication (`/tacacs?tab=clients`) | tacacs |
| NMS | Configuration & Policy | Policy Analytics, Shadow Analysis, Config Drift, Infrastructure as Code, Hardening | v1/policies, drift, iac, hardening |
| NMS | Network Governance | Network Reports `/reports`, Configuration Audit `/iac?tab=audit`, Network Compliance (**planned**, not clickable) | reports (shared), iac |
| Shared | Administration | Log Sources, Notifications (admin), Settings (users and roles for admins) | log-sources, notifications, users, admin, system |

Placement follows each module's purpose:

- **Grid:** firewall threat events and security incidents.
- **NMS:** firewall health, VPN tunnel health, routing, policy usage, configuration drift, and TACACS+ server and device
  AAA administration.

Some modules serve both products. Alerts, Reports, Assets and the firewall list are **one implementation** linked from
both products (a cross-product link), never a copy.

## Routing

- **No existing path changed:** every bookmark still works.
- **New routes:**
  - `/grid`: the Grid dashboard, previously `/`.
  - `/nms`: the network dashboard.
  - `/select-product`: the product selector.
  - `/no-access`: the page for accounts with no product.
  - a not-found page for unknown paths.
- **`/`:** now the entry gate. It redirects to the right destination for the signed-in account.
- **Deep links** open their own product directly, without the selector. If the account cannot use that product, the
  page explains why inside the product it can use, and the API refuses the data independently.
- **Shared pages** (alerts without `?product`, reports, assets, administration) keep the product the user was last in.
- **Session expiry:** the existing flow shows the sign-in form at the same URL. After sign-in the user returns there,
  and the page is authorized again. Signing out returns to `/`, so the next account starts at the gate.
- **Switching products** happens in the app, with no reload or second session. It goes to the last page visited in
  that product during this session, or to its dashboard.

## Frontend

| File | What it holds |
|---|---|
| `frontend/src/lib/products.ts` | product registry: navigation, page ownership, active-item matching (query tabs), entry target, last product and page. Tested in `products.test.ts`. |
| `frontend/src/components/Sidebar.tsx` | per-product branding (Grid red, NMS teal), product switcher (shown only with more than one product), collapsible groups (state saved per product), badges per product, the existing collapsed rail and active indicator |
| `frontend/src/pages/ProductSelect.tsx` | the selector and the no-access page |
| `frontend/src/pages/nms/NmsDashboard.tsx` | the network landing page |
| `frontend/src/App.tsx` | entry gate, product shell, guards |

The NMS accent `teal` is part of the themed palette, so both light and dark themes keep their contrast.
