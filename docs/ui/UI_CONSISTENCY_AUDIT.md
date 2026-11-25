# UI consistency audit and standardisation (2026-11-14)

**Scope:** the whole frontend (`frontend/src`, 80 page modules, about 13,900 lines of TSX). That is:
- Sentinel Grid: 27 sidebar routes;
- Sentinel NMS: 64 sidebar routes, including tab routes;
- Administration.

**Method:**
1. Read the shared layer: tokens, `ui.tsx`, charts, layout, sidebar, product navigation.
2. Scan every page statically: colours, tables, pagers, clickable elements, labels.
3. Sweep every route in the running app at the target resolutions.

**Results:** the design system that came out of it is [DESIGN_SYSTEM.md](DESIGN_SYSTEM.md). The earlier layout audit
is [../UI_AUDIT.md](../UI_AUDIT.md), and its fixes are still in place.

**Test environment:**
- local dev server (Vite) against the lab backend (SQLite + embedded ClickHouse) with seeded NMS data:
  - WLCs and APs, 46 wireless clients, 1,368 wireless events;
  - switches and WAN targets.
- SIEM (Grid) pages ran against an empty event store, so they were checked for layout, labels and errors with
  their empty states, not with dense data.

## 1. What already existed (kept)

The frontend already had a real design system. This pass did not replace it; it removed the places that bypassed it.

**Kept as they were:**
- **Tokens:**
  - semantic CSS variables (`--bg`, `--surface`, `--border`, `--text-muted`, `--accent`, `--ok/warn/bad`, `--sev-*`,
    `--chart-*`);
  - the Tailwind hue scales mirrored per theme, so one class works in day and night;
  - the Zomato brand scale.
- **Shared components:** Card, Kpi, Tabs, Modal, Drawer, TableWrap, rowProps, Loading / Empty / NoData, Time,
  Trunc, Sev.
- **Chart layer:** registered day / night ECharts themes, a validated 8-slot palette, series roles, ResizeObserver
  sizing, and tree-shaken ECharts.
- **App structure:**
  - route-level code splitting;
  - the product-aware sidebar with tests for duplicate or dead links;
  - the off-canvas drawer below 1024 px.

**Theme:** day and night both exist and are complete. There is no third mode, and no partial theme was added.

## 2. Baseline (before)

**Browser sweep** (`frontend/scripts/ui-sweep.js`, all sidebar routes):

| Resolution | Routes | Page overflow | Console / API 5xx errors | Unlabeled form controls | Nameless buttons / links | Unscrollable tables |
|---|---|---|---|---|---|---|
| 1366×768 | 91 | 0 | 0 | **27** on 11 routes | 0 | 0 |
| 390×844 | 91 | 0 | 0 | **27** | 0 | 0 |

**Static scan:**

| Finding | Count |
|---|---|
| Hex colour literals in pages and components (outside the chart palette file and brand artwork) | 26 in 11 files |
| Pagination implementations | **12** (3 module `Pager`s with different props and wording, 9 inline `‹ ›` / Previous / Next variants) |
| `SortTh` defined in a module (`wan/common`), imported across modules | 1 |
| Clickable `<tr>` / `<td>` with mouse-only `onClick` (no keyboard, no focus) | **30** rows + 5 cells |
| `<label className="label">` not associated with its control (sibling, no `htmlFor`) | **172** |
| Checkbox groups captioned by a `<label>` that labels nothing | 13 |
| Broken colour: `bg-[var(--surface,#0f172a)]` (the variable is an RGB triplet, so the popup had no background) | 1 (Identity user search) |
| Status colour definitions for the same states (`up` = #34d399 / #10b981 / #1baf7a, not theme-aware) | 4 |

**Visual issues (screenshots in `screenshots/`):**
- **Header wraps at 1366 px:** the top bar wrapped its last control (the theme toggle) onto a second row, a 97 px
  header.
- **Phone header:** three rows of filters, about 140 px.
- **Phone tabs:** wireless and other tab bars wrapped into 7 rows of tabs on a phone.
- **Phone tables:** identifiers split at hyphens ("HQ-F3-AP-05" over four lines) because tables squeezed to the
  screen width.
- **Dialogs:**
  - focus stayed on the page behind the dialog;
  - Tab left the dialog;
  - focus was lost on close.

## 3. Inconsistencies and fixes

| # | Area | Issue | Fix | Files |
|---|---|---|---|---|
| 1 | Pagination | 12 implementations: ‹ › vs Previous / Next, "page 1 / 5 · 120" vs "1–25 of 120" vs "1/5", 0- vs 1-based, offset vs page | One `Pager` in `ui.tsx`: "first–last of N", ‹ Previous / Next ›, `aria-label`s, `<nav aria-label="Pagination">`, `hasMore` mode for APIs without a total. Module pagers re-export it (TACACS+ keeps an offset adapter). | `ui.tsx`, `wan/common`, `iac/common`, `tacacs/common`, Policies, Explorer, Watchlists, Assets, Automation, SwitchesPage (3), SwitchDetail, tacacs/Accounting |
| 2 | Tables | `SortTh` lived in the WAN module | Moved to `ui.tsx` (`type=button`, `aria-sort`, hidden arrow glyph); WAN re-exports it | `ui.tsx`, `wan/common` |
| 3 | Tables / a11y | 30 rows clickable by mouse only, with ad-hoc `cursor-pointer hover:bg-white/5` | `{...rowProps(fn)}`: focusable, Enter / Space, cursor and hover from `.tbl`. Admin-only rows stay inert for viewers. Selected row tinted with the brand token. | NMS dashboard, WAN (4), wireless (5), SNMP, Operations, Geo, Vpn, ThreatIntel, tacacs/Accounting |
| 4 | Tables / a11y | 5 clickable `<td>`s (flow IPs, exporters) | Real `<button className="link">` | nms/Flows |
| 5 | Forms / a11y | 172 captions not tied to their control | Caption wraps the control (`<label className="block min-w-0"><span className="label">`), or `Field`. 152 converted by a checked codemod (only parents with exactly one control and nothing interactive), the rest by hand. | 30 pages |
| 6 | Forms / a11y | 13 checkbox groups "labelled" by an orphan `<label>` | `role="group" aria-label` + caption `<span>` | Detections, Hardening, Notifications, Reports, Operations, SNMP |
| 7 | Forms / a11y | Search boxes, page-size, rank-by, timezone and password inputs without a name | `aria-label` (+ `autocomplete` on password fields) | SNMP, Explorer, nms/Analytics, Settings |
| 8 | Forms | `Field` defined twice (WAN, TACACS+) as `<div><label/>{children}</div>` (not associated) | One `Field` in `ui.tsx` with a real wrapping label and an optional hint | `ui.tsx`, `wan/common`, `tacacs/common` |
| 9 | Colour | 4 status maps with different greens / reds / greys, dark-only | `STATUS_HEX[theme]` + `statusColor(theme, state)` in `Chart.tsx` (ok / warn / bad / unknown / paused, mapped from up, established, degraded, down, lost, auth_failed …) | `Chart.tsx`, Bgp, Topology, wan/Live, wan/common |
| 10 | Colour | Hex literals in charts (muted series, denied edges, RF and ISP heatmaps, map land, path highlight) | `SERIES_ROLE` / `STATUS_HEX` / `PALETTES` / new `CHART_THEME.land` | FirewallHealth, Isp, EntityGraph, ResultView, wireless/Rf, WorldMap, Topology |
| 11 | Colour | Brand fills written as `bg-[#cb202d]`, `text-[#ffffff]` in several places | Fixed tokens `solid.brand / brand-hover / mark / nms / nms-bar / on` in `tailwind.config.js`; `.btn-primary`, sidebar tiles and badges use them | `tailwind.config.js`, `index.css`, Sidebar |
| 12 | Colour | Identity search popup: `bg-[var(--surface,#0f172a)]` rendered transparent | `bg-panel` | Identity |
| 13 | Tabs | Tabs selected by mouse only; active border hex; 7 rows of tabs on phones | WAI-ARIA tabs (arrows, Home / End, roving tabindex, focus follows selection); `border-brand-500`; one scrollable row below 640 px with the selected tab kept in view | `ui.tsx` (used by 24 pages) |
| 14 | Dialogs | No focus management | `useDialog`: focus to the first field (or the dialog), Tab trapped, Escape closes, focus returns to the opener, or to its re-rendered twin when closing changed a URL parameter. Shared close button. | `ui.tsx` |
| 15 | Header | Wrapped at 1366 px; three rows on phones | "Updated" timestamp compacted (full time in its tooltip) and shown from 1360 px (new `hd` breakpoint); search 224 px below 1536. Phones: menu, range, **Filters** (with a count of active scope filters) and refresh. The Filters button reveals firewall, site, search, auto-refresh and theme. | Layout |
| 16 | Tables, phones | Identifiers split at hyphens in squeezed tables | Below 640 px cells keep one line and the table scrolls in its wrapper; `.cell-wrap` columns (event details) still wrap | `index.css`, wireless event tables |
| 17 | Buttons | Several buttons without `type` | `type="button"` on the shared buttons (Kpi, tabs, dialog close, pager, header) | `ui.tsx`, Layout |

**Not changed (deliberately):**
- **Business logic, APIs, data and metrics:** no endpoint, query or calculation changed. Every pager still requests
  the same page size the page requested before.
- **Brand artwork:** the sign-in and product-selector artwork keeps its literal colours.
- **Navigation:** no module or navigation item was removed or renamed.
- **Memoisation:** none added blindly. The chart wrappers already memoise their options on content, and no
  measured re-render problem was found in this pass.

## 4. Automated validation

### Playwright: evaluated, not added

The prompt asks to evaluate it. Not added in this pass:
1. Its browsers download from a CDN that the corporate TLS inspection blocks here (the same failure as the kind
   node image in the container pass).
2. The checks below need no new dependency.

Adding it later is a small step: point Playwright at the same `ui-sweep.js` (it exports `uiSweep`) and run it in CI
against a seeded backend.

### What runs instead

| Check | Where | Runs |
|---|---|---|
| Static guards: no hex colours, every table `.tbl`, one pager / sort header, no mouse-only rows or cells, associated labels, one status-colour map | `src/lib/uiConsistency.test.ts` (8 tests) | `npm test`, CI |
| Route sweep: overflow, console / 5xx errors, visible error alerts, unlabeled controls, nameless buttons, charts without a text alternative, unscrollable tables, stuck loaders | `scripts/ui-sweep.js` | in the browser against a signed-in app; read-only (navigates only) |
| Interaction checks (keyboard) | browser, scripted | this pass (below) |

### Results after the changes

**Route sweep:**

| Resolution | Routes | Clean | Page overflow | Errors | Unlabeled | Nameless | Unscrollable tables | Alerts shown |
|---|---|---|---|---|---|---|---|---|
| 1366×768 | 91 | 89 | 0 | 0 | **0** (was 27) | 0 | 0 | 2 |
| 1024×768 | 91 | 89 | 0 | 0 | 0 | 0 | 0 | 2 |
| 768×1024 | 91 | 89 | 0 | 0 | 0 | 0 | 0 | 2 |
| 390×844 | 91 | 89 | 0 | 0 | 0 | 0 | 0 | 2 |

The 2 alerts are real: "Monitoring data is stale: the ICMP collector has not run yet" on the ISP overview and live
pages. The lab runs no WAN poller. The alerts stay visible by design.

**Header height** (one row = 64 px):

| Width | Before | After |
|---|---|---|
| 1920, 1440 | 64 px | 64 px |
| 1366 | 97 px (wrapped) | 64 px on Grid, NMS and wireless pages |
| 1280 | 97 px | 64 px ("Updated" timestamp shown from 1360 px, the new `hd` breakpoint) |
| 1024 | 97 px | 97 px: two clean rows (784 px beside the sidebar) |
| 390 | about 140 px (3 rows) | 64 px (1 row + Filters) |

1600 px was not measured separately; it falls between the measured 1440 and 1920.

**Interaction (keyboard, scripted in the browser):**
- **Tabs:** → selects the next tab and moves focus to it, ← returns, exactly one tab is in the Tab order.
- **Rows:**
  - Enter on a client row opens the client drawer with focus inside;
  - Tab from the last control wraps to the first;
  - Escape closes it and focus returns to the same row.

  Verified on wireless clients and APs.
- **Pager:** on wireless events, "1–100 of 1,368" → Next → "101–200 of 1,368". The first row changed, Previous
  became enabled, and the data came from the API.

**Builds and tests:**
- `npm run typecheck`: clean.
- `npm test`: 15 files, **53 tests** passed (45 before plus the 8 new guards).
- `npm run build`: OK. Chunk sizes are unchanged in kind:
  - the shared `Chart` chunk is 727 kB (242 kB gzip; ECharts, loaded only by chart pages);
  - the entry chunk is 266 kB (84 kB gzip).

## 5. Performance

This pass did not need performance work. The earlier audit already did the structural items, and they were
confirmed in place:
- route-level lazy loading;
- tree-shaken ECharts;
- debounced filters;
- content-keyed chart memos;
- one ResizeObserver per chart.

**Effect of this pass's changes:**
- No new dependency; no runtime cost beyond three passive document listeners (dialog opener tracking).
- The unified Pager renders less than some inline versions did.

**Not done:** Web Vitals measurement on production. The procedure is in `../FRONTEND_PERFORMANCE_REPORT.md` §5.

## 6. Modified files

**New:**
- `frontend/scripts/ui-sweep.js`;
- `frontend/src/lib/uiConsistency.test.ts`;
- `docs/ui/DESIGN_SYSTEM.md`, `docs/ui/UI_CONSISTENCY_AUDIT.md`, `docs/ui/screenshots/`.

**Shared layer:**
- `frontend/tailwind.config.js`;
- `frontend/src/index.css`;
- `frontend/src/components/{ui,Chart,Layout,Sidebar,ResultView,WorldMap}.tsx`.

**Pages (codemods plus manual edits):**

| Area | Files |
|---|---|
| Grid | Alerts, Assets, Automation, Bgp, Detections, Dns, EntityGraph, Explorer, FirewallHealth, Firewalls, Geo, Hardening, Hunting, Identity, Isp, LogSources, Notifications, Policies, PolicyDetail, Reports, Search, Searches, Settings, ThreatIntel, Vpn, Watchlists, Web, Workbooks |
| IaC | `iac/common` |
| NMS | `nms/{Analytics,Flows,NmsDashboard,Operations}`, `snmp/SnmpPage` |
| Switches | `switches/{Admin,SwitchDetail,SwitchesPage,Topology}` |
| TACACS+ | `tacacs/{Accounting,common}` |
| WAN | `wan/{Analytics,Incidents,Live,Overview,common}` |
| Wireless | `wireless/{Aps,ClientAnalytics,Clients,Rf,WirelessPage}` |

No backend file changed.

## 7. Remaining issues and limits

- **Sweep depth:** the sweep visits every sidebar route but not every modal, drawer or deep tab. The static guards
  cover the label and row rules everywhere; forms inside dialogs were converted by the same codemod but not each
  opened in the browser.
- **Header between 1024 and 1279 px:** two rows (clean wrap, not overflow).
- **Contrast:** checked by token (documented ratios), not measured per rendered element. Night theme was
  spot-checked on wireless clients (1920) and switch topology (1440), not swept separately (the sweep checks
  structure, which is identical in both themes).
- **Grid with dense data:** Grid pages were exercised with an empty SIEM store in the lab. Layouts with dense real
  data were covered by the earlier audit but not re-run in this pass.
- **Playwright / CI browser run:** not set up (above). The route sweep is manual today.
- **Brand artwork colours:** Login and ProductSelect keep literal colours.
- **Not deployed:** nothing is deployed to production yet; nothing is committed.
