# UI audit checklist

Stack: React 18 + TypeScript + Vite, react-router 6, TanStack Query 5, Tailwind 3, ECharts 5 (no component library).
Method: automated overflow audit script (document, `<main>` and every `.card`, plus any element extending past
`<main>` outside a table scroller) run on all 12 routes at 1920×1080, 1440×900, 1024×768, 768×1024 and 390×844,
with console-error capture and screenshots. API responses were checked against the charts.

## Root causes

| # | Issue | Root cause | Layer | Status |
|---|---|---|---|---|
| 1 | Blocked-vs-allowed (and every time chart) showed one or a few huge bars | API returned only populated buckets; the chart used a *category* x-axis, so sparse buckets were stretched across the full width (7 d → 8 buckets covering about 21 h; a freshly connected firewall → 1 bucket) | Backend + chart | Fixed: ClickHouse `WITH FILL` zero-fills every bucket of the window; time x-axis; buckets before the first collected event are shaded "not collected" (`data_start`) |
| 2 | Cards overflowing (+176 px dashboard charts, +180 security, +206 investigate) | Grid children had no `min-width: 0`, so canvases and `white-space: nowrap` tables set the track width | CSS | Fixed: `.card`, `.grid-cards > *` have `min-width: 0`; every table sits in `.tbl-wrap` (`overflow-x: auto`) |
| 3 | Squeezed tables / DNS names breaking panels | Global `td { white-space: nowrap }`; three-column grid too narrow for tables | CSS + layout | Fixed: cells wrap by default; `.num`/`.nowrap` opt-in; long names use `.cell-wrap`; investigate uses a two-column grid with scroll-capped cards |
| 4 | Mobile unusable (content 174 px wide) | Fixed 208 px sidebar always in flow | Layout | Fixed: off-canvas drawer below `lg` with hamburger, overlay, Escape and auto-close on navigation |
| 5 | Web KPI row clipped | Fixed `md:grid-cols-6` | CSS | Fixed: `.kpi-grid` uses `repeat(auto-fill, minmax(9.5rem, 1fr))` |
| 6 | Donut legend crowded / paginated | ECharts scroll legend with every category | Chart | Fixed: top-7 plus "Other (n)" (members in tooltip); HTML legend with counts and percentages; "Show all" full-breakdown table; percentages of displayed total, which sum to 100 % |
| 7 | Empty states implied a working collection | Generic "No events" | Data/UX | Fixed: `/api/system/coverage`; `NoData` distinguishes *never collected* (with a config hint) from *no matches* (with the time of the last event) |
| 8 | Timestamps long or clipped | Full locale string in cells | UX | Fixed: `<Time>` shows a compact form (time only for today) with the full timestamp and relative time as a tooltip, in the user's timezone |
| 9 | Clickable rows / IP links not keyboard accessible | `onClick` on `<tr>`/`<span>` | A11y | Fixed: `rowProps` (`tabIndex`, Enter/Space), IP links are `<button>`s, `role=dialog`/`aria-modal`, Escape closes modals and drawers, `aria-label` on selects, focus-visible ring |
| 10 | Search queries on every keystroke | No debounce | Perf | Fixed: `useDebounced` (400 ms) on web/DNS filters; invalid IP input is flagged and not sent |
| 11 | Severity colours inconsistent (badge vs chart) | Separate hardcoded maps | Design | Fixed: tokens in `index.css` (`--sev-*`) used by `.sev-*` badges and `SEV_HEX` in charts |
| 12 | Alert from an investigation could not be opened | No deep link | UX | Fixed: `/alerts?id=N` opens the alert drawer |
| 13 | Narrow-screen overflow in tab bars, explorer chips, card controls | `flex` without wrap | CSS | Fixed: `flex-wrap` |

## Round 2 — Security page (screenshot) root cause
| # | Issue | Root cause | Fix |
|---|---|---|---|
| 14 | Donut panels very tall with chart floating in empty space | CSS grid default `align-items: stretch` made the donut cards as tall as the 25-row table in the same row; `.card` (flex column) + `.card-b { flex: 1 }` filled that height | `.grid-cards` now `items-start` (cards keep content height); Security page puts the charts in their own row and the table full width |
| 15 | `app-ctrl` split across lines, "Microsoft.365.Porta / l" | Global cell wrapping + `break-all` in a one-third-width column; Type cell lacked `nowrap`; numeric cells lacked `num` | `.cell-wrap` uses `overflow-wrap:anywhere` only; Type/Severity `nowrap`; threat names truncate with a tooltip; numbers right-aligned (fixed across Settings, Firewalls and Web tables too) |
| 16 | Investigate bytes chart said "No events" for 1,224 denied sessions | Empty-state text did not name the metric; denied sessions carry 0 bytes | Empty states name the metric; added an events chart |
| 17 | React "setState while rendering" warning on Hardening | Selection reset inside a state-updater function | Compute the next state first, then update |

## Data integrity checks (automated)
- Time-series bucket sums equal the KPI and summary totals (traffic allowed/denied, web blocked/allowed): `test_timeseries_zero_fills_whole_window_and_totals_match`, `test_web_timeseries_blocked_allowed_match_totals`.
- Category distribution sums equal total web events (same test).
- Coverage endpoint reflects only collected categories: `test_coverage_reports_collected_categories`.
- Top-N + Other conserves counts and percentages: `frontend/src/lib/chartData.test.ts`.
- Filters (time range, firewall, site) flow from the global context into every widget through `useData`; pagination totals come from server-side `count()` with the same WHERE clause.

## Final audit results (dev server, demo + syslog data)
All 16 routes (including Policy Analytics, Shadow Analysis, policy detail and Hardening) at 1920, 1440, 1024, 768 and
390 px: document overflow 0, `<main>` overflow 0, overflowing cards 0, console errors during the audit 0.
Remaining by design: wide tables (explorer, top-N) scroll horizontally inside their own card.
