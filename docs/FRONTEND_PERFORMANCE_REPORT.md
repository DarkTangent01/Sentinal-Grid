# Frontend Performance Report

- **Stack (verified):** React 18.3, React Router 6.30, TanStack Query 5, ECharts 5.5 (now `echarts/core`), Vite 6.4 and Tailwind 3.4.
- **Measurement:** production builds (`npm run build`) on an Apple M3 with 8 GB RAM and Node 22.12.
- **Lighthouse and Core Web Vitals (LCP/INP/CLS) were not measured.** No Chrome/Lighthouse runner was available in the audit environment, so no claim is made about those targets. See §5 for how to measure them.

## 1. Bundle (measured)

| | Before | After |
|---|---|---|
| JS loaded on first visit (entry) | 2,388 KB raw / 692 KB gzip, 1 file | **264 KB raw / 83 KB gzip**, a 88% gzip reduction |
| Total JS across all pages | 2,388 KB | 2,096 KB (−12%, from tree-shaking ECharts) |
| JS chunks | 1 | 58 |
| ECharts | in the entry chunk | `Chart-*.js`, 726 KB raw / 241 KB gzip, loaded by the first chart page |
| World map (atlas + topojson) | in the entry chunk | `Geo-*.js`, 116 KB, loaded only by Geography |

## 2. Rendering and data findings

| # | Finding (file:line before the fix) | Fix | Status |
|---|---|---|---|
| F1 | `lib/context.tsx`: every `useData` success called `markUpdated()` (global `setState`), and the provider value was a new object every render, so every consumer re-rendered once per query (Dashboard: 13 queries, about 13 full-tree renders per refresh) | Provider value memoised. The "Updated" timestamp comes from a query-cache subscription in a leaf `<LastUpdated/>` component | **Fixed** |
| F2 | `components/charts.tsx`: TimeChart memo keyed on inline `series` arrays, so the option was rebuilt and `setOption(notMerge)` redrew the chart on every parent render | Memo keyed on `JSON.stringify(series)`. Duplicate mount-time `setOption` removed (`Chart.tsx`) | **Fixed** |
| F3 | `App.tsx`: 52 statically imported pages | `React.lazy` per route, one `<Suspense>` boundary with an accessible `role="status"` fallback | **Fixed** |
| F4 | `Chart.tsx`, `WorldMap.tsx`: full `echarts` build | `lib/echarts.ts` registers only the series and components the app uses: bar, line, pie, map, graph, heatmap, gauge, radar, custom, grid, tooltip, legend, visualMap, markArea, markLine, graphic, calendar, title, dataset, aria | **Fixed**. A missing component fails silently, so smoke-test every chart page after adding a new chart type |
| F5 | `lib/api.ts`: no `AbortSignal`, so superseded range or filter requests kept running on ClickHouse | `api()` accepts `signal`; `useData` and the switch tables forward TanStack's `signal` | **Fixed** (tested in `src/lib/api.test.ts`) |
| F6 | `switches/SwitchDetail.tsx`: interface (up to 2,000 rows) and MAC searches queried on every keystroke | `useDebounced(q, 300)` | **Fixed** |
| F7 | `/firewalls` fetched under two query keys (`firewalls-lite` in Layout, `firewalls` in pages) | One key, so a mutation refreshes the header dropdown too | **Fixed** |
| F8 | `tacacs/Studio.tsx`: unconditional 5 s poll | 3 s only while a job is pending or running, 30 s otherwise | **Fixed** |
| F9 | `Alerts.tsx`, `Incidents.tsx` (`size: 200` every 30 s), `SwitchDetail` events (500), `ResultView` (unbounded rows) | Paginate at 50, use `React.memo` rows, cap `ResultTable` | Backlog TD-12 |
| F10 | Remaining per-keystroke inputs: `tacacs/Identity.tsx`, `Inventory.tsx`, `TacacsPage.tsx`, `Accounting.tsx` | Same `useDebounced` pattern | Backlog TD-13 |
| F11 | `Dashboard.tsx` `sevTypes` computed during render | `useMemo` over `sec.data` | Backlog TD-13 (minor; F1 removed the repeated renders that made it costly) |
| F12 | Large tables are not virtualised | `@tanstack/react-virtual`, after server-side paging (TD-12) | Backlog |

**Verified as fine (no change needed):**
- Polling stops on hidden tabs (`refetchIntervalInBackground` is false).
- Timers and listeners are cleaned up.
- Stable keys are used in lists.
- Query keys are hashed structurally, so there are no refetch loops.

## 3. UI/UX

The Zomato-aligned design system from the previous pass is still in place and was not reworked here:
- the token-driven Tailwind palette;
- day and night themes;
- a validated chart palette;
- WCAG-AA text contrast;
- focus rings;
- the accessible route fallback.

This pass added the Suspense loading state and kept every page's behaviour unchanged.

## 4. Tests

- `npm test`: 39 passed, including the new `src/lib/api.test.ts`, which checks that an abort reaches `fetch`.
- `tsc -b --noEmit`: clean.
- `npm run build`: clean.
- The context and Chart render-count improvements have no automated test, because React Testing Library and jsdom are not installed (see TD-15).

## 5. How to measure Web Vitals (not done here)

```bash
npm run build && npx vite preview --host 127.0.0.1 --port 4173
npx lighthouse http://127.0.0.1:4173/ --preset=desktop --only-categories=performance,accessibility
```

Run it against a logged-in page by using Chrome DevTools' Lighthouse panel on a test account. Use a test instance, not production.
