# Sentinel design system (Grid and NMS)

The one reference for building UI in `frontend/`. Everything here already exists in code; this page says where
and how to use it. The audit that produced it is in [UI_CONSISTENCY_AUDIT.md](UI_CONSISTENCY_AUDIT.md).

**Stack:**
- React 18 + TypeScript + Vite;
- Tailwind 3;
- ECharts 5 (tree-shaken in `lib/echarts.ts`);
- TanStack Query;
- no component library: the shared components are in `src/components/`.

## 1. Tokens

### Colour

Colours are CSS variables holding RGB triplets, so Tailwind opacity modifiers work (`bg-brand-500/10`). The
**day** theme (`:root.light`) is the default; **night** is `:root` without `.light`. The toggle is in the top bar
(`ThemeToggle`, `lib/theme.tsx`).

| Role | Tailwind class | Token (`src/index.css`) | Use |
|---|---|---|---|
| Page background | `bg-bg` | `--bg` | `<body>` only |
| Card / panel surface | `bg-panel` | `--surface` | cards, header, sidebar, dialogs |
| Secondary surface | `bg-panel2` | `--surface-2` | insets, toggles |
| Borders | `border-line` | `--border` | every divider |
| Primary text | `text-slate-200` / `text-slate-100` | (mirrored scale) | body, emphasis |
| Secondary text | `text-muted` | `--text-muted` | captions, table headers, hints (5.5:1 day, 7.4:1 night) |
| Accent / brand text | `text-brand-400` | brand scale | active nav, links, selected tab |
| Status | `text-ok`, `text-warn`, `text-bad` (or `text-emerald-400`, `text-amber-300`, `text-red-400`) | `--ok`, `--warn`, `--bad` | KPI tones, inline state |
| Severity | `.sev-critical` … `.sev-informational` (via `<Sev>`) | `--sev-*` | alert / event severity badges |
| Fixed brand fills | `bg-solid-brand`, `bg-solid-mark`, `bg-solid-nms`, `text-solid-on` | `tailwind.config.js` `solid.*` | white-on-colour fills (primary button, nav badges, product tiles); identical in both themes |

**How the hue scales work.**
- The Tailwind hue scales (`slate`, `sky`, `emerald`, `red`, `amber`, `orange`, `teal`, `brand`) are variables too.
  The day theme mirrors each scale one step darker, so a class written for the dark UI (`text-emerald-400`) reaches
  4.5:1 on white without a second class.
- `white` is mirrored to near-black in the day theme. For real white on a coloured fill, use `text-solid-on`.

**Do not:**
- write hex literals in components;
- use `var(--surface)` as a colour (it is a triplet: `rgb(var(--surface))`, or simply `bg-panel`).

`src/lib/uiConsistency.test.ts` enforces both. The only hex in TSX is the brand artwork in `Login.tsx` and
`ProductSelect.tsx`.

### Chart colours (`src/components/Chart.tsx`)

| Constant | Meaning |
|---|---|
| `PALETTES[theme]` | 8 categorical slots, assigned in order; fold the rest into "Other". Red is deliberately not a categorical slot. |
| `SERIES_ROLE[theme]` | `primary` (traffic / volume), `alert` (denied / blocked / threat, brand red), `warn` (degraded; draw dashed next to `alert`), `muted` (context, "Other") |
| `STATUS_HEX[theme]` + `statusColor(theme, state)` | operational state: `ok` (up / established / healthy), `warn` (degraded), `bad` (down / failed / lost), `unknown`, `paused`. **One definition** for BGP, topology, WAN timelines, RF heatmap, ISP heatmap. |
| `SEV_HEX` | severity in charts, matching the `.sev-*` badges |
| `SEQUENTIAL[theme]` | one-hue magnitude ramp |
| `CHART_THEME[theme]` | chrome: text, strong text, axis, split lines, tooltip, surface, map land |

**Rules:**
- **TX vs RX and similar pairs:** use slots 0 and 1, never green / red.
- **The green / red status pair:** never the only cue. Pair it with a label, an icon or a dashed line.

### Typography

| Use | Class |
|---|---|
| Base | 14 px / 1.45, Inter → system stack (no web-font download: CSP `font-src 'self'`) |
| Page / card title | `.card-h` (0.9 rem semibold) |
| KPI value | `text-xl xl:text-2xl font-extrabold tabular-nums` (in `<Kpi>`) |
| Captions, table headers | `text-2xs` (11 px) uppercase `tracking-wide text-muted` |
| Numbers | `tabular-nums`; right-aligned in tables (`td.num`) |
| Identifiers (IP, MAC, OID, serial) | `font-mono text-xs` |

### Spacing, radius, elevation
- Page padding: `p-3 sm:p-5` (in `<Layout>`).
- Card: `rounded-card` (14 px), `.card-h` `px-4 py-2.5`, `.card-b` `p-4`.
- Grids: `.grid-cards` (gap 16, `items-start`, `min-w-0` children) and `.kpi-grid` (auto-fill, min 9.5 rem).
- Controls: `rounded-lg`. Pills: `rounded-md`. Avatars and dots: `rounded-full`.
- Elevation: day theme cards use `shadow-card`; night cards rely on borders only.

## 2. Components (`src/components/ui.tsx` unless noted)

| Component | Purpose | Notes |
|---|---|---|
| `Card` | titled panel | `title`, `right` (actions), `bodyClass="p-0"` for edge-to-edge tables |
| `Kpi` | metric tile | `tone` ok / warn / bad; with `onClick` it is a real `<button>` |
| `Tabs` | page sections | WAI-ARIA tabs: arrows / Home / End, roving tabindex, focus follows selection; one scrollable row on phones |
| `Modal`, `Drawer` | dialogs | focus moves in on open, Tab is trapped, Escape closes, focus returns to the opener (also when the list re-rendered) |
| `Field` | form field | real `<label>` around exactly one control; `hint` |
| `Pager` | every paged list | 1-based `page`, `size`, `total` (or `hasMore` when the API has no total); "first–last of N"; hidden on one page |
| `SortTh` | sortable header | `aria-sort`; first click sorts descending |
| `TableWrap` | table scroller | horizontal scroll inside the card; `maxH` for vertical |
| `rowProps(fn)` | clickable row | focusable, Enter / Space, pointer cursor and hover from `.tbl` |
| `Loading`, `Empty`, `NoData` | states | `Loading` shows the API error text (`role=alert`); `NoData` separates "never collected" from "no matches" |
| `Sev`, `Action`, `Time`, `Trunc`, `IpLink` | cells | `Time`: compact time + full tooltip in the user's timezone; `Trunc`: ellipsis + full-text tooltip |
| `TimeChart`, `TopBar`, `Donut` (`charts.tsx`) | standard charts | zero-filled buckets, "not collected" shading, top-N + Other |
| `Chart` (`Chart.tsx`) | any ECharts option | theme-aware, ResizeObserver, ECharts aria description |

Module helpers re-export the shared ones:
- `wan/common` re-exports `Pager`, `SortTh` and `Field`;
- `iac/common` re-exports `Pager`;
- `tacacs/common` re-exports `Field`, and its `Pager` is an offset adapter over the shared one.

Import from `components/ui` in new code.

## 3. Layout and navigation

**Shell (`Layout.tsx`):**
- **Sidebar:** 240 px, collapsible to a 64 px rail on desktop, an off-canvas drawer below 1024 px.
- **Top bar:** one row from 1280 px (verified at 1280, 1366, 1440 and 1920); it wraps to two rows between 1024 and 1279. The "Updated" timestamp shows from 1360 px (`hd` breakpoint).
- **Top bar on phones:** below 640 px it shows
  - menu, range, **Filters**, and refresh;
  - the Filters button reveals firewall, site, search, auto-refresh and theme, and shows a count of active scope
    filters.

**Sidebar (`Sidebar.tsx`, `lib/products.ts`):**
- Grouped by product (Grid / NMS) plus Administration.
- **Active item:** tinted background, accent bar, `aria-current="page"`.
- **Groups:** fold, but the group of the active item never folds.
- **Badges:** open alerts and incidents.
- **Planned items:** greyed out with an explanation; they are not links.
- `products.test.ts` keeps labels and links unique and every link routed.

**Pages:** filters first, then KPIs (`.kpi-grid`), then charts (`.grid-cards`), then detail tables.

## 4. Tables (`.tbl` in `index.css`)
- **Header:** 11 px uppercase muted, `nowrap`, bottom-aligned.
- **Rows:** compact padding, hover tint, `tr[tabindex]` gets the pointer cursor.
- **Cells:**
  - **Numbers:** `td.num` (right, tabular, nowrap).
  - **Identifiers:** `font-mono text-xs`.
  - **Long text:** `<Trunc>` (ellipsis + tooltip) or `.cell-wrap` (wraps only at need, never mid-word).
- **Width:** a table never widens the page. It scrolls inside `TableWrap` / `.tbl-wrap`.
- **Phones (< 640 px):** cells stay on one line (identifiers no longer split at hyphens) and the table scrolls;
  `.cell-wrap` columns still wrap.
- **Behaviour:** sorting through `SortTh`, paging through `Pager`, row activation through `rowProps`.

## 5. Charts
- **Wrappers:** use `TimeChart` / `TopBar` / `Donut` where they fit, and `Chart` with an option otherwise.
- **Theme and size:** never set chart text, axis or tooltip colours (the registered `siem-day` / `siem-night`
  themes do it). Never set a fixed pixel width (the container is `width: 100%`).
- **Colour:** series colours come from `seriesColor` / `SERIES_ROLE` / `STATUS_HEX`. A new colour goes into
  `Chart.tsx`, not the page.
- **Time axes:** the user's timezone (`getTimezone()`), via `axisTime` / `fmtTime`.
- **Gaps:** shown as gaps (`connectNulls: false`), not as zero.

## 6. Forms and filters
- **Label every control:**
  - wrap it (`<Field label>` or `<label className="block min-w-0"><span className="label">…</span><input/></label>`);
  - or give it `aria-label` when the caption is implicit (search boxes, page-size, rank-by selects);
  - for checkbox groups, use `role="group" aria-label` with the caption as a `<span className="label">`.
- **Validation:** invalid input gets `aria-invalid` and is not sent (see the Web page IP filter); API errors appear
  in `Loading` / `ErrorText`, never swallowed.
- **Filter bars:** `flex flex-wrap gap-2`; selects `input py-1`; free-text search is debounced (`useDebounced`,
  400 ms).

## 7. Accessibility checklist (WCAG 2.2 AA, as practical)

| Requirement | How |
|---|---|
| Contrast | day text tokens ≥ 4.5:1 (muted 5.5:1, brand text 5.6:1); primary button white on #CB202D 5.6:1 |
| Focus visible | global `:focus-visible` outline (2 px accent) |
| Keyboard | rows (`rowProps`), tabs (arrows), dialogs (trap + Escape + return), sidebar groups (`aria-expanded`), product menu (Escape) |
| Names | every form control, button and link has an accessible name (checked by the UI sweep) |
| Landmarks | `<aside aria-label="Sidebar">`, `<nav>`, `<header>`, `<main>`, `role=search`, pagination `<nav aria-label="Pagination">` |
| Status | load errors are `role=alert` and stay visible |

## 8. Checks
- **`npm test`:** includes `src/lib/uiConsistency.test.ts`:
  - no hex colours;
  - every table is `.tbl`;
  - one pager and one sort header;
  - no mouse-only rows or cells;
  - labels associated;
  - one status-colour definition.
- **UI sweep (`frontend/scripts/ui-sweep.js`):** visits every sidebar route in a running, signed-in app and reports:
  - page overflow;
  - console and 5xx errors;
  - visible error alerts;
  - unlabeled controls;
  - nameless buttons;
  - charts without a text alternative;
  - unscrollable tables;
  - stuck loaders.

  It only navigates and reads. Usage is in the file header.
