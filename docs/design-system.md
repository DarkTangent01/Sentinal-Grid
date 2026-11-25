# Sentinel design system

Sentinel is one platform with two products. They share every foundation (surfaces, type, spacing, components, status
colours) and differ only in name and accent.

| Product | Tagline | Accent |
|---|---|---|
| **Sentinel NMS** | Network Monitoring & Intelligence | sky / cyan `#38BDF8` (hover `#0EA5E9`; supporting `#06B6D4`, `#3B82F6`) |
| **Sentinel Grid** | Security Intelligence Platform | violet `#A78BFA` (hover `#8B5CF6`; supporting `#6366F1`) |

Use exactly these names. Not "Sentinel SIEM", "Grid SIEM" or "Sentinel Security".

## 1. Brand identity

Sentinel stands for visibility, intelligence, protection, precision and operational control. The voice is calm and
exact: say what is measured, what is estimated, and what is not known. The visual language is navy surfaces, one
accent per product, thin borders, compact density, and gradients only in the logo.

## 2. Logo

**The mark.** A hexagonal frame (the protective structure) split into two interlocking halves that meet in a central
node. It reads as an **S**, as a guarded perimeter, and as a three-node network: the two open ends are nodes, and the
centre is the sentinel's eye and core. It is drawn on a 32-unit grid with 2.6-unit round strokes and stays legible at
16 px.

**Sources** (change them together):
- `frontend/scripts/generate-brand.py`: the geometry and all static assets.
- `frontend/src/components/Brand.tsx` (`MARK_PATHS`, `MARK_NODES`): the same geometry for the UI.

| Asset | File / component | Use |
|---|---|---|
| Primary logo, dark background | `public/brand/sentinel-logo-dark.svg` · `<SentinelLogo />` | documentation, launch screens |
| Primary logo, light background | `public/brand/sentinel-logo-light.svg` | documents, light pages |
| Monochrome | `public/brand/sentinel-logo-mono.svg`, `sentinel-mark-mono.svg` · `<SentinelMark tone="mono" />` | single-colour print, embossing; inherits `currentColor` |
| Icon only | `public/brand/sentinel-mark.svg` · `<SentinelMark />` | small spaces |
| Sentinel NMS | `public/brand/sentinel-nms-dark.svg`, `-light.svg` · `<SentinelLogo product="nms" tagline />` | product headers |
| Sentinel Grid | `public/brand/sentinel-grid-dark.svg`, `-light.svg` · `<SentinelLogo product="grid" tagline />` | product headers |
| App tile / sidebar compact | `public/brand/sentinel-tile.svg`, `sentinel-icon-512.png` · `<SentinelTile tone="nms" />` | sidebar, collapsed rail, launcher, loading screen |
| Favicon | `public/favicon.svg`, `favicon.ico` (16–64 px), `apple-touch-icon.png` | browser, home screen |
| Login | `<SentinelLogo size={30} />` on `AuthShell` | sign-in, product selection |

**Gradients** (logo only):

| Use | Gradient |
|---|---|
| Platform | `#38BDF8` → `#A78BFA` |
| NMS | `#38BDF8` → `#3B82F6` |
| Grid | `#A78BFA` → `#6366F1` |

On light backgrounds use the darker pairs (`#0284C7` → `#7C3AED` and so on), as the `-light.svg` files do.

**Rules:**
- Keep clear space of at least the centre node's diameter around the mark.
- Minimum size is 16 px (mark) and 96 px wide (logo with wordmark).
- Don't rotate, outline, add effects to, re-colour outside the defined gradients, or place the gradient mark on a busy
  image. On colour, use the mono mark.
- The wordmark is Inter Semibold with −2 % tracking. "Sentinel" is set in the text colour; the product word is set in
  its accent.

Regenerate the static assets after a geometry change with:

```bash
cd frontend && ../.venv/bin/python scripts/generate-brand.py
```

## 3. Colour

Every colour is a token: CSS variables in `src/index.css` and Tailwind names in `tailwind.config.js`.
- **Components never use hex literals.** `src/lib/uiConsistency.test.ts` enforces this. The only allowlisted files
  are the logo, the always-dark launch screens and the chart palette.
- **Themes.** Night is the default. Day mirrors every scale one step darker so the same classes keep AA contrast.
- **Accent switch.** `<html data-product="nms|grid">` switches the `brand-*` scale and the `solid-*` fills.

### Foundation (night)

| Token | Value | Tailwind |
|---|---|---|
| Primary background | `#0B1220` | `bg-bg` |
| Secondary background (sidebar, header, table heads) | `#0F172A` | `bg-panel2` |
| Surface (cards) | `#111C2E` | `bg-panel` |
| Elevated (menus, dialogs, tooltips) | `#162238` | `bg-elevated` |
| Border | `#263449` | `border-line` |
| Primary text | `#F1F5F9` | `text-slate-100` |
| Secondary text | `#94A3B8` | `text-muted` / `text-slate-400` |
| Muted text | `#64748B` | `text-subtle` / `text-slate-500` |
| Accent | NMS `#38BDF8` · Grid `#A78BFA` | `text-brand-400`, `bg-brand-500/10`, `bg-solid-brand` |
| Text on accent fills | `#0B1220` (night) · white (day) | `text-solid-on` |

### Product accent: where it appears, and nowhere else

- active navigation and selected tabs;
- primary buttons and focus rings;
- links;
- the product word in the logo;
- the product's own chart series (`SERIES_ROLE.primary`, read from `--chart-primary`).

### Status (one meaning everywhere)

| State | Colour | Tailwind / class |
|---|---|---|
| Healthy / operational | `#22C55E` | `emerald-*` (mapped to green), `text-ok`, `.dot-ok` |
| Warning / degraded | `#F59E0B` | `amber-*`, `text-warn`, `.dot-warn` |
| Critical / down | `#EF4444` | `red-*`, `text-bad`, `.dot-bad` |
| Informational | `#38BDF8` | `sky-*`, `.dot-info` |
| Unknown / disabled | `#64748B` | `slate-500`, `.dot-unknown` |

**Severity** (`<Sev>`, `.sev-*`): critical `#EF4444`, high `#F97316`, medium `#F59E0B`, low `#38BDF8`, informational
`#64748B`.

Never convey state by colour alone. A status dot sits beside a text label: `<Kpi tone>` adds a dot with an accessible
name, and pills carry the word.

### Charts (`components/Chart.tsx`)

- **Categorical palette.** It leads with the two product accents and avoids pure green, red and amber, so a category
  is never read as a status. Night: `#38BDF8 #A78BFA #2DD4BF #F472B6 #FBBF24 #818CF8 #FB923C #94A3B8`.
- **More than 8 series:** fold the rest into "Other".
- **Roles:** `primary` (product accent), `alert` (`#EF4444`), `warn` (`#F59E0B`, drawn dashed beside alert), `muted`.
- **Status:** `STATUS_HEX` and `statusColor(theme, state)`.
- **Chrome:** navy tooltips, `#263449` axes, `#1A263A` grid lines, Inter with tabular numbers.

## 4. Typography

**Fonts:**
- Inter Variable, self-hosted (`@fontsource-variable/inter`, bundled: the CSP allows `font-src 'self'` only).
- Monospace: JetBrains Mono if installed, else the system monospace.

| Role | Size / weight | Class |
|---|---|---|
| Page title | 24 px semibold | `.page-title` |
| Section title | 18 px semibold | `.section-title` |
| Card title | 14 px semibold | `.card-h` (via `<Card title>`) |
| Body | 13.5 px regular | default |
| Secondary / table | 12–13 px | `.tbl`, `text-xs` |
| Labels / eyebrows | 11 px semibold, uppercase, +8 % tracking | `.eyebrow`, table heads |
| Metrics | 20 → 24 → 26 px semibold, tabular | `.metric` (responsive) |

**Usage:**
- Use tabular numerals (`tabular-nums`, automatic in `<time>`, `.num` cells and metrics) for counters, traffic,
  timestamps and IP tables.
- Use monospace (`.mono`, `font-mono`) only for IPs, MACs, ports, IDs, hashes and CLI output.
- Avoid extra bold: use semibold for emphasis and medium for active navigation.

## 5. Spacing, shape and elevation

- **Spacing:** a 4 px base. Card padding is 16 px (`.card-b`); grid gaps are 12 px for KPI rows and 16 px for cards;
  page padding is 12 px on phones and 20 px from `sm`.
- **Radius:** 12 px for cards, 8 px for controls, 6 px for pills and menu items, and 28 % for the logo tile.
- **Elevation:**

  | Element | Treatment |
  |---|---|
  | Cards | `shadow-card` (subtle) |
  | Menus, dialogs, drawers | `shadow-pop` |
  | Elevated surfaces | lighter fill, not a heavier shadow |

- **Borders:** 1 px `border-line`. Don't nest cards inside cards; use sections inside one card.

## 6. Components (`src/components/ui.tsx`, `src/index.css`)

| Component | API / classes | Notes |
|---|---|---|
| Card | `<Card title right bodyClass>` · `.card .card-h .card-b` | default; `card-interactive` for clickable cards |
| Metric card | `<Kpi label value sub tone onClick>` | label eyebrow, tabular value, context line, status dot with text; clickable = drill-down |
| Buttons | `.btn` (secondary), `.btn-primary`, `.btn-ghost`, `.btn-danger`, `.btn-icon`, `.btn-sm` | hover, active press, focus ring, disabled; loading = `<Spinner />` + "…ing" label |
| Inputs | `.input`, `.label`, `.help`, `.field-error`, `<Field label hint>` | the label wraps the control; checkboxes and radios use the accent |
| Tables | `.tbl` in `<TableWrap maxH>` | compact rows, uppercase heads, sticky head with `maxH`, hover, `.num` right-aligned tabular, `rowProps()` for keyboard-accessible rows, `<SortTh>`, `<Pager>` |
| States | `<Loading q>` (skeleton / error), `<Empty text>` | every list has all three |
| Tabs | `<Tabs>` | accent underline; arrow keys, Home, End |
| Modal / Drawer | `<Modal>`, `<Drawer>` | scrim, pop / slide-in, focus trap, Escape, focus returns to the opener |
| Pills | `.pill`, `<Sev>`, `.sev-*` | |
| Status dot | `.dot .dot-ok/-warn/-bad/-info/-unknown` | always beside a label |
| Skeleton | `.skeleton` | shimmer, disabled with reduced motion |
| Tooltip | `.tip[data-tip]` | hover and keyboard focus; use `title` inside scroll containers |
| Logo | `<SentinelMark>`, `<SentinelTile>`, `<SentinelLogo>`, `<SplashScreen>` | `components/Brand.tsx` |
| Launch surfaces | `<AuthShell>`, `AUTH.*` | always dark: login, product selection, no access |

## 7. Application shell

**Sidebar** (`components/Sidebar.tsx`):
- logo tile, product name, tagline / status, product switcher;
- grouped navigation with foldable groups and SVG chevrons;
- active item: an accent bar, an accent icon and a tinted row;
- badges for open alerts and incidents (with accessible counts);
- collapse to a 68 px rail (native tooltips, `aria-label`s);
- user block with sign-out;
- on phones it becomes a drawer with a scrim.

**Header** (`components/Layout.tsx`):
- breadcrumbs (product / section / page, from the navigation definition), last updated, refresh and theme toggle;
- a second row with the global scope (time range, firewall, site, search, auto-refresh), hidden on pages with their own
  filters (Traffic Intelligence) and folded behind "Filters" on phones;
- "Skip to content" link;
- the document title follows the page.

**Content:** fluid width, 20 px padding, cards in responsive grids (`.kpi-grid`, `.grid-cards`).

## 8. Iconography

One set: the inline 24 px stroke icons in `components/Sidebar.tsx` (`ICONS`), with a 1.8 stroke, round caps and
joins, and `currentColor`.
- No icon dependency and no emoji. Unicode symbols are not used as icons in the shell. Some page bodies still use
  arrows (→) in text links.
- Navigation icon names are set in `lib/products.ts` (`icon:` on each item).
- Common actions: refresh, filter, close and chevrons use the same stroke style (Layout, ui).

## 9. Motion

Motion is short and purposeful:
- 150 ms colour and border transitions;
- 160 ms pop-in for menus and dialogs;
- 200 ms drawer slide;
- skeleton shimmer.

`prefers-reduced-motion` turns all of it off (`index.css`). There are no animated backgrounds.

## 10. Accessibility

- **Contrast:** AA on text in both themes. Secondary text is 7:1 on night surfaces, and accent fills carry dark text in
  night (9:1 / 7.6:1) and white in day.
- **Focus:** a visible 2 px accent focus ring on every control.
- **Keyboard:**
  - keyboard-operable rows (`rowProps`), tabs and menus;
  - dialogs trap focus and return it to the opener;
  - a skip link.
- **Labels:** form captions are real labels, and icon-only buttons have `aria-label`s.
- **Colour:** status is never colour-only.

## 11. Theme rules

- Night is the primary theme (`theme-init.js` default). The day theme uses the same tokens. The user's choice is
  remembered per browser.
- **Do:** use tokens (`bg-panel`, `text-muted`, `border-line`, `brand-*`, status hues).
- **Don't:**
  - use hex literals in components;
  - use `var(--token)` directly as a colour (tokens are RGB triplets: use `rgb(var(--token) / a)` in CSS);
  - set product colours outside `brand-*`.
- The launch screens (sign-in, product selection) are always dark by design.

## 12. Examples

```tsx
<Card title="Top applications" right={<ExportLink … />}>
  <Loading q={q} />
  {q.data && (q.data.items.length ? <TableWrap maxH="max-h-96"><table className="tbl">…</table></TableWrap> : <Empty text="No traffic in this window." />)}
</Card>

<div className="kpi-grid">
  <Kpi label="Devices online" value="128 / 130" tone="warn" sub="2 unreachable" onClick={() => nav("/switches?state=down")} />
</div>

<button className="btn btn-primary"><Spinner /> Saving…</button>
<span className="inline-flex items-center gap-1.5"><span className="dot dot-bad" aria-hidden />Down</span>
```
