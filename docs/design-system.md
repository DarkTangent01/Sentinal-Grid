# Sentinel design system

Sentinel is one platform with two products. They share every foundation (surfaces, type, spacing, components, status
colours) and differ only in name and accent.

| Product | Tagline | Accent |
|---|---|---|
| **Sentinel NMS** | Network Monitoring & Intelligence | sky `#38BDF8` (restrained: selected navigation, own chart series, highlights) |
| **Sentinel Grid** | Security Intelligence Platform | violet `#A78BFA` (same restraint) |

Use exactly these names. Not "Sentinel SIEM", "Grid SIEM" or "Sentinel Security".

## 1. Brand identity

Sentinel stands for visibility, intelligence, protection, precision and operational control. The voice is calm and
exact: say what is measured, what is estimated, and what is not known. The visual language is **minimal black**: true
black and neutral graphite surfaces, one hairline border, neutral primary actions, restrained product accents, status
colours only for status, compact density, and no gradients, glows, patterns or decorative animation anywhere.

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

**Colour** (solid, no gradients):

| Use | Dark background | Light background |
|---|---|---|
| Platform | `#F5F5F5` | `#09090B` |
| NMS | `#38BDF8` | `#0284C7` |
| Grid | `#A78BFA` | `#7C3AED` |

The tile is `#0A0A0A` with a 1 px `#292929` border, no shadow.

**Rules:**
- Keep clear space of at least the centre node's diameter around the mark.
- Minimum size is 16 px (mark) and 96 px wide (logo with wordmark).
- Don't rotate, outline, add effects to, re-colour outside the defined colours, or place the mark on a busy image. On colour, use the mono mark.
- The wordmark is Inter Semibold with −2 % tracking. "Sentinel" is set in the text colour; the product word is set in
  its accent.

Regenerate the static assets after a geometry change with:

```bash
cd frontend && python3 scripts/generate-brand.py   # needs Pillow
```

## 3. Colour

Every colour is a token: CSS variables in `src/index.css` and Tailwind names in `tailwind.config.js`.
- **Components never use hex literals.** `src/lib/uiConsistency.test.ts` enforces this. The only allowlisted files
  are the logo, the always-dark launch screens and the chart palette.
- **Themes.** Night is the default. Day mirrors every scale one step darker so the same classes keep AA contrast.
- **Accent switch.** `<html data-product="nms|grid">` switches `--accent` / `brand-*` and `--chart-primary`. It does
  **not** recolour primary buttons: those are neutral in both products.

### Foundation (night)

| Token | Value | Tailwind |
|---|---|---|
| Application background | `#090909` | `bg-bg` |
| Sidebar / header | `#0A0A0A` | `bg-panel2` |
| Surface (cards) | `#111111` | `bg-panel` |
| Secondary surface (tile in a card, row hover) | `#161616` | `--surface-tile` |
| Elevated (menus, dialogs, tooltips) | `#1C1C1C` | `bg-elevated` |
| Hover | `#222222` | `bg-hover` |
| Border | `#292929` | `border-line` |
| Strong border | `#383838` | `border-line-strong` |
| Primary text | `#F5F5F5` | `text-slate-100` |
| Secondary text | `#A1A1AA` | `text-muted` / `text-slate-400` |
| Muted text | `#71717A` | `text-subtle` / `text-slate-500` |
| Disabled text | `#52525B` | `text-disabled` |
| Primary action | `#F5F5F5` fill, `#090909` text (day: black fill, white text) | `bg-solid-brand text-solid-on` |

The `slate-*` scale is mapped to Tailwind's neutral `zinc`, so existing classes carry no blue tint. Day uses white
`#FFFFFF` / `#FAFAFA` surfaces, `#E4E4E7` borders and `#09090B` text.

### Product accent: where it appears, and nowhere else

- the active navigation item's 2 px bar;
- the product's own chart series (`SERIES_ROLE.primary`, read from `--chart-primary`);
- the product word on launch screens, and the logo mark;
- a meaningful highlight, sparingly.

Not on buttons, links, tabs, focus rings, pills or badges: links are neutral and underlined, the selected tab has a
neutral underline, focus is a neutral ring, and pills are neutral chips.

### Status (one meaning everywhere)

| State | Colour | Tailwind / class |
|---|---|---|
| Healthy / operational | `#22C55E` | `emerald-*` (mapped to green), `text-ok`, `.dot-ok` |
| Warning / degraded | `#F59E0B` | `amber-*`, `text-warn`, `.dot-warn` |
| Critical / down | `#EF4444` | `red-*`, `text-bad`, `.dot-bad` |
| Informational | `#38BDF8` | `sky-*`, `.dot-info` |
| Unknown / disabled | `#71717A` | `slate-500`, `.dot-unknown` |

**Severity** (`<Sev>`, `.sev-*`): a small dot plus the coloured word, no tinted background. Critical `#EF4444`, high
`#F97316`, medium `#F59E0B`, low `#38BDF8`, informational `#71717A`.

**Status pills** (alert state, compliance result, health and so on) are neutral chips (`.pill`) with the state's text
colour; no tinted fill or ring. Status dots never pulse.

Never convey state by colour alone. A status dot sits beside a text label: `<Kpi tone>` adds a dot with an accessible
name, and pills carry the word.

### Charts (`components/Chart.tsx`)

- **Categorical palette.** Product accent first, then neutral greys and a few muted hues; avoids pure green, red and
  amber so a category is never read as a status. Night: `#38BDF8 #2DD4BF #A78BFA #A1A1AA #F472B6 #FBBF24 #71717A #D4D4D8`; "Other" and "Unknown" are always the muted grey.
- **More than 8 series:** fold the rest into "Other".
- **Roles:** `primary` (product accent), `alert` (`#EF4444`), `warn` (`#F59E0B`, dashed beside alert), `muted`.
- **Status:** `STATUS_HEX` and `statusColor(theme, state)`.
- **Chrome:** `#1C1C1C` tooltips with a `#383838` border and no shadow, `#292929` axes, `#1C1C1C` grid lines, `#A1A1AA`
  labels. Lines are 1.5 px and straight (no smoothing); area fills are 6 % opacity.

## 4. Typography

**Fonts:**
- Inter Variable, self-hosted (`@fontsource-variable/inter`, bundled: the CSP allows `font-src 'self'` only).
- Monospace: JetBrains Mono if installed, else the system monospace.

| Role | Size / weight | Class |
|---|---|---|
| Page title | 22 px semibold | `.page-title` |
| Section title | 15 px semibold | `.section-title` |
| Card title | 13 px semibold | `.card-h` (via `<Card title>`) |
| Body | 13 px regular | default |
| Table | 12.5 px; heads 12 px medium, normal case, muted, no shaded band | `.tbl` |
| Metadata / labels | 11–12 px | `.eyebrow`, `text-xs`, `text-2xs` |
| Metrics | 20 → 22 px semibold, tabular | `.metric` (responsive) |

**Usage:**
- Use tabular numerals (`tabular-nums`, automatic in `<time>`, `.num` cells and metrics) for counters, traffic,
  timestamps and IP tables.
- Use monospace (`.mono`, `font-mono`) only for IPs, MACs, ports, IDs, hashes and CLI output.
- Avoid extra bold: use semibold for emphasis and medium for active navigation.

## 5. Spacing, shape and elevation

- **Spacing:** a 4 px base. Card padding is 16 px (`.card-b`); KPI gaps are 10 px, card gaps 12 px; page padding 12 px
  on phones and 20 px from `sm`.
- **Radius:** 8 px for cards (`rounded-card`), 6 px for controls, 4 px for pills, 24 % for the logo tile.
- **Elevation:** none on cards (`shadow-card` is `none`). Menus, dialogs and drawers use `shadow-pop` and the elevated
  surface; scrims have no blur.
- **Borders:** 1 px `border-line`; hover raises it to `border-line-strong`.
- **No boxes in boxes:** a `.card` inside a `.card` loses its border and becomes a flat `#161616` tile (CSS rule in
  `index.css`), so KPI cards inside a section card do not draw nested frames.
- **Density:** about four KPI cards per row at most (`.kpi-grid`, or `grid-cols-2 lg:grid-cols-4`); secondary figures go
  in one `<StatStrip>` row instead of more cards.

## 6. Components (`src/components/ui.tsx`, `src/index.css`)

| Component | API / classes | Notes |
|---|---|---|
| Card | `<Card title right bodyClass>` · `.card .card-h .card-b` | default; `card-interactive` for clickable cards |
| Metric card | `<Kpi label value sub tone onClick>` | 12 px label, tabular value (red / amber only for a problem), context line, status dot with text; clickable = drill-down |
| Stat strip | `<StatStrip items>` · `.stat-strip` | a quiet row of secondary figures (label over value); values can be links |
| Buttons | `.btn` (secondary), `.btn-primary`, `.btn-ghost`, `.btn-danger`, `.btn-icon`, `.btn-sm` | hover, active press, focus ring, disabled; loading = `<Spinner />` + "…ing" label |
| Inputs | `.input`, `.label`, `.help`, `.field-error`, `<Field label hint>` | the label wraps the control; neutral focus border; checkboxes use the text colour |
| Tables | `.tbl` in `<TableWrap maxH>` | compact rows (5 px), normal-case muted heads, sticky head with `maxH`, hover, `.num` right-aligned tabular, `rowProps()` for keyboard-accessible rows, `<SortTh>`, `<Pager>` |
| States | `<Loading q>` (skeleton / error), `<Empty text>` | every list has all three |
| Tabs | `<Tabs>` | neutral white underline; arrow keys, Home, End |
| Modal / Drawer | `<Modal>`, `<Drawer>` | scrim, pop / slide-in, focus trap, Escape, focus returns to the opener |
| Pills | `.pill`, `<Sev>`, `.sev-*` | neutral chip; severity is dot + word |
| Status dot | `.dot .dot-ok/-warn/-bad/-info/-unknown` | always beside a label |
| Skeleton | `.skeleton` | shimmer, disabled with reduced motion |
| Tooltip | `.tip[data-tip]` | hover and keyboard focus; use `title` inside scroll containers |
| Logo | `<SentinelMark>`, `<SentinelTile>`, `<SentinelLogo>`, `<SplashScreen>` | `components/Brand.tsx` |
| Launch surfaces | `<AuthShell>`, `AUTH.*` | always plain black, no pattern or gradient: login, product selection, no access |

## 7. Application shell

**Sidebar** (`components/Sidebar.tsx`), 240 px, `#0A0A0A`:
- the product mark (no tile), "Sentinel NMS" / "Sentinel Grid" in neutral text, tagline / status, product switcher;
- grouped navigation: **groups are collapsed by default except the one holding the current page**; a group the user
  opens or closes keeps that choice (per product, in the browser);
- active item: neutral `#222222` row, white text and icon, and a 2 px product-accent bar;
- badges for open alerts and incidents: a neutral chip with a red count (accessible names kept);
- collapse to a 64 px rail (native tooltips, `aria-label`s); user block with a neutral avatar and sign-out;
- on phones it becomes a drawer with a scrim.

**Header** (`components/Layout.tsx`), on the page background with one bottom border, no blur:
- one title line (product / section / page, no icon), last updated, refresh and theme toggle;
- the global scope row (time range, firewall, site, search, auto-refresh), hidden on pages with their own filters
  (Traffic Intelligence) and folded behind "Filters" on phones;
- "Skip to content" link; the document title follows the page.

**Content:** fluid width, 20 px padding, cards in responsive grids (`.kpi-grid`, `.grid-cards`).

## 8. Iconography

One set: the inline 24 px stroke icons in `components/Sidebar.tsx` (`ICONS`), with a 1.8 stroke, round caps and
joins, and `currentColor`.
- No icon dependency and no emoji. Unicode symbols are not used as icons in the shell. Some page bodies still use
  arrows (→) in text links.
- Navigation icon names are set in `lib/products.ts` (`icon:` on each item).
- Common actions: refresh, filter, close and chevrons use the same stroke style (Layout, ui).

## 9. Motion

Motion is short and purposeful: 100–150 ms colour and border transitions, a quick pop-in for menus and dialogs, the
drawer slide and the skeleton shimmer. No hover lift, glow, pulsing status dot or animated background.
`prefers-reduced-motion` turns all of it off (`index.css`).

## 10. Accessibility

- **Contrast:** AA on text in both themes. Secondary text `#A1A1AA` on `#111111` is about 7.5:1; the neutral
  primary button is black on near-white (about 18:1).
- **Focus:** a visible 1.5 px neutral focus ring on every control.
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
  - set product colours outside `brand-*`, or use the accent for buttons, links or pills.
- The launch screens (sign-in, product selection) are always black by design.

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
