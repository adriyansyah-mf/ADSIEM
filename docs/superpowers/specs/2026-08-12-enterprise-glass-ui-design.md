# Enterprise Glassmorphism UI Redesign — Design Spec

Date: 2026-08-12
Status: Approved for planning

## Context

The dashboard (`dashboard/`) is a 26-page React + Tailwind SIEM admin console. It currently
has **two overlapping, inconsistent visual themes**:

1. `src/index.css` defines a cyberpunk/retro SOC theme: navy base (`#050a12`), neon cyan
   accent (`#00d4ff`), `Rajdhani`/`Exo 2`/`Share Tech Mono` fonts, uppercase page titles,
   a scanline grid background (`body::before`), and `glow-*` box-shadow utilities.
   `DataTable.tsx`, `SeverityBadge.tsx`, and `StatusBadge.tsx` follow this theme (recent
   commits were actively pushing more pages toward it: title-color unification,
   `FimPage`/`AuditLogsPage` table alignment, `DataTable` retro-theme alignment).
2. `Layout.tsx` — the component actually mounted by the router — uses a **different**,
   flatter slate/blue palette (`#111318`, `#0d0f14`, accent `#3b82f6`) with plain
   system/Inter-ish typography and no glow/scanline effects. `Sidebar.tsx` is a separate,
   unused (dead code) nav component that nobody imports.

The user supplied a reference file, `enterprise_siem_dashboard.html`, showing a
Splunk-style enterprise SIEM dashboard: navy base (`#07111d`), blue accent (`#3193ff`),
flat solid gradient cards, KPI row with sparklines, donut charts, severity-badged tables,
geolocation map, and an activity heatmap.

**Goal:** replace both existing themes with a single, consistent design system —
"enterprise" in layout/density (matching the reference's information architecture) and
**glassmorphism** in surface treatment (frosted, translucent panels instead of the
reference's flat solid cards) — applied across all 26 pages and shared components.

This was converged on visually across three rounds of browser mockups (see
`.superpowers/brainstorm/1663412-1786516359/content/visual-style*.html`): the user
rejected pure cyan-neon (option A) and light-mode enterprise (option E), and confirmed
the final merge mockup (`visual-style-v3-merge.html`) that combines the reference's navy/
blue palette and layout density with a frosted-glass card treatment.

## Scope

**In scope:** visual/styling redesign only, applied globally so it cascades to all 26
pages:
Dashboard, Agents, Logs, Events, Alerts, Cases, CaseDetail, Hunts, UEBA, Hygiene, FIM,
LiveResponse, Rules (includes the in-page Correlation panel), Decoders, YARA, Artifacts,
SOP, Handover, Webhooks, AuditLogs, Settings, Users, SOAR, MitreHeatmap, Reports,
LogSources, Login.

**Out of scope:**
- No backend/API changes, no new features, no changes to data-fetching or route logic.
- No light-mode / theme toggle — dark-only, per user decision (rejected the "Light
  Enterprise" option).
- `Sidebar.tsx` — confirmed dead code (no imports anywhere in `src`), left untouched.
- Page-specific custom components (`AttackGraph`, `QueryBuilder`, `YamlEditor`, MITRE
  heatmap grid) get chrome-only restyling (card wrapper, borders, colors) — their
  internal rendering logic is not rewritten.

## 1. Design tokens

Replace the token block in `src/index.css` (`:root` / `.dark`) with an enterprise-glass
palette derived from the user's reference file:

| Token | Value | Notes |
|---|---|---|
| `--bg-base` | `#07111d` | page background base (was `#050a12`) |
| `--bg-panel` | `#0d1a2a` | |
| `--bg-card` | `#101f31` | |
| `--border` | `#1d3045` | |
| `--accent-blue` (primary) | `#3193ff` | replaces `--accent-cyan` as the primary accent everywhere |
| `--accent-red` (critical) | `#ff4d4d` | |
| `--accent-orange` (high) | `#ff941f` | |
| `--accent-yellow` (medium) | `#f3c43e` | |
| `--accent-green` (low/ok) | `#64c466` | |
| `--accent-purple` | `#a765f5` | secondary/incident accent, matches reference |
| `--text-primary` | `#e8f0fa` | |
| `--text-secondary` | `#80a0be` | |
| `--text-muted` | `#5c7086` | |
| `--glass-bg` | `rgba(13,26,42,0.45)` | card/panel fill |
| `--glass-border` | `rgba(148,197,255,0.10)` | card/panel border |
| `--glass-blur` | `blur(18px) saturate(150%)` | `backdrop-filter` value for cards |
| `--glass-blur-chrome` | `blur(18px) saturate(140%)` | sidebar/topbar (slightly less saturated) |
| `--radius` | `0.5rem` (8px) | down from mockup's 14px — smaller reads more "enterprise", not "consumer app" |

Update Tailwind's `hsl(var(--...))`-mapped compat tokens (`--background`, `--card`,
`--primary`, `--muted`, `--destructive`, etc.) to match, so existing `bg-card`,
`border-border`, `text-primary`, `bg-muted` Tailwind classes throughout the 26 pages
automatically pick up the new palette with zero per-page class changes.

**Background:** replace the flat base + scanline-grid (`body::before` repeating-linear-
gradient) with a soft gradient mesh — three faint radial blobs (blue top-left, purple
top-right, blue bottom-center) over the navy base, as in the merge mockup. This is what
makes the glass blur visually read; a flat single-color background makes
`backdrop-filter: blur()` invisible.

**Typography:** drop `Rajdhani` / `Exo 2` / `Share Tech Mono` and the `main h1 { text-
transform: uppercase }` rule. Adopt **Inter** (already loaded via Google Fonts import for
the reference-matching look) as the sole UI font, at normal case, for headings, body, and
tabular data alike. Keep `font-variant-numeric: tabular-nums` on numeric table cells.

**Radius & shadow:** `--radius: 8px` for cards/buttons/inputs, `10px` for larger panels.
Card shadow: `0 8px 24px rgba(0,0,0,0.18), inset 0 1px 0 rgba(255,255,255,0.04)` (matches
merge mockup) for subtle depth without heavy glow. Existing `.glow-cyan/red/green/orange`
utility classes are redefined to use the new palette (blue/red/green/orange) with reduced
opacity/spread — glow becomes an occasional accent (active nav item, live indicator), not
a default card treatment.

## 2. Global chrome — `Layout.tsx`

- **Sidebar:** becomes a glass panel — `background: var(--glass-bg)`, `backdrop-filter:
  var(--glass-blur-chrome)`, right border `var(--glass-border)` — replacing the flat
  `#111318`. Existing nav grouping (Monitor / Analytics / Response / Configuration /
  Administration), collapse/expand behavior, and role filtering (`hasRole`) are
  unchanged — restyle only. Active nav item: left border `--accent-blue`, translucent
  blue background, label color bump to near-white, small glow (`0 0 10px
  rgba(49,147,255,0.35)`), matching the reference/mockup pattern. Bottom agent-count
  status strip keeps its green/gray online dot logic, restyled onto glass.
- **Topbar:** becomes a glass bar — same fill/blur as sidebar, thin bottom border. Page
  title, live-feed pulse dot, global search box, clock, Admin dropdown, and Sign-out
  button keep their existing behavior; only surface colors, border-radius, and font
  change. Search dropdown results panel and Admin dropdown menu also get the glass
  treatment (currently flat `#111318` panels) for consistency.
- **`AssistantWidget`** (floating chat widget): restyle its container to match the glass
  card treatment so it doesn't look like a leftover flat-theme element.

## 3. Shared components

New primitives in `src/components/ui/` (this directory doesn't exist yet — no shared
`Card`/`Button` primitives currently exist; every page hand-rolls containers with ad-hoc
Tailwind classes):

- **`GlassCard`** — the base panel: `bg-[var(--glass-bg)] backdrop-blur-xl border
  border-[var(--glass-border)] rounded-lg shadow-[...]`. Accepts optional `title`/
  `actions` slot to cover the common "card with a header + a `View all →` link" pattern
  seen in the reference.
- **`PageHeader`** — page title + optional breadcrumb + right-aligned action buttons
  (mirrors the reference topbar's `<h1><span class="crumb">` + `.actions` pattern),
  replacing the current copy-pasted `<h1 className="text-xl font-bold">` (or inline-
  styled Rajdhani heading) at the top of every page.
- **`StatCard`** — KPI tile: label, large value, trend delta (colored ↑/↓), optional
  sparkline slot. Used on `DashboardPage` and anywhere else a page currently renders ad-
  hoc metric tiles.

Updates to existing shared components (no prop/behavior changes, styling only):

- **`DataTable.tsx`** — outer container becomes `GlassCard`-styled instead of `bg-card
  border-border`; header row uses `--text-secondary` on transparent glass instead of
  solid `bg-muted`; row hover accent changes from hardcoded `hover:border-l-cyan-500/40`
  to the new blue token; pagination/search/date-range controls keep their exact current
  markup and handlers, restyled to match.
- **`SeverityBadge.tsx` / `StatusBadge.tsx`** — drop `fontFamily: 'Rajdhani'` +
  uppercase + letterSpacing; use Inter medium-weight, same pill shape, colors remapped
  to the new severity tokens (critical/high/medium/low/info → red/orange/yellow/
  green/blue). `color-mix` translucent background approach is kept (it already works
  well for a glass aesthetic).
- **Modals** (`AlertDetailModal`, and any Radix `Dialog`-based modal) and **`Toaster`** —
  restyle their surface (overlay + content panel) to the glass treatment so pop-over UI
  doesn't look like a flat-theme leftover against the new glass background.

## 4. Rollout across the 26 pages

Since no shared `Card` primitive exists today, each page currently composes its own
container markup. The rollout is a **mechanical per-page pass**, not a rewrite:

1. Replace ad-hoc wrapper `div`s (`className="rounded border border-border bg-card p-4"`
   or inline-styled equivalents) with `<GlassCard>`.
2. Replace each page's top `<h1>` (whether plain `text-xl font-bold` or inline-styled
   Rajdhani heading) with `<PageHeader title="..." />`, optionally with action buttons
   where a page already has top-right buttons (e.g., "New Case", "Export").
3. Where a page renders ad-hoc metric/count tiles (e.g., Dashboard's summary numbers),
   swap in `<StatCard>`.
4. Buttons and inputs across pages pick up the new token colors automatically where they
   use Tailwind's `border-border`/`bg-primary`/`text-muted-foreground` classes; pages
   with hardcoded hex colors (e.g., leftover `#3b82f6`/`#111318` inline styles copied
   from the old `Layout.tsx` pattern) get those replaced with the new tokens.
5. Pages with bespoke visualizations (`AttackGraph`, `QueryBuilder`, `YamlEditor`,
   `MitreHeatmapPage`'s grid) keep their internal rendering as-is; only their outer
   card/panel chrome is restyled.

No page's data-fetching, routing, form logic, or business rules change in this pass.

## Testing / verification

- Visual QA pass in a running dev server (`npm run dev`) across a representative sample
  first (Dashboard, Alerts, Cases, CaseDetail, a settings-style page, a table-heavy page
  like Logs or AuditLogs, a page with a bespoke visualization like MitreHeatmap), then
  the remaining pages.
- Check both collapsed and expanded sidebar states, and the search/admin dropdowns.
- No automated visual regression tooling exists in this repo; verification is manual
  via browser (per project convention for frontend changes).
