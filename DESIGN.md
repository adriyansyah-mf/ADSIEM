# AD-SIEM design system

## 1. Atmosphere & identity

A quiet security operations workspace. Existing features, role gates, data tables,
severity semantics and the AD-SIEM wordmark remain. This approved consolidation
replaces the previous Exo/Rajdhani/neon theme with neutral layered surfaces,
readable system typography and a restrained blue action accent. Operational risk,
not decoration, determines what receives a status color.

## 2. Color

The existing dark-only product remains dark in this iteration, including when the
OS prefers light. A light-theme selector is not introduced. Canonical values live
in `dashboard/src/index.css`; legacy `--bg-*`, `--accent-*`, and Tailwind aliases
resolve to the same palette, so existing screens inherit the foundation.

| Role | Token | Value |
| --- | --- | --- |
| Canvas | --bg-base | #101318 |
| Navigation | --bg-panel | #15191f |
| Panel | --bg-card | #1a1f27 |
| Hover | --bg-hover | #242c37 |
| Divider | --border-default | #343e4c |
| Primary text | --text-primary | #edf1f7 |
| Secondary text | --text-secondary | #b2bdcd |
| Metadata | --text-muted | #9aa7bb |
| Action | --accent-cyan | #83adfa |
| Action fill / ink | --action-fill / --action-ink | #83adfa / #101318 |
| Critical/error | --accent-red | #ff8997 |
| High/warning | --accent-orange | #f0b383 |
| Medium | --accent-yellow | #e2ca82 |
| Success/low | --accent-green | #85c9a7 |

Status badges pair a named label and a dot with a low-alpha semantic surface.
Neutral controls use neutral borders. Focus rings are the only accent outlines.
The legacy hex `--border` is separated from the HSL Tailwind `--border-tw` token.

## 3. Typography

UI: `system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif`.
Technical values: `ui-monospace, SFMono-Regular, Consolas, monospace`.
No third-party font requests. Sentence case headings, tabular numerals for metrics.

| Role | Size | Weight |
| --- | --- | --- |
| Page heading | 24px | 600 |
| Panel heading | 15px | 600 |
| Body/control/table | 14px | 400 / 500 |
| Metadata/badge | 12px | 400 / 500 |
| Metric | 30px | 600 |

Metadata is secondary, not the main content. Use wrapping for titles and paths;
monospace never substitutes for the body font in long prose.

## 4. Spacing & layout

4px base, with 4/8/12/16/20/24/32/40/48px steps. Page padding is 24px desktop,
16px phone; panel padding 20px. Main content is fluid up to 1600px. Sidebar is
232px expanded / 64px rail; header 64px. Below 768px, navigation is a native modal
dialog. Case supporting panes stack below 1100px.

The shell follows the [fixed-sidenav-shell spatial pattern](https://github.com/changeroa/StyleGallery/blob/main/patterns/viewport-shell/fixed-sidenav-shell.md):
the header and navigation stay fixed, `main` owns page scrolling, navigation owns
its own overflow. Dashboard panels do not add vertical scroll regions. Tables
own horizontal overflow; sticky headers are only used in bounded table regions.
Every flex/grid child carrying content can shrink (`min-width: 0`).

## 5. Components

- `PageHeader`: eyebrow, h1, description and wrapping actions. One prominent
  action at most; mobile source order matches reading order.
- `Panel`: neutral bordered section, semantic h2, optional action slot, 20px body.
  Used for dashboard and case-detail sections. No decorative accent edges.
- `QueryState`: named loading, error with Retry, and empty with next-step copy.
  `role=status` for loading, `role=alert` for failure. Never turn errors into zeros.
- `SeverityBadge` / `StatusBadge`: common compact label + dot + tonal background.
  Sentence case, no glow. Status and severity stay distinct concepts.
- `DataTable`: named search/date/density/column controls, keyboard-accessible row
  actions, neutral hover, bounded horizontal overflow, contextual empty copy,
  CSV explicitly limited to the current page, selected density/column state.
- `AppSidebar`: grouped task navigation, role filtering, active wash + icon,
  collapsed tooltips; native mobile dialog provides Escape, focus containment
  and focus return. All existing routes remain reachable.
- `MetricCard`: primary value, unit/time-window label, optional destination.
  Values come from server aggregates, never a paginated sample. Missing values
  show an em dash, with query failure reported separately.
- `WorkspaceDialog`: native modal dialog, heading and description, neutral bordered
  surface, close control, Escape dismissal, focus containment and focus return.
  It owns vertical scrolling when its content exceeds the viewport. Width is
  bounded at 640px (standard) or 768px (deployment), with 16px viewport clearance.
  Confirmation dialogs name the exact host/case and consequences; submitting
  disables duplicate requests and dismissal until the request finishes. Failure
  remains inside the dialog with a retryable action. Sensitive token dialogs are
  read-only and never fetch until explicitly opened.
- Operational list pages reuse `PageHeader`, labelled filter bars, `DataTable`,
  shared badges and `QueryState`. Case quick actions live in expandable table
  rows; endpoint response actions require confirmation. Result totals describe
  the current server-filtered query, not a page-local sample.
- Telemetry explorers share an explicit Lucene search form (`?q=`), an optional
  structured query builder, and a cursor-aware results footer. Applying search
  or structured filters starts a fresh cursor chain; no offset/page jumps are
  invented. Previous results are not labelled as the new page while it loads.
  The structured builder uses labelled field/operator/value controls, wrapping
  neutral groups, and explicit Apply/Clear actions. Its draft survives free-text
  searches. Raw log and decoded event evidence opens read-only in `WorkspaceDialog`;
  long messages and unbroken values wrap without truncating the original data.

Shared states: hover changes the surface, active retains a tonal wash, visible
keyboard focus, disabled controls remain legible, and pending actions disable
duplicate submission. Primitive QA uses the real components with a temporary
local harness; the harness is not a production route.

## 6. Motion & interaction

120ms opacity/color feedback, 180ms transform for contextual overlays. No
decorative pulsing, grid backgrounds, or glow. No animated width or layout.
Reduced motion removes positional movement while retaining immediate state
feedback. Data refresh keeps the last successful data and labels failures/staleness.
Search is debounced; shortcuts never change data or approve actions.

## 7. Depth & surface

Neutral borders distinguish panels; progressively lighter surfaces distinguish
canvas, navigation, panels and hover. Shadows belong only to dialogs/popovers.
Radii: 4px badges, 6px controls, 8px panels, 12px dialogs. Icon set remains Lucide.

## 8. Accessibility constraints & accepted debt

Target WCAG 2.2 AA: 4.5:1 body contrast, visible focus, named inputs and icon
controls, semantic headings/landmarks, no color-only states, keyboard navigation,
and reduced-motion support. Phone controls use a 44px minimum height.

Existing specialized screens retain their workflows and some legacy inline
styling. They inherit the palette, but are not claimed as fully redesigned or
fully accessibility-audited. No new accessibility debt is accepted. Visual QA
must distinguish tested screens from regression-smoke coverage.
