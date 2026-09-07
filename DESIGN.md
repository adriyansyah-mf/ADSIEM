# AD-SIEM Design System

## 1. Atmosphere & Identity

AD-SIEM is an industrial-grade security operations workspace. It should feel like instrumentation an analyst trusts after years of use, not a product a marketer sold them: compact gunmetal surfaces, a rationed steel-blue interactive accent, and copper reserved only for urgent, non-severity operational attention. It rejects blur, glow, gradients, and decorative cyberpunk effects — hierarchy comes from layout, typography, borders, and sparse semantic color.

Source of truth: [`docs/superpowers/specs/2026-09-07-ironwatch-ai-siem-ui-ux-design.md`](docs/superpowers/specs/2026-09-07-ironwatch-ai-siem-ui-ux-design.md) (the Ironwatch AI-SIEM UI/UX design contract) and [`design-system-enterprise-soc/design-system.md`](design-system-enterprise-soc/design-system.md) (the Ironwatch token/component reference). This document reconciles both into the single contract that governs all touched components, superseding the prior navy-glass contract and its `docs/superpowers/specs/2026-08-12-enterprise-glass-ui-design.md` source.

## 2. Color

### Palette

| Role | Token | Value | Usage |
|---|---|---:|---|
| Canvas | `--bg-base` | `#14181D` | Application background |
| Surface | `--bg-panel` / `--bg-card` | `#1B2028` | Workspace and data regions — cards, sidebar, topbar, tables |
| Elevated surface | `--bg-hover` / `--glass-bg-strong` | `#232A34` | Menus, dropdowns, dialogs, hover rows |
| Sunken well | *(surface-sunken)* | `#10141A` | Inputs, log viewers, code blocks |
| Border | `--border` | `#2E3540` | Opaque dividers and controls |
| Text primary | `--text-primary` | `#E4E8ED` | Titles and primary values |
| Text secondary | `--text-secondary` | `#9AA4B2` | Body and supporting labels |
| Text muted | `--text-muted` | `#68717E` | Timestamps and tertiary metadata |
| Interactive accent | `--accent-blue` | `#2C6E8E` | Focus, links, selected controls, primary action — the only general accent |
| Attention-now | `--accent-copper` | `#C9822E` | Urgent, non-severity operational attention only (e.g. unread, live) — never decorative |
| Critical | `--accent-red` | `#D8393F` | Critical severity and destructive action |
| High | `--accent-orange` | `#D8752E` | High severity |
| Medium | `--accent-yellow` | `#D8B23D` | Medium severity and caution |
| Healthy / Low | `--accent-green` | `#4F8F63` | Online, success, low severity |
| Secondary / info | `--accent-purple` | `#5C7C99` | Informational, investigation context |

Rules:

- Steel blue is the only general interactive accent. Copper is rationed for "needs a human to look now," never decorative. Other accents are strictly semantic (severity/health).
- Color never carries status alone; pair it with text, icon, or shape. Severity and health states are labeled — shape-coded badges are the target contract (see Badge below); components not yet migrated must at minimum keep the text label.
- Components consume tokens, never raw color literals. `grep`-checked periodically; see Accepted Debt for current stragglers.
- Body text targets WCAG 2.2 AA contrast of at least 4.5:1; large UI and graphical controls target 3:1.
- No blur, no glow, no gradients, no glass. Depth comes from a 1px border and a flat, dark `box-shadow` only (see Depth & Surface).

## 3. Typography

| Role | Font | Usage |
|---|---|---|
| Display | `Archivo`, weights 600/700/800 | Page titles, KPI/metric values, compact headings |
| Body / UI | `Public Sans`, weights 400/500/600/700 | Default UI copy, tables, forms, navigation |
| Data | `JetBrains Mono` | Timestamps, hashes, IDs, IPs, query/code snippets |

Numeric content uses tabular figures (`font-variant-numeric: tabular-nums`) wherever digits line up in columns — counts, timers, table cells.

| Level | Size | Weight | Usage |
|---|---:|---:|---|
| Page title | `1.625rem` (26px) | 700, Archivo | Page identity |
| Section title | `1.0625rem` (17px) | 600, Archivo | Panel/card headers |
| Body | `0.9375rem` (15px) | 400, Public Sans | Primary reading text, form inputs |
| Body small | `0.8125rem` (13px) | 400, Public Sans | Default table/dense UI copy — the workhorse size |
| Label | `0.75rem` (12px) | 600, Public Sans | Field labels, fine print |
| Caption | `0.6875rem` (11px) | 700, JetBrains Mono, uppercase, `0.06em` tracking | Badge text, table column headers |
| KPI | `2.25rem` (36px) | 800, Archivo | Operational values |

Sentence case is the default. Uppercase is limited to compact machine-like metadata and table column labels. Decorative type, glow, gradients, and glass effects are out of scope.

## 4. Spacing & Layout

All design spacing uses a 4px base (`--space-1` through `--space-16`, see `design-system-enterprise-soc/design-tokens.json`).

- The fixed shell uses `100dvh`: `WorkflowSidebar` and `OperationalTopbar` stay fixed; `<main>` is the primary vertical scroll owner.
- Shell zones: navigation 216px (56px collapsed), fluid 12-column primary workspace, 320px contextual rail present only when it adds decision value. On 768px the rail becomes collapsible; at 375px it becomes an explicit, keyboard-accessible bottom sheet. The page itself never scrolls horizontally — tables own a labeled horizontal scroll region.
- Sidebar width matches the shell zone above; touch targets remain at least 44px on narrow/touch layouts.
- Breakpoints verified at 375px, 768px, 1280px, and 200% zoom.
- Border radius stays small (2–8px) — nothing bubbly; this is precision, not friendliness.

## 5. Components

### Application shell

Decomposed by responsibility (see `dashboard/src/components/shell/`):

- **`AppShell`** — orchestrates layout: skip link, sidebar + topbar + single scrolling `<main>`, owns cross-cutting state (sidebar collapsed, live-feed WebSocket).
- **`WorkflowSidebar`** — the workflow-grouped navigation (Command Center / Detection / Investigation / Agent Fleet / Automation / Governance). States: expanded/collapsed; item default/hover/active/focus. Icon-only collapsed control has an accessible name.
- **`OperationalTopbar`** — current page identity, live-feed indicator, `EntityCommandPalette` trigger, identity/admin menu, sign-out.
- **`EntityCommandPalette`** — global entity search (IP, hostname, user, hash, agent, alert, case), opened via trigger or keyboard shortcut, routes to the appropriate detail workspace. States: closed, open/typing, results, empty, error.

**Accessibility:** skip link targets `<main>`; menus expose expanded state; focus is never hidden under chrome. Keyboard flow: skip link → navigation → top-bar search → page header actions → main content → context rail.
**Motion:** opacity and transform only; 120ms micro-transitions; no width animation under reduced motion; `prefers-reduced-motion: reduce` disables non-essential transitions.

### PageHeader

Title/breadcrumb stack plus wrapping action cluster. Exactly one page-level `h1` (rendered in Archivo via the shared `main h1` rule). Actions remain keyboard reachable.

### MetricCard / StatCard

Label, primary value (tabular numerals), optional trend/sparkline. Variants: neutral, critical, high, medium, healthy, info. Status includes text, not color alone.

### DataTable

Toolbar, horizontally-scrollable table viewport (its own scroll region, never the page), pagination cluster. States: loading, populated, empty, error, row hover/focus, selected. Semantic table markup, labeled controls, visible focus.

### Badge family

`SeverityBadge`, `HealthBadge`, `ConfidenceBadge`, `ApprovalStateBadge` — static, no decorative animation, complete readable text, at least 3:1 boundary contrast. Target contract: shape + color + label (critical = square, high = triangle, medium = diamond, low = circle, info = outline) — see Accepted Debt for current color-only instances awaiting migration.

### Investigation & fleet primitives

`EvidenceTimeline`, `EntitySummary`, `ActionReviewSheet`, `AiRecommendationCard` (Investigation workspace); `AgentHealthScore`, `CollectorStateList`, `SpoolState`, `DriftIndicator` (Agent Fleet). Each ships default/hover/focus-visible/disabled/loading/empty/error states where relevant, added as their owning phase lands (see the Ironwatch spec's phased delivery table).

### Overlay surfaces

Scrim, elevated flat panel (solid `--bg-hover`, 1px border, `box-shadow: 0 12px 32px rgba(0,0,0,0.6)` — no blur), heading, body, close/action controls. Focus trap where supported, Escape closes, focus returns to trigger, `aria-live` for toast feedback.

### Form controls

States: default, hover, focus, disabled, read-only, loading, invalid, valid. Persistent label (never placeholder-as-label), inline error and recovery guidance, 44px minimum touch height on mobile. Focus is a visible 2px `--accent-blue` outline — never suppressed without a replacement (see `:where(button,a,input,select,textarea):focus-visible` in `index.css`).

## 6. Motion & Interaction

| Token | Value | Usage |
|---|---|---|
| `--motion-micro` | `120ms ease-out` | Press and hover feedback |
| `--motion-standard` | `200ms ease-in-out` | Menus, dialog transitions, sidebar state |

- Motion communicates state and causality; decorative motion is prohibited — no glow pulses, no ambient rings, no scanlines.
- Only `transform` and `opacity` animate.
- `prefers-reduced-motion: reduce` disables non-essential transitions.

## 7. Depth & Surface

Strategy: a 1px border plus a flat, dark `box-shadow`. No blur, no translucency, no glass.

| Level | Value | Usage |
|---|---|---|
| Surface | `1px solid var(--border)`, `box-shadow: 0 2px 8px rgba(0,0,0,0.5)` | Default cards, panels, shell chrome |
| Elevated | `1px solid var(--border)`, `box-shadow: 0 12px 32px rgba(0,0,0,0.6)` | Menus, dialogs, dropdowns |

## 8. Accessibility Constraints & Accepted Debt

### Constraints

- WCAG 2.2 AA target; visible 2px focus ring on every interactive element.
- Full keyboard operation for navigation, menus, search, tables, and dialogs.
- Reduced-motion support and 200% text zoom without loss of content or controls.
- Status never relies on color alone (target — see Accepted Debt for current gaps).
- Primary targets are at least 44 by 44 CSS pixels on narrow/touch layouts.
- Dense layouts keep stable wayfinding: page title, active navigation, and current state remain obvious.

### Inclusive personas

- **SOC analyst under incident pressure:** must scan severity, ownership, and next action without decorative noise.
- **Keyboard-only administrator:** must reach navigation, search, table tools, actions, and sign-out in logical order.
- **Low-vision analyst at 200% zoom:** must retain readable hierarchy without clipped primary content.
- **Motion-sensitive operator:** must receive all state changes with reduced motion enabled.

### Accepted debt

| Item | Location | Why accepted | Owner / Exit |
|---|---|---|---|
| Severity badges are color+text only, not yet shape-coded | `SeverityBadge.tsx`, `SeverityTile` (`CasesPage.tsx`), chart legends | Shape-coding touches JSX/SVG structure across many call sites, not just token values; deferred out of the Phase 1/2 shell-and-Command-Center scope | Exit when a dedicated badge-shape pass lands (tracked against the Ironwatch spec's Phase 6) |
| `--accent-copper` defined but unused | `index.css` | No component yet claims an "attention-now" surface distinct from severity | Exit when the first real attention-now indicator (e.g. unread Command Center brief) adopts it |
| Full route-level code splitting and bundle-size remediation | `dashboard/src/App.tsx` | Predates this redesign; changing it expands behavior scope beyond the visual/IA contract | Follow-up performance task |
| Some legacy pages retain page-local inline styles | Pages not yet touched by a phase | Existing theme is heavily inline-styled; each touched page removes old-theme literals as it's touched, untouched pages remain stable until their phase | Exit when the Ironwatch spec's Phase 6 (remaining pages adopt primitives) lands |
| `AlertDetailModal`'s status-change dropdown offers `new/in_progress/resolved/false_positive`, missing `acknowledged` (the actual status ~87% of live alerts carry) and `closed` | `components/AlertDetailModal.tsx` | Discovered while building Command Center's Priority Queue against the same data; fixing the dropdown touches the alert-close workflow, which is outside Phase 1/2's shell-and-landing-page scope | Exit with a dedicated alert-workflow pass; `_RESOLVED_STATUSES` in `server-api/app/api/routes/alerts.py` is the authoritative status set to reconcile against |
