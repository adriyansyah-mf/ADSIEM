# AD-SIEM Design System

## 1. Atmosphere & Identity

AD-SIEM is a calm, high-density security operations command center. It should feel precise, trustworthy, and continuously active without looking theatrical or cyberpunk. The signature is restrained navy glass: translucent operational surfaces sit over a subtle blue-violet ambient field, while semantic color is reserved for detections, health, and actions.

Source of truth: the approved [enterprise glass redesign spec](docs/superpowers/specs/2026-08-12-enterprise-glass-ui-design.md) and the local `enterprise_siem_dashboard.html` reference. The UI/UX database reinforced dark, scannable, status-led information hierarchy; where its generated palette conflicts, this approved contract wins.

## 2. Color

### Palette

| Role | Token | Value | Usage |
|---|---|---:|---|
| Canvas | `--bg-base` | `#07111d` | Application background |
| Panel | `--bg-panel` | `#0d1a2a` | Inputs and nested regions |
| Card | `--bg-card` | `#101f31` | Opaque fallback surface |
| Glass surface | `--glass-bg` | `rgba(13, 26, 42, 0.72)` | Cards, sidebar, topbar |
| Glass strong | `--glass-bg-strong` | `rgba(16, 31, 49, 0.90)` | Menus, modals, elevated UI |
| Border | `--border` | `#1d3045` | Opaque dividers and controls |
| Glass border | `--glass-border` | `rgba(148, 197, 255, 0.14)` | Translucent surface rims |
| Text primary | `--text-primary` | `#e8f0fa` | Titles and primary values |
| Text secondary | `--text-secondary` | `#9bb3c9` | Body and supporting labels |
| Text muted | `--text-muted` | `#6f879e` | Timestamps and tertiary metadata |
| Primary action | `--accent-blue` | `#3193ff` | Focus, links, active navigation |
| Critical | `--accent-red` | `#ff5c5c` | Critical severity and destructive action |
| High | `--accent-orange` | `#ff9f43` | High severity |
| Medium | `--accent-yellow` | `#f3c94f` | Medium severity and caution |
| Healthy | `--accent-green` | `#6bd47c` | Online, success, low severity |
| Secondary | `--accent-purple` | `#a979f7` | Investigation and AI context |

Rules:

- Blue is the only general interactive accent. Other accents are semantic.
- Color never carries status alone; pair it with text, icon, or shape.
- Components consume tokens, never raw color literals.
- Body text targets WCAG 2.2 AA contrast of at least 4.5:1; large UI and graphical controls target 3:1.

## 3. Typography

Primary and data font: `Inter, ui-sans-serif, system-ui, sans-serif`. Numeric content uses tabular figures rather than a separate monospace family.

| Level | Size | Weight | Line height | Tracking | Usage |
|---|---:|---:|---:|---:|---|
| Page title | `1.375rem` | 700 | 1.25 | `-0.015em` | Page identity |
| Section title | `1rem` | 600 | 1.35 | `-0.005em` | Panel headers |
| Body | `0.9375rem` | 400 | 1.5 | normal | Default UI copy |
| Body small | `0.8125rem` | 400 | 1.45 | normal | Dense table and navigation copy |
| Label | `0.75rem` | 600 | 1.35 | `0.02em` | Metadata and field labels |
| Caption | `0.6875rem` | 500 | 1.35 | `0.02em` | Secondary metadata |
| KPI | `1.75rem` | 700 | 1.1 | `-0.02em` | Operational values |

Sentence case is the default. Uppercase is limited to compact machine-like metadata and table column labels.

## 4. Spacing & Layout

All design spacing uses a 4px base.

| Token | Value | Usage |
|---|---:|---|
| `--space-1` | `0.25rem` | Tight icon details |
| `--space-2` | `0.5rem` | Inline groups |
| `--space-3` | `0.75rem` | Compact control padding |
| `--space-4` | `1rem` | Card and page rhythm |
| `--space-5` | `1.25rem` | Standard section padding |
| `--space-6` | `1.5rem` | Major groups |
| `--space-8` | `2rem` | Page section separation |

- The fixed shell uses `100dvh`: sidebar and topbar stay fixed; `<main>` is the primary vertical scroll owner.
- Desktop pages use a fluid 12-column grid with a 1536px content ceiling. Dashboard rails collapse below content-driven breakpoints.
- At 375px, primary content becomes one readable column with no page-level horizontal scrolling. Data tables may own a labeled horizontal scroll region.
- Sidebar width is 13.5rem expanded and 3.5rem collapsed. Touch targets remain at least 44px.
- Breakpoints verified at 375px, 768px, 1280px, and 1440px, plus 200% zoom.

## 5. Components

### Application shell

- **Structure:** fixed sidenav shell, fixed topbar, single scrolling main region.
- **States:** sidebar expanded/collapsed; navigation default/hover/active/focus; WebSocket live/offline; search closed/results/empty; admin menu closed/open.
- **Accessibility:** skip link targets `<main>`; icon-only collapse control has an accessible name; menus expose expanded state; focus is never hidden under chrome.
- **Motion:** opacity, background, and transform only; 150ms micro transitions; no width animation under reduced motion.

### GlassCard

- **Structure:** semantic `section` or `div`, optional header cluster, content region.
- **Variants:** default, elevated, interactive, compact.
- **States:** default, hover and focus for interactive cards, loading, empty, error.
- **Spacing:** `--space-4` default, `--space-3` compact.
- **Accessibility:** headings retain hierarchy; interactive cards use real links/buttons.

### PageHeader

- **Structure:** title/breadcrumb stack plus wrapping action cluster.
- **States:** with or without breadcrumb/actions; long-title wrapping.
- **Accessibility:** exactly one page-level `h1`; actions remain keyboard reachable.

### StatCard

- **Structure:** label, primary value, optional context/trend, optional sparkline.
- **Variants:** neutral, critical, high, medium, healthy, info.
- **Accessibility:** status includes text; trend arrows include descriptive labels; values use tabular figures.

### DataTable

- **Structure:** toolbar, horizontally scrollable table viewport, pagination cluster.
- **States:** loading, populated, empty, error, row hover/focus, selected.
- **Accessibility:** semantic table markup, labeled controls, visible focus, color-independent status badges.

### Badge

- **Variants:** severity and workflow status.
- **States:** static; no decorative animation.
- **Accessibility:** complete readable text and at least 3:1 boundary contrast.

### Overlay surfaces

- **Structure:** scrim, elevated glass panel, heading, body, close/action controls.
- **States:** opening, open, closing, busy, error.
- **Accessibility:** focus trap where supported, Escape closes, focus returns to trigger, `aria-live` for toast feedback.

### Form controls

- **States:** default, hover, focus, disabled, read-only, loading, invalid, valid.
- **Accessibility:** persistent label, inline error and recovery guidance, 44px minimum touch height on mobile.

## 6. Motion & Interaction

| Token | Value | Usage |
|---|---|---|
| `--motion-micro` | `120ms ease-out` | Press and hover feedback |
| `--motion-standard` | `200ms ease-in-out` | Menus, modal fade, sidebar state |
| `--motion-emphasis` | `360ms cubic-bezier(0.16, 1, 0.3, 1)` | Rare page-level reveal |

- Motion communicates state and causality; decorative motion is prohibited.
- Only `transform`, `opacity`, and `filter` animate.
- `prefers-reduced-motion: reduce` disables non-essential transitions and the live pulse.
- Pressed controls use a subtle transform without shifting neighboring layout.

## 7. Depth & Surface

Strategy: mixed translucent borders, tonal shift, and restrained shadows.

| Level | Value | Usage |
|---|---|---|
| Glass | translucent navy + 18px blur + inner rim | Default cards and shell chrome |
| Elevated | stronger navy + 20px blur + `0 18px 48px rgba(0, 0, 0, 0.34)` | Menus and modals |
| Interactive | glass plus subtle blue-tinted hover rim | Clickable rows/cards |

Glass is a hierarchy tool, not decoration. Avoid nested glass cards where spacing or a divider communicates grouping more clearly. Ambient gradients remain faint so detection data stays dominant.

## 8. Accessibility Constraints & Accepted Debt

### Constraints

- WCAG 2.2 AA target; visible 2px focus ring on every interactive element.
- Full keyboard operation for navigation, menus, search, tables, and dialogs.
- Reduced-motion support and 200% text zoom without loss of content or controls.
- Status never relies on color alone.
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
| Full route-level code splitting and Lighthouse remediation | `dashboard/src/App.tsx` | Existing bundle architecture predates this visual-only redesign; changing it would expand behavior scope. | Follow-up performance task after visual parity |
| Legacy page-specific inline styles during rollout | Dashboard pages | Existing theme is heavily inline-styled; each touched page must remove old theme literals, while untouched logic remains stable. | Exit when final token scan is clean |
