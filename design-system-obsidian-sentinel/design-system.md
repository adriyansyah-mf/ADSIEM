# Obsidian Sentinel

A design system for AD-SIEM — an enterprise Security Operations Center console.

## Overview

Obsidian Sentinel is built for analysts staring at this screen for eight-hour shifts, not for a marketing site. Every choice optimizes for **fast triage**: a dedicated five-step severity ramp that reads before you consciously parse the label, IBM Plex Mono for every technical value (IPs, hashes, hostnames, timestamps) so they're instantly distinguishable from prose, and a near-black graphite base with a cold radar-teal accent — serious, technical, unmistakably a command console rather than a dashboard template with the colors swapped.

## Color System

### Core

| Token | Swatch | Hex | Usage |
|---|---|---|---|
| `primary` | ████ | `#00D9C0` | Primary buttons, active nav, links, focus rings |
| `primary-hover` | ████ | `#00BFA8` | Hover/active state — darkens, never lightens |
| `secondary` | ████ | `#4A5A78` | Secondary buttons, inactive tabs |
| `accent` | ████ | `#FFB020` | Notification dots, highlighted metrics |
| `background` | ████ | `#0A0E14` | App shell background |
| `surface` | ████ | `#11161F` | Cards, panels, sidebar, table rows |
| `surface-elevated` | ████ | `#182030` | Modals, dropdowns, toasts |
| `border` | ████ | `#232B3A` | Default dividers and input borders |
| `border-strong` | ████ | `#334059` | Hover/focus borders, emphasized dividers |
| `text-primary` | ████ | `#E6EAF2` | Body copy, headings, data values |
| `text-secondary` | ████ | `#8A94A6` | Labels, captions, table headers |
| `text-muted` | ████ | `#5A6478` | Placeholders, timestamps, disabled text |
| `text-on-primary` | ████ | `#04140F` | Text sitting on primary-teal backgrounds |

### Semantic

| Token | Swatch | Hex | Usage |
|---|---|---|---|
| `success` | ████ | `#2ED47A` | Healthy/online/resolved |
| `warning` | ████ | `#FFB020` | Degraded, pending review |
| `error` | ████ | `#FF3B5C` | Failed actions, destructive confirmations |
| `info` | ████ | `#3D9EFF` | Neutral system notices |

### Severity ramp (the core of this domain)

| Token | Swatch | Hex | Usage |
|---|---|---|---|
| `severity.critical` | ████ | `#FF3B5C` | Top of the triage stack |
| `severity.high` | ████ | `#FF7A45` | |
| `severity.medium` | ████ | `#FFC53D` | |
| `severity.low` | ████ | `#3D9EFF` | |
| `severity.informational` | ████ | `#6B7A99` | Deliberately desaturated — recedes under real findings |

**Do:** use the severity ramp *only* for alert/finding severity. Reuse `error`/`success`/`warning` for everything else (form validation, connection status, toasts) so severity always means one specific thing on screen.

**Don't:** invent a sixth severity color, and don't reuse `error` red for a non-severity destructive action without also using the `.btn-destructive` pattern — the two need to stay visually distinct from a critical-severity badge at a glance.

**Accessibility:** every text/background pairing above meets WCAG AA (4.5:1 for body text, 3:1 for large text and badges) against both `background` and `surface`. Badges use a ~12% opacity tint of the semantic color as background with the full-strength color as text, which is what keeps contrast high while still color-coding the row.

## Typography

**Pairing:** IBM Plex Sans (UI, headings, prose) + IBM Plex Mono (anything technical: IPs, hashes, hostnames, timestamps, rule IDs, raw log/event payloads, code). Same type family, designed together — headers and the data underneath them share one voice instead of clashing.

```html
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
```

| Token | Size / Line | Usage |
|---|---|---|
| `xs` | 11px / 14px | Badge text, table micro-labels |
| `sm` | 13px / 18px | Table cells, form labels — **the default density for this console** |
| `base` | 15px / 24px | Body copy, modal text |
| `lg` | 17px / 26px | Card titles, panel headers |
| `xl` | 20px / 28px | Section headers |
| `2xl` | 24px / 32px | Page titles |
| `3xl` | 32px / 36px | KPI numbers, dashboard headline metrics |
| `4xl` | 44px / 48px | Reserved for landing/marketing surfaces only — never inside the app shell |

**Weight rules:** 400 for body copy, 500 for emphasis/labels, 600 for headings and badge text, 700 reserved for KPI numbers only. Never use 700 for body text — it reads as shouting in a data-dense UI.

**The `sm` (13px) scale is the workhorse.** Tables, forms, and the majority of on-screen text in a SOC console run at this size — it's what lets the platform show more signal per screen without feeling cramped. `base` (15px) is for the minority of surfaces meant to be read like prose (case notes, modals, settings descriptions).

## Spacing & Layout

Base unit: **4px**. Scale: 0, 4, 8, 12, 16, 20, 24, 32, 40, 48, 64, 80px.

- Cards use `space-5` (20px) internal padding — enough breathing room without wasting vertical space in a console meant to show many cards per screen.
- Table cells use `space-3 space-4` (12px/16px) — tighter than card padding, because tables need row density more than they need whitespace.
- Sidebar nav items use `space-2 space-3` and stack with no gap beyond their own padding — a dense, scannable list, not a spaced-out menu.
- Section-level gaps (between page header and content, between stacked cards) use `space-6` (24px). Never go below `space-4` (16px) between distinct sections — that's the line between "dense" and "cluttered."

## Component Patterns

**Buttons** — four variants: `primary` (teal fill, dark text — the one clear call-to-action per view), `secondary` (elevated-surface fill with a visible border, for the second-priority action next to a primary), `ghost` (no fill until hover, for tertiary/inline actions like table row actions), `destructive` (solid error-red, reserved for irreversible actions — never use it for merely "important," only for "this deletes/blocks/isolates something").

**Cards** — `surface` background, `border` outline, small shadow. Reserve `card-elevated` (brighter surface, bigger shadow) for anything that floats above the page: modals, command palettes, dropdown panels.

**Inputs** — dark (`background`, not `surface`) so they visually recess below the surface they sit on. Search/filter fields that accept IPs, hashes, or query syntax should use `.input-mono`; free-text fields (case titles, notes) use the default body font.

**Badges** — always uppercase, always monospace, always the tint-background/solid-text/tint-border pattern. This is the single most load-bearing component in the system: an analyst scanning a table of 50 alerts needs every severity badge to be recognizable in peripheral vision before they've read a single word.

**Status dots** — 8px circle, optional soft glow (`box-shadow`) in the status color for online/degraded states so live agent/service status is readable even in a dense grid of them.

**Tables** — header row uses `surface` background with a `border-strong` bottom rule (visually heavier than the row dividers below it, so the header reads as structurally separate). Row hover uses `surface` background — a state, not a permanent tint. Any IP/hash/hostname/timestamp cell gets `.cell-mono`.

**Sidebar** — active item gets a 2px left-edge accent bar in `primary` plus a 12%-opacity teal background tint, not a full-color fill (a fully-filled active nav item competes visually with severity badges, which should be the loudest color signal on screen).

## AI Agent Instructions

Paste this section into a system prompt or `CLAUDE.md` when generating UI for this platform:

- Use `design-tokens.json` and `design-system.css` as the source of truth. Never invent a new color — if nothing fits, use the closest existing token rather than adding one.
- Body/UI font is **IBM Plex Sans**. Technical values (IP, hash, hostname, timestamp, rule ID, raw payload, code) are always **IBM Plex Mono**. Never use Plex Mono for prose; never use Plex Sans for a raw log line.
- The severity ramp (`critical` / `high` / `medium` / `low` / `informational`) is reserved exclusively for alert/finding severity. Use `success`/`warning`/`error`/`info` for everything else.
- Default text size for tables and forms is `sm` (13px), not `base`. This console is data-dense by design — don't inflate type size "for readability" at the cost of density.
- Border radius stays small: `sm`/`md` (4-6px) for almost everything, `lg` (8px) for cards/modals only. Never use a large/pill radius on a button or input — this is an enterprise console, not a consumer app.
- One `btn-primary` per view maximum. Secondary actions are `btn-secondary` or `btn-ghost`.
- Badges are always uppercase monospace with the tint/solid-text/tint-border pattern — never a solid-fill badge, it fights with row hover states and reduces the badge's own legibility.
- Background is near-black graphite (`#0A0E14`), not pure black and not neutral gray — don't substitute a generic `#000` or `#1a1a1a`.
