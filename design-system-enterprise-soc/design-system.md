# Ironwatch

Industrial-grade design system for AD-SIEM. Replaces the previous "Obsidian Sentinel" concept entirely.

## Overview

Ironwatch is built to look like instrumentation an analyst trusts, not a product a marketer sold them. The reference points are Splunk Enterprise Security, Microsoft Sentinel, IBM QRadar, Elastic Security, and CrowdStrike Falcon — tools that share a restrained palette, real information density, and zero decoration. Nothing in this system glows, floats, or has a bubbly corner radius. Every visual decision optimizes for one thing: an analyst scanning this screen for the 400th time today, at 3am, still finds the critical row in under a second.

## Color System

| Token | Hex | Swatch | Usage |
|---|---|---|---|
| `--color-primary` | `#2C6E8E` | ████ | The one confident blue — primary buttons, active nav, links, focus rings |
| `--color-accent` | `#C9822E` | ████ | Copper — reserved *only* for "a human needs to look at this now" (unread badge, live indicator). Never decorative. |
| `--color-background` | `#14181D` | ████ | Page background — gunmetal, not pure black |
| `--color-surface` | `#1B2028` | ████ | Card/panel/table background |
| `--color-surface-elevated` | `#232A34` | ████ | Modal/dropdown/popover |
| `--color-surface-sunken` | `#10141A` | ████ | Inset wells — inputs, log viewers, code blocks |
| `--color-border` | `#2E3540` | ████ | Default dividers and rules |
| `--color-text-primary` | `#E4E8ED` | ████ | Body text — soft white, never `#FFF` |
| `--color-text-secondary` | `#9AA4B2` | ████ | Labels, table headers, timestamps |
| `--color-success` | `#4F8F63` | ████ | Resolved, healthy, online |
| `--color-warning` | `#D8B23D` | ████ | Degraded, SLA at risk |
| `--color-error` | `#D8393F` | ████ | Errors, destructive actions |

**Severity ramp** (the most important color decision in the whole system):

| Severity | Hex | Shape |
|---|---|---|
| Critical | `#D8393F` | ■ filled square |
| High | `#D8752E` | ▲ filled triangle |
| Medium | `#D8B23D` | ◆ filled diamond |
| Low | `#4F8F63` | ● filled circle |
| Info | `#5C7C99` | ○ outlined circle |

**Do:** pair every severity color with its shape and a text label. Print this UI in grayscale and severity must still be readable.
**Don't:** use color as the only signal, and don't introduce a sixth "brand purple" — this system has exactly one accent color and it's rationed.

Every color pair meets WCAG AA (4.5:1 body text, 3:1 large text/UI) against its intended surface.

## Typography

- **Display** — Archivo (600/700/800): page titles, card-title labels, KPI numbers. Chosen for its slightly condensed, technical character — it looks like it belongs on a rack-mounted device, not a landing page.
- **Body** — Public Sans (400/500/600/700): everything else. This is literally the U.S. federal government's own typeface (USWDS), engineered for maximum legibility at small sizes across thousands of civil-servant screens — exactly the "battle-tested, not trendy" personality this system wants.
- **Mono** — JetBrains Mono: log lines, IPs, hashes, code, badge text.

| Token | Size | Usage |
|---|---|---|
| `2xs` | 11px | Badge text, table header caps |
| `xs` | 12px | Timestamps, fine print |
| `sm` | 13px | **Default table/body text — the workhorse size** |
| `base` | 15px | Primary reading text, inputs |
| `lg` | 17px | Card/panel titles |
| `xl` | 20px | Section headers |
| `2xl` | 26px | Page titles |
| `3xl` | 36px | KPI tile numbers |

Inter, Roboto, and system-ui are never used as the primary face — see AI Agent Instructions.

## Spacing & Layout

4px base unit. Use the scale (`--space-1` through `--space-16`) exclusively — no arbitrary pixel values. Cards get `--space-4` (16px) internal padding; dense tables use `--space-2`/`--space-3` cell padding to maximize rows-per-screen without touching. Align everything to an 8px rhythm at the layout level (nav width, header height, panel gaps).

## Component Patterns

- **Buttons**: `primary` (steel blue, the only call-to-action color), `secondary` (outlined gray), `ghost` (text-only, for table-row actions), `danger` (for destructive confirms only — isolate agent, delete rule).
- **Cards**: flat `--color-surface` panel, 1px border, `--radius-md` (4px — sharp, not bubbly), `--shadow-md`. No gradient fills, no backdrop-blur.
- **Inputs**: sunken background (`--color-surface-sunken`) so they read as a "well" the value sits in, not a floating box. Focus state is a 3px steel-blue ring, never a color change alone.
- **Severity badges**: shape + color + text, every time — see Color System above. This is the one non-negotiable rule in this entire document.
- **Tables**: sunken header background, hover-highlight rows in `--color-surface-elevated`, 1px row dividers. This is the primary UI of the whole product — give it the most design attention, not the least.

## AI Agent Instructions

Paste this block into a system prompt or CLAUDE.md when generating AD-SIEM UI code:

> Use the Ironwatch design system. Background `#14181D`, surfaces `#1B2028`/`#232A34`, sunken wells `#10141A`. One primary color (`#2C6E8E` steel blue) for actions/links/focus — do not introduce other accent hues. Copper (`#C9822E`) is reserved exclusively for "needs human attention now" indicators, never decoration. Severity is critical `#D8393F`/high `#D8752E`/medium `#D8B23D`/low `#4F8F63`/info `#5C7C99` — every severity badge MUST show its shape (square/triangle/diamond/circle/outlined-circle) and text label alongside the color, never color alone. Typography: Archivo for display/titles, Public Sans for everything else, JetBrains Mono for technical values — never Inter, Roboto, or system-ui as the primary face. Border-radius stays small (2–8px) — nothing bubbly. Shadows are flat and dark (`0 2px 8px rgba(0,0,0,.5)`) — no glow, no colored shadows, no backdrop-blur/glassmorphism. Tables are the primary UI surface and get the most design attention: sunken header, 1px row dividers, hover-highlight rows. Default body/table text size is 13px (`--text-sm`) — this is a data-dense instrument, not a marketing page.
