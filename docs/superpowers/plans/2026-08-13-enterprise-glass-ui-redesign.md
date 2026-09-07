# Enterprise Glassmorphism UI Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the dashboard's two conflicting visual themes (cyberpunk-neon `index.css` tokens vs. flat slate `Layout.tsx` chrome) with one enterprise-glassmorphism design system, applied consistently across all 26 pages and shared components.

**Architecture:** Token-first rollout. Redefine the CSS custom properties and Tailwind compat mapping once (Task 1), fix the pre-existing `--border` naming collision that currently breaks ~93 border declarations app-wide (Task 1), rebuild global chrome (Task 2-4), add three new shared primitives — `GlassCard`, `PageHeader`, `StatCard` (Task 5-7) — update the shared table/badge/modal/toast components to consume the new tokens (Task 8-11), then mechanically roll the primitives out page-by-page (Task 12-37). This is a **styling-only** change: no data-fetching, routing, or business-logic edits anywhere in this plan.

**Tech Stack:** React 18 + TypeScript, Tailwind CSS (HSL custom-property theme), Vite. No component/visual test framework exists in this repo — verification is `tsc`/`vite build` (catches broken JSX/props) plus manual browser QA in the running dev server, per the spec's own "Testing / verification" section and project convention for frontend changes.

**Spec:** `docs/superpowers/specs/2026-08-12-enterprise-glass-ui-design.md` (read this first — it has the full rationale, token table, and rejected alternatives).

---

## Important pre-existing bug this plan fixes

`dashboard/src/index.css` currently defines `--border` **twice** with incompatible formats: `:root` sets it to a hex color (`#1a2d45`, for raw `var(--border)` CSS usage — ~93 call sites across the pages), but `.dark` (permanently applied via `<html class="dark">`, no toggle exists) overrides it to a bare HSL triplet (`213 50% 18%`, for Tailwind's `hsl(var(--border))` utility mapping used by `border-border`/`border-border/40` etc. — ~28 call sites). Since `.dark` always wins, every raw `var(--border)` usage today receives an invalid CSS color value and silently falls back to `currentcolor`. Task 1 fixes this by giving the two formats separate variable names (`--border` = hex, `--border-tw` = HSL triplet for Tailwind) instead of reusing one name for both.

---

## Task 1: Design tokens — `index.css` + `tailwind.config.ts`

**Files:**
- Modify: `dashboard/src/index.css`
- Modify: `dashboard/tailwind.config.ts`
- Modify: `dashboard/index.html:9` (Google Fonts `<link>`)

- [ ] **Step 1: Replace the font import and root token block**

In `dashboard/src/index.css`, replace lines 1–53 (the `@import` line through the end of the `.dark { ... }` block) with:

```css
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

@tailwind base;
@tailwind components;
@tailwind utilities;

:root {
  --bg-base: #07111d;
  --bg-panel: #0d1a2a;
  --bg-card: #101f31;
  --border: #1d3045;

  --accent-blue: #3193ff;
  --accent-red: #ff4d4d;
  --accent-orange: #ff941f;
  --accent-yellow: #f3c43e;
  --accent-green: #64c466;
  --accent-purple: #a765f5;

  --text-primary: #e8f0fa;
  --text-secondary: #80a0be;
  --text-muted: #5c7086;

  --glass-bg: rgba(13, 26, 42, 0.45);
  --glass-border: rgba(148, 197, 255, 0.10);
  --glass-blur: blur(18px) saturate(150%);
  --glass-blur-chrome: blur(18px) saturate(140%);

  --radius: 0.5rem;

  /* Tailwind compat — hsl(var(--x)) mapped in tailwind.config.ts.
     Keep in sync with the hex tokens above (HSL equivalents). */
  --background: 213 61% 7%;
  --foreground: 213 64% 95%;
  --card: 213 51% 13%;
  --card-foreground: 213 64% 95%;
  --border-tw: 212 41% 19%;
  --primary: 212 100% 60%;
  --primary-foreground: 213 61% 7%;
  --muted: 213 53% 11%;
  --muted-foreground: 209 32% 62%;
  --destructive: 0 100% 65%;
  --destructive-foreground: 213 64% 95%;
}
```

Note this drops the separate `.dark { ... }` block entirely — since the app is dark-only with no theme toggle (`<html class="dark">` is static in `index.html`), duplicating every token under a `.dark` selector added no value and was the source of the `--border` collision. Tailwind's `darkMode: ['class']` config still works unchanged: it only cares whether `<html>` has the `dark` class (it does, statically), not whether `index.css` has a `.dark {}` rule.

- [ ] **Step 2: Replace the page-title uppercase rule and background grid**

Replace this block (originally lines 69–101, the `main h1` comment/rule through the `body::before` grid):

```css
/* Page-title consistency: several pages (Alerts, Hunts, YARA, FIM, Live
   Response, Reports, Decoders, Webhooks, Users, Logs, Audit Log, Log
   Sources, Handover, MITRE Heatmap) render a bare `<h1 className="text-xl
   font-bold">` with no font override, while Cases/Dashboard/Settings/etc.
   set Rajdhani + uppercase + letter-spacing inline. Tailwind's utility
   classes never set font-family/text-transform/letter-spacing, so this
   rule fills that gap for every plain h1 without touching each page —
   and has zero effect on headings that already set their own inline
   font-family (inline styles win over this stylesheet rule). */
main h1 {
  font-family: 'Rajdhani', sans-serif;
  font-weight: 700;
  letter-spacing: 0.02em;
  text-transform: uppercase;
}

/* Tabular numerals for counters, timers, and table cells with changing
   numbers — keeps digit widths stable instead of jittering. */
main :is(td, .tabular-nums) {
  font-variant-numeric: tabular-nums;
}

/* Grid line background */
body::before {
  content: '';
  position: fixed;
  inset: 0;
  pointer-events: none;
  z-index: 0;
  background-image:
    repeating-linear-gradient(0deg, transparent, transparent 39px, rgba(0,212,255,0.04) 39px, rgba(0,212,255,0.04) 40px),
    repeating-linear-gradient(90deg, transparent, transparent 39px, rgba(0,212,255,0.04) 39px, rgba(0,212,255,0.04) 40px);
}
```

with:

```css
/* Tabular numerals for counters, timers, and table cells with changing
   numbers — keeps digit widths stable instead of jittering. */
main :is(td, .tabular-nums) {
  font-variant-numeric: tabular-nums;
}

/* Soft gradient mesh — this is what makes the glass panels' backdrop-blur
   visible; a flat single-color background makes blur() invisible. */
body::before {
  content: '';
  position: fixed;
  inset: 0;
  pointer-events: none;
  z-index: 0;
  background:
    radial-gradient(ellipse 900px 600px at 8% -10%, rgba(49, 147, 255, 0.14), transparent 60%),
    radial-gradient(ellipse 800px 500px at 92% -8%, rgba(167, 101, 245, 0.10), transparent 60%),
    radial-gradient(ellipse 1100px 700px at 50% 115%, rgba(49, 147, 255, 0.08), transparent 60%);
}
```

- [ ] **Step 3: Update `html, body` font-family and scrollbar/glow colors**

Replace:

```css
html, body {
  margin: 0;
  padding: 0;
  background-color: var(--bg-base);
  color: var(--text-primary);
  font-family: 'Exo 2', system-ui, sans-serif;
  font-size: 15px;
  line-height: 1.5;
}
```

with:

```css
html, body {
  margin: 0;
  padding: 0;
  background-color: var(--bg-base);
  color: var(--text-primary);
  font-family: 'Inter', system-ui, sans-serif;
  font-size: 15px;
  line-height: 1.5;
}
```

Replace the scrollbar-thumb hover and glow utilities:

```css
::-webkit-scrollbar-thumb:hover {
  background: var(--accent-cyan);
}
```
→
```css
::-webkit-scrollbar-thumb:hover {
  background: var(--accent-blue);
}
```

```css
/* Glow utilities */
.glow-cyan {
  box-shadow: 0 0 12px rgba(0, 212, 255, 0.4);
}
.glow-red {
  box-shadow: 0 0 12px rgba(255, 34, 68, 0.4);
}
.glow-green {
  box-shadow: 0 0 12px rgba(0, 255, 136, 0.4);
}
.glow-orange {
  box-shadow: 0 0 12px rgba(255, 107, 0, 0.4);
}
```
→
```css
/* Glow utilities — used as an occasional accent (active nav item, live
   indicator), not a default card treatment. */
.glow-cyan {
  box-shadow: 0 0 10px rgba(49, 147, 255, 0.35);
}
.glow-red {
  box-shadow: 0 0 10px rgba(255, 77, 77, 0.35);
}
.glow-green {
  box-shadow: 0 0 10px rgba(100, 196, 102, 0.35);
}
.glow-orange {
  box-shadow: 0 0 10px rgba(255, 148, 31, 0.35);
}
```

- [ ] **Step 4: Update the `@layer base` border-color override**

Replace:

```css
@layer base {
  * { border-color: #1a2d45; }
  body { background-color: var(--bg-base); color: var(--text-primary); }
}
```

with:

```css
@layer base {
  * { border-color: #1d3045; }
  body { background-color: var(--bg-base); color: var(--text-primary); }
}
```

- [ ] **Step 5: Point Tailwind's `border` color at the new `--border-tw` variable**

In `dashboard/tailwind.config.ts`, change:

```ts
        border: 'hsl(var(--border))',
```
to:
```ts
        border: 'hsl(var(--border-tw))',
```

This is the fix for the naming collision described above — Tailwind's `border-border` / `border-border/40` utilities now read the HSL triplet from `--border-tw`, while every raw `var(--border)` in hand-written styles reads the hex value from `--border`, and the two are kept visually identical by construction (`--border: #1d3045` / `--border-tw: 212 41% 19%` are the same color in different formats).

- [ ] **Step 6: Swap the Google Fonts `<link>` in `index.html`**

In `dashboard/index.html`, replace:

```html
    <link href="https://fonts.googleapis.com/css2?family=Exo+2:wght@300;400;500;600;700&family=Rajdhani:wght@400;500;600;700&family=Share+Tech+Mono&display=swap" rel="stylesheet" />
```

with:

```html
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet" />
```

- [ ] **Step 7: Verify the build compiles**

Run: `cd dashboard && npm run build`
Expected: build succeeds with no TypeScript or Vite errors (this step only touches CSS/HTML, so a failure here means a typo in the CSS, not a real regression — double-check brace matching).

- [ ] **Step 8: Verify no remaining references to removed tokens**

Run: `cd dashboard && grep -rn "accent-cyan\|Rajdhani\|Share Tech Mono\|Exo 2" src/index.css`
Expected: no output (all removed from the token file itself; per-page usages of these are cleaned up in later tasks — this step only confirms `index.css` itself is clean).

- [ ] **Step 9: Commit**

```bash
git add dashboard/src/index.css dashboard/tailwind.config.ts dashboard/index.html
git commit -m "feat(dashboard): replace cyberpunk tokens with enterprise-glass palette

Fixes a pre-existing --border naming collision (hex custom token vs.
Tailwind's hsl(var(--border)) mapping) that silently broke ~93 border
declarations app-wide."
```

---

## Task 2: Global chrome — `Layout.tsx` sidebar

**Files:**
- Modify: `dashboard/src/components/Layout.tsx`

- [ ] **Step 1: Restyle the root container and `<aside>` sidebar shell**

Replace:

```tsx
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden', background: '#0d0f14' }}>

      {/* ── Sidebar ── */}
      <aside style={{
        width: sidebarW,
        minWidth: sidebarW,
        display: 'flex',
        flexDirection: 'column',
        background: '#111318',
        borderRight: '1px solid #1e2028',
        transition: 'width 0.2s ease, min-width 0.2s ease',
        overflow: 'hidden',
      }}>
```

with:

```tsx
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden', background: 'transparent' }}>

      {/* ── Sidebar ── */}
      <aside style={{
        width: sidebarW,
        minWidth: sidebarW,
        display: 'flex',
        flexDirection: 'column',
        background: 'var(--glass-bg)',
        backdropFilter: 'var(--glass-blur-chrome)',
        WebkitBackdropFilter: 'var(--glass-blur-chrome)',
        borderRight: '1px solid var(--glass-border)',
        transition: 'width 0.2s ease, min-width 0.2s ease',
        overflow: 'hidden',
      }}>
```

- [ ] **Step 2: Restyle the logo block**

Replace:

```tsx
        <div style={{
          height: 52,
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          padding: '0 16px',
          borderBottom: '1px solid #1e2028',
          flexShrink: 0,
        }}>
          <img
            src="/favicon.jpeg"
            alt="AD-SIEM"
            style={{
              width: 28, height: 28, borderRadius: 6,
              objectFit: 'cover', flexShrink: 0,
            }}
          />
          {!collapsed && (
            <div>
              <div style={{ fontSize: 13, fontWeight: 700, color: '#f1f5f9', letterSpacing: '0.02em', lineHeight: 1.1 }}>
                AD-SIEM
              </div>
              <div style={{ fontSize: 10, color: '#64748b', letterSpacing: '0.04em' }}>
                Security Operations
              </div>
            </div>
          )}
        </div>
```

with:

```tsx
        <div style={{
          height: 52,
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          padding: '0 16px',
          borderBottom: '1px solid var(--glass-border)',
          flexShrink: 0,
        }}>
          <img
            src="/favicon.jpeg"
            alt="AD-SIEM"
            style={{
              width: 28, height: 28, borderRadius: 6,
              objectFit: 'cover', flexShrink: 0,
            }}
          />
          {!collapsed && (
            <div>
              <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '0.02em', lineHeight: 1.1 }}>
                AD-SIEM
              </div>
              <div style={{ fontSize: 10, color: 'var(--text-secondary)', letterSpacing: '0.04em' }}>
                Security Operations
              </div>
            </div>
          )}
        </div>
```

- [ ] **Step 3: Restyle nav group labels (both occurrences)**

This exact block appears twice — once for `NAV_GROUPS` (~line 187), once for the `Administration` group (~line 243). Use `replace_all` for this edit since both are byte-identical:

Replace (all occurrences):

```tsx
                  fontSize: 10,
                  fontWeight: 600,
                  letterSpacing: '0.08em',
                  color: '#64748b',
                  textTransform: 'uppercase',
```

with:

```tsx
                  fontSize: 10,
                  fontWeight: 600,
                  letterSpacing: '0.08em',
                  color: 'var(--text-secondary)',
                  textTransform: 'uppercase',
```

Also replace both group-divider lines (collapsed state), `replace_all`:

Replace:
```tsx
              {collapsed && gi > 0 && <div style={{ height: 1, background: '#1e2028', margin: '6px 10px' }} />}
```
with:
```tsx
              {collapsed && gi > 0 && <div style={{ height: 1, background: 'var(--glass-border)', margin: '6px 10px' }} />}
```

and:
```tsx
              {collapsed && <div style={{ height: 1, background: '#1e2028', margin: '6px 10px' }} />}
```
with:
```tsx
              {collapsed && <div style={{ height: 1, background: 'var(--glass-border)', margin: '6px 10px' }} />}
```

- [ ] **Step 4: Restyle nav `<Link>` items (both occurrences)**

The `<Link>` style object below appears twice (regular nav items ~line 207, admin items ~line 263) with byte-identical content. Use `replace_all`:

Replace (all occurrences):

```tsx
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 10,
                      padding: collapsed ? '8px 0' : '7px 16px',
                      justifyContent: collapsed ? 'center' : 'flex-start',
                      textDecoration: 'none',
                      background: active ? 'rgba(59,130,246,0.1)' : 'transparent',
                      borderLeft: active ? '2px solid #3b82f6' : '2px solid transparent',
                      color: active ? '#93c5fd' : '#64748b',
                      transition: 'color 0.12s, background 0.12s',
                    }}
```

with:

```tsx
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 10,
                      padding: collapsed ? '8px 0' : '7px 16px',
                      justifyContent: collapsed ? 'center' : 'flex-start',
                      textDecoration: 'none',
                      background: active ? 'color-mix(in srgb, var(--accent-blue) 12%, transparent)' : 'transparent',
                      borderLeft: active ? '2px solid var(--accent-blue)' : '2px solid transparent',
                      color: active ? 'var(--accent-blue)' : 'var(--text-secondary)',
                      boxShadow: active ? '0 0 10px rgba(49,147,255,0.35)' : 'none',
                      transition: 'color 0.12s, background 0.12s, box-shadow 0.12s',
                    }}
```

And the nested label `<span>` (also appears twice, identical), `replace_all`:

Replace:
```tsx
                      <span style={{
                        fontSize: 13,
                        fontWeight: active ? 500 : 400,
                        color: active ? '#e2e8f0' : '#94a3b8',
                        whiteSpace: 'nowrap',
                        letterSpacing: '0.01em',
                      }}>
```
with:
```tsx
                      <span style={{
                        fontSize: 13,
                        fontWeight: active ? 500 : 400,
                        color: active ? 'var(--text-primary)' : 'var(--text-secondary)',
                        whiteSpace: 'nowrap',
                        letterSpacing: '0.01em',
                      }}>
```

- [ ] **Step 5: Restyle the bottom agent-count / collapse strip**

Replace:

```tsx
        <div style={{ borderTop: '1px solid #1e2028', flexShrink: 0 }}>
          {!collapsed ? (
            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '10px 16px',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                <span style={{
                  width: 7, height: 7, borderRadius: '50%',
                  background: onlineCount > 0 ? '#34d399' : '#374151',
                  boxShadow: onlineCount > 0 ? '0 0 5px #34d399' : 'none',
                  flexShrink: 0,
                }} />
                <span style={{ fontSize: 12, color: '#64748b' }}>
                  <span style={{ color: onlineCount > 0 ? '#34d399' : '#64748b', fontWeight: 500 }}>{onlineCount}</span>
                  <span> / {totalCount} agents</span>
                </span>
              </div>
              <button
                onClick={() => setCollapsed(true)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#64748b', display: 'flex', padding: '8px', borderRadius: 4 }}
                title="Collapse sidebar"
              >
                <PanelLeftClose size={14} />
              </button>
            </div>
          ) : (
            <button
              onClick={() => setCollapsed(false)}
              title="Expand sidebar"
              style={{
                width: '100%', background: 'none', border: 'none',
                cursor: 'pointer', color: '#64748b',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                padding: '14px 0',
              }}
            >
              <PanelLeftOpen size={14} />
            </button>
          )}
        </div>
```

with:

```tsx
        <div style={{ borderTop: '1px solid var(--glass-border)', flexShrink: 0 }}>
          {!collapsed ? (
            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '10px 16px',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                <span style={{
                  width: 7, height: 7, borderRadius: '50%',
                  background: onlineCount > 0 ? '#34d399' : 'var(--text-muted)',
                  boxShadow: onlineCount > 0 ? '0 0 5px #34d399' : 'none',
                  flexShrink: 0,
                }} />
                <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                  <span style={{ color: onlineCount > 0 ? '#34d399' : 'var(--text-secondary)', fontWeight: 500 }}>{onlineCount}</span>
                  <span> / {totalCount} agents</span>
                </span>
              </div>
              <button
                onClick={() => setCollapsed(true)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-secondary)', display: 'flex', padding: '8px', borderRadius: 4 }}
                title="Collapse sidebar"
              >
                <PanelLeftClose size={14} />
              </button>
            </div>
          ) : (
            <button
              onClick={() => setCollapsed(false)}
              title="Expand sidebar"
              style={{
                width: '100%', background: 'none', border: 'none',
                cursor: 'pointer', color: 'var(--text-secondary)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                padding: '14px 0',
              }}
            >
              <PanelLeftOpen size={14} />
            </button>
          )}
        </div>
```

(The green online-status dot is intentionally left as `#34d399` — it's a general system-status green, not one of the severity/accent tokens, and the spec explicitly says the online-dot logic is "restyled onto glass," not recolored.)

- [ ] **Step 6: Run the dev server and visually check the sidebar**

Run: `cd dashboard && npm run dev`
Open the app in a browser, check: sidebar shows a frosted/blurred panel over the gradient-mesh background (not flat `#111318`), active nav item has a blue left border + subtle glow, collapsed/expanded toggle still works, group dividers are visible.

- [ ] **Step 7: Commit**

```bash
git add dashboard/src/components/Layout.tsx
git commit -m "feat(dashboard): restyle sidebar chrome to enterprise-glass"
```

---

## Task 3: Global chrome — `Layout.tsx` topbar

**Files:**
- Modify: `dashboard/src/components/Layout.tsx`

- [ ] **Step 1: Restyle the topbar `<header>` shell and title**

Replace:

```tsx
        <header style={{
          height: 52,
          flexShrink: 0,
          display: 'flex',
          alignItems: 'center',
          gap: 16,
          padding: '0 20px',
          background: '#111318',
          borderBottom: '1px solid #1e2028',
        }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
            <span style={{ fontSize: 15, fontWeight: 600, color: '#e2e8f0', letterSpacing: '0.01em' }}>
              {currentLabel}
            </span>
```

with:

```tsx
        <header style={{
          height: 52,
          flexShrink: 0,
          display: 'flex',
          alignItems: 'center',
          gap: 16,
          padding: '0 20px',
          background: 'var(--glass-bg)',
          backdropFilter: 'var(--glass-blur-chrome)',
          WebkitBackdropFilter: 'var(--glass-blur-chrome)',
          borderBottom: '1px solid var(--glass-border)',
        }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
            <span style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-primary)', letterSpacing: '0.01em' }}>
              {currentLabel}
            </span>
```

- [ ] **Step 2: Restyle the global search box + results dropdown**

Replace:

```tsx
          <div style={{ flex: 1, maxWidth: 320, position: 'relative', margin: '0 16px' }}>
            <div style={{
              display: 'flex', alignItems: 'center', gap: 6,
              background: '#0d0f14', border: '1px solid #1e2028',
              borderRadius: 6, padding: '4px 10px',
            }}>
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#475569" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
              </svg>
              <input
                value={searchQuery}
                onChange={e => { setSearchQuery(e.target.value); setSearchOpen(true); handleSearch(e.target.value) }}
                onFocus={() => setSearchOpen(true)}
                onBlur={() => setTimeout(() => setSearchOpen(false), 200)}
                placeholder="Search alerts, cases, IPs…"
                style={{
                  background: 'none', border: 'none', outline: 'none',
                  color: '#94a3b8', fontSize: 12, width: '100%',
                }}
              />
            </div>
            {searchOpen && searchResults && (searchResults.alerts.length > 0 || searchResults.cases.length > 0) && (
              <div style={{
                position: 'absolute', top: '100%', left: 0, right: 0, marginTop: 4,
                background: '#111318', border: '1px solid #1e2028', borderRadius: 6,
                zIndex: 1000, overflow: 'hidden', boxShadow: '0 4px 20px rgba(0,0,0,0.5)',
              }}>
                {searchResults.alerts.map((a: any) => (
                  <div
                    key={a.id}
                    onMouseDown={() => { navigate(`/alerts?open=${a.id}`); setSearchOpen(false); setSearchQuery('') }}
                    style={{ padding: '8px 14px', cursor: 'pointer', borderBottom: '1px solid #1e2028', display: 'flex', gap: 8, alignItems: 'center' }}
                    onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = '#1e2028' }}
                    onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'transparent' }}
                  >
                    <span style={{ fontSize: 10, padding: '1px 5px', borderRadius: 3, background: 'rgba(255,34,68,0.15)', color: '#ff2244', fontFamily: 'Share Tech Mono, monospace', textTransform: 'uppercase', whiteSpace: 'nowrap' }}>
                      {a.severity}
                    </span>
                    <span style={{ fontSize: 12, color: '#e2e8f0', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {a.title}
                    </span>
                    <span style={{ fontSize: 10, color: '#475569', whiteSpace: 'nowrap' }}>alert</span>
                  </div>
                ))}
                {searchResults.cases.map((c: any) => (
                  <div
                    key={c.id}
                    onMouseDown={() => { navigate(`/cases/${c.id}`); setSearchOpen(false); setSearchQuery('') }}
                    style={{ padding: '8px 14px', cursor: 'pointer', borderBottom: '1px solid #1e2028', display: 'flex', gap: 8, alignItems: 'center' }}
                    onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = '#1e2028' }}
                    onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'transparent' }}
                  >
                    <span style={{ fontSize: 10, padding: '1px 5px', borderRadius: 3, background: 'rgba(0,212,255,0.1)', color: '#00d4ff', fontFamily: 'Share Tech Mono, monospace', textTransform: 'uppercase', whiteSpace: 'nowrap' }}>
                      {c.status}
                    </span>
                    <span style={{ fontSize: 12, color: '#e2e8f0', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {c.title}
                    </span>
                    <span style={{ fontSize: 10, color: '#475569', whiteSpace: 'nowrap' }}>case</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div style={{ width: 1, height: 24, background: '#1e2028' }} />
```

with:

```tsx
          <div style={{ flex: 1, maxWidth: 320, position: 'relative', margin: '0 16px' }}>
            <div style={{
              display: 'flex', alignItems: 'center', gap: 6,
              background: 'var(--bg-base)', border: '1px solid var(--glass-border)',
              borderRadius: 6, padding: '4px 10px',
            }}>
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
              </svg>
              <input
                value={searchQuery}
                onChange={e => { setSearchQuery(e.target.value); setSearchOpen(true); handleSearch(e.target.value) }}
                onFocus={() => setSearchOpen(true)}
                onBlur={() => setTimeout(() => setSearchOpen(false), 200)}
                placeholder="Search alerts, cases, IPs…"
                style={{
                  background: 'none', border: 'none', outline: 'none',
                  color: 'var(--text-secondary)', fontSize: 12, width: '100%',
                }}
              />
            </div>
            {searchOpen && searchResults && (searchResults.alerts.length > 0 || searchResults.cases.length > 0) && (
              <div style={{
                position: 'absolute', top: '100%', left: 0, right: 0, marginTop: 4,
                background: 'var(--glass-bg)', backdropFilter: 'var(--glass-blur)', WebkitBackdropFilter: 'var(--glass-blur)',
                border: '1px solid var(--glass-border)', borderRadius: 6,
                zIndex: 1000, overflow: 'hidden', boxShadow: '0 4px 20px rgba(0,0,0,0.5)',
              }}>
                {searchResults.alerts.map((a: any) => (
                  <div
                    key={a.id}
                    onMouseDown={() => { navigate(`/alerts?open=${a.id}`); setSearchOpen(false); setSearchQuery('') }}
                    style={{ padding: '8px 14px', cursor: 'pointer', borderBottom: '1px solid var(--glass-border)', display: 'flex', gap: 8, alignItems: 'center' }}
                    onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'rgba(148,197,255,0.08)' }}
                    onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'transparent' }}
                  >
                    <span style={{ fontSize: 10, padding: '1px 5px', borderRadius: 3, background: 'rgba(255,77,77,0.15)', color: 'var(--accent-red)', fontWeight: 600, textTransform: 'uppercase', whiteSpace: 'nowrap' }}>
                      {a.severity}
                    </span>
                    <span style={{ fontSize: 12, color: 'var(--text-primary)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {a.title}
                    </span>
                    <span style={{ fontSize: 10, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>alert</span>
                  </div>
                ))}
                {searchResults.cases.map((c: any) => (
                  <div
                    key={c.id}
                    onMouseDown={() => { navigate(`/cases/${c.id}`); setSearchOpen(false); setSearchQuery('') }}
                    style={{ padding: '8px 14px', cursor: 'pointer', borderBottom: '1px solid var(--glass-border)', display: 'flex', gap: 8, alignItems: 'center' }}
                    onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'rgba(148,197,255,0.08)' }}
                    onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'transparent' }}
                  >
                    <span style={{ fontSize: 10, padding: '1px 5px', borderRadius: 3, background: 'rgba(49,147,255,0.12)', color: 'var(--accent-blue)', fontWeight: 600, textTransform: 'uppercase', whiteSpace: 'nowrap' }}>
                      {c.status}
                    </span>
                    <span style={{ fontSize: 12, color: 'var(--text-primary)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {c.title}
                    </span>
                    <span style={{ fontSize: 10, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>case</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div style={{ width: 1, height: 24, background: 'var(--glass-border)' }} />
```

- [ ] **Step 3: Restyle the user block, admin dropdown, and sign-out button**

Replace:

```tsx
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: 13, fontWeight: 500, color: '#cbd5e1', lineHeight: 1.2 }}>
                {user?.username ?? '—'}
              </div>
              <div style={{ fontSize: 11, color: '#475569', lineHeight: 1.2, fontVariantNumeric: 'tabular-nums' }}>
                {clock.toLocaleTimeString('en-US', { hour12: false })}
              </div>
            </div>
            {ADMIN_ITEMS.filter(i => hasRole(i.minRole ?? 'viewer')).length > 0 && (
              <div style={{ position: 'relative' }}>
                <button
                  onClick={() => setAdminMenuOpen(o => !o)}
                  onBlur={() => setTimeout(() => setAdminMenuOpen(false), 150)}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 4,
                    padding: '5px 12px',
                    borderRadius: 5,
                    border: '1px solid #1e2028',
                    background: adminMenuOpen ? '#1e2028' : 'transparent',
                    color: '#94a3b8',
                    fontSize: 12,
                    fontWeight: 500,
                    cursor: 'pointer',
                  }}
                >
                  Admin <ChevronDown size={13} />
                </button>
                {adminMenuOpen && (
                  <div style={{
                    position: 'absolute', top: '100%', right: 0, marginTop: 4,
                    background: '#111318', border: '1px solid #1e2028', borderRadius: 6,
                    zIndex: 1000, overflow: 'hidden', minWidth: 160,
                    boxShadow: '0 4px 20px rgba(0,0,0,0.5)',
                  }}>
                    {ADMIN_ITEMS.filter(i => hasRole(i.minRole ?? 'viewer')).map(item => {
                      const Icon = item.icon
                      const active = isActive(item.to)
                      return (
                        <Link
                          key={item.to}
                          to={item.to}
                          style={{
                            display: 'flex', alignItems: 'center', gap: 8,
                            padding: '8px 14px',
                            textDecoration: 'none',
                            background: active ? 'rgba(59,130,246,0.1)' : 'transparent',
                            color: active ? '#93c5fd' : '#cbd5e1',
                            fontSize: 12.5,
                          }}
                        >
                          <Icon size={14} strokeWidth={active ? 2 : 1.75} />
                          {item.label}
                        </Link>
                      )
                    })}
                  </div>
                )}
              </div>
            )}
            <button
              onClick={logout}
              className="sign-out-btn"
              style={{
                padding: '5px 12px',
                borderRadius: 5,
                border: '1px solid #1e2028',
                background: 'transparent',
                color: '#64748b',
                fontSize: 12,
                fontWeight: 500,
                cursor: 'pointer',
              }}
            >
              Sign out
            </button>
          </div>
```

with:

```tsx
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-primary)', lineHeight: 1.2 }}>
                {user?.username ?? '—'}
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.2, fontVariantNumeric: 'tabular-nums' }}>
                {clock.toLocaleTimeString('en-US', { hour12: false })}
              </div>
            </div>
            {ADMIN_ITEMS.filter(i => hasRole(i.minRole ?? 'viewer')).length > 0 && (
              <div style={{ position: 'relative' }}>
                <button
                  onClick={() => setAdminMenuOpen(o => !o)}
                  onBlur={() => setTimeout(() => setAdminMenuOpen(false), 150)}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 4,
                    padding: '5px 12px',
                    borderRadius: 5,
                    border: '1px solid var(--glass-border)',
                    background: adminMenuOpen ? 'rgba(148,197,255,0.08)' : 'transparent',
                    color: 'var(--text-secondary)',
                    fontSize: 12,
                    fontWeight: 500,
                    cursor: 'pointer',
                  }}
                >
                  Admin <ChevronDown size={13} />
                </button>
                {adminMenuOpen && (
                  <div style={{
                    position: 'absolute', top: '100%', right: 0, marginTop: 4,
                    background: 'var(--glass-bg)', backdropFilter: 'var(--glass-blur)', WebkitBackdropFilter: 'var(--glass-blur)',
                    border: '1px solid var(--glass-border)', borderRadius: 6,
                    zIndex: 1000, overflow: 'hidden', minWidth: 160,
                    boxShadow: '0 4px 20px rgba(0,0,0,0.5)',
                  }}>
                    {ADMIN_ITEMS.filter(i => hasRole(i.minRole ?? 'viewer')).map(item => {
                      const Icon = item.icon
                      const active = isActive(item.to)
                      return (
                        <Link
                          key={item.to}
                          to={item.to}
                          style={{
                            display: 'flex', alignItems: 'center', gap: 8,
                            padding: '8px 14px',
                            textDecoration: 'none',
                            background: active ? 'color-mix(in srgb, var(--accent-blue) 12%, transparent)' : 'transparent',
                            color: active ? 'var(--accent-blue)' : 'var(--text-primary)',
                            fontSize: 12.5,
                          }}
                        >
                          <Icon size={14} strokeWidth={active ? 2 : 1.75} />
                          {item.label}
                        </Link>
                      )
                    })}
                  </div>
                )}
              </div>
            )}
            <button
              onClick={logout}
              className="sign-out-btn"
              style={{
                padding: '5px 12px',
                borderRadius: 5,
                border: '1px solid var(--glass-border)',
                background: 'transparent',
                color: 'var(--text-secondary)',
                fontSize: 12,
                fontWeight: 500,
                cursor: 'pointer',
              }}
            >
              Sign out
            </button>
          </div>
```

- [ ] **Step 4: Visually verify in the dev server**

With `npm run dev` still running from Task 2: check the topbar reads as a frosted glass bar, search box + dropdown results are legible against the glass, Admin dropdown opens with the glass treatment, sign-out button still turns red on hover (from `.sign-out-btn:hover` in `index.css`, untouched).

- [ ] **Step 5: Commit**

```bash
git add dashboard/src/components/Layout.tsx
git commit -m "feat(dashboard): restyle topbar, search dropdown, and admin menu to enterprise-glass"
```

---

## Task 4: `AssistantWidget.tsx` glass restyle

**Files:**
- Modify: `dashboard/src/components/AssistantWidget.tsx`

- [ ] **Step 1: Restyle the floating toggle button**

Replace:

```tsx
        style={{
          position: 'fixed', right: 24, bottom: 24, zIndex: 60,
          width: 52, height: 52, borderRadius: '50%',
          background: open ? 'var(--bg-card)' : 'rgba(0,212,255,0.12)',
          border: '1px solid var(--accent-cyan)',
          color: 'var(--accent-cyan)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          cursor: 'pointer', boxShadow: '0 4px 20px rgba(0,212,255,0.25)',
        }}
```

with:

```tsx
        style={{
          position: 'fixed', right: 24, bottom: 24, zIndex: 60,
          width: 52, height: 52, borderRadius: '50%',
          background: open ? 'var(--bg-card)' : 'rgba(49,147,255,0.12)',
          border: '1px solid var(--accent-blue)',
          color: 'var(--accent-blue)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          cursor: 'pointer', boxShadow: '0 4px 20px rgba(49,147,255,0.25)',
        }}
```

- [ ] **Step 2: Restyle the chat panel shell and header**

Replace:

```tsx
        <div style={{
          position: 'fixed', right: 24, bottom: 88, zIndex: 60,
          width: 380, maxWidth: '92vw', height: 520, maxHeight: '70vh',
          background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: 10,
          display: 'flex', flexDirection: 'column', overflow: 'hidden',
          boxShadow: '0 12px 40px rgba(0,0,0,.5)',
        }}>
          <div style={{
            padding: '12px 14px', borderBottom: '1px solid var(--border)',
            display: 'flex', alignItems: 'center', gap: 8,
            background: 'linear-gradient(180deg,var(--bg-card),var(--bg-panel))',
          }}>
            <Bot size={16} color="var(--accent-cyan)" />
            <div>
              <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: 13, letterSpacing: 1, color: 'var(--text-primary)', textTransform: 'uppercase' }}>
                SOC Assistant
              </div>
              <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: 9.5, color: 'var(--text-muted)' }}>
                Read-only · alerts, cases, agents, UEBA, FIM, hunts, rules
              </div>
            </div>
          </div>
```

with:

```tsx
        <div style={{
          position: 'fixed', right: 24, bottom: 88, zIndex: 60,
          width: 380, maxWidth: '92vw', height: 520, maxHeight: '70vh',
          background: 'var(--glass-bg)', backdropFilter: 'var(--glass-blur)', WebkitBackdropFilter: 'var(--glass-blur)',
          border: '1px solid var(--glass-border)', borderRadius: 10,
          display: 'flex', flexDirection: 'column', overflow: 'hidden',
          boxShadow: '0 12px 40px rgba(0,0,0,.5)',
        }}>
          <div style={{
            padding: '12px 14px', borderBottom: '1px solid var(--glass-border)',
            display: 'flex', alignItems: 'center', gap: 8,
          }}>
            <Bot size={16} color="var(--accent-blue)" />
            <div>
              <div style={{ fontWeight: 700, fontSize: 13, letterSpacing: '0.02em', color: 'var(--text-primary)' }}>
                SOC Assistant
              </div>
              <div style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>
                Read-only · alerts, cases, agents, UEBA, FIM, hunts, rules
              </div>
            </div>
          </div>
```

- [ ] **Step 3: Restyle the message list, bubbles, and input row**

Replace:

```tsx
            {messages.length === 0 && (
              <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.6 }}>
                Ask me things like "any critical alerts today?", "summarize case X", "what's risky right now?", or "is host web01 online?"
                <br /><br />
                I can't change settings, users, or webhooks, or take actions — I just look things up.
              </div>
            )}
            {messages.map((m, i) => (
              <div key={i} style={{
                alignSelf: m.role === 'user' ? 'flex-end' : 'flex-start',
                maxWidth: '88%',
                background: m.role === 'user' ? 'rgba(0,212,255,0.12)' : 'var(--bg-card)',
                border: `1px solid ${m.role === 'user' ? 'var(--accent-cyan)' : 'var(--border)'}`,
                borderRadius: 8, padding: '8px 11px',
                fontSize: 13, color: 'var(--text-primary)', lineHeight: 1.5, whiteSpace: 'pre-wrap',
              }}>
                {m.content}
              </div>
            ))}
```

with:

```tsx
            {messages.length === 0 && (
              <div style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.6 }}>
                Ask me things like "any critical alerts today?", "summarize case X", "what's risky right now?", or "is host web01 online?"
                <br /><br />
                I can't change settings, users, or webhooks, or take actions — I just look things up.
              </div>
            )}
            {messages.map((m, i) => (
              <div key={i} style={{
                alignSelf: m.role === 'user' ? 'flex-end' : 'flex-start',
                maxWidth: '88%',
                background: m.role === 'user' ? 'rgba(49,147,255,0.12)' : 'var(--bg-card)',
                border: `1px solid ${m.role === 'user' ? 'var(--accent-blue)' : 'var(--glass-border)'}`,
                borderRadius: 8, padding: '8px 11px',
                fontSize: 13, color: 'var(--text-primary)', lineHeight: 1.5, whiteSpace: 'pre-wrap',
              }}>
                {m.content}
              </div>
            ))}
```

Replace:

```tsx
          <div style={{ padding: 10, borderTop: '1px solid var(--border)', display: 'flex', gap: 8 }}>
            <input
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send() } }}
              placeholder="Ask about alerts, cases, agents…"
              disabled={loading}
              style={{
                flex: 1, background: 'var(--bg-base)', border: '1px solid var(--border)', borderRadius: 5,
                padding: '8px 10px', color: 'var(--text-primary)', fontSize: 13, outline: 'none',
              }}
            />
            <button
              onClick={send}
              disabled={loading || !input.trim()}
              style={{
                width: 36, borderRadius: 5, border: '1px solid var(--accent-cyan)',
                background: 'rgba(0,212,255,0.1)', color: 'var(--accent-cyan)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                cursor: loading || !input.trim() ? 'not-allowed' : 'pointer',
                opacity: loading || !input.trim() ? 0.5 : 1,
              }}
            >
              <Send size={14} />
            </button>
          </div>
```

with:

```tsx
          <div style={{ padding: 10, borderTop: '1px solid var(--glass-border)', display: 'flex', gap: 8 }}>
            <input
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send() } }}
              placeholder="Ask about alerts, cases, agents…"
              disabled={loading}
              style={{
                flex: 1, background: 'var(--bg-base)', border: '1px solid var(--glass-border)', borderRadius: 5,
                padding: '8px 10px', color: 'var(--text-primary)', fontSize: 13, outline: 'none',
              }}
            />
            <button
              onClick={send}
              disabled={loading || !input.trim()}
              style={{
                width: 36, borderRadius: 5, border: '1px solid var(--accent-blue)',
                background: 'rgba(49,147,255,0.1)', color: 'var(--accent-blue)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                cursor: loading || !input.trim() ? 'not-allowed' : 'pointer',
                opacity: loading || !input.trim() ? 0.5 : 1,
              }}
            >
              <Send size={14} />
            </button>
          </div>
```

Also update the "Looking into it…" loading row — replace `color: 'var(--text-muted)'` line is already token-based, no change needed there.

- [ ] **Step 4: Verify build and visually check**

Run: `cd dashboard && npm run build` — expect success.
In the dev server, open the assistant widget (bottom-right bot icon) and confirm it now reads as a glass panel matching the rest of the chrome.

- [ ] **Step 5: Commit**

```bash
git add dashboard/src/components/AssistantWidget.tsx
git commit -m "feat(dashboard): restyle AssistantWidget to enterprise-glass"
```

---

## Task 5: New shared primitive — `GlassCard`

**Files:**
- Create: `dashboard/src/components/ui/GlassCard.tsx`

- [ ] **Step 1: Create the component**

```tsx
import type { ReactNode } from 'react'

interface GlassCardProps {
  title?: string
  actions?: ReactNode
  className?: string
  children: ReactNode
}

export default function GlassCard({ title, actions, className = '', children }: GlassCardProps) {
  return (
    <div
      className={`rounded-lg border border-[var(--glass-border)] bg-[var(--glass-bg)] backdrop-blur-xl shadow-[0_8px_24px_rgba(0,0,0,0.18),inset_0_1px_0_rgba(255,255,255,0.04)] ${className}`}
    >
      {(title || actions) && (
        <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--glass-border)]">
          {title && <h2 className="text-sm font-semibold text-[var(--text-primary)]">{title}</h2>}
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </div>
      )}
      <div className="p-4">{children}</div>
    </div>
  )
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd dashboard && npx tsc --noEmit -p .`
Expected: no new errors from `GlassCard.tsx`.

- [ ] **Step 3: Commit**

```bash
git add dashboard/src/components/ui/GlassCard.tsx
git commit -m "feat(dashboard): add GlassCard shared primitive"
```

---

## Task 6: New shared primitive — `PageHeader`

**Files:**
- Create: `dashboard/src/components/ui/PageHeader.tsx`

- [ ] **Step 1: Create the component**

```tsx
import type { ReactNode } from 'react'

interface PageHeaderProps {
  title: string
  subtitle?: string
  breadcrumb?: string
  actions?: ReactNode
}

export default function PageHeader({ title, subtitle, breadcrumb, actions }: PageHeaderProps) {
  return (
    <div className="flex items-start justify-between gap-4 mb-5">
      <div>
        <h1 className="text-xl font-semibold text-[var(--text-primary)] flex items-center gap-2 m-0">
          {breadcrumb && <span className="text-[var(--text-muted)] font-normal">{breadcrumb} /</span>}
          {title}
        </h1>
        {subtitle && <p className="text-xs text-[var(--text-secondary)] mt-1 mb-0">{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-2 flex-shrink-0">{actions}</div>}
    </div>
  )
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd dashboard && npx tsc --noEmit -p .`
Expected: no new errors from `PageHeader.tsx`.

- [ ] **Step 3: Commit**

```bash
git add dashboard/src/components/ui/PageHeader.tsx
git commit -m "feat(dashboard): add PageHeader shared primitive"
```

---

## Task 7: New shared primitive — `StatCard`

**Files:**
- Create: `dashboard/src/components/ui/StatCard.tsx`

- [ ] **Step 1: Create the component**

```tsx
import type { ReactNode } from 'react'

interface StatCardProps {
  label: string
  value: string | number
  trend?: { value: string; direction: 'up' | 'down' }
  trendGood?: 'up' | 'down'
  sparkline?: ReactNode
  onClick?: () => void
}

export default function StatCard({ label, value, trend, trendGood = 'up', sparkline, onClick }: StatCardProps) {
  const trendColor = trend
    ? (trend.direction === trendGood ? 'var(--accent-green)' : 'var(--accent-red)')
    : undefined

  return (
    <div
      onClick={onClick}
      className={`rounded-lg border border-[var(--glass-border)] bg-[var(--glass-bg)] backdrop-blur-xl shadow-[0_8px_24px_rgba(0,0,0,0.18),inset_0_1px_0_rgba(255,255,255,0.04)] p-4 ${
        onClick ? 'cursor-pointer hover:border-[var(--accent-blue)] transition-colors' : ''
      }`}
    >
      <div className="text-xs text-[var(--text-secondary)] uppercase tracking-wider">{label}</div>
      <div className="flex items-end justify-between mt-1 gap-2">
        <div className="text-2xl font-semibold text-[var(--text-primary)] tabular-nums">{value}</div>
        {trend && (
          <div style={{ color: trendColor }} className="text-xs font-medium flex items-center gap-0.5 pb-1">
            {trend.direction === 'up' ? '↑' : '↓'} {trend.value}
          </div>
        )}
      </div>
      {sparkline && <div className="mt-2">{sparkline}</div>}
    </div>
  )
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd dashboard && npx tsc --noEmit -p .`
Expected: no new errors from `StatCard.tsx`.

- [ ] **Step 3: Commit**

```bash
git add dashboard/src/components/ui/StatCard.tsx
git commit -m "feat(dashboard): add StatCard shared primitive"
```

---

## Task 8: `DataTable.tsx` glass restyle

**Files:**
- Modify: `dashboard/src/components/DataTable.tsx`

- [ ] **Step 1: Restyle the table container**

Replace:

```tsx
      <div className="rounded border border-border bg-card overflow-auto shadow-[0_0_0_1px_hsl(var(--primary)/0.06)]">
```

with:

```tsx
      <div className="rounded-lg border border-[var(--glass-border)] bg-[var(--glass-bg)] backdrop-blur-xl overflow-auto shadow-[0_8px_24px_rgba(0,0,0,0.18),inset_0_1px_0_rgba(255,255,255,0.04)]">
```

- [ ] **Step 2: Restyle the header row and row-hover accent**

Replace:

```tsx
          <thead className="bg-muted text-muted-foreground">
```

with:

```tsx
          <thead className="bg-transparent text-[var(--text-secondary)] border-b border-[var(--glass-border)]">
```

Replace:

```tsx
              <tr
                key={row.id}
                onClick={() => onRowClick?.(row)}
                className={`border-t border-border transition-colors ${onRowClick ? 'cursor-pointer hover:bg-white/[0.06] hover:border-l-2 hover:border-l-cyan-500/40' : 'hover:bg-white/[0.03]'}`}
              >
```

with:

```tsx
              <tr
                key={row.id}
                onClick={() => onRowClick?.(row)}
                className={`border-t border-[var(--glass-border)] transition-colors ${onRowClick ? 'cursor-pointer hover:bg-white/[0.06] hover:border-l-2 hover:border-l-[var(--accent-blue)]' : 'hover:bg-white/[0.03]'}`}
              >
```

- [ ] **Step 3: Leave the search/date-range inputs and pagination controls as-is**

These already use Tailwind's `border-border`/`bg-background`/`bg-muted` classes, which pick up the new palette automatically from Task 1's token update — no markup change needed. Confirm by reading the file: search input, date inputs, page-size `<select>`, and Prev/Next buttons all reference `border-border`/`bg-background`/`bg-muted` only.

- [ ] **Step 4: Verify build**

Run: `cd dashboard && npm run build`
Expected: success.

- [ ] **Step 5: Visually verify**

In the dev server, open any table page (e.g. `/agents`, `/logs`) and confirm: table container reads as a glass card, header row has no solid background, row hover shows a blue left-border accent instead of cyan.

- [ ] **Step 6: Commit**

```bash
git add dashboard/src/components/DataTable.tsx
git commit -m "feat(dashboard): restyle DataTable container to enterprise-glass"
```

---

## Task 9: `SeverityBadge.tsx` + `StatusBadge.tsx` restyle

**Files:**
- Modify: `dashboard/src/components/SeverityBadge.tsx`
- Modify: `dashboard/src/components/StatusBadge.tsx`

- [ ] **Step 1: Update `SeverityBadge.tsx`'s color map and typography**

Replace:

```tsx
const COLOR: Record<string, string> = {
  critical: 'var(--accent-red)',
  high: 'var(--accent-orange)',
  medium: 'var(--accent-yellow)',
  low: 'var(--accent-green)',
  info: 'var(--accent-cyan)',
}

export default function SeverityBadge({ severity }: { severity: string }) {
  const c = COLOR[severity] ?? 'var(--text-muted)'
  return (
    <span
      style={{
        display: 'inline-block',
        padding: '2px 8px',
        borderRadius: 3,
        border: `1px solid ${c}`,
        background: `color-mix(in srgb, ${c} 12%, transparent)`,
        color: c,
        fontFamily: 'Rajdhani, sans-serif',
        fontWeight: 700,
        fontSize: 11,
        letterSpacing: '0.5px',
        textTransform: 'uppercase',
        whiteSpace: 'nowrap',
      }}
    >
      {severity}
    </span>
  )
}
```

with:

```tsx
const COLOR: Record<string, string> = {
  critical: 'var(--accent-red)',
  high: 'var(--accent-orange)',
  medium: 'var(--accent-yellow)',
  low: 'var(--accent-green)',
  info: 'var(--accent-blue)',
}

export default function SeverityBadge({ severity }: { severity: string }) {
  const c = COLOR[severity] ?? 'var(--text-muted)'
  return (
    <span
      style={{
        display: 'inline-block',
        padding: '2px 8px',
        borderRadius: 4,
        border: `1px solid ${c}`,
        background: `color-mix(in srgb, ${c} 12%, transparent)`,
        color: c,
        fontWeight: 600,
        fontSize: 11,
        letterSpacing: '0.02em',
        textTransform: 'uppercase',
        whiteSpace: 'nowrap',
      }}
    >
      {severity}
    </span>
  )
}
```

- [ ] **Step 2: Update `StatusBadge.tsx`'s color map and typography**

Replace:

```tsx
const COLOR: Record<string, string> = {
  new: 'var(--accent-cyan)',
  in_progress: 'var(--accent-yellow)',
  resolved: 'var(--accent-green)',
  false_positive: 'var(--text-muted)',
  online: 'var(--accent-green)',
  offline: 'var(--text-muted)',
}

export default function StatusBadge({ status }: { status: string }) {
  const c = COLOR[status] ?? 'var(--text-muted)'
  return (
    <span
      style={{
        display: 'inline-block',
        padding: '2px 8px',
        borderRadius: 3,
        border: `1px solid ${c}`,
        background: `color-mix(in srgb, ${c} 12%, transparent)`,
        color: c,
        fontFamily: 'Rajdhani, sans-serif',
        fontWeight: 700,
        fontSize: 11,
        letterSpacing: '0.5px',
        textTransform: 'uppercase',
        whiteSpace: 'nowrap',
      }}
    >
      {status.replace('_', ' ')}
    </span>
  )
}
```

with:

```tsx
const COLOR: Record<string, string> = {
  new: 'var(--accent-blue)',
  in_progress: 'var(--accent-yellow)',
  resolved: 'var(--accent-green)',
  false_positive: 'var(--text-muted)',
  online: 'var(--accent-green)',
  offline: 'var(--text-muted)',
}

export default function StatusBadge({ status }: { status: string }) {
  const c = COLOR[status] ?? 'var(--text-muted)'
  return (
    <span
      style={{
        display: 'inline-block',
        padding: '2px 8px',
        borderRadius: 4,
        border: `1px solid ${c}`,
        background: `color-mix(in srgb, ${c} 12%, transparent)`,
        color: c,
        fontWeight: 600,
        fontSize: 11,
        letterSpacing: '0.02em',
        textTransform: 'uppercase',
        whiteSpace: 'nowrap',
      }}
    >
      {status.replace('_', ' ')}
    </span>
  )
}
```

- [ ] **Step 3: Verify build and visually check**

Run: `cd dashboard && npm run build` — expect success.
In the dev server, open `/alerts` and confirm severity/status pills render with the new palette (no more cyan "info"/"new"), Inter font (not the old condensed Rajdhani look — pills read slightly wider/less condensed now, which is expected).

- [ ] **Step 4: Commit**

```bash
git add dashboard/src/components/SeverityBadge.tsx dashboard/src/components/StatusBadge.tsx
git commit -m "feat(dashboard): remap SeverityBadge/StatusBadge to enterprise-glass tokens"
```

---

## Task 10: `AlertDetailModal.tsx` glass restyle

**Files:**
- Modify: `dashboard/src/components/AlertDetailModal.tsx`

- [ ] **Step 1: Restyle the modal overlay and panel**

Replace:

```tsx
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div className="w-full max-w-2xl rounded-lg border border-border bg-card p-6 shadow-2xl max-h-[90vh] overflow-auto"
        onClick={(e) => e.stopPropagation()}>
```

with:

```tsx
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div className="w-full max-w-2xl rounded-lg border border-[var(--glass-border)] bg-[var(--glass-bg)] backdrop-blur-xl p-6 shadow-2xl max-h-[90vh] overflow-auto"
        onClick={(e) => e.stopPropagation()}>
```

Everything else in this file (`bg-muted/20` panels, `border-border`, `text-muted-foreground`, the yellow/emerald suppression-suggestion callouts) already uses Tailwind compat classes that pick up the new palette from Task 1 automatically — no further edits needed.

- [ ] **Step 2: Verify build and visually check**

Run: `cd dashboard && npm run build` — expect success.
In the dev server, open `/alerts`, click a row to open the modal, confirm it now reads as a frosted glass panel over a blurred backdrop.

- [ ] **Step 3: Commit**

```bash
git add dashboard/src/components/AlertDetailModal.tsx
git commit -m "feat(dashboard): restyle AlertDetailModal to enterprise-glass"
```

---

## Task 11: `Toaster.tsx` glass restyle

**Files:**
- Modify: `dashboard/src/components/Toaster.tsx`

- [ ] **Step 1: Restyle the info-toast variant**

Replace:

```tsx
          className={`flex items-start gap-3 rounded border px-4 py-3 text-sm shadow-lg transition-all
            ${t.type === 'success' ? 'border-green-600 bg-green-950 text-green-200' : ''}
            ${t.type === 'error' ? 'border-red-600 bg-red-950 text-red-200' : ''}
            ${t.type === 'info' ? 'border-border bg-card text-foreground' : ''}
          `}
```

with:

```tsx
          className={`flex items-start gap-3 rounded-lg border px-4 py-3 text-sm shadow-lg backdrop-blur-xl transition-all
            ${t.type === 'success' ? 'border-green-600 bg-green-950/80 text-green-200' : ''}
            ${t.type === 'error' ? 'border-red-600 bg-red-950/80 text-red-200' : ''}
            ${t.type === 'info' ? 'border-[var(--glass-border)] bg-[var(--glass-bg)] text-[var(--text-primary)]' : ''}
          `}
```

- [ ] **Step 2: Verify build**

Run: `cd dashboard && npm run build` — expect success.

- [ ] **Step 3: Commit**

```bash
git add dashboard/src/components/Toaster.tsx
git commit -m "feat(dashboard): restyle Toaster info variant to enterprise-glass"
```

---

## Task 12: `DashboardPage.tsx` restyle (bespoke — KPI/StatCard integration)

**Files:**
- Modify: `dashboard/src/pages/DashboardPage.tsx`

`DashboardPage.tsx` hand-rolls its own local `SeverityBadge` component (duplicating the shared one with the old palette) plus `SectionCard`/`StatRow` layout helpers. Per spec scope, page business logic and data-fetching are untouched — this task only remaps the page's hardcoded colors/fonts to the new tokens and swaps ad-hoc section containers for `GlassCard`.

- [ ] **Step 1: Remap the local `severityColors` map**

Replace:

```tsx
const severityColors = {
  critical: { bg: 'rgba(255,34,68,0.15)', border: '#ff2244', color: '#ff2244' },
  high:     { bg: 'rgba(255,107,0,0.15)', border: '#ff6b00', color: '#ff6b00' },
  medium:   { bg: 'rgba(255,215,0,0.1)',  border: '#ffd700', color: '#ffd700' },
  low:      { bg: 'rgba(0,255,136,0.1)',  border: '#00ff88', color: '#00ff88' },
  info:     { bg: 'rgba(0,212,255,0.1)',  border: '#00d4ff', color: '#00d4ff' },
}
```

with:

```tsx
const severityColors = {
  critical: { bg: 'rgba(255,77,77,0.15)',  border: '#ff4d4d', color: '#ff4d4d' },
  high:     { bg: 'rgba(255,148,31,0.15)', border: '#ff941f', color: '#ff941f' },
  medium:   { bg: 'rgba(243,196,62,0.12)', border: '#f3c43e', color: '#f3c43e' },
  low:      { bg: 'rgba(100,196,102,0.12)',border: '#64c466', color: '#64c466' },
  info:     { bg: 'rgba(49,147,255,0.12)', border: '#3193ff', color: '#3193ff' },
}
```

- [ ] **Step 2: Drop the local `fontFamily: 'Rajdhani, sans-serif'` / uppercase styling on the local `SeverityBadge`**

Replace:

```tsx
      background: c.bg,
      color: c.color,
      fontFamily: 'Rajdhani, sans-serif',
      fontWeight: 700,
      fontSize: '11px',
      letterSpacing: '0.5px',
      textTransform: 'uppercase',
      boxShadow: `0 0 6px ${c.border}44`,
    }}>
```

with:

```tsx
      background: c.bg,
      color: c.color,
      fontWeight: 600,
      fontSize: '11px',
      letterSpacing: '0.02em',
      textTransform: 'uppercase',
      boxShadow: `0 0 6px ${c.border}44`,
    }}>
```

- [ ] **Step 3: Replace remaining hardcoded severity hex literals used for the `StatRow` accents**

Run: `grep -n "'#ff2244'\|'#ff6b00'\|'#ffd700'\|'#00ff88'\|'#00d4ff'" dashboard/src/pages/DashboardPage.tsx`

For each match found, replace the literal with the new equivalent using this mapping (do this as individual `Edit` calls per call site, since these are scattered `color="#ff2244"` prop values on `<StatRow>`/inline `style` attributes, not one contiguous block):

| Old | New |
|---|---|
| `#ff2244` (critical/red) | `#ff4d4d` |
| `#ff6b00` (high/orange) | `#ff941f` |
| `#ffd700` (medium/yellow) | `#f3c43e` |
| `#00ff88` (low/green) | `#64c466` |
| `#00d4ff` (info/cyan→blue) | `#3193ff` |

- [ ] **Step 4: Replace remaining `var(--accent-cyan)` and Rajdhani/Share Tech Mono references**

Run: `grep -n "accent-cyan\|Rajdhani\|Share Tech Mono" dashboard/src/pages/DashboardPage.tsx`

For each match: replace `var(--accent-cyan)` → `var(--accent-blue)`. For any inline `fontFamily: 'Rajdhani, sans-serif'` or `'Share Tech Mono, monospace'` declarations, delete the `fontFamily` line entirely (the page inherits Inter from `body` now) — keep the rest of that style object's other properties unchanged.

- [ ] **Step 5: Swap the `SectionCard` helper's container styling to the glass treatment**

Read the `SectionCard` component definition in this file (a small local wrapper used throughout the page for each panel — "Alert Statistics", "Top Source IPs", etc.). Update its outer container's `background`/`border` styling (whatever hex/`var(--bg-card)`/`var(--border)` values it currently uses) to:
```tsx
background: 'var(--glass-bg)',
backdropFilter: 'var(--glass-blur)',
WebkitBackdropFilter: 'var(--glass-blur)',
border: '1px solid var(--glass-border)',
borderRadius: 8,
boxShadow: '0 8px 24px rgba(0,0,0,0.18), inset 0 1px 0 rgba(255,255,255,0.04)',
```
Do not change `SectionCard`'s props/children API — this is a styling-only edit to its internal `style` object.

- [ ] **Step 6: Use `StatCard` for any top-of-page KPI tiles**

Read the full page to find its layout structure. `DashboardPage.tsx` has two different metric patterns:
- The "Alert Statistics" `SectionCard` (left column) renders `StatRow` items — compact label/value list rows. This is a **list**, not a tile grid; leave it as `StatRow` inside the now-glass `SectionCard` from Step 5 (don't force it into `StatCard`, which is a standalone bordered tile, not a list-row component — swapping the pattern here would be a layout rewrite, out of this plan's "restyle only" scope).
- If the page separately renders a row of large-number KPI tiles anywhere (e.g. total alerts today, open cases, active agents, MTTR — each its own bordered box with a big number), replace each of those specific ad-hoc tiles with `<StatCard label="..." value={...} />`, importing `StatCard` from `@/components/ui/StatCard`. Preserve whatever value/formatting expression the ad-hoc tile currently computes — only the wrapping markup changes.
- If no such KPI-tile row exists on this page today (i.e. all metrics are already list-style `StatRow`s), do not force one into existence — that would be a new feature, not a restyle, and is out of scope per the spec's "no new features" rule. In that case this step is a no-op; note that in the commit body.

- [ ] **Step 7: Verify build and visually check**

Run: `cd dashboard && npm run build` — expect success.
In the dev server, open `/` (Dashboard) and confirm: KPI/section panels read as glass cards, severity colors match the new palette, no leftover cyan or Rajdhani-styled text.

- [ ] **Step 8: Commit**

```bash
git add dashboard/src/pages/DashboardPage.tsx
git commit -m "feat(dashboard): restyle DashboardPage to enterprise-glass tokens"
```

---

## Task 13: `LoginPage.tsx` restyle (bespoke — standalone auth screen)

**Files:**
- Modify: `dashboard/src/pages/LoginPage.tsx`

`LoginPage.tsx` renders entirely outside `Layout.tsx`'s chrome — it's a full-screen, heavily custom-styled branded screen (animated scanline, pulsing rings, cyan grid background, inline `<style>{CSS}</style>` block with `@keyframes`). It needs its own pass rather than the generic per-page pattern used in Tasks 14+.

- [ ] **Step 1: Read the full file to scope all cyan/Rajdhani/Share-Tech-Mono references**

Run: `grep -n "cyan\|Rajdhani\|Share Tech Mono\|#00d4ff\|#020408\|rgba(6,182,212" dashboard/src/pages/LoginPage.tsx`

This page uses raw hex (not CSS custom properties) throughout, so there is no token-driven auto-update — every match from this grep needs a manual literal replacement.

- [ ] **Step 2: Replace the imported font and root background**

Replace the `CSS` template literal's font import line:
```
@import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;500;600;700&family=Share+Tech+Mono&display=swap');
```
with:
```
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
```

Replace the root container's:
```tsx
        background: '#020408',
        fontFamily: "'Share Tech Mono', monospace",
```
with:
```tsx
        background: '#040a12',
        fontFamily: "'Inter', system-ui, sans-serif",
```

- [ ] **Step 3: Replace all `rgba(6,182,212,...)` (old cyan) occurrences with the blue accent**

For every `rgba(6,182,212, X)` literal found in Step 1's grep, replace with `rgba(49,147,255, X)` (same alpha channel, new hue) — this covers the grid-line background, scanline gradient, corner brackets, and ring-pulse borders.

- [ ] **Step 4: Replace the brand/heading typography**

Wherever the file sets `fontFamily: 'Rajdhani, sans-serif'` (or similar Rajdhani declarations) with `textTransform: 'uppercase'` for the "AD-SIEM" / "SECURITY OPERATIONS CENTER" brand text and form labels, remove the `fontFamily` line and keep `textTransform: 'uppercase'` only where it applies to short label text (form field labels, brand tagline) — drop `letterSpacing` down to a value appropriate for Inter (roughly half the Rajdhani value, e.g. `'2px'` → `'1px'`) since Inter is not a condensed face.

- [ ] **Step 5: Replace the login button and input accent colors**

For any `#00d4ff` or cyan-named literal used on the submit button, focus rings, or input borders, replace with `#3193ff`.

- [ ] **Step 6: Verify build and visually check**

Run: `cd dashboard && npm run build` — expect success.
Log out (or open `/login` directly) and confirm: the branded left panel and form now use the blue accent instead of cyan, Inter typography, and the ring/scanline animations still play (only their color changed, not their `@keyframes` definitions).

- [ ] **Step 7: Commit**

```bash
git add dashboard/src/pages/LoginPage.tsx
git commit -m "feat(dashboard): restyle LoginPage to enterprise-glass palette"
```

---

## Task 14–37: Mechanical rollout — remaining 24 pages

**Pattern (identical for every page task below):**

1. Read the page file.
2. Replace the page's `<h1>` title block with `<PageHeader title="..." />` (add `subtitle`/`actions` props only if the page already renders a subtitle line or top-right action buttons next to the old `<h1>` — preserve those, don't drop them).
3. Add the import: `import PageHeader from '@/components/ui/PageHeader'` (and `import GlassCard from '@/components/ui/GlassCard'` if step 4 applies).
4. Find the page's ad-hoc outer panel wrapper(s) — `className` containing `rounded border border-border bg-card` (or `rounded-lg border ... bg-card`), or inline `style` referencing `var(--bg-card)`/`var(--bg-panel)` + `var(--border)` — and replace with `<GlassCard>...</GlassCard>`, preserving all children and their handlers unchanged. Skip this step for a page whose only "container" is a `DataTable` (already restyled in Task 8) with no additional wrapper chrome.
5. Grep the file for `Rajdhani`, `Share Tech Mono`, `accent-cyan`, and any hardcoded `#3b82f6`/`#00d4ff`/`#111318`/`#0d0f14` literals; remove `fontFamily: 'Rajdhani...'`/`'Share Tech Mono...'` declarations (Inter is inherited from `body`), replace `var(--accent-cyan)` → `var(--accent-blue)`, and replace any hardcoded hex matches per the color-mapping table in Task 12 Step 3.
6. Run `cd dashboard && npm run build` — expect success.
7. Manually check the page in the dev server.
8. Commit with message `feat(dashboard): restyle <PageName> to enterprise-glass`.

The exact current `<h1>` markup for each page (from a live grep of the codebase) is given below so each task starts from real code, not a guess:

- [ ] **Task 14 — `AgentsPage.tsx`** (`pages/AgentsPage.tsx:236`): `<h1 className="text-xl font-bold">Agents</h1>` → `<PageHeader title="Agents" />`. Also has `var(--accent-cyan)`/Rajdhani usages per Task grep — clean up per Step 5.

- [ ] **Task 15 — `AlertsPage.tsx`** (`pages/AlertsPage.tsx:182`): `<h1 className="text-xl font-bold">Alerts</h1>` → `<PageHeader title="Alerts" />`.

- [ ] **Task 16 — `AuditLogsPage.tsx`** (`pages/AuditLogsPage.tsx:43`): `<h1 className="text-xl font-bold">Audit Log</h1>` → `<PageHeader title="Audit Log" />`.

- [ ] **Task 17 — `CaseDetailPage.tsx`** (`pages/CaseDetailPage.tsx:290-301`):
```tsx
<h1 style={{
  fontFamily: 'Exo 2, sans-serif',
  fontWeight: 700,
  fontSize: '20px',
  color: 'var(--text-primary)',
  margin: 0,
  flex: 1,
}}>
  {caseData.created_by_ai && <span style={{ marginRight: '8px' }}>🤖</span>}
  {caseData.title}
</h1>
```
This one renders dynamic content (the case title + a conditional emoji) inside a back-button row, not a static string — do **not** replace it with `<PageHeader>` (which takes a plain string `title`). Instead, just strip the `fontFamily: 'Exo 2, sans-serif',` line so it inherits Inter, keep everything else (this file's title is already using the correct `--text-primary` token and non-uppercase casing, so this is the smallest edit of any page task). Also check for `ActionBtn`'s ad-hoc wrapper `<div>`s in this file (the ones already touched by the unrelated pending `transition: 'opacity 0.15s'` diff currently in the working tree — leave that existing uncommitted change alone, it's unrelated to this redesign) and wrap any `bg-card`/`var(--bg-card)` panel containers with `<GlassCard>` per Step 4.

- [ ] **Task 18 — `CasesPage.tsx`** (`pages/CasesPage.tsx:272-283`):
```tsx
<h1 style={{
  fontFamily: 'Rajdhani, sans-serif',
  fontWeight: 700,
  fontSize: '22px',
  letterSpacing: '2px',
  color: 'var(--accent-cyan)',
  margin: 0,
  display: 'flex',
  alignItems: 'center',
  gap: '8px',
}}>
```
This heading has a trailing icon/badge inside it (the `gap: '8px'` flex layout implies extra inline children after the text) — read the file to capture the full children before editing. Replace the `<h1>` wrapper with `<PageHeader title="Cases" />` only if the only child is plain text; if there's a trailing badge/count next to the title, keep the custom `<h1>` but change its style to `{ fontWeight: 700, fontSize: '22px', color: 'var(--text-primary)', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }` (drop `fontFamily`/`letterSpacing`, swap `accent-cyan` → `text-primary`).

- [ ] **Task 19 — `DecodersPage.tsx`** (`pages/DecodersPage.tsx:117`): `<h1 className="text-xl font-bold">Decoders</h1>` → `<PageHeader title="Decoders" />`.

- [ ] **Task 20 — `EventsPage.tsx`** (`pages/EventsPage.tsx:34`): `<h1 className="text-xl font-bold">Events</h1>` → `<PageHeader title="Events" />`.

- [ ] **Task 21 — `FimPage.tsx`** (`pages/FimPage.tsx:102-105`):
```tsx
<h1 className="text-xl font-bold flex items-center gap-2">
  <ShieldAlert size={20} />
  File Integrity Monitoring
</h1>
```
Has a leading icon — extend `PageHeader` usage as `<PageHeader title="File Integrity Monitoring" />` and move the `<ShieldAlert size={20} />` icon to render inline before the title text via a small local wrapper, e.g.:
```tsx
<PageHeader title={<span className="flex items-center gap-2"><ShieldAlert size={20} /> File Integrity Monitoring</span> as unknown as string} />
```
Since `PageHeader`'s `title` prop is typed `string`, prefer instead **not** using `PageHeader` for this page and just strip the Tailwind-only styling is already token-driven (`text-xl font-bold` has no hardcoded color) — leave the `<h1>` exactly as-is; `text-xl font-bold` already inherits `--text-primary`/Inter automatically from Task 1's token/font changes, so no edit is required here beyond confirming (Step 5's grep) there's no other hardcoded cyan/Rajdhani elsewhere in the file.

- [ ] **Task 22 — `HandoverPage.tsx`** (`pages/HandoverPage.tsx:49`): `<h1 className="text-xl font-bold">Shift Handover</h1>` → `<PageHeader title="Shift Handover" />`.

- [ ] **Task 23 — `HuntsPage.tsx`** (`pages/HuntsPage.tsx:164`): `<h1 className="text-xl font-bold">Threat Hunt</h1>` → `<PageHeader title="Threat Hunt" />`.

- [ ] **Task 24 — `HygienePage.tsx`** (`pages/HygienePage.tsx:486-493`):
```tsx
<h1 style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '20px', color: 'var(--accent-cyan)', letterSpacing: '2px', textTransform: 'uppercase', margin: 0 }}>
  IT HYGIENE
</h1>
<div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>
  Host health + package vulnerability scan via osv.dev · auto-refresh 5 min
</div>
```
Replace with:
```tsx
<PageHeader title="IT Hygiene" subtitle="Host health + package vulnerability scan via osv.dev · auto-refresh 5 min" />
```
(Drop the forced uppercase — `PageHeader` renders titles in normal case per the spec's typography rules; "IT Hygiene" reads correctly in title case without the `textTransform` hack.)

- [ ] **Task 25 — `LiveResponsePage.tsx`** (`pages/LiveResponsePage.tsx:233`): `<h1 className="text-xl font-bold">Live Response</h1>` → `<PageHeader title="Live Response" />`.

- [ ] **Task 26 — `LogSourcesPage.tsx`** (`pages/LogSourcesPage.tsx:61`): `<h1 className="text-xl font-bold">Log Sources</h1>` → `<PageHeader title="Log Sources" />`.

- [ ] **Task 27 — `LogsPage.tsx`** (`pages/LogsPage.tsx:34`): `<h1 className="text-xl font-bold">Raw Logs</h1>` → `<PageHeader title="Raw Logs" />`.

- [ ] **Task 28 — `MitreHeatmapPage.tsx`** (`pages/MitreHeatmapPage.tsx:50-56`):
```tsx
<div>
  <h1 className="text-xl font-bold flex items-center gap-2">
    <Grid3x3 size={20} /> MITRE ATT&amp;CK Heatmap
  </h1>
  <div className="text-xs text-muted-foreground mt-1">
    Technique frequency across triaged alerts — darker cells were seen more often.
  </div>
</div>
```
This uses only Tailwind compat classes (no hardcoded hex/Rajdhani) — already inherits the new palette/font from Task 1, so leave the heading markup unchanged. Only action for this page: check (Step 5 grep) for any hardcoded colors inside the heatmap grid cells themselves; per spec section "Out of scope," the heatmap grid's internal rendering logic is untouched, only its outer card chrome (if it has an ad-hoc wrapper) gets `<GlassCard>` treatment per Step 4.

- [ ] **Task 29 — `ReportsPage.tsx`** (`pages/ReportsPage.tsx:45`): `<h1 className="text-xl font-bold">Reports</h1>` → `<PageHeader title="Reports" />`.

- [ ] **Task 30 — `RulesPage.tsx`** (`pages/RulesPage.tsx:370`): `<h1 className="text-xl font-bold">Rules</h1>` → `<PageHeader title="Rules" />`. This page also includes the in-page Correlation panel per spec scope — apply Step 4/5 (GlassCard wrapper + accent-cyan/Rajdhani cleanup) to that panel's markup too, not just the top-level page.

- [ ] **Task 31 — `SettingsPage.tsx`** (`pages/SettingsPage.tsx:328-335`):
```tsx
<h1 style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '22px', color: 'var(--accent-cyan)', letterSpacing: '2px', textTransform: 'uppercase', margin: 0 }}>
  Platform Settings
</h1>
<p style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '12px', color: 'var(--text-muted)', margin: '4px 0 0' }}>
  Configure AI analyst, integrations, and platform behaviour. Changes take effect within 60 seconds.
</p>
```
Replace with:
```tsx
<PageHeader title="Platform Settings" subtitle="Configure AI analyst, integrations, and platform behaviour. Changes take effect within 60 seconds." />
```
Also wrap each settings-row group container with `<GlassCard>` per Step 4 (check `SettingRow`'s parent wrapper markup).

- [ ] **Task 32 — `SoarPage.tsx`** (`pages/SoarPage.tsx:313`): `<h1 style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '20px', color: 'var(--accent-cyan)', letterSpacing: '2px', textTransform: 'uppercase', margin: 0 }}>SOAR Playbooks</h1>` → `<PageHeader title="SOAR Playbooks" />`.

- [ ] **Task 33 — `SopPage.tsx`** (`pages/SopPage.tsx:63-66`):
```tsx
<h1 style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '20px', color: 'var(--accent-cyan)', letterSpacing: '2px', textTransform: 'uppercase', margin: 0 }}>
  SOP Documents
</h1>
```
This one sits in a flex row alongside an upload button (`<div>` with the file input + button, not inside the `<h1>`) — replace just the `<h1>` with `<PageHeader title="SOP Documents" />` and keep the sibling upload-button `<div>` exactly as-is (don't try to fold it into `PageHeader`'s `actions` prop unless it's trivial to lift without touching the `fileRef`/`handleUpload` logic — if it is trivial, pass it as `actions={...}` instead).

- [ ] **Task 34 — `UEBAPage.tsx`** (`pages/UEBAPage.tsx:257-264`):
```tsx
<h1 style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '20px', color: 'var(--accent-cyan)', letterSpacing: '2px', textTransform: 'uppercase', margin: 0 }}>
  UEBA
</h1>
<div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>
  User &amp; Entity Behavior Analytics &middot; Anomaly Detection Engine
</div>
```
Replace with:
```tsx
<PageHeader title="UEBA" subtitle="User & Entity Behavior Analytics · Anomaly Detection Engine" />
```

- [ ] **Task 35 — `UsersPage.tsx`** (`pages/UsersPage.tsx:38`): `<h1 className="text-xl font-bold">Users</h1>` → `<PageHeader title="Users" />`.

- [ ] **Task 36 — `WebhooksPage.tsx`** (`pages/WebhooksPage.tsx:30`): `<h1 className="text-xl font-bold">Webhooks</h1>` → `<PageHeader title="Webhooks" />`.

- [ ] **Task 37 — `YaraPage.tsx`** (`pages/YaraPage.tsx:100`): `<h1 className="text-xl font-bold">YARA Rules</h1>` → `<PageHeader title="YARA Rules" />`.

Each of Tasks 14–37 ends with the same three steps — run them individually per task, don't batch:

- [ ] Run `cd dashboard && npm run build` — expect success.
- [ ] Manually check the page renders correctly in the dev server (`npm run dev`).
- [ ] Commit: `git add dashboard/src/pages/<Page>.tsx && git commit -m "feat(dashboard): restyle <PageName> to enterprise-glass"`.

---

## Task 38: Final cross-cutting verification

**Files:** none (verification only)

- [ ] **Step 1: Confirm zero remaining references to removed tokens/fonts across the whole dashboard**

Run:
```bash
cd dashboard && grep -rn "accent-cyan\|Rajdhani\|Share Tech Mono\|Exo 2" src/ --include="*.tsx" --include="*.css"
```
Expected: no output. If anything remains, it was missed by a per-page task above — fix it directly (replace `accent-cyan`→`accent-blue`, strip the font-family override) and commit as `fix(dashboard): remove leftover cyberpunk-theme reference in <file>`.

- [ ] **Step 2: Confirm zero remaining bare `var(--border)` regressions**

Run:
```bash
cd dashboard && grep -c "hsl(var(--border-tw))" tailwind.config.ts
```
Expected: `1` — confirms Task 1's collision fix is still in place (hasn't been reverted by a later edit).

- [ ] **Step 3: Full production build**

Run: `cd dashboard && npm run build`
Expected: clean build, no TypeScript errors, no Vite warnings about unused imports (a page task that removed a `<h1 className="text-xl font-bold">` but forgot to remove a now-unused icon import would surface here).

- [ ] **Step 4: Full manual QA pass**

Run: `cd dashboard && npm run dev`, then in a browser walk through the spec's verification checklist:
- Dashboard, Alerts, Cases, CaseDetail, Settings, Logs (table-heavy), AuditLogs (table-heavy), MitreHeatmap (bespoke viz), Login (standalone).
- Sidebar collapsed and expanded states.
- Global search dropdown and Admin dropdown.
- Alert detail modal and a toast (trigger any mutation that shows one, e.g. updating a setting).
- Then spot-check the remaining pages from the full 26-page list.

- [ ] **Step 5: Commit any final fixes found during QA, then merge/finish per `superpowers:finishing-a-development-branch`**

If QA turns up issues, fix and commit them individually with descriptive messages (`fix(dashboard): ...`). Once clean, this plan's work is done — hand off to whatever the team's normal PR/merge flow is (this plan does not prescribe one).
