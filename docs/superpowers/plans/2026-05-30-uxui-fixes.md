# UX/UI Design Audit Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix all 12 findings from the design audit — accessibility, typography, contrast, touch targets, microcopy, language consistency.

**Architecture:** CSS/TSX-only changes. No new components, no refactor. Each task is one file or one concern.

**Tech Stack:** React + TypeScript, inline styles + CSS variables, Tailwind (limited), Vite

---

### Task 1: Sidebar group label contrast (FINDING-004)
**Files:** `dashboard/src/components/Layout.tsx`

- [ ] Change `color: '#3f4558'` → `color: '#64748b'` on both group label divs (lines 173, 230)
- [ ] Build verify: `cd dashboard && npm run build 2>&1 | tail -5`
- [ ] Commit: `git add dashboard/src/components/Layout.tsx && git commit -m "style(a11y): raise sidebar group label contrast #3f4558→#64748b"`

---

### Task 2: Touch targets — mode buttons & collapse button (FINDING-002)
**Files:** `dashboard/src/components/Layout.tsx`

- [ ] Mode buttons padding: `'3px 10px'` → `'8px 12px'` (line ~347)
- [ ] Mode buttons add `minHeight: 32`
- [ ] Collapse button: wrap in div with `padding: 8, cursor: pointer` to expand hit area
- [ ] Commit: `git add dashboard/src/components/Layout.tsx && git commit -m "style(a11y): expand touch targets mode buttons + collapse btn"`

---

### Task 3: Mode button tooltips (FINDING-008)
**Files:** `dashboard/src/components/Layout.tsx`

- [ ] Add `title` attribute to each mode button
- [ ] Commit: `git add dashboard/src/components/Layout.tsx && git commit -m "ux: add tooltip description to MANUAL/OBSERVER/OPERATOR mode buttons"`

---

### Task 4: Sign out hover via CSS, not inline JS (FINDING-011)
**Files:** `dashboard/src/components/Layout.tsx`, `dashboard/src/index.css`

- [ ] Remove `onMouseEnter`/`onMouseLeave` from sign out button
- [ ] Add `className="sign-out-btn"` to sign out button
- [ ] Add `.sign-out-btn:hover` CSS in index.css
- [ ] Commit

---

### Task 5: Login font align with app (FINDING-001)
**Files:** `dashboard/src/pages/LoginPage.tsx`

- [ ] Change Google Fonts import: add Rajdhani, remove Orbitron (already have it via index.css)
- [ ] Replace all `fontFamily: "'Orbitron', monospace"` → `fontFamily: "'Rajdhani', sans-serif"`
- [ ] Keep Share Tech Mono for form inputs (matches app's mono usage)
- [ ] Commit: `git add dashboard/src/pages/LoginPage.tsx && git commit -m "style: align login page fonts with app (Rajdhani replaces Orbitron)"`

---

### Task 6: Fix 10px text → 12px in login (FINDING-003)
**Files:** `dashboard/src/pages/LoginPage.tsx`

- [ ] Label "SECURE ACCESS PORTAL": `fontSize: 10` → `fontSize: 12`
- [ ] Labels `[ USERNAME ]` / `[ PASSWORD ]`: `fontSize: 10` → `fontSize: 12`
- [ ] Status items at bottom: `fontSize: 10` → `fontSize: 12`
- [ ] Commit: `git add dashboard/src/pages/LoginPage.tsx && git commit -m "style(a11y): raise login page minimum font size 10px→12px"`

---

### Task 7: Add prefers-reduced-motion (FINDING-005)
**Files:** `dashboard/src/pages/LoginPage.tsx`

- [ ] Append to end of CSS string (before closing backtick):
```css
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    transition-duration: 0.01ms !important;
  }
}
```
- [ ] Commit: `git add dashboard/src/pages/LoginPage.tsx && git commit -m "style(a11y): respect prefers-reduced-motion in login page animations"`

---

### Task 8: UEBA jargon fix (FINDING-012)
**Files:** `dashboard/src/pages/UEBAPage.tsx`

- [ ] Line ~191: `User &amp; Entity Behavior Analytics &middot; Isolation Forest` → `User &amp; Entity Behavior Analytics &middot; Anomaly Detection Engine`
- [ ] Commit

---

### Task 9: Settings — add missing human-readable labels (FINDING-007)
**Files:** `dashboard/src/pages/SettingsPage.tsx`

- [ ] Add missing keys to SETTING_LABELS: `retention_alerts_days`, `retention_events_days`, `retention_logs_days`, `case_auto_close_days`, `max_alerts_per_rule`, and any others returned from API
- [ ] Add corresponding SETTING_HINTS entries
- [ ] Commit

---

### Task 10: Dashboard layout focal point (FINDING-010)
**Files:** `dashboard/src/pages/DashboardPage.tsx`

- [ ] Change left column `width: '260px'` → `width: '220px'`
- [ ] Give middle column explicit `flex: 1` and right column `width: '280px'`
- [ ] Commit

---

### Task 11: AI prompts — English language (FINDING-009)
**Files:** `worker/worker/groq_client.py`, `worker/worker/hunter.py`

- [ ] In groq_client.py: change triage_notes prompt from Indonesian to English
- [ ] In groq_client.py: change narrative prompt from Indonesian to English
- [ ] In hunter.py: change attack_narrative prompt from Indonesian to English
- [ ] Commit

---

### Task 12: Base font size 14px → 15px (FINDING-006)
**Files:** `dashboard/src/index.css`

- [ ] `font-size: 14px` → `font-size: 15px` in html/body
- [ ] Commit
