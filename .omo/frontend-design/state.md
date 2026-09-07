# Frontend Design State

## Current Objective

Apply the approved enterprise-glass design system consistently across the AD-SIEM React dashboard without changing routing, data fetching, or business behavior.

## Locked Decisions

- Dark-only enterprise SOC interface.
- Navy glass surfaces, restrained blue interactive accent, semantic severity colors.
- Inter typography with tabular figures; no retro/cyberpunk display fonts.
- Preserve all existing user edits and application behavior.
- `DESIGN.md` is the implementation contract.

## Source Inputs

- `DESIGN.md`
- `docs/superpowers/specs/2026-08-12-enterprise-glass-ui-design.md`
- `docs/superpowers/plans/2026-08-13-enterprise-glass-ui-redesign.md`
- `enterprise_siem_dashboard.html`
- UI/UX database query: `enterprise security operations SIEM dark glass data-dense accessible`

## Design Brief

The primary users are SOC analysts and administrators who need high-density, low-noise situational awareness. The visual hierarchy prioritizes severity, recency, ownership, and next actions. Glass depth supports grouping; it must never overpower operational data.

## Inclusive Personas

- SOC analyst responding under time pressure.
- Keyboard-only administrator.
- Low-vision analyst using 200% zoom.
- Motion-sensitive operator using reduced-motion preferences.

## Adaptive Preferences

Verify reduced motion, visible keyboard focus, responsive reflow at 375/768/1280px, and 200% zoom. Dark mode is the approved and only color scheme.

## Verification Matrix

- TypeScript/Vite production build.
- LSP diagnostics on changed TypeScript files.
- Visual QA at 375px, 768px, and 1280px on representative routes.
- Expanded/collapsed sidebar, search/admin menus, dialog and toast surfaces.
- Design-token scan and accessibility/heuristic walkthrough.

## Design Debt Register

| ID | Source | Severity | Issue | Affected users | Suggested fix | Status | Notes |
|---|---|---|---|---|---|---|---|
| DS-001 | Existing app | Minor | Initial bundle is monolithic and exceeds the Vite warning threshold. | Slow-network users | Route-level code splitting in a dedicated performance change. | Accepted | Outside visual-only scope; user approval required before architecture work. |

## Evidence Index

- Baseline build: passed on 2026-09-05; Vite reported the pre-existing chunk-size warning.
- Visual QA artifacts: `.omo/evidence/enterprise-ui/qa-report.json` and 72 screenshots across 23 routed screens plus login at 375/768/1280px; final report has `failures: []`.
- Interaction smoke: sidebar collapse/expand, Admin menu ARIA state, assistant open state, global search result, and login label associations all passed in Chromium.
- React Doctor: scanned 73 files; reported 198 warnings, predominantly pre-existing accessibility debt and oversized legacy components. No new runtime errors were found in the changed surface.
- Browser QA was run with deterministic API fixtures because the live database password is no longer the seed value and the local host port 8000 is occupied by another service.

## Handoff Notes

Implementation must preserve the three pre-existing modified pages: `CaseDetailPage.tsx`, `CasesPage.tsx`, and `SettingsPage.tsx`.

## Runtime Note

The documented seed remains `admin` / `admin123`, but the persistent database currently has a different Argon2id hash for the active `admin` superadmin account. The application/API were not modified to reset credentials.

The local dev proxy now targets host port `8002`, which publishes the Compose `server-api` container's port `8000`; host port `8000` remains reserved for another service.
