# DASHBOARD (React 18 + Vite + Tailwind)

SOC UI. React Router for pages, TanStack Query for server state, zustand for auth. TypeScript strict — `npm run build` runs `tsc -b` then `vite build`.

## STRUCTURE

```
dashboard/
├── src/
│   ├── App.tsx        # route table (25+ routes) + auth rehydrate effect
│   ├── main.tsx       # React root
│   ├── api/client.ts  # axios instance; Authorization from stores/auth
│   ├── pages/         # 26 page components (one per route)
│   ├── components/    # Layout, Sidebar, DataTable, AttackGraph, YamlEditor, modals...
│   ├── hooks/         # 19 TanStack Query hooks (useAlerts, useCases, useAgents, ...)
│   ├── stores/auth.ts # zustand: accessToken, user, setUser, logout
│   └── types/index.ts # shared TS types (7.5 KB)
├── tsconfig.json / tsconfig.app.json   # strict
├── tailwind.config.ts / vite.config.ts
└── Dockerfile / Dockerfile.dev / nginx-spa.conf
```

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Add a route | `src/App.tsx` | register page **and** role gate in the same `<Routes>` tree |
| Role gating | `App.tsx` via `<ProtectedRoute minRole="...">` | roles: `viewer` < `analyst` < `admin` < `superadmin` |
| Auth boot / token refresh | `App.tsx:36` effect + `src/stores/auth.ts` | on mount calls `GET /api/auth/me`; 401 → `logout()` |
| API calls | `src/api/client.ts` | single axios instance; never construct ad-hoc axios/fetch for platform APIs |
| Server state pattern | `src/hooks/use*.ts` | one hook file per domain wrapping TanStack Query keys |
| Layout / navigation | `src/components/Layout.tsx` (21 KB) + `Sidebar.tsx` | |
| Attack graph view | `src/components/AttackGraph.tsx` | |
| YAML editing UI | `src/components/YamlEditor.tsx` | CodeMirror + yaml lang |
| SPA fallback / build serve | `nginx-spa.conf`, `Dockerfile` | served on :80 internally |

## CONVENTIONS

- **All server state through TanStack Query hooks** in `src/hooks/` — components should not hold fetches directly.
- **Auth is zustand**, not context: `useAuthStore()` is the only token source.
- **Route role gating is nested at the route element**, not inside the page component.
- **Radix UI primitives + Tailwind** (`class-variance-authority`, `clsx`, `tailwind-merge`) — compose variants rather than writing raw CSS; the only stylesheet is `index.css` (4 KB).
- **Path alias `@/`** maps to `src/` (see `vite.config.ts` + tsconfig) — import as `@/api/client`, `@/hooks/useAlerts`.

## ANTI-PATTERNS

- **No `as any` / `@ts-ignore` / `@ts-expect-error`** — repo policy; types are strict for a reason.
- **`eslint-disable-next-line react-hooks/exhaustive-deps` is a smell** — it appears in `AttackGraph.tsx`, `YamlEditor.tsx`, `CaseDetailPage.tsx`; don't add more without a comment justifying the dep omission.
- **No unit test runner is configured** — `npm run build` is the only gate. Do not claim a dashboard change is "tested" without a build.
- **Do not hardcode API URLs** — use the axios client so `VITE_API_URL` / nginx routing stays in charge.
- **Do not add a page without registering it** in `App.tsx`'s route list — it will be unreachable (the `*` catch-all redirects to `/`).
- **`dist/` is committed** — a stale committed build will not reflect source changes; rebuild before concluding a UI bug is real.
