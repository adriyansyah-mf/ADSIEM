# Security & Governance release gate — 2026-09-06

Plan: `docs/superpowers/plans/2026-09-06-security-governance.md`
Ledger: `.superpowers/sdd/2026-09-06-security-governance/progress.md`
Task reports: `task-1` (Central outbound URL policy, prior turn) through `task-5-report.md` in
the same directory.

This gate re-runs the complete security/governance test set as one coherent pass and performs
live negative checks through the actual nginx edge, rather than re-describing each task's own
verification. Per-task detail, RED evidence, and design rationale live in the individual task
reports; this document is the final go/no-go record.

## Environment

- Branch: `feature/siem-implementation`, commit `ab7c9a30e6d6ecfdca3ffb23f7b95a6c5b2f55ea`
  (worktree intentionally dirty — see `docs/IMPLEMENTATION_STATUS.md` Known Limitations; no
  task in this initiative has created a commit, by standing ruling recorded in the ledger).
- Containers at gate time (`docker compose ps`):
  - `siem-platform-server-api-1` — image `siem-platform-server-api`, healthy
  - `siem-platform-nginx-1` — image `nginx:alpine`, healthy (restarted this session to pick up
    Task 5's config changes — see Residual Risk)
  - `siem-platform-postgres-1` — image `pgvector/pgvector:pg16`, healthy
  - `siem-platform-redis-1` — image `redis:7-alpine`, healthy
  - `siem-platform-worker-1`, `siem-platform-dashboard-1`, `siem-platform-elasticsearch-1` —
    all healthy, unaffected by this initiative (no files under `worker/` or `agent/` were
    touched by any task in this plan)
- Host Python lacks `asyncpg`, `structlog`, and `pgvector` — all server-api Python tests below
  were run inside `siem-platform-server-api-1` via `PYTHONPATH=/app`, except the
  `docker`-CLI-dependent tenant-isolation tests, run from the host against the live API through
  nginx (documented per-suite below).

## 1. Complete security/governance test set

| Suite | Command | Result | Exit |
|---|---|---|---|
| Full non-live suite (SSRF, permission matrix, API keys, audit chain, rate limits, RBAC, auth, decoders, ingest, sigma-compat, soar approval) | `docker exec siem-platform-server-api-1 sh -lc "cd /tmp/repo && PYTHONPATH=/app python -m pytest -q tests/server-api/ -k 'not service_e2e'"` | **72 passed**, 8 deselected | 0 |
| Tenant isolation (live, real Postgres fixtures) | `python -m pytest -q -m service_e2e tests/server-api/test_tenant_isolation.py` (from host — this file's fixture shells out to the `docker` CLI, unavailable inside the container) | **3 passed** | 0 |
| Audit chain (live, real Postgres, concurrent + tamper) | `docker exec siem-platform-server-api-1 sh -lc "cd /tmp/repo && PYTHONPATH=/app python -m pytest -q tests/server-api/test_audit_chain.py -m service_e2e"` | **5 passed** | 0 |
| **Total** | — | **80 passed, 0 failed** | — |
| `compileall` | `docker exec -e PYTHONPYCACHEPREFIX=/tmp/pycache siem-platform-server-api-1 python -m compileall -q app` | clean | 0 |
| Dashboard production build | `cd dashboard && npm run build` (`tsc -b && vite build`) | succeeds; one pre-existing chunk-size warning (bundle >500kB, already tracked in Known Limitations) | 0 |

Test suite breakdown by file: `test_api_keys.py` (19), `test_audit_chain.py` (10, 5 pure + 5
live), `test_auth.py`, `test_decoder_route.py`, `test_ingest.py`, `test_outbound_url_policy.py`,
`test_rbac.py`, `test_route_permission_matrix.py` (2), `test_security_boundaries.py` (10),
`test_sigma_compat.py`, `test_soar_approval.py`, `test_tenant_isolation.py` (3, live-only).

OpenAPI operation count at gate time: **152** (148 baseline inventoried in Task 2A + 3 new
`/api/api-keys` operations in Task 3 + 1 new `/api/audit-logs/verify` in Task 4; Task 5 added
no routes). Confirmed via `test_route_permission_matrix_covers_each_openapi_operation`, which
asserts the matrix, the live OpenAPI schema, and the public-route dependency scan all agree —
not just a manually-eyeballed count.

## 2. Live negative checks (through nginx, port 80 — not the direct server-api port)

All six checks below were run fresh for this gate (not merely re-cited from earlier task
reports), against the running `nginx` container, exactly as an external client would reach the
platform.

### 2.1 Loopback / metadata URL rejection (SSRF)
```
POST /api/webhooks {"url": "http://127.0.0.1/admin"}        -> 422 "Outbound URLs must use HTTPS"
POST /api/webhooks {"url": "https://127.0.0.1/admin"}        -> 422 "Outbound URL resolves to a non-public address"
POST /api/webhooks {"url": "https://169.254.169.254/..."}    -> 422 "Outbound URL resolves to a non-public address"
```
Both the scheme check and the DNS/IP-class check reject independently, and the cloud-metadata
address is rejected identically to loopback.

### 2.2 Cross-tenant denial
Created a disposable tenant fixture (role, user in group `blue`, an alert in group `red`),
authenticated as the `blue` user, and requested the `red` alert by ID:
```
GET /api/alerts/{red_alert_id}  (as blue-tenant user) -> 404 {"detail":"Alert not found"}
```
All fixture rows deleted immediately after (verified via `DELETE ... ` row counts, all 1).

### 2.3 Revoked API-key denial
```
POST /api/api-keys        (admin JWT)      -> 201, secret returned once
DELETE /api/api-keys/{id} (admin JWT)      -> 204
GET /api/api-keys         (revoked secret) -> 401 {"detail":"Invalid or expired API key"}
```

### 2.4 Rate limiting
Six consecutive `POST /api/auth/mfa/disable` calls from the same authenticated session (policy:
5 requests/60s, tenant-scoped): the first five returned `200`, the sixth returned `429`. (The
login-route rate limit's full cycle — including the `Retry-After` value and confirmation that a
legitimate login succeeds again once the window resets — was verified in Task 5 and is not
re-run here to avoid re-locking the only interactive account in this dev database for this
gate's remaining checks.)

### 2.5 Audit chain verification
```
GET /api/audit-logs/verify?group_id=default -> {"verified": true, "verified_count": 214,
  "total_count": 214, "head_hash_prefix": "97b6d4da7744", "broken_at_id": null,
  "broken_at_timestamp": null}
```
Row count (214) is higher than Task 4's recorded 201-203 because normal platform activity
(logins during this session's testing) continued appending to the real chain between tasks —
expected, and itself evidence the chain keeps accepting and verifying new entries correctly.

### 2.6 Redacted secret responses
```
GET /api/settings (admin JWT) -> every is_secret=true row's "value" field is either "••••••••"
  (masked, set) or "" (masked, unset) — confirmed across all secret-flagged settings currently
  seeded (AbuseIPDB, 9router, OTX, Shodan, SMTP password, and several Splunk-integration
  settings from other in-progress work in this shared worktree). No plaintext secret value was
  present in any response body inspected during this gate.
```
Audit-log secret redaction (a distinct mechanism — redacting `detail` payload keys before
hashing/storage, not response masking) was verified in Task 4 with dedicated tests
(`test_redaction_applies_before_storage_and_hashing`) and is not re-run here.

## 3. Residual risk and environmental limitations (aggregated from all five task reports)

- **No task in this plan has produced a commit.** Every change (Tasks 1 through 5) remains in
  the working tree, per the standing ruling recorded in the ledger: this worktree is
  intentionally dirty with other in-progress work (SOAR v2, Splunk integration visible in
  Settings, dashboard rebuilds), and a clean scoped commit was judged not safely extractable
  without a dedicated reconciliation pass this plan did not include. This is the single largest
  piece of residual risk: **the verified state described in this report exists only in the
  working tree**, not in git history, until a future session commits it.
- `require_resource_group` (Task 2B) returns `404` unconditionally for a resource with a null
  `group_id`, including for superadmin callers — not observed as a live bug (no in-scope
  resource has nullable `group_id`), flagged for any future resource family that might.
- `ServicePrincipal.id` (Task 3) is always `None`; content created via an API key stores `NULL`
  for the acting-identity column. Task 4's `actor_type`/`actor_id` audit fields are the intended
  place for real per-action service attribution, not yet extended to every content table.
- Historical audit rows (Task 4) migrated into the tamper-evident chain are attributed to a
  tenant on a best-effort basis; rows with no resolvable actor share an `__unscoped__` chain.
  `GET /api/audit-logs/verify` defaults an unscoped superadmin call to that same bucket, not an
  aggregate of all tenants.
- Rate-limit thresholds (Task 5) are this task's own considered defaults, not validated against
  real traffic. The "tenant, not per-user" identity model (matching the plan's literal wording)
  means multiple users in one tenant share a budget for authenticated policies.
- `nginx.prod.conf`'s Task 5 changes were validated for syntax only (`nginx -t` in a throwaway
  container); this dev environment runs `nginx.conf`, not the production config, so its runtime
  behavior could not be exercised live.
- **A live verification-process gap was caught and fixed during Task 5, not before**: editing
  `nginx.conf` on the host had no effect on the running `nginx` container until it was
  explicitly restarted (nginx reads its config once at process start; the dev `server-api`
  container's `uvicorn --reload` had been masking the fact that this project's other services
  don't auto-reload on config changes). The fix was applied and re-verified live, but this is
  worth carrying forward as a checklist item for anyone editing nginx config in this repo:
  restart the `nginx` service explicitly, don't assume the bind mount alone is sufficient.
- **This gate's `npm run build` regenerated `dashboard/dist/`**, which was already in a dirty,
  mid-flight state before this session began (tracked files marked deleted, untracked hashed
  bundle files present from a prior build). The new build produced a fresh, current, correct
  set of hashed output files reflecting all of Tasks 3 and 4's UI changes — `dist/` is fully
  reproducible from source at any time, so no source-level work was at risk — but the specific
  previously-untracked build artifacts on disk before this gate ran no longer exist, replaced by
  this run's output. Nothing under `dashboard/dist/` was staged or committed.
- Task 6 introduces no new application code — only this report and the `CHANGELOG.md` summary
  below — so no new residual risk of its own beyond what Tasks 1-5 already documented.

## 4. Verdict

**PASS.** All 80 automated tests pass; `compileall` and the dashboard production build succeed;
all six live negative checks behave as specified, run fresh through the actual nginx edge. The
security-governance plan's six tasks are functionally complete and verified live. The residual
risks above are documented trade-offs and environmental gaps, not known defects — the most
consequential is that this verified state has not yet been captured in a git commit.
