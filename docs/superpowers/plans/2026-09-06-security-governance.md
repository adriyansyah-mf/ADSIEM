# Security and Governance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enforce safe outbound HTTP, explicit tenant-aware authorization, scoped service identities, and tamper-evident audit history across AD-SIEM.

**Architecture:** Add reusable security boundaries at the FastAPI dependency and service layers, then route all user-controlled network destinations and identities through them. Persist API-key metadata and tenant audit-chain hashes in PostgreSQL; expose only non-secret management data to the dashboard.

**Tech Stack:** Python 3.12, FastAPI, Pydantic v2, SQLAlchemy async, PostgreSQL 16, HTTPX, pytest, React/TypeScript.

**Spec:** `docs/superpowers/specs/2026-09-06-production-hardening-design.md`

## Global Constraints

- Every database query, Redis key, Elasticsearch query, export, service credential, and background job is scoped by tenant/group unless explicitly global and superadmin-only.
- Network destinations supplied by users reject loopback, RFC1918, link-local, multicast, metadata, unsafe redirects, and DNS rebinding results.
- Secrets never enter API responses, logs, audits, AI prompts, metrics labels, exports, or reports.
- Existing JWT user authentication and permission names remain compatible.
- Every delivered task updates `CHANGELOG.md` and includes focused tests plus live container verification.

---

### Task 1: Central outbound URL policy

**Files:**
- Create: `server-api/app/core/outbound_url.py`
- Modify: `server-api/app/api/routes/rules.py`
- Modify: `server-api/app/api/routes/webhooks.py`
- Test: `tests/server-api/test_outbound_url_policy.py`

**Interfaces:**
- Produces: `async def validate_outbound_url(url: str, *, allowed_hosts: frozenset[str] = frozenset()) -> ValidatedOutboundUrl`
- Produces: `ValidatedOutboundUrl(url: str, host: str, resolved_addresses: tuple[str, ...])`

- [ ] **Step 1: Write failing destination-policy tests**

```python
@pytest.mark.parametrize("url", [
    "http://127.0.0.1/admin",
    "http://169.254.169.254/latest/meta-data",
    "http://10.0.0.7/internal",
    "http://[::1]/",
])
async def test_rejects_non_public_destinations(url):
    with pytest.raises(OutboundUrlRejected):
        await validate_outbound_url(url)
```

- [ ] **Step 2: Run the focused test and confirm failure**

Run: `python -m pytest -q tests/server-api/test_outbound_url_policy.py`
Expected: import failure because `outbound_url.py` does not exist.

- [ ] **Step 3: Implement URL parsing and address validation**

Use `urllib.parse.urlsplit`, `asyncio.get_running_loop().getaddrinfo`, and `ipaddress.ip_address`. Accept only `https` by default; reject embedded credentials, missing host, prohibited ports, and any resolved prohibited address. Preserve the validated normalized URL as the only value passed to HTTPX.

- [ ] **Step 4: Route repository import and webhook create/update through the policy**

`import_sigma_repository`, `create_webhook`, and `update_webhook` must call the validator before persisting or fetching. Repository fetches use `follow_redirects=False`, connect/read timeouts, and the existing response-size limit.

- [ ] **Step 5: Verify**

Run the focused test, compileall for changed files, and an in-container smoke proving a public allowlisted repository URL passes while loopback fails.

### Task 2: Permission matrix and cross-tenant route audit

**Files:**
- Create: `server-api/app/core/permission_matrix.py`
- Modify: `server-api/app/core/deps.py`
- Modify: affected route modules under `server-api/app/api/routes/`
- Test: `tests/server-api/test_route_permission_matrix.py`
- Test: `tests/server-api/test_tenant_isolation.py`

**Interfaces:**
- Produces: `ROUTE_PERMISSIONS: Mapping[tuple[str, str], str | None]`
- Produces: `require_resource_group(resource_group: str | None, scoped_group: str | None) -> None`

- [ ] **Step 1: Generate a failing OpenAPI permission coverage test**

```python
def test_every_non_public_api_operation_has_declared_permission(app):
    operations = {(method.upper(), path) for path, item in app.openapi()["paths"].items() for method in item}
    assert operations - PUBLIC_OPERATIONS <= ROUTE_PERMISSIONS.keys()
```

- [ ] **Step 2: Add table-driven foreign-group tests**

Cover alerts, cases, agents/log sources, rules/revisions, webhooks, suppressions, schedules, SOAR executions, reports, saved investigations, and exports. Each test creates tenant A/B resources and asserts tenant B cannot read, mutate, or delete tenant A IDs.

- [ ] **Step 3: Add the matrix and standard group guard**

The matrix is the authoritative inventory for tests and documentation. Existing route dependencies remain the runtime mechanism; missing or weaker route guards are corrected without changing response shapes.

- [ ] **Step 4: Verify all route and isolation tests**

Run in the server container against disposable tenant fixtures, then run compileall and OpenAPI generation.

### Task 3: Scoped API keys and service accounts

**Files:**
- Modify: `server-api/app/models/models.py`
- Modify: `server-api/app/schemas/schemas.py`
- Create: `server-api/app/services/api_keys.py`
- Create: `server-api/app/api/routes/api_keys.py`
- Modify: `server-api/app/core/deps.py`
- Modify: `server-api/app/main.py`
- Modify: `db/init.sql`
- Create: `dashboard/src/hooks/useApiKeys.ts`
- Create: `dashboard/src/components/settings/ApiKeyPanel.tsx`
- Modify: `dashboard/src/pages/SettingsPage.tsx`
- Test: `tests/server-api/test_api_keys.py`

**Interfaces:**
- `ApiKey(id, prefix, secret_hash, name, group_id, permissions, expires_at, last_used_at, revoked_at, created_by, created_at)`
- `POST /api/api-keys` returns the plaintext secret exactly once.
- `GET /api/api-keys` returns metadata only.
- `DELETE /api/api-keys/{id}` revokes within the caller’s group.

- [ ] **Step 1: Write failing create/authenticate/revoke/expiry tests**

Assert the stored value is an Argon2 hash, listing never returns the secret, permission escalation is rejected, and expired/revoked keys receive `401`.

- [ ] **Step 2: Add schema, startup migration, and initial SQL**

Use a visible `adsiem_` prefix plus random secret; persist only prefix and hash. Seed `api_keys:manage` for superadmin/admin roles.

- [ ] **Step 3: Extend authentication dependencies**

Accept `Authorization: Bearer <key>` alongside JWT. Resolve one immutable principal contract containing actor type/id, group, role, and permissions.

- [ ] **Step 4: Add management API and Settings panel**

Show prefix, name, permissions, expiry, last use, and revocation. Show the newly created secret once with a copy warning; never cache it in query state.

- [ ] **Step 5: Verify API tests, build, and responsive UI**

Capture empty, created-secret, populated, and revoked states at 375/768/1280 pixels.

### Task 4: Tamper-evident tenant audit chain

**Files:**
- Modify: `server-api/app/models/models.py`
- Modify: `server-api/app/schemas/schemas.py`
- Modify: `server-api/app/services/audit.py`
- Modify: `server-api/app/api/routes/audit_logs.py`
- Modify: `server-api/app/main.py`
- Modify: `db/init.sql`
- Modify: `dashboard/src/pages/AuditLogsPage.tsx`
- Test: `tests/server-api/test_audit_chain.py`

**Interfaces:**
- Audit fields: `actor_type`, `actor_id`, `group_id`, `request_id`, `payload_hash`, `previous_hash`, `chain_hash`.
- Produces: `verify_audit_chain(group_id: str) -> AuditChainVerification`.
- Adds: `GET /api/audit-logs/verify` guarded by `audit:verify`.

- [ ] **Step 1: Write deterministic chain and tamper tests**

Use canonical JSON with sorted keys and compact separators. Assert two sequential rows link hashes and modifying a historical payload causes verification failure at that row.

- [ ] **Step 2: Add fields, indexes, and tenant-chain locking**

Create one `audit_chain_heads` row per tenant and lock it with `SELECT ... FOR UPDATE` while appending. Existing audit rows are migrated into a verifiable genesis segment.

- [ ] **Step 3: Update audit service and API**

Accept the immutable principal contract from Task 3, redact secret-valued fields before hashing, and expose verification status without exposing raw sensitive payloads.

- [ ] **Step 4: Add UI chain status**

Display verified/broken status, verified row count, head hash prefix, and failure timestamp. The UI cannot repair or rewrite history.

- [ ] **Step 5: Verify concurrent append and tamper detection**

Run database-backed tests with concurrent appenders, compileall, frontend build, and responsive visual QA.

### Task 5: Rate limits and security headers

**Files:**
- Create: `server-api/app/core/rate_limit.py`
- Modify: `server-api/app/main.py`
- Modify: `nginx/nginx.conf`
- Modify: `nginx/nginx.prod.conf`
- Test: `tests/server-api/test_security_boundaries.py`

**Interfaces:**
- Produces: `RateLimitPolicy(name: str, requests: int, window_seconds: int)`.
- Applies strict policies to login, MFA, ingestion, repository import, API-key creation, AI chat, and SOAR approval routes.

- [ ] **Step 1: Add failing policy and header tests**

Assert the limit boundary returns `429` plus `Retry-After`. Assert API responses include HSTS in production, CSP, `X-Content-Type-Options`, `Referrer-Policy`, and frame restrictions.

- [ ] **Step 2: Implement Redis-backed fixed-window limits**

Keys include policy, tenant or unauthenticated client identity, and time bucket. Redis failure follows an explicit per-route fail-open/fail-closed table: authentication and API-key creation fail closed; observability reads fail open.

- [ ] **Step 3: Add FastAPI and Nginx headers**

Keep one header source authoritative per deployment layer and test the rendered production response through Nginx.

- [ ] **Step 4: Verify live boundaries**

Run focused tests, container smoke requests, and confirm all main services remain healthy.

### Task 6: Security release gate and evidence

**Files:**
- Create: `reports/security-governance-verification-2026-09-06.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Run the complete security/governance test set**

Run SSRF, permission matrix, tenant isolation, API keys, audit chain, rate limits, migrations, compileall, and dashboard build.

- [ ] **Step 2: Perform live negative checks**

Through Nginx, verify loopback URL rejection, cross-tenant denial, revoked API-key denial, rate limiting, audit verification, and redacted secret responses.

- [ ] **Step 3: Record evidence and residual risk**

The report records exact commands, exit codes, container versions, tested route count, test totals, and any environmental limitation. Update `CHANGELOG.md` with shipped behavior only.
