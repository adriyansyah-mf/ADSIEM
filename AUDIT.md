# SECURITY & CORRECTNESS AUDIT

**Date:** 2026-10-17
**Commit:** 8ac73e7
**Branch:** nightmare-c0de
**Auditor:** Sisyphus (read-only static analysis)
**Scope:** all services — `server-api`, `worker`, `agent`, `dashboard`, infra (`docker-compose*`, `nginx/`, `db/init.sql`, `.github/`)

---

## METHOD

Every finding below was confirmed by reading the cited file at the cited line. Findings are grouped by severity. Each carries **Evidence** (file:line + snippet), **Impact**, and **Fix**. Items that could not be verified against code were excluded. This is a static audit — no runtime exploitation was performed, so exploitability is reasoned from code, and some Critical items are confirmed *reachable* rather than *demonstrated*.

**Severity key:** `CRITICAL` = cross-tenant data exposure or auth bypass with no mitigating control · `HIGH` = privilege escalation, secret exposure, or guaranteed data-loss / worker death · `MEDIUM` = SSRF, DoS, correctness bug with real user impact · `LOW` = hygiene, hardening, docs drift.

---

## CRITICAL

### C-1. Cross-tenant data exposure via ID-addressed endpoints (missing group scoping)

Group isolation is the platform's core multi-tenancy guarantee (`AGENTS.md`, `README` RBAC section). It is enforced on *list* endpoints but **omitted on most single-resource endpoints**, so any authenticated user can read/modify/delete another group's objects by guessing or harvesting a UUID. UUIDv4 is not a sufficient access control (IDs leak through the assistant, search results, exports, and the WebSocket feed).

Confirmed instances (each returns/acts on the object with **no** `get_scoped_group()` check):

| # | Endpoint | Evidence |
|---|----------|----------|
| C-1a | `GET /api/agents/{agent_id}` | `server-api/app/api/routes/agents.py:139-148` — `select(Agent)...where(Agent.id == agent_id)`, no group filter |
| C-1b | `PUT /api/agents/{agent_id}` | `agents.py:150-166` — same; **write** to another group's agent |
| C-1c | `DELETE /api/agents/{agent_id}` | `agents.py:168-181` — **delete** another group's agent |
| C-1d | `GET/POST/PUT/DELETE /api/agents/{agent_id}/log-sources` | `agents.py:185-246` — all four lack an agent-group check |
| C-1e | `POST/DELETE /api/agents/{agent_id}/isolate` | `agents.py:248-275` — can **network-isolate** another group's host |
| C-1f | `PUT /api/cases/{case_id}` | `server-api/app/api/routes/cases.py:126-149` — no group filter on the `select` |
| C-1g | `POST /api/cases/{case_id}/escalate` | `cases.py:151-168` — same |
| C-1h | `POST /api/cases/{case_id}/notes` | `cases.py:170-184` — only checks existence, not group |
| C-1i | `DELETE /api/cases/{case_id}` | `cases.py:262-276` — **delete** another group's case |
| C-1j | `GET /api/cases/{case_id}/timeline` | `cases.py:217-345` — returns another group's alerts/notes; **also** `db: ... = None` default at `cases.py:219` |
| C-1k | `POST /api/cases/{case_id}/feedback` | `cases.py:227-259` — reads another group's case, writes feedback with its `group_id` |
| C-1l | `PUT /api/alerts/{alert_id}` | `server-api/app/api/routes/alerts.py:131-183` — no group filter; **status-change/assign** another group's alert |
| C-1m | `POST /api/alerts/{alert_id}/notes` | `alerts.py:185-197` — same |
| C-1n | `GET/POST /api/alerts/{alert_id}/feedback` | `alerts.py:199-238` — same |
| C-1o | `GET /api/hunts/{hunt_id}` | `server-api/app/api/routes/hunts.py:78-89` — `db.get(ThreatHunt, hunt_id)`, no filter |
| C-1p | `GET /api/fim/paths`, `POST`, `PATCH`, `DELETE /api/fim/paths/{id}` | `server-api/app/api/routes/fim.py:19-72` — all four unscoped (FIM paths are global config anyway, but the write path has no privilege gate either) |
| C-1q | `GET /api/hygiene/{agent_id}` and `/vulns` | `server-api/app/api/routes/hygiene.py:140-176` — no group filter (only `get_current_user`) |
| C-1r | `GET /api/ueba/*` | `server-api/app/api/routes/ueba.py:28-113` — every UEBA endpoint lacks `get_scoped_group`; entities are per-group |
| C-1s | `GET /api/tasks*`, `/api/fleet-hunts*` | `server-api/app/api/routes/tasks.py:24-186` — none scoped by group |
| C-1t | `PUT /api/webhooks/{id}`, `DELETE /api/webhooks/{id}` | `server-api/app/api/routes/webhooks.py:60-97` — list is scoped (`:25-26`), update/delete are not; **exfiltrate or redirect another group's webhook** (which may carry a secret URL) |
| C-1u | `PUT/DELETE /api/rules/{rule_id}` | `server-api/app/api/routes/rules.py:61-99` — list scoped (`:28`), mutations not |
| C-1v | `DELETE /api/suppressions/{id}` | `server-api/app/api/routes/suppressions.py:68-78` — list scoped (`:51`), delete not |
| C-1w | `PUT/DELETE /api/yara-rules/{rule_id}` | `server-api/app/api/routes/yara_rules.py:127-168` — unscoped |
| C-1x | `GET /api/audit-logs` | `server-api/app/api/routes/audit_logs.py:14-38` — no `get_scoped_group`; `AuditLog` has **no `group_id` column** (`services/audit.py:15-22`), so all groups' audit trail is visible to any authenticated user |
| C-1y | `DELETE /api/enrollment-tokens/{id}` | `server-api/app/api/routes/enrollment_tokens.py:70-83` — list scoped (`:29`), revoke not |

**Representative evidence — `agents.py:139-148`:**

```python
async def get_agent(
    agent_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],   # no get_scoped_group
):
    result = await db.execute(select(Agent).options(selectinload(Agent.log_sources)).where(Agent.id == agent_id))
```

**Impact:** Any authenticated user (role `viewer` and up) can read, modify, or delete any other group's agents, cases, alerts, hunts, webhooks, rules, YARA rules, suppressions, enrollment tokens, and the entire audit log — and can trigger live-response actions (`isolate`, `yara_scan`, `file_get`) on other groups' hosts. This defeats the product's stated multi-tenancy model completely. **C-1e is the worst:** remote network isolation of an arbitrary host across tenants.

**Fix:** Add `group_filter: Annotated[str | None, Depends(get_scoped_group)]` to every single-resource handler and apply the same `if group_filter and obj.group_id != group_filter: raise 404` guard that `cases.py:118-124` (`get_case`) and `alerts.py:104-114` (`get_alert`) already use correctly. Best done via a shared dependency/helper (e.g. `fetch_scoped(db, Model, id, group_filter)`). Also add `group_id` to `AuditLog` and scope `GET /api/audit-logs`.

---

### C-2. Worker: any single background loop's crash kills the entire worker

`worker/worker/main.py:141` gathers 15 loops with **no `return_exceptions=True`**, and several loops can raise out of their own `while True` body.

**Evidence — `main.py:141-158`:**

```python
    await asyncio.gather(
        _consume(), reload_loop(state), dlq_retry_loop(state), webhook_retry_loop(),
        ai_analysis_loop(), ai_backfill_loop(), ueba_snapshot_loop(), ueba_train_loop(),
        ueba_ai_loop(), hunt_loop(), agent_monitor_loop(), maintenance_loop(),
        report_loop(redis), hunt_scheduler_loop(), rag_index_loop(), sop_index_loop(),
        health_probe_loop(),
    )   # ← no return_exceptions=True
```

`_consume` (the wrapper at `main.py:135-137`) calls `consume_loop`, which *does* catch per-iteration (`consumer.py:147-151`) — so that one is safe. But the other loops rely on their own `try/except`; any loop whose `try` does not wrap the whole body, or that raises in its setup (e.g. a Redis/SQL error on the first `await`), propagates out of `gather`, cancelling **every** loop including ingest.

**Impact:** One flaky dependency (TI provider timeout, Redis blip, a bad rule during reload) takes the whole detection pipeline down — logs stop being consumed, alerts stop being generated, and the process exits. In prod this is a restart loop, not graceful degradation.

**Fix:** `await asyncio.gather(..., return_exceptions=True)` **and** wrap each loop's body in its own `try/except Exception: log.error(...); await asyncio.sleep(5)` supervisor, so a failing loop retries instead of dying. Optionally restart individual tasks via `asyncio.create_task` + a watchdog.

---

### C-3. Worker: unsafe `pickle.loads` on shared Redis data

**Evidence — `worker/worker/ueba/scorer.py:3,47-49`:**

```python
import pickle
...
    if user_b64:
        _user_model = pickle.loads(base64.b64decode(user_b64))   # arbitrary code execution
    if ip_b64:
        _ip_model = pickle.loads(base64.b64decode(ip_b64))
```

Models are written by the trainer at `worker/worker/ueba/trainer.py:105` (`pickle.dumps`) to `ueba:model:user` / `ueba:model:ip` in Redis. Any write access to Redis (a shared service on the `siem-net` Docker network, also used by server-api, and reachable by anything with the Redis URL) allows planting a malicious pickle that executes arbitrary code the moment the scorer loads it — inside the worker process, which holds DB credentials and can trigger SOAR actions (host isolation).

**Impact:** Redis compromise (or any container on the network, or a leaked `REDIS_URL`) → remote code execution inside the worker. Pickle is explicitly unsafe for data that crosses a trust boundary; Redis is not verified-authenticated-integrity storage here.

**Fix:** Replace pickle with a non-executable format (`joblib` with a safe backend is still pickle; prefer serializing model params as JSON/`numpy` arrays, or use `sklearn`'s `tree_` arrays), or at minimum sign the blob (HMAC with a key not stored in Redis) and verify before `pickle.loads`. Add Redis `requirepass` + bind to an internal-only network.

---

## HIGH

### H-1. CORS wildcard + credentials

**Evidence — `server-api/app/main.py:393-399`:**

```python
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])
```

**Impact:** The wildcard-with-credentials combination is rejected by browsers and signals the intent was "any origin". If a deployment ever replaces the wildcard with a reflected `Origin`, this becomes full credential-bearing cross-origin access. It also defeats any origin-based defence-in-depth for the JWT-in-header + refresh-cookie flow (`auth.py:55` sets `refresh_token` as an `httponly` cookie).

**Fix:** Replace `["*"]` with an explicit allow-list from config (e.g. `settings.CORS_ORIGINS`), and set `allow_credentials=False` unless cookies are genuinely needed cross-origin.

### H-2. Webhook SSRF — user-supplied URL is fetched with no validation

**Evidence:** `schemas.py:305` — `class WebhookCreate: url: str` (plain string, no `HttpUrl`, no host allow/deny). `webhook_sender.py:157-158` posts to `config.url` directly:

```python
async with httpx.AsyncClient(timeout=10.0) as client:
    resp = await client.post(config.url, json=post_payload)
```

No blocklist for link-local (`169.254.169.254` cloud metadata), loopback, or RFC1918 targets.

**Impact:** An `admin` (or, via C-1t, any tenant who can update another group's webhook) can point a webhook at internal-only services — cloud metadata endpoints, `postgres:5432`, `9router:20128`, `elasticsearch:9200` — turning alert delivery into an authenticated-ish SSRF probe/DoS against the internal network.

**Fix:** Validate `url` with `pydantic.HttpUrl`, resolve the host and reject private/loopback/link-local ranges (except an explicit allow-list), and re-check at delivery time (DNS-rebind). Add an egress proxy for webhook sends.

### H-3. Enrollment token is a single global static secret, compared non-constant-time, and re-enrollable

**Evidence — `agents.py:100-107`:**

```python
    if body.enrollment_token != settings.AGENT_ENROLLMENT_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid enrollment token")
```

and `config.py:13` defaults it to `"bootstrap-token"`. The existence of a dedicated `EnrollmentToken` model + routes (`enrollment_tokens.py`) shows per-token scoping was *intended*, but `enroll_agent` never consults it.

**Impact:** (a) Every agent host shares one token; leaking it from one host enrolls unlimited agents. (b) Default value ships if the env var is unset — a deployment that forgets it accepts `bootstrap-token`. (c) `!=` is not constant-time. (d) Re-enrollment **rotates the token for an existing hostname+group** (`agents.py:118-120`), so an attacker who knows a victim hostname can hijack its agent identity and receive its task dispatch. (e) The per-group `EnrollmentToken` rows are minted and never checked — dead, misleading code.

**Fix:** Use the `EnrollmentToken` table for enrollment (hash lookup, `is_active`, `expires_at`, `used_at`); remove the global-token branch or make it a fallback only when no tokens exist. Require `AGENT_ENROLLMENT_TOKEN` to be explicitly set (no insecure default — mirror the JWT_SECRET validator). Use `secrets.compare_digest`. Require an existing agent to present its current token to re-enroll.

### H-4. Agent token cannot be revoked/rotated independently; `get_agent` has no timing-safe compare

**Evidence — `deps.py:59-68`:** agent auth is `hash_token(token)` then a DB equality lookup. On de-enrollment the token is *overwritten* (`agents.py:119`) but the old token remains valid until overwritten, and `delete_agent` (`agents.py:173-181`) removes the row (good) — however there is no per-token revocation list, no expiry, and `hash_token` is a raw unsalted `sha256` (`security.py:17-18`).

**Impact:** Agent tokens are effectively permanent bearer credentials with no rotation, expiry, or audit; a leaked token is valid until the agent row is deleted. `sha256` without a salt is fine for high-entropy tokens but offers no defence if a low-entropy token is ever used.

**Fix:** Give agent tokens an `expires_at` and a revocation path; rotate on a schedule. Consider HMACing with a server-side pepper so a DB read alone doesn't yield offline-verifiable hashes.

### H-5. `POST /api/ingest/log` trusts fields, but is at least agent-authenticated — mixed; **webhook/notification secret exposure via settings**

**Evidence — `settings.py:25-38`:** `list_settings` returns all settings, masking only `is_secret` rows (`_mask` at `settings.py:12-17`). The mask is the literal string `"••••••••"`. `ninerouter_api_key` is seeded `is_secret=True` (`main.py:51`) — **good** — but `ninerouter_model`, `org_name`, etc. are not secret. The risk is `PUT /api/settings/{key}` (`settings.py:30-49`): **there is no `is_secret` check and no confirmation**, so any `settings:manage` holder can overwrite `ninerouter_api_key` to point the assistant at an attacker-controlled LLM (prompt/data exfiltration), and the response mask does not hide that the value changed.

**Impact:** A `settings:manage` user can silently redirect the AI assistant and the weekly report to an attacker endpoint, exfiltrating alert/case content fed into prompts (`services/assistant.py` sends alert/case data; `reports.py:96-110` sends aggregated data). Combined with the near-total absence of group scoping, the blast radius widens.

**Fix:** Treat secret settings specially (separate write path, require re-entry + audit, never echo). Add an allow-list of settable keys. Log actor+diff for every settings write.

---

## MEDIUM

### M-1. Audit log entries have no `group_id` (cross-tenant visibility, no tamper scoping)

**Evidence — `services/audit.py:15-22`** writes `AuditLog(actor_id, action, resource_type, resource_id, detail)` with no group; `db/init.sql`'s `audit_logs` likewise. `GET /api/audit-logs` (`audit_logs.py:14-38`) has no `get_scoped_group`.

**Impact:** Every authenticated user sees every group's audit trail; there is no way to answer "what happened in group X". Also means C-1x cannot be fixed without a schema change.

**Fix:** Add `group_id` to `AuditLog`, populate from the actor's group, scope the read endpoint.

### M-2. `GET /api/logs` bypasses tenant scoping entirely

**Evidence — `logs.py:14-52`:** unlike `events.py:18-22` (which applies `group_filter`), `list_logs` builds filters from `log_type`/`search`/`filter_tree` and **never** adds a group filter. Raw logs are stored in ES with a `group_id` field (`es_client.py:12`), so the data to scope on exists.

**Impact:** Any user with `logs:read` sees **raw log lines from every tenant** — including secrets that appear in logs (auth tokens, credentials). This is a straight data leak, distinct from the ID-addressed findings because it needs no guessing.

**Fix:** Add `group_filter` dependency and inject `{"term": {"group_id": group_filter}}` into `filters`, exactly as `events.py:19-20` does.

### M-3. Query-string (Lucene) passthrough enables ES abuse

**Evidence — `logs.py:27-28` and `events.py:31-33`:**

```python
        filters.append({"query_string": {"query": search, "default_field": "raw_message"}})
```

`search` is user input placed into a `query_string`, which supports wildcards, regex-ish patterns, and field access. `filter_tree` (`query_builder.py`) also lets the client name arbitrary fields for term/range/prefix queries.

**Impact:** A user can craft expensive wildcard/regex queries (ES search DoS), and — because `default_field` is overridable via `field:` syntax — probe index structure. Combined with M-2, cross-tenant search is confirmed.

**Fix:** Constrain `query_string` (cap length, ban leading wildcards, set `allow_leading_wildcard=false`), or replace with a structured filter DSL. Validate `filter_tree` fields against an allow-list in `query_builder._KEYWORD_FIELDS`.

### M-4. `query_string` default fields differ from the mapping; `decoded_fields.*` probing

**Evidence:** `events.py:32` uses `default_field: "decoded_fields.*"`. `query_builder._keyword_field` (see `query_builder.py:13-21`) assumes a `.keyword` sub-field for `decoded_fields.*`.

**Impact:** Silent zero-result searches (queries that "should" match don't), and analysts lose trust in the tool. Not a security bug but a correctness one with real operational cost.

**Fix:** Add an integration test that ingests a known event and asserts a decoded-field search returns it; align the field mapping.

### M-5. `httpx` clients created per-request / per-job (connection-pool churn)

**Evidence:** `hygiene.py:59` (`async with httpx.AsyncClient(...)`), `webhook_sender.py:157`, `metrics.py:150` (`quick_ti_lookup` opens a client per call), `handover`/`reports` similar. Contrast `es_client.py:33-38` which correctly memoizes a global client.

**Impact:** Under load, TLS handshakes and socket churn per webhook/TI/OSV call add latency and can exhaust file descriptors; also slows alert delivery (webhook retry loop).

**Fix:** Module-level shared `AsyncClient` (or app-lifespan client) reused everywhere; the pattern already exists in `es_client.py` — copy it.

### M-6. Worker `reload_loop` / `health_probe_loop` have unbounded-error surfaces

**Evidence — `main.py:78-114`:** `health_probe_loop`'s `try` blocks catch, but the loop's first `await get_redis()` is *outside* any try; `reload_loop` (`consumer.py:178-189`) catches inside `while True` but its guard depends on `AsyncSessionLocal` being importable and a DB response. If `get_redis()` raises on the very first call, the exception escapes `main`'s gather (see C-2).

**Impact:** Same class as C-2 — amplified because these loops are the ones most likely to hit a transient dependency failure at boot.

**Fix:** Superset of C-2's fix (supervisor wrapper). Additionally move every setup `await` inside the loop's `try`.

### M-7. `dashboard` has zero test runner; build is the only gate; `dist/` committed

**Evidence:** `dashboard/package.json:8-12` — scripts are `dev`, `build` (`tsc -b && vite build`), `preview`; **no `test`**. `dashboard/dist/` is committed (build artifacts tracked per `AGENTS.md` NOTES).

**Impact:** UI regressions (broken routes, auth redirects) are uncaught until manual QA; the committed `dist/` can mask source changes (a stale bundle makes bugs look non-existent).

**Fix:** Add Vitest + Testing Library for hooks/components; add a CI job running `tsc -b` (already) plus unit tests; stop committing `dist/`.

### M-8. No CI runs the Python/dashboard test suites

**Evidence:** `.github/workflows/agent-release.yml` is the only workflow (tags `agent-v*`, builds `.deb`/`.rpm`/binary). Nothing runs `pytest`, `go test ./...` (agent), or the dashboard build on PR/push.

**Impact:** The repo's own tests (`pytest.ini` importlib mode is load-bearing; dashboard build is the only gate) are effectively advisory. Regressions in server-api/worker merge silently.

**Fix:** Add a `ci.yml` running `pytest`, `cd tests/agent && go test ./...`, and `cd dashboard && npm run build` on push/PR.

### M-9. `db: Annotated[AsyncSession, Depends(get_db)] = None` hides a real bug

**Evidence — `cases.py:219`:** `db: ... = None` on `case_timeline`. FastAPI will still inject it (the default is ignored for `Depends`), so this happens to work — but the `None` default is a latent trap: any refactor to a non-injected call, or a linter/type-checker, sees `Optional[AsyncSession]`.

**Impact:** No runtime bug today; a type-safety landmine and a signal the endpoint was not reviewed. The same pattern appears in `search.py:19` (`db: ... = None`).

**Fix:** Remove the `= None` defaults; let `Depends` be required.

---

## LOW

### L-1. Docs drift — architecture described incorrectly

**Evidence:**
- `docs/PROJECT_OVERVIEW.md` and `prompt.md:679` describe `server-api → NATS → worker`; the real queue is **Redis Streams** (`ingest.py` → `enqueue_log`, `consumer.py` `XREADGROUP`).
- `docs/PROJECT_OVERVIEW.md` says agent is **Go 1.22**; `agent/go.mod` says `go 1.25.0`, `go.work` says `1.26.1`.
- `docs/PROJECT_OVERVIEW.md` lists `GROQ_API_KEY` as a main env var; `.env.example` has none — the LLM path is `NINEROUTER_*` (`9router`). `agentic-soc-gaps.md` still says "weekly report via Groq".

**Impact:** New contributors (and AI agents) are misled about the data flow and stack.

**Fix:** Reconcile both docs, or mark them historical.

### L-2. README Roadmap is stale

**Evidence:** `README.md:506-514` lists 8 unchecked items; 2 are shipped (WebSocket feed exists at `ws.py`; email via `email_sender.py`), 1 partially (Prometheus exists, Grafana doesn't).

**Fix:** Tick the shipped items.

### L-3. `nginx.conf` dev sets HSTS on plain HTTP

**Evidence — `nginx/nginx.conf:28`:** `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;` on the `listen 80` dev server (`nginx.prod.conf:36` sets it correctly on the TLS server).

**Impact:** Browsers cache HSTS for a host served over HTTP in dev; can wedge local access after a dev/prod mix-up.

**Fix:** Only set HSTS on the TLS server (`nginx.prod.conf`).

### L-4. Container images not pinned by digest; `9router`, `searxng` use `latest`

**Evidence:** `docker-compose.yml:56` — `image: decolua/9router:latest`, plus floating tags for redis/nginx etc.

**Impact:** Non-reproducible builds; a compromised upstream tag executes in the SIEM network.

**Fix:** Pin digests for third-party images.

### L-5. Committed build artifacts inflate the repo

**Evidence:** `agent/bin/agent` (~9.8 MB), `siem-agent_1.0.0_amd64.deb` (~5 MB at repo root), `dashboard/dist/` (1 MB JS bundle), `agent/internal/procexec/bpf/include/bpf/vmlinux.h` (2.8 MB).

**Impact:** Bloated clones; stale binaries shipped by accident (the `.deb` at root is a real risk — it looks installable and is 3 versions behind the tag flow).

**Fix:** Gitignore binaries + `dist/`; publish artifacts via releases/registry. Keep `vmlinux.h` only if the build genuinely needs it (document why).

### L-6. `AGENT_ENROLLMENT_TOKEN` default in config

**Evidence — `config.py:13`:** `AGENT_ENROLLMENT_TOKEN: str = "bootstrap-token"`, unlike `JWT_SECRET` which is validated non-default (`config.py:24-35`).

**Impact:** Security posture is inconsistent: the JWT secret is forced strong, the agent enrollment secret silently falls back to a public value.

**Fix:** Apply the same validator pattern (no default; reject known-insecure values).

### L-7. `except Exception: pass` on non-critical but silent paths

**Evidence:** `cases.py:28-32` and `:38-42` (`_push_rag_reindex`, `_push_feedback_reindex`), `hygiene.py:105-106` (`_query_osv`), `metrics.py:161-162` (`quick_ti_lookup`), `ws.py` broadcast disconnect list.

**Impact:** Intentional for the "best-effort" design, but there is no log line, so a permanently broken reindex queue / OSV lookup is invisible. The comment "hourly loop will catch it" is only true for cases, not feedback/OSV.

**Fix:** Add a `log.warning(...)` before `pass` (structlog is already a dependency) so silent degradation is observable.

---

## POSITIVES (verified, do not regress)

- **JWT secret is validated** against insecure defaults and a 32-char minimum — `config.py:22-35`. Good pattern; replication recommended (L-6).
- **JWT algorithm is pinned** (`algorithms=[settings.JWT_ALGORITHM]`, `security.py:34`) — no `alg=none` / algorithm-confusion.
- **Password hashing is argon2** (`security.py:11`), and the seed admin hash is argon2id (`db/init.sql:305`).
- **Rate limiting is applied** to auth endpoints (`auth.py:26,60`) and the limiter is registered (`main.py:390`), with a real-IP key function that honours `X-Forwarded-For` (`limiter.py`).
- **Path traversal is blocked** on package download — explicit `/`, `\`, `..` rejection before `PACKAGES_DIR / filename` (`agents.py:60-63`).
- **The AI assistant is genuinely read-only in code**, not just by prompt: `assistant.py`'s tool loop can only call `run_tool` over `TOOLS` in `assistant_tools.py`, which imports no settings/users/webhooks modules (`assistant.py:1-7`, `assistant_tools.py:1-3`). The prompt-only guarantee is backed by an import-level guarantee.
- **Secret settings are masked on read** (`settings.py:12-17`) and `ninerouter_api_key` is seeded `is_secret=True` (`main.py:51`).
- **ES pagination uses `search_after` + `_seq_no` tiebreaker**, avoiding the 10k window and unstable cursors (`es_client.py:60-90`).
- **Migration lock** prevents concurrent replica DDL deadlocks (`main.py:355-381`).
- **Agent buffer is mutex-protected** with drop-oldest backpressure and counters (`agent/internal/buffer/buffer.go`).
- **Agent never points at `http://`** — the Go client downgrades POST→GET on 301, and the README/AGENTS.md both call this out (`README` troubleshooting; verified contract).
- **Seeding is idempotent** and replica-race safe (per-item SAVEPOINT) — `seeder.py`.

---

## SUMMARY

| Severity | Count | Headline |
|----------|-------|----------|
| CRITICAL | 3 | Cross-tenant exposure (26 endpoints) · worker death on one loop failure · pickle RCE via Redis |
| HIGH | 5 | CORS wildcard+credentials · webhook SSRF · global static enrollment token · agent token lifecycle · secret-setting overwrite |
| MEDIUM | 9 | unscoped raw logs · Lucene abuse · audit-log cross-tenant · pool churn · no CI/tests · schema drift |
| LOW | 7 | docs drift · stale roadmap · dev HSTS · unpinned images · committed binaries · insecure default · silent excepts |

**Top 3 to fix first:** C-1 (add the group guard to every single-resource handler — highest impact, mechanical fix), C-2 (`return_exceptions=True` + per-loop supervisor), C-3 (drop pickle).

**Caveat:** this is a static read of commit `8ac73e7`. No exploit was executed. Severity is reasoned from code reachability; confirm each with a dynamic PoC before treating as final for disclosure purposes.
