# Task 1 Code Review — Central outbound URL policy

## Verdict

- **Spec compliance:** COMPLIANT (after fix round 1)
- **codeQualityStatus:** CLEAR
- **recommendation:** APPROVE
- **Task quality:** Approved

## Re-review — fix round 1 (supersedes the initial findings below)

All prior blockers were re-checked against the current Task 1 files, current report, durable live evidence, and a live rebuilt container.

| Prior blocker | Re-review result |
| --- | --- |
| Tenant scope/group override | **Resolved.** Non-superadmin creates overwrite caller-supplied `group_id` with `group_filter` (`webhooks.py:46-49`); updates query by `id` and scoped `group_id`, reject a mismatch, and overwrite attempted reassignment (`:65-81`). Focused create/cross-tenant-update/reassignment tests cover the routes. |
| Actual DNS connection pinning | **Resolved.** The HTTPX transport delegates TCP only to `ValidatedOutboundUrl.resolved_addresses` (`outbound_url.py:32-69`) while the httpcore connection retains the validated hostname for TLS/SNI. `fetch_repository_content` uses that transport with `trust_env=False` (`rules.py:43-52`). The focused backend test proves an IP, not the hostname, is dialed; the live container successfully fetched an allowlisted raw GitHub file through this path. |
| URL query secrets | **Resolved.** Query-bearing URLs reject before normalization/persistence (`outbound_url.py:148-149`), and the rejection test covers `?token=...`. Credentials remain rejected. |
| Effective 2 MB response limit | **Resolved.** The repository request streams with a pre-check of `Content-Length` and an incremental byte cap (`rules.py:52-62`); a focused oversized-stream test verifies HTTP 413. |
| Route tests | **Resolved.** The focused suite now covers create tenant override, cross-tenant update rejection, reassignment prevention, pinning, and the streaming cap. |
| Ruff | **Resolved.** Current scoped Ruff run passed. |
| Durable evidence | **Resolved.** [`task-1-live-container-fix-round-1.md`](/home/wonka/Documents/ADSIEM/.omo/evidence/task-1-live-container-fix-round-1.md) exists and records a rebuilt-container allowlisted pinned fetch plus negative cases. |

Independent re-review verification:

- `ruff check server-api/app/core/outbound_url.py server-api/app/api/routes/rules.py server-api/app/api/routes/webhooks.py tests/server-api/test_outbound_url_policy.py` — **passed**.
- `python -m compileall -q` for the Task 1 Python files — **passed**.
- Host `python -m pytest` could not collect because this environment lacks the application dependency `asyncpg`; this is not a Task 1 test failure.
- `docker compose run --rm --no-deps -v "$PWD/tests:/tests:ro" server-api python -m pytest -q -p no:cacheprovider /tests/server-api/test_outbound_url_policy.py` — **17 passed** (two pre-existing pytest/passlib deprecation warnings).
- In the healthy current `server-api` container, `fetch_repository_content` successfully retrieved the allowlisted raw GitHub README through the pinned transport, and public-allowlisted/HTTPS-private/query-token smoke checks passed.

The `remove-ai-slops` and `programming` perspectives were re-applied. The revised tests are behavior-oriented rather than prose/deletion/tautological tests; the custom transport is a necessary security seam, not needless abstraction. No residual Task 1 finding remains.

## Scope and evidence inspected

The review is bounded to the Task 1 package: `server-api/app/core/outbound_url.py`, the Task 1 integration paths in `server-api/app/api/routes/rules.py` and `server-api/app/api/routes/webhooks.py`, `tests/server-api/test_outbound_url_policy.py`, and the Task 1 CHANGELOG entry. The brief, implementer report, and review package were read first. `omo ulw-loop status --json` reported `ULW_LOOP_PLAN_MISSING`, so this fallback evidence location is used.

Independent checks against the current worktree:

- `python -m pytest -q tests/server-api/test_outbound_url_policy.py` — **9 passed**.
- `python -m compileall -q` for the four Task 1 Python files — **passed**.
- `ruff check` for all four Task 1 Python files — **failed** with `F401` and `F811` in `server-api/app/api/routes/webhooks.py:9,11`.
- Current `server-api` container smoke — **passed**: allowlisted `https://github.com/` passed; HTTPS loopback, metadata, RFC1918, and IPv6 loopback URLs raised `OutboundUrlRejected`.

The executor’s report names no persistent path for its claimed live-container evidence. A scoped evidence search found no Task 1 outbound-policy artifact before this review artifact. Its success claim is therefore not independently auditable from executor-produced evidence.

## Skill-perspective check

The required `remove-ai-slops` and `programming` skill perspectives were loaded and applied. The Python reference was also consulted, including the network/HTTP guidance.

- **remove-ai-slops:** No deletion-only or prompt/prose tests, tautological assertion, needless helper, or needless data extraction/parsing was found. The central validator and immutable result type are justified seams. The test suite is nevertheless weak for the security behavior it purports to cover; see MEDIUM findings.
- **programming:** The new value and error types are frozen, slotted, and typed; no production `Any`, casts, or broad exception catch was added. The brief expressly requires `asyncio.get_running_loop().getaddrinfo`, so the skill’s general AnyIO preference is not treated as a violation. Existing `httpx` is project-pinned and the task requires redirects disabled, so the reference’s general client factory does not override the task’s SSRF constraint. The diff violates the perspective on test relevance (insufficient observable integration coverage), not on unnecessary abstraction or production parsing.

## Initial-review findings (superseded by the fix-round-1 results above)

### CRITICAL

1. **Tenant isolation is bypassed for both Task 1 webhook write paths.** `create_webhook` preserves any caller-supplied `group_id` and only fills it when absent (`server-api/app/api/routes/webhooks.py:41-47`). A non-superadmin can therefore create a webhook in another tenant. `update_webhook` loads by ID with no `get_scoped_group` dependency or `WebhookConfig.group_id` predicate (`server-api/app/api/routes/webhooks.py:55-73`), allowing a user who knows another tenant’s UUID to modify its URL or move it by changing `group_id`. `get_scoped_group` returns the caller’s group for non-superadmins (`server-api/app/core/deps.py:51-54`), proving the intended model. This violates the explicit tenant-scope constraint.

### HIGH

1. **DNS rebinding remains exploitable.** The validator resolves and validates `host` at `server-api/app/core/outbound_url.py:52-68`, then the repository importer gives the hostname URL to a fresh HTTPX request at `server-api/app/api/routes/rules.py:229-230`. HTTPX resolves the hostname again to connect, so an attacker-controlled DNS answer can be public during validation and private/metadata at connect time. `ValidatedOutboundUrl.resolved_addresses` is never used to constrain the socket destination. This fails the explicit rebinding-destination requirement.

2. **Webhook query-string secrets are persisted and returned verbatim.** The validator preserves the full query string (`server-api/app/core/outbound_url.py:72-74`), and create/update return a schema that exposes `url` (`server-api/app/api/routes/webhooks.py:43,53,69,77`; `server-api/app/schemas/schemas.py:371-379`). `https://hooks.example/endpoint?token=...` is allowed and its token enters API responses, violating the stated rule that secrets never enter responses. Reject/segregate sensitive URL material and return only a redacted representation.

3. **The asserted 2 MB repository limit is post-buffering, not an actual download limit.** `AsyncClient.get()` buffers the response before `response.content` is inspected (`server-api/app/api/routes/rules.py:230-233`). A hostile allowed host can make the service allocate an arbitrarily large response, so the route does not retain an effective response-size protection. Stream the response and stop before the limit is exceeded (with a `Content-Length` pre-check where useful).

4. **The executor’s claimed live verification has no artifact path.** The report only contains pasted output and mentions no saved evidence artifact; no Task 1 evidence file was found. This is a required blocker under the review contract, despite the reviewer’s separate current-container smoke above.

### MEDIUM

1. **The primary address-class test does not test address policy.** Every parameter in `test_rejects_non_public_destinations` is `http://` (`tests/server-api/test_outbound_url_policy.py:10-18`), so each passes solely because line 41 rejects non-HTTPS URLs before DNS/IP classification. Regressing HTTPS loopback, link-local/metadata, RFC1918, IPv6, or multicast handling would not fail this test. Use HTTPS URLs for the direct-address cases and assert the rejection reason/class; include multicast and a rebind-safe connection-path test.

2. **There is no route-level test for the Task 1 integrations.** Searches in the declared test scope found only unit tests for `validate_outbound_url`; none exercise `import_sigma_repository`, `create_webhook`, or `update_webhook`. Consequently the suite cannot prove that the HTTP client uses only a validator-constrained destination, that a rejected URL is never persisted/fetched, or that tenant predicates are applied. This is false-confidence coverage rather than adequate regression protection.

3. **The modified webhook module fails its scoped lint gate.** `ruff check` reports an unused `get_current_user` import at `server-api/app/api/routes/webhooks.py:9` and a duplicate `Annotated` import at `:11`. The executor calls these pre-existing, but the Task 1 report is untrusted and no baseline artifact establishes that. At minimum, the task cannot claim a clean all-changed-files lint result.

### LOW

None beyond the findings above.

## Strengths

- The validator correctly requires HTTPS, rejects credentials/missing hosts/prohibited ports, canonicalizes the validated URL, and rejects every resolved address that is not `ipaddress.is_global`.
- Repository imports apply a narrow GitHub/GitLab/raw GitHub allowlist, disable redirects, and use explicit timeout components.
- The response errors are stable and do not echo the submitted URL; the new policy data and error types are immutable and typed.
- The Task 1 CHANGELOG entry is present.

## Initial blockers (resolved in fix round 1)

1. Enforce tenant scope and prevent non-superadmin caller-controlled `group_id` in the Task 1 webhook create/update paths; add authorization regression tests.
2. Bind outbound connections to the validated address set (or revalidate the actual peer immediately before/use of connection) so a DNS rebind cannot change the destination; prove it with a focused regression.
3. Prevent URL-borne secrets, including query tokens, from being returned or otherwise disclosed, and add coverage.
4. Enforce repository payload size while streaming, before unbounded buffering.
5. Provide an executor-produced live-container evidence artifact path and correct the scoped lint failures or establish an auditable pre-task baseline.
