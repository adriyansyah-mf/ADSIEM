# Web Protection (Stage B3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Fill the Web Protection blocklist automatically from URLhaus and PhishTank and from malicious domain/URL indicators of alerts, with the dashboard switches to control it — without agents ever missing an entry and without overloading endpoints.

**Architecture:** Two worker loops (feeds, like `worker/worker/malware_feed.py`) and one triage hook (alert auto-block) write `web_block_entries` through one helper that takes a transaction-level advisory lock, so seqs commit in order; the agent sync (`delta`) takes the same lock in shared mode. TI enrichment gains structured per-indicator reputation. The dashboard exposes the per-group switches and feed status. Agents skip `www.` lines for feed entries and jitter their syncs.

**Tech Stack:** Python 3.12 async (worker + FastAPI), PostgreSQL advisory locks, httpx, Redis, React + TS, Go (agent).

**Spec:** `docs/superpowers/specs/2026-11-07-threat-iocs-web-protection-design.md` section B3 (incl. its "seq commit order" prerequisite) and the B1 contract.

## Global Constraints

- Every write that assigns `web_block_seq` (entries, policies, allowlist marker) runs inside a transaction that first takes `pg_advisory_xact_lock(WEB_BLOCK_SEQ_LOCK)`; `delta()` takes `pg_advisory_xact_lock_shared(WEB_BLOCK_SEQ_LOCK)` before reading. `WEB_BLOCK_SEQ_LOCK = 0x5745424C4B` (a constant in `worker/worker/web_domains.py`, imported by server-api and worker). The heartbeat version stays lock-free and read-only.
- Bulk writers commit in batches of ≤ 1000 rows, taking the lock per batch.
- Feeds write global rows (`group_id = '*'`, `source` `urlhaus` / `phishtank`); groups receive them only when their policy has `feed_enabled` (already enforced by `delta`). Feed hosts that are IP literals or match an enabled global (`*`) allowlist rule are stored with `status = 'suppressed'` and the rule as `reason`.
- Domains always go through `worker.web_domains.normalize`.
- Feed keys: `abusech_auth_key` (fallback `malwarebazaar_api_key`) for URLhaus; `phishtank_app_key` for PhishTank. Missing key → that feed is skipped with status `missing_key`. Intervals: URLhaus 30 min, PhishTank 60 min. Entries not seen in a feed for 24 h → `removed`.
- Feed state in Redis `siem:webblock_feed:<name>` (JSON: status, last_success, last_attempt, entries, suppressed, removed, error).
- Alert auto-block (all must hold): group policy `enabled` and `alert_enabled`; alert family in `case_grouping.OUTBOUND_FAMILIES`; the indicator is malicious by TI (URLhaus listed, or VirusTotal malicious ≥ 3) or the AI verdict is `escalate`/`create_case`; not allowlisted for the group; the alert is not itself a `web_block` event (decoded field `event.action == "web_block"` or log type `web_block`). Entry `source = 'alert'`, `alert_id`, `expires_at = now + alert_block_days`; an alert note records it.
- Agent (Linux and Windows identical): feed-sourced entries render only the domain line (no `www.`); after a version change the sync starts after a random 0–60 s delay (first sync after start and `""`→enabled transitions are immediate).
- Group scoping, `alerts:read` / `agents:manage` / `settings:manage` as in B1; CI pins pytest-asyncio 0.24; worker and server tests run in separate processes.
- Commit trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

### Test commands

```bash
docker run -d --rm --name adsiem-testpg-sdd -e POSTGRES_USER=soc -e POSTGRES_PASSWORD=soc -e POSTGRES_DB=test -p 55433:5432 pgvector/pgvector:pg16
export JWT_SECRET=ci-test-secret-0123456789abcdef0123456789abcdef TEST_DATABASE_URL=postgresql+asyncpg://soc:soc@localhost:55433/test DATABASE_URL=postgresql+asyncpg://soc:soc@localhost:55433/test
PY=/tmp/adsiem-ci-venv/bin/python
$PY -m pytest tests/server-api tests/evidence -q -p no:cacheprovider
$PY -m pytest tests/worker worker/tests -q --ignore=tests/worker/test_pipeline.int.test.py --deselect worker/tests/test_rag.py::test_embed_text_returns_384_dimensions --deselect worker/tests/test_rag.py::test_embed_text_different_inputs_differ
cd agent && go test ./internal/webblock/... -race && GOOS=windows go vet ./internal/webblock/...
cd dashboard && npx tsc --noEmit -p . && npx vite build
```

---

### Task 1: Ordered seq commits (advisory lock)

**Files:** `worker/worker/web_domains.py` (constant), `server-api/app/services/web_blocks.py` (helper + delta shared lock), `server-api/app/api/routes/web_protection.py` (every seq-assigning write path), tests `tests/server-api/test_web_blocks.int.py`.

- Add `WEB_BLOCK_SEQ_LOCK` to `web_domains.py`.
- `web_blocks.lock_seq_writes(db)`: `SELECT pg_advisory_xact_lock(:k)`; call it at the start of every transaction that assigns `next_seq()` or calls `mark_rules_changed` — `expire()`, add/remove block (single + bulk), allowlist add/update/delete, policy PUT, feed-allowlist on unblock, seeding. `delta()` runs `SELECT pg_advisory_xact_lock_shared(:k)` before computing `top`/rows (it already commits after `expire()`; take the shared lock after that commit).
- Test (the race the lock prevents): with two sessions, session A takes the write lock and inserts an entry (seq N) without committing; a `delta()` in session B started concurrently must not return a seq ≥ N until A commits — run B's delta in a task, assert it is still pending after 0.3 s, commit A, then assert B's result includes the entry. Plus: existing delta tests still pass.

Commit: `fix(webblock): commit seqs in order with an advisory lock`.

### Task 2: URLhaus and PhishTank feeds (worker)

**Files:** create `worker/worker/webblock_feeds.py`; modify `worker/worker/main.py` (loop in the gather); tests `tests/worker/test_webblock_feeds.py` (parsers, pure) and `tests/worker/test_webblock_feeds.int.py` (DB upserts, expiry; schema-per-test fixture like `tests/worker/test_alert_iocs_backfill.int.py`).

- Read `worker/worker/malware_feed.py` and copy its structure (loop interval, `_due`, Redis state key, `get_setting`, httpx client, error handling).
- URLhaus: `GET https://urlhaus.abuse.ch/downloads/csv_online/` with header `Auth-Key: <key>`; CSV with `#` comment lines; columns `id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter`. Keep `url_status == online`. Reason `URLhaus: <threat>` (+ first tag), `sample_url` = url.
- PhishTank: `GET https://data.phishtank.com/data/<key>/online-valid.json` (User-Agent `phishtank/adsiem`), JSON list with `url`, `verified`, `online`, `target`. Keep `verified == "yes"` and `online == "yes"`. Reason `PhishTank: phishing (<target>)`.
- Per feed run: normalize each URL host (`DomainError` → skip, counted), dedupe by domain, check the global allowlist (`web_allowlist` rows with `group_id='*'` and `enabled`), then upsert in batches of 1000 inside `lock_seq_writes`: `INSERT … ON CONFLICT (group_id, domain, source) DO UPDATE SET last_seen_in_feed = now(), reason = EXCLUDED.reason, sample_url = EXCLUDED.sample_url, status = EXCLUDED.status, seq = <next>, updated_at = now()` — but only bump `seq` (and `updated_at`) when `status`/`reason` actually changed (use `WHERE web_block_entries.status IS DISTINCT FROM EXCLUDED.status OR web_block_entries.reason IS DISTINCT FROM EXCLUDED.reason`, and a second statement that only touches `last_seen_in_feed` for unchanged rows) so an unchanged feed does not make every agent resync. Then mark rows of that source with `last_seen_in_feed < now() - 24h` and `status = 'active'` as `removed` (seq bump, locked).
- The worker writes with SQL (`text()`), using the same lock constant; no ORM model duplication needed.
- Guard: at most 200 000 URLs parsed per run; response size limit 200 MB; timeout 120 s.
- Tests: parser fixtures (CSV with comments and offline rows; JSON with unverified/offline rows; IP-host URLs skipped; IDN host); DB: first run inserts active rows + suppressed for an allowlisted host; second identical run bumps no seq; a row absent for > 24 h is removed with a new seq; missing key → state `missing_key`, nothing written.

Commit: `feat(webblock): URLhaus and PhishTank feeds`.

### Task 3: Structured TI reputation and alert auto-block (worker)

**Files:** `worker/worker/ti/models.py` (`IOCReputationScore.sources: list[str] = []`, `malicious: bool = False`), `worker/worker/ti/aggregator.py` (fill `reputation` for domains/URLs: URLhaus listed → `sources += ["urlhaus"]`, `malicious = True`; VirusTotal `malicious ≥ 3` → `sources += ["virustotal"]`, `malicious = True`; keep existing bullets), create `worker/worker/webblock_auto.py`, hook in `worker/worker/graph/triage_graph.py` / `worker/worker/ai_analyst.py` deps (after the alert's IoCs are known in triage), tests `tests/worker/test_webblock_auto.py` (+ `.int.py` for the DB write).

- `webblock_auto.maybe_block(alert_id, group_id, family, verdict, decoded_fields, enrichment, iocs)` implements the Global Constraints conditions exactly; candidate domains = normalized hosts of the alert's domain and URL indicators (reuse `alert_iocs.collect` output types `domain`/`url`); TI malicious = an enrichment reputation entry for that domain or URL with `malicious = True`.
- Write: inside `lock_seq_writes`, upsert `(group_id, domain, 'alert')` → `status='active'`, `alert_id`, `reason = "Alert: <title> (<evidence>)"`, `expires_at = now + alert_block_days` (extend if already active), seq bump; then an alert note `Web Protection: blocked <domains> for group <g> until <date>`.
- Never raises into triage (log and continue).
- Tests: the full condition matrix (each failing condition → nothing written), allowlisted domain skipped, `web_block` event alert skipped, extension of an existing block, aggregator reputation for URLhaus-listed domain and VT malicious=5 vs 2.

Commit: `feat(webblock): structured TI reputation and alert auto-block`.

### Task 4: Feed status, settings and policy switches (server + dashboard)

**Files:** `server-api/app/api/routes/web_protection.py` (`GET /api/web-blocks/feeds` → `{"feeds":[{name, enabled_key_present, status, last_success, last_attempt, entries, suppressed, removed, error}]}` from Redis + setting presence, `alerts:read`; `POST /api/web-blocks/feeds/{name}/sync` (`settings:manage`) pushes to a Redis list `siem:webblock_feed:sync` that the worker loop checks), `server-api/app/main.py` `_seed_settings` (register `abusech_auth_key`, `phishtank_app_key` as secrets if the seeding pattern lists known keys), dashboard hook + "Feeds" tab (status per feed, last sync, counts, error, "Sync now", link to Settings for keys) and the Blocklist tab policy panel (switches `feed_enabled`, `alert_enabled`; number inputs `alert_block_days` 1–365, `max_entries` 100–200000; save through the existing policy PUT keeping `page_html`), tests for both routes.

Commit: `feat(webblock): feed status and per-group feed/auto-block switches`.

### Task 5: Agent: lighter hosts for feed entries and sync jitter

**Files:** `agent/internal/webblock/hosts.go` / `controller.go` (pass per-domain source to the renderer so feed-sourced domains get no `www.` line), `agent/internal/webblock/store.go` (jitter), tests.

- `Selected()` already orders by source; extend the hosts render input to `[]Selected{Domain, Source}` (or a set of feed domains) so `www.` is added only for `manual` and `alert`.
- Jitter: when `Want(v)` changes the wanted version and the store already has an active list with the same group prefix, the next `Sync` starts after `rand(0..60s)` (injectable for tests); first sync after start, `""`→non-empty, and group changes are immediate.
- Tests: feed domain renders one line, manual renders two; jitter applied/not applied per rule (fake clock/delay func).

Commit: `feat(webblock): no www. lines for feed entries; jitter fleet syncs`.

## Final verification
All commands in "Test commands"; then push and let CI run the Linux/Windows e2e.
