# Agent evidence implementation evidence

Implementation worktree: `.claude/worktrees/next-phase-roadmap`, branch
`feat/enterprise-ui`. Durable mode is not wired into production or released.

## 2026-10-22: resumed publisher verification

The previous session stopped during Task 4. The persisted publisher and bridge
implementation was recovered and tested on Linux. Tasks 1-3 retain the review
status recorded in the implementation plan; this is not a native Windows gate.

| Command | Result |
| --- | --- |
| `go test ./agent/internal/evidence ./agent/internal/buffer ./agent/internal/detect -count=1` | Passed |
| `go test -race -shuffle=on ./agent/internal/evidence ./agent/internal/buffer ./agent/internal/detect -count=1` | Passed |
| `go vet ./agent/internal/evidence ./agent/internal/buffer ./agent/internal/detect` | Passed |
| `make -C agent bpf` | Passed; objects already current |
| `go test ./agent/... ./tests/agent/... -count=1` | Passed |
| `GOOS=windows GOARCH=<arch> CGO_ENABLED=0 go test -c ./agent/internal/<package> -o <temporary artifact>` for amd64, 386, arm64 and evidence, buffer | All six cross-builds passed |

Publisher tests exercise admission blocked at fsync, cursor preservation after
failed admission, bounded overload while disk is blocked, reentrant detection,
loss persistence and failed persistence, and joining work across shutdown
deadlines. Cross-builds do not execute these scenarios on Windows.

Task 4 independent spec and code-quality reviews passed, recorded under
`.omo/evidence/task4-publisher-review/` and
`.omo/evidence/task4-publisher-quality/`. The resumed session did not recover the
original red test execution, so the plan retains that unchecked evidence item.
Tasks 5-12 remain pending; backend receipts,
production wiring, collector resume, health UI, migration, and full acceptance
are not represented as complete by the passing library tests.

The graph generation `2026-10-17T18:29:47Z` excludes this worktree. Source reads
were used after `check_index_coverage` reported the `.claude` exclusion.

## Task 5 implementation in progress

Testing uses a task-owned disposable PostgreSQL container and random isolated
schemas. The container's `fsync`, `full_page_writes`, and `synchronous_commit`
settings were checked and are `on`. Existing application databases are outside
this test scope.

The shared envelope fixture contains NUL in its raw message. PostgreSQL JSONB
cannot directly represent that character. The planned storage representation is
a JSONB scalar string containing canonical envelope JSON; decoding that string
with `json.loads` recovers the complete envelope, including NUL. The HTTP
envelope remains unchanged. The worker must use this same representation in
Task 6. Capacity accounting must include the outer JSON string encoding;
the independent event-size limit remains compatible with Go's JSON encoding.
See [PostgreSQL 16 JSON types](https://www.postgresql.org/docs/16/datatype-json.html)
for its NUL restriction. The implementation and PostgreSQL roundtrip tests pass.

Task 5 verification results:

| Scope | Result and artifact |
| --- | --- |
| Initial protocol tests before schema implementation | 23 failed, `.omo/evidence/task5-inbox/protocol-red.txt` |
| Initial inbox tests before model implementation | 22 fixture errors, `.omo/evidence/task5-inbox/inbox-red.txt` |
| Extended protocol/PostgreSQL/HTTP tests | 56 passed, `.omo/evidence/task5-inbox/focused-green.txt` |
| Complete API suite, `tests/server-api` | 193 passed, 7 skipped, 2 warnings; `.omo/evidence/task5-inbox/api-suite-py314.txt` |
| `git diff --check` | Passed |

The complete API run used the temporary Python 3.14 environment
`/tmp/adsiem-task5-inbox-py314` with the project's pinned `langgraph==1.2.15`.
Initial attempts lacked `langchain_core`, and one environment selected Python
3.12 without pytest. Those setup attempts are recorded separately; the initial
`api-suite.xml` belongs to the failed collection, not the passing run. CI's
Python 3.12 environment has not been rerun here. The seven existing live
9router tests require separately configured model credentials; no new evidence
test was skipped. Two warnings concern existing SlowAPI deprecation usage.

The focused suite covers concurrent same-ID retries, changed-evidence conflicts,
multi-agent group-capacity races, stale agent snapshots across group moves,
commit rollback, retained receipts after deletion, auth/approval, actual
synchronous-commit enforcement, schema/durability readiness, bounded streaming
requests, and isolated test schemas. Independent Task 5 reviews are pending.

## 2026-10-24: Task 6 inbox dispatch and worker ownership

Branch `feat/agent-evidence` (Tasks 1-5 moved here from `feat/enterprise-ui`,
rebased onto `feature/siem-implementation` without the MalwareBazaar commit).
Durable mode is still not wired into the agent and `EVIDENCE_INGEST_ENABLED`
stays false: Task 7 (receipt-aware sender) is the next prerequisite.

Implemented in `worker/worker/evidence_inbox.py`: `evidence_event_id`
(UUIDv5, namespace = agent UUID, name = event UUID string), `dispatch_once`
(`FOR UPDATE SKIP LOCKED`, one non-transactional XADD pipeline, next dispatch
committed only after XADD), `process_reference` (row lock, authoritative
payload, 60 s attempt, completion committed before XACK), failure accounting in
a fresh transaction (backoff 2^n s capped at 60 s, dead letter at 20 with the
payload kept), `evidence_retention_once` (completed payloads released after
7 days with the group budget in the same transaction, completed receipts
deleted after 30 days), and supervised dispatch/retention loops in worker
main. The consumer routes `kind=evidence_v2` references before legacy
decoding, acks every outcome and never copies them into the legacy DLQ.
`process_message` takes an optional stable `event_id`; legacy keeps uuid4.

| Command | Result |
| --- | --- |
| New tests before `worker.evidence_inbox` existed | Collection failed: module missing (red) |
| `pytest tests/worker/test_evidence_event_id.py tests/worker/test_evidence_inbox.int.py tests/worker/test_consumer_batching.py` with disposable Postgres (pgvector pg16) and Redis 7 | 15 passed, including the real-stream dispatch test |
| Worker suites (CI command, Python 3.12) | 298 passed, 4 skipped |
| `pytest tests/server-api` (Python 3.12, this branch) | 163 passed, 7 skipped (the MalwareBazaar tests live on `feat/enterprise-ui`) |

Covered: immediate processing after dispatch despite a future
`next_dispatch_at`, duplicate references, three concurrent dispatchers,
Redis outage, trimmed stream redispatch, failure after indexing retried with
the same identity, 20-failure dead letter, attempt timeout releasing the row
lock, busy and missing references, retention (idempotent, never pending or
dead-letter), NUL/Unicode payload round trip into `process_message`.

Not covered yet: a cross-service test that drives an HTTP v2 acceptance and
then the worker against one schema (worker tests seed rows in the API's
canonical JSON form instead), and Elasticsearch itself (`process_message` is
mocked; it already writes with PUT by id). Independent Task 6 review pending.
