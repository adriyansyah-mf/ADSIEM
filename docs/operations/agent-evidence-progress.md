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

## 2026-10-24: Task 7 receipt-aware sender and runtime selection

`agent/internal/evidence/sender.go`: `Sender{Journal, Transport, SupportsV2}`
with `Step`/`Run`. An event is reclaimed only for HTTP 202 + protocol 2 + the
same event ID + `accepted`/`duplicate` + a valid receipt UUID; a legacy
`{"status":"queued"}` 202 keeps it. The first attempt is persisted before any
network I/O; after 30 days without a receipt the event is held, never resent.
Network errors, 408, 429 and 5xx back off 1-60 s with jitter and honor a
Retry-After bounded to 1-300 s; `pending_approval`, 401 and other 403 retry
every 60 s as blocked; 400/409/413/422 quarantine and move on, but after 5
rejections in a row the sender stops quarantining and blocks
(`repeated_rejections`) so a server-side validation regression cannot
quarantine the backlog; unknown statuses block and keep evidence. Responses are
read to at most 16 KiB and every body is closed. Until a heartbeat advertises
`evidence_protocols: [2]` nothing is sent (checked every second, in memory);
the heartbeat clears support when the server stops advertising it.

`agent/cmd/agent/evidence.go`, behind `evidence.enabled` (default false):
producers push into a sink buffer whose entries become publisher bridge
offers; local detection observes every live admitted event once through the
publisher; the legacy spill is never opened or drained and the legacy sender
does not run; a journal open failure blocks collection (counted as heartbeat
`buffer_dropped`) with no legacy fallback while heartbeat continues. Shutdown
stops tailers and eBPF monitors explicitly, then the sender, then the
publisher (bounded, three 10 s rounds; a still-appending publisher leaves the
journal open), then closes the journal.

| Command | Result |
| --- | --- |
| Sender tests before `sender.go` existed | Build failed: `Sender`/`Transport` undefined (red) |
| `go test -race ./agent/internal/evidence -run 'TestSender|TestLegacySuccess'` | 15 tests and subtests passed |
| `go test -race ./agent/cmd/agent -run TestDurable` | 5 passed (admission, once-per-event offline detection, blocked journal, protocol gating then delivery, shutdown) |
| Same runtime/sender tests `-count=10 -race` | Passed, no flakes |
| `go test ./agent/... ./tests/agent/...` | Passed |
| `GOOS=windows go vet` and `go build ./agent/cmd/agent` | Passed |
| Go-encoded envelopes (cursor/no cursor, NUL, `<&>`, ns, non-UTC offset) validated with server `EvidenceEnvelope` | 4/4 valid |

Known limits, for later tasks:
- Producers are not joined: `Stop` on tailers/eBPF monitors closes channels but
  does not wait for their goroutines. A late offer after the publisher stopped
  is refused and counted as dropped, never written to a closed journal. Joining
  the tailer belongs to Task 8, which rewrites it.
- A local detection raised while shutdown drains the bridge is refused (its
  triggering event is kept).
- Today's producers are bridge offers (not replayable): a crash loses offers
  still in the 64-slot bridge. Task 8 makes file sources replayable.
- `agent/cmd/agent` tests need the eBPF objects (`make -C agent bpf`), so CI's
  non-eBPF Go step does not run them yet.
- Sender status is exposed by `Sender.Status()` but not yet reported in the
  heartbeat; that is Task 10.

## 2026-10-24: Task 8 durable file cursors

`agent/internal/tailer/durable_file.go`: `TailDurable(ctx, path, logType,
journal, sink)` for a file or glob. Each file has cursor source
`file:<path>` with its platform identity (`identity_linux.go` dev:ino,
`identity_windows.go` volume serial + file index; other OSes refuse with
`ErrUnsupported`), a random generation per identity, and the offset just after
the last complete admitted line, never the read-ahead position.

- First enablement (no `source:<path>` marker) starts existing files at EOF;
  files that appear later, including several glob arrivals between passes,
  start at zero.
- Restart resumes the committed cursor; lines written while stopped are read.
- Partial lines stay pending and are reread from the committed offset.
- Lines over `MaxEventBytes` are discarded with bounded memory, counted
  (`oversize` loss) and their end offset committed; loss is recorded before
  the offset, so a crash can count twice but never skips silently.
- Running rotation drains the open file (one extra read after the rename is
  seen), commits a drained marker unless the identity lives on under another
  in-scope name, then reads the replacement from zero with a new generation.
- Rotated while stopped: inside a glob scope the renamed identity resumes from
  its cursor; otherwise an unknown gap is recorded and the replacement starts
  at zero. Truncation below the cursor (copytruncate) records a gap and starts
  a new generation at zero.
- `ErrFull` and storage failures pause the source (health `paused`) and retry
  the same draft with backoff up to 5 s; the cursor only moves after durable
  admission, and stopping while paused keeps it.
- Health uses one source per configured path (`file:<path or glob>`).

`Manager.Update`/`StopAll` now wait for the sources they stop, restart a path
whose log type changed, and never hold the manager while a source needs it.
`NewDurableManager(journal, publisher)` runs files through `TailDurable`;
Windows event log channels still use the publisher bridge until Task 9. The
agent uses it in `evidence.enabled` mode, so shutdown now joins the tailers
(closing the Task 7 gap for files).

| Command | Result |
| --- | --- |
| Tailer tests before the implementation | Build failed: `TailDurable`/`durablePoll` undefined (red) |
| `go test -race ./agent/internal/tailer` | 17 passed (15 new: read-ahead, cursor identity/location, first enablement at EOF, restart without skips, partial line across restart, oversize counted once, renamed open file drained, glob arrivals, missing rotated identity gap, rename in glob scope while stopped, copytruncate gap, disk pressure retry, stop while paused, storage failure, manager restart/join, manager disable) |
| Same, `-count=5 -race` | Passed, no flakes |
| `go test -race ./agent/... ./tests/agent/...` | Passed |
| `GOOS=windows go vet` + test compile of tailer, Windows agent build, darwin vet | Passed |

Known limits:
- Windows was compiled and vetted, not executed: native NTFS identity and
  rename-while-open behavior need the Windows runner (Task 12). Go opens files
  without `FILE_SHARE_DELETE`, as the legacy tailer always did, so some Windows
  writers cannot rename a log the agent holds open.
- Cursor keys are per file path; date-named glob files leave old keys in the
  journal's cursor map (small, unbounded over a long time).
- Detection of copytruncate is by size: a truncation followed by a rewrite of
  at least the old length before the next poll is not detectable.
- eBPF monitors are still not joined at shutdown (late offers are refused).
