# Agent Evidence Reliability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make log evidence durably recoverable and explicitly acknowledged, with equal Windows and Linux correctness gates.

**Architecture:** A shared Go evidence journal owns locally admitted events until a matching durable PostgreSQL receipt is recorded. Redis carries retryable inbox references to the existing worker; stable evidence IDs prevent duplicate Elasticsearch documents. OS-specific file identities and Windows bookmarks advance only with durable admission.

**Tech Stack:** Go standard library and existing `golang.org/x/sys`; FastAPI/Pydantic, async SQLAlchemy/PostgreSQL 16, Redis Streams, Elasticsearch; existing React/TypeScript dashboard.

**Spec:** `docs/superpowers/specs/2026-10-21-agent-evidence-reliability-design.md` — read in full before execution.

## Global Constraints

- “Windows and Linux have equal acceptance criteria for durable collection, restart recovery, acknowledged delivery, and visible failure.”
- “Exactly-once rule evaluation, alerts, SOAR actions, and kernel capture are not promised.”
- “Never evict unacknowledged evidence to make space.”
- “Agent credentials are attached only at send time and are not stored in records.”
- Defaults: 1 GiB total local evidence budget, 16 MiB segments, 1 MiB maximum encoded event, 16 MiB reserved control/health budget included in the total; server inbox payload budget 1 GiB per group.
- Retry dispatch cap: 60 seconds; processing dead-letter threshold: 20 failed attempts; completed payload retention: seven days; completed receipt retention: 30 days; agent uncertainty window: 30 days from persisted first attempt.
- “FIM events sent directly to `/api/fim` are not covered by the new log-ingest guarantee.”
- “New models/migration helpers belong in the API startup migration path under the existing advisory lock, not new bootstrap-only tables in `db/init.sql`.”
- Mandatory group scoping and existing `agents:manage` permission for operator mutations; no worker imports of API modules.
- No release tag, package publication, push, or automatic commit is authorized by this plan. Each commit checkpoint below means inspect/review and commit only when explicitly requested.
- Preserve the existing uncommitted `.github/workflows/ci.yml` Prometheus isolation fix. It has its own verification evidence and must not be reverted or hidden in an unrelated commit.
- Recorded Task 2 storage boundary: initial Windows durable mode supports local fixed NTFS with existing SYSTEM/admin volume-flush access; unsupported storage/access is explicit, never an automatic privilege grant or silent downgrade. Volume flush is limited to namespace transitions; native elevated tests and latency measurements remain release gates.

## Execution context and decomposition

Run repository-relative commands from `/home/wonka/Documents/ADSIEM/.claude/worktrees/next-phase-roadmap`, not the older root checkout. Existing branch: `feat/enterprise-ui`. The graph project is `home-wonka-Documents-ADSIEM`, generation `2026-10-17T18:29:47Z`; this worktree is excluded, so exact source reads are the authority for changes. Refresh coverage when discovering additional files.

This is one coupled reliability contract, not twelve independent features. Tasks 1–4 establish the local library; 5–6 establish durable server ownership; 7 joins the halves; 8–11 complete resumability, visibility, and upgrade safety; 12 is the release gate. Keep production wiring on the current legacy path until the durable path is complete. Do not advertise a durable capability on a partially deployed backend.

### File responsibility map

| Area | Files and responsibility |
| --- | --- |
| Protocol | New `agent/internal/evidence/envelope.go`, `tests/fixtures/evidence-v2.json`; API schemas in existing `server-api/app/schemas/schemas.py`. |
| Journal | New `agent/internal/evidence/{journal,record,checkpoint,health,publisher,migration}.go` and focused `_test.go` peers; OS operations in `{storage,identity}_{linux,windows,other}.go`. |
| Runtime | Existing agent config, buffer adapter, main, heartbeat, tailer manager/files/eventlog; new `agent/internal/evidence/sender.go`. |
| Server | Existing models/config/ingest/main; new `app/services/{evidence_inbox,evidence_schema}.py`, `app/api/routes/evidence.py`. |
| Worker | Existing models/config/main/consumer; new `worker/worker/evidence_inbox.py`. |
| Operator visibility | Existing agent API schemas/routes and dashboard agent types/pages/hooks; new `dashboard/src/components/EvidenceHealth.tsx`. |
| Verification | New Go unit/fault tests, API/worker integration tests, `tests/evidence/` acceptance harness, Windows bookmark tests; existing workflows extended, not replaced. |

## Test environment and checkpoint discipline

Use TDD for each task: create its test, run to observe the specific failure, implement, rerun, then review its diff. Missing module/symbol failures are expected only on the first run; later failures must be assertions for the intended behavior. No placeholder implementations or skipped new correctness tests.

Go package tests without eBPF dependencies can run directly from repo root:

```bash
go test ./agent/internal/evidence/... -count=1
go test ./agent/internal/tailer/... -count=1
go test ./tests/agent/... -count=1
```

Full Linux agent tests/build require both embedded BPF objects: run `make -C agent bpf` first, using the existing Makefile. Do not commit objects or built packages. Native Windows uses Go 1.26.1 or newer to satisfy the repository workspace, even though `agent/go.mod` has a lower floor.

Python integration tests require `JWT_SECRET` and `DATABASE_URL=TEST_DATABASE_URL`, all targeting an explicitly named disposable test database. Reuse existing fixture patterns only after removing their assumption that arbitrary supplied databases are safe to reset. New fixtures create a random schema in that disposable DB, set its search path, and drop only that schema during cleanup. Never copy `DROP SCHEMA public CASCADE` into new fixtures.

Run the service suites in separate processes. Existing CI exclusions are not authorization to skip new tests:

```bash
pytest tests/server-api
pytest tests/worker worker/tests --ignore=tests/worker/test_pipeline.int.test.py --deselect worker/tests/test_rag.py::test_embed_text_returns_384_dimensions --deselect worker/tests/test_rag.py::test_embed_text_different_inputs_differ
```

Keep a task evidence log with command, exit status, native OS, and fault scenario. A plan checkbox is not proof that its test ran.

### Task 1: Immutable envelope, shared fixtures, validated configuration

**Files:** Create `agent/internal/evidence/envelope.go`, `envelope_test.go`, `tests/fixtures/evidence-v2.json`; modify `agent/internal/config/config.go`; create `agent/internal/config/{evidence_test,defaults_linux,defaults_windows,defaults_other}.go`.

**Interfaces produced:**

```go
type Cursor struct {
    Source string `json:"source"`
    Generation string `json:"generation"`
    Identity string `json:"identity"`
    Offset int64 `json:"offset,omitempty"`
    Bookmark string `json:"bookmark,omitempty"`
    Empty bool `json:"empty,omitempty"`
}
type Draft struct { LogType, Location, RawMessage string; Cursor *Cursor }
type Envelope struct {
    ProtocolVersion int `json:"protocol_version"`
    EventID string `json:"event_id"`
    AgentID string `json:"agent_id"`
    CollectedAt time.Time `json:"collected_at"`
    Hostname string `json:"hostname"`
    LogType string `json:"log_type"`
    Location string `json:"location"`
    RawMessage string `json:"raw_message"`
    Cursor *Cursor `json:"cursor,omitempty"`
    LegacyImport bool `json:"legacy_import,omitempty"`
}
func NewEnvelope(agentID, hostname string, d Draft, now time.Time) (Envelope, error)
type Options struct {
    Dir, AgentID string
    MaxBytes, SegmentBytes, ReservedBytes int64
    MaxEventBytes int
}
```

- [x] Write `TestEnvelopeRoundTrip` and `TestEvidenceConfigDefaults` first. Include multiline, NUL, Unicode, timestamp nanoseconds, distinct random UUIDs, no serialized token, invalid UUID, negative sizes, segment larger than data budget, symlink escape, and platform-default state paths.

```go
func TestEnvelopeRoundTrip(t *testing.T) {
    at := time.Date(2026, 10, 21, 1, 2, 3, 123456789, time.UTC)
    e, err := NewEnvelope("11111111-1111-4111-8111-111111111111", "host", Draft{LogType:"syslog", RawMessage:"a\n\x00b"}, at)
    if err != nil { t.Fatal(err) }
    b, err := json.Marshal(e); if err != nil { t.Fatal(err) }
    var got Envelope
    if err := json.Unmarshal(b, &got); err != nil { t.Fatal(err) }
    if got.EventID != e.EventID || !got.CollectedAt.Equal(at) || got.RawMessage != e.RawMessage { t.Fatal("envelope changed") }
}
```

- [x] Run `go test ./agent/internal/evidence ./agent/internal/config -run 'TestEnvelope|TestEvidenceConfig' -count=1`; observe the missing definitions or assertion failures.
- [x] Implement UUIDv4 with `crypto/rand`, explicit JSON names, validation, and `evidence` config options. Resolve default state directories per OS before deriving the journal directory; keep old `buffer.spill_path` solely as an import source. Restrict journal paths to resolved state-dir descendants and reject symlink/reparse-point escapes. Store the shared fixture with fixed IDs/timestamp and no credentials.
- [ ] Rerun those tests on Linux and Windows. Commit checkpoint: `feat(agent): define durable evidence protocol and storage config`.

Task 1 implementation/review complete: Linux focused and race/shuffle suites plus vet pass; Windows cross-compiles. Native Windows execution remains pending as a release gate. No commit created. Task evidence lives in this plan's `.superpowers/sdd/` workspace.

### Task 2: Append/flush/recovery and exclusive ownership

**Files:** Create `agent/internal/evidence/{journal,record,storage_linux,storage_windows,storage_other}.go`, `journal_test.go`, `storage_windows_test.go`.

**Consumes:** `Envelope`, `Cursor`, `Options` from Task 1.
**Produces:** `Open(Options) (*Journal,error)`, `(*Journal).Append(context.Context,Envelope) error`, `Peek(context.Context) (Envelope,bool,error)`, `Cursor(source string) (Cursor,bool)`, `SaveBaseline(context.Context,Cursor) error`, `Close() error`; sentinel errors `ErrFull`, `ErrLocked`, `ErrCorrupt`, `ErrIdentityMismatch`, `ErrOversize`.

- [x] Add `TestAppendSurvivesReopen`, `TestSyncFailureDoesNotCommitCursor`, `TestSecondWriterRefused`, `TestTornTailPreservesPrefix`, and `TestInteriorCorruptionBlocks`. Use a package-private storage interface (`Write`, `Sync`, `Close`) so tests inject short writes and flush errors without production environment-variable hooks.

```go
func TestAppendSurvivesReopen(t *testing.T) {
    o := Options{Dir:t.TempDir(), AgentID:"11111111-1111-4111-8111-111111111111", MaxBytes:1<<20, SegmentBytes:64<<10, ReservedBytes:16<<10, MaxEventBytes:4096}
    j, err := Open(o); if err != nil { t.Fatal(err) }
    e, err := NewEnvelope(o.AgentID, "host", Draft{LogType:"syslog", RawMessage:"number=1"}, time.Now().UTC()); if err != nil { t.Fatal(err) }
    if err := j.Append(context.Background(), e); err != nil { t.Fatal(err) }
    if err := j.Close(); err != nil { t.Fatal(err) }
    j, err = Open(o); if err != nil { t.Fatal(err) }; defer j.Close()
    got, ok, err := j.Peek(context.Background())
    if err != nil || !ok || got.EventID != e.EventID { t.Fatalf("recovery: %v %v", ok, err) }
}
```

- [x] Run `go test ./agent/internal/evidence -run 'TestAppend|TestSync|TestSecond|TestTorn|TestInterior' -count=1` and record red results.
- [x] Implement framed records: magic/version, bounded length, CRC32C, JSON payload; validate length before allocation. Data and baseline records share the flush boundary. Use kernel-backed file locks, not a permanent PID-file convention. Linux uses existing `x/sys/unix`; Windows uses `LockFileEx` and restricted ACLs. Bind the journal header to its agent UUID. Keep only bounded read windows/segment metadata in memory. Preserve a forensic copy of a torn suffix before recovery truncation; refuse interior corruption.
- [ ] Rerun the fault tests and `go test -race ./agent/internal/evidence` natively where supported. Commit checkpoint: `feat(agent): add durable evidence journal and crash recovery`.

  Implementation and independent review complete, including Windows owner-creation fix. Linux race/shuffle/vet and Windows cross-compilation/vet passed; native elevated Windows correctness and namespace latency remain global release gates. No commit authorized or created.

### Task 3: Durable ACK, quarantine, retention window, compaction

**Files:** Create `agent/internal/evidence/{checkpoint,health}.go`, `checkpoint_test.go`, `health_test.go`; extend journal/storage files.

**Produces:** `Ack(ctx context.Context,eventID,receiptID string) error`, `MarkAttempt(ctx context.Context,eventID string,at time.Time) error`, `Hold(ctx context.Context,eventID,reason string) error`, `Quarantine(ctx context.Context,eventID,reason string) error`, `Compact(ctx context.Context) error`, `Snapshot() Health`, `RecordLoss(ctx context.Context,source,reason string,known int64,unknown bool) error`, `SetSourceState(ctx context.Context,source,state,reason string) error`. `Health` JSON fields: version, state, reason, queued_events, queued_bytes, oldest_queued_at, last_receipt_at, retries, quarantined, held, known_loss, unknown_gaps, sources. Counters are cumulative; `known_loss` keys are bounded reason enums.

- [x] Add tests for crash after remote receipt but before local ACK; ACK checkpoint flush failure; cursor snapshot surviving segment deletion; quarantine not counted delivered; full data budget leaving reserved control space; unknown loss interval on storage failure; first attempt surviving restart and operator hold at 30 days.

```go
func TestAckUnknownEventIsRejected(t *testing.T) {
    o := Options{Dir:t.TempDir(), AgentID:"11111111-1111-4111-8111-111111111111", MaxBytes:1<<20, SegmentBytes:64<<10, ReservedBytes:16<<10, MaxEventBytes:4096}
    j, err := Open(o); if err != nil { t.Fatal(err) }; defer j.Close()
    if err := j.Ack(context.Background(), "missing", "22222222-2222-4222-8222-222222222222"); err == nil { t.Fatal("accepted unknown event ACK") }
}
```

- [x] Run `go test ./agent/internal/evidence -run 'TestAck|TestCompact|TestQuarantine|TestBudget|TestAttempt|TestHealth' -count=1` red.
- [x] Persist terminal states separately from receipt ACKs: quarantined/held records remain accounted and readable by operator tools. Maintain a contiguous reclaim frontier plus sparse terminal-state records, so quarantine cannot make later records undeliverable or falsely ACKed. Checkpoint source cursors and immutable-generation manifests before deleting segments; preserve quarantine payloads inside the same total budget. Sync new files and OS-appropriate metadata transitions before publishing a generation. Recover the newest fully committed generation, not simply the newest filename. Do not assume replacing an open file works on Windows. Accumulate counters in reserved control records and expose storage failure even if its counter cannot be persisted.
- [x] Rerun complete journal tests with forced crash points before/after every manifest publication/deletion operation. Commit checkpoint: `feat(agent): checkpoint evidence receipts without destructive replay`.

  Implementation/review complete after committed-prefix repair guard. Linux full race/shuffle/vet and 68 subprocess crash boundaries passed; native Windows/persistent-load validation and real Sender window enforcement remain global/later-task gates. Controller small ext4 benchmark is not a throughput acceptance claim. No commit authorized or created.

### Task 4: Producer admission and bounded non-replayable bridge

**Files:** Create `agent/internal/evidence/publisher.go`, `publisher_test.go`; modify `agent/internal/buffer/buffer.go`; create `agent/internal/buffer/durable_test.go`.

**Produces:** `NewPublisher(j *Journal,agentID,hostname string,observe func(Envelope)) *Publisher`, `(*Publisher).Submit(ctx context.Context,d Draft) (Envelope,error)`, `TrySubmit(d Draft) error`, `Stop(ctx context.Context) error`; buffer constructor `NewWithSink(sink func(string) error) *Buffer` for existing non-replayable producers. Legacy `New` behavior stays unchanged.

- [x] Write tests proving no memory-only success; `Submit` waits for durable append; pressure returns `ErrFull` without advancing cursor; repeated sender reads do not call `observe`; `TrySubmit` bounds its pending queue at 64 entries, returns explicit overload, and records failed durable writes. Make observer invocation occur outside journal locks, and test reentrant emission of a local-detection event.

```go
func TestSinkBufferNeverQueuesInMemory(t *testing.T) {
    calls := 0
    b := NewWithSink(func(s string) error { calls++; return errors.New("disk full") })
    b.Push("syslog\x00line")
    if calls != 1 || b.Len() != 0 || b.Dropped() != 1 { t.Fatal("hidden memory fallback or missing rejection") }
}
```

- [ ] Run `go test ./agent/internal/evidence ./agent/internal/buffer -count=1` red for the new tests. The resumed session recovered the implementation and verified green results; the original red run has not been recovered as evidence.
- [x] Implement synchronous `Submit` for replayable collectors; the bounded bridge is explicitly not durable until its background append succeeds. Kernel/non-replayable callbacks get no indefinite disk wait; failures count loss. Decode the existing two/three-field tailer codec in the main-owned adapter, avoiding a buffer→tailer import cycle. Local detector observes admitted live events only; guard against observing its own `local_detection` output recursively. No production main wiring yet.
- [x] Rerun buffer, publisher, and existing detector tests. Commit checkpoint: `feat(agent): route producers through explicit evidence admission`.

  Resumed verification on 2026-10-22: focused tests, race/shuffle, vet, full Linux agent suite, and Windows amd64/386/arm64 cross-builds pass. Independent spec and code-quality reviews pass; reports are `.omo/evidence/task4-publisher-review/review.md` and `.omo/evidence/task4-publisher-quality/review.md`. Native Windows remains pending. The main-owned codec adapter belongs with Task 7 production wiring and is not implemented here. No commit created. See `docs/operations/agent-evidence-progress.md` for commands and limits.

### Task 5: PostgreSQL inbox, atomic capacity, v2 receipts

**Files:** Modify `server-api/app/{models/models.py,schemas/schemas.py,core/config.py,api/routes/ingest.py,api/routes/system.py,main.py}`; create `app/services/{evidence_inbox,evidence_schema}.py`, `tests/server-api/test_evidence_ingest.int.py`, `tests/server-api/test_evidence_protocol.py`.

**Produces:** Pydantic `EvidenceEnvelope` matching Task 1; `EvidenceReceipt(protocol_version,event_id,status,receipt_id)`; `accept_evidence(db: AsyncSession,agent: Agent,body: EvidenceEnvelope) -> EvidenceReceipt`; `check_evidence_durability(db: AsyncSession) -> bool`; startup `migrate_evidence() -> None`. Service owns the commit; route returns only after it succeeds.

Schema: `evidence_inbox` includes receipt UUID PK, agent UUID (retained identity, no cascading deletion), event UUID, group/hostname snapshot, SHA256 digest, JSONB payload nullable after retention, payload_bytes bigint, collected_at, received_at, status (`pending/completed/dead_letter`), failure count/error, next_attempt_at, next_dispatch_at, dispatch count, completed_at. Unique `(agent_id,event_id)`; indexes on eligible pending time and retention time. `evidence_group_usage` contains group PK and payload byte count. Agent deletion must not cascade-delete inbox evidence.

- [ ] Add isolated-schema integration fixtures named `inbox_env`: fields `sessions`, `agent_id`, `token`, `request`; `request` is a validated copy of the shared JSON fixture with that seeded agent ID. Seed real Agent(name,hostname,group_id,token_hash,approved); each concurrent acceptance uses its own session. Define `inbox_env.accept(body=None)` to open a session, load that Agent, and call `accept_evidence` (service-level tests); use HTTP dependency overrides for token/identity/status tests.

```python
async def test_concurrent_retry_has_one_receipt(inbox_env):
    import asyncio
    receipts = await asyncio.gather(*(inbox_env.accept() for _ in range(8)))
    assert len({r.receipt_id for r in receipts}) == 1
    assert sum(r.status == "accepted" for r in receipts) == 1
    assert all(r.event_id == inbox_env.request.event_id for r in receipts)
```

- [ ] Run `pytest tests/server-api/test_evidence_protocol.py tests/server-api/test_evidence_ingest.int.py -q`; confirm red with a disposable DB, not skipped results.
- [ ] Implement canonical digest with normalized UUID/UTC fields, JSON sorted keys, compact separators, UTF-8. Exclude credentials/server attribution from digest; include every immutable envelope field. Validate the encoded event maximum consistently with Go. Lock the group usage row transactionally; recheck duplicates before capacity rejection. Reserve capacity and insert in one transaction; rollback both on failure. Enforce `SET LOCAL synchronous_commit=on`, verify `fsync` and `full_page_writes` on; reject 503 if durable configuration check fails. Check DB flags for each acceptance, not only stale startup state. Defer Redis dispatch to Task 6. Bound HTTP body to 2 MiB before parsing (1 MiB event limit remains stricter); include transfer without Content-Length in the limit. Keep legacy ingest unchanged.
- [ ] Test commit rollback/no receipt; duplicate while quota is full; two replicas competing for last capacity; 409 changed evidence; 403 pending approval; 401 invalid token; wrong agent ID; group move preserves receipt attribution; Unicode payload digest; unsupported version; oversized/chunked body. Add startup migration under existing lock, and advertise heartbeat `evidence_protocols: [2]` only when durability check is healthy and backend enabled by `EVIDENCE_INGEST_ENABLED` (default false until rollout).
- [ ] Add `/ready` in the existing system router: when durable ingest is enabled, unhealthy durability/schema prerequisites return HTTP 503; when disabled, do not advertise protocol 2. Preserve `/health` as the existing liveness/diagnostic endpoint. Test readiness and capability agree on disabled, healthy, and unsafe-durability states. Rerun API suite separately. Commit checkpoint: `feat(api): acknowledge evidence after durable inbox commit`.

### Task 6: Recoverable dispatch, worker ownership, stable ES IDs

**Files:** Modify `worker/worker/{models,config,main,consumer}.py`; create `worker/worker/evidence_inbox.py`, `tests/worker/test_evidence_inbox.int.py`, `tests/worker/test_evidence_event_id.py`.

**Consumes:** Task 5 tables; mirror mappings without API imports.
**Produces:** `evidence_event_id(agent_id: UUID,event_id: UUID) -> UUID`, `dispatch_once(now: datetime) -> int`, `process_reference(receipt_id: UUID,state: dict) -> str`, `evidence_dispatch_loop() -> None`, `evidence_retention_once(now: datetime) -> int`. Processing outcomes: `completed`, `duplicate`, `busy`, `deferred`, `dead_letter`, `missing`. Add optional `event_id: UUID | None = None` to existing `process_message`; legacy path keeps generated UUID behavior.

- [ ] Write stable identity test and PostgreSQL/Redis integration tests with two dispatchers/workers, duplicate references, trimmed stream, Redis outage, ES failure, and crash after ES before completion. Assert a newly dispatched reference is immediately processable even though `next_dispatch_at` has moved into the future.

```python
def test_stable_evidence_id_is_scoped_to_agent():
    from uuid import UUID
    from worker.evidence_inbox import evidence_event_id
    agent = UUID("11111111-1111-4111-8111-111111111111")
    event = UUID("22222222-2222-4222-8222-222222222222")
    assert evidence_event_id(agent, event) == UUID("61396d92-7faa-5629-b99c-b073e1e76122")
    assert evidence_event_id(event, event) != UUID("61396d92-7faa-5629-b99c-b073e1e76122")
```

Also assert the actual `process_reference` call passes this UUID to mocked `process_message`, not just that UUIDv5 itself is deterministic.

- [ ] Run `pytest tests/worker/test_evidence_event_id.py tests/worker/test_evidence_inbox.int.py -q` red.
- [ ] Implement `FOR UPDATE SKIP LOCKED` dispatch batches and Redis reference fields `kind=evidence_v2`, `receipt_id`, group/hostname hints for grouping. Commit next dispatch time only after successful XADD; a crash can duplicate references safely. Keep `next_attempt_at` (processing retry eligibility) separate from `next_dispatch_at` (Redis wake-up throttling): advancing the latter must not defer the worker that just received a reference. Worker locks the inbox row per event, reads the authoritative payload, checks completion/dead-letter/next_attempt_at, and bounds one processing attempt to 60 seconds. Pass UUIDv5(agent UUID, event UUID) and original collection time into processing/indexing. Commit completion before XACK. Route new references before legacy decoding/grouping and never copy authoritative payloads into the legacy DLQ. Busy/missing/stale references may be ACKed because the DB dispatcher owns recovery.
- [ ] On processing failure, rollback its lock transaction, then use a fresh short locking transaction to increment failures and schedule retry (cap 60 seconds). At 20 failures retain payload as dead letter. Ordinary Redis redispatch is not a failed processing attempt. Timeout cancellation releases the DB connection/lock; test cancellation explicitly. Do not change the existing best-effort UEBA contract. Add dispatch/retention loops using `_supervise` in worker main. Retention removes only completed payloads after seven days and releases usage atomically; delete receipt metadata only after 30 days completed. Dead-letter/pending rows never age out.
- [ ] Rerun worker suite and test that HTTP retries create one inbox event/document while a crash can repeat detection. Commit checkpoint: `feat(worker): recover durable inbox delivery across Redis loss`.

### Task 7: Receipt-aware sender and safe runtime selection

**Files:** Create `agent/internal/evidence/{sender,sender_test}.go`; modify `agent/cmd/agent/main.go`, `agent/internal/heartbeat/heartbeat.go`; create `agent/cmd/agent/evidence_test.go`.

**Produces:** `type Transport interface { PostContext(context.Context,string,any)(*http.Response,error) }`; `Sender{Journal *Journal, Transport Transport, SupportsV2 func() bool}` with `Step(ctx context.Context,now time.Time) error`, `Run(ctx context.Context) error`. Responses are bounded to 16 KiB and closed on every branch.

- [ ] Add httptest scenarios for a matching receipt, queued legacy 202, wrong UUID/version/receipt, malformed JSON, network disconnect after commit, retryable statuses, pending approval, auth failures, permanent validation errors, and 30-day hold. Use a stub clock and injected wait function rather than real backoff sleeps.

```go
func TestLegacySuccessIsNotDurableReceipt(t *testing.T) {
    s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusAccepted); _, _ = w.Write([]byte(`{"status":"queued"}`))
    })); defer s.Close()
    // sender_test.go defines a fixture that opens a real temp journal,
    // admits one envelope and builds Sender with client.New(s.URL,"test-token").
    sender, j, id := newSenderFixture(t, s.URL)
    if err := sender.Step(context.Background(), time.Now().UTC()); err == nil { t.Fatal("legacy success was ACKed") }
    got, ok, err := j.Peek(context.Background())
    if err != nil || !ok || got.EventID != id { t.Fatal("unconfirmed event was removed") }
}
```

`newSenderFixture(t *testing.T,url string) (*Sender,*Journal,string)` registers journal cleanup, appends one Task 1 envelope, and sets `SupportsV2` true. It must not use the memory buffer as its evidence store.

- [ ] Run `go test ./agent/internal/evidence -run TestSender -count=1` (name the new status cases `TestSender...`; include the legacy case explicitly with `-run 'TestSender|TestLegacySuccess'`).
- [ ] Implement status table from spec. Persist first attempt before network I/O; use jittered 1–60 second backoff, auth/approval retry every 60 seconds, bounded Retry-After (1–300 seconds). Unsupported protocol blocks sending but not heartbeat/collection. Unknown statuses preserve evidence and set blocked health rather than falling through as success. ACK requires 202, version 2, matching event ID, accepted/duplicate status, valid receipt UUID. Permanent errors quarantine; server-global validation failures must remain visible rather than loop silently.
- [ ] Wire new mode behind `evidence.enabled` for testing; when disabled keep the old sender and spill entirely separate. In new mode never open/drain the legacy spill writer, use the sink bridge for old non-replayable producers, and stop all producers before bounded publisher shutdown/journal close. Track producer goroutines and await them, not just close stop channels. Keep local detection before delivery through publisher observation, not sender attempts. A journal startup error keeps heartbeat alive but blocks evidence producers; no hidden legacy fallback.
- [ ] Run sender/runtime tests after `make -C agent bpf`; verify offline local detection still works once per live admitted event. Commit checkpoint: `feat(agent): require matching durable receipts before queue reclamation`.

### Task 8: File cursors, partial lines, rotation, bounded backpressure

**Files:** Modify `agent/internal/tailer/{tailer,manager}.go`; create `agent/internal/tailer/{durable_file,identity_linux,identity_windows,identity_other}.go`, `durable_file_test.go`, `manager_test.go`.

**Consumes:** Publisher.Submit, Journal.Cursor/SaveBaseline and source-health methods.
**Produces:** `type DurableSink interface { Submit(context.Context,evidence.Draft)(evidence.Envelope,error) }`; `TailDurable(ctx context.Context,path,logType string,j *evidence.Journal,sink DurableSink) error`; manager constructor `NewDurableManager(j *evidence.Journal,p *evidence.Publisher) *Manager`. Preserve legacy `Tail`/`NewManager` for compatibility tests.

- [ ] Add real-temp-file tests that establish a baseline, append a numbered line, reopen the journal/tailer after shutdown, append while stopped, and verify no skipped line. Add partial-EOF, oversized line, read-ahead, renamed open file, two intermediate glob arrivals, missing rotated identity, copytruncate, source type changes, disk pressure, and stop-while-paused cases.

```go
func TestCompleteLineOffsetIgnoresReadAhead(t *testing.T) {
    drafts := runDurableTailFixture(t, "one\ntwo\npartial", 2)
    if len(drafts) != 2 { t.Fatalf("expected two complete lines, got %d", len(drafts)) }
    if drafts[0].Cursor == nil || drafts[1].Cursor == nil { t.Fatal("missing source cursor") }
    if drafts[0].RawMessage != "one" || drafts[0].Cursor.Offset != 4 || drafts[1].RawMessage != "two" || drafts[1].Cursor.Offset != 8 { t.Fatal("checkpoint includes read-ahead or partial line") }
}
```

Define `runDurableTailFixture(t *testing.T,raw string,count int) []evidence.Draft` in durable_file_test.go: create an empty temp source, establish its persisted baseline, append raw bytes, run the real `TailDurable` against a capturing sink backed by a real temporary journal, and cancel after count successful admissions. Bound completion with context timeout; join the collector goroutine before reading drafts. Do not replace the collector with a test implementation of its parser.

- [ ] Run `go test ./agent/internal/tailer -count=1` red on the durable-tail cases.
- [ ] Implement platform identities (Linux device/inode; Windows volume/file ID), persistent generation/baseline, byte-accounted line framing, and deterministic discovery of all matching configured files. Keep at most MaxEventBytes plus bounded read buffer per source. Oversized complete lines produce a durable loss/control record with their end offset before advancing, so restart does not loop forever or silently skip them. Partial lines survive reread from last committed offset; no checkpoint past an unadmitted complete line. On ErrFull retain/retry the same draft; never create a new ID for an already successful append. Source identity changes start a new generation; report unavailable old bytes as unknown gap.
- [ ] Manager stop/update waits for source goroutines to finish before returning and restarts on log_type changes for the same path. Do not hold its mutex while waiting for a worker that needs manager state. Rerun on native Linux and Windows. Commit checkpoint: `feat(agent): resume file evidence from durable source cursors`.

### Task 9: Native Windows bookmark lifecycle and gap recovery

**Files:** Modify `agent/internal/winevent/{subscribe_windows,subscribe_other}.go`, `agent/internal/tailer/eventlog.go`; create `agent/internal/winevent/{bookmark_windows,bookmark_windows_test}.go`, `agent/internal/tailer/durable_eventlog.go`, `durable_eventlog_test.go`; extend `tests/windows/mock_siem.py` and create `tests/windows/evidence-resume.ps1`.

**Produces:** `winevent.Event{Line string; Bookmark string; RecordID uint64}`, `winevent.Resume{Bookmark string; Empty bool; Initialized bool}`, `SubscribeResume(ctx context.Context,channel string,resume Resume,emit func(Event) error) error`, `Baseline(ctx context.Context,channel string) (Resume,error)`; typed `ErrBookmarkGap`. Existing Subscribe remains a compatibility wrapper.

- [ ] Write fake-native-call unit tests for handle lifetime, render failure, callback admission error, strict flags, and empty baseline; then native tests using a uniquely named disposable event channel/source. Never clear Security/System or another user's channel.

```powershell
# In evidence-resume.ps1, $channel is a newly created test-only channel.
$before = [Guid]::NewGuid().ToString()
Write-EventLog -LogName $channel -Source $channel -EventId 701 -EntryType Information -Message $before
# Harness stops its own subscriber, writes another marker, then resumes
# the same state directory and asserts both admitted markers exactly once.
```

- [ ] Run `go test ./agent/internal/winevent ./agent/internal/tailer -count=1` on Windows; initial bookmark tests must fail before implementation. Unix stubs must still compile and report unsupported source health.
- [ ] Implement EvtCreateBookmark/EvtUpdateBookmark/EvtRender(bookmark) while event handles remain open; every enumerated handle closes on success, failure, and cancellation. Nonempty first baseline bookmarks the latest retained event; subscribe strictly after it so events between baseline and subscription are not missed. Empty baseline uses oldest-available resume. Propagate admission error without moving committed bookmark. On stale/missing strict bookmark emit an explicit gap, save a new generation baseline, and read oldest retained events. Preserve `FormatXML` line contract and existing Query API.
- [ ] Extend TLS mock heartbeat capability and matching v2 receipts so MSI tests exercise actual new mode without pretending the mock proves PostgreSQL durability. Reuse its certificate trust path. Record/render/format errors must update source health; never advance past them unnoticed. Native harness clears only its own test channel to prove gap recovery, removes it in finally, and uses bounded polling rather than fixed long sleeps.
- [ ] Run existing Windows format/decoder tests plus native resume and MSI smoke. Commit checkpoint: `feat(agent): recover Windows events with durable bookmarks`.

### Task 10: Evidence health, scoped operator controls, narrow UI

**Files:** Modify `agent/internal/heartbeat/heartbeat.go`, `agent/internal/evidence/checkpoint.go`, `server-api/app/models/models.py`, `server-api/app/schemas/schemas.py`, `server-api/app/api/routes/agents.py`, `server-api/app/main.py`; create `agent/cmd/agent/evidence_commands.go`, `evidence_commands_test.go`, `server-api/app/api/routes/evidence.py`, `tests/server-api/test_evidence_health.int.py`, `tests/server-api/test_evidence_admin.int.py`; modify `dashboard/src/types/index.ts`, `dashboard/src/pages/AgentsPage.tsx`, `dashboard/src/hooks/useAgents.ts`, `tests/dashboard/test_enterprise_ui.py`; create `dashboard/src/components/EvidenceHealth.tsx`.

**Produces:** heartbeat `evidence_health` optional object from Task 3 and `evidence_protocols` response; stored Agent `evidence_health` JSONB and `evidence_health_at`; `GET /api/agents/{id}/evidence` (scoped metadata/status), `POST /api/agents/{id}/evidence/{receipt_id}/retry` (`agents:manage`, dead-letter only, original group scope). Local journal operator commands: `-evidence-list`, `-evidence-release <event-id>`, `-evidence-discard <event-id>` with required `-reason`; offline exclusive lock, service/admin identity, durable audit control record, duplicate-risk warning/explicit confirmation for release beyond uncertainty window. Implement command parsing in new `agent/cmd/agent/evidence_commands.go` rather than growing main substantially.

- [ ] Add tests that failed heartbeats do not reset counters; legacy heartbeat omits new fields; invalid/unbounded health input is rejected; source maps have bounded entries (256) and bounded strings; cross-group inbox fetch/retry returns 404; ordinary analyst mutation returns 403; local discard without reason fails and does not delete data.

```python
async def test_health_uses_persisted_cumulative_counts(inbox_env):
    from app.schemas.schemas import HeartbeatRequest
    body = HeartbeatRequest(agent_id=inbox_env.agent_id,
        evidence_health={"version": 1, "state": "degraded", "reason": "disk_full",
                         "queued_events": 3, "queued_bytes": 1024,
                         "known_loss": {"queue_full": 2}, "unknown_gaps": 0})
    assert body.evidence_health.known_loss["queue_full"] == 2
```

- [ ] Run targeted API tests and agent heartbeat/operator command tests red. Treat the health snippet as a schema test; integration tests must also call the actual heartbeat and read the scoped agent response.
- [ ] Persist snapshots using server receipt time, never client-provided group. Validate numeric ranges and enum reasons; keep raw paths out of metric labels. Retry mutations retain original payload and reset failed-attempt state under a lock; add existing BackgroundTask audit logging. Register the router explicitly. Add journal `Resolve(ctx context.Context,eventID,action,reason string,allowDuplicate bool) error` for `release`/`discard`, callable only under the exclusive local operator lock. Local discard writes/flushed tombstone+audit before space reclamation; CLI never echoes raw evidence or tokens.
- [ ] Render a separate “Evidence delivery” status next to connectivity, with backlog bytes/age, last receipt, loss/gap/quarantine counts, and reason/time. For legacy agents show “Not reported”, never “Healthy”. Treat heartbeat older than two configured intervals as stale, preserving its last known evidence state. Keep existing tokens/layout; no general redesign, no `as any` or new unit-test framework. Add scoped API hooks for detail/retry and clear duplicate-risk confirmations for operator actions.
- [ ] Run API suites, `DASHBOARD_TEST_URL=http://127.0.0.1:5173 pytest tests/dashboard/test_enterprise_ui.py` against a task-owned Vite server, and `npm --prefix dashboard run build`. The browser suite intercepts API requests; do not point it at production. Add fixture states for legacy, healthy, backlogged, auth-blocked, degraded disk-full, and stale evidence health and assert their displayed status/counts. Manually inspect the same states. Commit checkpoint: `feat(agents): expose evidence health and audited recovery controls`.

### Task 11: Non-destructive spill migration and staged activation

**Files:** Create `agent/internal/evidence/migration.go`, `migration_test.go`, `docs/operations/agent-evidence-recovery.md`; modify `agent/cmd/agent/main.go`, `agent/internal/config/config.go`, `agent/packaging/config.yaml`, `agent/packaging/windows/config.yaml`. Read `agent/config.yaml` without overwriting local deployment values; add configuration examples to packaged templates instead.

**Produces:** `ImportLegacy(ctx context.Context,j *Journal,path string,agentID,hostname string) error`. Store import source identity/hash, byte cursor, and import record ID in the same journal record. Imported envelope IDs derive deterministically from journal identity, source content digest, and line byte offset, so interrupted import has a stable identity. Mark legacy timestamp as import time and set the Task 1 `legacy_import` flag; protocol/digest tests must include both imported and ordinary envelopes.

- [ ] Add tests with three old spill lines, interruption after each record flush, rerun import, marker write failure, backup rename failure, empty/missing spill, marker substitution/new file, legacy newline marker, and import exceeding the budget.

```go
func TestImportPreservesOriginal(t *testing.T) {
    // newMigrationFixture opens a real journal and returns a spill containing one encoded line.
    j, path := newMigrationFixture(t)
    before, err := os.ReadFile(path); if err != nil { t.Fatal(err) }
    if err := ImportLegacy(context.Background(), j, path, "11111111-1111-4111-8111-111111111111", "host"); err != nil { t.Fatal(err) }
    after, err := os.ReadFile(path); if err != nil { t.Fatal(err) }
    if !bytes.Equal(before, after) { t.Fatal("import destroyed original spill") }
}
```

`newMigrationFixture(t *testing.T) (*Journal,string)` creates a temp directory/journal with Task 2 options and writes a temporary spill using `os.WriteFile` inside the Go test, not repository shell writes. Original spill remains untouched; completion is a durable marker, not a required rename.

- [ ] Run `go test ./agent/internal/evidence -run TestImport -count=1` red.
- [ ] Implement single-writer import before new producers start. A completed marker prevents reimport; partial progress resumes at last committed input offset, recovering from journal records even if snapshot lags. Corrupt/oversized legacy records are preserved and quarantined or reported, never skipped silently. Import pauses with explicit migration-blocked health if capacity is exhausted. Do not change old backlog IDs on reenrollment. Preserve protected original backup indefinitely until explicit operator cleanup.
- [ ] Document backend-first deployment, 1% canary, correctness/health review before 10% then fleet rollout, monitoring server/local capacity and measured latency, stopping service before local recovery, uncertainty-window warning, and downgrade preservation. Enable durable mode by default only after Tasks 1–12 pass and backend capability is deployed; no automatic downgrade on an older server. Never edit a live config or publish a package during plan execution without deployment authorization.
- [ ] Rerun migration, startup, and configuration tests on both platforms. Commit checkpoint: `feat(agent): migrate legacy spill with restart-safe progress`.

### Task 12: Native CI, end-to-end fault harness, performance evidence

**Files:** Modify `.github/workflows/ci.yml`, `.github/workflows/windows-agent.yml`, `tests/windows/smoke-msi.ps1`; create `tests/evidence/{compose.yml,run.py,assertions.py,test_acceptance.py}`, `docs/operations/agent-evidence-validation.md`; add `agent/internal/evidence/benchmark_test.go`.

**Produces:** `python tests/evidence/run.py --scenario <name> --count 10000 --output <directory>` creates a uniquely named disposable Compose project, randomized host ports, per-run volumes, and a service fault-controller harness. Scenarios: `offline-restart`, `lost-response`, `redis-loss`, `worker-crash`, `quota`, `corruption`, `retention`. It starts only its own project; cleanup targets its exact resolved project/resources. Unit tests for assertions do not require Docker. Native Windows source tests remain separate from Linux-container backend tests.

- [ ] Write acceptance assertions before the harness. `assert_delivery(admitted: set[str], receipts: list[dict], documents: list[dict]) -> None` checks full ID-set equality and uniqueness, not merely counts. `assert_loss_visible(health: dict,reason: str) -> None` rejects a healthy state when the scenario injected a known loss. Record collection/receipt timestamps and crash boundaries for diagnosis.

```python
def test_duplicate_id_cannot_hide_missing_event():
    import pytest
    from assertions import assert_delivery
    with pytest.raises(AssertionError):
        assert_delivery({"a", "b"}, [{"event_id": "a"}, {"event_id": "a"}],
                        [{"event_id": "a"}, {"event_id": "a"}])
```

- [ ] Run `pytest tests/evidence/test_acceptance.py -q` red, then implement the equality checks and harness. Use SIGKILL/TerminateProcess for process-crash tests, not only graceful shutdown. Inject journal crash points via test helper subprocesses rather than production remotely configurable switches. Count only successful durable admissions in no-loss assertions; separately check loss counters for rejected producers.
- [ ] Extend Linux CI to compile both BPF objects and run `go test ./agent/... ./tests/agent/...`; add native Windows internal tests (Go 1.26.1+) and the disposable channel resume test. Preserve MSI install/enroll/flow/uninstall coverage. Add a separate backend acceptance job with PostgreSQL/Redis/Elasticsearch; always upload sanitized logs and bounded evidence artifacts. Maintain the separate API/worker pytest invocations from the existing CI fix.
- [ ] Add Go benchmarks for append sync latency, journal recovery, replay and compaction at 10,000 events, plus a one-hour sustained capture run on each native OS. Collect events/sec, p50/p95 append latency, CPU, peak memory, data/physical disk bytes, and hardware/filesystem details. Run `go test ./agent/internal/evidence -bench . -benchmem -run '^$'`; publish measurements, not invented targets. If measurements show unacceptable resource growth, hold rollout and revise with explicit evidence rather than weakening durability silently.
- [ ] Run every spec acceptance row and link its artifact in the validation document. Native Windows unavailable locally means this gate is pending CI, not passed by cross-build. Full correctness requires no missing successfully admitted IDs, one logical receipt/document per event within the dedup window, bounded budgets, and explicit health for every injected loss/gap. Commit checkpoint: `test(agent): gate evidence reliability on native fault recovery`.

## Self-review / spec coverage map

| Spec requirement | Tasks |
| --- | --- |
| Immutable IDs/timestamps, credentials excluded | 1, 5, 7 |
| Flush-before-admit, locks, torn/interior corruption, bounded memory | 2, 3, 12 |
| ACK checkpoint, compaction cursors, quarantine, pressure | 3, 4, 7, 10 |
| Local detection independent of delivery and retry replay | 4, 7 |
| File restart/rotation/glob/partial lines and source gaps | 8, 12 |
| Windows bookmarks, initial baseline, native handle safety | 9, 12 |
| Auth, duplicate digest, quota races, durable receipt | 5, 12 |
| Redis loss, worker concurrency, ES stable IDs, downstream repeat caveat | 6, 12 |
| Dead letter, retention, uncertainty hold | 3, 6, 7, 10, 12 |
| Persistent health, scoped UI/operator audit, file ACLs | 2, 3, 10 |
| Non-destructive migration, identity mismatch, backend-first activation | 2, 7, 11 |
| Equal OS gates, no dev DB destruction, measured performance | 12 plus test-environment constraints |

No agent implementation is represented as completed in this document. Any design change that weakens the approved receipt/flush contract requires review before execution proceeds.
