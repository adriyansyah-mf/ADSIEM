# Agent evidence reliability — Windows and Linux

Date: 2026-10-21
Status: written specification approved by the user on 2026-10-21; implementation in progress, not released.
Scope: phase one of the enterprise-agent roadmap. This document is not a claim of enterprise EDR equivalence.

## 1. Outcome and boundaries

Use one Go agent with OS-specific collectors. Windows and Linux have equal acceptance criteria for durable collection, restart recovery, acknowledged delivery, and visible failure. They do not need identical sensors.

The delivery contract is **at least once from a successful local durable append to a durable server inbox**, with idempotent acceptance of retries. Elasticsearch evidence uses a stable document identity. Exactly-once rule evaluation, alerts, SOAR actions, and kernel capture are not promised.

The guarantee assumes working local persistent storage and PostgreSQL storage that honors flushes. It does not cover disk destruction, an administrator deleting state, or OS events overwritten before collection. Recoverable backlog must survive process crashes; unrecoverable gaps must be reported, not silently relabeled as successful delivery.

Excluded: response-action parity, new process sensors, full YARA, behavioral prevention, anti-tamper redesign, signed updates, automatic updates, and a general dashboard redesign. Existing task, flow, heartbeat, and FIM HTTP endpoints retain their own delivery semantics. FIM events sent directly to `/api/fim` are not covered by the new log-ingest guarantee.

## 2. Source-grounded starting point

Reviewed in worktree `.claude/worktrees/next-phase-roadmap`, branch `feat/enterprise-ui`. The graph generation is `2026-10-17T18:29:47Z`; that worktree is excluded from the graph, so findings below were checked in the actual source rather than inferred from the older index.

| Current implementation | Reliability consequence |
| --- | --- |
| `agent/internal/buffer/buffer.go`: bounded memory queue drops the oldest entry | Newly collected evidence can disappear before any durable write. |
| `agent/cmd/agent/main.go`: failed sends requeue and append to spill; `replaySpill` drains into memory | One event can have multiple copies; replay can exceed memory capacity. |
| `agent/internal/buffer/spill.go`: append has no explicit sync; `Drain` truncates before server ACK | Spill is not an acknowledged write-ahead queue. |
| `agent/internal/tailer/tailer.go`: file opens seek to EOF; cursor state is not persisted | Restart can skip lines written while the agent was down. |
| `agent/internal/winevent/subscribe_windows.go`: future-only subscription, no bookmark | Restart cannot recover retained events emitted while offline. |
| `server-api/app/api/routes/ingest.py`: returns `queued` after Redis enqueue; unapproved agents receive `pending_approval` | HTTP success alone is not a durable evidence receipt. |
| `server-api/app/services/ingest.py`: approximate stream length trimming | A Redis stream entry is not an indefinite retention guarantee. |
| `worker/worker/consumer.py`: generates a new UUID per processing attempt | Retrying the same evidence can create another Elasticsearch document. |
| `agent/internal/heartbeat/heartbeat.go`: resets dropped count before sending heartbeat | A failed heartbeat can lose the report of dropped events. |

## 3. Chosen architecture

```text
collector + source cursor
        -> local journal append + flush
        -> sender retries immutable event
        -> authenticated API: PostgreSQL inbox transaction commits
        <- explicit matching durable receipt
        -> local ACK checkpoint + eventual segment reclamation

PostgreSQL inbox -> Redis wake-up/reference -> worker -> stable ES document
       ^               retry dispatch             -> detection pipeline
       +----------- unfinished work remains here until completed
```

Two additions are essential: a local acknowledged journal and a server durable inbox. The latter is a deliberate backend extension of phase one: changing only the agent cannot make the current Redis response a durable acceptance guarantee.

Alternatives considered:

- Improve the existing spill only: smaller change, but still leaves pre-spill loss, uncertain ACKs, and unstable identities.
- Local SQLite queue: transactional convenience, but adds an embedded database dependency and cross-platform packaging surface. Prefer a narrowly scoped append-only journal with explicit recovery tests for this phase.
- Redis-only receipt/dedup: simpler backend, but acceptance would depend on Redis persistence, dedup atomicity, and stream-retention policy. Keep Redis as transport, not the durable owner of new-protocol evidence.

## 4. Local journal and collection contract

Introduce `agent/internal/evidence` as the shared envelope/journal boundary. Producers currently writing log entries to the memory buffer must submit through this boundary; putting a new queue behind the current drop-oldest buffer is insufficient.

An immutable envelope contains protocol version, random UUID `event_id`, agent identity, `collected_at`, hostname, log type, location, raw message, and optional source identity/cursor. Source event time is separate when available. Retries never regenerate the ID or collection timestamp. Agent credentials are attached only at send time and are not stored in records.

The journal uses length-delimited, versioned, checksummed records and bounded segments. Each accepted record includes its source cursor. `Append` returns success only after the record has been flushed to stable storage. Group commit is allowed, but all callers in the group wait for that flush. The memory structure is an index/cache, never the sole owner of accepted evidence.

Journal rules:

1. Only one process may open a journal for writing; a second instance reports a state-lock error.
2. Sender reads without deleting. Only a valid matching durable server receipt advances a durable local ACK checkpoint.
3. Reclaim only segments wholly covered by a persisted ACK checkpoint. Preserve the latest committed source cursors in a durable snapshot before removing their journal records.
4. Checkpoint/snapshot replacement and segment creation/reclamation must use OS-appropriate durable filesystem operations. Windows behavior must be tested natively, not assumed from Unix rename semantics.
5. A torn final record is isolated on recovery; valid preceding records are replayed. A corrupt interior record puts the affected journal into degraded/manual-recovery state, preserves the original bytes, and never silently skips later records.
6. Shutdown stops producers, finishes outstanding append/flush operations, and closes the journal. Sending is time-bounded; unsent records remain on disk. There is no destructive shutdown drain.

Local detection observes newly admitted live events independently of network success. Sender retries and ordinary journal replay must not repeatedly feed local detection. Persisting the detector's windows across crashes is outside this phase; report that boundary rather than claim exactly-once local decisions.

### Storage defaults and pressure

Proposed defaults: journal under `agent.state_dir/evidence`, 1 GiB total evidence budget, 16 MiB segments, 1 MiB maximum encoded event, and a 16 MiB reserved control/health budget included in the total. Configuration rejects invalid sizes and paths outside the configured state policy. Linux defaults derive from `/var/lib/siem-agent`; Windows derives from `%ProgramData%\SIEMAgent`, not a Unix fallback path.

Never evict unacknowledged evidence to make space. Pause replayable sources at capacity; resume when ACK reclamation frees space. Non-replayable producers must not block kernel readers indefinitely: reject their append explicitly and count known lost events. Oversized records are rejected with source, size, and reason, not payload contents; do not silently truncate them. Keep bounded memory and health reporting available during disk pressure.

On disk-full or write failure, do not fall back to a memory-only queue while advertising durable mode. Keep heartbeat/service operation alive in `degraded` state. Preserve counters in reserved state when possible; complete storage failure can itself prevent durable loss accounting and must be disclosed as an unknown interval.

Implementation storage boundary (recorded during Task 2): the initial Windows durable implementation supports a local fixed NTFS volume with the service's existing SYSTEM/admin access to flush namespace transitions. Ordinary appends flush only the journal file; namespace changes additionally flush the volume. ReFS, network/removable storage, and unavailable volume-flush access return an explicit unsupported state. No privileges are granted automatically. Native elevated Windows tests and namespace-transition latency measurements must pass before rollout; this restriction is not a claim of support for every Windows filesystem.

## 5. Source resume behavior

### Windows Event Log

Use a bookmark per configured channel. Update/render a bookmark while the native event handle is valid, and include the resulting cursor in the same journal record as the formatted event. Advance the committed cursor only after durable append, not after enumeration or HTTP send.

On restart, reconstruct the last committed cursor from snapshot plus journal, then subscribe after it with strict bookmark handling. Existing `FormatXML` output remains compatible with the Windows decoders. Access-denied, render, and format failures become explicit source-health failures, not silent `continue` paths.

For a first-ever subscription, preserve the existing future-only policy, but establish and persist a baseline against retained channel history before declaring the source ready. Events predating that baseline are an intentional initial-collection boundary. If the channel is empty, record an empty baseline and subscribe from the oldest available event on subsequent startup so events created during downtime are recoverable.

If a saved bookmark is stale, missing, or invalid after clearing/rollover, record a gap with channel, last known cursor, current bounds where available, and unknown loss count unless it can be established. Recover from the oldest retained event under a new source generation. Do not fabricate an exact count or silently jump to future events. Event Record ID alone is not a globally unique identity across channel resets.

### File logs on both OSes

Persist source definition, platform file identity, generation, and the byte offset immediately after each complete admitted line. Account for buffered reads: the file descriptor's read-ahead offset is not the committed line offset. Keep incomplete lines pending until completed; do not turn every EOF fragment into a separate event.

First-ever enablement starts at a persisted EOF baseline, preserving the current no-history-backfill policy. Restart resumes the committed cursor. Rotation drains the already-open old file and starts a newly created replacement at offset zero. Glob handling tracks identities/cursors for configured matching files rather than selecting only the newest and skipping intermediates.

Resume a rotated identity when it can still be found in the configured source scope. If it is gone, or a truncation invalidates the saved offset, report the potential gap and start a new generation at the beginning of the available replacement. Copytruncate can destroy unread bytes; do not claim to recover them. Permission/read errors preserve the last committed cursor and expose degraded source health.

## 6. Versioned ingest and explicit receipts

Keep `/api/ingest/log` unchanged for legacy agents. Add `/api/ingest/v2/log` for the new envelope and advertise support in heartbeat capabilities. New agents must not silently downgrade to the legacy endpoint or treat an arbitrary HTTP 2xx as an ACK.

Authenticate with the existing agent-token mechanism. Agent/group/hostname attribution is resolved from the authenticated database agent; reject identity mismatches. The dedup key is `(authenticated agent_id, event_id)`. Store a canonical digest of immutable client evidence fields: reuse of an ID with different evidence is a conflict, not a duplicate success. Server-derived group changes do not change that digest or reattribute an existing receipt.

For approved agents, insert a PostgreSQL inbox row with a unique dedup key, payload digest, server receipt time, original group attribution, and pending processing state. Return a receipt only after commit with synchronous commit enabled and durable PostgreSQL configuration. If that durability configuration cannot be established, refuse new durable-protocol acceptance and expose readiness failure. A duplicate with the same digest returns the existing receipt without enqueueing a second logical event.

Successful response: HTTP 202 with `protocol_version: 2`, matching `event_id`, `status: accepted` or `duplicate`, and a stable `receipt_id`. This means durable inbox acceptance, not completed detection. A lost response after commit is resolved by retrying the same ID.

Sender error policy:

| Result | Agent behavior |
| --- | --- |
| Valid matching durable receipt | Persist local ACK, then allow reclamation. |
| Network error, timeout, 408, 429, or 5xx | Keep event and retry with bounded exponential backoff and jitter; honor bounded `Retry-After`. |
| Unapproved agent | API returns retryable 403 with `pending_approval`; retain backlog and slow retries. |
| Other 401/403 | Retain evidence, expose auth-blocked health, retry slowly; no automatic reenrollment or state deletion. |
| 400/409/413/422 permanent record error | Durably quarantine the affected record with reason, expose operator action, and continue other valid records. |
| 404/unsupported protocol or malformed/mismatched 2xx | Retain evidence and report protocol-blocked health; no downgrade. |

Quarantine remains inside the storage budget and is not delivery success. Removing it requires an explicit operator action with an audit record. An authenticated API must impose request-size and per-group inbox-capacity limits before acceptance; pressure returns retryable 429/503 without a receipt. Initial inbox payload budget is 1 GiB per group, enforced transactionally across replicas and configurable for deployment capacity.

## 7. Durable inbox to existing worker

The inbox owns unfinished evidence; Redis messages are wake-up references to inbox IDs. A dispatcher scans eligible unfinished rows and reissues references with backoff capped at 60 seconds. Redis loss, trimming, or an ACK must never delete the authoritative inbox payload. Existing legacy messages continue through their existing path.

For a new-protocol reference, a worker locks its inbox row before processing. A completed row is a no-op; concurrent duplicate references cannot process it simultaneously. On success, commit completion in PostgreSQL before acknowledging the Redis reference. Crash/rollback leaves the inbox available for retry. Avoid transactions spanning an entire batch; bound each processing attempt and expose lock/processing latency.

Use a stable UUID derived from authenticated agent identity plus event ID as the Elasticsearch document ID and the event ID passed to alert creation. On retry, update the same evidence document. Preserve the original document timestamps and receipt attribution. Do not skip the rest of processing merely because the Elasticsearch document already exists: a previous attempt may have crashed after indexing but before detection.

Rule evaluation, alert suppression, UEBA counters, and SOAR are not a distributed transaction with Elasticsearch and PostgreSQL. They can repeat after a worker crash. This phase does not promise their exactly-once behavior or introduce a new autonomous-response guarantee. Ordinary agent HTTP retries must not create multiple logical inbox events; crash-repeated downstream side effects remain a documented separate hardening item.

Retry failed processing with bounded backoff. After 20 failed attempts, retain the payload in a PostgreSQL dead-letter state, expose the error and backlog count, and require an audited operator retry after remediation. Never delete failed/unprocessed payloads on age alone. Use existing admin RBAC and mandatory group scoping for inspection/retry operations.

Completed payloads may be removed after seven days; retain receipt identity and digest for 30 days after completion. Agent automatic retry has a maximum uncertainty window of 30 days from its persisted first send attempt. If no receipt can be established within that window, move the record to operator-held state instead of blindly resending beyond the dedup contract. Offline events never attempted are not aged out. Operator replay beyond the window explicitly warns of possible duplicate downstream processing.

New models/migration helpers belong in the API startup migration path under the existing advisory lock, not new bootstrap-only tables in `db/init.sql`. Worker mappings must match the API-owned schema.

## 8. Health and security

Heartbeat gains an optional versioned evidence-health object: durable mode/state, queued events/bytes, oldest queued timestamp, last durable receipt time, retries, quarantine count, known loss counters by bounded reason, unknown-gap count, and per-source resume status. Persist cumulative counters; a failed heartbeat does not reset them. Keep the legacy `buffer_dropped` field for old agents without presenting it as the whole new health model.

Persist the latest health snapshot with agent metadata and expose it through the existing scoped agent detail API/UI. Show `healthy`, `backlogged`, `blocked`, or `degraded`, including reason and timestamp; an ordinary online heartbeat must not imply evidence delivery is healthy. Report health independently of the evidence queue, with structured local logging as an additional fallback. Do not use raw paths/event IDs as unbounded Prometheus labels.

Journal/cursor/quarantine files contain sensitive logs: restrict to the service identity and administrative principals using Linux permissions or Windows ACLs. Do not store tokens in them or log raw rejected events. Encryption at rest depends on host/storage protection in this phase; no custom cryptography. Deleting/re-enrolling an agent must not silently attach its old journal to a different identity; identity mismatch blocks sending pending operator resolution.

## 9. Compatibility and rollout

Deploy schema, API capability/endpoint, dispatcher, and worker handling before upgrading agents. Enable durable mode only after server capability validation. If the server is old, continue heartbeats and report blocked delivery while preserving locally accepted events. Keep release tagging/publishing separate from implementation approval.

Migrate an existing spill non-destructively: freeze the legacy writer, import into the journal, flush, and durably record migration progress before marking the old spill imported. Recovery must distinguish a completed import from a partial one so retrying migration does not append the whole spill again. Preserve a protected backup until operator-approved cleanup. Old spill copies may already be duplicates and have no original event IDs/timestamps; label them as legacy imports and do not claim retrospective deduplication.

Do not run old and new queue writers simultaneously. Downgrades must not consume/delete the new journal; the runbook requires stopping the service and preserving its state first. New-protocol receipt retention, server disk budgets, and backlog growth must be monitored during a staged rollout before broad deployment.

## 10. Acceptance tests — same release gate for both OSes

Tests use temporary state directories and disposable PostgreSQL/Redis/Elasticsearch instances. No development schema resets. Windows-native tests are mandatory; cross-compilation alone is not evidence of bookmark or filesystem durability.

| Scenario | Required evidence |
| --- | --- |
| Collect 10,000 numbered events with API offline, restart agent, restore connectivity | Every successful durable append reaches one logical inbox event and one ES document; IDs/timestamps remain stable. |
| Inject crashes before/after append flush, cursor commit, API commit, local ACK commit, and compaction | No acknowledged data disappears; ambiguous delivery retries the same ID; cursor never advances past durable admission. |
| Drop HTTP response after inbox commit; retry concurrently through two API replicas | One inbox row/receipt, matching retries succeed; changed payload under same ID conflicts. |
| Restart Redis or trim all wake-up messages | Unfinished PostgreSQL payloads are redispatched and processed without agent resend. |
| Crash worker after ES indexing and before inbox completion | Retry uses the same ES document; test documents the permitted repeated detection boundary. |
| Fill local and server quotas; inject disk-full/permission/sync errors | No oldest-unacknowledged eviction; replayable sources pause; counters/blocked health remain visible; rejected records get no receipt. |
| Restart Windows service with retained events written while stopped | Bookmark replay recovers events after the committed baseline without a future-only gap. |
| Clear/roll over a test Windows channel and inject format/render failure | Explicit gap/source-health indication; recover retained events without fabricated loss counts. |
| Restart file tailing, rename rotation, multiple glob arrivals, copytruncate, missing old identity, partial/oversized line | Correct committed offsets and generation changes; loss/invalid-input boundaries are explicit. |
| Failed heartbeats, unapproved agent, expired token, unsupported server, wrong/malformed receipt | No false ACK or counter reset; backlog survives and health explains the block. |
| Interrupted spill migration, torn tail, corrupt interior journal, simultaneous agent starts | Repeatable recovery without destructive import/replay; corrupted data is preserved for inspection. |
| Advance time past receipt retention/uncertainty window | Unconfirmed records become operator-held, not silently discarded or blindly resent. |

CI must execute new internal Go journal/source tests plus the external agent suite on native Linux and Windows, preserve existing Windows decoder tests, and run API/worker suites in separate interpreters to avoid their independent Prometheus registries colliding. Record throughput, append latency, CPU, memory, and disk amplification for both platforms; no benchmark number is asserted before measurement. Release acceptance requires passing correctness tests and publishing these measurements with test environment details.

## 11. Review and subsequent work

This specification intentionally trades additional disk writes and a small PostgreSQL evidence inbox for a defensible receipt contract. It does not turn PostgreSQL into the long-term event-search store: Elasticsearch remains that store, and completed inbox payload retention is short.

After written-spec approval, create an implementation plan with separable, testable increments: local journal/envelope, collector resume, versioned durable ingest/worker integration, health/migration, and native OS fault testing. The existing Prometheus CI isolation fix remains a separate change. No response/prevention feature should be bundled into this phase.

### Primary technical references

- [Microsoft: bookmarking events](https://learn.microsoft.com/en-us/windows/win32/wes/bookmarking-events) — native bookmark lifecycle and resume APIs.
- [Microsoft: event subscription flags](https://learn.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_subscribe_flags) — strict missing-bookmark handling and subscription modes.
- [PostgreSQL 16: write-ahead log configuration](https://www.postgresql.org/docs/16/runtime-config-wal.html) — durable commit depends on WAL/fsync and synchronous commit settings.
- [Microsoft: FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers) — file/volume flush access and write-through metadata considerations for the Windows storage implementation.
