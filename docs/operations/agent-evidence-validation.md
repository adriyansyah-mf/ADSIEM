# Durable agent evidence: validation record

Evidence for the release gate in
`docs/superpowers/specs/2026-10-21-agent-evidence-reliability-design.md` §10.
Every row links what proves it. **Rollout stays on hold** (`evidence.enabled:
false`, `EVIDENCE_INGEST_ENABLED=false`) until every row below is *passed* on
both operating systems; see [Gate status](#gate-status).

Branch `feat/agent-evidence`. CI: `.github/workflows/ci.yml` (Linux Go tests,
Python suites, `evidence-acceptance` matrix), `.github/workflows/windows-agent.yml`
(native Windows tests, MSI smoke in legacy and durable mode, sustained capture
on dispatch).

## How to reproduce

```bash
# journal, sender, tailer, cmd (Linux; eBPF objects first)
make -C agent bpf && go test -race ./agent/... ./tests/agent/...
# end-to-end under faults: one disposable Compose project per scenario
python tests/evidence/run.py --build --scenario offline-restart --count 10000 --output out/offline-restart
# measurements (use a real disk: /tmp is often tmpfs)
TMPDIR=/path/on/disk go test ./agent/internal/evidence -bench . -benchmem -run '^$'
EVIDENCE_SOAK=1h EVIDENCE_SOAK_REPORT=soak.json go test ./agent/internal/evidence -run TestSustainedCapture -timeout 0
```

Windows: `./tests/windows/evidence-resume.ps1` (elevated) and
`./tests/windows/smoke-msi.ps1 -Msi <msi> [-Durable]`.

## Acceptance rows

Harness numbers are from CI run 40131345114 (`a34c6e2`, 5,000 lines per
scenario; CI now runs 10,000). "Harness" checks by full set equality that each
source line has exactly one inbox receipt and one Elasticsearch document whose
id is `uuid5(agent_id, event_id)` of that receipt.

| Spec row | Evidence | Linux | Windows |
| --- | --- | --- | --- |
| 10,000 events with API offline, agent restart, reconnect | harness `offline-restart` (proxy down at 20%, SIGKILL agent at 50%, restored at 80%): 5,000/5,000 documents and receipts, stable ids | passed (5k); 10k pending next CI run | file/journal path native: `native-evidence` |
| Crashes around append flush, cursor commit, API commit, local ACK, compaction | `checkpoint_ack_crash_test` (26 ACK boundaries), `checkpoint_crash_test` (30 compaction boundaries), `checkpoint_recovery_crash_test` (12 cleanup boundaries), `journal_process_test` (abrupt exit, concurrent admissions), harness SIGKILL of agent and worker | passed | pending: evidence package timed out (see gate) |
| Lost response after commit; retries through two API replicas; changed payload conflicts | harness `lost-response`: 12 responses dropped after commit, round robin over `api`/`api2`, 5,000 receipts, none duplicated; `tests/server-api/test_evidence_batch.int.py` (duplicate, 409 on changed payload, repeated id in one batch) | passed | n/a (server) |
| Redis restart or lost wake-ups | harness `redis-loss` (SIGKILL, Redis returns empty): 5,000/5,000. Found a bug: the consumer never recreated its group after `NOGROUP` and stopped processing until restarted; fixed in `6286a99`, regression test `tests/worker/test_consumer_redis_loss.py` (red before, green after) | passed | n/a |
| Worker crash between indexing and completion | harness `worker-crash` (SIGKILL twice): 5,000/5,000, document ids stable; repeated detection after such a crash is the documented boundary (`worker/worker/evidence_inbox.py`) | passed | n/a |
| Local and server quotas, disk/sync errors | server: harness `quota` (budget 400,000 B: usage 399,816 B, 696 accepted, the rest got 429 and no receipt, sender reported `retrying/status_429` with the backlog; all delivered once capacity returned). Local: `journal_limits_test`, `publisher_loss_test`, `journal_recovery_test` (sync failure), `migration_test` (capacity) | passed | journal tests pending (gate) |
| Windows service restart with events written while stopped | `TestNativeResumeAfterBookmarkExactlyOnce`, `TestNativeDurableEventLogResumeExactlyOnce` | n/a | passed in run 40109721243; re-run pending |
| Cleared/rolled-over channel, render/format failure | `TestNativeClearedChannelIsAGap`, `TestDurableEventLogClearedChannelIsAGapAndANewGeneration`, `TestRenderAndFormatFailuresAreReportedNotSkipped`, `TestDurableEventLogUnrenderableEventIsCountedNotSkippedSilently` | n/a | passed in run 40109721243; re-run pending |
| File restart, rename rotation, globs, copytruncate, missing identity, partial/oversized lines | `agent/internal/tailer/durable_file_test.go` (+ `_windows_test.go`), inode-reuse fingerprint (`20d2de6`) | passed | pending (gate) |
| Failed heartbeats, unapproved agent, expired token, unsupported server, wrong receipt | `sender_test.go`, `sender_batch_test.go` (unmatched, reordered, bad receipt, wrong status: nothing acknowledged), `test_evidence_batch.int.py` (403 pending approval), `cmd/agent/evidence_test.go` (waits for protocol 2) | passed | pending (gate) |
| Interrupted spill migration, torn tail, corrupt interior, simultaneous starts | `migration_test.go` (resumes after every interruption), `journal_recovery_test.go` (torn header keeps the exact suffix), `TestJournalLockAcrossProcesses`, harness `corruption`: the damaged segment's SHA-256 is unchanged and health says `degraded/journal_unavailable` | passed, **with an open item** (below) | pending (gate) |
| Time past receipt retention / uncertainty window | `TestSenderHoldsAfterThirtyDayUncertainty` (operator hold, no blind resend); harness `retention`: payloads released after 7 days with their budget, pending rows untouched, receipts deleted after 30 days, all 5,500 documents kept | passed | sender test pending (gate) |
| MSI install in durable mode | `smoke-msi.ps1 -Durable`: delivery only through the durable endpoints, heartbeat carries evidence health | n/a | pending: first run failed on the test's own setup (fixed in `ed68acc`) |

## Measurements

Local machine: Intel Core Ultra 7 155U (14 threads), WD SN560 NVMe, ext4,
Linux 7.1.5, Go 1.26.5. GitHub runners for the sustained capture.

| What | Result |
| --- | --- |
| Append, durable (frame + flush), no concurrent delivery | p50 0.49 ms, p95 0.83 ms, flat with backlog size |
| Append while a batch drainer delivers (90 s, 200 ev/s) | p50 0.84 ms, p95 4.9 ms, p99 6.9 ms (measured while Docker builds loaded the disk; redo in the 1 h capture) |
| Recover 10k-event journal at open | 145 ms |
| Replay 10k, one event per request | 59.7 s (~167 ev/s): a checkpoint publication (fsync) per attempt and per ACK |
| Replay 10k, batches of 200 | 0.50 s (~19,900 ev/s) |
| Compact 10k delivered | 62 ms |
| Health snapshot, 10k backlog | 3.5 ms (was 49 ms while it scanned the journal) |
| Health snapshot counting, 2.6M events | 43 ms (was ~13 s projected, under the journal lock, once a minute) |
| Index RAM per retained event | 52-84 B (power-of-two map growth): 80 MiB at 1M, 160 MiB at 2.6M (a full 1 GiB journal) |
| CPU, 200 ev/s sustained with delivery | 8.5% of one core, peak RSS 36 MB (30 s local run) |
| 1 h sustained capture, Linux and Windows | pending: run 40131140555 |

### Corrections to earlier numbers

- Early append and replay figures were taken on `/tmp`, which is tmpfs here:
  fsync costs nothing there, so they showed only scanning cost. All figures
  above are on ext4.
- The first estimate of index memory (~150 MB at a full journal) was low; the
  measured unpacked index was ~225 MiB. Packing positions into 12 bytes brought
  it to 128 MiB; adding the collection second (needed for cheap health
  snapshots) makes it 160 MiB.
- The first capture report said 34% CPU: `runtime/metrics` counts time blocked
  in fsync. The profile and `getrusage` give 7-8.5%.

## Open items

1. **Recovery from a corrupt journal loses data silently.** The agent refuses
   to open a journal damaged inside a segment and preserves it, as required.
   But the only way back to collecting is to move the journal aside, and a new
   journal has no cursors, so every file restarts at its end: undelivered lines
   and lines written while blocked are skipped with no loss counter. While
   blocked, non-replayable sources are dropped uncounted. Needs a decision: a
   salvage command (import readable records and cursors into a new journal,
   counting what could not be read), and/or a recorded gap when a journal is
   replaced. Procedure until then: `agent-evidence-recovery.md`.
2. Append p95 rises to ~5 ms while delivery runs: checkpoint publications for
   attempts and receipts hold the journal lock through their fsyncs. Not a
   correctness issue; measure in the 1 h capture before deciding.

## Gate status

Not passed. Pending:

- Windows `native-evidence`: the evidence package exceeded the 10-minute test
  timeout in run 40131010666 (it took 380 s in 40109721243). Diagnostics added
  (`00f4ea8`); re-running in 40132026970.
- Windows `msi-smoke-durable`: re-running in 40132026970.
- 1 h sustained capture on Linux and Windows: run 40131140555.
- Harness at 10,000 lines per scenario: next CI run.
- Open item 1: decision on corrupt-journal salvage.
