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
scenario); all seven scenarios also passed at 10,000 lines in 40132159095
(`8e7ca2a`) and, with the salvage step in `corruption`, in 40172430150
(`4313ed6`). "Harness" checks by full set equality that each source line has
exactly one inbox receipt and one Elasticsearch document whose id is
`uuid5(agent_id, event_id)` of that receipt.

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
| Interrupted spill migration, torn tail, corrupt interior, simultaneous starts | `migration_test.go` (resumes after every interruption), `journal_recovery_test.go` (torn header keeps the exact suffix), `TestJournalLockAcrossProcesses`, `salvage_test.go` + `evidence_commands_test.go` (salvage keeps identities, cursors, holds and first attempts; the damaged journal is byte-identical afterwards; tests mutation-checked), harness `corruption`: the agent refuses the damaged journal without changing it, then `-evidence-salvage` restores collection and every line written while blocked or afterwards is delivered, the destroyed records are reported as a gap | passed | salvage tests run in `native-evidence` |
| Time past receipt retention / uncertainty window | `TestSenderHoldsAfterThirtyDayUncertainty` (operator hold, no blind resend); harness `retention`: payloads released after 7 days with their budget, pending rows untouched, receipts deleted after 30 days, all 5,500 documents kept | passed | sender test pending (gate) |
| MSI install in durable mode | `smoke-msi.ps1 -Durable`: delivery only through the durable endpoints, heartbeat carries evidence health | n/a | passed in 40132026970 and 40172461041 |

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

### One-hour sustained capture (run 40131140555)

`TestSustainedCapture`, one producer appending durably at a target of 200
events/s while a batch drainer delivers and compacts every minute. GitHub
runners, AMD EPYC 7763, 4 vCPUs; Linux ext4 root, Windows NTFS.

| | Linux | Windows |
| --- | --- | --- |
| Achieved rate | 200.0 ev/s (720,001 appended, 719,997 delivered) | **127.4 ev/s** (458,701 appended, 458,694 delivered): the target was not reached |
| Append p50 / p95 / p99 | 0.27 / 1.1 / 3.0 ms | 0.56 / **38.5 / 47.5** ms |
| Process CPU | 8.0% of one core | 25.8% of one core |
| Peak RSS | 38 MB | 29 MB |
| Peak journal on disk | 17 MB | 20 MB |
| Backlog during the run | 2-12 events | 1-12 events |

Heap (`HeapAlloc`, garbage included) ranged 3-17 MiB on both; RSS stayed
under 40 MB, so the hour shows no growth beyond the batch working set.

### One-hour sustained capture with group commit (runs 40173950482, 40173959289)

Same runners and test at `c77ba5c`, now committing every due event at once
(`AppendBatch`, as tailers and the Event Log source do), at 200 and 1000
events/s. Lag is the wait from an event being due to its admission.

| | Windows 200/s | Windows 1000/s | Linux 200/s | Linux 1000/s |
| --- | --- | --- | --- | --- |
| Achieved rate | **200.0** (was 127.4) | **1000.0** | 200.0 | 1000.0 |
| Appended / delivered | 720,000 / 719,993 | 3,599,999 / 3,599,967 | 720,001 / 719,991 | 3,600,001 / 3,599,970 |
| Mean events per commit | 3.2 | 26.9 | 1.0 | 1.16 |
| Lag p50 / p95 / max | 22 / 65 / 914 ms | 51 / 75 / 1,179 ms | 0.9 / 2.2 / 196 ms | 0.8 / 2.9 / 828 ms |
| Commit p50 / p95 | 13.1 / 41.3 ms | 25.7 / 41.9 ms | 0.28 / 1.6 ms | 0.25 / 0.51 ms |
| Process CPU (one core) | 27.6% | 40.0% | 8.2% | 18.7% |
| Peak RSS | 31 MB | 36 MB | 57 MB | 188 MB |
| Peak journal on disk | 21 MB | 42 MB | 12 MB | 42 MB |
| Backlog during the run | 1-11 events | 32-73 events | 3-10 events | 9-52 events |

Commits on NTFS still cost tens of milliseconds, but batches grow with the
load (27 events per flush at 1000/s), so the rate is held and the backlog
stays bounded instead of growing. Delivered trails appended only by the last
batch in flight when the hour ended.

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

1. While blocked on a corrupt journal (before an operator runs the salvage),
   non-replayable sources (process/network telemetry, local detection) are
   dropped without a count. Files lose nothing as long as they stay on disk.
2. Lag peaks of about one second appear on both OSes (max 0.8-1.2 s against a
   p95 of 3-75 ms), most likely segment rotation and checkpoint publication
   holding the journal lock. Acceptable for log evidence; not yet attributed.
3. Peak RSS was 188 MB on Linux at 1000 ev/s against 36 MB on Windows at the
   same rate. The heap rose and fell (10 to 104 to 79 MiB) with no growth
   trend, so no leak is indicated, but the difference is not explained yet.
4. Event Log tests on Windows run 2-6x slower since group commit (e.g. 1.2 s
   to 6.8 s); they pass, and file-tailer tests are unchanged. Not explained yet.

Resolved: Windows durable throughput. Before group commit one producer
reached only 127 of 200 ev/s on NTFS (p95 append 38.5 ms), because every event
paid its own flush. Group commit (`c77ba5c`) shares flushes between adjacent
admissions without changing what an admission means; the hour above holds 200
and 1000 ev/s on Windows.

Resolved: recovery from a corrupt journal used to be "move it aside", which
restarted every file at its end and skipped data silently.
`siem-agent -evidence-salvage -reason <why>` now replaces it with the readable
undelivered evidence and every cursor, keeps the damaged journal unchanged and
counts what was destroyed (`agent-evidence-recovery.md`).

Fixed along the way (found by these tests): the worker never recreated its
consumer group after Redis lost its data (`6286a99`); heartbeats reported a
backlog up to a minute old (`b8b37b3`); a batch the checkpoint reserve could
not hold was retried forever (`59d800e`).

## Gate status

**Passed on both OSes** at `a6f6c4b` (merged in #57): every acceptance row in
CI and the end-to-end harness (40173942640), native Windows journal, cursor,
bookmark and salvage tests plus MSI smoke in both modes (40176533352), and the
one-hour captures at 200 and 1000 ev/s on Linux and Windows.

The feature stays off by default. Turn it on in the order of
`agent-evidence-recovery.md`: server inbox first, then a few agents, watching
the Evidence delivery panel, before a wider rollout. Open items 1-4 are not
correctness gaps; keep watching 2 and 3 in the first deployments.
