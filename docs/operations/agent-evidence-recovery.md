# Durable agent evidence: rollout and recovery

Durable evidence keeps every collected event in a local journal until the
server confirms a durable receipt. It is **off by default** on both sides
(`EVIDENCE_INGEST_ENABLED=false` on the server, `evidence.enabled: false` on
agents) and must stay off until the release gate (Task 12 of
`docs/superpowers/plans/2026-10-21-agent-evidence-reliability.md`) passes.
This runbook is for when it does.

## What the guarantee is

- At least once from a local durable append to the server inbox. Retries reuse
  the same event ID; Elasticsearch documents use a stable ID.
- Not exactly once: rules, alerts and SOAR actions can run again for an event
  whose processing was interrupted after detection.
- An event sent without a receipt for 30 days is **held**, not resent: past the
  server's receipt retention a resend could be processed twice.
- FIM events sent to `/api/fim` are not covered.

## Rollout order

1. **Backend first.** Deploy server-api and worker with the evidence code.
   Check: `GET /ready` returns `{"evidence": "disabled"}`; the `evidence_inbox`
   and `evidence_group_usage` tables exist; the worker logs no
   `evidence_dispatch_error`.
2. **Enable the server.** Set `EVIDENCE_INGEST_ENABLED=true` and restart
   server-api. Check: `/ready` returns `{"status": "ok", "evidence": "ready"}`.
   If it returns 503, the database is not durable (`fsync`,
   `full_page_writes`) or the schema is incomplete: fix that first. Heartbeats
   advertise `evidence_protocols: [2]` only while `/ready` is ok.
3. **Canary, about 1% of agents** (prefer one group, both OSes). Upgrade the
   agent, set `evidence.enabled: true` (see the commented block in the packaged
   `config.yaml`), restart. Agents keep sending nothing until the server
   advertises protocol 2.
4. **Review for at least a day before 10%**:
   - Agents page, Evidence delivery: every canary `Healthy`; investigate
     `Backlogged`, `Blocked`, `Degraded`, `Stale`.
   - Server inbox per agent: `processing` drains, `failed` stays 0.
   - Server budget: `SELECT group_id, payload_bytes FROM evidence_group_usage`
     well under `EVIDENCE_GROUP_BUDGET_BYTES` (1 GiB per group). Completed
     payloads are released after 7 days, so the budget must cover a week of
     evidence; raise it or the 429s will block agents.
   - Local budget: health `queued_bytes` well under `evidence.max_bytes`.
   - Latency: alert time minus event `collected_at` comparable to legacy mode.
   - Detection parity: the same rules fire as on legacy agents.
5. **10%, then the fleet**, repeating the review at each step.

Never enable the agent side against a server that does not advertise protocol
2 expecting a fallback: there is none. The agent keeps heartbeating, collects
into its journal and reports `Blocked (protocol_unsupported)` until the server
supports it.

## Upgrading an agent that has a legacy spill

On its first durable start the agent imports `buffer.spill_path`
(`/var/lib/siem-agent/spill.log`, `%ProgramData%\SIEMAgent\spill.log`) into the
journal before any collector starts:

- The spill file is **not modified or deleted**. Completion is a marker in the
  journal; a restart does not import again.
- Imported events are labelled `legacy_import` and get the import time as
  `collected_at` (the spill kept no original IDs or times). They may duplicate
  events the legacy agent already delivered.
- If the journal is full the import pauses (health source `legacy-spill`,
  `migration_blocked`), keeps its progress and resumes as delivery frees
  space; collection runs meanwhile.
- Entries over the event limit are counted as `legacy_import` loss; the
  original line stays in the spill.

Keep the spill until the canary review passes, then remove it by hand. **Do not
switch an agent back to legacy mode with the spill still present**: the legacy
sender replays and truncates it, sending the imported events a second time.

## Downgrading or disabling

1. Stop the service.
2. Copy the state directory aside (journal: `<state_dir>/evidence`).
3. Set `evidence.enabled: false` (or install the older package) and start.

Older agents and legacy mode never read or delete the journal, but nothing
delivers it either: undelivered evidence stays there until durable mode is
enabled again. Do not delete the journal while it holds undelivered events.

## Operator actions on parked evidence

Held (no receipt for 30 days) and quarantined (rejected by the server)
evidence stays in the journal and counts against its budget until resolved.
Stop the service first: the journal belongs to one process.

```
siem-agent -config <config> -evidence-list
siem-agent -config <config> -evidence-release <event-id> -reason "<why>"        # quarantined
siem-agent -config <config> -evidence-release <event-id> -reason "<why>" -yes   # held: may duplicate
siem-agent -config <config> -evidence-discard <event-id> -reason "<why>"
```

Run as root (Linux) or from an elevated prompt (Windows). Every action is kept
in the journal's audit trail (the last 64 are listed by `-evidence-list`).
Releasing held evidence can repeat its detections and automated responses.

Server-side failures (20 failed processing attempts) appear on the Agents page
as failed events and are retried there (`agents:manage`, audited), after
fixing the cause.

## Recovery situations

| Symptom | Meaning | Action |
| --- | --- | --- |
| `Blocked (protocol_unsupported)` | server not advertising protocol 2 | check `/ready`, `EVIDENCE_INGEST_ENABLED` |
| `Blocked (auth_blocked / pending_approval)` | token rejected or agent not approved | approve or re-enroll; the journal is kept |
| `Blocked (repeated_rejections)` | server rejects every record (validation bug) | fix the server; records were not quarantined past the first 5 |
| `Backlogged` | events waiting, sender retrying | check connectivity, server 5xx/429 (group budget) |
| `Degraded (capacity)` | local journal full; sources paused | restore delivery; never delete unconfirmed events to make space |
| `Degraded (journal_unavailable)` | journal could not open; collection blocked | see agent log: permissions, disk, NTFS requirement on Windows; for `corrupt` see below |
| `Degraded (storage_failure)` | a journal write or read failed | check the disk; restart once fixed |
| Unknown gaps > 0 | a file was rotated/truncated or a channel cleared while unread | expected occasionally; investigate if frequent |
| `Stale` | no heartbeat for two intervals | agent down or unreachable; the last state is shown |

### A corrupt journal (`journal_unavailable`, agent log says `corrupt`)

A torn tail (the last, incomplete record after a crash) is repaired at start
and its bytes are saved beside the segment. Damage *inside* the journal is
not repaired: the agent refuses to open it, changes nothing on disk, and
reports `Degraded (journal_unavailable)`. Verified by the `corruption`
acceptance scenario: the damaged segment's SHA-256 is identical after the
agent ran against it.

While it is in this state:

- nothing is delivered, including evidence admitted before the damage;
- file sources lose nothing permanently as long as the files stay on disk:
  the lines are still in the file and the cursor is in the preserved journal;
- non-replayable sources (process/network telemetry, local detection
  events) collected during the outage are dropped and **not counted**.

Recovery today:

1. Stop the agent. Copy the whole evidence directory somewhere safe: it is
   the only copy of undelivered evidence and of the cursors.
2. Get the agent log line naming the segment and offset, and keep it with the copy.
3. Moving the directory aside and starting the agent creates a new, empty
   journal. **This loses data silently:** a new journal has no cursors, so
   every configured file is treated as newly enabled and starts at its end.
   Lines the old journal held but had not delivered, and lines written while
   the agent was blocked, are skipped without a loss counter. Do it only after
   recording that window (from the last receipt the dashboard shows to the
   restart) as an evidence gap in the case or audit trail.

There is no salvage tool yet that imports the readable records and cursors
of a damaged journal into a new one; see
`docs/operations/agent-evidence-validation.md` (open items).
