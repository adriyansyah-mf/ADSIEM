# Endpoint Agent Production Improvement Roadmap

Status: proposed only — no agent, API, database, or dashboard behavior is changed by this document.

## Current baseline

The Go endpoint agent already enrolls with the API, tails configured logs, receives heartbeat-driven configuration, performs FIM and hygiene collection, and accepts live-response tasks. It uses a bounded in-memory ring buffer, exponential retry, `X-Agent-Token` authentication, and HTTPS support with a temporary self-signed bootstrap escape hatch.

This baseline is suitable for lab and small deployment use. Production operations need durable delivery, stronger device identity, richer fleet visibility, and safer task execution.

## Outcomes

1. Do not silently lose accepted endpoint evidence during network loss, agent restart, or server retry.
2. Make every agent's operational condition explainable from the fleet UI and API.
3. Treat every configuration change and response task as authenticated, replay-safe, auditable control-plane data.
4. Roll out agent binaries safely and recover from a failed rollout quickly.
5. Keep endpoint response actions explicitly approved, constrained, attributable, and reversible where technically possible.

## Delivery sequence

| Priority | Change | Scope | Observable outcome |
|---|---|---|---|
| P0 | Durable event spool and delivery acknowledgement | Agent + ingest API | Events survive restart; a persisted item is removed only after a server acknowledgement; duplicates are idempotently ignored. |
| P0 | Fleet-health telemetry | Agent + heartbeat API + Agents UI | Operator sees queue depth, oldest buffered event, drops, send latency, collector errors, and last successful ingest. |
| P0 | Device trust and signed control plane | Agent + API + PKI/settings | Per-agent certificate identity, certificate rotation/expiry, signed config/task envelopes, nonce and expiry checks. |
| P1 | Safe response-task runner | Agent + SOAR/API | Explicit task lifecycle, approval reference, capability checks, bounded execution, artifact hashes, rollback outcome. |
| P1 | Capability and policy inventory | Agent + API + Agents UI | Fleet view shows OS/version, enabled collectors, required privileges, effective policy/config hash, and drift. |
| P1 | Managed upgrade lifecycle | Agent + API + UI + release pipeline | Canary cohorts, package signature verification, staged rollout, health gate, automatic halt, and rollback. |
| P2 | Local privacy and data-quality controls | Agent + decoder/ingest | Source-level allow/deny filtering, redaction, source health, and rate controls before sensitive data leaves the host. |

## P0-A: Durable event spool and delivery acknowledgement

Replace the restart-volatile in-memory buffer with a bounded, permission-restricted on-disk write-ahead spool. The recommended implementation is an embedded transactional store such as bbolt with one durable record per event envelope.

Each envelope carries a generated immutable event ID, agent ID, sequence number, capture timestamp, payload hash, source identity, and retry metadata. The sender removes an envelope only after the ingest endpoint returns a durable acknowledgement for that event ID. The API stores or caches recently accepted IDs within a retention window so retrying after a lost response cannot create duplicate raw logs, events, or alerts.

Backpressure policy is explicit: preserve critical source classes first, cap by both event count and bytes, expose the oldest queued event age, and record a permanent loss counter with a machine-readable reason. The agent does not claim guaranteed delivery when the bounded spool is full; it reports evidence loss immediately.

Acceptance criteria:

- Kill and restart the agent during a server outage; persisted events are sent in capture order after reconnect.
- Drop the API response after persistence; the agent retries and the server records one logical event.
- Fill the spool; the UI/API report depth, byte usage, oldest age, and every loss decision.
- A corrupt spool is quarantined with an operator-visible recovery action, never silently discarded.

## P0-B: Fleet-health telemetry

Extend heartbeat and the agent health model with operational, not merely liveness, data:

- `spool_depth_events`, `spool_depth_bytes`, `spool_oldest_age_seconds`, and categorized drop counters;
- last send success/failure, rolling delivery latency, retry count, and last ingest acknowledgement;
- agent version/build, config hash, certificate expiry, uptime, and restart reason;
- collector-level state for log tailers, FIM, hygiene, process execution, and task runner;
- local CPU, memory, disk pressure, and clock skew as health signals.

The fleet UI gets a health score with an explainable breakdown rather than a single online/offline dot. An agent detail view should make the next action obvious: reconnect, inspect a blocked collector, free spool space, update a stale binary, rotate a certificate, or approve a pending response task.

## P0-C: Device identity and control-plane integrity

The current token enrolment flow remains the one-time bootstrap path, but production transport moves to a per-agent client certificate issued by the platform CA. The agent validates the server certificate against a configured CA or pin; `insecure_skip_verify` remains development/bootstrap-only and must be surfaced as a critical fleet risk when enabled.

Server configuration and task payloads are signed envelopes containing `task_id` or `config_version`, issued/expiry timestamps, nonce, signing key ID, body hash, and signature. The agent validates signature, expiry, target agent, capability, and replay state before acting. Certificate/key rotation is automatic before expiry and revocation takes effect at the next control-plane contact.

## P1-A: Safe response-task runner

Unify legacy SOAR actions and direct agent tasks behind a task state machine:

```text
requested → approval_required → approved → dispatched → acknowledged
          → running → succeeded | failed | timed_out | cancelled | rolled_back
```

Every destructive action links to the approval actor, reason, immutable input hash, agent capability check, execution timeout, output/artifact hashes, and rollback reference. The agent enforces a narrow allowlist of task types and validates parameters at its trust boundary. Artifact collection streams hashes and size limits; it does not permit arbitrary host command execution.

This task also resolves the currently documented legacy SOAR agent-task mismatch before new automation is layered on it.

## P1-B: Capability, policy, and upgrade management

Agents publish a signed capability manifest: OS/kernel, architecture, installed agent version, enabled collectors, supported response actions, required privileges, and current policy/config hash. The server calculates drift against the intended policy and makes unsupported actions unavailable in the UI.

Upgrades use signed release manifests and declared rollout cohorts. A canary cohort must remain healthy for a configured soak period before the next cohort starts. Health regression, failed startup, delivery loss, or collector failure automatically halts the rollout; rollback restores the last verified package/config pair.

## P2: Local privacy and data-quality controls

Add per-source filtering and redaction before queuing an event, with audit-safe counters for withheld data. Each source reports parsing/tailing state, last observed line/time, rotation errors, and rate pressure. The operator can distinguish an idle host from a broken collector without exposing filtered secrets.

## UI contract for the Agent Fleet

The AI SIEM redesign should make the fleet a first-class operational surface:

- **Fleet overview:** total/healthy/degraded/offline, ingestion lag distribution, version/config drift, pending approvals, and source coverage.
- **Agent row:** health score with textual reason, last acknowledgement, spool state, policy version, installed version, enabled capabilities, and permitted quick actions.
- **Agent detail:** evidence-delivery timeline, collector diagnostics, FIM/hygiene context, active tasks, approval/audit history, and remediation guidance from the AI copilot.
- **AI guardrails:** recommendations cite observed telemetry and never dispatch destructive work without the existing approval boundary.

## Non-goals for the first pass

- Endpoint EDR kernel telemetry or full arbitrary remote shell.
- Replacing all existing ingestion protocols at once.
- Encrypting all local log payloads independently of host disk encryption; spool file permissions and operational key handling ship first.
- Autonomous destructive remediation without approval.

## Implementation boundaries and verification

This roadmap becomes several independently releasable plans. Each phase requires red/green unit tests, a real-service integration test, an interrupted-network/restart scenario, security review of the control plane, and UI visual QA at 375px, 768px, and 1280px. Every phase must update `CHANGELOG.md` and `docs/IMPLEMENTATION_STATUS.md` with completed work, remaining work, evidence, and limitations.
