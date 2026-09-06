# AD-SIEM Implementation Status

Last updated: 2026-09-06

This document is the durable delivery ledger. Every implementation turn must update the Completed, In Progress, Remaining, Verification, and Known Limitations sections together with `CHANGELOG.md`.

## Completed

### Sigma and detection

- PySigma-compatible validation, matching, condition parsing, and Lucene hunting.
- Sigma YAML import/export, repository import, quality score, approval, revisions, diff, and rollback.
- Threat Hunt UI with Sigma editor, validation, query preview, results, pagination, and responsive controls.
- Active Sigma match context flows into alert persistence and AI triage.
- ECS-like normalization and an initial OCSF projection.
- Correlation engine supporting grouped sequence/threshold evaluation, temporal windows, Redis state, bounded evidence, and suppression.
- Correlation provenance persists on alerts and appears in group-scoped case timelines.

### Alert operations and reliability

- Alert deduplication, suppression, optional least-loaded assignment, analyst queue filtering, and severity SLA indicators.
- Worker/API health checks and metrics for queues, ingestion stream, Sigma latency, SLA breaches, and unassigned alerts.
- Event and webhook retry/dead-letter foundations.
- Load/smoke evidence for Sigma evaluation, Redis ingestion, queue drain, worker health, and resource usage.

### AI and SOAR

- AI receives Sigma rule intent, matched fields, and false-positive context.
- SOAR playbooks support alert-triggered actions.
- Destructive isolate/block actions default to approval-required behavior.
- SOAR execution API exposes list, approve, and rollback operations with idempotency metadata.
- SOAR UI exposes recent executions, approval, and rollback controls.

### Backup and recovery

- PostgreSQL custom-format backup with SHA-256 manifest.
- Elasticsearch filesystem snapshot repository and backup script.
- Disposable PostgreSQL restore verified with 110 alerts.
- Disposable Elasticsearch restore verified with 7,294 log documents.
- Restore targets were removed after verification; active data was not overwritten.

### Security and governance

- Central outbound URL policy validates HTTPS destinations, rejects prohibited IP classes and query-secret URLs, pins validated DNS addresses for repository fetches, streams responses with a 2 MB cap, and validates webhook create/update destinations.
- Webhook create/update tenant-scope bypasses were closed.
- Task 1 security review passed after 17 focused tests, scoped lint/compile checks, and container smoke verification.
- Current OpenAPI permission inventory covers all 148 HTTP operations, classifying public, JWT-authenticated, agent-token, and seeded RBAC-permission requirements.

## In Progress

### Security and governance Task 2

- Cross-tenant negative tests and resource-group guards.
- Audit discovery identified likely gaps in alert, case, agent/log-source, rule/revision, webhook-delete, suppression-delete, and enrollment-token mutation routes.

## Remaining

### Security and governance

- Complete cross-tenant isolation corrections.
- Add scoped API keys and service accounts with expiry, revocation, and one-time secret display.
- Add tamper-evident per-tenant audit chains and verification UI.
- Add Redis-backed rate limits and production security headers.
- Run the complete security release gate and record evidence.

### CI and reliability

- Real PostgreSQL/Redis/Elasticsearch integration tests in CI.
- Golden Sigma and decoder tests plus OpenAPI-dashboard contract tests.
- Security scan, migration, frontend regression, and sustained-load gates.
- Operational DLQ UI, retry/discard actions, and alert-delivery monitoring.
- Tenant-configurable SLA escalation notifications for email, Slack, Teams, and webhooks.

### Threat intelligence and OCSF

- Provider-normalized confidence, source attribution, TTL, cache, and stale fallback.
- Automatic IOC propagation across events, alerts, proposed rules, and cases.
- Versioned OCSF mappings for Windows, Linux, firewall, DNS, proxy, cloud, endpoint/FIM, and fallback logs.

### Investigation workspace

- Unified cursor-paginated alert/event/FIM/SOAR/note/enrichment timeline.
- IOC/entity pivots, saved queries, bookmarks, and sharing permissions.
- Signed chain-of-custody incident export with artifact hashes.

### Data lifecycle and maintainability

- Per-tenant retention, Elasticsearch hot/warm/delete lifecycle, archive controls, storage quotas, and query limits.
- Split large Hunts and SOAR pages into focused panels and shared hooks.
- Complete responsive visual QA for new and modified UI states.

## Verification Evidence

- `reports/p0-correlation-redis-smoke-2026-09-06.md`
- `reports/p0-soar-approval-gate-2026-09-06.md`
- `reports/p0-backup-restore-drill-2026-09-06.md`
- `reports/sigma-load-baseline-2026-09-06.md`
- `reports/ingestion-smoke-2026-09-06.md`
- `reports/sustained-ingestion-baseline-2026-09-06.md`
- `reports/batched-ingestion-baseline-2026-09-06.md`
- `.omo/evidence/task-1-live-container-fix-round-1.md`
- `.omo/evidence/task-1-code-review.md`
- `.omo/evidence/task-2a/container-pytest.log`

## Known Limitations

- The host Python environment lacks some runtime test dependencies such as `asyncpg` and `structlog`; dependency-complete container smoke tests are used where host collection cannot run.
- Correlation definitions currently reload when the worker restarts.
- The frontend production bundle remains above Vite's 500 kB warning threshold.
- Existing work is intentionally retained in a dirty `feature/siem-implementation` worktree; task reviews are path-scoped to avoid conflating prior changes.
