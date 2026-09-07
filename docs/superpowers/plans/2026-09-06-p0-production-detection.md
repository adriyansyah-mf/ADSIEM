# P0 Production Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the four P0 production capabilities with observable UI/API behavior and repeatable verification.

**Architecture:** Extend the current worker/Redis/PostgreSQL/Elasticsearch flow with a focused correlation module and provenance fields. Reuse existing alert, case, playbook, and audit models; add explicit approval/idempotency records for SOAR and operator-facing backup scripts rather than hidden background behavior.

**Tech Stack:** Python, FastAPI, SQLAlchemy, Redis, Elasticsearch, PostgreSQL, React/TypeScript, pytest, Docker Compose.

**Spec:** `docs/superpowers/specs/2026-09-06-p0-production-detection-design.md`

## Global Constraints

- Preserve tenant/group isolation on every read, write, Redis key, and Elasticsearch query.
- Keep Sigma context optional for non-Sigma producers.
- Destructive SOAR actions require explicit approval and idempotency protection.
- Every code, schema, script, or report change must be recorded in `CHANGELOG.md`.
- No secrets, tokens, or raw credentials may enter alerts, AI prompts, reports, or audit records.

### Task 1: Correlation contract and Redis state engine

**Files:**
- Create: `worker/worker/correlation_engine.py`
- Create: `worker/worker/correlation_models.py`
- Modify: `worker/worker/consumer.py`
- Test: `tests/worker/test_correlation_engine.py`

**Interfaces:**
- `CorrelationDefinition(id: str, mode: Literal["sequence", "threshold"], window_seconds: int, group_by: tuple[str, ...], stages: tuple[dict, ...], suppression_seconds: int = 0)`
- `CorrelationEngine.evaluate(definition, event, now=None) -> CorrelationMatch | None`
- `CorrelationMatch.correlation_key`, `stage_count`, `first_seen`, `last_seen`, `events`

- [ ] Write failing tests for grouped sequence, threshold, window expiry, and suppression.
- [ ] Implement Redis state keys prefixed with tenant/group and correlation id; use atomic expiry and bounded event payloads.
- [ ] Wire normalized events into the engine without changing legacy Sigma matching.
- [ ] Run focused tests and a Redis container smoke test.

### Task 2: End-to-end correlated alert and case provenance

**Files:**
- Modify: `worker/worker/alert_manager.py`
- Modify: `worker/worker/consumer.py`
- Modify: `server-api/app/api/routes/alerts.py`
- Modify: `server-api/app/api/routes/cases.py`
- Modify: `server-api/app/models/models.py`
- Modify: `db/init.sql`
- Test: `tests/worker/test_detection_pipeline.py`

**Interfaces:**
- Alert provenance fields: `correlation_id`, `correlation_key`, `source_event_ids`, `sigma_rule`.
- Case timeline event type: `detection_provenance` containing rule/correlation identifiers only.

- [ ] Add failing integration-style tests for the five-failed-login-then-success scenario and duplicate suppression.
- [ ] Persist one alert per correlation key with group-scoped deduplication and valid Sigma rule identity.
- [ ] Create/update a case through the existing case path and append provenance to the timeline.
- [ ] Verify API responses expose provenance only to the owning group.

### Task 3: SOAR approval, idempotency, audit, and rollback

**Files:**
- Inspect/modify: `server-api/app/api/routes/soar.py`
- Inspect/modify: `server-api/app/services/soar_service.py`
- Modify: `server-api/app/models/models.py`
- Modify: `db/init.sql`
- Modify: `dashboard/src/pages/SoarPage.tsx`
- Test: `tests/server-api/test_soar_approval.py`

**Interfaces:**
- `POST /api/soar/executions/{execution_id}/approve`
- `POST /api/soar/executions/{execution_id}/rollback`
- Step states: `pending_approval`, `approved`, `running`, `succeeded`, `failed`, `rolled_back`.

- [ ] Add failing API tests proving destructive steps cannot run while pending approval.
- [ ] Add step execution records with actor, timestamp, idempotency key, input hash, result status, and rollback reference.
- [ ] Gate destructive actions, make retries idempotent, and implement rollback for reversible steps.
- [ ] Add approval/rollback controls and status history to the SOAR UI.
- [ ] Run API tests plus a disposable worker execution smoke test.

### Task 4: PostgreSQL/Elasticsearch backup and restore drill

**Files:**
- Create: `ops/backup/backup_postgres.sh`
- Create: `ops/backup/backup_elasticsearch.sh`
- Create: `ops/backup/restore_verify.sh`
- Create: `reports/p0-backup-restore-drill-2026-09-06.md`
- Modify: `docker-compose.yml`
- Modify: `CHANGELOG.md`

- [ ] Add scripts with explicit targets, checksum manifests, retention flags, and non-zero failure exits.
- [ ] Run a disposable backup/restore drill for PostgreSQL and Elasticsearch and verify row/document counts plus a known alert.
- [ ] Record commands, duration, recovery point, and limitations in the report.

### Task 5: UI integration, release verification, and changelog

**Files:**
- Modify: `dashboard/src/pages/RulesPage.tsx`
- Modify: `dashboard/src/pages/AlertsPage.tsx`
- Modify: `dashboard/src/pages/CasesPage.tsx`
- Modify: `dashboard/src/pages/SoarPage.tsx`
- Modify: `CHANGELOG.md`

- [ ] Expose correlation status and provenance links from rule/alert/case views.
- [ ] Run frontend build and manual QA at 375px, 768px, and 1280px for empty, populated, pending-approval, and rollback states.
- [ ] Run focused Python tests, lint, container health checks, and the backup drill.
- [ ] Append exact shipped behavior and any pre-existing limitations to `CHANGELOG.md`.
