# P0 Production Detection Design

## Goal

Close the four production-critical gaps: multi-event correlation, automatic detection-to-case flow, safe SOAR execution, and verified backup/restore.

## Scope

This work is split into four independently testable slices. Existing Sigma, normalization, alert, AI, case, and SOAR APIs remain backward compatible.

## Design

1. **Correlation engine:** compile declarative correlation definitions into Redis-backed windows keyed by tenant and grouping fields. Support sequence, threshold, temporal window, suppression, and deterministic correlation keys.
2. **Detection pipeline:** run enabled rules on every normalized event, emit one deduplicated alert per correlation key, assign according to the existing queue policy, and optionally create/update a case with a complete provenance chain.
3. **SOAR safety:** execute playbook steps through an approval gate for destructive actions, persist step-level audit records and idempotency keys, and expose rollback for reversible actions.
4. **Backup/restore:** provide operator commands and documented drills for PostgreSQL and Elasticsearch snapshots, with checksums, retention, and restore verification.

## Non-goals

- Replacing the existing Sigma matcher or AI provider.
- Introducing a second queue technology.
- Automatically executing destructive actions without explicit approval.

## Acceptance criteria

- A five-failed-login-then-success scenario grouped by IP/user creates exactly one correlated alert within the configured window.
- Duplicate events do not create duplicate alerts for the same correlation key and suppression period.
- A matching enabled Sigma rule is traceable from event to alert to AI analysis to case.
- Destructive SOAR steps remain pending until approved; every step has immutable audit metadata and reversible steps can be rolled back.
- Backup and restore drills complete against disposable PostgreSQL and Elasticsearch services with a machine-readable verification report.
