# Changelog

All notable changes to AD-SIEM are documented here.

## [Unreleased]

### Planning

- Added `docs/IMPLEMENTATION_STATUS.md` as the permanent ledger of completed, in-progress, remaining, verified, and limited platform work; it must be updated on every implementation turn.
- Added the Security and Governance implementation plan for outbound URL policy, route permission coverage, tenant isolation, API keys/service accounts, tamper-evident audits, rate limits, and security headers.
- Added the production-hardening design covering security/governance, CI/reliability, threat intelligence/OCSF, investigation workflows, and data lifecycle/frontend maintainability.
- Added the P0 production detection design and implementation plan covering correlation, end-to-end detection provenance, SOAR approval/rollback, and PostgreSQL/Elasticsearch backup-restore drills.

### Added

- Added a checked-in permission inventory for all 148 current OpenAPI operations, including explicit public, authenticated, agent-token, and seeded RBAC-permission requirements.
- Added an OpenAPI contract test that detects missing route inventory entries and permissions absent from the database seed set.
- Added centralized outbound HTTPS URL validation for repository imports and webhooks, including DNS resolution checks that reject non-public destinations.
- Added the first P0 correlation-engine slice with tenant-scoped Redis state, grouped sequence/threshold evaluation, temporal expiry, suppression cooldowns, and bounded event payloads.
- Added live Redis smoke evidence for the P0 grouped sequence correlation path after rebuilding the worker image.
- Added runtime loading of tenant-configured correlation definitions from the `correlation_definitions` platform setting with bounded window validation.
- Rebuilt the worker image and verified the deployed correlation loader plus Redis sequence path in-container.
- Correlation matches now emit provenance-bearing alerts through the existing alert/AI/SOAR pipeline, including correlation key and source event IDs.
- Alerts now persist correlation identifiers and source event IDs, with correlation-key deduplication and API exposure.
- Case timelines now expose group-scoped correlated detection provenance and source event IDs.
- Added the `correlation_definitions` platform setting so operators can author grouped correlation rules through Settings without code changes.
- Hardened case timeline group isolation and added correlated detection provenance entries for investigation views.
- Live legacy SOAR execution now defaults destructive `isolate_agent` and `block_ip` actions to pending explicit approval, with an alert audit note and configurable platform setting.
- Added a SOAR Recent executions panel with approval and rollback controls wired to the execution API.
- Added in-container SOAR approval-service smoke verification covering pending-to-approved transition.
- Added operator backup scripts for PostgreSQL dumps, Elasticsearch filesystem snapshots, checksum manifests, and explicit-confirmation restore verification.
- Configured Elasticsearch `path.repo` and the mounted backup volume required for filesystem snapshot restore drills.
- Completed backup evidence for PostgreSQL and Elasticsearch; restore verification script is available and intentionally requires explicit confirmation against a disposable environment.
- Completed disposable restore verification: PostgreSQL restored 110 alerts and Elasticsearch restored 7,294 log documents into a renamed index before cleanup; transient disk watermark override was reverted.

- Added AI queue depth and ingestion stream length to the proxied worker metrics and Dashboard System Health panel.
- Added API-proxied worker metrics and a Worker health row in the Dashboard System Health panel.
- Added per-rule Sigma evaluation latency metrics (`siem_sigma_evaluation_seconds`) for reliability tuning.
- Added batched Redis ingestion benchmark evidence using a persistent producer and queue-drain measurement.
- Added sustained ingestion baseline evidence for worker health, Redis backlog, Elasticsearch growth, and resource usage.
- Added a runtime ingestion smoke-test report covering Redis stream delivery and worker health.
- Added a repeatable Sigma detection load baseline report for 10,000 synthetic events.
- Added opt-in least-loaded analyst auto-assignment via the `auto_assign_alerts` platform setting.
- Added a one-click **My queue** shortcut on Alerts for analyst-owned triage work.
- Added a System Health panel to the Dashboard showing API, PostgreSQL, and Redis status with live refresh.
- Added SLA breach and unassigned-open counters to SOC metrics, surfaced in the Dashboard SOC Response panel.
- Added Alerts queue assignee filtering, including an explicit Unassigned view for triage ownership.
- Added severity-based SLA tracking to Alerts, including breached/within-SLA indicators in the alert table and detail modal.
- Added allowlisted HTTPS GitHub/GitLab raw YAML import with payload-size protection.
- Added revision comparison controls inside the rule editor.
- Added OCSF-compatible event metadata (`class_uid`, `category_uid`, `activity_name`, product metadata) alongside the ECS-like projection.
- Added revision history display in the rule editor, including version content snapshots.
- Added persistent Sigma revision snapshots with diff and rollback endpoints, including a Rules UI rollback action.
- Added Sigma revision snapshots, revision diff and rollback API endpoints, with rollback available from the Rules UI.
- Added Sigma rule quality scoring and explicit approve-and-enable workflow in the Rules API and UI.
- Added Sigma rule import/export controls in the Rules UI and group-scoped API endpoints.
- Added multi-event canonical normalization with ECS-like `source`, `host`, `user`, `event`, and `@timestamp` projections while retaining legacy decoded fields.
- Added Sigma YAML multi-document import (disabled by default for review) and group-scoped YAML export endpoints.
- Added an ECS-like normalized event projection while preserving existing decoded fields and Sigma aliases.
- Detection alerts now retain a valid originating Sigma `rule_id` when available, while non-UUID internal rules remain safe.
- AI triage receives the originating Sigma rule context and matched event fields for rule-aware reasoning.
- Integrated Sigma hunting into the Threat Hunt UI with YAML editing, PySigma-compatible validation, Lucene query preview, event results, and cursor pagination.
- Added Sigma rule metadata propagation from worker detection through the AI analysis queue.
- Added Sigma context to AI triage prompts, including rule intent, logsource, condition, tags, and matched event fields for better false-positive assessment.
- Added regression coverage for preserving Sigma rule context during event matching.

### Changed

- Hardened rule revision startup migration for existing databases without revision defaults or unique constraints.
- Sigma mode now resets stale results when the rule content changes and hides IoC-only hunt controls.
- Improved responsive behavior, focus states, and touch targets on the Threat Hunt page.
