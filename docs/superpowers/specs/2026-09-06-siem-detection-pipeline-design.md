# SIEM Detection Pipeline Design

## Goal

Make active Sigma detections flow reliably from event ingestion to a contextual AI-triaged alert and case.

## Scope

This first sub-project covers the detection pipeline only. Sigma lifecycle management and ECS/OCSF normalization follow as separate sub-projects because they introduce independent API and data contracts.

## Design

The worker loads enabled Sigma rules, evaluates each normalized/decoded event, and emits a match containing `rule_id`, rule metadata, and matched event fields. Alert creation persists the originating `rule_id` and queues the complete detection context for AI. AI triage receives the Sigma condition, logsource, tags, and event fields, then writes its verdict and explanation. Deduplication remains group-scoped; assignment defaults to an analyst queue; case creation is driven by the existing AI verdict path.

## Contracts

- `SigmaMatch`: `rule_id`, `title`, `level`, `tags`, `mitre_tags`, `sigma_rule`, `matched_fields`.
- Alert persistence must retain the originating rule identifier.
- AI queue payload must include `sigma_rule` and `decoded_fields`.
- Existing non-Sigma/UEBA alert producers remain valid by treating Sigma context as optional.

## Acceptance criteria

- A matching active Sigma rule produces an alert with a non-null originating rule ID.
- The AI queue payload contains rule metadata and matched event fields.
- The AI prompt explicitly evaluates rule intent and false-positive risk.
- Existing deduplication, SOAR dispatch, and non-Sigma alert paths continue to work.
- Tests cover metadata propagation and the fallback path without Sigma context.
