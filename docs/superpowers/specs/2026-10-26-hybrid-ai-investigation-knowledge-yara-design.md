# Hybrid AI Investigation, Knowledge Vault, and YARA Drafting Design

**Date:** 2026-10-26  
**Status:** Proposed  
**Scope:** Case AI Investigation, analyst knowledge, evidence-driven YARA drafting  
**Out of scope:** Implementation of the full YARA compiler/runtime, which is being developed separately

## 1. Summary

This design upgrades the existing **Investigate** action on a case into a hybrid investigation workspace:

- Investigation starts immediately without asking the analyst a questionnaire.
- The AI creates an editable queue of evidence-gathering actions.
- Safe SIEM queries and read-only endpoint collectors run automatically.
- Analysts may add, skip, or stop queued actions while execution continues.
- Custom commands still require approval unless an administrator has explicitly auto-approved the program.
- Every conclusion is backed by an evidence ledger and source citation.
- Analyst-authored DFIR knowledge is automatically indexed and used as investigation guidance.
- When file evidence supports a malware hypothesis, the AI may offer to generate a disabled YARA draft.
- Full YARA validation and execution are consumed through a capability/API contract owned by the separate full-YARA effort.

The design intentionally distinguishes three concepts:

1. **Knowledge** suggests what to investigate.
2. **Evidence** records what was actually observed.
3. **Detection content** operationalizes a reviewed conclusion for future events.

Knowledge alone can never prove a case verdict, and an AI-generated detection can never become active without validation and analyst review.

## 2. Existing Baseline

The deployed platform already provides useful foundations.

### 2.1 AI investigation

- A case can start a `CaseInvestigation`.
- The investigator uses read-only SIEM tools, endpoint artifacts, and an optional `run_command` tool.
- Commands are sent as a program plus an argument vector; the agent does not invoke a shell implicitly.
- Commands have an eight-command investigation budget, a maximum 300-second timeout, output limits, and a 15-minute approval expiry.
- Interpreters and sensitive credential paths cannot be auto-approved.
- Approval requires case-management and live-response authorization.
- The agent can locally refuse all custom commands.
- Investigation progress is currently retained primarily as an append-only `steps` timeline.

### 2.2 Knowledge

- `knowledge_entries` stores analyst notes and reference material.
- `knowledge_chunks` stores vectorized chunks.
- Exact entity scope supports IP, host, user, and rule matches.
- Semantic retrieval supports unscoped notes.
- PayloadsAllTheThings can be synchronized as external reference material.
- Analyst feedback on AI verdicts is embedded for retrieval.
- The investigator can call `search_knowledge`.

### 2.3 YARA

- Rules can be created, edited, enabled, disabled, and selected for an endpoint scan.
- The agent receives YARA scan tasks and reports matching files/strings.
- The current in-tree agent implementation uses a limited internal matcher rather than a complete YARA runtime.
- A separate effort is implementing full-YARA validation/runtime support. This design must integrate with that effort rather than duplicate it.

## 3. Goals

1. Make one click on **Investigate** useful without requiring preliminary analyst answers.
2. Let the AI investigate autonomously while keeping the action queue visible and editable.
3. Preserve human approval for actions with material endpoint risk.
4. Recover safely after API/worker restart without duplicating endpoint work.
5. Make every final claim traceable to concrete evidence.
6. Turn analyst notes and DFIR articles into an auditable, scoped second brain.
7. Allow case findings to produce reusable YARA drafts without auto-deploying unsafe detection content.
8. Maintain strict group isolation and existing RBAC expectations.

## 4. Non-goals

- A conversational wizard that asks the analyst questions before every investigation.
- Automatic remediation inside the Investigate workflow.
- Fully autonomous activation or fleet deployment of generated YARA rules.
- Uploading malware binaries to an LLM or external provider.
- Treating external reputation, knowledge articles, or model output as proof of execution.
- Implementing another YARA compiler/runtime in parallel with the ongoing full-YARA work.
- Two-way live synchronization with a desktop Obsidian vault in the first release.

## 5. User Experience

### 5.1 Starting an investigation

Clicking **Investigate** immediately creates an investigation and opens the investigation panel. The AI does not ask setup questions. It:

1. Reads the case, linked alerts, entities, prior notes, and relevant knowledge.
2. Creates an initial plan containing five to ten actions.
3. Starts all dependency-free Tier 0 and Tier 1 actions.
4. Updates hypotheses and queues additional targeted actions as evidence arrives.

The analyst sees results streaming into the same panel.

### 5.2 Investigation panel

The panel contains five sections:

- **Summary:** phase, elapsed time, current verdict, confidence, and evidence gaps.
- **Hypotheses:** active alternatives with supporting and contradicting evidence.
- **Action queue:** running, queued, approval-required, completed, skipped, and failed actions.
- **Evidence:** source-linked findings with provenance and timestamps.
- **Report:** timeline, affected entities, IOCs, verdict, recommendations, and detection opportunities.

Analyst controls are deliberately small:

- Add action
- Skip queued action
- Stop investigation
- Approve/reject risky command
- Pin evidence
- Mark finding incorrect

There is no requirement to edit the plan before it starts.

### 5.3 Editable queue behavior

- Adding an action places it after its declared dependencies.
- Skipping is allowed only while an action is queued or awaiting approval.
- Running endpoint work is cancelled through the existing flow cancellation mechanism when supported; otherwise the result is allowed to finish but marked ignored.
- Completed actions are immutable and remain in the audit timeline.
- AI replanning may append actions but may not silently modify analyst-created actions.
- Duplicate actions are rejected by an idempotency key based on investigation, tool, target, and normalized parameters.

## 6. Investigation Architecture

```text
Case + Alerts + Entities + Prior Feedback
                  |
                  v
        Context and Knowledge Retrieval
                  |
                  v
          Structured Investigation Planner
                  |
                  v
          Persistent Editable Action Queue
             /          |           \
            v           v            v
       SIEM tools   Endpoint flows   Command approval
            \           |            /
             \          v           /
                  Evidence Ledger
                        |
                        v
            Hypothesis and Gap Analysis
                        |
                 targeted replanning
                        |
                        v
                Cited Final Report
                        |
              optional detection draft
```

### 6.1 Investigation phases

An investigation uses the following state machine:

```text
queued -> planning -> collecting -> analyzing -> reporting -> completed
                    \         \                     \
                     \         -> awaiting_approval  -> failed
                      -> cancelled
```

`awaiting_approval` is an action state, not a global blocker. Other independent read-only actions continue while a command waits for approval.

### 6.2 Risk tiers

| Tier | Examples | Default behavior |
|---|---|---|
| 0 | Search events, aggregate alerts, retrieve case/knowledge | Automatic |
| 1 | Processes, sockets, persistence, event logs, file metadata/hash, YARA read-only scan | Automatic |
| 2 | Arbitrary program execution without an implicit shell | Analyst approval unless explicitly auto-approved |
| 3 | Kill, quarantine, isolate, delete, block, modify configuration | Never executed by Investigate; offer a separate response action |

An action's tier is assigned by the server policy, not by the model.

### 6.3 Planner contract

The planner must return schema-validated actions. Each proposed action contains:

- `kind`
- `tool`
- `target`
- `params`
- `reason`
- `expected_evidence`
- `dependencies`
- `priority`

The model cannot select its own risk tier or bypass an approval requirement. Unknown tools or parameters fail validation and are shown as a refused planning step.

### 6.4 Replanning

Replanning occurs after a batch of actions finishes, not after every row. The replanner receives compact evidence summaries and existing idempotency keys. It may:

- Close a hypothesis.
- Adjust confidence.
- Add a targeted action for an unresolved gap.
- Stop early when evidence sufficiently answers the case.

It must not repeat an action that already completed, failed deterministically, was rejected, or was skipped by an analyst.

## 7. Data Model

New tables are created through API startup migration helpers under the existing advisory lock, not through `db/init.sql`.

### 7.1 `investigation_actions`

| Field | Purpose |
|---|---|
| `id` | UUID primary key |
| `investigation_id` | Owning investigation |
| `group_id` | Mandatory tenant/group scope |
| `ordinal` | Stable display ordering |
| `kind` | SIEM query, artifact, command, analysis, report, or detection draft |
| `tool` | Registered tool or collector name |
| `target` | Host/entity target |
| `params` | Validated JSON parameters |
| `reason` | Human-readable purpose |
| `expected_evidence` | What would confirm or refute the hypothesis |
| `risk_tier` | Server-assigned tier 0-3 |
| `status` | queued, running, awaiting_approval, completed, skipped, failed, cancelled |
| `source` | planner, replanner, or analyst |
| `dependencies` | Action UUIDs that must finish first |
| `idempotency_key` | Unique normalized operation key per investigation |
| `result_ref` | Flow, event query, or evidence reference |
| `error` | Bounded failure detail |
| `attempts` | Retry count |
| timestamps | Created, started, finished, updated |

Status transitions use conditional updates so multiple API replicas cannot run the same action.

### 7.2 `investigation_evidence`

| Field | Purpose |
|---|---|
| `id` | UUID primary key |
| `investigation_id` / `action_id` | Provenance |
| `group_id` | Tenant/group scope |
| `evidence_type` | event, alert, flow row, file, hash, command result, TI result, knowledge guidance |
| `source_type` / `source_id` | Link to canonical source |
| `title` / `summary` | Bounded display text |
| `observed_at` | Timestamp of observed activity |
| `entities` | Hosts, users, IPs, files, processes, techniques |
| `content_hash` | Integrity/deduplication hash |
| `confidence` | Confidence in extraction, not incident verdict |
| `sensitivity` | normal, sensitive, restricted |
| `pinned` | Analyst pin |
| timestamps | Creation/update |

Large flow output, binaries, and raw event bodies remain in their canonical stores. Evidence rows reference them rather than duplicate them.

### 7.3 `investigation_hypotheses`

Each hypothesis stores a statement, state, confidence, supporting evidence IDs, contradicting evidence IDs, unresolved questions, and timestamps. Confidence changes are appended to the audit timeline with a reason.

### 7.4 Existing timeline

`CaseInvestigation.steps` remains an append-only audit/event timeline for compatibility and UI streaming. Queue state and evidence are normalized into the new tables.

## 8. Evidence and Reporting Rules

- A report claim must reference at least one evidence ID.
- Knowledge guidance may explain why an action was chosen but cannot satisfy a claim's evidence requirement.
- External reputation can support identification but cannot prove execution or compromise.
- `not_found` from a reputation provider is an evidence gap, not a clean verdict.
- Conflicting evidence is shown explicitly rather than averaged away.
- The final report includes:
  - verdict and confidence;
  - executive summary;
  - attack timeline;
  - affected entities;
  - observed IOCs;
  - supporting and contradicting evidence;
  - collection gaps;
  - recommended response actions;
  - detection opportunities;
  - knowledge citations.

## 9. Knowledge Vault (Second Brain)

### 9.1 Content types

- Environment note
- DFIR article
- SOP/playbook
- Detection note
- Incident lesson
- External reference

### 9.2 Authoring format

Articles use Markdown and optional frontmatter:

```markdown
---
title: Investigating Suspicious PowerShell
tags: [windows, powershell, dfir]
platforms: [windows]
mitre: [T1059.001]
trust: verified
scope:
  groups: [default]
---

# Triage

Inspect [[PowerShell Script Block Logging]] and the parent process.
```

Supported authoring features:

- Markdown preview
- Heading outline
- Tags and folders
- `[[wikilinks]]` with autocomplete
- Backlinks and related notes
- Draft/published state
- Owner and reviewer
- Revision history and restore
- Expiry date
- Index status and error detail

### 9.3 Storage extensions

`knowledge_entries` is extended with:

- `slug`
- `path`
- `tags`
- `frontmatter`
- `status` (`draft`, `published`, `archived`)
- `trust` (`draft`, `reviewed`, `verified`, `external`)
- `owner_id`
- `reviewed_by`
- `reviewed_at`
- `version`
- `checksum`

New supporting tables:

- `knowledge_links`: source entry, target entry/slug, heading, resolved status.
- `knowledge_revisions`: immutable content/frontmatter snapshots and author.
- `knowledge_usage`: investigation/case, entry, chunk, query, retrieval score, and use type.

Existing `knowledge_chunks` remains the vector index.

### 9.4 Indexing pipeline

Saving or publishing an entry pushes an index job to Redis. The periodic worker loop remains a recovery mechanism.

```text
Save/publish
    -> validate frontmatter
    -> secret scan
    -> parse headings and wikilinks
    -> revision snapshot
    -> chunk by heading/paragraph
    -> embedding + full-text index
    -> resolve backlinks
    -> mark ready
```

Only published, enabled, unexpired entries are available to AI retrieval.

### 9.5 Retrieval

Retrieval combines:

1. Exact entity scope.
2. Metadata filters for group, platform, MITRE, tags, and content type.
3. PostgreSQL full-text ranking.
4. Vector similarity.
5. One-hop wikilink/backlink expansion.
6. Trust and recency weighting.

The returned result contains entry, heading, chunk, score components, trust, revision, and canonical link. The AI cites `Knowledge: <title>#<heading>`.

### 9.6 Obsidian import

The first release supports one-way import of a ZIP/folder containing Markdown:

- Preserve relative paths.
- Parse frontmatter and wikilinks.
- Ignore hidden/system files.
- Enforce file/count/expanded-size limits.
- Reject path traversal and archive bombs.
- Compute checksums and update only changed entries.
- Report link and frontmatter errors before publish.

Two-way filesystem or Git synchronization is deferred. Native editing plus repeatable import avoids conflict-resolution complexity in the first release.

### 9.7 Knowledge safety

- Group scoping applies at query time and write time.
- Drafts are never retrieved.
- External reference content is marked untrusted.
- Prompts state that retrieved content is reference data, not executable instructions.
- Secrets are blocked before indexing and redacted from previews.
- Analyst-provided text cannot change tool permissions, risk tier, or system instructions.
- Every AI use is recorded in `knowledge_usage`.

## 10. Malware Finding and YARA Drafting

### 10.1 Eligibility

The AI offers **Generate YARA Draft** only when the evidence ledger contains a concrete suspicious file with:

- host and path or evidence-vault object;
- SHA-256;
- file type and size;
- at least one behavioral, reputation, or analyst finding supporting the malware hypothesis.

A bare IP/domain IOC or an unobserved third-party hash is insufficient.

### 10.2 Analyst card

The investigation panel shows:

```text
Potential malware identified
Host, path, SHA-256, signer, reputation, supporting evidence

[Generate YARA Draft] [Scan With Existing Rules] [Dismiss]
```

Generating a draft is explicit analyst intent; the AI does not create large volumes of speculative rules automatically.

### 10.3 Safe feature collection

The AI requests a structured, read-only file-feature collector. It returns bounded metadata rather than sending the binary to the model:

- hashes and fuzzy hashes when supported;
- magic/type, size, entropy;
- PE/ELF metadata, imports, exports, and section names;
- signer and signature status;
- bounded printable strings with offsets and encodings;
- PDB/build paths;
- packer indicators;
- strings shared with related samples when available.

Credential-like strings and environment secrets are redacted. Raw binaries remain on the endpoint or in the governed evidence vault.

### 10.4 Draft generation

The AI generates:

- rule name using organization conventions;
- metadata containing case, investigation, sample SHA-256, author, date, confidence, tags, and MITRE mappings;
- stable strings selected for family relevance;
- a condition appropriate to the available engine capability;
- rationale for every selected string;
- known limitations and likely false positives.

Hash-only conditions and extremely short/common strings receive blocking quality warnings.

### 10.5 Lifecycle

```text
draft -> validating -> valid | invalid -> testing -> review -> active -> retired
```

- New AI rules are disabled.
- Validation is mandatory before test scan.
- Test scan is mandatory before review completion.
- Activation requires a user with rule-update permission.
- Fleet scans require live-response authorization and a separate confirmation.
- Every edit creates a revision.

### 10.6 Quality checks

Validation includes:

- syntax/compiler validation;
- engine capability compatibility;
- duplicate/similar rule detection;
- short/common string warnings;
- overly broad condition warnings;
- sample match test when governed sample access exists;
- clean corpus or approved baseline scan;
- estimated match volume and timeout limits.

Failure leaves the rule as a visible draft with actionable diagnostics.

### 10.7 Full-YARA integration contract

The separate full-YARA implementation owns compiler/runtime details. This feature consumes the following stable contract:

#### Capability

`GET /api/yara/capabilities`

Returns engine/version, supported syntax/modules/modifiers, supported endpoint platforms, maximum file/rule sizes, and whether validation/test/deployment are available.

#### Validation

`POST /api/yara-rules/validate`

Accepts rule text and returns normalized diagnostics with line/column, capability failures, warnings, compiled fingerprint, and engine version.

#### Test

`POST /api/yara-rules/{id}/test`

Accepts governed sample IDs and/or approved corpus selectors. Returns matches, non-matches, errors, elapsed time, engine version, and corpus revision.

#### Scan

The existing rule-scan path remains the orchestration entry point but returns structured rule revision, engine version, target scope, scanned file count, errors, and matches.

The AI feature does not import compiler libraries or change the agent's YARA runtime.

### 10.8 Feature modes

Platform setting `yara_ai_generation` supports:

- `off`: no draft option.
- `draft_only`: collect features and save disabled drafts; validation/scan unavailable.
- `full`: capability validation, test, review, activation, and scan integration.

If the full-YARA dependency is unavailable, the system degrades to `draft_only` and explains the gap.

### 10.9 Detection feedback loop

After activation:

- YARA matches create alerts linked to rule revision, file, host, and originating case.
- False-positive feedback updates rule quality metrics.
- The approved rationale becomes a reviewed Knowledge Vault detection note.
- Future Investigate runs can retrieve that note and rule provenance.

## 11. API Surface

### Investigation

- `GET /api/cases/{case_id}/investigations/{id}/actions`
- `POST /api/cases/{case_id}/investigations/{id}/actions`
- `POST /api/investigation-actions/{id}/skip`
- `GET /api/cases/{case_id}/investigations/{id}/evidence`
- `POST /api/investigation-evidence/{id}/pin`
- Existing command decision endpoint remains in use.

### Knowledge

- CRUD for Markdown entries and revisions.
- Publish/archive/restore endpoints.
- Link/backlink endpoint.
- Obsidian ZIP import and dry-run validation endpoints.
- Retrieval preview returns score breakdown and canonical citations.

### YARA drafting

- `POST /api/investigations/{id}/yara-drafts`
- `GET /api/yara/capabilities`
- Validation/test endpoints from the full-YARA contract.
- Activation remains under the YARA rule permission model.

All endpoints require group scoping. Single-resource lookups verify ownership before returning data.

## 12. Concurrency, Recovery, and Failure Handling

- Queue claims use atomic conditional updates and leases.
- A stale running action returns to queued only if it is idempotent; endpoint commands require flow-state reconciliation first.
- Retryable network/provider failures use bounded exponential backoff.
- Deterministic validation or permission failures do not retry.
- Investigation cancellation expires pending approvals and stops scheduling new work.
- In-flight flows finish or are cancelled independently and remain auditable.
- Host-offline actions may defer for a bounded period or return an evidence gap.
- Index failures leave the prior published knowledge revision active.
- YARA dependency failure never blocks the final investigation report.

## 13. Security and Audit

- Server policy assigns risk tiers.
- Custom command output is secret-scanned/redacted before entering model context.
- Full command output remains access-controlled in flow storage.
- Every plan, queue edit, approval, evidence pin, knowledge revision, YARA draft, validation, test, activation, and scan is audited.
- Knowledge and YARA content are treated as untrusted input when included in prompts.
- No binary is sent to an LLM or external enrichment service.
- External enrichment sends only explicitly approved indicators such as a SHA-256.
- Tier 3 response remains outside Investigate to prevent investigative reasoning from silently mutating endpoints.

## 14. Observability

Metrics include:

- investigation duration and completion rate;
- actions by type/status/risk tier;
- approval latency and expiry rate;
- flow failure/timeout rate;
- replans and duplicate-action rejections;
- evidence count and uncited report-claim failures;
- knowledge indexing latency/failures and retrieval score/source distribution;
- knowledge citations per investigation;
- YARA draft/validation/test/activation counts;
- YARA false-positive and match volume by revision.

Structured logs include investigation, action, group, agent, flow, knowledge entry/revision, and YARA rule/revision identifiers.

## 15. Testing Strategy

### Unit tests

- Planner schema validation and risk-tier assignment.
- Action idempotency and state transitions.
- Evidence citation enforcement.
- Hypothesis confidence/history updates.
- Markdown/frontmatter/wikilink parsing.
- Chunking, ranking, trust weighting, expiry, and group isolation.
- Archive safety and checksum behavior.
- YARA eligibility, feature redaction, draft quality checks, and capability negotiation.

### Integration tests

- One-click investigation completes with no analyst interaction for read-only cases.
- Independent actions continue while one command awaits approval.
- Analyst-added/skipped actions are respected during replanning.
- API restart recovers the queue without duplicate endpoint execution.
- Knowledge publication becomes retrievable and is cited by an investigation.
- Draft or cross-group knowledge is never retrieved.
- Obsidian import preserves paths/links and reindexes only changed files.
- Malware evidence creates a disabled YARA draft with provenance.
- Missing full-YARA capability degrades to draft-only.
- Validation/test failure cannot activate a rule.
- Approved YARA match links the resulting alert to rule revision and originating case.

### Manual QA

1. Investigate a Windows process alert and observe the editable queue.
2. Add a read-only endpoint action while the investigation is running.
3. Reject a custom command and verify the AI adapts without asking again.
4. Publish a scoped DFIR article and confirm retrieval/citation.
5. Import a small Obsidian vault and verify backlinks.
6. Investigate a governed malware sample, generate a YARA draft, validate/test it, and confirm it remains disabled until review.
7. Trigger a reviewed rule match and verify alert/case provenance.

## 16. Rollout

### Phase 1: Persistent investigation queue and evidence ledger

- Normalize actions/evidence/hypotheses.
- Add editable queue UI.
- Preserve current tools, command approval, and timeline behavior.
- Enforce cited reports.

### Phase 2: Knowledge Vault

- Markdown editor, publishing, revisions, links, backlinks, and event-driven indexing.
- Hybrid retrieval and knowledge usage citations.
- One-way Obsidian import.

### Phase 3: Malware feature collection and draft-only YARA

- Add governed file-feature collector.
- Add malware eligibility and analyst offer card.
- Generate disabled drafts with provenance and quality warnings.

### Phase 4: Full-YARA integration

- Integrate capability, validation, test, scan, and alert provenance contracts delivered by the separate YARA effort.
- Enable `yara_ai_generation=full` only when capability checks pass.

### Phase 5: Feedback and tuning

- Knowledge created from completed cases.
- Detection quality dashboards.
- Ranking and investigation-plan tuning from analyst feedback.

## 17. Acceptance Criteria

The feature is ready when:

1. Clicking Investigate immediately starts a useful read-only plan.
2. Analysts can add, skip, and stop work without corrupting the investigation.
3. Risky commands still require existing RBAC and approval controls.
4. Restarts do not duplicate endpoint commands.
5. Every verdict claim links to evidence.
6. Published Markdown knowledge is automatically indexed, scoped, cited, and auditable.
7. Draft/untrusted/cross-group knowledge cannot influence unauthorized investigations.
8. Malware evidence can produce a disabled, provenance-rich YARA draft.
9. No YARA draft can activate without validation, test, permission, and analyst review.
10. The feature operates in draft-only mode until the separate full-YARA capability is available.

