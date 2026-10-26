# Hybrid AI Investigation, Knowledge Vault, and YARA Drafting Design

**Date:** 2026-10-26  
**Status:** Proposed (revision 2, 2026-10-26)  
**Scope:** Case AI Investigation, analyst knowledge, evidence-driven YARA drafting  
**Out of scope:** Implementation of the full YARA compiler/runtime, which is being developed separately

### Revision 2 changes

Revision 2 checks the baseline against the code and closes gaps found in review:

- Section 2 now records the real investigator runtime (in-process loop per API replica, existing budgets, `create_artifact`) and the real YARA baseline (a pure-Go engine on `feat/yara-full`, fleet-wide distribution of enabled rules).
- Phase 1 is split into **1a** (persist actions and evidence alongside the current loop) and **1b** (durable, replica-safe queue). See sections 6.6 and 16.
- `create_artifact` and AI-authored artifacts are now classified in the risk-tier policy (section 6.2).
- Per-investigation and per-host budgets are stated (section 6.5).
- Investigation status and action status are separated (section 6.1).
- `investigation_hypotheses` has a field-level definition (section 7.3).
- Citation enforcement now has a mechanism: a structured report validated by the server (section 8.1).
- The full-YARA contract names where validation runs, how disabled drafts are tested, and which side owns each piece (sections 10.5, 10.7).
- Acceptance criteria are grouped by phase so Phase 1 can ship without the Knowledge Vault or YARA work (section 17).
- Open questions are listed in section 18.

This document remains the umbrella design. The Knowledge Vault (section 9) and YARA drafting (section 10) each get their own implementation plan.

### Implementation status

- **Phase 1a: implemented** on `feat/investigation-ledger`.
  - Server side: `server-api/app/services/investigation_ledger.py` plus the loop in `investigator.py`.
  - Routes: `api/routes/investigations.py`, and artifact promotion in `api/routes/flows.py`.
  - UI: `dashboard/src/components/InvestigationLedger.tsx`.
  - Where the implementation settled a detail differently from revision 2, this text was updated: sections 5.3, 6.2, 6.5 and 6.6.
- **Phase 1b: implemented** on the same branch: leases, scheduler adoption and reconciliation (section 6.6).
- **Phase 2: implemented** on the same branch: the Knowledge Vault (section 9.8 lists how).
- Phases 3 and 4: not started.

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

Runtime facts that constrain this design (`server-api/app/services/investigator.py`):

- An investigation is a single LangChain tool-calling loop. The conversation (`messages`) lives only in process memory.
- `spawn()` runs it as an `asyncio` task inside whichever API replica received the request. Production runs two `server-api` replicas (`docker-compose.prod.yml`).
- On startup, `mark_stale_interrupted()` marks any run not updated for five minutes as `interrupted` and expires its pending commands. Nothing resumes.
- Command approval already works across replicas, because the loop polls `InvestigationCommand` rows in the database.
- Existing budgets: `MAX_ROUNDS = 18`, `MAX_FLOWS = 12`, `MAX_NEW_ARTIFACTS = 4`, `MAX_COMMANDS = 8`, `MAX_SECONDS = 30 min`, `FLOW_WAIT_CAP = 600 s`.
- `create_artifact` lets the model persist a new group-scoped `FlowArtifact` (name prefixed `AI.`, built-in plugins only), which `run_artifact` can then execute.
- The report is free-form Markdown. The verdict is extracted with a regex (`VERDICT: ...`) and stored as an AI `CaseNote`.
- Investigation statuses in use: `queued`, `running`, `finished`, `error`, `cancelled`, `interrupted`.

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
- The separate full-YARA effort (`feat/yara-full`, which reached `feature/siem-implementation` through `feat/memory-scan`, PR #69) replaced the earlier limited matcher with a pure-Go engine in `agent/internal/yara`: lexer, parser, evaluator, `pe`/`elf`/`math` modules, and differential and fuzz tests. This design must integrate with that effort rather than duplicate it.
- On that branch, **enabling a rule deploys it fleet-wide**. Heartbeats carry the enabled-ruleset hash (`server-api/app/services/yara_ruleset.py`), and every agent fetches and compiles the set for on-access scanning. Agents compile each rule separately (`CompileSources`), so one broken rule is skipped rather than blocking the set.
- The `Linux.Detection.Yara` / `Windows.Detection.Yara` artifacts scan with **every enabled rule**. There is no way to scan with a single disabled rule.
- The server does not validate rules and does not expose an engine capability.

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
- Every action has an idempotency key based on investigation, tool, target (case-insensitive), and normalized parameters. The `reason` is excluded, and so are empty values.
  - Endpoint actions (tier 1 and above) never repeat once completed.
  - A failed endpoint action may be tried once more.
  - Tier 0 queries may run again under the same key, because logs keep arriving.
  - Any action an analyst skipped or rejected is refused if the model asks for it again.
- In Phase 1a (section 6.6), analyst edits take effect at the next round boundary:
  - The loop itself runs an added action and shows it to the model as a tool call followed by its result.
  - A skipped action is refused when the model tries to dispatch it.
  - In Phase 1b the orchestrator applies both directly.

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

Investigation state and action state are separate.

**Investigation `status`** keeps the existing coarse values for compatibility with current UI, tests, and `mark_stale_interrupted()`:

```text
queued -> running -> finished
             |-> error
             |-> cancelled
             '-> interrupted   (Phase 1a only; Phase 1b resumes instead)
```

**Investigation `phase`** is a new column, meaningful only while `status = running`:

```text
planning -> collecting <-> analyzing -> reporting
```

`collecting` and `analyzing` alternate once per replan batch.

**Action `status`** is defined in section 7.1:

```text
queued -> running -> completed
   |         |-> failed
   |         '-> cancelled
   |-> awaiting_approval -> queued (approved) | skipped (rejected/expired)
   '-> skipped
```

`awaiting_approval` is only an action state. It never blocks the investigation: other independent read-only actions continue while a command waits.

### 6.2 Risk tiers

| Tier | Examples | Default behavior |
|---|---|---|
| 0 | Search events, aggregate alerts, retrieve case/knowledge | Automatic |
| 1 | Processes, sockets, persistence, event logs, file metadata/hash, YARA read-only scan | Automatic |
| 2 | Arbitrary program execution without an implicit shell | Analyst approval unless explicitly auto-approved |
| 3 | Kill, quarantine, isolate, delete, block, modify configuration | Never executed by Investigate; offer a separate response action |

An action's tier is assigned by the server policy, not by the model.

#### AI-authored artifacts

`create_artifact` is not an endpoint action, but it persists content that later runs on endpoints. Policy:

| Action | Tier | Rule |
|---|---|---|
| `create_artifact` | 0 (authoring) | Automatic, within `MAX_NEW_ARTIFACTS`. Name must start with `AI.`, and every source must use a plugin from the server's read-only plugin allowlist. Any other plugin fails validation. |
| `run_artifact` on a built-in artifact | 1 | Automatic. |
| `run_artifact` on an `AI.*` artifact | 1 | Automatic only when the artifact was created by **this** investigation, or has been promoted by an analyst. Otherwise the action is queued `awaiting_approval`. |
| `run_artifact` on an artifact containing a non-read-only plugin | 2 | Approval required. This case is unreachable through `create_artifact`, but the policy checks the stored content, not the author. |

AI-created artifacts are tagged with the creating investigation ID.

- They stay out of other investigations' `list_artifacts` until an analyst promotes them. Promotion happens through `POST /api/flow-artifacts/{name}/promote` (requires `agents:manage`), or automatically when a person saves the artifact in the editor.
- The Live Response artifact list still shows them, because a human running a collector is a human decision.
- Without promotion, a future investigation in the same group cannot silently reuse another run's model-written collector. If it asks for one by name, the run waits for approval.

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

### 6.5 Budgets

Removing the questionnaire and auto-running Tier 0/1 work makes budgets the main protection for endpoints. All values are platform settings. The defaults keep current behavior where a limit already exists.

| Limit | Default | Scope | On exhaustion |
|---|---|---|---|
| Initial plan size (Phase 1b) | 10 actions | investigation | Extra planned actions are dropped and logged |
| Replan batches (Phase 1b) | 6 | investigation | Move to `reporting` |
| Planner/replanner model calls | 18 (`MAX_ROUNDS`) | investigation | Move to `reporting` |
| Endpoint flows (Tier 1 + 2) | 12 (`MAX_FLOWS`) | investigation | New endpoint actions refused with a visible reason |
| Concurrent flows | 2 | host, across all investigations | Action stays `queued` |
| Auto Tier 1 flows | 6 | host, per investigation | Further flows on that host need approval |
| Custom commands | 8 (`MAX_COMMANDS`) | investigation | Refused |
| New AI artifacts | 4 (`MAX_NEW_ARTIFACTS`) | investigation | Refused |
| Wall clock | 30 min (`MAX_SECONDS`) | investigation | Report with an explicit gap list |

Analyst-added actions count toward the flow and command budgets. An analyst with live-response permission may raise an investigation's flow budget once, by up to 100%, and the change is audited.

### 6.6 Execution model and phasing

The current investigator holds all of its state in an in-process conversation. A persistent, editable, replica-safe queue is therefore an architectural change, not an incremental one. It is delivered in two steps.

#### Phase 1a: persisted ledger on the existing loop

- The LangChain loop, the tools, and `spawn()` stay as they are.
- Every tool call writes an `investigation_actions` row (`source = planner`) before dispatch and updates it on completion.
- Tool results that carry observations are normalized into `investigation_evidence`.
- Analyst-added actions are inserted as `queued` rows with `source = analyst`. At each round boundary, the loop runs every analyst row whose dependencies have finished, under the same policy and budgets as model actions. The model sees each one as a tool call followed by its result.
  - An analyst's own action needs no further approval.
  - A model action held by the policy waits for an analyst's decision, with the investigation clock paused, and expires after 15 minutes.
- Before dispatch, the loop looks up the action's idempotency key. A skipped, rejected or already-completed endpoint action returns a tool result telling the model why, and does not run.
- The phase in 1a has no separate planner: the model's own tool calls fill the queue. The initial-plan and replan-batch limits in section 6.5 start applying in Phase 1b.
- Restart behavior is unchanged: the run becomes `interrupted`, and its persisted actions and evidence remain visible.
- The structured report (section 8.1) ships in this phase.

Phase 1a delivers the visible queue, the evidence ledger, analyst add/skip, and cited reports without touching the concurrency model.

#### Phase 1b: durable orchestrator

As implemented:

- **Leases.** One replica runs an investigation at a time, under a lease on `case_investigations`:
  - The lease is held in `lease_owner` (`host:pid:random`, `investigator.REPLICA_ID`) and `lease_expires_at`.
  - It lasts 90 s and is renewed every 30 s.
  - The claim is one conditional `UPDATE ... RETURNING`.
  - A run is claimable when its lease has expired, or when it never had a lease and is either `queued` or a pre-lease run whose `updated_at` is older than `STALE_AFTER`. That last condition keeps a rolling deploy from stealing a run that an old-code replica is still driving.
- **Scheduler.** Each `server-api` replica runs `investigator.scheduler_loop()` from the app lifespan. Every 15 s it spawns up to ten claimable runs.
- **Starting and stopping.** `spawn()` claims before running, so a start request and a scheduler pass can't both run the same investigation. On graceful shutdown, `investigator.shutdown()` cancels this replica's runs and expires their leases, so another replica adopts them at its next pass.
- **Losing a lease.** If a renewal finds another owner, this copy is cancelled.
- **Cancellation never finalizes.** A run cancelled by shutdown or a lost lease doesn't expire pending commands or close its queue, and its in-flight action rows stay `running`.
- **Resuming without a transcript.** While a replica owns a run, the model's conversation stays in memory. The conversation is rebuilt only when a replica adopts a run:
  - the case context, plus a ledger brief listing every action with its status, the evidence ids and summaries it produced, the hypotheses, and the budget used;
  - `rounds_used` and `active_seconds` are saved every round, so the round budget and clock continue rather than restart.
- **Reconciliation before the model runs:**
  - An artifact action with a linked flow waits for that flow.
  - A command resumes at its decision (an approval still counts) or at its flow, and is scheduled at most once.
  - A held action keeps waiting for its analyst.
  - An interrupted Tier 0 query, or endpoint work that never reached a flow, is marked failed and may run again.
- **No double scheduling.** The flow id is generated before scheduling and written to the action row (and the command row) in the same transaction as the flow. A crash therefore can't leave a scheduled flow that the ledger doesn't know about.
- **What replaces `mark_stale_interrupted()`.** The function is gone; adoption replaces it. `interrupted` remains only for an adopted run that has no AI provider configured.
- **Not done.** Analyst-queued actions still run on the owning replica's round boundary, not through a separate action claim. A dedicated action-claim queue (`FOR UPDATE SKIP LOCKED`) is unnecessary while one replica owns the whole run.

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
| `evidence_type` | `event`, `alert`, `flow_row`, `file`, `hash`, `command_result`, `ti_result`, `knowledge_guidance` (`knowledge_guidance` never satisfies a claim, see section 8.1) |
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

| Field | Purpose |
|---|---|
| `id` | UUID primary key |
| `investigation_id` | Owning investigation |
| `group_id` | Mandatory tenant/group scope |
| `ordinal` | Display order |
| `statement` | Bounded text, e.g. "PowerShell spawned by Word downloaded a second stage" |
| `state` | `open`, `supported`, `refuted`, `inconclusive`, `superseded` |
| `confidence` | 0-100 integer, model-proposed and server-clamped |
| `supporting_evidence_ids` | UUID array referencing `investigation_evidence` in the same investigation |
| `contradicting_evidence_ids` | UUID array, same constraint |
| `open_questions` | Short list of unresolved gaps that drive replanning |
| `superseded_by` | Hypothesis ID when merged or replaced |
| `source` | `planner`, `replanner`, or `analyst` |
| `history` | Append-only array of `{at, state, confidence, reason, actor}` |
| timestamps | Created, updated |

Rules:

- Moving to `supported` or `refuted` requires at least one supporting or contradicting evidence ID respectively. The server rejects the change otherwise.
- Evidence IDs from another investigation, and evidence of type `knowledge_guidance`, are rejected.
- Analyst-created hypotheses cannot be closed by the model. The model may only add evidence links and propose a state, which is shown to the analyst.
- Every confidence change is also appended to `CaseInvestigation.steps`.

### 7.4 Changes to existing tables

`case_investigations` gains:

- `phase` (section 6.1);
- `report_json` (section 8.1); the existing `report` keeps the rendered Markdown;
- `budget_overrides` (JSON, section 6.5);
- `lease_owner` and `lease_expires_at` (Phase 1b);
- `rounds_used` and `active_seconds`, the progress an adopting replica resumes from (Phase 1b).

`flow_artifacts` gains:

- `created_by_investigation_id` (nullable);
- `promoted_at` and `promoted_by` (section 6.2).

### 7.5 Existing timeline

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

### 8.1 Structured report and citation enforcement

Free-form Markdown cannot be checked for citations, so the final model call returns a schema-validated object instead:

```json
{
  "verdict": "true_positive | false_positive | inconclusive",
  "confidence": 0,
  "executive_summary": "...",
  "claims": [
    {
      "id": "c1",
      "section": "timeline | entities | iocs | analysis | recommendation | detection",
      "text": "...",
      "evidence_ids": ["<uuid>"],
      "contradicting_evidence_ids": []
    }
  ],
  "gaps": ["..."],
  "recommended_actions": ["..."],
  "detection_opportunities": ["..."],
  "knowledge_citations": [{"entry_id": "<uuid>", "heading": "...", "revision": 3}]
}
```

The server validates the object:

1. The JSON matches the schema. Verdict and confidence come from fields, not from a regex.
2. Every claim in `timeline`, `entities`, `iocs`, or `analysis` has at least one `evidence_ids` entry.
3. Every referenced ID exists in this investigation's `investigation_evidence` and is not of type `knowledge_guidance`.
4. Every `knowledge_citations` entry exists in `knowledge_usage` for this investigation.

Recommendation and detection claims may cite knowledge instead of evidence.

If validation fails, the model gets **one** repair attempt with the list of failing claims. Claims that still fail are kept but rendered under "Unverified statements" with a visible marker, and each one increments the uncited-claim metric (section 14). The verdict is downgraded to `inconclusive` if the only claims supporting it are unverified.

The server renders `report_json` into the Markdown stored in `report` and in the AI `CaseNote`. Each claim gets footnote links to its evidence. Models without structured-output support fall back to the current Markdown path with regex verdict extraction. Such reports are flagged `citations_unchecked` and cannot satisfy acceptance criterion 5.

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

### 9.8 As implemented (Phase 2)

**Where the code lives:**
- Shared pure module: `worker/worker/knowledge_markdown.py` (frontmatter, headings, wikilinks, slugs, secret scan, checksum, heading chunks). The server-api image copies it, like `knowledge_query.py`.
- Server: `server-api/app/services/knowledge_vault.py` (save, revisions, links, usage, import) and the `/api/knowledge/articles*` and `/api/knowledge/import` routes.
- Indexing: `worker/worker/knowledge.py`. Retrieval: `worker/worker/knowledge_query.py`.
- UI: `dashboard/src/components/KnowledgeVault.tsx`, the Vault tab on the Knowledge page.

**Articles and quick notes:**
- Articles are `knowledge_entries` rows of kind `note`. The existing quick-notes API keeps working: its notes are published, `reviewed` trust, and now also secret-scanned and pushed to the index queue.
- A new vault article starts as a draft with `draft` trust.
- Review rules:
  - Another person marks it reviewed.
  - Only a user with `settings:manage` marks it verified, or saves frontmatter that says `verified`.
  - The author can't review their own article.

**Frontmatter:**
- Recognized keys: `title`, `tags`, `platforms`, `mitre` (validated technique ids), `type` (the six content types in section 9.1), `trust`, `expires`, `aliases`, `scope`.
- Other keys, such as Obsidian's own, are kept as they are.
- `scope.groups` names one group (or `"*"`) and must be the writer's own.
- `scope.ips/hosts/users/rules` feed the existing exact matching.

**Secret scan:** high-confidence credential shapes only (private keys, cloud and API tokens, JWTs, long credential assignments). A bare `password=` in a DFIR example is allowed. Matches are reported by line with a redacted excerpt, never echoed back.

**Saving and revisions:**
- Saving an unchanged checksum is a no-op.
- A changed article gets a new version, an immutable `knowledge_revisions` row, and rebuilt `knowledge_links`.
- Dangling links elsewhere resolve once an article with that slug or title appears.
- Restoring a revision makes a new version; history is never rewritten.

**Indexing:**
- Event-driven: saves push to the Redis list `siem:knowledge:index`, and the worker's `BLPOP` wakes on it. The 60 s pass remains as recovery.
- Only published entries are indexed.
- Chunks follow H1–H3 sections and store their `heading`. A generated `tsvector` column (`simple` configuration) sits beside the embedding.
- A failed embedding records `index_error` and leaves the previous chunks searchable.

**Retrieval:**
- Candidates come from exact scope, the vector top 20 and the full-text top 20 (an OR query with stopwords removed). All are filtered to published, enabled, unexpired entries in the group, optionally narrowed by tags, type, platform or MITRE technique.
- Score = (0.65 × vector + 0.35 × normalized full text) × trust weight (verified 1.0, reviewed 0.9, external 0.75, draft 0.5) × recency (1.0 for 90 days, easing to 0.8 at two years).
- Up to two one-hop link neighbours are added at half their parent's score.
- Each result carries its heading, version, trust, `/knowledge?article=<id>` link and score breakdown.
- Full text keeps retrieval working without the embedding model.

**Usage tracking:** `search_knowledge` results and report `knowledge_citations` are written to `knowledge_usage` as `retrieved` and `cited`, with investigation and case. Alert triage in the worker does not record usage yet.

**Obsidian import:**
- One way, a zip upload with a dry run by default.
- Limits: 20 MB compressed, 60 MB expanded, a 100:1 ratio, 2,000 notes, 1 MB per note.
- Paths that escape the vault are refused. Hidden folders and `__MACOSX` are ignored, and non-Markdown files are listed as skipped. A single top folder is stripped.
- Notes are upserted by path, and unchanged checksums are skipped.
- The report lists frontmatter or secret errors and links that resolve nowhere.

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
- **Activation is fleet deployment.** On the full-YARA engine, setting `is_enabled` puts the rule into the heartbeat ruleset hash, so every agent downloads it and applies it to on-access scanning within one heartbeat. The activation dialog must state this and show the estimated match volume from testing.
- Fleet on-demand scans require live-response authorization and a separate confirmation.
- Every edit creates a revision. Editing an active rule creates a new draft revision. The active revision keeps running until the new one passes validation and testing and is activated.
- Test scans never use the enabled-ruleset path (section 10.7), so a draft can be tested without being deployed.

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

The separate full-YARA implementation owns compiler/runtime details. This feature consumes the contract below.

#### Where validation runs

The engine is Go code in `agent/internal/yara`, and `server-api` is Python. Validation must use **the same engine the agents run**, otherwise a rule could pass the server and fail on endpoints. The chosen approach:

- The full-YARA effort ships a small static binary, `yaracheck`, built from `agent/internal/yara` at the same commit as the agent release. It is copied into the `server-api` image.
- `yaracheck validate` reads rule text on stdin and writes JSON diagnostics.
- `yaracheck capabilities` writes the engine's version, modules, and limits.
- `yaracheck scan --rules <file> <path>` scans governed samples or corpus files available to the server.
- `server-api` calls it through `asyncio.create_subprocess_exec` with a timeout and memory limit. No compiler library is imported into Python.

Alternatives considered:

- Compiling the engine to WASM adds a runtime dependency for no gain.
- Dispatching validation to a live agent makes validation depend on endpoint availability.
- Using a Python YARA library would break engine parity.

#### Capability

`GET /api/yara/capabilities`

Returns the output of `yaracheck capabilities` together with the agent engine versions seen in heartbeats:

- engine name and version;
- supported modules and string modifiers;
- maximum rule size and scan size;
- whether validation, testing, and deployment are available;
- the share of online agents running a compatible engine.

If `yaracheck` is missing, the endpoint returns `validation: false`. Section 10.8 then degrades to `draft_only`.

#### Validation

`POST /api/yara-rules/validate`

Accepts rule text and returns:

- normalized diagnostics with line and column;
- capability failures, such as an unsupported module;
- the warnings from section 10.6;
- a compiled fingerprint;
- the engine version.

#### Test

`POST /api/yara-rules/{id}/test`

Accepts a rule **revision** plus governed sample IDs, approved corpus selectors, and/or explicit agent targets. Returns matches, non-matches, errors, elapsed time, engine version, and corpus revision.

- Server-side samples and corpora are scanned with `yaracheck scan`.
- Endpoint tests need a **rule-scoped scan**: a scan task that carries the rule text (or revision ID) explicitly instead of using the enabled ruleset. Today's `*.Detection.Yara` artifacts cannot do this. The full-YARA effort must add a `Rules` parameter (revision IDs, resolved server-side) to the `yara` plugin task. Endpoint testing is unavailable until that parameter exists.

#### Scan

The existing rule-scan path remains the orchestration entry point. It must return structured results:

- rule revision;
- engine version;
- target scope;
- scanned file count;
- errors;
- matches.

On-access matches from enabled rules must carry the rule ID and revision so section 10.9 can link the resulting alerts.

#### Ownership

| Item | Owner |
|---|---|
| Engine, `yaracheck` binary, and its release pinning | full-YARA effort |
| Rule-scoped scan parameter on the agent `yara` plugin | full-YARA effort |
| Rule ID and revision in on-access match events | full-YARA effort |
| `/api/yara/capabilities`, `/validate`, `/test` endpoints (wrappers around `yaracheck`) | this feature |
| Rule revisions, lifecycle states, quality warnings, activation dialog | this feature |
| Feature collector, eligibility, draft generation | this feature |

The AI feature does not import compiler libraries or change the agent's YARA runtime.

### 10.8 Feature modes

Platform setting `yara_ai_generation` supports:

- `off`: no draft option.
- `draft_only`: collect features and save disabled drafts; validation/scan unavailable.
- `full`: capability validation, test, review, activation, and scan integration.

If the full-YARA dependency is unavailable, the system degrades to `draft_only` and explains the gap. Partial availability degrades only the affected step:

- No `yaracheck` binary: validation and server-side tests are disabled.
- No rule-scoped scan on the agents: endpoint tests are disabled, and server-side corpus tests still run.
- Fewer than a configurable share of online agents (default 90%) run a compatible engine: activation shows a blocking warning listing the incompatible agents.

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
- `GET /api/cases/{case_id}/investigations/{id}/hypotheses`
- `POST /api/cases/{case_id}/investigations/{id}/hypotheses` (analyst hypothesis)
- `POST /api/cases/{case_id}/investigations/{id}/budget` (one-time flow budget raise, section 6.5)
- `POST /api/flow-artifacts/{name}/promote` (AI artifact promotion, section 6.2)
- `POST /api/investigation-actions/{id}/decision` (approve or reject an action the policy held; commands keep their own route)
- `POST /api/investigation-hypotheses/{id}` (analyst update: state, confidence, evidence links)
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

- Phase 1a keeps the existing single-owner loop. A restart marks the run `interrupted`, and its persisted ledger remains readable.
- Phase 1b: queue claims use atomic conditional updates and leases (section 6.6).
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
- Risk-tier policy for `create_artifact` and `run_artifact`: an AI artifact from another investigation needs approval, and a non-read-only plugin is Tier 2.
- Budget enforcement for every row in section 6.5, including the per-host concurrency cap across investigations.
- Structured report validation: missing citations, foreign evidence IDs, `knowledge_guidance` used as proof, the repair attempt, and verdict downgrade.
- Hypothesis state rules: `supported` without evidence is rejected, and the model cannot close an analyst hypothesis.
- `yaracheck` wrapper: timeout, oversized input, malformed JSON output, and binary missing (degrades to `draft_only`).

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
- Phase 1a: an analyst add/skip during a running loop is honored at the next round, and the persisted ledger survives an `interrupted` restart.
- Phase 1b: kill the replica holding an investigation lease mid-flow. The other replica takes over, reconciles the flow, and does not re-dispatch it.
- Engine parity: the `differential_test.go` corpus gives identical match results through `yaracheck scan` and through the agent.
- A rule-scoped endpoint test of a disabled draft never changes the heartbeat ruleset hash.

### Manual QA

1. Investigate a Windows process alert and observe the editable queue.
2. Add a read-only endpoint action while the investigation is running.
3. Reject a custom command and verify the AI adapts without asking again.
4. Publish a scoped DFIR article and confirm retrieval/citation.
5. Import a small Obsidian vault and verify backlinks.
6. Investigate a governed malware sample, generate a YARA draft, validate/test it, and confirm it remains disabled until review.
7. Trigger a reviewed rule match and verify alert/case provenance.

## 16. Rollout

### Phase 1a: Persisted ledger on the existing loop

- Add `investigation_actions`, `investigation_evidence`, `investigation_hypotheses`, and the new `case_investigations` and `flow_artifacts` columns.
- Write the ledger from the current loop, and add analyst add/skip at round boundaries.
- Add the editable queue, evidence, and hypotheses UI.
- Add the structured report with citation enforcement.
- Add the risk-tier policy for AI artifacts and the budgets from section 6.5.
- Preserve current tools, command approval, and timeline behavior.

### Phase 1b: Durable, replica-safe orchestrator

- Leases, stateless planner/replanner calls, action claims, and lease takeover with flow reconciliation.
- Replace `mark_stale_interrupted()` with resume.

Phase 1b depends only on Phase 1a. It may run in parallel with Phase 2.

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
- Depends on `feat/yara-full` being merged into `feature/siem-implementation`, plus the three full-YARA items in the section 10.7 ownership table.

### Phase 5: Feedback and tuning

- Knowledge created from completed cases.
- Detection quality dashboards.
- Ranking and investigation-plan tuning from analyst feedback.

## 17. Acceptance Criteria

Criteria are numbered as before and grouped by the phase that must satisfy them. Each phase ships when its own criteria pass.

**Phase 1a**

1. Clicking Investigate immediately starts a useful read-only plan.
2. Analysts can add, skip, and stop work without corrupting the investigation.
3. Risky commands still require existing RBAC and approval controls, and AI-authored artifacts follow the section 6.2 policy.
5. Every verdict claim links to evidence, enforced by section 8.1 validation, not by prompt instructions.
11. No investigation exceeds the section 6.5 budgets, and no host exceeds its concurrent-flow cap.

**Phase 1b**

4. Restarts and replica loss do not duplicate endpoint commands or flows, and the investigation resumes instead of becoming `interrupted`.

**Phase 2**

6. Published Markdown knowledge is automatically indexed, scoped, cited, and auditable.
7. Draft/untrusted/cross-group knowledge cannot influence unauthorized investigations.

**Phase 3**

8. Malware evidence can produce a disabled, provenance-rich YARA draft.
10. The feature operates in draft-only mode until the separate full-YARA capability is available.

**Phase 4**

9. No YARA draft can activate without validation, test, permission, and analyst review.
12. Validation and server-side tests use the same engine build as the agents (`yaracheck`), and testing a draft never changes the deployed ruleset.

## 18. Open Questions

1. **Per-host concurrency across investigations (section 6.5).** This needs a shared counter that is visible to both replicas. Use the database (a count of running flows per agent) or Redis? The database is simpler and is already queried for flows. Redis is cheaper per check.
2. **AI artifact promotion.** Should promoted `AI.*` artifacts be renamed into the normal namespace, or keep the prefix as provenance? The recommendation is to keep the prefix.
3. **Model support for structured output.** Which configured investigation models reliably return the section 8.1 schema? The fallback path must be measured before acceptance criterion 5 is claimed for those models.
4. **`yaracheck` distribution.** Should it be built in the `server-api` Docker image from the agent sources, or downloaded as a release artifact pinned to the agent version? Building in the image guarantees parity but couples the server build to the Go toolchain.
5. **Staged YARA deployment.** Activation is currently all-or-nothing across the fleet. Should the full-YARA effort add a deployment scope (agent label or group) so a new AI rule can go to a canary set first? This design works without it but would use it.
6. **Phase 1b placement.** Should the orchestrator run in `server-api` (where the tools live today) or move to `worker`? The design assumes `server-api` to avoid moving the tool implementations.

