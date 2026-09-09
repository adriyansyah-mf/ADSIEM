# SOAR Visual Workflow Engine — Design

**Date:** 2026-09-09
**Status:** Approved design, pending implementation plan
**Scope:** Phase 1 of a two-phase effort. Phase 1 (this spec) delivers the graph
executor and the visual canvas. Phase 2 (separate spec) grows a typed connector
catalogue on top of it.

---

## 1. Problem

SOAR today is a flat, form-based model: a playbook has trigger conditions and a
linear list of actions. Analysts cannot express branching, cannot wait for a
condition, cannot call an external API, and cannot see what data moved between
steps. The requested target is the interaction model of n8n / Shuffle: a node
canvas with branching, per-node data inspection, and an extensible action
catalogue.

## 2. Current state

Verified against the working tree on 2026-09-09, not from documentation.

**v1 (the only live path).** `soar_playbooks` + `soar_actions`. All routes in
`server-api/app/api/routes/soar.py` are `/playbooks` and `/actions`. The engine is
`worker/worker/soar_engine.py`, triggered from `ai_analyst.py`. The frontend
(`dashboard/src/components/soar/PlaybookEditor.tsx`, `ConditionRow`, `ActionRow`)
edits exactly this shape.

**v2 (half-built, disconnected).** The node-graph schema already exists in
`server-api/app/models/models.py`:

| Table | Notable columns |
|---|---|
| `soar_workflows` | `name`, `is_enabled`, `group_id` |
| `soar_nodes` | `node_type`, `config` JSONB, `pos_x`, `pos_y` |
| `soar_edges` | `source_node_id`, `source_handle`, `target_node_id` |
| `soar_runs` | `status`, `trigger_type`, `trigger_ref`, `current_node_id`, `variables`, `resume_at` |
| `soar_run_steps` | `input`, `output`, `error`, `idempotency_key`, `input_hash`, `is_destructive`, `is_reversible`, `actor_id`, `acted_at`, `rollback_of_step_id` |

`server-api/app/services/soar_service.py` already implements step-level execution
semantics: idempotent retry validation, approval, rollback construction, and
rollback application.

`server-api/app/api/routes/soar_executions.py` already exposes the operator half of
that: `GET /api/soar/executions`, `POST /api/soar/executions/{id}/approve` (calling
`approve_step` then `execute_approved_step`), and
`POST /api/soar/executions/{id}/rollback`. All three are registered in
`server-api/app/core/permission_matrix.py:151-153`. **Approval, destructive
execution, and rollback are therefore already live**, including correct
`AgentTask` queuing via `params` with `created_by` set and `agent.is_isolated`
maintained (`soar_service.py:196-208`).

**What is missing:** nothing walks the graph. No file outside `models.py`,
`main.py` (table creation) and `scripts/migrate_soar_v1_to_v2.py` references
`SoarNode`. There is no traversal, no run creation, no workflow/node/edge API
routes, no node-type registry, and no canvas UI. The gap is narrower than it
first appears: the dangerous half is built, the authoring and orchestration half
is not.

**Production data** (queried 2026-09-09): 2 v1 playbooks, 2 v1 actions, and zero
v2 workflows, nodes, and runs. Migration burden is therefore negligible and v2 is
effectively greenfield.

**Pre-existing defect, confined to v1.** `worker/worker/soar_engine.py`'s
`_action_isolate_agent` and `_action_block_ip` are broken in three distinct ways,
one more than previously recorded in `docs/IMPLEMENTATION_STATUS.md`:

1. `soar_engine.py:192` imports `AgentTask` from `worker.models`, where no such
   model is defined — an `ImportError` at execution time.
2. `soar_engine.py:203` passes `payload={}`, but the column is named `params`
   (`server-api/app/models/models.py:380`).
3. `soar_engine.py:210` writes `Agent.is_isolated`, which exists in the database
   (`db/init.sql:50`) and in the server-api model
   (`server-api/app/models/models.py:61`) but **not** in the worker's `Agent`
   model (`worker/worker/models.py:15-21`).

These three defects are **v1-only**. The v2 path does not share this code: its
Block IP and Isolate Host nodes reach `AgentTask` through
`soar_service.execute_approved_step`, which is already correct. The defects
therefore need no fix in phase 1 — they are deleted along with the v1 engine
during retirement (§12). They are recorded here so the deletion is understood as
removing broken code, not working code.

## 3. Goals and non-goals

**Goals.** A persisted, resumable graph executor. A visual canvas with node
palette, per-node configuration, and run inspection showing each node's input and
output. Branching. An extensible node registry. Destructive actions that keep the
approval, idempotency, and rollback guarantees already built in `soar_service.py`.

**Non-goals for phase 1.** A typed connector catalogue (phase 2). A credential
store (phase 2). Arbitrary code execution nodes (rejected outright, see §10).
True parallel branch execution (see §14). Loop constructs (see §14).

## 4. Approach

**Chosen: build the executor on the existing v2 schema, with a React Flow canvas
and a generic HTTP Request node as the connector escape hatch.**

Two alternatives were considered and rejected:

*Embedding n8n or Shuffle as a container.* Buys hundreds of connectors and a
mature canvas for no engine work. Rejected because the destructive actions here
are "isolate this endpoint" and "block this IP". Executing those outside the
platform bypasses the approval, idempotency, and rollback semantics in
`soar_service.py`, splits the tamper-evident audit chain, and sidesteps tenant
scoping — the platform would lose its answer to "who approved this block, and can
it be reversed". n8n's Sustainable Use License is additionally a problem if the
platform is ever sold. n8n remains usable later as a *destination* called from the
HTTP node, which captures most of the connector benefit without surrendering the
engine.

*A minimal engine of trigger/if/http/code only.* Rejected: a code node is
arbitrary code execution inside a security product, and routing every SOC action
through hand-written API calls gives analysts a poor authoring experience while
losing the typed, audited path for destructive operations.

## 5. Execution model

The executor runs in **server-api**, as a background asyncio loop started at
application startup.

This is deliberate and was reconsidered during planning. `server-api` and `worker`
have separate Docker build contexts (`./server-api` and `./worker`, with worker's
Dockerfile copying only `worker/`), so they cannot share code — which is why the
database models are already duplicated across both. Placing the executor in the
worker would therefore force one of two bad outcomes: duplicating the approval,
idempotency, and rollback logic of `soar_service.py` — which is precisely how the
v1 path rotted into the three defects of §2 — or a network hop back into
server-api for every destructive step.

The executor belongs next to the authoritative implementation of the actions it
invokes. The earlier argument for the worker (that workflows may wait hours) does
not survive the step-at-a-time model of this section: a waiting run occupies
nothing, it is a row in the database.

Execution is **step-at-a-time and persisted**, not a single coroutine walking the
graph to completion. Each iteration claims a runnable run, executes exactly one
node, persists a `soar_run_steps` row, and advances `current_node_id`. The
existing schema only makes sense under this model — `current_node_id`,
`variables`, and `resume_at` exist precisely to let a run be reconstructed from
the database.

Consequences: a worker may die mid-workflow without losing progress; Wait and
Approval nodes are free (the run simply sits in `waiting`); and the existing
`idempotency_key` prevents an action from being applied twice on replay.

**Run status lifecycle:** `pending` → `running` → (`waiting`) → `succeeded` |
`failed` | `cancelled`. A run is runnable when it is `pending`, `running`, or
`waiting` with either `resume_at <= now()` or a granted approval.

**Step status vocabulary is already established** by `soar_service.py` and the
executor must reuse it rather than invent parallel values: `pending`,
`pending_approval`, `approved`, `running`, `succeeded`, `rolled_back`. A
destructive step is created as `pending_approval`, a non-destructive one as
`approved` (`soar_service.py:109`).

The executor adds exactly one value, `failed`, for a node whose handler raised.
Nothing in `soar_service.py` produces it, because approval and rollback have no
such outcome — a step there either succeeds or throws before being written. A
graph executor must be able to record the node that broke, so this one addition
is deliberate and is the only permitted extension of the set.

### 5.1 Concurrency

Production runs **two server-api replicas** (`siem-platform-server-api-1`, `-2`),
so two executor loops are live at all times. Without locking, both could claim the
same run and, for example, block an IP twice. Runs are therefore claimed with
`SELECT ... FOR UPDATE SKIP LOCKED` (PostgreSQL 16 is already in use). This is a
correctness requirement, not an optimisation, and has a dedicated test (§11).

### 5.2 Graph snapshot

`soar_runs` gains a `graph_snapshot` JSONB column. On run creation the workflow's
nodes and edges are serialised into it, and **the executor traverses the snapshot,
never the live tables**.

Without this, editing a workflow while a run is in flight corrupts that run:
deleting a node cascades away the row that `current_node_id` and historical
`soar_run_steps.node_id` point at, breaking both the live run and the ability to
render past runs. The snapshot also yields an audit property that matters for a
security product: it preserves exactly what the workflow looked like at the moment
it blocked an IP.

### 5.3 Fan-out

`soar_runs.current_node_id` is a single column and cannot represent two
simultaneously active branches. Phase 1 therefore executes **one active path**: if
a handle has multiple outgoing edges they run sequentially, depth-first, with the
remaining frontier held in a new `soar_runs.pending_node_ids` JSONB column. True
parallel branches are deferred, not forgotten (§14).

### 5.4 Data flow and the expression resolver

Every node receives a JSON input and produces a JSON output, both persisted to the
existing `soar_run_steps.input` / `.output`. Node configuration may reference
earlier results:

```
{{ trigger.alert.source_ip }}
{{ nodes.enrich_ip.output.risk_score }}
{{ vars.escalation_channel }}
```

The resolver is a **restricted dotted-path lookup** — deliberately not Jinja2 and
not `eval`. A general-purpose template engine would reintroduce the
arbitrary-code-execution node that §4 rejected, only through a side door.

The filter set is closed and limited to these four: `default(x)`, `lower`,
`upper`, and `json`. Adding a filter is a deliberate change to this spec, not an
implementation detail — the value of a closed set is that it cannot quietly grow
into an expression language.

Unresolvable paths yield `null` and are recorded in the step rather than raising.

### 5.5 Node registry

Each node type is registered in Python as a handler plus a JSON Schema describing
its configuration. `GET /api/soar/node-types` serves that catalogue and the
frontend **renders the configuration form directly from the schema**. Adding a
node is therefore one Python module and one registry entry, with no frontend
change — which is what makes the phase 2 connector catalogue cheap.

### 5.6 Triggers

- **Alert Trigger** — alerts are created in the worker, but the executor lives in
  server-api (§5), so the two are bridged by Redis, matching the pattern the
  platform already uses for `siem:ai-analysis`. Where `ai_analyst.py` currently
  calls the v1 engine it instead publishes the alert id to a `siem:soar-triggers`
  queue; the server-api executor consumes it, matches enabled workflows' trigger
  filters, and creates a `soar_runs` row with `trigger_type='alert'` and
  `trigger_ref={'alert_id': ...}`. This keeps trigger evaluation — which reads
  workflow definitions — on the side that owns them, so no SOAR model is
  duplicated into the worker.
- **Schedule Trigger** — a cron-style worker loop.
- **Manual Trigger** — an API endpoint used by a "Run now" button.
- **Inbound Webhook Trigger** — an authenticated endpoint that starts a run and
  passes the request body as trigger data.

## 6. Schema changes

All additive, applied by the existing startup-migration pattern in
`server-api/app/main.py`:

| Change | Purpose |
|---|---|
| `soar_runs.graph_snapshot` JSONB | §5.2 |
| `soar_runs.pending_node_ids` JSONB | §5.3 |

No table is created or dropped, and no worker-side model changes are needed: the
executor lives in server-api (§5), whose models are already complete.
`soar_playbooks` and `soar_actions` are retained through this release (§12).

## 7. Node catalogue — phase 1

| Group | Nodes |
|---|---|
| Trigger | Alert Trigger (filtered), Schedule, Manual, Inbound Webhook |
| Logic | If, Switch, Wait/Delay, Set Variables |
| Data | HTTP Request |
| SOC action | Enrich IOC, Create Case, Add Note, Update Alert Status, Block IP, Isolate Host |
| Human | Require Approval |
| Notification | Send Email, Send Webhook (Slack/Discord/Teams formatting) |
| AI | AI Analyze |

Branching nodes emit a handle name that selects the outgoing edge: If emits
`true` / `false`; Switch emits `case_<n>` or `default`.

**Block IP and Isolate Host route through `soar_service.py`**, not around it, so
approval, idempotency, and rollback continue to apply. Concretely, these nodes
build a `StepPreparation` and persist the step via `build_step_record`; because
their `action_type` is in `DESTRUCTIVE_ACTIONS`, the step is created as
`pending_approval` and the run parks in `waiting`. The already-live
`POST /api/soar/executions/{id}/approve` route then performs the execution. No new
destructive code path is introduced by this spec.

## 8. Frontend

React Flow (`@xyflow/react`), a new dependency. The production bundle is already
1.2 MB — above Vite's 500 kB warning threshold — so the canvas route is
**lazy-loaded** (`React.lazy`) and analysts who never open SOAR do not pay for the
editor.

Layout follows the established n8n/Shuffle convention: node palette on the left
grouped by the categories from `/api/soar/node-types`; canvas in the centre;
configuration panel on the right rendered from the selected node's JSON Schema;
run history in a bottom drawer.

**Run inspector.** Opening a run recolours the canvas by per-node status and
clicking any node shows that step's input, output, error, and duration. This is
read-only replay over `soar_run_steps` and introduces no new backend concept.

**Editing.** A workflow is saved as a whole graph (nodes and edges diffed
server-side) rather than through per-node API calls. In-flight runs are unaffected
because they execute from their snapshot (§5.2).

## 9. Error handling and safety limits

- **Per-node `on_error`**: `fail_run` (default), `continue`, or divert to a
  dedicated `error` handle on the canvas.
- **Retries** with exponential backoff, restricted to retryable classes (HTTP 5xx,
  timeouts, network errors). **Destructive actions are never retried
  automatically**; the idempotency key protects against duplication, but silently
  reattempting "block this IP" is not a decision the engine should make alone.
- **Per-node timeouts.**
- **The executor must commit its database transaction before any HTTP or LLM
  call.** This repeats a defect already paid for in production: a transaction held
  open across a 60–90 s 9router call blocked a migration and stalled live alert
  ingestion. The AI Analyze and HTTP Request nodes are the most likely places to
  repeat it, so the rule is stated here rather than left to memory.

  **Blocking precondition on the connector slice.** As built in slice 1, the
  executor claims a run with `SELECT ... FOR UPDATE SKIP LOCKED` and holds that
  transaction open across the node handler. That is safe only while every handler
  is a fast local database operation, which is true of the six nodes in §7 and of
  nothing beyond them. **The slice that introduces the HTTP Request or AI Analyze
  node must first replace this with a lease-based claim** — mark the run
  `running`, commit, execute unlocked, then reopen a transaction to persist the
  result — or it will hold a row lock across a 60–90 s call and reproduce the
  incident above. This is a precondition, not a cleanup task.
- **Run-level guards**: maximum steps per run, maximum run duration, and maximum
  concurrent runs per workflow and per tenant.
- **Loop protection**: graphs are validated as **acyclic on save**, with the step
  ceiling as a second line of defence. n8n permits loops; phase 1 deliberately
  does not (§14).

## 10. Security

- **No code-execution node**, in phase 1 or later, unless separately specified and
  sandboxed. Arbitrary execution inside the platform that is supposed to detect
  it is not a trade worth making.
- **Expression resolution is path-only** (§5.4) for the same reason.
- **The HTTP Request node requires SSRF protection, and must reuse the existing
  implementation rather than write its own.** `server-api/app/core/outbound_url.py`
  already provides `validate_outbound_url()` plus `PinnedAsyncHTTPTransport`,
  which pins the validated address for the actual request and so also defends
  against DNS rebinding; it is already relied on by `routes/webhooks.py` and
  `routes/rules.py`. In a multi-tenant security platform an unrestricted HTTP node
  is a cannon aimed at `169.254.169.254` and at the platform's own internal
  services — and a second, home-grown guard would inevitably drift from the
  hardened one. This is a further reason the executor belongs in server-api (§5).
- **Tenant isolation**: workflows, runs, and steps are all scoped by the existing
  `group_id`.
- **Destructive actions** retain approval, idempotency, and rollback via
  `soar_service.py`, and remain visible in the audit chain.

## 11. Testing

Test-first, matching the repository's existing workflow.

- Executor against a fake node registry: linear traversal, branch selection by
  `source_handle`, Wait then resume, approval pause then resume, and **idempotent
  replay** (a repeated key does not re-execute).
- **Concurrency**: two executors, one run, executed exactly once — covering the
  two-replica hazard of §5.1.
- Expression resolver, including injection attempts and missing paths.
- HTTP node SSRF: assert it routes through `validate_outbound_url()` and the
  pinned transport. The guard itself is already tested; what needs proving is that
  the node cannot bypass it.
- Per-node handler tests with mocked side effects.
- **Destructive-node contract**: Block IP and Isolate Host must produce a step
  whose `action_type` lands in `DESTRUCTIVE_ACTIONS`, leaving it
  `pending_approval` and the run `waiting` — never executing inline. A test that
  a destructive node cannot self-execute is the guardrail that keeps §7's promise
  true as the catalogue grows.
- One end-to-end integration test against a real database: alert → trigger → run →
  steps → terminal status.

## 12. Migration, retirement, and rollout

**Migration.** The two production playbooks are mapped by hand to equivalent
graphs (Alert Trigger → If → action nodes). With only two, hand-mapping and
verifying is cheaper and safer than trusting `scripts/migrate_soar_v1_to_v2.py`,
which has never been exercised.

**Retirement**, only after v2 is verified in production: remove the `/playbooks`
and `/actions` routes, the v1 path in `worker/worker/soar_engine.py`, the v1
trigger call in `ai_analyst.py`, and `PlaybookEditor` with `ConditionRow` and
`ActionRow`. This is where the three §2 defects disappear — by deletion rather
than repair, since nothing in v2 depends on that code. The `soar_playbooks` and `soar_actions` **tables are retained for one
release** and dropped in a follow-up.

**Rollout.** The v2 executor sits behind a `soar_v2_enabled` platform setting,
defaulting to `false`. Production serves real customer traffic; a new automation
engine capable of blocking IPs should be switched on deliberately after
verification, not silently at deploy time.

## 13. Delivery sequencing

This spec is deliberately larger than one implementation plan. It is delivered as
three, each independently valuable and independently verifiable:

1. **Engine core (headless).** Schema additions, the step executor with claiming
   and snapshotting, the node registry, the expression resolver, workflow/node/edge
   CRUD routes, and the six nodes needed for a real end-to-end run: Alert Trigger,
   If, Create Case, Add Note, Block IP, Isolate Host. The last two only prepare
   steps; execution stays with the existing approve route (§7). Verifiable
   entirely through tests and the API, with no UI.
2. **Canvas and run inspector.** The React Flow editor, schema-driven config
   panel, and per-node run inspection.
3. **Catalogue completion and v1 retirement.** The remaining nodes of §7, the
   hand-mapping of the two production playbooks, and removal of the v1 surface.

Splitting this way keeps the risky part — an engine that can block IPs — behind
tests before any of it is reachable from a UI.

## 14. Deliberate limitations

- **No parallel branches.** One active path per run; fan-out is sequential
  depth-first (§5.3). Lifting this needs a frontier table or a rethink of
  `current_node_id`.
- **No reconverging graphs.** A node may have at most one inbound edge, enforced
  when a workflow is saved. Found during implementation: because the frontier
  keeps no visited-set, a diamond whose two edges leave the *same* handle and
  meet again downstream would execute the shared node once per branch — a
  doubled "block IP" or "isolate host", not a cosmetic bug. If-branching is
  unaffected, since only one handle is ever followed. The traversal implements
  tree semantics, so validation enforces tree semantics and rejects the graph at
  authoring time rather than failing silently at run time. An author who wants a
  shared tail step duplicates that node on each branch until a visited-set
  arrives with parallel execution.
- **No loops.** Graphs must be acyclic (§9).
- **No connector catalogue and no credential store.** Phase 2. Until then external
  systems are reached through the HTTP Request node, and its credentials are a
  known gap: today's API keys live in global `platform_settings`, which is not an
  adequate home for per-workflow secrets.
- **No workflow version history.** Runs snapshot their graph (§5.2), so history is
  inspectable per run, but there is no editable version timeline for a workflow.

## 15. Phase 2 preview

Typed connector nodes registered on the HTTP foundation of §5.5, plus a proper
per-tenant credential store with encrypted values, so that a "Send to Jira" node
is a registry entry rather than a hand-assembled HTTP call.
