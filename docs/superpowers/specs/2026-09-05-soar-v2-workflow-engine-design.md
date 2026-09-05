# SOAR v2 — Visual Workflow Engine
**Date:** 2026-09-05
**Status:** Draft

---

## 1. Why

SOAR v1 (`docs/superpowers/plans/2026-05-29-soar-engine.md`) ships a flat model: a `SoarPlaybook` has one set of AND/OR trigger conditions and an **ordered list** of `SoarAction` rows, executed top to bottom, synchronously, inside the alert ingest path. That covers "if alert matches X, do A then B" and nothing else. It cannot express:

- Branching ("if severity is critical, block IP; otherwise just enrich")
- Waiting ("send Slack, wait 10 minutes for no reply, then escalate")
- Looping ("for each IP in the TI report, block on every online agent")
- Human-in-the-loop approval before a destructive action (isolate host, block IP)
- Arbitrary outbound calls to a ticketing/chat system without a bespoke handler
- Any trigger other than "alert was just created"
- Any record of what actually happened when a playbook fired (no run history — only `structlog` lines)

The target is a graph-based workflow engine in the shape of n8n/Shuffle: **nodes + edges**, a **resumable execution engine** (so delay/approval nodes can pause for minutes/hours without blocking a worker), and a **visual canvas** in the dashboard.

---

## 2. Verified current state

| Concern | Where | Limitation |
|---|---|---|
| Trigger evaluation | `worker/worker/soar_engine.py:53` `_matches_trigger` | Flat condition list, single match mode (`all`/`any`), no nesting |
| Action execution | `worker/worker/soar_engine.py:263-271` `_ACTION_HANDLERS` | 7 hardcoded handlers, executed in `order_index` sequence, no conditional skip, no data passed between actions beyond the fixed `ctx` dict built once at dispatch |
| Dispatch site | `worker/worker/alert_manager.py:205` | Only call site; fired synchronously inline after alert commit, wrapped in a single `try/except` that swallows all failures |
| Second dispatch site | `worker/worker/ai_analyst.py:544` | Fire-and-forget `asyncio.ensure_future(run_soar_playbooks(...))` after AI verdict — same engine, same limitations |
| Data model | `worker/worker/models.py:256-274` (`SoarPlaybook`, `SoarAction`), mirrored in `server-api/app/models/models.py` | No columns for graph position, no node output schema, no run/execution table at all |
| API | `server-api/app/api/routes/soar.py` | CRUD for playbook + flat action list only |
| Frontend | `dashboard/src/pages/SoarPage.tsx` | Form-based editor (dropdowns + rows), no canvas, registered at `/soar` in `App.tsx:70`, nav item in `Layout.tsx:58` |
| Async task pattern already in the codebase | `worker/worker/hunt_scheduler.py` | A DB-polling loop (`while True: ... await asyncio.sleep(1800)`) registered via `asyncio.gather(...)` in `worker/worker/main.py:141-155` — this is the existing pattern for "check a table on an interval and act," and it's the one SOAR v2's delay/schedule resumption reuses instead of introducing a new task-queue dependency (no Celery in this codebase — confirmed via repo-wide grep). |
| Similar async task-and-poll pattern | `worker/worker/soar_engine.py:183-260` (`_action_isolate_agent`, `_action_block_ip`) | Already writes to `AgentTask` (pending → agent polls → completed) instead of blocking — same "write row, someone else's poll loop advances it" shape SOAR v2 generalizes. |

---

## 3. Target architecture

```
┌────────────────────────────────────────────────────────────────┐
│  Dashboard (React + @xyflow/react canvas)                      │
│  WorkflowEditorPage: drag nodes, connect edges, configure       │
│  panel, Run History tab (per-run step timeline + approve btn)   │
└───────────────────────────┬──────────────────────────────────────┘
                            │ REST (bulk graph save, run/approve endpoints)
┌───────────────────────────▼──────────────────────────────────────┐
│  server-api  (server-api/app/api/routes/soar_v2.py)             │
│  CRUD workflows/nodes/edges · run history · manual run          │
│  · approve/reject · inbound webhook trigger endpoint            │
└───────────────────────────┬──────────────────────────────────────┘
                            │ writes SoarRun (status=pending)
┌───────────────────────────▼──────────────────────────────────────┐
│  worker  (worker/worker/soar_v2/engine.py)                      │
│  step(): load run → load current node → execute → persist       │
│  variables + SoarRunStep → advance cursor OR set                │
│  status=waiting_delay/waiting_approval OR completed/failed      │
│                                                                  │
│  worker/worker/soar_v2/scheduler.py  (new poll loop, same shape  │
│  as hunt_scheduler.py) — finds runs with                        │
│  status=waiting_delay AND resume_at <= now(), calls step()       │
└────────────────────────────────────────────────────────────────┘
```

Execution is **not** a single synchronous function call anymore. A run is a row that gets stepped forward — once immediately on dispatch, then again either immediately (normal node) or later (delay/approval node) by the scheduler loop. This is what makes "wait 10 minutes" or "wait for a human" possible without holding a worker task open.

---

## 4. Data model

New tables (worker + server-api models kept in sync, same as `SoarPlaybook`/`SoarAction` are today):

```sql
CREATE TABLE soar_workflows (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    description      TEXT,
    is_enabled      BOOLEAN NOT NULL DEFAULT true,
    group_id        VARCHAR(100) NOT NULL DEFAULT 'default',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE soar_nodes (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id  UUID NOT NULL REFERENCES soar_workflows(id) ON DELETE CASCADE,
    node_type    VARCHAR(50) NOT NULL,   -- see §5
    name         VARCHAR(255) NOT NULL,
    config       JSONB NOT NULL DEFAULT '{}',
    pos_x        DOUBLE PRECISION NOT NULL DEFAULT 0,
    pos_y        DOUBLE PRECISION NOT NULL DEFAULT 0
);

CREATE TABLE soar_edges (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id    UUID NOT NULL REFERENCES soar_workflows(id) ON DELETE CASCADE,
    source_node_id UUID NOT NULL REFERENCES soar_nodes(id) ON DELETE CASCADE,
    source_handle  VARCHAR(50) NOT NULL DEFAULT 'out',  -- 'out' | 'true' | 'false' | 'case:<value>'
    target_node_id UUID NOT NULL REFERENCES soar_nodes(id) ON DELETE CASCADE
);

CREATE TABLE soar_runs (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id    UUID NOT NULL REFERENCES soar_workflows(id) ON DELETE CASCADE,
    status         VARCHAR(20) NOT NULL DEFAULT 'pending',
        -- pending | running | waiting_delay | waiting_approval | completed | failed | cancelled
    trigger_type   VARCHAR(30) NOT NULL,   -- alert_match | webhook | schedule | manual
    trigger_ref    JSONB NOT NULL DEFAULT '{}',   -- e.g. {"alert_id": "..."}
    current_node_id UUID REFERENCES soar_nodes(id),
    variables      JSONB NOT NULL DEFAULT '{}',   -- accumulated output of every node, keyed by node name
    resume_at      TIMESTAMPTZ,             -- set by delay nodes; scheduler polls on this
    group_id       VARCHAR(100) NOT NULL DEFAULT 'default',
    started_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at    TIMESTAMPTZ
);

CREATE TABLE soar_run_steps (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id      UUID NOT NULL REFERENCES soar_runs(id) ON DELETE CASCADE,
    node_id     UUID NOT NULL REFERENCES soar_nodes(id),
    status      VARCHAR(20) NOT NULL,   -- ok | error | skipped
    input       JSONB,
    output      JSONB,
    error       TEXT,
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ
);
```

`soar_playbooks`/`soar_actions` are **not dropped**. A one-time migration script (Phase 0, see plan doc) converts every existing enabled playbook into an equivalent trivial graph: one `trigger` node (`alert_match`, config = old `trigger_conditions`) fanning into the old actions re-created as `action` nodes chained in `order_index` order. Old tables are kept read-only for one release as a rollback path, then dropped in a follow-up cleanup task — never referenced by new code after cutover.

---

## 5. Node type registry (v1 of the new engine)

Every node reads from `run.variables` (a dict keyed by node name, populated as each upstream node completes) and the fixed trigger context (`severity`, `rule_title`, `source_ip`, `hostname`, `user_name`, `tags`, `mitre_tags`, `ai_verdict`, `ai_confidence`, `ti_risk_score` — unchanged from `soar_engine.py:285-297`).

| `node_type` | `config` shape | Behavior |
|---|---|---|
| `trigger` | `{"trigger_type": "alert_match", "conditions": [...], "match": "all"}` | Entry point. Not "executed" — matched at dispatch time to decide whether to create a run at all. |
| `action` | `{"action_type": "enrich_ioc"\|"send_webhook"\|"create_case"\|"suppress_alert"\|"add_note"\|"isolate_agent"\|"block_ip", "params": {...}}` | Wraps the 7 existing handlers in `soar_engine.py` unchanged — reused, not rewritten. |
| `condition` | `{"conditions": [...], "match": "all"}` | Evaluates like today's trigger matcher; emits edge handle `true` or `false`. Exactly one of the two outgoing edges is followed. |
| `delay` | `{"seconds": 600}` | Sets `run.status = waiting_delay`, `run.resume_at = now() + seconds`. Scheduler loop resumes it. |
| `http_request` | `{"method": "POST", "url": "...", "headers": {...}, "body_template": {...}}` | Generic outbound call. **SSRF guard (mandatory, see §7): resolve host, reject RFC1918/loopback/link-local targets unless the target host is explicitly present in an admin-managed allowlist setting.** Response status + parsed JSON body stored as node output. |
| `approval` | `{"prompt": "...", "required_role": "analyst"}` | Sets `run.status = waiting_approval`. Resumed only via `POST /api/soar/runs/{id}/approve` or `.../reject` — never by the scheduler's time-based poll. |
| `loop` | `{"over": "$.variables.enrich.ips", "node_id": "<subgraph entry>"}` | Iterates a JSON array from a prior node's output, executing the referenced downstream node once per item with `variables._loop_item` set. Nesting depth 1 only in v1 (see §8 out of scope). |

Frontend node palette (§6) maps 1:1 to this table — the config panel per node type reuses the exact param-editing inputs already written in `SoarPage.tsx:99-146` (`ActionRow`) rather than rebuilding them.

---

## 6. Frontend

- New page `dashboard/src/pages/WorkflowEditorPage.tsx`, route `/soar/workflows/:id`, using `@xyflow/react` (CDN/npm, MIT-licensed, the standard React canvas lib n8n's OSS predecessor and several SOAR-style tools build on).
- `SoarPage.tsx` becomes the **workflow list** (rename in place: list + enable toggle + "Open canvas" instead of "Edit" opening the modal form). The old `PlaybookEditor` modal is deleted once cutover (§8/Phase 6) completes.
- Canvas: left sidebar = node palette (grouped by row in §5), center = `<ReactFlow>` canvas with custom node components per `node_type`, right-side drawer = config panel for the selected node (opens on click, same interaction as today's `ActionRow` expand-on-click at `SoarPage.tsx:122-126`).
- Save is a single bulk `PUT /api/soar/workflows/{id}/graph` with the full `{nodes, edges}` payload (diffed server-side) — not per-node CRUD calls — because a canvas edit session touches many nodes/edges at once and per-node round-trips would be both slow and hard to keep consistent.
- New **Run History** tab on the workflow detail view: table of `SoarRun` rows (status, trigger_type, started_at) → click a run → vertical step timeline of `SoarRunStep` rows (node name, status, input/output JSON, error). This is the piece SOAR v1 has zero equivalent of today.
- Approval nodes surface a banner/toast (reusing `dashboard/src/components/Toaster.tsx`) with Approve/Reject buttons when a run the current user's role can act on is `waiting_approval`.

---

## 7. Security

- **`http_request` node is the SSRF surface.** Config is admin-authored (same trust level as today's `send_webhook` action, which already exists unguarded at `soar_engine.py:96-116` — v2 does not regress that, but a generic method+arbitrary-body node raises the stakes enough to add the guard now rather than carry the gap forward). Resolve the hostname before connecting; reject loopback, link-local, and RFC1918 ranges unless explicitly allowlisted in `platform_settings`. Apply the same guard retroactively to `send_webhook`.
- **`approval` node `required_role`** is enforced server-side on the approve/reject endpoint via the existing `get_current_user`/role-check dependency pattern already used across `server-api/app/api/routes/*.py` — never trust a client-supplied role.
- **No code/script node in v1.** An arbitrary-Python node (n8n's "Function" node equivalent) is a sandboxing problem (RCE if under-restricted) disproportionate to the ask here; out of scope, revisit only with a proper sandboxed runtime (e.g. subprocess + seccomp, or WASM) as its own spec.
- Group scoping (`group_id`) on `soar_workflows`/`soar_runs` follows the existing `get_scoped_group` dependency pattern already used in `soar.py:68` — unchanged.

---

## 8. Out of scope for v1

- Nested loops (depth > 1), loop-of-loops
- Workflow versioning/rollback (edit is destructive; no history of graph edits)
- A public "marketplace" of community-contributed node types
- Sub-workflow (call another workflow as a node) — natural v2.1 addition once the run-step model is proven
- Cron-expression scheduling (v1 schedule trigger reuses `HuntSchedule`'s simple `interval_hours` shape, not full cron)

---

## 9. Rollback plan

Old `soar_playbooks`/`soar_actions` tables and `worker/worker/soar_engine.py`'s `run_soar_playbooks()` stay in place and functional through Phase 5. If the v2 engine misbehaves in production, revert the two call sites (`alert_manager.py:205`, `ai_analyst.py:544`) to call the old function — a one-line change per site — and hide the new nav/routes. Nothing is deleted until Phase 6, which only runs after a verification window.
