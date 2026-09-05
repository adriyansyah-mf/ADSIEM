# SOAR v2 Workflow Engine — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace SOAR v1's linear trigger-conditions + ordered-action-list model with a graph (nodes + edges) workflow engine that supports branching, delay, human-approval, generic HTTP calls, and a visual drag-and-drop canvas — without breaking existing playbooks mid-migration.

**Design spec:** `docs/superpowers/specs/2026-09-05-soar-v2-workflow-engine-design.md` — read it first. This plan implements that spec phase by phase; each phase is independently shippable and the old engine keeps running until Phase 6.

**Tech stack:** Same as v1 (PostgreSQL JSONB, SQLAlchemy async ORM, FastAPI, React + TanStack Query) plus `@xyflow/react` for the canvas (new frontend dependency).

---

## Phase 0 — Schema + one-time data migration

**Create:**
- `worker/worker/models.py` — add `SoarWorkflow`, `SoarNode`, `SoarEdge`, `SoarRun`, `SoarRunStep` ORM models (see spec §4 for exact columns)
- `server-api/app/models/models.py` — same five models, API side (kept in sync with worker side, matching how `SoarPlaybook`/`SoarAction` are duplicated today)
- `server-api/app/scripts/migrate_soar_v1_to_v2.py` — one-time script: for every `SoarPlaybook`, create a `SoarWorkflow` + one `trigger` node (`config = {"trigger_type": "alert_match", "conditions": playbook.trigger_conditions.conditions, "match": playbook.trigger_conditions.match}`) + one `action` node per `SoarAction` ordered by `order_index`, chained edges `trigger → action1 → action2 → ...`

**Modify:**
- `server-api/app/main.py` — add `_migrate_soar_v2_tables()` alongside the existing `_migrate_soar_tables()` (pattern at `server-api/app/main.py:288`), call it in the lifespan startup list (`server-api/app/main.py:376`)

**Tasks:**
- [ ] Add the five new ORM models to both `models.py` files with identical column definitions
- [ ] Write `_migrate_soar_v2_tables()` — `CREATE TABLE IF NOT EXISTS` for all five tables (follow the existing raw-SQL-via-`text()` pattern used by `_migrate_soar_tables`, not Alembic — this repo has no migration framework)
- [ ] Write and dry-run `migrate_soar_v1_to_v2.py` against the current dev DB; verify every existing enabled `SoarPlaybook` produces an equivalent `SoarWorkflow` graph (manual check: node count = 1 + action count, edge count = node count - 1)
- [ ] Do **not** modify or drop `soar_playbooks`/`soar_actions` in this phase

---

## Phase 1 — Execution engine core (trigger / action / condition / delay only)

**Create:**
- `worker/worker/soar_v2/__init__.py`
- `worker/worker/soar_v2/engine.py` — `dispatch_trigger(trigger_type, ctx)`: finds enabled workflows whose `trigger` node conditions match `ctx`, creates a `SoarRun` (status=`pending`, `variables={}`) per match, calls `step(run_id)` once immediately. `step(run_id)`: loads run + current node, executes it, writes a `SoarRunStep`, merges output into `run.variables[node.name]`, advances `current_node_id` to the next node via `soar_edges` (following `source_handle` for `condition` nodes), or sets `status=completed` if no outgoing edge, or `status=waiting_delay`+`resume_at` for a `delay` node. Action nodes call the *existing* handlers in `worker/worker/soar_engine.py:_ACTION_HANDLERS` unchanged — do not reimplement them.
- `worker/worker/soar_v2/scheduler.py` — poll loop modeled directly on `worker/worker/hunt_scheduler.py`: every 30s, `SELECT * FROM soar_runs WHERE status='waiting_delay' AND resume_at <= now()`, call `step(run.id)` for each.

**Modify:**
- `worker/worker/alert_manager.py:205` — replace the `run_soar_playbooks(...)` call with `dispatch_trigger("alert_match", ctx)` (build the same ctx dict `run_soar_playbooks` builds internally today at `soar_engine.py:285-297`)
- `worker/worker/ai_analyst.py:544` — same replacement for the AI-verdict dispatch site
- `worker/worker/main.py` — import and register `soar_v2_scheduler_loop()` in the `asyncio.gather(...)` list alongside `hunt_scheduler_loop()` (`worker/worker/main.py:141-155`)

**Tasks:**
- [ ] Implement `step()` for `action` and `trigger` node types only first; unit test a 1-node linear workflow end to end
- [ ] Implement `condition` node branch-following (`true`/`false` handles)
- [ ] Implement `delay` node (`waiting_delay` + `resume_at`) and the scheduler loop resuming it
- [ ] Switch both dispatch call sites; keep `worker/worker/soar_engine.py` importable and untouched (old UI still points at it until Phase 6)
- [ ] Integration test: alert fires → migrated-from-v1 workflow (Phase 0 output) runs identically to how it ran under `soar_engine.py` — same actions, same side effects

---

## Phase 2 — API layer

**Create:**
- `server-api/app/api/routes/soar_v2.py` — `GET/POST /api/soar/workflows`, `GET /api/soar/workflows/{id}` (returns full graph: nodes + edges), `PUT /api/soar/workflows/{id}/graph` (bulk replace nodes/edges — diff against existing rows, delete-then-recreate is acceptable since node/edge IDs are canvas-local, not referenced elsewhere except by `SoarRunStep.node_id`, which must survive — so update-in-place by node id when present, insert when new, delete rows absent from the payload), `POST /api/soar/workflows/{id}/run` (manual trigger), `GET /api/soar/workflows/{id}/runs` (run history list), `GET /api/soar/runs/{id}` (run detail + steps), `POST /api/soar/runs/{id}/approve`, `POST /api/soar/runs/{id}/reject`

**Modify:**
- `server-api/app/main.py` — register the new router

**Tasks:**
- [ ] CRUD + bulk graph save endpoints, group-scoped via `get_scoped_group` (same dependency `soar.py:68` already uses)
- [ ] Run history + run detail endpoints
- [ ] Manual run endpoint — calls into `worker.soar_v2.engine.dispatch_trigger("manual", ctx={})` (requires the API process to be able to enqueue into the worker's execution path — confirm whether this needs a Redis-queued message or a direct DB insert the scheduler will pick up; **decide during implementation**: a direct `SoarRun` insert with `status=pending` plus a fast poll — the scheduler already polls every 30s, add a `pending` status to its `WHERE` clause too — avoids needing a new cross-process call)
- [ ] Approve/reject endpoints: flip `waiting_approval` → `running`/`failed`, enforce `required_role` from the node's `config`

---

## Phase 3 — Node library expansion

**Modify:**
- `worker/worker/soar_v2/engine.py` — add `http_request`, `loop` node handlers

**Create:**
- `worker/worker/soar_v2/ssrf_guard.py` — hostname resolution + private-range rejection helper, used by `http_request` (and retrofitted into `soar_engine.py`'s `_action_send_webhook`, per spec §7)

**Tasks:**
- [ ] `http_request` node with SSRF guard (see spec §7) — write a test asserting a request to `169.254.169.254` (cloud metadata IP) and `127.0.0.1` are both rejected before any connection is attempted
- [ ] Retrofit the same guard into `_action_send_webhook` in `soar_engine.py`
- [ ] `loop` node (single-level iteration over a JSON array from `run.variables`)
- [ ] `approval` node wiring already covered by Phase 1's `waiting_approval` status + Phase 2's approve/reject endpoints — add the node type to the engine's dispatch table here

---

## Phase 4 — Trigger expansion

**Create:**
- `server-api/app/api/routes/soar_v2.py` addition — `POST /api/soar/triggers/webhook/{workflow_id}/{token}` (inbound webhook trigger; token stored on `SoarWorkflow` or a new column, validated before dispatch)
- `worker/worker/soar_v2/schedule_trigger.py` — reuses `HuntSchedule`'s polling shape (`worker/worker/hunt_scheduler.py`) for `schedule` trigger type nodes with `interval_hours` config

**Tasks:**
- [ ] Inbound webhook endpoint validates token, builds ctx from POST body, calls `dispatch_trigger("webhook", ctx)`
- [ ] Scheduled trigger poll loop, registered in `main.py`
- [ ] Manual "Run" button already covered by Phase 2

---

## Phase 5 — Frontend canvas

**Modify:**
- `dashboard/package.json` — add `@xyflow/react`
- `dashboard/src/App.tsx` — add route `/soar/workflows/:id` → `WorkflowEditorPage`
- `dashboard/src/pages/SoarPage.tsx` — becomes workflow list (enable toggle, "Open canvas" link, delete); remove the `PlaybookEditor` modal usage

**Create:**
- `dashboard/src/pages/WorkflowEditorPage.tsx` — canvas (`@xyflow/react`), node palette sidebar, config drawer per selected node (reuse param-input patterns from `SoarPage.tsx`'s current `ActionRow`), bulk save via `PUT /api/soar/workflows/{id}/graph`
- `dashboard/src/components/soar/nodes/*.tsx` — one custom node component per `node_type` (trigger, action, condition, delay, http_request, approval, loop)
- `dashboard/src/pages/WorkflowRunHistoryPage.tsx` (or a tab within `WorkflowEditorPage`) — run list + step timeline, approve/reject buttons for `waiting_approval` runs

**Tasks:**
- [ ] Canvas renders a loaded graph (nodes positioned via `pos_x`/`pos_y`, edges connecting handles)
- [ ] Drag-connect creates edges; condition nodes expose two handles (`true`/`false`)
- [ ] Config drawer edits `config` per node type, save triggers bulk `PUT`
- [ ] Run history tab + approve/reject UI, wired to a toast (`Toaster.tsx`) for `waiting_approval` runs the current user can act on
- [ ] Manual QA: build a 4-node workflow (trigger → condition → delay → action) in the canvas, fire it, watch it move through `pending → running → waiting_delay → completed` in the run history view

---

## Phase 6 — Cutover and cleanup

**Tasks:**
- [ ] Run `migrate_soar_v1_to_v2.py` against production data; verify every migrated workflow's first live run matches its pre-migration behavior
- [ ] Update `Layout.tsx:58` nav item if the route path changed
- [ ] Delete `worker/worker/soar_engine.py`'s dispatch entry points once both call sites (`alert_manager.py`, `ai_analyst.py`) have run on `soar_v2` in production for a verification window with no regressions — keep the action handler functions themselves (imported by `soar_v2/engine.py`, not duplicated)
- [ ] Drop `soar_playbooks`/`soar_actions` tables in a follow-up migration, only after this task list is fully checked off
