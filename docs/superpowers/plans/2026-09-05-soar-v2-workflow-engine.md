# SOAR v2 Workflow Engine — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace SOAR v1's linear trigger-conditions + ordered-action-list model with a graph (nodes + edges) workflow engine that supports branching, delay, human-approval, generic HTTP calls, and a visual drag-and-drop canvas — without breaking existing playbooks mid-migration.

**Design spec:** `docs/superpowers/specs/2026-09-05-soar-v2-workflow-engine-design.md` — read it first. This plan implements that spec phase by phase; each phase is independently shippable and the old engine keeps running until Phase 6.

**Tech stack:** Same as v1 (PostgreSQL JSONB, SQLAlchemy async ORM, FastAPI, React + TanStack Query) plus `@xyflow/react` for the canvas (new frontend dependency).

---

## Phase 0 — Schema + one-time data migration

**Global constraints for every task in this phase:**
- Do **not** modify or drop `soar_playbooks`/`soar_actions` — SOAR v1 keeps running unmodified through this phase.
- This repo has no Alembic/migration framework — table creation goes through hand-written `CREATE TABLE IF NOT EXISTS` SQL via `text()`, following the exact pattern already used by `_migrate_soar_tables()` in `server-api/app/main.py:288`.
- Exact column definitions for all five new tables are in `docs/superpowers/specs/2026-09-05-soar-v2-workflow-engine-design.md` §4 — copy them verbatim, do not improvise column names or types.

### Task 1: Add SOAR v2 ORM models (both codebases)

**Files:**
- `worker/worker/models.py` — add `SoarWorkflow`, `SoarNode`, `SoarEdge`, `SoarRun`, `SoarRunStep` ORM models (see spec §4 for exact columns)
- `server-api/app/models/models.py` — same five models, API side (kept in sync with worker side, matching how `SoarPlaybook`/`SoarAction` are duplicated today)

**Requirements:**
- Column names, types, nullability, defaults, and foreign keys must match spec §4 exactly (`soar_workflows`, `soar_nodes`, `soar_edges`, `soar_runs`, `soar_run_steps`).
- Both `models.py` files must define identical columns for all five tables — this mirrors how `SoarPlaybook`/`SoarAction` are already duplicated between the two codebases (`worker/worker/models.py:256-274`).
- Do not add a migration/table-creation call in this task — that's Task 2.
- Do not write the data-migration script in this task — that's Task 3.

### Task 2: Add `_migrate_soar_v2_tables()`

**Files:**
- `server-api/app/main.py` — add `_migrate_soar_v2_tables()` alongside the existing `_migrate_soar_tables()` (pattern at `server-api/app/main.py:288`), call it in the lifespan startup list (`server-api/app/main.py:376`)

**Requirements:**
- `CREATE TABLE IF NOT EXISTS` for all five new tables (`soar_workflows`, `soar_nodes`, `soar_edges`, `soar_runs`, `soar_run_steps`), same raw-SQL-via-`text()` style as `_migrate_soar_tables()`.
- Register the new function in the same startup call list that already calls `_migrate_soar_tables()` (`server-api/app/main.py:376`), added after it (new tables reference no columns from the old ones, but keeping migration order predictable matters more than it seeming to not matter here).
- Depends on Task 1's ORM models existing (for column-definition parity) but does not import them — this is raw SQL, matching how `_migrate_soar_tables()` itself doesn't import `SoarPlaybook`.

### Task 3: Write and dry-run the v1→v2 data-migration script

**Files:**
- `server-api/app/scripts/migrate_soar_v1_to_v2.py` — one-time script: for every `SoarPlaybook`, create a `SoarWorkflow` + one `trigger` node (`config = {"trigger_type": "alert_match", "conditions": playbook.trigger_conditions.conditions, "match": playbook.trigger_conditions.match}`) + one `action` node per `SoarAction` ordered by `order_index`, chained edges `trigger → action1 → action2 → ...`

**Requirements:**
- Depends on Task 1 (ORM models) and Task 2 (tables must exist) — run after both are complete.
- For every `SoarPlaybook` row (regardless of `is_enabled` — migrate everything, enabled state carries over unchanged onto the new `SoarWorkflow.is_enabled`): create one `SoarWorkflow` (same `name`, `description`, `is_enabled`, `group_id`), one `trigger` node, one `action` node per existing `SoarAction` ordered by `order_index`, and edges chaining them in sequence (`trigger → action[0] → action[1] → ... → action[n-1]`).
- Script must be idempotent-safe to re-run against the same DB without duplicating rows on a second run (e.g., skip a playbook if a `SoarWorkflow` with the same source name already exists from a prior run — use whatever guard is simplest, but state the guard explicitly in the script's docstring since there's no unique constraint enforcing it).
- Dry-run the script against the current dev DB (the `soar_platform` Postgres database, container `siem-platform-postgres-1` in this environment) and report actual counts: number of `SoarPlaybook` rows migrated, resulting `SoarWorkflow`/`SoarNode`/`SoarEdge` row counts. Verify per-workflow: node count = 1 + action count, edge count = node count - 1.
- Report the dry-run output (row counts, any playbooks skipped/failed and why) in the task report — this is the acceptance evidence for the task, not just "script written."

---

## Phase 1 — Execution engine core (trigger / action / condition / delay only)

> Each `#### Task N` below is an outline stub, not a full brief — flesh it out (Files/Requirements, matching Phase 0's `### Task` sections) before dispatching it. The heading exists now so plan tooling (`task-brief`) has a stable boundary to extract against.

#### Task 4 — engine core (trigger/action/condition)

Create `worker/worker/soar_v2/__init__.py`, `worker/worker/soar_v2/engine.py` with `dispatch_trigger(trigger_type, ctx)` and `step(run_id)` (trigger/action/condition node types only — see spec §5/§6). Action nodes call the *existing* handlers in `worker/worker/soar_engine.py:_ACTION_HANDLERS` unchanged — do not reimplement them.

#### Task 5 — delay node + scheduler

Add `delay` node handling to `step()` (`waiting_delay` + `resume_at`). Create `worker/worker/soar_v2/scheduler.py`, a poll loop modeled directly on `worker/worker/hunt_scheduler.py` (every 30s, `SELECT * FROM soar_runs WHERE status='waiting_delay' AND resume_at <= now()`, call `step(run.id)`). Register it in `worker/worker/main.py`'s `asyncio.gather(...)` list (`worker/worker/main.py:141-155`).

#### Task 6 — switch dispatch call sites + integration test

Replace `run_soar_playbooks(...)` with `dispatch_trigger("alert_match", ctx)` at `worker/worker/alert_manager.py:205` and `worker/worker/ai_analyst.py:544`. Keep `worker/worker/soar_engine.py` importable and untouched. Integration test: alert fires → migrated-from-v1 workflow (Phase 0 output) runs identically to how it ran under `soar_engine.py`.

---

## Phase 2 — API layer

> Flesh out before dispatching (see Phase 1's note above).

#### Task 7 — CRUD + bulk graph endpoints

Create `server-api/app/api/routes/soar_v2.py` with `GET/POST /api/soar/workflows`, `GET /api/soar/workflows/{id}`, `PUT /api/soar/workflows/{id}/graph` (bulk replace — update-in-place by node id when present since `SoarRunStep.node_id` must survive, insert when new, delete rows absent from payload). Register the router in `server-api/app/main.py`. Group-scoped via `get_scoped_group` (same dependency `soar.py:68` already uses).

#### Task 8 — run history + manual run + approval endpoints

`GET /api/soar/workflows/{id}/runs`, `GET /api/soar/runs/{id}`, `POST /api/soar/workflows/{id}/run` (manual trigger — decide during implementation whether this needs a direct `SoarRun` insert with `status=pending` picked up by an extended scheduler poll, or a cross-process call; a direct insert + poll avoids adding a new cross-process mechanism), `POST /api/soar/runs/{id}/approve`, `POST /api/soar/runs/{id}/reject` (flip `waiting_approval` → `running`/`failed`, enforce `required_role` from the node's `config`).

---

## Phase 3 — Node library expansion

> Flesh out before dispatching.

#### Task 9 — `http_request` node + SSRF guard

Add `http_request` node handler to `worker/worker/soar_v2/engine.py`. Create `worker/worker/soar_v2/ssrf_guard.py` (hostname resolution + private-range rejection, spec §7) — test asserting a request to `169.254.169.254` and `127.0.0.1` are both rejected before any connection is attempted. Retrofit the same guard into `_action_send_webhook` in `soar_engine.py`.

#### Task 10 — `loop` and `approval` nodes

Add `loop` node (single-level iteration over a JSON array from `run.variables`) and register `approval` in the engine's dispatch table (wiring for `waiting_approval` already exists from Phase 1/2 — this task just adds the node type).

---

## Phase 4 — Trigger expansion

> Flesh out before dispatching.

#### Task 11 — inbound webhook trigger

Add `POST /api/soar/triggers/webhook/{workflow_id}/{token}` to `server-api/app/api/routes/soar_v2.py` (token stored on `SoarWorkflow` or a new column, validated before dispatch, builds ctx from POST body, calls `dispatch_trigger("webhook", ctx)`).

#### Task 12 — scheduled trigger

Create `worker/worker/soar_v2/schedule_trigger.py`, reusing `HuntSchedule`'s polling shape (`worker/worker/hunt_scheduler.py`) for `schedule` trigger type nodes with `interval_hours` config. Register in `worker/worker/main.py`.

---

## Phase 5 — Frontend canvas

> Flesh out before dispatching.

#### Task 13 — dependency + route + list page conversion

Add `@xyflow/react` to `dashboard/package.json`. Add route `/soar/workflows/:id` → `WorkflowEditorPage` in `dashboard/src/App.tsx`. Convert `dashboard/src/pages/SoarPage.tsx` into a workflow list (enable toggle, "Open canvas" link, delete); remove the `PlaybookEditor` modal usage.

#### Task 14 — canvas + config drawer + bulk save

Create `dashboard/src/pages/WorkflowEditorPage.tsx` (canvas via `@xyflow/react`, node palette sidebar, config drawer reusing param-input patterns from `SoarPage.tsx`'s current `ActionRow`, bulk save via `PUT /api/soar/workflows/{id}/graph`) and `dashboard/src/components/soar/nodes/*.tsx` (one custom node component per `node_type`). Canvas renders a loaded graph (nodes positioned via `pos_x`/`pos_y`, edges connecting handles); drag-connect creates edges; condition nodes expose two handles (`true`/`false`); config drawer edits `config` per node type, save triggers bulk `PUT`.

#### Task 15 — run history UI

Create `dashboard/src/pages/WorkflowRunHistoryPage.tsx` (or a tab within `WorkflowEditorPage`) — run list + step timeline, approve/reject buttons for `waiting_approval` runs, wired to a toast (`Toaster.tsx`) for runs the current user can act on.

#### Task 16 — manual QA

Build a 4-node workflow (trigger → condition → delay → action) in the canvas, fire it, watch it move through `pending → running → waiting_delay → completed` in the run history view.

---

## Phase 6 — Cutover and cleanup

> Flesh out before dispatching.

#### Task 17 — production data migration

Run `migrate_soar_v1_to_v2.py` against production data; verify every migrated workflow's first live run matches its pre-migration behavior.

#### Task 18 — nav update

Update `Layout.tsx:58` nav item if the route path changed.

#### Task 19 — retire v1 dispatch entry points

Delete `worker/worker/soar_engine.py`'s dispatch entry points once both call sites (`alert_manager.py`, `ai_analyst.py`) have run on `soar_v2` in production for a verification window with no regressions — keep the action handler functions themselves (imported by `soar_v2/engine.py`, not duplicated).

#### Task 20 — drop v1 tables

Drop `soar_playbooks`/`soar_actions` tables in a follow-up migration, only after Task 19 is verified.
