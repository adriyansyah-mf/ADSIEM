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
- Dry-run the script against the current dev DB (the `soc_platform` Postgres database, container `siem-platform-postgres-1` in this environment) and report actual counts: number of `SoarPlaybook` rows migrated, resulting `SoarWorkflow`/`SoarNode`/`SoarEdge` row counts. Verify per-workflow: node count = 1 + action count, edge count = node count - 1.
- Report the dry-run output (row counts, any playbooks skipped/failed and why) in the task report — this is the acceptance evidence for the task, not just "script written."

---

## Phase 1 — Execution engine core (trigger / action / condition / delay only)

**Global constraints for every task in this phase:**
- `worker/worker/soar_engine.py` and its `run_soar_playbooks()` entry point stay importable and completely untouched through Task 5 — Task 6 stops calling it from the two dispatch sites but does not delete it (rollback safety per spec §9; deletion is Phase 6 Task 19's job, not this phase's).
- Do not touch `soar_playbooks`/`soar_actions` tables, `server-api/app/api/routes/soar.py`, or `dashboard/src/pages/SoarPage.tsx` — v1's API/UI keep working unmodified throughout.
- No local Python venv/pytest exists in this environment (confirmed in Phase 0) — verification is live dry-run against the running `siem-platform-postgres-1`/`siem-platform-worker-1` containers (same approach Phase 0 Task 3 used: apply/insert via `docker exec ... psql`, run code via `docker cp` + `docker exec ... python3`), plus `ast.parse` syntax checks. Clean up any synthetic test rows afterward, same as Task 3.

### Task 4: Engine core — `dispatch_trigger()` + `step()` for trigger/action/condition nodes

**Files:**
- Create `worker/worker/soar_v2/__init__.py` (empty)
- Create `worker/worker/soar_v2/engine.py`

**Design decisions (binding — do not re-derive or deviate from these):**

1. **`dispatch_trigger(trigger_type: str, ctx: dict) -> None`** is generic and caller-agnostic — it does not know or care where `ctx` came from (alert pipeline, future webhook/manual/schedule triggers in later phases). It:
   - Queries `SoarWorkflow` where `is_enabled == True` and (`group_id == ctx.get("group_id")` or `group_id == "default"`) — same group-scoping semantics as today's `run_soar_playbooks` query in `soar_engine.py`.
   - For each such workflow, loads its node(s) with `node_type == "trigger"`. A workflow may have more than one trigger node (not produced by Phase 0's migration, which always creates exactly one, but the schema allows it and Phase 5's canvas may eventually let users add more) — evaluate every trigger node independently.
   - A trigger node's `config` is shaped `{"trigger_type": "...", "conditions": [...], "match": "all"|"any"}` (this is exactly what Phase 0's migration script wrote). Skip the trigger node if `config.get("trigger_type") != trigger_type`. Otherwise evaluate `config` against `ctx` by **reusing** `worker.soar_engine._matches_trigger(trigger, ctx)` unchanged (import it — it's the same shape `_matches_trigger` already expects: `{"conditions": [...], "match": ...}`) — do not reimplement condition matching.
   - For every trigger node that matches: create one `SoarRun` (`workflow_id`, `status="pending"`, `trigger_type=trigger_type`, `trigger_ref=ctx`, `variables={}`, `group_id=ctx.get("group_id", "default")`). **`trigger_ref` stores the entire `ctx` dict verbatim** (not just an alert id) — this is the durable per-run context that `step()` later hands to action handlers, since the v1 action handlers (`_ACTION_HANDLERS`) require the full `ctx` shape (`severity`, `rule_title`, `source_ip`, `hostname`, `user_name`, `tags`, `mitre_tags`, `ai_verdict`, `ai_confidence`, `ti_risk_score`, plus whatever else the caller includes, e.g. `alert_id`). The caller is responsible for making `ctx` JSON-serializable (e.g. `str()`-ing any UUID) before calling `dispatch_trigger` — `engine.py` does not need to sanitize it.
   - Find the trigger node's own outgoing edge (`SoarEdge` where `source_node_id == trigger_node.id`, default `source_handle == "out"`) and set the new run's `current_node_id` to that edge's `target_node_id` (or `None` if the trigger has no outgoing edge — an empty/degenerate workflow). **The trigger node itself is never executed by `step()`** and gets no `SoarRunStep` row — it is purely a dispatch-time filter (spec §5).
   - After creating the run, call `step(run.id)` once (synchronously, in the same call).

2. **`step(run_id: uuid.UUID) -> None` runs an internal loop, not a single node.** One external call to `step()` must advance the run all the way to its next stopping point — completed, failed, or (Task 5) suspended for a delay — not just one node. Loop:
   - Re-fetch the `SoarRun` row fresh at the top of the function (defends against the scheduler double-invoking a run whose state changed since it was queued — see Task 5). If `run.status` is not one of `"pending"`, `"running"` (Task 5 adds `"waiting_delay"` as a valid re-entry status), return immediately (no-op) — the run is already terminal or being handled elsewhere.
   - Set `run.status = "running"` if it was `"pending"`.
   - If `run.current_node_id is None`: set `run.status = "completed"`, `run.finished_at = now_utc()`, commit, return.
   - Loop: load `node = SoarNode` at `run.current_node_id`.
     - **`node_type == "action"`:** call the existing handler `worker.soar_engine._ACTION_HANDLERS[node.config["action_type"]](alert_id, run.trigger_ref, node.config.get("params", {}))` unchanged (import `_ACTION_HANDLERS` from `soar_engine.py`, do not reimplement any handler). `alert_id` here is `run.trigger_ref.get("alert_id")` parsed back to `uuid.UUID` if present, else `None` (some future trigger types may have no alert). **Catch exceptions from the handler and do NOT halt the run** — log the error into that node's `SoarRunStep` (`status="error"`, `error=str(exc)`) and still advance to the next node. This matches `soar_engine.py`'s existing per-action `try/except` in `run_soar_playbooks` (a single failing action doesn't stop the rest) — Task 6's integration test depends on this behavior being identical to v1. On success, write `SoarRunStep` with `status="ok"`, `output=None` (v1 handlers are side-effect-only and return `None`) and set `run.variables[node.name] = {"action_type": node.config.get("action_type")}` (a minimal "this ran" marker — v1 actions don't produce chainable data; Phase 3's `http_request`/`loop` nodes are the first to need real output).
     - **`node_type == "condition"`:** evaluate `node.config` (shaped like a trigger's `config`, minus `trigger_type`) against `run.trigger_ref` using the same reused `_matches_trigger(node.config, run.trigger_ref)`. Write `SoarRunStep` with `output={"result": <bool>}`. Find the outgoing edge whose `source_handle` is `"true"` or `"false"` matching the result; if none exists, treat as end-of-graph (fall through to the "no outgoing edge" handling below, but log a warning — a condition node with no matching branch is a malformed graph, not a crash).
     - **`node_type == "trigger"`:** this should never be the current node (trigger nodes are skipped over at dispatch time) — if it happens (data integrity bug), write `SoarRunStep` with `status="error"`, set `run.status = "failed"`, `run.finished_at = now_utc()`, commit, return.
     - **Any other `node_type`** (Task 4 does not implement `delay`, `http_request`, `loop`, `approval` yet — those are Task 5 and Phase 3): write `SoarRunStep` with `status="error"`, `error=f"node_type '{node.node_type}' not supported by engine yet"`, set `run.status = "failed"`, commit, return. (Task 5 will add a `delay` branch here; leave the `if/elif` chain structured so that's a clean addition, not a rewrite.)
   - After executing the node (action/condition, not the error paths above): merge its output into `run.variables` **by reassignment, not in-place mutation** — `run.variables = {**run.variables, node.name: <output>}` (this codebase has no `MutableDict`/`flag_modified` usage anywhere for JSONB columns — an in-place `run.variables[x] = y` would NOT be flagged dirty by SQLAlchemy and would silently fail to persist; this was flagged explicitly in Phase 0's final review as the single most likely way this phase loses data). Then determine the next node via the current node's outgoing edge(s): query `SoarEdge` where `source_node_id == node.id` (filtered by the matched `true`/`false` handle for a condition node; for an action node, take the edge with `source_handle == "out"` if present, else the first one found by `id` — log a warning if more than one candidate edge exists, since an action node should have at most one outgoing edge). If no outgoing edge: set `run.status = "completed"`, `run.finished_at = now_utc()`, commit, return (loop ends). Otherwise: set `run.current_node_id` to the edge's `target_node_id`, commit (so a crash mid-loop leaves the run correctly resumable at the next node), and continue the loop with the new current node.
   - **Safety cap:** track an iteration counter; if it exceeds 100 node-executions in one `step()` call, stop, write a final `SoarRunStep`-level or run-level error noting a possible cycle in the graph, set `run.status = "failed"`, and return — protects against a malformed/cyclic graph looping forever.

3. **Commit after every node**, not once at the end of the loop — matches the crash-safety property described above and the existing codebase's per-action commit pattern in `soar_engine.py`'s action handlers.

**Testing:** Live dry-run against the dev DB. Suggested approach (adapt as needed): insert one synthetic `SoarWorkflow` with a `trigger` node (`config={"trigger_type": "alert_match", "conditions": [], "match": "all"}` — matches everything) → `action` node (`config={"action_type": "add_note", "params": {"content": "phase1 test"}}`) chained by an edge, via `docker exec ... psql` (same pattern as Phase 0 Task 3). Also insert one throwaway `Alert` row (or reuse an existing one) to get a real `alert_id` for `add_note` to attach its note to. Call `dispatch_trigger("alert_match", ctx)` directly (via `docker cp` + `docker exec ... python3`) with a `ctx` containing that `alert_id` and matching group_id. Verify: a `SoarRun` reaches `status="completed"`, exactly one `SoarRunStep` exists (for the action node — not the trigger), and the `AlertNote` the `add_note` handler creates actually appears against that alert. Clean up all synthetic rows afterward and verify counts return to baseline, same as Phase 0 Task 3.

---

### Task 5: `delay` node + resume scheduler

**Files:**
- Modify `worker/worker/soar_v2/engine.py` — add a `delay` branch to `step()`'s node-type dispatch
- Create `worker/worker/soar_v2/scheduler.py`
- Modify `worker/worker/main.py` — register the new loop

**Design decisions:**

1. **`delay` node handling in `step()`:** `node.config` is `{"seconds": <int>}`. When the current node is a `delay` node: write its `SoarRunStep` (`status="ok"`, `output={"resume_at": <iso timestamp>}`). Advance `run.current_node_id` to the node's outgoing edge's target **immediately** (same as an action node) — the delay node's job is only to compute *when* to resume, not to occupy the "current" pointer while waiting. Then set `run.status = "waiting_delay"`, `run.resume_at = now_utc() + timedelta(seconds=node.config["seconds"])`, commit, and **break out of `step()`'s loop entirely** (return) — do not continue processing the next node in this call.
2. **On resume:** when `step(run_id)` is called again (by the scheduler below) for a run whose `status == "waiting_delay"`: since `run.current_node_id` already points past the delay node (set in step 1 above), all `step()` needs to do differently is accept `"waiting_delay"` as a valid re-entrant status (already specified in Task 4's re-fetch guard above — make sure that guard's status allowlist includes it), flip `run.status` back to `"running"`, clear `run.resume_at = None`, and continue the loop normally from `run.current_node_id`. **Defensively re-check** `resume_at <= now_utc()` at the top of `step()` even though the scheduler already filters on this — if a stale/duplicate call arrives early, return without doing anything (don't un-suspend early).
3. **`worker/worker/soar_v2/scheduler.py`** — model directly on `worker/worker/hunt_scheduler.py`'s shape (`await asyncio.sleep(120)` startle delay, then `while True: ... await asyncio.sleep(CHECK_INTERVAL)` with `CHECK_INTERVAL = 30`, each iteration in its own `try/except` so one bad tick doesn't kill the loop). Each tick: `SELECT id FROM soar_runs WHERE status='waiting_delay' AND resume_at <= now()`, and call `step(run.id)` for each (sequentially, not concurrently, within one tick — matches `hunt_scheduler_loop`'s sequential-within-tick pattern). Using `SELECT ... FOR UPDATE SKIP LOCKED` for the due-runs query is a nice-to-have for multi-process safety but not required for this task (single-worker-process assumption, matching `hunt_scheduler_loop`'s own lack of row locking).
4. **Register** `soar_v2_scheduler_loop()` in `worker/worker/main.py`'s `asyncio.gather(...)` list (currently at `worker/worker/main.py:140-156`), alongside `hunt_scheduler_loop()`, with the corresponding import added near the other loop imports at the top of the file.

**Testing:** Live dry-run extending Task 4's approach — a 2-node workflow (trigger → `delay` with `seconds=5` → `action` add_note, or just trigger → delay → (no further node) to keep it minimal) fired via `dispatch_trigger`, confirm the run lands in `status="waiting_delay"` with a `resume_at` ~5s in the future immediately after the call returns, then either wait for the scheduler's next tick (if the worker container is running the updated code) or call `step()` directly again after the delay to confirm it reaches `status="completed"`. Clean up synthetic rows afterward.

---

### Task 6: Switch dispatch call sites to `dispatch_trigger` + integration test

**Files:**
- Modify `worker/worker/alert_manager.py:205` (the `run_soar_playbooks(...)` call site)
- Modify `worker/worker/ai_analyst.py:544` (the second `run_soar_playbooks(...)` call site, inside `asyncio.ensure_future(...)`)

**Requirements:**
- At each call site, build a `ctx` dict with the exact same keys `soar_engine.py`'s `run_soar_playbooks` already builds internally (`severity`, `rule_title`, `tags`, `mitre_tags`, `source_ip`, `hostname`, `user_name`, `group_id`, and — only at the `ai_analyst.py` site — `ai_verdict`, `ai_confidence`, `ti_risk_score`), **plus `alert_id: str(alert_id)`** (new — needed so `dispatch_trigger`'s stored `trigger_ref` can reconstruct the `uuid.UUID` for action handlers, per Task 4's design). Replace the `run_soar_playbooks(...)` call with `await dispatch_trigger("alert_match", ctx)` (import from `worker.soar_v2.engine`).
- `worker/worker/alert_manager.py:205` currently passes a `rule_match: dict` (with `level`/`title`/`tags`/`mitre_tags` keys) plus separate `source_ip`/`hostname`/`user`/`group_id` params — flatten these into the `ctx` shape above (`severity = rule_match["level"]`, `rule_title = rule_match["title"]`, etc.).
- `worker/worker/ai_analyst.py:544` already builds a `rule_match_ctx` dict with `level`/`title`/`tags`/`mitre_tags` for its own purposes — reuse the same flattening, plus the `ai_verdict`/`ai_confidence`/`ti_risk_score`/`alert_id` it already has in scope at that call site.
- Keep both call sites' existing `try/except` wrapping (don't let a `dispatch_trigger` failure propagate and break alert ingestion or AI triage — matches how `run_soar_playbooks` is wrapped today).
- Do **not** delete `run_soar_playbooks` or any of `soar_engine.py` — just stop calling it from these two sites.

**Integration test (live dry-run):** Using a workflow produced by Phase 0's actual migration script (`server-api/app/scripts/migrate_soar_v1_to_v2.py`) run against a synthetic `SoarPlaybook`+`SoarAction` (e.g. one `add_note` action) — rather than a hand-inserted `SoarWorkflow` like Tasks 4-5's tests — trigger it two ways and confirm identical side effects: (a) directly call the OLD `run_soar_playbooks(...)` against the original `SoarPlaybook`/`SoarAction` rows, note what it wrote (e.g. the `AlertNote` content); (b) call `dispatch_trigger("alert_match", ctx)` against the migrated `SoarWorkflow`/`SoarNode`/`SoarEdge` rows with equivalent `ctx`, confirm it produces an equivalent `AlertNote`. This is the concrete proof that the migrated-from-v1 path behaves identically, per this task's brief. Clean up all synthetic rows (playbook, action, workflow, nodes, edges, runs, run steps, alert notes) afterward.

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
