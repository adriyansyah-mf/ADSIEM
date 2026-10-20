"""Run engine: match playbooks to an event, queue runs, and execute them node by node.

Runs are rows in soar_runs. Matching an alert only queues a run; soar_loop
claims queued runs (FOR UPDATE SKIP LOCKED, so worker replicas never share one)
and executes them off the log pipeline. Every node writes a soar_run_steps row.

Per node: retry up to node.retry times; on failure follow the node's "error"
edge, else its first output when continue_on_error, else fail the run. An
Approval node parks the run as "waiting" until the API records a decision
(status "resume") or wait_until passes.
"""
from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import structlog
from sqlalchemy import select, text

from worker.database import AsyncSessionLocal
from worker.models import SoarAction, SoarPlaybook, SoarRun, SoarRunStep
from worker.soar.conditions import matches
from worker.soar.graph import NODE_TYPES, GraphError, from_legacy, trigger_event, trigger_node, validate
from worker.soar.nodes import HANDLERS, WAIT, NodeError
from worker.soar.template import render

log = structlog.get_logger()

MAX_STEPS = 100
RUN_TIMEOUT_S = 600
NODE_TIMEOUT_S = 120
STORED_OUTPUT_CAP = 256_000
STALE_RUNNING = timedelta(minutes=15)
POLL_INTERVAL_S = 2.0
MAX_CONCURRENT_RUNS = 8

_wake = asyncio.Event()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def playbook_graph(pb: SoarPlaybook, actions: list[SoarAction]) -> dict:
    """The playbook's validated graph; old playbooks are converted on the fly."""
    if pb.graph:
        return validate(pb.graph)
    return validate(from_legacy(pb.trigger_conditions, [
        {"action_type": a.action_type, "order_index": a.order_index, "params": a.params} for a in actions
    ]))


async def dispatch(event: str, trigger: dict, *, group_id: str) -> list[str]:
    """Queue a run for every enabled playbook whose Trigger matches. Returns run ids."""
    trigger = {**trigger, "event": event, "group_id": group_id}
    ctx = {"trigger": trigger, "steps": {}}
    queued: list[str] = []
    async with AsyncSessionLocal() as db:
        playbooks = (await db.execute(
            select(SoarPlaybook).where(
                SoarPlaybook.is_enabled.is_(True),
                (SoarPlaybook.group_id == group_id) | (SoarPlaybook.group_id == "default"),
            )
        )).scalars().all()
        for pb in playbooks:
            actions = [] if pb.graph else (await db.execute(
                select(SoarAction).where(SoarAction.playbook_id == pb.id)
            )).scalars().all()
            try:
                graph = playbook_graph(pb, list(actions))
            except GraphError as exc:
                log.warning("soar_playbook_invalid", playbook=pb.name, errors=exc.errors[:5])
                continue
            if trigger_event(graph) != event or not matches(trigger_node(graph)["params"], ctx):
                continue
            run = SoarRun(playbook_id=pb.id, group_id=group_id, status="queued", trigger_event=event,
                          alert_id=trigger.get("alert_id"), graph=graph,
                          context={"trigger": trigger, "steps": {}, "queue": [trigger_node(graph)["id"]], "done": []})
            db.add(run)
            await db.flush()
            queued.append(str(run.id))
            log.info("soar_run_queued", playbook=pb.name, run_id=str(run.id), trigger_event=event)
        await db.commit()
    if queued:
        _wake.set()
    return queued


def _children(graph: dict, node_id: str, output: str) -> list[str]:
    return [e["to"] for e in graph["edges"] if e["from"] == node_id and e["output"] == output]


def _jsonable(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


def _cap(value: Any) -> Any:
    """Keep stored outputs bounded; the in-memory context keeps the full value."""
    value = _jsonable(value)
    if len(json.dumps(value)) > STORED_OUTPUT_CAP:
        return {"_truncated": True, "preview": json.dumps(value)[:2000]}
    return value


async def _record_step(run_id: uuid.UUID, node: dict, *, status: str, output_name: str | None,
                       input_: Any, output: Any, error: str | None, attempts: int, started: datetime) -> None:
    async with AsyncSessionLocal() as db:
        db.add(SoarRunStep(run_id=run_id, node_id=node["id"], node_type=node["type"], status=status,
                           output_name=output_name, input=_cap(input_) if input_ is not None else None,
                           output=_cap(output) if output is not None else None, error=error,
                           attempts=attempts, started_at=started,
                           duration_ms=int((_now() - started).total_seconds() * 1000)))
        await db.commit()


async def _save_run(run_id: uuid.UUID, **values) -> None:
    if "context" in values:
        values["context"] = _jsonable(values["context"])
    async with AsyncSessionLocal() as db:
        run = await db.get(SoarRun, run_id)
        for k, v in values.items():
            setattr(run, k, v)
        run.updated_at = _now()
        await db.commit()


def _persisted(ctx: dict, queue: list[str], done: list[str], decision: dict | None = None) -> dict:
    out = {"trigger": ctx["trigger"], "steps": {k: _cap(v) for k, v in ctx["steps"].items()},
           "queue": queue, "done": done}
    if decision:
        out["decision"] = decision
    return out


async def _is_cancelled(run_id: uuid.UUID) -> bool:
    async with AsyncSessionLocal() as db:
        return (await db.execute(select(SoarRun.status).where(SoarRun.id == run_id))).scalar() == "cancelled"


async def execute_run(run_id: uuid.UUID) -> str:
    """Execute a claimed run until it finishes, fails, or waits. Returns the final status."""
    async with AsyncSessionLocal() as db:
        run = await db.get(SoarRun, run_id)
        pb = await db.get(SoarPlaybook, run.playbook_id)
        graph, stored = run.graph, dict(run.context or {})
        waiting_node = run.waiting_node
        playbook_id = str(run.playbook_id)
        playbook_name = pb.name if pb else ""

    from worker.settings_cache import settings_with_prefix
    secrets = await settings_with_prefix("soar_secret_")
    ctx = {"trigger": stored.get("trigger", {}), "steps": dict(stored.get("steps", {})),
           "run": {"id": str(run_id), "playbook_id": playbook_id, "playbook_name": playbook_name},
           "secrets": secrets}
    masked = {**ctx, "secrets": {k: "••••" for k in secrets}}
    nodes = {n["id"]: n for n in graph["nodes"]}
    queue: list[str] = list(stored.get("queue", []))
    done: list[str] = list(stored.get("done", []))

    # Resume after an approval decision (or its timeout).
    decision = stored.get("decision")
    if waiting_node and decision and decision.get("node") == waiting_node:
        node = nodes[waiting_node]
        verdict = "approved" if decision.get("decision") == "approved" else "rejected"
        data = {**ctx["steps"].get(waiting_node, {}), **decision}
        ctx["steps"][waiting_node] = data
        done.append(waiting_node)
        if waiting_node in queue:
            queue.remove(waiting_node)
        queue += _children(graph, waiting_node, verdict)
        await _record_step(run_id, node, status="success", output_name=verdict, input_=None, output=data,
                           error=None, attempts=1, started=_now())
        await _save_run(run_id, waiting_node=None, wait_until=None, context=_persisted(ctx, queue, done))

    started_at = asyncio.get_running_loop().time()
    steps_run = 0
    while queue:
        if steps_run >= MAX_STEPS or asyncio.get_running_loop().time() - started_at > RUN_TIMEOUT_S:
            await _save_run(run_id, status="failed", error="run exceeded its step or time limit",
                            finished_at=_now(), context=_persisted(ctx, queue, done))
            return "failed"
        if await _is_cancelled(run_id):
            await _save_run(run_id, finished_at=_now(), context=_persisted(ctx, queue, done))
            return "cancelled"

        nid = queue.pop(0)
        if nid in done or nid not in nodes:
            continue
        node = nodes[nid]
        steps_run += 1
        raw = node.get("params") or {}
        rendered = render(raw, ctx)
        shown = None if node["type"] == "trigger" else render(raw, masked)
        started = _now()

        result, err, attempts = None, None, 0
        for attempt in range(int(node.get("retry", 0)) + 1):
            attempts += 1
            try:
                result = await asyncio.wait_for(HANDLERS[node["type"]](node, rendered, ctx), NODE_TIMEOUT_S)
                err = None
                break
            except NodeError as exc:
                err = exc
            except asyncio.TimeoutError:
                err = NodeError(f"node took longer than {NODE_TIMEOUT_S}s")
            except Exception as exc:  # a bug in a handler must not kill the loop
                log.exception("soar_node_crashed", node=nid, type=node["type"])
                err = NodeError(f"{exc.__class__.__name__}: {exc}")
            if attempt < int(node.get("retry", 0)):
                await asyncio.sleep(min(2 ** attempt, 5))

        if err is None and result.output == WAIT:
            ctx["steps"][nid] = result.data
            queue.insert(0, nid)
            minutes = int(result.data.get("timeout_minutes", 60))
            await _record_step(run_id, node, status="waiting", output_name=None, input_=shown,
                               output=result.data, error=None, attempts=attempts, started=started)
            await _save_run(run_id, status="waiting", waiting_node=nid,
                            wait_until=_now() + timedelta(minutes=minutes),
                            context=_persisted(ctx, queue, done))
            log.info("soar_run_waiting", run_id=str(run_id), node=nid)
            return "waiting"

        if err is None:
            ctx["steps"][nid] = result.data
            done.append(nid)
            queue += [c for c in _children(graph, nid, result.output) if c not in queue]
            await _record_step(run_id, node, status="success", output_name=result.output, input_=shown,
                               output=result.data, error=None, attempts=attempts, started=started)
        else:
            data = {"error": str(err)}
            if isinstance(err.data, dict):
                data.update(err.data)
            ctx["steps"][nid] = data
            done.append(nid)
            error_children = _children(graph, nid, "error")
            if error_children:
                taken = "error"
            elif node.get("continue_on_error"):
                taken = NODE_TYPES[node["type"]]["outputs"][0]
                error_children = _children(graph, nid, taken)
            else:
                taken = None
            await _record_step(run_id, node, status="error", output_name=taken, input_=shown,
                               output=data, error=str(err), attempts=attempts, started=started)
            if taken is None:
                await _save_run(run_id, status="failed", error=f"{node['label']}: {err}",
                                finished_at=_now(), context=_persisted(ctx, queue, done))
                log.warning("soar_run_failed", run_id=str(run_id), node=nid, error=str(err))
                return "failed"
            queue += [c for c in error_children if c not in queue]

        await _save_run(run_id, context=_persisted(ctx, queue, done))

    await _save_run(run_id, status="success", finished_at=_now(), context=_persisted(ctx, queue, done))
    log.info("soar_run_done", run_id=str(run_id), steps=steps_run)
    return "success"


async def _claim(limit: int) -> list[uuid.UUID]:
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(text("""
            UPDATE soar_runs SET status = 'running', updated_at = now()
            WHERE id IN (
                SELECT id FROM soar_runs WHERE status IN ('queued', 'resume')
                ORDER BY created_at LIMIT :limit FOR UPDATE SKIP LOCKED
            )
            RETURNING id
        """), {"limit": limit})).scalars().all()
        await db.commit()
    return list(rows)


async def _expire_and_reap() -> None:
    """Approvals past their deadline resume as rejected; runs stuck 'running' are failed."""
    async with AsyncSessionLocal() as db:
        expired = (await db.execute(
            select(SoarRun).where(SoarRun.status == "waiting", SoarRun.wait_until < _now())
            .with_for_update(skip_locked=True).limit(50)
        )).scalars().all()
        for run in expired:
            run.context = {**(run.context or {}), "decision": {
                "node": run.waiting_node, "decision": "rejected", "reason": "timeout", "at": _now().isoformat()}}
            run.status = "resume"
        stale = (await db.execute(
            select(SoarRun).where(SoarRun.status == "running", SoarRun.updated_at < _now() - STALE_RUNNING)
            .with_for_update(skip_locked=True).limit(50)
        )).scalars().all()
        for run in stale:
            run.status, run.error, run.finished_at = "failed", "interrupted (worker stopped mid-run)", _now()
        await db.commit()
    if expired:
        _wake.set()


async def soar_loop() -> None:
    running: set[asyncio.Task] = set()
    while True:
        try:
            await _expire_and_reap()
            free = MAX_CONCURRENT_RUNS - len(running)
            for run_id in (await _claim(free) if free > 0 else []):
                task = asyncio.create_task(_safe_execute(run_id))
                running.add(task)
                task.add_done_callback(running.discard)
        except Exception as exc:
            log.error("soar_loop_error", error=str(exc))
        _wake.clear()
        try:
            await asyncio.wait_for(_wake.wait(), POLL_INTERVAL_S)
        except asyncio.TimeoutError:
            pass


async def _safe_execute(run_id: uuid.UUID) -> None:
    try:
        await execute_run(run_id)
    except Exception as exc:
        log.exception("soar_run_crashed", run_id=str(run_id))
        try:
            await _save_run(run_id, status="failed", error=f"engine error: {exc}", finished_at=_now())
        except Exception:
            pass
