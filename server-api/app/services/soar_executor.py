"""Graph snapshot and traversal for the SOAR v2 executor.

The functions in this module are pure so they can be tested without a
database. A run executes against the snapshot taken when it started, never
the live tables, so editing a workflow cannot corrupt a run in flight or
make an old run unrenderable — see the design doc, section 5.2.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import AsyncSessionLocal
from app.models.models import PlatformSetting, SoarEdge, SoarNode, SoarRun, SoarRunStep
from app.services.soar_nodes import NodeContext, get_node_type
from app.services.soar_service import input_hash

log = structlog.get_logger()

POLL_INTERVAL_SECONDS = 5
MAX_STEPS_PER_RUN = 200


class CyclicWorkflowError(ValueError):
    """A workflow graph contains a cycle. Phase 1 supports DAGs only."""


class ConvergentWorkflowError(ValueError):
    """A node has more than one inbound edge. Phase 1 executes a single
    active path with no visited-set, so a reconverging graph would run the
    shared node once per inbound branch."""


class DisconnectedWorkflowError(ValueError):
    """A workflow has no entry node, or more than one. Execution starts from a
    single root, so any other root's nodes would never run."""


def build_snapshot(nodes: Iterable[Any], edges: Iterable[Any]) -> dict[str, Any]:
    return {
        "nodes": {
            str(node.id): {
                "id": str(node.id),
                "node_type": node.node_type,
                "name": node.name,
                "config": node.config or {},
                "pos_x": float(node.pos_x or 0),
                "pos_y": float(node.pos_y or 0),
            }
            for node in nodes
        },
        "edges": [
            {
                "source_node_id": str(edge.source_node_id),
                "source_handle": edge.source_handle,
                "target_node_id": str(edge.target_node_id),
            }
            for edge in edges
        ],
    }


def find_entry_node_id(snapshot: dict[str, Any]) -> str | None:
    targets = {edge["target_node_id"] for edge in snapshot["edges"]}
    for node_id in snapshot["nodes"]:
        if node_id not in targets:
            return node_id
    return None


def next_node_ids(snapshot: dict[str, Any], node_id: str, handle: str) -> list[str]:
    return [
        edge["target_node_id"]
        for edge in snapshot["edges"]
        if edge["source_node_id"] == node_id and edge["source_handle"] == handle
    ]


def advance_frontier(
    snapshot: dict[str, Any],
    node_id: str,
    handle: str,
    pending: list[str],
) -> tuple[str | None, list[str]]:
    """Pick the next node and the frontier that remains after it.

    Fan-out is depth-first and sequential: the first successor becomes
    current, the rest wait ahead of whatever was already pending. A single
    active path is all `soar_runs.current_node_id` can represent, so true
    parallel branches are out of scope (design doc, section 5.3).
    """
    successors = next_node_ids(snapshot, node_id, handle)
    queue = [*successors, *pending]
    if not queue:
        return None, []
    return queue[0], queue[1:]


def validate_acyclic(snapshot: dict[str, Any]) -> None:
    adjacency: dict[str, list[str]] = {node_id: [] for node_id in snapshot["nodes"]}
    for edge in snapshot["edges"]:
        adjacency.setdefault(edge["source_node_id"], []).append(edge["target_node_id"])

    visiting: set[str] = set()
    visited: set[str] = set()

    def walk(node_id: str) -> None:
        if node_id in visiting:
            raise CyclicWorkflowError(f"cycle through node {node_id}")
        if node_id in visited:
            return
        visiting.add(node_id)
        for target in adjacency.get(node_id, []):
            walk(target)
        visiting.discard(node_id)
        visited.add(node_id)

    for node_id in list(adjacency):
        walk(node_id)


def validate_single_inbound(snapshot: dict[str, Any]) -> None:
    seen: set[str] = set()
    for edge in snapshot["edges"]:
        target = edge["target_node_id"]
        if target in seen:
            raise ConvergentWorkflowError(f"node {target} has multiple inbound edges")
        seen.add(target)


def validate_single_entry(snapshot: dict[str, Any]) -> None:
    targets = {edge["target_node_id"] for edge in snapshot["edges"]}
    roots = [node_id for node_id in snapshot["nodes"] if node_id not in targets]
    if len(roots) != 1:
        raise DisconnectedWorkflowError(f"expected exactly one entry node, found {len(roots)}")


def validate_graph(snapshot: dict[str, Any]) -> None:
    """Full validation for a workflow that this executor can run."""
    validate_acyclic(snapshot)
    validate_single_inbound(snapshot)
    validate_single_entry(snapshot)


async def start_run(
    db: AsyncSession,
    workflow,
    trigger_type: str,
    trigger_ref: dict[str, Any],
) -> SoarRun:
    """Snapshot the workflow and queue a run at its entry node."""
    nodes = (await db.execute(
        select(SoarNode).where(SoarNode.workflow_id == workflow.id)
    )).scalars().all()
    edges = (await db.execute(
        select(SoarEdge).where(SoarEdge.workflow_id == workflow.id)
    )).scalars().all()
    snapshot = build_snapshot(nodes, edges)
    validate_graph(snapshot)
    entry_node_id = find_entry_node_id(snapshot)
    if entry_node_id is None:
        raise ValueError(f"workflow {workflow.id} has no entry node")
    run = SoarRun(
        id=uuid.uuid4(),
        workflow_id=workflow.id,
        status="pending",
        trigger_type=trigger_type,
        trigger_ref=trigger_ref,
        current_node_id=uuid.UUID(entry_node_id),
        variables={},
        graph_snapshot=snapshot,
        pending_node_ids=[],
        group_id=workflow.group_id,
    )
    db.add(run)
    return run


async def claim_runnable_run(db: AsyncSession) -> SoarRun | None:
    """Claim one run for this replica.

    Both server-api replicas run this loop, so the row lock is a
    correctness requirement: without SKIP LOCKED two replicas could execute
    the same node twice (design doc, section 5.1).
    """
    now = datetime.now(timezone.utc)
    query = (
        select(SoarRun)
        .where(
            SoarRun.status.in_(["pending", "running"])
            | ((SoarRun.status == "waiting") & (SoarRun.resume_at != None) & (SoarRun.resume_at <= now))
        )
        .order_by(SoarRun.started_at)
        .limit(1)
        .with_for_update(skip_locked=True)
    )
    return (await db.execute(query)).scalars().first()


async def _build_context(db: AsyncSession, run: SoarRun, node_id: uuid.UUID) -> NodeContext:
    steps = (await db.execute(
        select(SoarRunStep).where(SoarRunStep.run_id == run.id)
    )).scalars().all()
    snapshot_nodes = run.graph_snapshot["nodes"]
    outputs: dict[str, Any] = {}
    for step in steps:
        node = snapshot_nodes.get(str(step.node_id))
        if node is not None and step.output is not None:
            outputs[node["name"]] = {"output": step.output}
    return NodeContext(
        run_id=run.id,
        node_id=node_id,
        group_id=run.group_id,
        trigger=run.trigger_ref or {},
        nodes=outputs,
        vars=run.variables or {},
    )


async def execute_one_step(db: AsyncSession, run: SoarRun) -> bool:
    """Execute exactly one node. Returns True if the run is still active."""
    if run.current_node_id is None:
        run.status = "succeeded"
        run.finished_at = datetime.now(timezone.utc)
        return False

    node_id = run.current_node_id
    node = run.graph_snapshot["nodes"].get(str(node_id))
    if node is None:
        run.status = "failed"
        run.finished_at = datetime.now(timezone.utc)
        log.error("soar_node_missing_from_snapshot", run_id=str(run.id), node_id=str(node_id))
        return False

    executed = (await db.execute(
        select(SoarRunStep).where(SoarRunStep.run_id == run.id)
    )).scalars().all()
    if len(executed) >= MAX_STEPS_PER_RUN:
        run.status = "failed"
        run.finished_at = datetime.now(timezone.utc)
        log.error("soar_run_step_ceiling", run_id=str(run.id))
        return False

    run.status = "running"
    context = await _build_context(db, run, node_id)
    started_at = datetime.now(timezone.utc)
    try:
        node_type = get_node_type(node["node_type"])
        result = await node_type.handler(db, context, node["config"])
    except Exception as exc:
        db.add(SoarRunStep(
            id=uuid.uuid4(), run_id=run.id, node_id=node_id,
            action_type=node["node_type"], status="failed",
            is_destructive=False, is_reversible=False,
            idempotency_key=f"{run.id}:{node_id}:error",
            input_hash=input_hash({}), input={}, error=str(exc),
            started_at=started_at, finished_at=datetime.now(timezone.utc),
        ))
        run.status = "failed"
        run.finished_at = datetime.now(timezone.utc)
        log.error("soar_node_failed", run_id=str(run.id), node=node["name"], error=str(exc))
        return False

    if not node_type.is_destructive:
        db.add(SoarRunStep(
            id=uuid.uuid4(), run_id=run.id, node_id=node_id,
            action_type=node["node_type"], status="succeeded",
            is_destructive=False, is_reversible=False,
            idempotency_key=f"{run.id}:{node_id}",
            input_hash=input_hash(node["config"]), input=node["config"],
            output=result.output,
            started_at=started_at, finished_at=datetime.now(timezone.utc),
        ))

    if result.wait:
        run.status = "waiting"
        return False

    current, pending = advance_frontier(
        run.graph_snapshot, str(node_id), result.handle, list(run.pending_node_ids or [])
    )
    run.current_node_id = uuid.UUID(current) if current else None
    run.pending_node_ids = pending
    if current is None:
        run.status = "succeeded"
        run.finished_at = datetime.now(timezone.utc)
        return False
    return True


async def _enabled(db: AsyncSession) -> bool:
    row = await db.get(PlatformSetting, "soar_v2_enabled")
    return bool(row and row.value.lower() == "true")


async def executor_tick() -> bool:
    """One claim-and-execute cycle. Returns True if work was done."""
    async with AsyncSessionLocal() as db:
        async with db.begin():
            if not await _enabled(db):
                return False
            run = await claim_runnable_run(db)
            if run is None:
                return False
            await execute_one_step(db, run)
            return True


async def soar_executor_loop() -> None:
    while True:
        try:
            did_work = await executor_tick()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.error("soar_executor_tick_failed", error=str(exc))
            did_work = False
        if not did_work:
            await asyncio.sleep(POLL_INTERVAL_SECONDS)
