"""One-time data migration: SOAR v1 (SoarPlaybook + ordered SoarAction) -> SOAR v2
(SoarWorkflow + SoarNode + SoarEdge graph).

For every existing `SoarPlaybook` row (migrated regardless of `is_enabled` —
the flag carries over unchanged onto the new `SoarWorkflow.is_enabled`), this
script creates:

  - one `SoarWorkflow`  (same `name`, `description`, `is_enabled`, `group_id`)
  - one `trigger` node  (config = {"trigger_type": "alert_match",
                                    "conditions": <old trigger_conditions.conditions>,
                                    "match": <old trigger_conditions.match>})
  - one `action` node per `SoarAction`, ordered by `order_index`
                        (config = {"action_type": ..., "params": ...})
  - edges chaining them in sequence: trigger -> action[0] -> action[1] -> ... -> action[n-1]

Edge case: a playbook with zero `SoarAction` rows produces exactly 1 node
(the trigger) and 0 edges.

Idempotency guard
------------------
`soar_workflows.name` has NO unique constraint, so re-running this script
naively would duplicate every workflow on a second pass. The guard used here
is deliberately simple, per the task brief: before creating a workflow for a
given `SoarPlaybook`, this script checks whether a `SoarWorkflow` with that
exact `name` AND the same `group_id` already exists (matching how
`soar_playbooks` itself scopes by group), and skips migrating that playbook
if so. This is a "same source name in this group already migrated"
heuristic, not a strict identity check (e.g. it would also skip a *new* v2
workflow a user hand-created that happens to reuse a v1 playbook's name
within the same group) — acceptable for a one-time cutover script where this
is expected to run at most a handful of times against a stable dataset. Do
not build a more general upsert/dedup mechanism here; if a different guard
is ever needed, replace this one, don't layer on top of it.

Usage (see server-api Docker container, which already has the correct
DATABASE_URL and dependencies installed):

    python3 -m app.scripts.migrate_soar_v1_to_v2

Safe to re-run: the second run will report 0 playbooks migrated (all skipped)
and 0 new rows in soar_workflows/soar_nodes/soar_edges.
"""
import asyncio

import structlog
from sqlalchemy import select

from app.core.database import AsyncSessionLocal
from app.models.models import SoarAction, SoarEdge, SoarNode, SoarPlaybook, SoarWorkflow

log = structlog.get_logger()


async def migrate() -> None:
    migrated = 0
    skipped = 0
    total_nodes = 0
    total_edges = 0

    async with AsyncSessionLocal() as db:
        playbooks = (await db.execute(select(SoarPlaybook))).scalars().all()

        for playbook in playbooks:
            existing = (
                await db.execute(
                    select(SoarWorkflow).where(
                        SoarWorkflow.name == playbook.name,
                        SoarWorkflow.group_id == playbook.group_id,
                    )
                )
            ).scalars().first()
            if existing is not None:
                skipped += 1
                log.info(
                    "soar_v1_to_v2.skip_existing",
                    playbook_id=str(playbook.id),
                    name=playbook.name,
                )
                continue

            workflow = SoarWorkflow(
                name=playbook.name,
                description=playbook.description,
                is_enabled=playbook.is_enabled,
                group_id=playbook.group_id,
            )
            db.add(workflow)
            await db.flush()  # assign workflow.id

            trigger_conditions = playbook.trigger_conditions or {}
            trigger_node = SoarNode(
                workflow_id=workflow.id,
                node_type="trigger",
                name="Trigger",
                config={
                    "trigger_type": "alert_match",
                    "conditions": trigger_conditions.get("conditions", []),
                    "match": trigger_conditions.get("match", "all"),
                },
                pos_x=0,
                pos_y=0,
            )
            db.add(trigger_node)
            await db.flush()  # assign trigger_node.id

            node_chain = [trigger_node]

            actions = (
                await db.execute(
                    select(SoarAction)
                    .where(SoarAction.playbook_id == playbook.id)
                    .order_by(SoarAction.order_index)
                )
            ).scalars().all()

            for idx, action in enumerate(actions):
                action_node = SoarNode(
                    workflow_id=workflow.id,
                    node_type="action",
                    name=f"{action.action_type} #{idx + 1}",
                    config={
                        "action_type": action.action_type,
                        "params": action.params or {},
                    },
                    pos_x=0,
                    pos_y=len(node_chain) * 140,
                )
                db.add(action_node)
                await db.flush()  # assign action_node.id
                node_chain.append(action_node)

            for source, target in zip(node_chain, node_chain[1:]):
                db.add(
                    SoarEdge(
                        workflow_id=workflow.id,
                        source_node_id=source.id,
                        source_handle="out",
                        target_node_id=target.id,
                    )
                )

            total_nodes += len(node_chain)
            total_edges += len(node_chain) - 1
            migrated += 1
            log.info(
                "soar_v1_to_v2.migrated",
                playbook_id=str(playbook.id),
                workflow_id=str(workflow.id),
                name=playbook.name,
                node_count=len(node_chain),
                edge_count=len(node_chain) - 1,
            )

        await db.commit()

    print(
        f"soar_v1_to_v2 migration complete: "
        f"{migrated} playbook(s) migrated, {skipped} skipped (already migrated), "
        f"{total_nodes} node(s) created, {total_edges} edge(s) created"
    )


if __name__ == "__main__":
    asyncio.run(migrate())
