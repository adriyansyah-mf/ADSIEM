"""Graph snapshot and traversal for the SOAR v2 executor.

The functions in this module are pure so they can be tested without a
database. A run executes against the snapshot taken when it started, never
the live tables, so editing a workflow cannot corrupt a run in flight or
make an old run unrenderable — see the design doc, section 5.2.
"""
from __future__ import annotations

from typing import Any, Iterable


class CyclicWorkflowError(ValueError):
    """A workflow graph contains a cycle. Phase 1 supports DAGs only."""


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
