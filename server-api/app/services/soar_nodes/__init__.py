"""Registry of SOAR node types.

Adding a node is one module plus one `register()` call: the API serves the
catalogue and the frontend renders each node's configuration form from its
JSON Schema, so no frontend change is needed for a new node.
"""
from __future__ import annotations

from typing import Any

from app.services.soar_nodes.base import (
    NodeContext,
    NodeHandler,
    NodeResult,
    NodeType,
)

_REGISTRY: dict[str, NodeType] = {}

__all__ = [
    "NodeContext",
    "NodeHandler",
    "NodeResult",
    "NodeType",
    "catalogue",
    "clear_registry",
    "get_node_type",
    "register",
]


def register(node_type: NodeType) -> None:
    if node_type.node_type in _REGISTRY:
        raise ValueError(f"node type {node_type.node_type!r} already registered")
    _REGISTRY[node_type.node_type] = node_type


def get_node_type(name: str) -> NodeType:
    try:
        return _REGISTRY[name]
    except KeyError as error:
        raise KeyError(f"unknown node type {name!r}") from error


def clear_registry() -> None:
    """Test seam. Production never calls this."""
    _REGISTRY.clear()


def catalogue() -> list[dict[str, Any]]:
    entries = [
        {
            "node_type": node.node_type,
            "label": node.label,
            "category": node.category,
            "config_schema": node.config_schema,
            "handles": list(node.handles),
            "is_destructive": node.is_destructive,
        }
        for node in _REGISTRY.values()
    ]
    return sorted(entries, key=lambda entry: (entry["category"], entry["node_type"]))
