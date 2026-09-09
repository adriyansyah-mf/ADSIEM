from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(frozen=True, slots=True)
class NodeContext:
    """Everything a node may read. Deliberately not the ORM session's world:
    a node sees resolved data, not arbitrary database reach."""
    run_id: uuid.UUID
    node_id: uuid.UUID
    group_id: str
    trigger: dict[str, Any] = field(default_factory=dict)
    nodes: dict[str, Any] = field(default_factory=dict)
    vars: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"trigger": self.trigger, "nodes": self.nodes, "vars": self.vars}


@dataclass(frozen=True, slots=True)
class NodeResult:
    output: dict[str, Any]
    handle: str = "out"
    wait: bool = False


NodeHandler = Callable[[AsyncSession, NodeContext, dict[str, Any]], Awaitable[NodeResult]]


@dataclass(frozen=True, slots=True)
class NodeType:
    node_type: str
    label: str
    category: str
    config_schema: dict[str, Any]
    handler: NodeHandler
    handles: tuple[str, ...] = ("out",)
    is_destructive: bool = False
