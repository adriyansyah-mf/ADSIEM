"""The six node types of engine-core slice 1.

Destructive nodes (block_ip, isolate_agent) deliberately only *prepare* a
step and park the run. Execution belongs to the already-live approve route,
so approval, idempotency, and rollback keep their single implementation in
soar_service.py.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import Case, CaseNote
from app.services.soar_expressions import resolve_config
from app.services.soar_nodes import NodeContext, NodeResult, NodeType, register
from app.services.soar_service import StepPreparation, build_step_record

_SEVERITIES = ["info", "low", "medium", "high", "critical"]


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _alert_trigger(db: AsyncSession, context: NodeContext, config: dict) -> NodeResult:
    return NodeResult(output={"alert": context.trigger.get("alert", {})})


def _compare(left: Any, operator: str, right: Any) -> bool:
    match operator:
        case "eq":
            return left == right
        case "ne":
            return left != right
        case "gt":
            return float(left) > float(right)
        case "gte":
            return float(left) >= float(right)
        case "lt":
            return float(left) < float(right)
        case "lte":
            return float(left) <= float(right)
        case "contains":
            return right in (left or [])
        case _:
            raise ValueError(f"unsupported operator {operator!r}")


async def _if_node(db: AsyncSession, context: NodeContext, config: dict) -> NodeResult:
    resolved = resolve_config(config, context.as_dict())
    matched = _compare(resolved.get("left"), resolved.get("operator", "eq"), resolved.get("right"))
    return NodeResult(output={"matched": matched}, handle="true" if matched else "false")


async def _create_case(db: AsyncSession, context: NodeContext, config: dict) -> NodeResult:
    resolved = resolve_config(config, context.as_dict())
    severity = resolved.get("severity", "medium")
    if severity not in _SEVERITIES:
        raise ValueError(f"invalid severity {severity!r}")
    case = Case(
        id=uuid.uuid4(),
        title=resolved.get("title") or "SOAR case",
        description=resolved.get("description"),
        severity=severity,
        status="open",
        created_by_ai=False,
        group_id=context.group_id,
    )
    db.add(case)
    await db.flush()
    return NodeResult(output={"case_id": str(case.id)})


async def _add_note(db: AsyncSession, context: NodeContext, config: dict) -> NodeResult:
    resolved = resolve_config(config, context.as_dict())
    raw_case_id = resolved.get("case_id")
    if not isinstance(raw_case_id, str) or not raw_case_id:
        raise ValueError("add_note requires a case_id")
    note = CaseNote(
        id=uuid.uuid4(),
        case_id=uuid.UUID(raw_case_id),
        author_id=None,
        content=resolved.get("content") or "",
        is_ai_generated=False,
    )
    db.add(note)
    return NodeResult(output={"case_id": raw_case_id})


def _prepare_destructive(
    db: AsyncSession,
    context: NodeContext,
    action_type: str,
    payload: dict[str, Any],
) -> NodeResult:
    preparation = StepPreparation(
        run_id=context.run_id,
        node_id=context.node_id,
        action_type=action_type,
        input_payload=payload,
        idempotency_key=f"{context.run_id}:{context.node_id}:{action_type}",
        started_at=_now(),
    )
    step = build_step_record(preparation)
    db.add(step)
    return NodeResult(output={"step_id": str(step.id), "awaiting_approval": True}, wait=True)


async def _block_ip(db: AsyncSession, context: NodeContext, config: dict) -> NodeResult:
    resolved = resolve_config(config, context.as_dict())
    ip = resolved.get("ip")
    agent_id = resolved.get("agent_id")
    if not isinstance(ip, str) or not isinstance(agent_id, str):
        raise ValueError("block_ip requires ip and agent_id")
    payload: dict[str, Any] = {"ip": ip, "agent_id": agent_id}
    duration = resolved.get("duration_seconds")
    if isinstance(duration, int):
        payload["duration_seconds"] = duration
    return _prepare_destructive(db, context, "block_ip", payload)


async def _isolate_agent(db: AsyncSession, context: NodeContext, config: dict) -> NodeResult:
    resolved = resolve_config(config, context.as_dict())
    agent_id = resolved.get("agent_id")
    if not isinstance(agent_id, str):
        raise ValueError("isolate_agent requires agent_id")
    return _prepare_destructive(db, context, "isolate_agent", {"agent_id": agent_id})


_STRING = {"type": "string"}

_BUILTIN = [
    NodeType(
        node_type="alert_trigger",
        label="Alert Trigger",
        category="trigger",
        config_schema={
            "type": "object",
            "properties": {
                "severities": {"type": "array", "items": {"enum": _SEVERITIES}},
                "title_contains": _STRING,
            },
        },
        handler=_alert_trigger,
    ),
    NodeType(
        node_type="if",
        label="If",
        category="logic",
        config_schema={
            "type": "object",
            "required": ["left", "operator"],
            "properties": {
                "left": _STRING,
                "operator": {"enum": ["eq", "ne", "gt", "gte", "lt", "lte", "contains"]},
                "right": {},
            },
        },
        handler=_if_node,
        handles=("true", "false"),
    ),
    NodeType(
        node_type="create_case",
        label="Create Case",
        category="action",
        config_schema={
            "type": "object",
            "required": ["title"],
            "properties": {
                "title": _STRING,
                "description": _STRING,
                "severity": {"enum": _SEVERITIES},
            },
        },
        handler=_create_case,
    ),
    NodeType(
        node_type="add_note",
        label="Add Note",
        category="action",
        config_schema={
            "type": "object",
            "required": ["case_id", "content"],
            "properties": {"case_id": _STRING, "content": _STRING},
        },
        handler=_add_note,
    ),
    NodeType(
        node_type="block_ip",
        label="Block IP",
        category="response",
        config_schema={
            "type": "object",
            "required": ["ip", "agent_id"],
            "properties": {
                "ip": _STRING,
                "agent_id": _STRING,
                "duration_seconds": {"type": "integer", "minimum": 60},
            },
        },
        handler=_block_ip,
        is_destructive=True,
    ),
    NodeType(
        node_type="isolate_agent",
        label="Isolate Host",
        category="response",
        config_schema={
            "type": "object",
            "required": ["agent_id"],
            "properties": {"agent_id": _STRING},
        },
        handler=_isolate_agent,
        is_destructive=True,
    ),
]


def register_builtin_nodes() -> None:
    for node_type in _BUILTIN:
        register(node_type)
