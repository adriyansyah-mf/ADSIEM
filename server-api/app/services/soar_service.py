from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import Agent, AgentTask, SoarRunStep

JsonValue = None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]

DESTRUCTIVE_ACTIONS = frozenset({"block_ip", "isolate_agent"})
REVERSIBLE_ACTIONS = frozenset({"isolate_agent"})


@dataclass(frozen=True, slots=True)
class StepPreparation:
    run_id: uuid.UUID
    node_id: uuid.UUID
    action_type: str
    input_payload: dict[str, JsonValue]
    idempotency_key: str
    started_at: datetime


@dataclass(frozen=True, slots=True)
class StepActorCommand:
    actor_id: uuid.UUID
    idempotency_key: str
    acted_at: datetime


@dataclass(frozen=True, slots=True)
class RollbackScope:
    actor_id: uuid.UUID
    group_id: str


@dataclass(frozen=True, slots=True)
class StepExecutionScope:
    actor_id: uuid.UUID
    group_id: str


@dataclass(frozen=True, slots=True)
class ApprovalRequiredError(RuntimeError):
    step_id: uuid.UUID

    def __str__(self) -> str:
        return f"step {self.step_id} requires approval"


@dataclass(frozen=True, slots=True)
class IdempotencyConflictError(RuntimeError):
    idempotency_key: str

    def __str__(self) -> str:
        return f"idempotency key {self.idempotency_key!r} was reused for different input"


@dataclass(frozen=True, slots=True)
class StepStateConflictError(RuntimeError):
    step_id: uuid.UUID
    status: str

    def __str__(self) -> str:
        return f"step {self.step_id} cannot transition from {self.status}"


@dataclass(frozen=True, slots=True)
class RollbackNotSupportedError(RuntimeError):
    step_id: uuid.UUID

    def __str__(self) -> str:
        return f"step {self.step_id} is not reversible"


@dataclass(frozen=True, slots=True)
class RollbackTargetError(RuntimeError):
    step_id: uuid.UUID

    def __str__(self) -> str:
        return f"step {self.step_id} has no valid rollback target"


@dataclass(frozen=True, slots=True)
class StepExecutionTargetError(RuntimeError):
    step_id: uuid.UUID

    def __str__(self) -> str:
        return f"step {self.step_id} has no valid execution target"


def input_hash(payload: dict[str, JsonValue]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def build_step_record(preparation: StepPreparation) -> SoarRunStep:
    is_destructive = preparation.action_type in DESTRUCTIVE_ACTIONS
    return SoarRunStep(
        id=uuid.uuid4(),
        run_id=preparation.run_id,
        node_id=preparation.node_id,
        action_type=preparation.action_type,
        status="pending_approval" if is_destructive else "approved",
        is_destructive=is_destructive,
        is_reversible=preparation.action_type in REVERSIBLE_ACTIONS,
        idempotency_key=preparation.idempotency_key,
        input_hash=input_hash(preparation.input_payload),
        input=preparation.input_payload,
        started_at=preparation.started_at,
    )


def validate_idempotent_retry(
    existing: SoarRunStep,
    preparation: StepPreparation,
) -> SoarRunStep:
    matches = (
        existing.run_id == preparation.run_id
        and existing.node_id == preparation.node_id
        and existing.action_type == preparation.action_type
        and existing.idempotency_key == preparation.idempotency_key
        and existing.input_hash == input_hash(preparation.input_payload)
    )
    if not matches:
        raise IdempotencyConflictError(preparation.idempotency_key)
    return existing


def approve_step(step: SoarRunStep, command: StepActorCommand) -> SoarRunStep:
    if step.idempotency_key != command.idempotency_key:
        raise IdempotencyConflictError(command.idempotency_key)
    if step.status == "approved":
        return step
    if step.status != "pending_approval":
        raise StepStateConflictError(step.id, step.status)
    step.status = "approved"
    step.actor_id = command.actor_id
    step.acted_at = command.acted_at
    return step


def assert_step_runnable(step: SoarRunStep) -> None:
    if step.status == "pending_approval":
        raise ApprovalRequiredError(step.id)
    if step.status != "approved":
        raise StepStateConflictError(step.id, step.status)


async def execute_approved_step(
    db: AsyncSession,
    step: SoarRunStep,
    scope: StepExecutionScope,
) -> SoarRunStep:
    if step.status == "succeeded":
        return step
    assert_step_runnable(step)
    match step.input:
        case dict() as input_payload:
            raw_agent_id = input_payload.get("agent_id")
        case _:
            raise StepExecutionTargetError(step.id)
    if not isinstance(raw_agent_id, str):
        raise StepExecutionTargetError(step.id)
    try:
        agent_id = uuid.UUID(raw_agent_id)
    except ValueError as error:
        raise StepExecutionTargetError(step.id) from error
    agent = await db.get(Agent, agent_id)
    if agent is None or agent.group_id != scope.group_id or agent.status != "online":
        raise StepExecutionTargetError(step.id)

    task_id = uuid.uuid4()
    match step.action_type:
        case "isolate_agent":
            task_type = "isolate_host"
            params: dict[str, JsonValue] = {}
            agent.is_isolated = True
        case "block_ip":
            raw_ip = input_payload.get("ip")
            if not isinstance(raw_ip, str):
                raise StepExecutionTargetError(step.id)
            duration = input_payload.get("duration_seconds", 3600)
            if not isinstance(duration, int):
                raise StepExecutionTargetError(step.id)
            task_type = "block_ip"
            params = {"ip": raw_ip, "duration_seconds": duration}
        case _:
            raise StepExecutionTargetError(step.id)

    step.status = "running"
    db.add(
        AgentTask(
            id=task_id,
            agent_id=agent.id,
            task_type=task_type,
            params=params,
            status="pending",
            created_by=scope.actor_id,
        )
    )
    step.status = "succeeded"
    step.output = {"agent_id": str(agent.id), "task_id": str(task_id)}
    step.finished_at = datetime.now(step.started_at.tzinfo)
    return step


def build_rollback_step(
    original: SoarRunStep,
    command: StepActorCommand,
) -> SoarRunStep:
    if not original.is_reversible or original.status != "succeeded":
        raise RollbackNotSupportedError(original.id)
    return SoarRunStep(
        id=uuid.uuid4(),
        run_id=original.run_id,
        node_id=original.node_id,
        action_type=original.action_type,
        status="rolled_back",
        is_destructive=False,
        is_reversible=False,
        actor_id=command.actor_id,
        acted_at=command.acted_at,
        idempotency_key=command.idempotency_key,
        input_hash=original.input_hash,
        rollback_of_step_id=original.id,
        input=original.input,
        started_at=command.acted_at,
        finished_at=command.acted_at,
    )


async def apply_rollback_effect(
    db: AsyncSession,
    original: SoarRunStep,
    rollback: SoarRunStep,
    scope: RollbackScope,
) -> None:
    match original.action_type:
        case "isolate_agent":
            match original.output, original.input:
                case (dict() as output, _):
                    raw_agent_id = output.get("agent_id")
                case (_, dict() as input_payload):
                    raw_agent_id = input_payload.get("agent_id")
                case _:
                    raise RollbackTargetError(original.id)
            if not isinstance(raw_agent_id, str):
                raise RollbackTargetError(original.id)
            try:
                agent_id = uuid.UUID(raw_agent_id)
            except ValueError as error:
                raise RollbackTargetError(original.id) from error
            agent = await db.get(Agent, agent_id)
            if agent is None or agent.group_id != scope.group_id:
                raise RollbackTargetError(original.id)
            agent.is_isolated = False
            db.add(
                AgentTask(
                    agent_id=agent.id,
                    task_type="unisolate_host",
                    params={},
                    status="pending",
                    created_by=scope.actor_id,
                )
            )
            rollback.output = {
                "rollback_action": "unisolate_host",
                "agent_id": str(agent.id),
            }
        case _:
            raise RollbackNotSupportedError(original.id)
