from datetime import datetime, timezone
from collections.abc import AsyncIterator
from types import SimpleNamespace
import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.routes.soar import router as soar_router
from app.api.routes.soar_executions import RateLimitApproval
from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group
from app.models.models import Agent, AgentTask, SoarRun, SoarRunStep
from app.services.soar_service import (
    ApprovalRequiredError,
    IdempotencyConflictError,
    RollbackNotSupportedError,
    StepExecutionScope,
    StepActorCommand,
    StepPreparation,
    approve_step,
    assert_step_runnable,
    build_rollback_step,
    build_step_record,
    execute_approved_step,
    validate_idempotent_retry,
)


def _preparation(action_type: str, payload: dict[str, str], key: str) -> StepPreparation:
    return StepPreparation(
        run_id=uuid.uuid4(),
        node_id=uuid.uuid4(),
        action_type=action_type,
        input_payload=payload,
        idempotency_key=key,
        started_at=datetime(2026, 9, 6, 10, 0, tzinfo=timezone.utc),
    )


class _FakeScalars:
    def __init__(self, values: list[SoarRunStep]) -> None:
        self._values = values

    def all(self) -> list[SoarRunStep]:
        return self._values


class _FakeResult:
    def __init__(self, values: list[SoarRunStep]) -> None:
        self._values = values

    def scalars(self) -> _FakeScalars:
        return _FakeScalars(self._values)


class _FakeSession:
    def __init__(
        self,
        run: SoarRun,
        steps: list[SoarRunStep],
        agent: Agent | None = None,
    ) -> None:
        self.run = run
        self.steps = steps
        self.agent = agent
        self.added: list[AgentTask | SoarRunStep] = []

    async def get(self, model, identity):
        if model is SoarRun and identity == self.run.id:
            return self.run
        if model is Agent and self.agent is not None and identity == self.agent.id:
            return self.agent
        return None

    async def execute(self, statement) -> _FakeResult:
        return _FakeResult(self.steps)

    async def commit(self) -> None:
        return None

    async def refresh(self, instance) -> None:
        return None

    def add(self, instance: AgentTask | SoarRunStep) -> None:
        self.added.append(instance)


def _approval_client(
    step: SoarRunStep,
    agent: Agent | None = None,
) -> tuple[TestClient, SoarRun, SimpleNamespace, _FakeSession]:
    run = SoarRun(
        id=step.run_id,
        workflow_id=uuid.uuid4(),
        status="waiting_approval",
        trigger_type="alert",
        trigger_ref={},
        variables={},
        group_id="blue",
        started_at=datetime(2026, 9, 6, 10, 0, tzinfo=timezone.utc),
    )
    user = SimpleNamespace(id=uuid.uuid4(), group_id="blue")
    session = _FakeSession(run, [step], agent)
    app = FastAPI()
    app.include_router(soar_router)

    async def override_db() -> AsyncIterator[_FakeSession]:
        yield session

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_scoped_group] = lambda: "blue"
    # This file exercises approval/rollback logic, not rate limiting (that has
    # its own dedicated coverage in test_security_boundaries.py) — bypass it
    # here so repeated runs within the same real Redis window can't make these
    # tests flake once the group's soar_approval budget is spent.
    app.dependency_overrides[RateLimitApproval] = lambda: None
    return TestClient(app), run, user, session


def test_destructive_step_cannot_run_while_pending_approval() -> None:
    # Given
    step = build_step_record(
        _preparation("isolate_agent", {"agent_id": "agent-7"}, "run-7-isolate")
    )

    # When / Then
    assert step.status == "pending_approval"
    with pytest.raises(ApprovalRequiredError):
        assert_step_runnable(step)


def test_approval_records_actor_timestamp_and_allows_step_to_run() -> None:
    # Given
    step = build_step_record(
        _preparation("block_ip", {"ip": "203.0.113.7"}, "run-8-block")
    )
    actor_id = uuid.uuid4()
    approved_at = datetime(2026, 9, 6, 10, 5, tzinfo=timezone.utc)

    # When
    approve_step(
        step,
        StepActorCommand(
            actor_id=actor_id,
            idempotency_key="run-8-block",
            acted_at=approved_at,
        ),
    )

    # Then
    assert step.status == "approved"
    assert step.actor_id == actor_id
    assert step.acted_at == approved_at
    assert_step_runnable(step)


def test_identical_retry_is_idempotent_but_changed_input_is_rejected() -> None:
    # Given
    preparation = _preparation("isolate_agent", {"agent_id": "agent-9"}, "retry-9")
    step = build_step_record(preparation)

    # When
    duplicate = validate_idempotent_retry(step, preparation)

    # Then
    assert duplicate is step

    # When / Then
    changed = _preparation("isolate_agent", {"agent_id": "agent-10"}, "retry-9")
    changed = StepPreparation(
        run_id=preparation.run_id,
        node_id=preparation.node_id,
        action_type=changed.action_type,
        input_payload=changed.input_payload,
        idempotency_key=changed.idempotency_key,
        started_at=changed.started_at,
    )
    with pytest.raises(IdempotencyConflictError):
        validate_idempotent_retry(step, changed)


def test_rollback_appends_linked_audit_record_for_reversible_step() -> None:
    # Given
    step = build_step_record(
        _preparation("isolate_agent", {"agent_id": "agent-11"}, "run-11-isolate")
    )
    step.status = "succeeded"
    step.output = {"agent_id": "agent-11"}
    step.finished_at = datetime(2026, 9, 6, 10, 10, tzinfo=timezone.utc)
    actor_id = uuid.uuid4()

    # When
    rollback = build_rollback_step(
        step,
        StepActorCommand(
            actor_id=actor_id,
            idempotency_key="rollback-run-11",
            acted_at=datetime(2026, 9, 6, 10, 15, tzinfo=timezone.utc),
        ),
    )

    # Then
    assert rollback.status == "rolled_back"
    assert rollback.rollback_of_step_id == step.id
    assert rollback.actor_id == actor_id
    assert step.status == "succeeded"


def test_rollback_rejects_irreversible_step() -> None:
    # Given
    step = build_step_record(
        _preparation("block_ip", {"ip": "203.0.113.12"}, "run-12-block")
    )
    step.status = "succeeded"

    # When / Then
    with pytest.raises(RollbackNotSupportedError):
        build_rollback_step(
            step,
            StepActorCommand(
                actor_id=uuid.uuid4(),
                idempotency_key="rollback-run-12",
                acted_at=datetime(2026, 9, 6, 10, 20, tzinfo=timezone.utc),
            ),
        )


def test_execution_approval_and_rollback_routes_are_registered() -> None:
    # Given
    app = FastAPI()
    app.include_router(soar_router)

    # When
    paths = app.openapi()["paths"]

    # Then
    assert "post" in paths["/api/soar/executions/{execution_id}/approve"]
    assert "post" in paths["/api/soar/executions/{execution_id}/rollback"]


def test_approval_api_rejects_a_mismatched_idempotency_key() -> None:
    # Given
    step = build_step_record(
        _preparation("isolate_agent", {"agent_id": "agent-13"}, "run-13-isolate")
    )
    client, run, _, _ = _approval_client(step)

    # When
    response = client.post(
        f"/api/soar/executions/{run.id}/approve",
        json={"idempotency_key": "different-key"},
    )

    # Then
    assert response.status_code == 409
    assert step.status == "pending_approval"


def test_approval_api_records_the_authenticated_actor() -> None:
    # Given
    agent_id = uuid.uuid4()
    step = build_step_record(
        _preparation("isolate_agent", {"agent_id": str(agent_id)}, "run-14-isolate")
    )
    agent = Agent(
        id=agent_id,
        name="host-14",
        hostname="host-14",
        group_id="blue",
        token_hash="hash",
        status="online",
        is_isolated=False,
    )
    client, run, user, session = _approval_client(step, agent)

    # When
    response = client.post(
        f"/api/soar/executions/{run.id}/approve",
        json={"idempotency_key": "run-14-isolate"},
    )

    # Then
    assert response.status_code == 200
    assert response.json()["status"] == "succeeded"
    assert response.json()["actor_id"] == str(user.id)
    assert agent.is_isolated is True
    assert len([item for item in session.added if isinstance(item, AgentTask)]) == 1


@pytest.mark.asyncio
async def test_retrying_an_approved_step_does_not_queue_duplicate_work() -> None:
    # Given
    agent_id = uuid.uuid4()
    step = build_step_record(
        _preparation("isolate_agent", {"agent_id": str(agent_id)}, "run-15-isolate")
    )
    actor_id = uuid.uuid4()
    approve_step(
        step,
        StepActorCommand(
            actor_id=actor_id,
            idempotency_key="run-15-isolate",
            acted_at=datetime(2026, 9, 6, 10, 25, tzinfo=timezone.utc),
        ),
    )
    agent = Agent(
        id=agent_id,
        name="host-15",
        hostname="host-15",
        group_id="blue",
        token_hash="hash",
        status="online",
        is_isolated=False,
    )
    run = SoarRun(id=step.run_id, workflow_id=uuid.uuid4(), group_id="blue")
    session = _FakeSession(run, [step], agent)
    scope = StepExecutionScope(actor_id=actor_id, group_id="blue")

    # When
    first = await execute_approved_step(session, step, scope)
    second = await execute_approved_step(session, step, scope)

    # Then
    assert first is second
    assert step.status == "succeeded"
    assert len([item for item in session.added if isinstance(item, AgentTask)]) == 1
