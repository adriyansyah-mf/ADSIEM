from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group, require_resource_group
from app.core.rate_limit import rate_limit_by_user_group
from app.models.models import SoarRun, SoarRunStep, User
from app.services.soar_executor import advance_frontier
from app.services.soar_service import (
    IdempotencyConflictError,
    RollbackNotSupportedError,
    RollbackScope,
    RollbackTargetError,
    StepActorCommand,
    StepExecutionScope,
    StepExecutionTargetError,
    StepStateConflictError,
    apply_rollback_effect,
    approve_step,
    build_rollback_step,
    execute_approved_step,
)

router = APIRouter(prefix="/executions", tags=["soar"])
RateLimitApproval = rate_limit_by_user_group("soar_approval")


class StepCommandIn(BaseModel):
    model_config = ConfigDict(frozen=True)

    idempotency_key: str = Field(min_length=8, max_length=255)


def _step_out(step: SoarRunStep) -> dict[str, str | bool | dict | None]:
    return {
        "id": str(step.id),
        "node_id": str(step.node_id),
        "action_type": step.action_type,
        "status": step.status,
        "is_destructive": step.is_destructive,
        "is_reversible": step.is_reversible,
        "actor_id": str(step.actor_id) if step.actor_id else None,
        "acted_at": step.acted_at.isoformat() if step.acted_at else None,
        "idempotency_key": step.idempotency_key,
        "input_hash": step.input_hash,
        "rollback_of_step_id": (
            str(step.rollback_of_step_id) if step.rollback_of_step_id else None
        ),
        "input": step.input,
        "output": step.output,
        "error": step.error,
        "started_at": step.started_at.isoformat() if step.started_at else None,
        "finished_at": step.finished_at.isoformat() if step.finished_at else None,
    }


async def _load_run(
    db: AsyncSession,
    execution_id: uuid.UUID,
    group_filter: str | None,
) -> SoarRun:
    run = await db.get(SoarRun, execution_id)
    require_resource_group(run.group_id if run is not None else None, group_filter)
    assert run is not None
    return run


async def _steps_for_run(db: AsyncSession, run_id: uuid.UUID) -> list[SoarRunStep]:
    result = await db.execute(
        select(SoarRunStep)
        .where(SoarRunStep.run_id == run_id)
        .order_by(SoarRunStep.started_at.asc(), SoarRunStep.id.asc())
    )
    return list(result.scalars().all())


@router.get("")
async def list_executions(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
) -> list[dict]:
    query = select(SoarRun).order_by(SoarRun.started_at.desc()).limit(50)
    if group_filter is not None:
        query = query.where(SoarRun.group_id == group_filter)
    runs = (await db.execute(query)).scalars().all()
    output = []
    for run in runs:
        steps = await _steps_for_run(db, run.id)
        output.append(
            {
                "id": str(run.id),
                "workflow_id": str(run.workflow_id),
                "status": run.status,
                "trigger_type": run.trigger_type,
                "started_at": run.started_at.isoformat(),
                "finished_at": run.finished_at.isoformat() if run.finished_at else None,
                "steps": [_step_out(step) for step in steps],
            }
        )
    return output


@router.post("/{execution_id}/approve")
async def approve_execution(
    execution_id: uuid.UUID,
    body: StepCommandIn,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _rate_limit: Annotated[None, Depends(RateLimitApproval)],
) -> dict[str, str | bool | dict | None]:
    run = await _load_run(db, execution_id, group_filter)
    steps = await _steps_for_run(db, run.id)
    step = next(
        (candidate for candidate in reversed(steps) if candidate.status == "pending_approval"),
        None,
    )
    if step is None:
        step = next(
            (
                candidate
                for candidate in reversed(steps)
                if candidate.idempotency_key == body.idempotency_key
                and candidate.status in {"approved", "succeeded"}
            ),
            None,
        )
    if step is None:
        raise HTTPException(status_code=409, detail="No step is pending approval")
    try:
        approve_step(
            step,
            StepActorCommand(
                actor_id=current_user.id,
                idempotency_key=body.idempotency_key,
                acted_at=datetime.now(timezone.utc),
            ),
        )
        await execute_approved_step(
            db,
            step,
            StepExecutionScope(actor_id=current_user.id, group_id=run.group_id),
        )
    except (
        IdempotencyConflictError,
        StepExecutionTargetError,
        StepStateConflictError,
    ) as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    if run.graph_snapshot is None:
        # A v1-era or manually created run has no snapshot to advance
        # through -- there is nothing left for this executor to drive.
        run.status = "succeeded"
        run.finished_at = datetime.now(timezone.utc)
    elif run.current_node_id != step.node_id:
        # The run has already moved past this step's node -- this is an
        # idempotent replay of an approval that already advanced it (the
        # lookup above matches a retried request by idempotency_key against
        # an already-approved/succeeded step). Advancing again would skip
        # the node the run is now actually parked at.
        pass
    else:
        current, pending = advance_frontier(
            run.graph_snapshot, str(step.node_id), "out", list(run.pending_node_ids or [])
        )
        run.current_node_id = uuid.UUID(current) if current else None
        run.pending_node_ids = pending
        if current is None:
            run.status = "succeeded"
            run.finished_at = datetime.now(timezone.utc)
        else:
            run.status = "running"
            run.finished_at = None
    await db.commit()
    await db.refresh(step)
    return _step_out(step)


@router.post("/{execution_id}/rollback", status_code=status.HTTP_201_CREATED)
async def rollback_execution(
    execution_id: uuid.UUID,
    body: StepCommandIn,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
) -> dict[str, str | bool | dict | None]:
    run = await _load_run(db, execution_id, group_filter)
    steps = await _steps_for_run(db, run.id)
    duplicate = next(
        (step for step in steps if step.idempotency_key == body.idempotency_key),
        None,
    )
    if duplicate is not None:
        if duplicate.status == "rolled_back":
            return _step_out(duplicate)
        raise HTTPException(status_code=409, detail="Idempotency key already used")
    rolled_back_ids = {
        step.rollback_of_step_id for step in steps if step.rollback_of_step_id is not None
    }
    original = next(
        (
            step
            for step in reversed(steps)
            if step.status == "succeeded"
            and step.is_reversible
            and step.id not in rolled_back_ids
        ),
        None,
    )
    if original is None:
        raise HTTPException(status_code=409, detail="No reversible step is available")
    try:
        rollback = build_rollback_step(
            original,
            StepActorCommand(
                actor_id=current_user.id,
                idempotency_key=body.idempotency_key,
                acted_at=datetime.now(timezone.utc),
            ),
        )
        rollback_group = group_filter or run.group_id
        await apply_rollback_effect(
            db,
            original,
            rollback,
            RollbackScope(actor_id=current_user.id, group_id=rollback_group),
        )
    except (
        RollbackNotSupportedError,
        RollbackTargetError,
        StepStateConflictError,
    ) as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    db.add(rollback)
    run.status = "rolled_back"
    await db.commit()
    await db.refresh(rollback)
    return _step_out(rollback)


@router.post("/{execution_id}/cancel")
async def cancel_execution(
    execution_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
) -> dict[str, str | bool | dict | None]:
    """Let an analyst decline a parked run instead of leaving it waiting
    forever -- `waiting` previously had no exit besides approve (finding
    I4)."""
    run = await _load_run(db, execution_id, group_filter)
    steps = await _steps_for_run(db, run.id)
    step = steps[-1] if steps else None
    if step is None:
        raise HTTPException(status_code=409, detail="Run has no steps to cancel")
    if step.status == "succeeded":
        raise HTTPException(
            status_code=409, detail="Latest step has already succeeded; nothing to cancel"
        )
    now = datetime.now(timezone.utc)
    # "failed" is the only terminal-negative value the closed step-status set
    # (soar_service.py / spec §5) permits; there is no dedicated "cancelled"
    # step status, so a declined step is recorded as failed with an error
    # explaining why.
    step.status = "failed"
    step.error = "Cancelled by analyst"
    step.actor_id = current_user.id
    step.acted_at = now
    step.finished_at = now
    run.status = "cancelled"
    run.finished_at = now
    await db.commit()
    await db.refresh(step)
    return _step_out(step)
