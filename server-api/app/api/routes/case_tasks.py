"""Tasks on a case: assignable to-dos with an owner and a due date.

Every route resolves the case through fetch_scoped first, so a task is only
reachable by users who can see its case's group."""
from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.core.deps import fetch_scoped, get_current_user, get_scoped_group, require_permission
from app.models.models import Case, CaseTask, User
from app.services.audit import audit_log

router = APIRouter(prefix="/api/cases", tags=["cases"])
Database = Annotated[AsyncSession, Depends(get_db)]
Scope = Annotated[str | None, Depends(get_scoped_group)]
MAX_TASKS_PER_CASE = 200


class CaseTaskOut(BaseModel):
    id: UUID
    case_id: UUID
    title: str
    done: bool
    assignee_id: UUID | None
    due_at: datetime | None
    created_by: UUID | None
    created_at: datetime | None
    completed_at: datetime | None
    model_config = {"from_attributes": True}


class CaseTaskCreate(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    assignee_id: UUID | None = None
    due_at: datetime | None = None


class CaseTaskUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=300)
    done: bool | None = None
    assignee_id: UUID | None = None
    due_at: datetime | None = None
    # explicit clears, since None above means "leave unchanged"
    clear_assignee: bool = False
    clear_due: bool = False


async def _task(db: AsyncSession, case: Case, task_id: UUID) -> CaseTask:
    task = await db.get(CaseTask, task_id)
    if task is None or task.case_id != case.id:
        raise HTTPException(status_code=404, detail="Task not found")
    return task


async def _check_assignee(db: AsyncSession, case: Case, assignee_id: UUID | None) -> None:
    if assignee_id is None:
        return
    user = (await db.execute(select(User).options(selectinload(User.role))
                             .where(User.id == assignee_id))).scalar_one_or_none()
    # superadmins work across groups; everyone else must belong to the case's group
    if user is None or (getattr(user.role, "name", None) != "superadmin" and user.group_id != case.group_id):
        raise HTTPException(status_code=422, detail="Assignee is not a member of this case's group")


@router.get("/{case_id}/tasks", response_model=list[CaseTaskOut])
async def list_tasks(case_id: UUID, db: Database, group: Scope, _=Depends(get_current_user)):
    case = await fetch_scoped(db, Case, case_id, group, detail="Case not found")
    rows = await db.execute(select(CaseTask).where(CaseTask.case_id == case.id)
                            .order_by(CaseTask.done, CaseTask.due_at.is_(None), CaseTask.due_at, CaseTask.created_at))
    return rows.scalars().all()


@router.post("/{case_id}/tasks", response_model=CaseTaskOut, status_code=201)
async def create_task(
    case_id: UUID, body: CaseTaskCreate, db: Database, group: Scope, background: BackgroundTasks,
    user: Annotated[User, Depends(require_permission("cases:manage"))],
):
    case = await fetch_scoped(db, Case, case_id, group, detail="Case not found")
    count = len((await db.execute(select(CaseTask.id).where(CaseTask.case_id == case.id))).all())
    if count >= MAX_TASKS_PER_CASE:
        raise HTTPException(status_code=409, detail=f"A case can hold at most {MAX_TASKS_PER_CASE} tasks")
    await _check_assignee(db, case, body.assignee_id)
    task = CaseTask(case_id=case.id, title=body.title.strip(), assignee_id=body.assignee_id,
                    due_at=body.due_at, created_by=user.id, created_at=datetime.now(timezone.utc))
    db.add(task)
    await db.commit()
    await db.refresh(task)
    background.add_task(audit_log, db, user.id, "case_task.create", "case", str(case.id),
                        {"task_id": str(task.id)}, group_id=case.group_id)
    return task


@router.put("/{case_id}/tasks/{task_id}", response_model=CaseTaskOut)
async def update_task(
    case_id: UUID, task_id: UUID, body: CaseTaskUpdate, db: Database, group: Scope, background: BackgroundTasks,
    user: Annotated[User, Depends(require_permission("cases:manage"))],
):
    case = await fetch_scoped(db, Case, case_id, group, detail="Case not found")
    task = await _task(db, case, task_id)
    if body.title is not None:
        task.title = body.title.strip()
    if body.done is not None and body.done != task.done:
        task.done = body.done
        task.completed_at = datetime.now(timezone.utc) if body.done else None
    if body.clear_assignee:
        task.assignee_id = None
    elif body.assignee_id is not None:
        await _check_assignee(db, case, body.assignee_id)
        task.assignee_id = body.assignee_id
    if body.clear_due:
        task.due_at = None
    elif body.due_at is not None:
        task.due_at = body.due_at
    await db.commit()
    await db.refresh(task)
    background.add_task(audit_log, db, user.id, "case_task.update", "case", str(case.id),
                        {"task_id": str(task.id), "done": task.done}, group_id=case.group_id)
    return task


@router.delete("/{case_id}/tasks/{task_id}", status_code=204)
async def delete_task(
    case_id: UUID, task_id: UUID, db: Database, group: Scope, background: BackgroundTasks,
    user: Annotated[User, Depends(require_permission("cases:manage"))],
):
    case = await fetch_scoped(db, Case, case_id, group, detail="Case not found")
    task = await _task(db, case, task_id)
    await db.delete(task)
    await db.commit()
    background.add_task(audit_log, db, user.id, "case_task.delete", "case", str(case.id),
                        {"task_id": str(task_id)}, group_id=case.group_id)
