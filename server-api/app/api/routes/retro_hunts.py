"""Retro-hunts: search the stored logs for an IOC, or run a rule over them
(services/retro_hunts.py queues, worker/retro_hunt.py runs)."""
from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group, require_permission
from app.models.models import RetroHunt, Rule, User
from app.services import retro_hunts as svc

router = APIRouter(prefix="/api/retro-hunts", tags=["retro-hunts"])


class RetroHuntIn(BaseModel):
    kind: Literal["ioc", "rule"]
    ioc_type: Optional[Literal["ip", "domain", "hash", "url", "text"]] = None
    ioc_value: Optional[str] = Field(None, max_length=2048)
    rule_id: Optional[UUID] = None
    days: Optional[int] = Field(None, ge=1, le=svc.MAX_DAYS)
    create_alerts: Optional[bool] = None
    group_id: Optional[str] = Field(None, max_length=100)  # superadmins: a group, or "*" for all


class RetroHuntOut(BaseModel):
    id: UUID
    kind: str
    ioc_type: Optional[str] = None
    ioc_value: Optional[str] = None
    rule_id: Optional[UUID] = None
    rule_title: Optional[str] = None
    days: int
    group_id: str
    trigger: str
    create_alerts: bool
    status: str
    scanned: int
    matched: int
    hosts: int
    alerts_created: int
    truncated: bool
    results: Optional[dict[str, Any]] = None
    error: Optional[str] = None
    created_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    model_config = {"from_attributes": True}


def _target_group(group_filter: str | None, user: User, requested: str | None) -> str:
    if group_filter is not None:  # a scoped user hunts in their own group only
        return group_filter
    return (requested or "*").strip() or "*"


@router.post("", response_model=RetroHuntOut, status_code=201)
async def create_retro_hunt(
    body: RetroHuntIn,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission("alerts:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    group = _target_group(group_filter, user, body.group_id)
    days = body.days or await svc.default_days(db)
    if body.kind == "ioc":
        if not body.ioc_type or svc.valid_ioc(body.ioc_type, body.ioc_value or "") is None:
            raise HTTPException(422, f"{body.ioc_value!r} is not a valid {body.ioc_type or 'IOC'}")
        hunt = RetroHunt(kind="ioc", ioc_type=body.ioc_type, ioc_value=svc.valid_ioc(body.ioc_type, body.ioc_value),
                         days=days, group_id=group, trigger="manual",
                         create_alerts=True if body.create_alerts is None else body.create_alerts,
                         created_by=await svc.actor(db, user.id))
    else:
        rule = await db.get(Rule, body.rule_id) if body.rule_id else None
        if rule is None or (group_filter is not None and rule.group_id not in (None, group_filter)):
            raise HTTPException(404, "Rule not found")
        hunt = RetroHunt(kind="rule", rule_id=rule.id, rule_title=rule.title, days=days, group_id=group,
                         trigger="manual", create_alerts=bool(body.create_alerts),
                         created_by=await svc.actor(db, user.id))
    db.add(hunt)
    await db.commit()
    await db.refresh(hunt)
    return hunt


@router.get("", response_model=list[RetroHuntOut])
async def list_retro_hunts(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
    limit: int = Query(50, ge=1, le=200),
):
    q = select(RetroHunt).order_by(desc(RetroHunt.created_at)).limit(limit)
    if group_filter is not None:
        q = q.where(RetroHunt.group_id == group_filter)
    return (await db.execute(q)).scalars().all()


@router.get("/{hunt_id}", response_model=RetroHuntOut)
async def get_retro_hunt(
    hunt_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    hunt = await db.get(RetroHunt, hunt_id)
    if hunt is None or (group_filter is not None and hunt.group_id != group_filter):
        raise HTTPException(404, "Retro-hunt not found")
    return hunt
