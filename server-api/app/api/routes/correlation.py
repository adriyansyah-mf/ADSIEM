from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Optional
import uuid

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group
from app.models.models import CorrelationRule, User

router = APIRouter(prefix="/api/correlation-rules", tags=["correlation"])


class RuleIn(BaseModel):
    title: str
    description: Optional[str] = None
    match_field: str = "source_ip"
    min_count: int = 5
    timewindow: int = 300
    severity_filter: Optional[str] = None
    output_severity: str = "high"
    output_title: str
    is_enabled: bool = True


class RuleUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    match_field: Optional[str] = None
    min_count: Optional[int] = None
    timewindow: Optional[int] = None
    severity_filter: Optional[str] = None
    output_severity: Optional[str] = None
    output_title: Optional[str] = None
    is_enabled: Optional[bool] = None


@router.get("")
async def list_rules(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_id: Optional[str] = Depends(get_scoped_group),
):
    q = select(CorrelationRule).order_by(CorrelationRule.created_at.desc())
    if group_id is not None:
        q = q.where(CorrelationRule.group_id == group_id)
    rows = (await db.execute(q)).scalars().all()
    return [
        {
            "id": str(r.id),
            "title": r.title,
            "description": r.description,
            "match_field": r.match_field,
            "min_count": r.min_count,
            "timewindow": r.timewindow,
            "severity_filter": r.severity_filter,
            "output_severity": r.output_severity,
            "output_title": r.output_title,
            "is_enabled": r.is_enabled,
            "group_id": r.group_id,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


@router.post("", status_code=201)
async def create_rule(
    body: RuleIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_id: Optional[str] = Depends(get_scoped_group),
):
    rule = CorrelationRule(
        title=body.title,
        description=body.description,
        match_field=body.match_field,
        min_count=body.min_count,
        timewindow=body.timewindow,
        severity_filter=body.severity_filter,
        output_severity=body.output_severity,
        output_title=body.output_title,
        is_enabled=body.is_enabled,
        group_id=group_id or current_user.group_id or "default",
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return {"id": str(rule.id), "title": rule.title}


@router.patch("/{rule_id}")
async def update_rule(
    rule_id: str,
    body: RuleUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rule = await db.get(CorrelationRule, uuid.UUID(rule_id))
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(rule, field, value)
    await db.commit()
    return {"ok": True}


@router.delete("/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rule = await db.get(CorrelationRule, uuid.UUID(rule_id))
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    await db.delete(rule)
    await db.commit()
