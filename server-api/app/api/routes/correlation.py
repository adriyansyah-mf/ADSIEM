# server-api/app/api/routes/correlation.py
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, require_permission
from app.models.models import CorrelationRule, User
from app.schemas.schemas import CorrelationRuleCreate, CorrelationRuleOut, CorrelationRuleUpdate

router = APIRouter(prefix="/api/correlation-rules", tags=["correlation"])
Perm = require_permission("rules:manage")


@router.get("", response_model=list[CorrelationRuleOut])
async def list_rules(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(select(CorrelationRule).order_by(CorrelationRule.created_at.desc()))
    return [CorrelationRuleOut.model_validate(r) for r in result.scalars().all()]


@router.post("", response_model=CorrelationRuleOut, status_code=201)
async def create_rule(
    body: CorrelationRuleCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(Perm)],
):
    rule = CorrelationRule(**body.model_dump())
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return CorrelationRuleOut.model_validate(rule)


@router.put("/{rule_id}", response_model=CorrelationRuleOut)
async def update_rule(
    rule_id: UUID, body: CorrelationRuleUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(Perm)],
):
    result = await db.execute(select(CorrelationRule).where(CorrelationRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, "Rule not found")
    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(rule, field, value)
    await db.commit()
    await db.refresh(rule)
    return CorrelationRuleOut.model_validate(rule)


@router.delete("/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(Perm)],
):
    result = await db.execute(select(CorrelationRule).where(CorrelationRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, "Rule not found")
    await db.delete(rule)
    await db.commit()
