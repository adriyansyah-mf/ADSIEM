# server-api/app/api/routes/rules.py
import yaml
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group, require_permission
from app.models.models import Rule, User
from app.schemas.schemas import (
    PaginatedResponse, RuleCreate, RuleOut, RuleTestRequest, RuleTestResponse, RuleUpdate
)
from app.services.audit import audit_log

router = APIRouter(prefix="/api/rules", tags=["rules"])

@router.get("", response_model=PaginatedResponse)
async def list_rules(
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(require_permission("logs:read")),
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
    page: int = 1, page_size: int = 25,
):
    q = select(Rule).order_by(Rule.created_at.desc())
    if group_filter is not None:
        q = q.where(Rule.group_id == group_filter)
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    result = await db.execute(q.offset((page - 1) * page_size).limit(page_size))
    return PaginatedResponse(total=total, page=page, page_size=page_size,
                             items=[RuleOut.model_validate(r) for r in result.scalars().all()])

@router.post("", response_model=RuleOut, status_code=201)
async def create_rule(
    body: RuleCreate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("rules:create"))],
):
    _validate_rule_yaml(body.content)
    rule = Rule(**body.model_dump())
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    background.add_task(audit_log, db, current_user.id, "rule_created", "rule", str(rule.id))
    return RuleOut.model_validate(rule)

@router.put("/{rule_id}", response_model=RuleOut)
async def update_rule(
    rule_id: UUID, body: RuleUpdate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("rules:update"))],
):
    result = await db.execute(select(Rule).where(Rule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    updates = body.model_dump(exclude_none=True)
    if "content" in updates:
        _validate_rule_yaml(updates["content"])
        updates["version"] = rule.version + 1
    for field, value in updates.items():
        setattr(rule, field, value)
    await db.commit()
    await db.refresh(rule)
    background.add_task(audit_log, db, current_user.id, "rule_updated", "rule", str(rule_id))
    return RuleOut.model_validate(rule)

@router.delete("/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: UUID,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("rules:delete"))],
):
    result = await db.execute(select(Rule).where(Rule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    await db.delete(rule)
    await db.commit()
    background.add_task(audit_log, db, current_user.id, "rule_deleted", "rule", str(rule_id))

@router.post("/test", response_model=RuleTestResponse)
async def test_rule(body: RuleTestRequest, _=Depends(require_permission("rules:create"))):
    try:
        rule_def = yaml.safe_load(body.content)
        matched = False
        rule_title = rule_def.get("title", "")
        if isinstance(rule_def, dict) and "detection" in rule_def:
            matched = True
        return RuleTestResponse(matched=matched, rule_title=rule_title)
    except Exception as e:
        return RuleTestResponse(matched=False, error=str(e))

def _validate_rule_yaml(content: str):
    try:
        parsed = yaml.safe_load(content)
        if not isinstance(parsed, dict):
            raise ValueError("Rule must be a YAML mapping")
        if "detection" not in parsed:
            raise ValueError("Rule must have a 'detection' block")
    except yaml.YAMLError as e:
        raise HTTPException(status_code=422, detail=f"Invalid YAML: {e}")
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
