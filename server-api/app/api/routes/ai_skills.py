"""AI skills: the procedures the investigator loads by name (services/ai_skills.py).

Analysts read them; settings managers add their own, edit or delete those,
and turn any skill on or off. A built-in skill's text is refreshed from
skills/*.md at every start, so it is changed by saving a copy under another
name (a POST with its text, which the dashboard pre-fills), never in place."""
from __future__ import annotations

from datetime import datetime
from typing import Annotated, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import require_permission
from app.models.models import AiSkill, User
from app.services import ai_skills
from app.services.audit import audit_log

router = APIRouter(prefix="/api/ai-skills", tags=["ai-skills"])
Read = Depends(require_permission("alerts:read"))
Manage = Depends(require_permission("settings:manage"))


class SkillOut(BaseModel):
    id: UUID
    name: str
    description: str
    content: str
    is_enabled: bool
    origin: str
    updated_at: Optional[datetime] = None
    model_config = {"from_attributes": True}


class SkillIn(BaseModel):
    name: str = Field(..., max_length=80)
    description: str = Field(..., min_length=10, max_length=ai_skills.MAX_DESCRIPTION)
    content: str = Field(..., min_length=20, max_length=ai_skills.MAX_CONTENT)

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip().lower()
        if not ai_skills.NAME_RE.match(v):
            raise ValueError("name: 3-80 lowercase letters, digits and hyphens, e.g. phishing-investigation")
        return v


class SkillPatch(BaseModel):
    is_enabled: Optional[bool] = None
    description: Optional[str] = Field(None, min_length=10, max_length=ai_skills.MAX_DESCRIPTION)
    content: Optional[str] = Field(None, min_length=20, max_length=ai_skills.MAX_CONTENT)


async def _get(db: AsyncSession, skill_id: UUID) -> AiSkill:
    row = await db.get(AiSkill, skill_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Skill not found")
    return row


async def _actor(db: AsyncSession, user: User) -> UUID | None:
    return user.id if await db.get(User, user.id) is not None else None


@router.get("", response_model=list[SkillOut])
async def list_skills(db: Annotated[AsyncSession, Depends(get_db)], _=Read):
    return (await db.execute(select(AiSkill).order_by(AiSkill.origin, AiSkill.name))).scalars().all()


@router.post("", response_model=SkillOut, status_code=201)
async def create_skill(body: SkillIn, db: Annotated[AsyncSession, Depends(get_db)], user: User = Manage):
    row = AiSkill(name=body.name, description=body.description.strip(), content=body.content.strip(),
                  is_enabled=True, origin="custom", created_by=await _actor(db, user))
    db.add(row)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail=f"a skill named {body.name} already exists")
    await db.refresh(row)
    await audit_log(db, user.id, "ai_skill.create", "ai_skill", str(row.id), {"name": row.name})
    return row


@router.patch("/{skill_id}", response_model=SkillOut)
async def update_skill(skill_id: UUID, body: SkillPatch, db: Annotated[AsyncSession, Depends(get_db)],
                       user: User = Manage):
    row = await _get(db, skill_id)
    if row.origin == ai_skills.BUILTIN and (body.description is not None or body.content is not None):
        raise HTTPException(status_code=409, detail="A built-in skill is refreshed at every start: save a copy "
                                                    "under another name to change it, then turn this one off")
    changed = {}
    if body.is_enabled is not None and body.is_enabled != row.is_enabled:
        row.is_enabled = changed["is_enabled"] = body.is_enabled
    if body.description is not None:
        row.description = body.description.strip()
        changed["description"] = True
    if body.content is not None:
        row.content = body.content.strip()
        changed["content"] = True
    await db.commit()
    await db.refresh(row)
    if changed:
        await audit_log(db, user.id, "ai_skill.update", "ai_skill", str(row.id), {"name": row.name, **changed})
    return row


@router.delete("/{skill_id}", status_code=204)
async def delete_skill(skill_id: UUID, db: Annotated[AsyncSession, Depends(get_db)], user: User = Manage):
    row = await _get(db, skill_id)
    if row.origin == ai_skills.BUILTIN:
        raise HTTPException(status_code=409, detail="A built-in skill can be turned off, not deleted")
    name = row.name
    await db.delete(row)
    await db.commit()
    await audit_log(db, user.id, "ai_skill.delete", "ai_skill", str(skill_id), {"name": name})
