# server-api/app/api/routes/settings.py
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.core.deps import get_current_user, require_permission
from app.models.models import PlatformSetting, User
from app.schemas.schemas import SettingOut, SettingUpdate

router = APIRouter(tags=["settings"])
Perm = require_permission("settings:manage")

SECRET_MASK = "••••••••"

def _mask(s: PlatformSetting) -> SettingOut:
    out = SettingOut.model_validate(s)
    if s.is_secret and s.value:
        out.value = SECRET_MASK
    return out

@router.get("/api/settings", response_model=list[SettingOut])
async def list_settings(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(Perm)],
):
    result = await db.execute(select(PlatformSetting).order_by(PlatformSetting.key))
    return [_mask(s) for s in result.scalars().all()]

@router.put("/api/settings/{key}", response_model=SettingOut)
async def update_setting(
    key: str, body: SettingUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(Perm)],
):
    result = await db.execute(select(PlatformSetting).where(PlatformSetting.key == key))
    setting = result.scalar_one_or_none()
    if not setting:
        raise HTTPException(status_code=404, detail="Setting not found")
    setting.value = body.value
    setting.updated_by = current_user.id
    await db.commit()
    await db.refresh(setting)
    return _mask(setting)
