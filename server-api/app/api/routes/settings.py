# server-api/app/api/routes/settings.py
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import require_permission
from app.models.models import PlatformSetting, User
from app.schemas.schemas import SettingOut, SettingUpdate
from app.services.audit import audit_log

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
    background: BackgroundTasks,
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
    background.add_task(
        audit_log, db, current_user.id, "setting_updated", "platform_setting", key,
        {"is_secret": bool(setting.is_secret)},
    )
    return _mask(setting)


@router.get("/api/settings/ai-models")
async def list_ai_models(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(Perm)],
):
    """Models and combos the configured 9router offers (its /v1/models), for the
    model pickers — every AI call still goes through 9router."""
    import httpx

    from app.core.config import settings

    key = (await db.execute(
        select(PlatformSetting.value).where(PlatformSetting.key == "ninerouter_api_key")
    )).scalar_one_or_none()
    if not key:
        raise HTTPException(status_code=422, detail="Set the 9router API key first")
    url = f"{settings.NINEROUTER_BASE_URL.rstrip('/')}/models"
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(url, headers={"Authorization": f"Bearer {key}"})
            resp.raise_for_status()
            body = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(status_code=502, detail=f"9router /models failed: {exc}")
    items = body.get("data", body) if isinstance(body, dict) else body
    if not isinstance(items, list):
        return {"models": []}
    return {"models": sorted({str(m["id"]) for m in items if isinstance(m, dict) and m.get("id")})}
