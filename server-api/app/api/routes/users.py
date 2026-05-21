from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, require_permission
from app.core.security import hash_password
from app.models.models import User
from app.schemas.schemas import PaginatedResponse, UserCreate, UserOut, UserUpdate
from app.services.audit import audit_log

router = APIRouter(prefix="/api/users", tags=["users"])
Perm = require_permission("users:manage")

@router.get("", response_model=PaginatedResponse)
async def list_users(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(Perm)],
    page: int = 1,
    page_size: int = 25,
):
    offset = (page - 1) * page_size
    total = (await db.execute(select(func.count()).select_from(User))).scalar()
    result = await db.execute(select(User).offset(offset).limit(page_size))
    users = result.scalars().all()
    return PaginatedResponse(total=total, page=page, page_size=page_size, items=[UserOut.model_validate(u) for u in users])

@router.post("", response_model=UserOut, status_code=201)
async def create_user(
    body: UserCreate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(Perm)],
):
    user = User(
        username=body.username, email=body.email,
        password_hash=hash_password(body.password),
        role_id=body.role_id, group_id=body.group_id,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    background.add_task(audit_log, db, current_user.id, "user_created", "user", str(user.id))
    return UserOut.model_validate(user)

@router.put("/{user_id}", response_model=UserOut)
async def update_user(
    user_id: UUID,
    body: UserUpdate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(Perm)],
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    for field, value in body.model_dump(exclude_none=True).items():
        if field == "password":
            setattr(user, "password_hash", hash_password(value))
        else:
            setattr(user, field, value)
    await db.commit()
    await db.refresh(user)
    background.add_task(audit_log, db, current_user.id, "user_updated", "user", str(user_id))
    return UserOut.model_validate(user)

@router.delete("/{user_id}", status_code=204)
async def delete_user(
    user_id: UUID,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(Perm)],
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    await db.delete(user)
    await db.commit()
    background.add_task(audit_log, db, current_user.id, "user_deleted", "user", str(user_id))
