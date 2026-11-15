"""Custom dashboards: a page of widgets, each a saved search shown as a
count, timeline, top values or latest rows. Personal, or shared with the
group (its searches must be shared too, or the group could not run them)."""
from __future__ import annotations

import uuid as uuidlib
from datetime import datetime
from typing import Annotated, Literal, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_scoped_group, require_permission
from app.models.models import CustomDashboard, SavedSearch, User
from app.services import saved_searches as svc

router = APIRouter(prefix="/api/dashboards", tags=["dashboards"])
Read = require_permission("logs:read")
MAX_WIDGETS = 24


class Widget(BaseModel):
    id: str = Field(default_factory=lambda: uuidlib.uuid4().hex[:12], max_length=40)
    title: str = Field("", max_length=120)
    search_id: UUID
    viz: svc.Viz = "count"
    hours: int = Field(24, ge=1, le=svc.MAX_HOURS)
    field: str = "log_type"
    width: Literal[1, 2, 3] = 1  # columns of a 3-column grid

    @model_validator(mode="after")
    def _field(self):
        if self.viz == "top" and self.field not in svc.TOP_FIELDS:
            raise ValueError(f"field must be one of {', '.join(svc.TOP_FIELDS)}")
        return self


class DashboardIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: Optional[str] = Field(None, max_length=2000)
    widgets: list[Widget] = Field(default_factory=list, max_length=MAX_WIDGETS)
    shared: bool = False


class DashboardOut(BaseModel):
    id: UUID
    name: str
    description: Optional[str] = None
    widgets: list[dict]
    shared: bool
    group_id: str
    owner_id: UUID
    mine: bool = False
    editable: bool = False
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    model_config = {"from_attributes": True}


def _out(d: CustomDashboard, user: User, group_filter: str | None) -> DashboardOut:
    out = DashboardOut.model_validate(d)
    out.mine = d.owner_id == user.id
    out.editable = svc.can_edit(d, user, group_filter)
    return out


async def _check_widgets(db: AsyncSession, body: DashboardIn, user: User, group_filter: str | None) -> None:
    ids = {w.search_id for w in body.widgets}
    if not ids:
        return
    found = {s.id: s for s in (await db.execute(select(SavedSearch).where(SavedSearch.id.in_(ids)))).scalars()}
    missing = [str(i) for i in ids if i not in found or not svc.visible(found[i], user, group_filter)]
    if missing:
        raise HTTPException(422, f"Saved search not found: {', '.join(missing)}")
    if body.shared:
        private = sorted(s.name for s in found.values() if not s.shared)
        if private:
            raise HTTPException(422, "Share these saved searches first, or the group cannot see their widgets: "
                                     + ", ".join(private))


async def _load(db, dashboard_id: UUID, user: User, group_filter: str | None) -> CustomDashboard:
    d = await db.get(CustomDashboard, dashboard_id)
    if d is None or not svc.visible(d, user, group_filter):
        raise HTTPException(404, "Dashboard not found")
    return d


@router.get("", response_model=list[DashboardOut])
async def list_dashboards(
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(Read)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    q = select(CustomDashboard)
    if group_filter is not None:
        q = q.where(or_(CustomDashboard.owner_id == user.id,
                        (CustomDashboard.shared.is_(True)) & (CustomDashboard.group_id == group_filter)))
    rows = (await db.execute(q.order_by(CustomDashboard.name))).scalars().all()
    return [_out(d, user, group_filter) for d in rows]


@router.get("/{dashboard_id}", response_model=DashboardOut)
async def get_dashboard(
    dashboard_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(Read)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    return _out(await _load(db, dashboard_id, user, group_filter), user, group_filter)


@router.post("", response_model=DashboardOut, status_code=201)
async def create_dashboard(
    body: DashboardIn,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(Read)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    await _check_widgets(db, body, user, group_filter)
    d = CustomDashboard(name=body.name.strip(), description=body.description, shared=body.shared,
                        widgets=[w.model_dump(mode="json") for w in body.widgets], owner_id=user.id,
                        group_id=group_filter or user.group_id or "default")
    db.add(d)
    await db.commit()
    await db.refresh(d)
    return _out(d, user, group_filter)


@router.put("/{dashboard_id}", response_model=DashboardOut)
async def update_dashboard(
    dashboard_id: UUID,
    body: DashboardIn,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(Read)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    d = await _load(db, dashboard_id, user, group_filter)
    if not svc.can_edit(d, user, group_filter):
        raise HTTPException(403, "Only the owner or a group admin can change this dashboard")
    await _check_widgets(db, body, user, group_filter)
    d.name, d.description, d.shared = body.name.strip(), body.description, body.shared
    d.widgets = [w.model_dump(mode="json") for w in body.widgets]
    await db.commit()
    await db.refresh(d)
    return _out(d, user, group_filter)


@router.delete("/{dashboard_id}", status_code=204)
async def delete_dashboard(
    dashboard_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(Read)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    d = await _load(db, dashboard_id, user, group_filter)
    if not svc.can_edit(d, user, group_filter):
        raise HTTPException(403, "Only the owner or a group admin can delete this dashboard")
    await db.delete(d)
    await db.commit()
