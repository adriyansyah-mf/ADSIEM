"""Custom dashboards, built like Wazuh / OpenSearch Dashboards: a grid of
visualizations, each over a saved search or its own query, all narrowed by
the dashboard's time range, query bar and filter pills. Personal, or shared
with the group (its saved searches must be shared too, or the group could not
run them)."""
from __future__ import annotations

import uuid as uuidlib
from datetime import datetime
from types import SimpleNamespace
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


class WidgetSource(BaseModel):
    """A saved search, or the widget's own query (kind + Lucene)."""
    search_id: Optional[UUID] = None
    kind: Literal["logs", "events"] = "logs"
    query: str = Field("", max_length=512)
    viz: svc.Viz = "count"
    field: str = "log_type"
    limit: int = Field(10, ge=1, le=50)

    @model_validator(mode="after")
    def _field(self):
        if self.viz in svc.FIELD_VIZ and self.field not in svc.GROUP_FIELDS:
            raise ValueError(f"field must be one of {', '.join(svc.GROUP_FIELDS)}")
        return self


class Widget(WidgetSource):
    id: str = Field(default_factory=lambda: uuidlib.uuid4().hex[:12], max_length=40)
    title: str = Field("", max_length=120)
    hours: int = Field(24, ge=1, le=svc.MAX_HOURS)  # used when the dashboard's time picker says "widget default"
    chart: Literal["area", "line", "bar"] = "area"  # timeline / split
    # position on a 12-column grid; width (1-3 thirds) is the old layout
    x: Optional[int] = Field(None, ge=0, le=11)
    y: Optional[int] = Field(None, ge=0, le=10_000)
    w: Optional[int] = Field(None, ge=1, le=12)
    h: Optional[int] = Field(None, ge=2, le=24)
    width: Optional[Literal[1, 2, 3]] = None


class Pin(BaseModel):
    field: str
    value: str = Field(max_length=512)
    negate: bool = False

    @model_validator(mode="after")
    def _field(self):
        if self.field not in svc.GROUP_FIELDS:
            raise ValueError(f"field must be one of {', '.join(svc.GROUP_FIELDS)}")
        return self


class WidgetRun(BaseModel):
    widget: WidgetSource
    hours: int = Field(24, ge=1, le=svc.MAX_HOURS)
    tz: Optional[str] = Field(None, max_length=64)
    query: str = Field("", max_length=512)  # the dashboard's query bar
    filters: list[Pin] = Field(default_factory=list, max_length=svc.MAX_FILTERS)


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
    ids = {w.search_id for w in body.widgets if w.search_id}
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


@router.post("/widget-data")
async def widget_data(
    body: WidgetRun,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(Read)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    """Run one visualization, in the caller's group, narrowed by the
    dashboard's time range, query bar and filters."""
    w = body.widget
    if w.search_id:
        s = await db.get(SavedSearch, w.search_id)
        if s is None or not svc.visible(s, user, group_filter):
            raise HTTPException(404, "Saved search not found")
        source = {"id": str(s.id), "name": s.name, "kind": s.kind, "query": s.query}
    else:
        s = SimpleNamespace(kind=w.kind, query=w.query, filter_tree=None, log_type=None)
        source = {"id": None, "name": None, "kind": w.kind, "query": w.query}
    try:
        out = await svc.run(s, group_filter, w.viz, body.hours, w.field, w.limit, body.tz,
                            extra_query=body.query, pins=[p.model_dump() for p in body.filters])
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    return {"search": source, **out}


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
