"""Saved searches (services/saved_searches.py): keep a Log search or Events
query by name, share it with the group, run it as a count, timeline, top
values or latest rows."""
from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_scoped_group, require_permission
from app.core.query_builder import _field_allowed, tree_to_query
from app.models.models import SavedSearch, User
from app.services import saved_searches as svc

router = APIRouter(prefix="/api/saved-searches", tags=["saved-searches"])
Read = require_permission("logs:read")


class SavedSearchIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: Optional[str] = Field(None, max_length=2000)
    kind: Literal["logs", "events"] = "logs"
    query: str = Field("", max_length=512)
    filter_tree: Optional[dict[str, Any]] = None
    log_type: Optional[str] = Field(None, max_length=100)
    shared: bool = False


class SavedSearchOut(BaseModel):
    id: UUID
    name: str
    description: Optional[str] = None
    kind: str
    query: str
    filter_tree: Optional[dict[str, Any]] = None
    log_type: Optional[str] = None
    shared: bool
    group_id: str
    owner_id: UUID
    mine: bool = False
    editable: bool = False
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    model_config = {"from_attributes": True}


def _out(s: SavedSearch, user: User, group_filter: str | None) -> SavedSearchOut:
    out = SavedSearchOut.model_validate(s)
    out.mine = s.owner_id == user.id
    out.editable = svc.can_edit(s, user, group_filter)
    return out


def _tree_fields(node, depth: int = 0) -> list[str]:
    if depth > 20 or not isinstance(node, dict):
        raise HTTPException(422, "filter_tree: too deep or not an object")
    if "children" in node:
        return [f for c in node.get("children") or [] for f in _tree_fields(c, depth + 1)]
    return [str(node.get("field", ""))]


def _check_tree(tree: dict | None) -> None:
    """The builder ignores conditions on fields it does not allow; a saved
    search must not silently keep a condition that never applies."""
    if not tree:
        return
    bad = sorted({f for f in _tree_fields(tree) if not _field_allowed(f)})
    if bad:
        raise HTTPException(422, f"filter_tree: these fields cannot be searched: {', '.join(bad)}")
    try:
        tree_to_query(tree)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 — a malformed tree is the caller's mistake
        raise HTTPException(422, f"filter_tree: {exc}") from None


async def load_visible(db: AsyncSession, search_id: UUID, user: User, group_filter: str | None) -> SavedSearch:
    s = await db.get(SavedSearch, search_id)
    if s is None or not svc.visible(s, user, group_filter):
        raise HTTPException(404, "Saved search not found")
    return s


@router.get("", response_model=list[SavedSearchOut])
async def list_saved(
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(Read)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
    kind: Optional[Literal["logs", "events"]] = None,
):
    q = select(SavedSearch)
    if group_filter is not None:
        q = q.where(or_(SavedSearch.owner_id == user.id,
                        (SavedSearch.shared.is_(True)) & (SavedSearch.group_id == group_filter)))
    if kind:
        q = q.where(SavedSearch.kind == kind)
    rows = (await db.execute(q.order_by(SavedSearch.name))).scalars().all()
    return [_out(s, user, group_filter) for s in rows]


@router.post("", response_model=SavedSearchOut, status_code=201)
async def create_saved(
    body: SavedSearchIn,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(Read)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    _check_tree(body.filter_tree)
    s = SavedSearch(**body.model_dump(), owner_id=user.id, group_id=group_filter or user.group_id or "default")
    s.name = s.name.strip()
    db.add(s)
    await db.commit()
    await db.refresh(s)
    return _out(s, user, group_filter)


@router.put("/{search_id}", response_model=SavedSearchOut)
async def update_saved(
    search_id: UUID,
    body: SavedSearchIn,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(Read)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    s = await load_visible(db, search_id, user, group_filter)
    if not svc.can_edit(s, user, group_filter):
        raise HTTPException(403, "Only the owner or a group admin can change this search")
    _check_tree(body.filter_tree)
    for k, v in body.model_dump().items():
        setattr(s, k, v.strip() if k == "name" else v)
    await db.commit()
    await db.refresh(s)
    return _out(s, user, group_filter)


@router.delete("/{search_id}", status_code=204)
async def delete_saved(
    search_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(Read)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    s = await load_visible(db, search_id, user, group_filter)
    if not svc.can_edit(s, user, group_filter):
        raise HTTPException(403, "Only the owner or a group admin can delete this search")
    await db.delete(s)
    await db.commit()


@router.get("/{search_id}/run")
async def run_saved(
    search_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(Read)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
    viz: svc.Viz = "count",
    hours: int = Query(24, ge=1, le=svc.MAX_HOURS),
    field: str = "log_type",
    limit: int = Query(10, ge=1, le=50),
    tz: Optional[str] = Query(None, max_length=64),
):
    s = await load_visible(db, search_id, user, group_filter)
    try:
        out = await svc.run(s, group_filter, viz, hours, field, limit, tz)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    return {"search": {"id": str(s.id), "name": s.name, "kind": s.kind}, **out}
