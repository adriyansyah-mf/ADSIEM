# server-api/app/api/routes/investigation.py
"""Saved queries and bookmarks: lightweight per-analyst (or tenant-shared)
pointers into the investigation surface -- a saved log/alert/hunt filter, or
a bookmark on an alert/case/indicator worth coming back to."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group
from app.models.models import Bookmark, SavedQuery, User

router = APIRouter(tags=["investigation"])

QUERY_TYPES = ("logs", "alerts", "events", "hunt")
BOOKMARK_ENTITY_TYPES = ("alert", "case", "ip", "hostname", "indicator")


class SavedQueryCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    query_type: str
    query_params: dict = Field(default_factory=dict)
    is_shared: bool = False


class BookmarkCreate(BaseModel):
    entity_type: str
    entity_id: str = Field(min_length=1, max_length=255)
    note: str | None = None
    is_shared: bool = False


def _saved_query_out(q: SavedQuery) -> dict:
    return {
        "id": str(q.id),
        "owner_id": str(q.owner_id),
        "name": q.name,
        "query_type": q.query_type,
        "query_params": q.query_params,
        "is_shared": q.is_shared,
        "created_at": q.created_at.isoformat() if q.created_at else None,
    }


def _bookmark_out(b: Bookmark) -> dict:
    return {
        "id": str(b.id),
        "owner_id": str(b.owner_id),
        "entity_type": b.entity_type,
        "entity_id": b.entity_id,
        "note": b.note,
        "is_shared": b.is_shared,
        "created_at": b.created_at.isoformat() if b.created_at else None,
    }


@router.get("/api/saved-queries")
async def list_saved_queries(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    """A caller's own saved queries, plus any other tenant member's queries
    marked shared. A superadmin (no group filter) sees only their own."""
    q = select(SavedQuery)
    if group_filter is not None:
        q = q.where(
            SavedQuery.group_id == group_filter,
            or_(SavedQuery.owner_id == current_user.id, SavedQuery.is_shared.is_(True)),
        )
    else:
        q = q.where(SavedQuery.owner_id == current_user.id)
    rows = (await db.execute(q.order_by(SavedQuery.created_at.desc()))).scalars().all()
    return [_saved_query_out(r) for r in rows]


@router.post("/api/saved-queries", status_code=201)
async def create_saved_query(
    body: SavedQueryCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    if body.query_type not in QUERY_TYPES:
        raise HTTPException(status_code=422, detail=f"query_type must be one of {QUERY_TYPES}")
    query = SavedQuery(
        group_id=group_filter or current_user.group_id or "default",
        owner_id=current_user.id,
        name=body.name,
        query_type=body.query_type,
        query_params=body.query_params,
        is_shared=body.is_shared,
    )
    db.add(query)
    await db.commit()
    await db.refresh(query)
    return _saved_query_out(query)


@router.delete("/api/saved-queries/{query_id}", status_code=204)
async def delete_saved_query(
    query_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Only the owner may delete their own saved query -- sharing a query
    makes it visible to the tenant, not editable by the tenant."""
    query = (
        await db.execute(select(SavedQuery).where(SavedQuery.id == query_id))
    ).scalar_one_or_none()
    if query is None or str(query.owner_id) != str(current_user.id):
        raise HTTPException(status_code=404, detail="Saved query not found")
    await db.delete(query)
    await db.commit()


@router.get("/api/bookmarks")
async def list_bookmarks(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
    entity_type: str | None = None,
):
    q = select(Bookmark)
    if group_filter is not None:
        q = q.where(
            Bookmark.group_id == group_filter,
            or_(Bookmark.owner_id == current_user.id, Bookmark.is_shared.is_(True)),
        )
    else:
        q = q.where(Bookmark.owner_id == current_user.id)
    if entity_type:
        q = q.where(Bookmark.entity_type == entity_type)
    rows = (await db.execute(q.order_by(Bookmark.created_at.desc()))).scalars().all()
    return [_bookmark_out(r) for r in rows]


@router.post("/api/bookmarks", status_code=201)
async def create_bookmark(
    body: BookmarkCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    if body.entity_type not in BOOKMARK_ENTITY_TYPES:
        raise HTTPException(status_code=422, detail=f"entity_type must be one of {BOOKMARK_ENTITY_TYPES}")
    existing = (
        await db.execute(
            select(Bookmark).where(
                Bookmark.owner_id == current_user.id,
                Bookmark.entity_type == body.entity_type,
                Bookmark.entity_id == body.entity_id,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        existing.note = body.note
        existing.is_shared = body.is_shared
        await db.commit()
        await db.refresh(existing)
        return _bookmark_out(existing)
    bookmark = Bookmark(
        group_id=group_filter or current_user.group_id or "default",
        owner_id=current_user.id,
        entity_type=body.entity_type,
        entity_id=body.entity_id,
        note=body.note,
        is_shared=body.is_shared,
    )
    db.add(bookmark)
    await db.commit()
    await db.refresh(bookmark)
    return _bookmark_out(bookmark)


@router.delete("/api/bookmarks/{bookmark_id}", status_code=204)
async def delete_bookmark(
    bookmark_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    bookmark = (
        await db.execute(select(Bookmark).where(Bookmark.id == bookmark_id))
    ).scalar_one_or_none()
    if bookmark is None or str(bookmark.owner_id) != str(current_user.id):
        raise HTTPException(status_code=404, detail="Bookmark not found")
    await db.delete(bookmark)
    await db.commit()
