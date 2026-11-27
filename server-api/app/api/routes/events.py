# server-api/app/api/routes/events.py
import json
from datetime import datetime
from typing import Annotated
from fastapi import APIRouter, Depends

from app.services.telemetry_facets import facets as telemetry_facets, time_filter

from app.core.deps import get_scoped_group, require_permission
from app.core.es_client import search as es_search
from app.core.query_builder import text_search, tree_to_query
from app.schemas.schemas import EventOut, PaginatedResponse

router = APIRouter(prefix="/api/events", tags=["events"])
Perm = require_permission("logs:read")

FACET_FIELDS = ["event_action", "event_category", "user_name", "source_ip"]


def _filters(group_filter: str | None, source_ip: str | None, event_action: str | None,
             search: str | None, filter_tree: str | None) -> list[dict]:
    filters: list[dict] = []
    if group_filter:
        filters.append({"term": {"group_id": group_filter}})
    if source_ip:
        filters.append({"term": {"source_ip": source_ip}})
    if event_action:
        filters.append({"term": {"event_action": event_action}})
    if search:
        filters.append(text_search(search, "decoded_fields.*"))
    if filter_tree:
        q = tree_to_query(json.loads(filter_tree))
        if q:
            filters.append(q)
    return filters


@router.get("/facets")
async def event_facets(
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(Perm),
    search: str | None = None,
    source_ip: str | None = None, event_action: str | None = None,
    filter_tree: str | None = None,
    since: datetime | None = None, until: datetime | None = None,
):
    """Count histogram and top values for the same query as the list (default window: 24 h)."""
    filters = _filters(group_filter, source_ip, event_action, search, filter_tree)
    window = time_filter(since, until)
    return await telemetry_facets(filters + ([window] if window else []), FACET_FIELDS, since, until)

@router.get("", response_model=PaginatedResponse)
async def list_events(
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(Perm),
    page_size: int = 25,
    after: str | None = None,
    search: str | None = None,
    source_ip: str | None = None, event_action: str | None = None,
    filter_tree: str | None = None,
    since: datetime | None = None, until: datetime | None = None,
):
    filters = _filters(group_filter, source_ip, event_action, search, filter_tree)
    window = time_filter(since, until)
    if window:
        filters.append(window)
    query = {"bool": {"filter": filters}} if filters else {"match_all": {}}

    search_after = json.loads(after) if after else None
    hits, total, next_cursor = await es_search(
        query,
        size=page_size,
        sort=[{"created_at": "desc"}],
        search_after=search_after,
    )
    items = [
        EventOut(
            id=h["id"],
            agent_id=h.get("agent_id"),
            group_id=h.get("group_id", "default"),
            decoded_fields=h.get("decoded_fields") or {},
            event_category=h.get("event_category"),
            event_action=h.get("event_action"),
            source_ip=h.get("source_ip"),
            user_name=h.get("user_name"),
            created_at=h["created_at"],
        )
        for h in hits
    ]
    return PaginatedResponse(
        total=total, page=1, page_size=page_size, items=items,
        next_after=json.dumps(next_cursor) if next_cursor else None,
    )
