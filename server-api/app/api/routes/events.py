# server-api/app/api/routes/events.py
import json
from typing import Annotated
from fastapi import APIRouter, Depends

from app.core.deps import get_scoped_group, require_permission
from app.core.es_client import search as es_search
from app.core.query_builder import tree_to_query
from app.schemas.schemas import EventOut, PaginatedResponse

router = APIRouter(prefix="/api/events", tags=["events"])
Perm = require_permission("logs:read")

@router.get("", response_model=PaginatedResponse)
async def list_events(
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(Perm),
    page_size: int = 25,
    after: str | None = None,
    search: str | None = None,
    source_ip: str | None = None, event_action: str | None = None,
    filter_tree: str | None = None,
):
    filters: list[dict] = []
    if group_filter:
        filters.append({"term": {"group_id": group_filter}})
    if source_ip:
        filters.append({"term": {"source_ip": source_ip}})
    if event_action:
        filters.append({"term": {"event_action": event_action}})
    if search:
        filters.append({"query_string": {"query": search, "default_field": "decoded_fields.*"}})
    if filter_tree:
        q = tree_to_query(json.loads(filter_tree))
        if q:
            filters.append(q)
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
