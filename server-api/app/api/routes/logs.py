# server-api/app/api/routes/logs.py
import json
from typing import Annotated

from fastapi import APIRouter, Depends

from app.core.deps import require_permission, get_scoped_group
from app.core.es_client import search as es_search
from app.core.query_builder import text_search, tree_to_query
from app.schemas.schemas import PaginatedResponse, RawLogOut

router = APIRouter(prefix="/api/logs", tags=["logs"])
Perm = require_permission("logs:read")

@router.get("", response_model=PaginatedResponse)
async def list_logs(
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(Perm),
    page_size: int = 25,
    after: str | None = None,
    log_type: str | None = None, search: str | None = None,
    filter_tree: str | None = None,
):
    filters: list[dict] = []
    if group_filter is not None:
        filters.append({"term": {"group_id": group_filter}})
    if log_type:
        filters.append({"term": {"log_type": log_type}})
    if search:
        # query_string gives the box real Lucene syntax (field:value, wildcards,
        # AND/OR/NOT, ranges, ...) — bare terms fall back to raw_message.
        filters.append(text_search(search, "raw_message"))
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
        RawLogOut(
            id=h["id"],
            agent_id=h.get("agent_id"),
            log_type=h.get("log_type"),
            raw_message=h.get("raw_message", ""),
            received_at=h["created_at"],
        )
        for h in hits
    ]
    return PaginatedResponse(
        total=total, page=1, page_size=page_size, items=items,
        next_after=json.dumps(next_cursor) if next_cursor else None,
    )
