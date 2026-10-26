# server-api/app/api/routes/elastic.py
"""Elasticsearch-backed analytics for the dashboard and the assistant tools.

Charts are computed with ES aggregations rather than by fetching hits, so the
cost stays flat as log volume grows. Every query is group-scoped exactly like
/api/events.
"""
import json
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group, require_permission
from app.core.es_client import aggregate, index_stats
from app.core.query_builder import text_search
from app.models.models import User

router = APIRouter(prefix="/api/elastic", tags=["elastic"])
Perm = get_current_user

ALLOWED_TERM_FIELDS = {
    "log_type": "log_type",
    "event_action": "event_action",
    "event_category": "event_category",
    "source_ip": "source_ip",
    "user_name": "user_name",
    "agent_id": "agent_id",
}

ALLOWED_DATE_FIELDS = {"created_at"}


def _base_filters(
    group_filter: str | None,
    hours: int,
    search: str | None = None,
    term_field: str | None = None,
    term_value: str | None = None,
) -> list[dict]:
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    filters: list[dict] = [{"range": {"created_at": {"gte": since}}}]
    if group_filter:
        filters.append({"term": {"group_id": group_filter}})
    if search:
        filters.append(text_search(search, "decoded_fields.*"))
    if term_field and term_value:
        field = ALLOWED_TERM_FIELDS.get(term_field)
        if field:
            filters.append({"term": {field: term_value}})
    return filters


def _wrap(filters: list[dict]) -> dict:
    return {"bool": {"filter": filters}} if filters else {"match_all": {}}


@router.get("/stats")
async def elastic_stats(
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(Perm),
):
    return await index_stats()


@router.get("/volume")
async def elastic_volume(
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(Perm),
    hours: int = Query(default=24, le=720),
    interval: str = Query(default="5m", pattern="^(1m|5m|15m|1h|1d)$"),
):
    """Events per interval bucket, split by log_type for a stacked view."""
    filters = _base_filters(group_filter, hours)
    result = await aggregate(
        _wrap(filters),
        {
            "by_time": {
                "date_histogram": {"field": "created_at", "fixed_interval": interval},
                "aggs": {"by_type": {"terms": {"field": "log_type", "size": 8}}},
            }
        },
    )
    buckets = result["aggregations"].get("by_time", {}).get("buckets", [])
    points = []
    for b in buckets:
        types = {t["key"]: t["doc_count"] for t in b.get("by_type", {}).get("buckets", [])}
        points.append({"t": b["key_as_string"], "total": b["doc_count"], "types": types})
    return {"hours": hours, "interval": interval, "total": result["total"], "points": points}


@router.get("/top")
async def elastic_top(
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(Perm),
    field: str = Query(default="source_ip"),
    hours: int = Query(default=24, le=720),
    limit: int = Query(default=10, le=50),
):
    """Top values for an allow-listed field (source_ip, log_type, event_action...)."""
    mapped = ALLOWED_TERM_FIELDS.get(field)
    if not mapped:
        return {"field": field, "values": [], "error": "field not allowed"}

    filters = _base_filters(group_filter, hours)
    result = await aggregate(
        _wrap(filters),
        {"top": {"terms": {"field": mapped, "size": limit}}},
    )
    buckets = result["aggregations"].get("top", {}).get("buckets", [])
    return {
        "field": field,
        "hours": hours,
        "values": [{"value": b["key"], "count": b["doc_count"]} for b in buckets],
    }


@router.get("/security-signals")
async def elastic_security_signals(
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(Perm),
    hours: int = Query(default=24, le=720),
    interval: str = Query(default="1h", pattern="^(5m|15m|1h|1d)$"),
):
    """Auth failures over time, event_action mix, and unique source IPs."""
    filters = _base_filters(group_filter, hours)
    auth_filters = filters + [{"term": {"event_category": "authentication"}}]

    failures = await aggregate(
        _wrap(auth_filters + [{"term": {"event_action": "login_failed"}}]),
        {
            "by_time": {
                "date_histogram": {"field": "created_at", "fixed_interval": interval}
            }
        },
    )
    actions = await aggregate(
        _wrap(filters),
        {
            "actions": {"terms": {"field": "event_action", "size": 10}},
            "unique_ips": {"cardinality": {"field": "source_ip"}},
        },
    )

    fail_buckets = failures["aggregations"].get("by_time", {}).get("buckets", [])
    agg = actions["aggregations"]
    return {
        "hours": hours,
        "interval": interval,
        "auth_failures": [{"t": b["key_as_string"], "count": b["doc_count"]} for b in fail_buckets],
        "action_mix": [
            {"action": b["key"], "count": b["doc_count"]}
            for b in agg.get("actions", {}).get("buckets", [])
        ],
        "unique_source_ips": agg.get("unique_ips", {}).get("value", 0),
    }


@router.get("/agents-volume")
async def elastic_agents_volume(
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(Perm),
    hours: int = Query(default=6, le=168),
    limit: int = Query(default=8, le=20),
):
    """Per-agent event volume for the sparkline row."""
    filters = _base_filters(group_filter, hours)
    result = await aggregate(
        _wrap(filters),
        {"per_agent": {"terms": {"field": "agent_id", "size": limit}}},
    )
    buckets = result["aggregations"].get("per_agent", {}).get("buckets", [])
    return {
        "hours": hours,
        "agents": [{"agent_id": b["key"], "count": b["doc_count"]} for b in buckets],
    }
