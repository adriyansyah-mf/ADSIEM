"""Saved searches and the widgets built on them (routes/saved_searches.py,
routes/dashboards.py).

A saved search is what the Log search or Events page had in its box (Lucene)
and visual builder. Running it always applies the *caller's* group, never the
owner's, so a search shared into a group cannot reach past it."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Literal

from app.core import es_client
from app.core.query_builder import text_search, tree_to_query

Viz = Literal["count", "timeline", "top", "table"]
MAX_HOURS = 24 * 30
TOP_FIELDS = ("log_type", "event_action", "event_category", "source_ip", "user_name", "agent_id")
TABLE_ROWS = 20
DEFAULT_FIELD = {"logs": "raw_message", "events": "decoded_fields.*"}


def interval_for(hours: int) -> str:
    return "15m" if hours <= 6 else "1h" if hours <= 48 else "6h" if hours <= 14 * 24 else "1d"


def visible(item, user, group_filter: str | None) -> bool:
    """Own, shared in the caller's group, or the caller is superadmin."""
    if group_filter is None:
        return True
    return item.owner_id == user.id or (item.shared and item.group_id == group_filter)


def can_edit(item, user, group_filter: str | None) -> bool:
    """The owner; for a shared one also the group's admins; superadmin always."""
    if group_filter is None or item.owner_id == user.id:
        return True
    return item.shared and item.group_id == group_filter and user.role.name == "admin"


def build_query(kind: str, query: str, filter_tree: dict | None, log_type: str | None,
                group_filter: str | None, hours: int | None) -> dict:
    filters: list[dict] = []
    if hours:
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        filters.append({"range": {"created_at": {"gte": since}}})
    if group_filter is not None:
        filters.append({"term": {"group_id": group_filter}})
    if log_type:
        filters.append({"term": {"log_type": log_type}})
    if query and query.strip():
        filters.append(text_search(query, DEFAULT_FIELD.get(kind, "raw_message")))
    tree = tree_to_query(filter_tree) if filter_tree else None
    if tree:
        filters.append(tree)
    return {"bool": {"filter": filters}} if filters else {"match_all": {}}


async def run(search, group_filter: str | None, viz: Viz, hours: int, field: str = "log_type",
              limit: int = 10) -> dict:
    hours = max(1, min(MAX_HOURS, hours))
    q = build_query(search.kind, search.query or "", search.filter_tree, search.log_type, group_filter, hours)
    if viz == "count":
        result = await es_client.aggregate(q, {})
        return {"viz": viz, "hours": hours, "total": result["total"]}
    if viz == "timeline":
        interval = interval_for(hours)
        result = await es_client.aggregate(q, {"t": {"date_histogram": {
            "field": "created_at", "fixed_interval": interval, "min_doc_count": 0,
            "extended_bounds": {"min": f"now-{hours}h", "max": "now"}}}})
        buckets = result["aggregations"].get("t", {}).get("buckets", [])
        return {"viz": viz, "hours": hours, "interval": interval, "total": result["total"],
                "points": [{"t": b.get("key_as_string") or b["key"], "count": b["doc_count"]} for b in buckets]}
    if viz == "top":
        if field not in TOP_FIELDS:
            raise ValueError(f"field must be one of {', '.join(TOP_FIELDS)}")
        result = await es_client.aggregate(q, {"top": {"terms": {"field": field, "size": max(1, min(50, limit))}}})
        buckets = result["aggregations"].get("top", {}).get("buckets", [])
        return {"viz": viz, "hours": hours, "field": field, "total": result["total"],
                "values": [{"value": b["key"], "count": b["doc_count"]} for b in buckets]}
    hits, total, _ = await es_client.search(q, size=max(1, min(TABLE_ROWS, limit)), sort=[{"created_at": "desc"}])
    return {"viz": "table", "hours": hours, "total": total, "rows": [
        {"id": h["id"], "created_at": h.get("created_at"), "log_type": h.get("log_type"),
         "hostname": h.get("hostname") or (h.get("decoded_fields") or {}).get("host.name"),
         "event_action": h.get("event_action"), "message": str(h.get("raw_message") or "")[:400]}
        for h in hits]}
