"""Saved searches and the widgets built on them (routes/saved_searches.py,
routes/dashboards.py).

A saved search is what the Log search or Events page had in its box (Lucene)
and visual builder. Running it always applies the *caller's* group, never the
owner's, so a search shared into a group cannot reach past it."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from app.core import es_client
from app.core.query_builder import text_search, tree_to_query

# count: a number; trend: the number against the window before it; unique:
# distinct values of a field; timeline / split: events over time (split: one
# series per top value of a field); top / donut / datatable / tagcloud / rare:
# the most (rare: the least) frequent values of a field; heatmap: weekday x
# hour; table: latest rows
Viz = Literal["count", "trend", "unique", "timeline", "split", "top", "donut", "datatable", "tagcloud",
              "rare", "heatmap", "table"]
TERMS_VIZ = {"top", "donut", "datatable", "tagcloud", "rare"}
FIELD_VIZ = TERMS_VIZ | {"unique", "split"}
MAX_FILTERS = 20
MAX_HOURS = 24 * 30
TABLE_ROWS = 20
DEFAULT_FIELD = {"logs": "raw_message", "events": "decoded_fields.*"}

# fields a widget may group by: the index's keyword fields, and the decoded
# fields the decoders fill (dynamic strings, aggregated on their .keyword)
TOP_FIELDS = ("log_type", "event_action", "event_category", "source_ip", "user_name", "agent_id")
DECODED_FIELDS = (
    "host.name", "source.ip", "destination.ip", "user.name", "process.name",
    "process.executable", "process.parent.name", "file.path", "url.domain", "dns.question.name",
    "http.request.method", "user_agent.original", "network.protocol",
    "event.outcome", "rule.name", "threat.indicator.ip", "device.vendor_id", "device.model.name",
)
GROUP_FIELDS = TOP_FIELDS + DECODED_FIELDS


def es_field(field: str) -> str:
    if field in TOP_FIELDS:
        return field
    if field in DECODED_FIELDS:
        return f"decoded_fields.{field}.keyword"
    raise ValueError(f"field must be one of {', '.join(GROUP_FIELDS)}")


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


def pin_clauses(pins: list[dict] | None) -> tuple[list[dict], list[dict]]:
    """Dashboard filter pills ({field, value, negate}) as (filter, must_not)."""
    keep: list[dict] = []
    drop: list[dict] = []
    for p in (pins or [])[:MAX_FILTERS]:
        clause = {"term": {es_field(str(p.get("field", ""))): str(p.get("value", ""))[:512]}}
        (drop if p.get("negate") else keep).append(clause)
    return keep, drop


def build_query(kind: str, query: str, filter_tree: dict | None, log_type: str | None,
                group_filter: str | None, hours: int | None, until_hours_ago: int = 0,
                extra_query: str = "", pins: list[dict] | None = None) -> dict:
    """until_hours_ago shifts the window back (trend: the window before);
    extra_query and pins are the dashboard's query bar and filter pills,
    ANDed onto the search."""
    filters: list[dict] = []
    if hours:
        now = datetime.now(timezone.utc)
        rng = {"gte": (now - timedelta(hours=hours + until_hours_ago)).isoformat()}
        if until_hours_ago:
            rng["lt"] = (now - timedelta(hours=until_hours_ago)).isoformat()
        filters.append({"range": {"created_at": rng}})
    if group_filter is not None:
        filters.append({"term": {"group_id": group_filter}})
    if log_type:
        filters.append({"term": {"log_type": log_type}})
    if query and query.strip():
        filters.append(text_search(query, DEFAULT_FIELD.get(kind, "raw_message")))
    tree = tree_to_query(filter_tree) if filter_tree else None
    if tree:
        filters.append(tree)
    if extra_query and extra_query.strip():
        filters.append(text_search(extra_query, DEFAULT_FIELD.get(kind, "raw_message")))
    keep, drop = pin_clauses(pins)
    filters.extend(keep)
    if not filters and not drop:
        return {"match_all": {}}
    out: dict = {"filter": filters}
    if drop:
        out["must_not"] = drop
    return {"bool": out}


def _tz(name: str | None) -> ZoneInfo:
    try:
        return ZoneInfo(name or "UTC")
    except (ZoneInfoNotFoundError, ValueError):
        return ZoneInfo("UTC")


async def run(search, group_filter: str | None, viz: Viz, hours: int, field: str = "log_type",
              limit: int = 10, tz: str | None = None, extra_query: str = "",
              pins: list[dict] | None = None) -> dict:
    """search is a SavedSearch, or anything with kind / query / filter_tree /
    log_type (a dashboard widget's own query)."""
    hours = max(1, min(MAX_HOURS, hours))
    limit = max(1, min(50, limit))
    args = (search.kind, search.query or "", search.filter_tree, search.log_type, group_filter)
    extra = {"extra_query": extra_query, "pins": pins}
    q = build_query(*args, hours, **extra)
    if viz in FIELD_VIZ:
        es = es_field(field)
    if viz == "count":
        result = await es_client.aggregate(q, {})
        return {"viz": viz, "hours": hours, "total": result["total"]}
    if viz == "trend":
        now = await es_client.aggregate(q, {})
        before = await es_client.aggregate(build_query(*args, hours, until_hours_ago=hours, **extra), {})
        prev = before["total"]
        change = None if prev == 0 else round((now["total"] - prev) / prev * 100, 1)
        return {"viz": viz, "hours": hours, "total": now["total"], "previous": prev, "change_pct": change}
    if viz == "unique":
        result = await es_client.aggregate(q, {"u": {"cardinality": {"field": es}}})
        return {"viz": viz, "hours": hours, "field": field, "total": result["total"],
                "unique": int(result["aggregations"].get("u", {}).get("value", 0))}
    if viz in ("timeline", "split"):
        interval = interval_for(hours)
        hist = {"date_histogram": {"field": "created_at", "fixed_interval": interval, "min_doc_count": 0,
                                   "extended_bounds": {"min": f"now-{hours}h", "max": "now"}}}
        if viz == "split":
            hist["aggs"] = {"s": {"terms": {"field": es, "size": min(limit, 8)}}}
        result = await es_client.aggregate(q, {"t": hist})
        buckets = result["aggregations"].get("t", {}).get("buckets", [])
        points = []
        for b in buckets:
            p = {"t": b.get("key_as_string") or b["key"], "count": b["doc_count"]}
            if viz == "split":
                p["series"] = {str(s["key"]): s["doc_count"] for s in b.get("s", {}).get("buckets", [])}
            points.append(p)
        out = {"viz": viz, "hours": hours, "interval": interval, "total": result["total"], "points": points}
        if viz == "split":
            totals: dict[str, int] = {}
            for p in points:
                for k, v in p["series"].items():
                    totals[k] = totals.get(k, 0) + v
            out["field"] = field
            out["keys"] = [k for k, _ in sorted(totals.items(), key=lambda kv: -kv[1])][:min(limit, 8)]
        return out
    if viz in TERMS_VIZ:
        terms = {"field": es, "size": limit}
        if viz == "rare":
            terms["order"] = {"_count": "asc"}
        result = await es_client.aggregate(q, {"top": {"terms": terms}})
        buckets = result["aggregations"].get("top", {}).get("buckets", [])
        other = result["aggregations"].get("top", {}).get("sum_other_doc_count", 0)
        return {"viz": viz, "hours": hours, "field": field, "total": result["total"], "other": other,
                "values": [{"value": str(b["key"]), "count": b["doc_count"]} for b in buckets]}
    if viz == "heatmap":
        zone = _tz(tz)
        result = await es_client.aggregate(q, {"h": {"date_histogram": {
            "field": "created_at", "fixed_interval": "1h", "min_doc_count": 1}}})
        grid = [[0] * 24 for _ in range(7)]  # Monday first
        for b in result["aggregations"].get("h", {}).get("buckets", []):
            at = datetime.fromtimestamp(b["key"] / 1000, tz=timezone.utc).astimezone(zone)
            grid[at.weekday()][at.hour] += b["doc_count"]
        return {"viz": viz, "hours": hours, "total": result["total"], "tz": str(zone), "grid": grid}
    hits, total, _ = await es_client.search(q, size=min(TABLE_ROWS, limit), sort=[{"created_at": "desc"}])
    return {"viz": "table", "hours": hours, "total": total, "rows": [
        {"id": h["id"], "created_at": h.get("created_at"), "log_type": h.get("log_type"),
         "hostname": h.get("hostname") or (h.get("decoded_fields") or {}).get("host.name"),
         "event_action": h.get("event_action"), "message": str(h.get("raw_message") or "")[:400]}
        for h in hits]}
