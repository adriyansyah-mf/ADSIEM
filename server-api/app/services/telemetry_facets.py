"""Histogram and top values for a log/event search (the Search page's chart and field sidebar).

Both are computed by Elasticsearch in one aggregation request, so the page never pulls hits
into Python to count them.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from app.core.es_client import aggregate

# ~48 bars across the window, rounded to an interval Elasticsearch accepts.
_INTERVALS = [
    (timedelta(minutes=1), "1m"), (timedelta(minutes=5), "5m"), (timedelta(minutes=10), "10m"),
    (timedelta(minutes=30), "30m"), (timedelta(hours=1), "1h"), (timedelta(hours=3), "3h"),
    (timedelta(hours=6), "6h"), (timedelta(hours=12), "12h"), (timedelta(days=1), "1d"),
]


def time_filter(since: datetime | None, until: datetime | None) -> dict | None:
    if not since and not until:
        return None
    bounds: dict = {}
    if since:
        bounds["gte"] = since.isoformat()
    if until:
        bounds["lte"] = until.isoformat()
    return {"range": {"created_at": bounds}}


def _interval(since: datetime, until: datetime) -> str:
    span = (until - since) / 48
    for step, name in _INTERVALS:
        if span <= step:
            return name
    return "1d"


async def facets(filters: list[dict], fields: list[str], since: datetime | None, until: datetime | None,
                 top: int = 5) -> dict:
    now = datetime.now(timezone.utc)
    end = until or now
    start = since or (end - timedelta(hours=24))
    window = [*filters]
    if not any("range" in f and "created_at" in f["range"] for f in window):
        window.append({"range": {"created_at": {"gte": start.isoformat(), "lte": end.isoformat()}}})
    aggs: dict = {
        "histogram": {"date_histogram": {
            "field": "created_at", "fixed_interval": _interval(start, end), "min_doc_count": 0,
            "extended_bounds": {"min": start.isoformat(), "max": end.isoformat()},
        }},
    }
    for field in fields:
        aggs[f"top:{field}"] = {"terms": {"field": field, "size": top}}
    began = time.perf_counter()
    result = await aggregate({"bool": {"filter": window}}, aggs)
    took_ms = round((time.perf_counter() - began) * 1000)
    data = result["aggregations"]
    return {
        "total": result["total"],
        "took_ms": took_ms,
        "since": start.isoformat(),
        "until": end.isoformat(),
        "histogram": [
            {"t": bucket.get("key_as_string") or bucket["key"], "count": bucket["doc_count"]}
            for bucket in data.get("histogram", {}).get("buckets", [])
        ],
        "facets": [
            {"field": field, "values": [
                {"value": str(bucket["key"]), "count": bucket["doc_count"]}
                for bucket in data.get(f"top:{field}", {}).get("buckets", [])
            ]}
            for field in fields
        ],
    }
