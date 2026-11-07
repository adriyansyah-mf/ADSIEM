# server-api/app/api/routes/iocs.py
"""Threat IoCs: attacker indicators recorded in alerts (Elasticsearch index
alert_iocs, written by worker/worker/alert_iocs.py), aggregated per indicator.
Every query carries the caller's group filter."""
import re
from datetime import datetime
from typing import Literal, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import es_client
from app.core.database import get_db
from app.core.deps import get_scoped_group, require_permission
from app.models.models import Alert

router = APIRouter(prefix="/api/iocs", tags=["iocs"])

IocType = Literal["ip", "domain", "url", "sha256", "sha1", "md5", "email"]
SEVERITY_NAMES = ["info", "low", "medium", "high", "critical"]
MAX_BUCKETS = 1000
MAX_DRILL_ALERTS = 200


def _wildcard(q: str) -> str:
    return "*" + re.sub(r"([\\*?])", r"\\\1", q.strip().lower()) + "*"


def _filters(group: Optional[str], q: str, since: Optional[datetime], until: Optional[datetime]) -> list[dict]:
    filters: list[dict] = []
    if group is not None:
        filters.append({"term": {"group_id": group}})
    if q.strip():
        filters.append({"wildcard": {"value": {"value": _wildcard(q), "case_insensitive": True}}})
    window = {k: v.isoformat() for k, v in (("gte", since), ("lte", until)) if v}
    if window:
        filters.append({"range": {"created_at": window}})
    return filters


def _value_of(agg: dict) -> Optional[str]:
    return (agg or {}).get("value_as_string")  # absent when the bucket has no value


@router.get("")
async def list_iocs(
    type: Optional[IocType] = None,
    q: str = Query("", max_length=200),
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    sort: Literal["last_seen", "alerts"] = "last_seen",
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0, le=MAX_BUCKETS - 1),
    _=Depends(require_permission("alerts:read")),
    group: Optional[str] = Depends(get_scoped_group),
):
    body = {
        "size": 0,
        "query": {"bool": {"filter": _filters(group, q, since, until)}},
        "aggs": {
            "types": {"terms": {"field": "type", "size": 10}},
            "matched": {
                "filter": {"term": {"type": type}} if type else {"match_all": {}},
                "aggs": {
                    "count": {"cardinality": {"field": "ioc_key"}},
                    "iocs": {
                        "terms": {"field": "ioc_key", "size": MAX_BUCKETS, "order": {sort: "desc"}},
                        "aggs": {
                            "alerts": {"cardinality": {"field": "alert_id"}},
                            "hosts": {"cardinality": {"field": "hostname"}},
                            "first_seen": {"min": {"field": "created_at"}},
                            "last_seen": {"max": {"field": "created_at"}},
                            "max_severity": {"max": {"field": "severity_rank"}},
                            "page": {"bucket_sort": {"from": offset, "size": limit}},
                        },
                    },
                },
            },
        },
    }
    aggs = (await es_client.search_iocs(body)).get("aggregations") or {}
    matched = aggs.get("matched") or {}
    items = []
    for bucket in (matched.get("iocs") or {}).get("buckets", []):
        kind, _, value = bucket["key"].partition(":")
        rank = (bucket.get("max_severity") or {}).get("value")
        items.append({
            "type": kind, "value": value,
            "alerts": int(bucket["alerts"]["value"]), "hosts": int(bucket["hosts"]["value"]),
            "first_seen": _value_of(bucket.get("first_seen")), "last_seen": _value_of(bucket.get("last_seen")),
            "max_severity": SEVERITY_NAMES[int(rank)] if rank is not None and 0 <= int(rank) < 5 else None,
            "blocked": None,  # Web Protection (stage B1) fills this
        })
    return {
        "total": min(int((matched.get("count") or {}).get("value", 0)), MAX_BUCKETS),
        "type_counts": {b["key"]: b["doc_count"] for b in (aggs.get("types") or {}).get("buckets", [])},
        "items": items,
    }


@router.get("/alerts")
async def ioc_alerts(
    type: IocType,
    value: str = Query(..., min_length=1, max_length=4096),
    limit: int = Query(50, ge=1, le=MAX_DRILL_ALERTS),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _=Depends(require_permission("alerts:read")),
    group: Optional[str] = Depends(get_scoped_group),
):
    filters = [{"term": {"type": type}}, {"term": {"value": value}}]
    if group is not None:
        filters.append({"term": {"group_id": group}})
    result = await es_client.search_iocs({
        "size": 0, "query": {"bool": {"filter": filters}},
        "aggs": {"ids": {"terms": {"field": "alert_id", "size": MAX_DRILL_ALERTS, "order": {"latest": "desc"}},
                         "aggs": {"latest": {"max": {"field": "created_at"}}}}},
    })
    ids = []
    for bucket in ((result.get("aggregations") or {}).get("ids") or {}).get("buckets", []):
        try:
            ids.append(UUID(bucket["key"]))
        except ValueError:
            continue
    if not ids:
        return {"total": 0, "items": []}
    query = select(Alert).where(Alert.id.in_(ids))
    if group is not None:  # Postgres is the authority: never trust the index for scoping alone
        query = query.where(Alert.group_id == group)
    alerts = (await db.execute(query.order_by(Alert.created_at.desc()))).scalars().all()
    return {"total": len(alerts), "items": [{
        "id": str(a.id), "title": a.title, "severity": a.severity, "status": a.status, "hostname": a.hostname,
        "created_at": a.created_at.isoformat() if a.created_at else None, "ai_verdict": a.ai_verdict,
    } for a in alerts[offset:offset + limit]]}
