# server-api/app/core/es_client.py
"""Thin Elasticsearch REST client for the `logs` index (raw_logs + events,
merged into one document per ingested line — see worker/worker/es_client.py
for the mapping this mirrors)."""
import httpx
from app.core.config import settings

LOGS_INDEX = "logs"

_MAPPING = {
    "mappings": {
        "properties": {
            "agent_id":       {"type": "keyword"},
            "group_id":       {"type": "keyword"},
            "log_type":       {"type": "keyword"},
            "raw_message":    {"type": "text"},
            "decoded_fields": {"type": "object", "dynamic": True},
            "event_category": {"type": "keyword"},
            "event_action":   {"type": "keyword"},
            "source_ip":      {"type": "keyword"},
            "user_name":      {"type": "keyword"},
            "created_at":     {"type": "date"},
        }
    }
}

_client: httpx.AsyncClient | None = None


def _get_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(base_url=settings.ELASTICSEARCH_URL, timeout=15)
    return _client


async def ensure_index() -> None:
    client = _get_client()
    resp = await client.head(f"/{LOGS_INDEX}")
    if resp.status_code == 200:
        return
    await client.put(f"/{LOGS_INDEX}", json=_MAPPING)


async def count_by_query(query: dict) -> int:
    client = _get_client()
    resp = await client.post(f"/{LOGS_INDEX}/_count", json={"query": query})
    resp.raise_for_status()
    return resp.json()["count"]


async def get_log(doc_id: str) -> dict | None:
    client = _get_client()
    resp = await client.get(f"/{LOGS_INDEX}/_doc/{doc_id}")
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    src = resp.json()["_source"]
    return {"id": doc_id, **src}


async def search(
    query: dict,
    size: int = 25,
    sort: list | None = None,
    search_after: list | None = None,
) -> tuple[list[dict], int, list | None]:
    """Returns (hits as [{id, **_source}], total_count, next_search_after_cursor).

    Uses search_after instead of from/size — Elasticsearch hard-rejects from+size
    past its default 10,000-result window, which a few hundred pages of real log
    volume (millions of docs) reaches almost immediately. search_after has no such
    depth limit. A tiebreaker (_seq_no — unique per doc, doc-values enabled by
    default, unlike _id which ES refuses to sort on without fielddata) is appended
    so the cursor is stable even when many docs share the same sort value (e.g.
    created_at, which easily collides across docs during bursty ingestion).
    """
    client = _get_client()
    effective_sort = (sort or [{"created_at": "desc"}]) + [{"_seq_no": "asc"}]
    body: dict = {"query": query, "size": size, "sort": effective_sort, "track_total_hits": True}
    if search_after:
        body["search_after"] = search_after
    resp = await client.post(f"/{LOGS_INDEX}/_search", json=body)
    resp.raise_for_status()
    result = resp.json()
    hits = result["hits"]["hits"]
    total = result["hits"]["total"]["value"]
    next_cursor = hits[-1]["sort"] if len(hits) == size else None
    return [{"id": h["_id"], **h["_source"]} for h in hits], total, next_cursor
