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
            "location":       {"type": "keyword"},
            "decoder":        {"type": "keyword"},
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


async def ping() -> bool:
    """True when the cluster answers and isn't red."""
    try:
        resp = await _get_client().get("/_cluster/health", timeout=2)  # inside the 5s healthcheck
        return resp.status_code == 200 and resp.json().get("status") != "red"
    except Exception:  # noqa: BLE001
        return False


async def ensure_index() -> None:
    client = _get_client()
    resp = await client.head(f"/{LOGS_INDEX}")
    if resp.status_code == 200:
        return
    await client.put(f"/{LOGS_INDEX}", json=_MAPPING)


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


async def aggregate(
    query: dict,
    aggs: dict,
    size: int = 0,
) -> dict:
    """Run a search with aggregations and return just the aggregations block.

    Charts are computed by Elasticsearch rather than by pulling hits into
    Python — at real log volume the hit count is in the millions, so a
    fetch-then-count approach would both be slow and hit memory limits.
    """
    client = _get_client()
    body = {"query": query, "size": size, "aggs": aggs, "track_total_hits": True}
    resp = await client.post(f"/{LOGS_INDEX}/_search", json=body)
    resp.raise_for_status()
    result = resp.json()
    return {
        "total": result["hits"]["total"]["value"],
        "aggregations": result.get("aggregations", {}),
    }


async def index_stats() -> dict:
    """Document count and store size for the logs index."""
    client = _get_client()
    resp = await client.get("/_cat/indices", params={"format": "json", "index": LOGS_INDEX})
    if resp.status_code != 200:
        return {"docs": 0, "size": "0b"}
    for row in resp.json():
        if row.get("index") == LOGS_INDEX:
            return {"docs": int(row.get("docs.count", 0) or 0), "size": row.get("store.size", "0b")}
    return {"docs": 0, "size": "0b"}


IOCS_INDEX = "alert_iocs"


async def search_iocs(body: dict) -> dict:
    """Raw search on alert_iocs (written by worker/worker/alert_iocs.py). {} before the index exists."""
    resp = await _get_client().post(f"/{IOCS_INDEX}/_search", json=body)
    if resp.status_code == 404:
        return {}
    resp.raise_for_status()
    return resp.json()


_KEYWORD = {"type": "keyword"}
# Mirrors worker/worker/alert_iocs.py MAPPING (the worker package is not importable here).
IOCS_MAPPING = {"mappings": {"properties": {
    "alert_id": _KEYWORD, "group_id": _KEYWORD, "type": _KEYWORD, "value": _KEYWORD, "ioc_key": _KEYWORD,
    "severity": _KEYWORD, "severity_rank": {"type": "byte"}, "hostname": _KEYWORD, "agent_id": _KEYWORD,
    "rule_title": _KEYWORD, "ai_verdict": _KEYWORD, "origin": _KEYWORD, "created_at": {"type": "date"},
}}}


async def index_ioc(doc_id: str, doc: dict) -> None:
    """Write one alert_iocs document under `doc_id` (overwrites), creating the index with
    the worker's mapping if nothing wrote one yet. Raises on an Elasticsearch error."""
    client = _get_client()
    if (await client.head(f"/{IOCS_INDEX}")).status_code == 404:
        resp = await client.put(f"/{IOCS_INDEX}", json=IOCS_MAPPING)
        if resp.status_code not in (200, 201, 400):  # 400: the worker created it in between
            resp.raise_for_status()
    resp = await client.put(f"/{IOCS_INDEX}/_doc/{doc_id}", json=doc, params={"refresh": "wait_for"})
    resp.raise_for_status()


async def delete_ioc(doc_id: str) -> bool:
    """Delete one alert_iocs document; False when it (or the index) does not exist."""
    resp = await _get_client().delete(f"/{IOCS_INDEX}/_doc/{doc_id}", params={"refresh": "wait_for"})
    if resp.status_code == 404:
        return False
    resp.raise_for_status()
    return True
