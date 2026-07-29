# worker/worker/es_client.py
"""Thin Elasticsearch REST client — raw_logs + events live here now instead of
Postgres. One document per ingested log line: raw_message + decoded_fields
together, since they're always 1:1 and always queried together."""
import httpx
import structlog
from worker.config import ELASTICSEARCH_URL

log = structlog.get_logger()

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
        _client = httpx.AsyncClient(base_url=ELASTICSEARCH_URL, timeout=15)
    return _client


async def ensure_index() -> None:
    """Idempotent — create the logs index with its mapping if it doesn't exist yet."""
    client = _get_client()
    resp = await client.head(f"/{LOGS_INDEX}")
    if resp.status_code == 200:
        return
    resp = await client.put(f"/{LOGS_INDEX}", json=_MAPPING)
    if resp.status_code not in (200, 201) and "resource_already_exists_exception" not in resp.text:
        log.error("es_index_create_failed", status=resp.status_code, body=resp.text[:500])
    else:
        log.info("es_index_ready", index=LOGS_INDEX)


async def index_log(doc_id: str, doc: dict) -> None:
    client = _get_client()
    resp = await client.put(f"/{LOGS_INDEX}/_doc/{doc_id}", json=doc)
    resp.raise_for_status()


async def search(query: dict, size: int = 100, sort: list | None = None) -> list[dict]:
    """Run a raw ES query body against the logs index. Returns list of {id, **_source}."""
    client = _get_client()
    body: dict = {"query": query, "size": size}
    if sort:
        body["sort"] = sort
    resp = await client.post(f"/{LOGS_INDEX}/_search", json=body)
    resp.raise_for_status()
    hits = resp.json()["hits"]["hits"]
    return [{"id": h["_id"], **h["_source"]} for h in hits]


async def delete_by_query(query: dict) -> int:
    """Delete matching documents. Returns the number deleted."""
    client = _get_client()
    resp = await client.post(f"/{LOGS_INDEX}/_delete_by_query", json={"query": query})
    resp.raise_for_status()
    return resp.json().get("deleted", 0)
