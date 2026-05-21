# worker/worker/searxng_client.py
import httpx
import structlog
from worker.config import SEARXNG_URL

log = structlog.get_logger()

async def search_threat_intel(query: str, num_results: int = 5) -> list[dict]:
    """Search SearXNG for threat intel. Returns list of {title, url, content}."""
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"{SEARXNG_URL}/search",
                params={"q": query, "format": "json", "categories": "general", "language": "en"},
            )
            resp.raise_for_status()
            data = resp.json()
            results = data.get("results", [])[:num_results]
            return [{"title": r.get("title",""), "url": r.get("url",""), "content": r.get("content","")} for r in results]
    except Exception as e:
        log.warning("searxng_search_failed", query=query, error=str(e))
        return []
