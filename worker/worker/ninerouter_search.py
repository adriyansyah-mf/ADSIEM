# worker/worker/ninerouter_search.py
"""Web search for the AI analyst's self-chosen research queries, routed through
9router's /v1/search (https://github.com/decolua/9router/blob/master/skills/
9router-web-search/SKILL.md) instead of hitting SearXNG directly. This gives
multi-provider auto-fallback (Tavily/Exa/Brave/Serper/Google PSE/Linkup/
You.com/Perplexity/SearXNG) when a "search-combo" is configured in the
9router dashboard — same pattern as ninerouter_model for chat completions.
Falls back to direct SearXNG (searxng_client.search_threat_intel) on any
9router failure, so this is a pure upgrade with no new failure mode."""
import json
import httpx
import structlog
from worker.config import NINEROUTER_API_KEY, NINEROUTER_BASE_URL, NINEROUTER_SEARCH_PROVIDER
from worker.settings_cache import get_setting

log = structlog.get_logger()


async def search_via_9router(query: str, num_results: int = 5) -> list[dict]:
    """Search via 9router's /v1/search. Returns list of {title, url, content},
    or [] on any failure (caller falls back to direct SearXNG)."""
    api_key = await get_setting("ninerouter_api_key") or NINEROUTER_API_KEY
    provider = await get_setting("ninerouter_search_provider", NINEROUTER_SEARCH_PROVIDER)
    url = f"{NINEROUTER_BASE_URL.rstrip('/')}/search"
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(
                url,
                headers={"Authorization": f"Bearer {api_key}",
                         "Content-Type": "application/json"},
                json={"provider": provider, "query": query, "max_results": num_results},
            )
            resp.raise_for_status()
            # Same text/event-stream quirk as /v1/chat/completions — parse the
            # leading JSON object and ignore any trailing "data: [DONE]".
            obj, _ = json.JSONDecoder().raw_decode(resp.text)
            results = obj.get("results", [])[:num_results]
            return [
                {
                    "title": r.get("title", ""),
                    "url": r.get("url", ""),
                    "content": r.get("content") or r.get("snippet", ""),
                }
                for r in results
            ]
    except Exception as e:
        log.warning("ninerouter_search_failed", query=query, provider=provider, error=str(e))
        return []
