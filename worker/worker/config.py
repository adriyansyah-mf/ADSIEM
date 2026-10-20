# worker/worker/config.py
import os

DATABASE_URL: str = os.environ.get("DATABASE_URL", "postgresql+asyncpg://soc:soc@postgres:5432/soc_platform")
REDIS_URL: str = os.environ.get("REDIS_URL", "redis://redis:6379/0")
REDIS_STREAM_KEY: str = os.environ.get("REDIS_STREAM_KEY", "siem:logs")
REDIS_CONSUMER_GROUP: str = os.environ.get("REDIS_CONSUMER_GROUP", "siem-workers")
DECODERS_DIR: str = os.environ.get("DECODERS_DIR", "/app/decoders")
RULES_DIR: str = os.environ.get("RULES_DIR", "/app/rules")
LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "info")
RELOAD_INTERVAL: int = int(os.environ.get("RELOAD_INTERVAL", "60"))
# Stream entries read per round, and how many source groups of them are processed
# at once (entries from one source IP/host stay in order). CONSUME_CONCURRENCY is
# the starting point; adaptive.py moves it between MIN and MAX with the stream lag
# and this container's CPU/memory. MAX is bounded by the DB pool (25).
CONSUME_BATCH: int = int(os.environ.get("CONSUME_BATCH", "100"))
CONSUME_CONCURRENCY: int = int(os.environ.get("CONSUME_CONCURRENCY", "8"))
CONSUME_CONCURRENCY_MIN: int = int(os.environ.get("CONSUME_CONCURRENCY_MIN", "4"))
CONSUME_CONCURRENCY_MAX: int = int(os.environ.get("CONSUME_CONCURRENCY_MAX", "16"))
ADAPT_INTERVAL: int = int(os.environ.get("ADAPT_INTERVAL", "10"))
LAG_HIGH: int = int(os.environ.get("LAG_HIGH", "2000"))  # entries waiting: climb
LAG_LOW: int = int(os.environ.get("LAG_LOW", "200"))     # caught up: ease back
WEBHOOK_RETRY_INTERVAL: int = int(os.environ.get("WEBHOOK_RETRY_INTERVAL", "30"))
MAX_WEBHOOK_ATTEMPTS: int = int(os.environ.get("MAX_WEBHOOK_ATTEMPTS", "5"))
NINEROUTER_BASE_URL: str = os.environ.get("NINEROUTER_BASE_URL", "http://9router:20128/v1")
# 9router always requires a real generated key for /v1/chat/completions (REQUIRE_API_KEY
# only affects other things, not this check) — there's no valid fixed/placeholder value.
# The key is generated once per environment via POST /api/keys against the 9router
# dashboard API (see docs/PROJECT_OVERVIEW.md) and stored in platform_settings, which
# always takes priority over this env var fallback.
NINEROUTER_API_KEY: str = os.environ.get("NINEROUTER_API_KEY", "")
NINEROUTER_MODEL: str = os.environ.get("NINEROUTER_MODEL", "combo")
# Provider/combo name for 9router's /v1/search — defaults to "searxng" (works
# out of the box, no dashboard setup needed). Switch to a "search-combo"
# configured in the 9router dashboard for multi-provider auto-fallback.
NINEROUTER_SEARCH_PROVIDER: str = os.environ.get("NINEROUTER_SEARCH_PROVIDER", "searxng")
SEARXNG_URL: str = os.environ.get("SEARXNG_URL", "http://searxng:8080")
AI_ANALYSIS_QUEUE: str = os.environ.get("AI_ANALYSIS_QUEUE", "siem:ai-analysis")
ELASTICSEARCH_URL: str = os.environ.get("ELASTICSEARCH_URL", "http://elasticsearch:9200")
