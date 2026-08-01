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
SEARXNG_URL: str = os.environ.get("SEARXNG_URL", "http://searxng:8080")
AI_ANALYSIS_QUEUE: str = os.environ.get("AI_ANALYSIS_QUEUE", "siem:ai-analysis")
ELASTICSEARCH_URL: str = os.environ.get("ELASTICSEARCH_URL", "http://elasticsearch:9200")
