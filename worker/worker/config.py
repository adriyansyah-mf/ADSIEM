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
