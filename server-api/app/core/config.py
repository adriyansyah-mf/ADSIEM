from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    DATABASE_URL: str = "postgresql+asyncpg://soc:soc@postgres:5432/soc_platform"
    REDIS_URL: str = "redis://redis:6379/0"
    JWT_SECRET: str  # required — must be set via JWT_SECRET environment variable
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    AGENT_ENROLLMENT_TOKEN: str = ""
    CORS_ORIGINS: str = ""  # comma-separated allow-list; empty = same-origin only
    ALLOW_PRIVATE_WEBHOOK_TARGETS: bool = False
    LOG_LEVEL: str = "info"
    EVIDENCE_INGEST_ENABLED: bool = False
    # Agent self-update: base64 ed25519 public keys (comma separated). When set,
    # only packages they verify are offered; agents verify with their own keys
    # either way (services/agent_update.py).
    AGENT_UPDATE_PUBLIC_KEYS: str = ""
    EVIDENCE_GROUP_BUDGET_BYTES: int = Field(default=1 << 30, gt=0)
    # agents' heartbeat interval (agent config server.heartbeat_interval); evidence
    # health older than two of them is shown as stale
    AGENT_HEARTBEAT_INTERVAL_SECONDS: int = Field(default=30, gt=0)
    REDIS_STREAM_KEY: str = "siem:logs"
    # Hard cap on the log stream (approximate). The worker trims what it has
    # processed (worker/stream_maintenance.py); this only bites if the workers
    # are down for long, so Redis can't grow until it is killed.
    REDIS_STREAM_MAXLEN: int = 2_000_000
    REDIS_CONSUMER_GROUP: str = "siem-workers"
    ELASTICSEARCH_URL: str = "http://elasticsearch:9200"
    NINEROUTER_BASE_URL: str = "http://9router:20128/v1"
    LANGGRAPH_ASSISTANT_MODEL: str = ""
    ASSISTANT_REASONING_EFFORT: str = ""

    @field_validator("JWT_SECRET")
    @classmethod
    def jwt_secret_must_not_be_default(cls, v: str) -> str:
        _insecure = {"change-me", "change-me-very-long-random-secret", ""}
        if not v or v in _insecure or v.startswith("change-me"):
            raise ValueError(
                "JWT_SECRET must be set to a strong random value via environment variable; "
                "generate one with: openssl rand -hex 32"
            )
        if len(v) < 32:
            raise ValueError("JWT_SECRET must be at least 32 characters")
        return v

settings = Settings()
