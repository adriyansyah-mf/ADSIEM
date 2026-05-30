from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    DATABASE_URL: str = "postgresql+asyncpg://soc:soc@postgres:5432/soc_platform"
    REDIS_URL: str = "redis://redis:6379/0"
    JWT_SECRET: str  # required — must be set via JWT_SECRET environment variable
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    AGENT_ENROLLMENT_TOKEN: str = "bootstrap-token"
    LOG_LEVEL: str = "info"
    REDIS_STREAM_KEY: str = "siem:logs"
    REDIS_CONSUMER_GROUP: str = "siem-workers"

    @field_validator("JWT_SECRET")
    @classmethod
    def jwt_secret_must_not_be_default(cls, v: str) -> str:
        _insecure = {"change-me", "change-me-very-long-random-secret", ""}
        if not v or v in _insecure or v.startswith("change-me"):
            raise ValueError(
                "JWT_SECRET must be set to a strong random value via environment variable; "
                "generate one with: openssl rand -hex 32"
            )
        return v

settings = Settings()
