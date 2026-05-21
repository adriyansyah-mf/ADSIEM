# SIEM Platform — Plan 1: Foundation, Database & Server API

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the PostgreSQL schema, seed data, and the complete FastAPI server-api with JWT auth, RBAC, and all REST endpoints.

**Architecture:** PostgreSQL 16 for persistence, FastAPI with SQLAlchemy 2.x async ORM, Alembic-free (init.sql handles schema), Pydantic v2 for validation. RBAC enforced via FastAPI dependencies injected per route.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy 2.x (async), asyncpg, python-jose, passlib[bcrypt], structlog, redis-py, pydantic v2, uvicorn, prometheus-client

**Build order:** DB schema → models → core auth → routes (auth → users → agents → ingest → logs/events → alerts → rules → decoders → webhooks → system)

---

## File Map

```
db/
└── init.sql

server-api/
├── Dockerfile
├── requirements.txt
├── app/
│   ├── main.py
│   ├── core/
│   │   ├── config.py          — Settings from env vars
│   │   ├── database.py        — Async SQLAlchemy engine + session
│   │   ├── redis_client.py    — Redis connection
│   │   ├── security.py        — JWT encode/decode, bcrypt, token generation
│   │   └── deps.py            — FastAPI dependencies (get_db, get_current_user, require_permission, get_scoped_group, get_agent)
│   ├── models/
│   │   └── models.py          — All SQLAlchemy ORM models
│   ├── schemas/
│   │   └── schemas.py         — All Pydantic request/response schemas
│   ├── services/
│   │   ├── audit.py           — audit_log() background task helper
│   │   └── ingest.py          — Redis XADD helper
│   └── api/
│       └── routes/
│           ├── auth.py
│           ├── users.py
│           ├── agents.py
│           ├── ingest.py
│           ├── logs.py
│           ├── events.py
│           ├── alerts.py
│           ├── rules.py
│           ├── decoders.py
│           ├── webhooks.py
│           └── system.py
tests/
└── server-api/
    ├── conftest.py
    ├── test_auth.py
    ├── test_ingest.py
    ├── test_decoder_route.py
    └── test_rbac.py
```

---

## Task 1: Database Schema

**Files:**
- Create: `db/init.sql`

- [ ] **Step 1: Write init.sql**

```sql
-- db/init.sql

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─── Auth & Users ────────────────────────────────────────────────

CREATE TABLE roles (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(50) UNIQUE NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE permissions (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(100) UNIQUE NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE role_permissions (
    role_id       INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username      VARCHAR(100) UNIQUE NOT NULL,
    email         VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role_id       INTEGER NOT NULL REFERENCES roles(id),
    group_id      VARCHAR(100) NOT NULL DEFAULT 'default',
    is_active     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── Agents ──────────────────────────────────────────────────────

CREATE TABLE agents (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name          VARCHAR(255) NOT NULL,
    hostname      VARCHAR(255) NOT NULL,
    group_id      VARCHAR(100) NOT NULL DEFAULT 'default',
    token_hash    TEXT NOT NULL,
    version       VARCHAR(50),
    status        VARCHAR(20) NOT NULL DEFAULT 'offline',
    last_seen_at  TIMESTAMPTZ,
    enrolled_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE agent_log_sources (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id    UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    path        TEXT NOT NULL,
    log_type    VARCHAR(100) NOT NULL,
    is_enabled  BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── Logs & Events ───────────────────────────────────────────────

CREATE TABLE raw_logs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id    UUID REFERENCES agents(id) ON DELETE SET NULL,
    log_type    VARCHAR(100),
    raw_message TEXT NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_raw_logs_agent_id ON raw_logs(agent_id);
CREATE INDEX idx_raw_logs_received_at ON raw_logs(received_at DESC);

CREATE TABLE events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    raw_log_id      UUID REFERENCES raw_logs(id) ON DELETE SET NULL,
    agent_id        UUID REFERENCES agents(id) ON DELETE SET NULL,
    group_id        VARCHAR(100) NOT NULL DEFAULT 'default',
    decoded_fields  JSONB NOT NULL DEFAULT '{}',
    event_category  VARCHAR(100),
    event_action    VARCHAR(100),
    source_ip       VARCHAR(45),
    user_name       VARCHAR(255),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_events_agent_id ON events(agent_id);
CREATE INDEX idx_events_group_id ON events(group_id);
CREATE INDEX idx_events_created_at ON events(created_at DESC);
CREATE INDEX idx_events_source_ip ON events(source_ip);

-- ─── Detections ──────────────────────────────────────────────────

CREATE TABLE rules (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title       VARCHAR(255) NOT NULL,
    description TEXT,
    content     TEXT NOT NULL,
    level       VARCHAR(20) NOT NULL DEFAULT 'medium',
    tags        TEXT[] NOT NULL DEFAULT '{}',
    mitre_tags  TEXT[] NOT NULL DEFAULT '{}',
    version     INTEGER NOT NULL DEFAULT 1,
    is_enabled  BOOLEAN NOT NULL DEFAULT TRUE,
    group_id    VARCHAR(100),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE decoders (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(255) UNIQUE NOT NULL,
    log_type    VARCHAR(100) NOT NULL,
    content     TEXT NOT NULL,
    priority    INTEGER NOT NULL DEFAULT 100,
    is_enabled  BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE alerts (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title       VARCHAR(255) NOT NULL,
    severity    VARCHAR(20) NOT NULL DEFAULT 'medium',
    status      VARCHAR(30) NOT NULL DEFAULT 'new',
    rule_id     UUID REFERENCES rules(id) ON DELETE SET NULL,
    event_id    UUID REFERENCES events(id) ON DELETE SET NULL,
    agent_id    UUID REFERENCES agents(id) ON DELETE SET NULL,
    group_id    VARCHAR(100) NOT NULL DEFAULT 'default',
    source_ip   VARCHAR(45),
    hostname    VARCHAR(255),
    assignee_id UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_group_id ON alerts(group_id);
CREATE INDEX idx_alerts_created_at ON alerts(created_at DESC);

CREATE TABLE alert_notes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id    UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    author_id   UUID REFERENCES users(id) ON DELETE SET NULL,
    content     TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── Operations ──────────────────────────────────────────────────

CREATE TABLE audit_logs (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id      UUID REFERENCES users(id) ON DELETE SET NULL,
    action        VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100),
    resource_id   TEXT,
    detail        JSONB NOT NULL DEFAULT '{}',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at DESC);

CREATE TABLE webhook_configs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(255) NOT NULL,
    url         TEXT NOT NULL,
    is_enabled  BOOLEAN NOT NULL DEFAULT TRUE,
    group_id    VARCHAR(100),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE webhook_deliveries (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id           UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    webhook_config_id  UUID NOT NULL REFERENCES webhook_configs(id) ON DELETE CASCADE,
    payload            JSONB NOT NULL DEFAULT '{}',
    status             VARCHAR(20) NOT NULL DEFAULT 'pending',
    attempts           INTEGER NOT NULL DEFAULT 0,
    last_attempted_at  TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webhook_deliveries_status ON webhook_deliveries(status);

-- ─── Seed Data ───────────────────────────────────────────────────

INSERT INTO roles (name) VALUES
    ('superadmin'),
    ('admin'),
    ('analyst'),
    ('viewer');

INSERT INTO permissions (name) VALUES
    ('users:manage'),
    ('agents:manage'),
    ('rules:create'),
    ('rules:update'),
    ('rules:delete'),
    ('decoders:create'),
    ('decoders:update'),
    ('decoders:delete'),
    ('logs:read'),
    ('alerts:read'),
    ('alerts:update');

-- superadmin: all permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p WHERE r.name = 'superadmin';

-- admin: agents:manage + rules:* + decoders:* + logs:read + alerts:read + alerts:update
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'admin'
  AND p.name IN (
    'agents:manage','rules:create','rules:update','rules:delete',
    'decoders:create','decoders:update','decoders:delete',
    'logs:read','alerts:read','alerts:update'
  );

-- analyst: logs:read + alerts:read + alerts:update
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'analyst'
  AND p.name IN ('logs:read','alerts:read','alerts:update');

-- viewer: logs:read + alerts:read
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'viewer'
  AND p.name IN ('logs:read','alerts:read');

-- default admin user (password: admin123) — CHANGE IN PRODUCTION
INSERT INTO users (username, email, password_hash, role_id, group_id)
SELECT
    'admin',
    'admin@siem.local',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj6o8HLpuVfe',
    r.id,
    'default'
FROM roles r WHERE r.name = 'superadmin';
```

- [ ] **Step 2: Verify SQL is valid**

```bash
docker run --rm -e POSTGRES_PASSWORD=test postgres:16 bash -c "
  docker-entrypoint.sh postgres &
  sleep 3
  psql -U postgres -c '\l'
" 2>/dev/null || echo "Use: psql -U soc soc_platform < db/init.sql after compose up"
```

Expected: No syntax errors. The bcrypt hash above is for `admin123` generated with `passlib.hash.bcrypt.hash("admin123")`.

- [ ] **Step 3: Commit**

```bash
git add db/init.sql
git commit -m "feat: add database schema and seed data"
```

---

## Task 2: Server API — Project Scaffold

**Files:**
- Create: `server-api/requirements.txt`
- Create: `server-api/Dockerfile`
- Create: `server-api/app/__init__.py`
- Create: `server-api/app/core/__init__.py`
- Create: `server-api/app/api/__init__.py`
- Create: `server-api/app/api/routes/__init__.py`

- [ ] **Step 1: Write requirements.txt**

```txt
fastapi==0.115.5
uvicorn[standard]==0.32.1
sqlalchemy[asyncio]==2.0.36
asyncpg==0.30.0
redis==5.2.0
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
pydantic[email]==2.10.3
pydantic-settings==2.6.1
structlog==24.4.0
prometheus-client==0.21.1
httpx==0.28.0
pyyaml==6.0.2
python-multipart==0.0.17
```

- [ ] **Step 2: Write Dockerfile**

```dockerfile
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health').raise_for_status()"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

- [ ] **Step 3: Create all __init__.py files**

```bash
mkdir -p server-api/app/{core,models,schemas,services,api/routes}
touch server-api/app/__init__.py \
      server-api/app/core/__init__.py \
      server-api/app/models/__init__.py \
      server-api/app/schemas/__init__.py \
      server-api/app/services/__init__.py \
      server-api/app/api/__init__.py \
      server-api/app/api/routes/__init__.py
```

- [ ] **Step 4: Commit**

```bash
git add server-api/
git commit -m "feat: scaffold server-api project structure"
```

---

## Task 3: Core Config & Database

**Files:**
- Create: `server-api/app/core/config.py`
- Create: `server-api/app/core/database.py`
- Create: `server-api/app/core/redis_client.py`

- [ ] **Step 1: Write config.py**

```python
# server-api/app/core/config.py
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    DATABASE_URL: str = "postgresql+asyncpg://soc:soc@postgres:5432/soc_platform"
    REDIS_URL: str = "redis://redis:6379/0"
    JWT_SECRET: str = "change-me"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    AGENT_ENROLLMENT_TOKEN: str = "bootstrap-token"
    LOG_LEVEL: str = "info"
    REDIS_STREAM_KEY: str = "siem:logs"
    REDIS_CONSUMER_GROUP: str = "siem-workers"

settings = Settings()
```

- [ ] **Step 2: Write database.py**

```python
# server-api/app/core/database.py
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from app.core.config import settings

engine = create_async_engine(settings.DATABASE_URL, echo=False, pool_pre_ping=True)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

class Base(DeclarativeBase):
    pass

async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session
```

- [ ] **Step 3: Write redis_client.py**

```python
# server-api/app/core/redis_client.py
import redis.asyncio as aioredis
from app.core.config import settings

_redis: aioredis.Redis | None = None

async def get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    return _redis
```

- [ ] **Step 4: Commit**

```bash
git add server-api/app/core/
git commit -m "feat: add core config, database, and redis client"
```

---

## Task 4: SQLAlchemy Models

**Files:**
- Create: `server-api/app/models/models.py`

- [ ] **Step 1: Write models.py**

```python
# server-api/app/models/models.py
import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, Integer,
    String, Text, ARRAY, UniqueConstraint
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from app.core.database import Base

def now_utc():
    return datetime.now(timezone.utc)

class Role(Base):
    __tablename__ = "roles"
    id         = Column(Integer, primary_key=True)
    name       = Column(String(50), unique=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    permissions = relationship("Permission", secondary="role_permissions", back_populates="roles")
    users       = relationship("User", back_populates="role")

class Permission(Base):
    __tablename__ = "permissions"
    id         = Column(Integer, primary_key=True)
    name       = Column(String(100), unique=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    roles      = relationship("Role", secondary="role_permissions", back_populates="permissions")

class RolePermission(Base):
    __tablename__ = "role_permissions"
    role_id       = Column(Integer, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True)
    permission_id = Column(Integer, ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True)

class User(Base):
    __tablename__ = "users"
    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username      = Column(String(100), unique=True, nullable=False)
    email         = Column(String(255), unique=True, nullable=False)
    password_hash = Column(Text, nullable=False)
    role_id       = Column(Integer, ForeignKey("roles.id"), nullable=False)
    group_id      = Column(String(100), nullable=False, default="default")
    is_active     = Column(Boolean, nullable=False, default=True)
    created_at    = Column(DateTime(timezone=True), default=now_utc)
    updated_at    = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    role          = relationship("Role", back_populates="users")

class Agent(Base):
    __tablename__ = "agents"
    id           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name         = Column(String(255), nullable=False)
    hostname     = Column(String(255), nullable=False)
    group_id     = Column(String(100), nullable=False, default="default")
    token_hash   = Column(Text, nullable=False)
    version      = Column(String(50))
    status       = Column(String(20), nullable=False, default="offline")
    last_seen_at = Column(DateTime(timezone=True))
    enrolled_at  = Column(DateTime(timezone=True), default=now_utc)
    created_at   = Column(DateTime(timezone=True), default=now_utc)
    updated_at   = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    log_sources  = relationship("AgentLogSource", back_populates="agent", cascade="all, delete-orphan")

class AgentLogSource(Base):
    __tablename__ = "agent_log_sources"
    id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id   = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    path       = Column(Text, nullable=False)
    log_type   = Column(String(100), nullable=False)
    is_enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    agent      = relationship("Agent", back_populates="log_sources")

class RawLog(Base):
    __tablename__ = "raw_logs"
    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id    = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="SET NULL"))
    log_type    = Column(String(100))
    raw_message = Column(Text, nullable=False)
    received_at = Column(DateTime(timezone=True), default=now_utc)

class Event(Base):
    __tablename__ = "events"
    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    raw_log_id      = Column(UUID(as_uuid=True), ForeignKey("raw_logs.id", ondelete="SET NULL"))
    agent_id        = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="SET NULL"))
    group_id        = Column(String(100), nullable=False, default="default")
    decoded_fields  = Column(JSONB, nullable=False, default=dict)
    event_category  = Column(String(100))
    event_action    = Column(String(100))
    source_ip       = Column(String(45))
    user_name       = Column(String(255))
    created_at      = Column(DateTime(timezone=True), default=now_utc)

class Rule(Base):
    __tablename__ = "rules"
    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title       = Column(String(255), nullable=False)
    description = Column(Text)
    content     = Column(Text, nullable=False)
    level       = Column(String(20), nullable=False, default="medium")
    tags        = Column(ARRAY(Text), nullable=False, default=list)
    mitre_tags  = Column(ARRAY(Text), nullable=False, default=list)
    version     = Column(Integer, nullable=False, default=1)
    is_enabled  = Column(Boolean, nullable=False, default=True)
    group_id    = Column(String(100))
    created_at  = Column(DateTime(timezone=True), default=now_utc)
    updated_at  = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

class Decoder(Base):
    __tablename__ = "decoders"
    id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name       = Column(String(255), unique=True, nullable=False)
    log_type   = Column(String(100), nullable=False)
    content    = Column(Text, nullable=False)
    priority   = Column(Integer, nullable=False, default=100)
    is_enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

class Alert(Base):
    __tablename__ = "alerts"
    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title       = Column(String(255), nullable=False)
    severity    = Column(String(20), nullable=False, default="medium")
    status      = Column(String(30), nullable=False, default="new")
    rule_id     = Column(UUID(as_uuid=True), ForeignKey("rules.id", ondelete="SET NULL"))
    event_id    = Column(UUID(as_uuid=True), ForeignKey("events.id", ondelete="SET NULL"))
    agent_id    = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="SET NULL"))
    group_id    = Column(String(100), nullable=False, default="default")
    source_ip   = Column(String(45))
    hostname    = Column(String(255))
    assignee_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    created_at  = Column(DateTime(timezone=True), default=now_utc)
    updated_at  = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    notes       = relationship("AlertNote", back_populates="alert", cascade="all, delete-orphan")

class AlertNote(Base):
    __tablename__ = "alert_notes"
    id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id   = Column(UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False)
    author_id  = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    content    = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=now_utc)
    alert      = relationship("Alert", back_populates="notes")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    actor_id      = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    action        = Column(String(100), nullable=False)
    resource_type = Column(String(100))
    resource_id   = Column(Text)
    detail        = Column(JSONB, nullable=False, default=dict)
    created_at    = Column(DateTime(timezone=True), default=now_utc)

class WebhookConfig(Base):
    __tablename__ = "webhook_configs"
    id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name       = Column(String(255), nullable=False)
    url        = Column(Text, nullable=False)
    is_enabled = Column(Boolean, nullable=False, default=True)
    group_id   = Column(String(100))
    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

class WebhookDelivery(Base):
    __tablename__ = "webhook_deliveries"
    id                = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id          = Column(UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False)
    webhook_config_id = Column(UUID(as_uuid=True), ForeignKey("webhook_configs.id", ondelete="CASCADE"), nullable=False)
    payload           = Column(JSONB, nullable=False, default=dict)
    status            = Column(String(20), nullable=False, default="pending")
    attempts          = Column(Integer, nullable=False, default=0)
    last_attempted_at = Column(DateTime(timezone=True))
    created_at        = Column(DateTime(timezone=True), default=now_utc)
    updated_at        = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
```

- [ ] **Step 2: Commit**

```bash
git add server-api/app/models/
git commit -m "feat: add SQLAlchemy ORM models"
```

---

## Task 5: Security & JWT

**Files:**
- Create: `server-api/app/core/security.py`

- [ ] **Step 1: Write security.py**

```python
# server-api/app/core/security.py
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

def generate_agent_token() -> str:
    return secrets.token_urlsafe(32)

def create_access_token(subject: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode({"sub": subject, "exp": expire, "type": "access"}, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

def create_refresh_token(subject: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    return jwt.encode({"sub": subject, "exp": expire, "type": "refresh"}, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

def decode_token(token: str) -> dict:
    return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
```

- [ ] **Step 2: Write failing test**

```python
# tests/server-api/test_auth.py
import pytest
from app.core.security import (
    hash_password, verify_password, hash_token,
    create_access_token, decode_token, create_refresh_token
)

def test_password_hash_and_verify():
    h = hash_password("secret123")
    assert verify_password("secret123", h)
    assert not verify_password("wrong", h)

def test_access_token_round_trip():
    token = create_access_token("user-123")
    payload = decode_token(token)
    assert payload["sub"] == "user-123"
    assert payload["type"] == "access"

def test_refresh_token_type():
    token = create_refresh_token("user-123")
    payload = decode_token(token)
    assert payload["type"] == "refresh"

def test_token_hash_is_deterministic():
    assert hash_token("abc") == hash_token("abc")
    assert hash_token("abc") != hash_token("xyz")
```

- [ ] **Step 3: Run tests**

```bash
cd server-api && pip install -r requirements.txt -q
cd .. && python -m pytest tests/server-api/test_auth.py -v
```

Expected: All 4 tests PASS.

- [ ] **Step 4: Commit**

```bash
git add server-api/app/core/security.py tests/server-api/test_auth.py
git commit -m "feat: add JWT and password security utilities"
```

---

## Task 6: FastAPI Dependencies (RBAC & Auth)

**Files:**
- Create: `server-api/app/core/deps.py`

- [ ] **Step 1: Write deps.py**

```python
# server-api/app/core/deps.py
from typing import Annotated
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.core.redis_client import get_redis
from app.core.security import decode_token, hash_token
from app.models.models import Agent, Permission, Role, User

bearer_scheme = HTTPBearer(auto_error=False)

async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    try:
        payload = decode_token(credentials.credentials)
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user_id: str = payload["sub"]
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    result = await db.execute(
        select(User).options(selectinload(User.role).selectinload(Role.permissions))
        .where(User.id == user_id, User.is_active == True)
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user

def require_permission(permission_name: str):
    async def checker(current_user: Annotated[User, Depends(get_current_user)]) -> User:
        # superadmin bypasses all permission checks
        if current_user.role.name == "superadmin":
            return current_user
        perms = {p.name for p in current_user.role.permissions}
        if permission_name not in perms:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return current_user
    return checker

def get_scoped_group(current_user: Annotated[User, Depends(get_current_user)]) -> str | None:
    if current_user.role.name == "superadmin":
        return None  # no filter
    return current_user.group_id

async def get_agent(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Agent:
    token = request.headers.get("X-Agent-Token")
    if not token:
        raise HTTPException(status_code=401, detail="Missing agent token")
    token_hash = hash_token(token)
    result = await db.execute(select(Agent).where(Agent.token_hash == token_hash))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=401, detail="Invalid agent token")
    return agent
```

- [ ] **Step 2: Write RBAC test**

```python
# tests/server-api/test_rbac.py
import pytest
from unittest.mock import AsyncMock, MagicMock
from app.core.deps import require_permission

def make_user(role_name: str, perms: list[str]):
    user = MagicMock()
    user.role.name = role_name
    user.role.permissions = [MagicMock(name=p) for p in perms]
    return user

@pytest.mark.asyncio
async def test_superadmin_bypasses_all_permissions():
    user = make_user("superadmin", [])
    checker = require_permission("users:manage")
    result = await checker(user)
    assert result is user

@pytest.mark.asyncio
async def test_viewer_denied_manage_permission():
    from fastapi import HTTPException
    user = make_user("viewer", ["logs:read", "alerts:read"])
    checker = require_permission("users:manage")
    with pytest.raises(HTTPException) as exc_info:
        await checker(user)
    assert exc_info.value.status_code == 403

@pytest.mark.asyncio
async def test_analyst_allowed_alerts_update():
    user = make_user("analyst", ["logs:read", "alerts:read", "alerts:update"])
    checker = require_permission("alerts:update")
    result = await checker(user)
    assert result is user
```

- [ ] **Step 3: Run RBAC tests**

```bash
python -m pytest tests/server-api/test_rbac.py -v
```

Expected: 3 tests PASS.

- [ ] **Step 4: Commit**

```bash
git add server-api/app/core/deps.py tests/server-api/test_rbac.py
git commit -m "feat: add RBAC dependencies and permission checking"
```

---

## Task 7: Pydantic Schemas

**Files:**
- Create: `server-api/app/schemas/schemas.py`

- [ ] **Step 1: Write schemas.py**

```python
# server-api/app/schemas/schemas.py
from __future__ import annotations
from datetime import datetime
from typing import Any
from uuid import UUID
from pydantic import BaseModel, EmailStr, Field

# ─── Auth ────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class UserMe(BaseModel):
    id: UUID
    username: str
    email: str
    role: str
    group_id: str
    model_config = {"from_attributes": True}

# ─── Users ───────────────────────────────────────────────────────

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    role_id: int
    group_id: str = "default"

class UserUpdate(BaseModel):
    username: str | None = None
    email: EmailStr | None = None
    password: str | None = None
    role_id: int | None = None
    group_id: str | None = None
    is_active: bool | None = None

class UserOut(BaseModel):
    id: UUID
    username: str
    email: str
    role_id: int
    group_id: str
    is_active: bool
    created_at: datetime
    model_config = {"from_attributes": True}

# ─── Agents ──────────────────────────────────────────────────────

class LogSourceIn(BaseModel):
    path: str
    log_type: str
    is_enabled: bool = True

class EnrollRequest(BaseModel):
    enrollment_token: str
    hostname: str
    version: str
    group: str = "default"
    name: str
    log_sources: list[LogSourceIn] = []

class EnrollResponse(BaseModel):
    agent_id: UUID
    agent_token: str

class AgentUpdate(BaseModel):
    name: str | None = None
    group_id: str | None = None

class LogSourceOut(BaseModel):
    id: UUID
    path: str
    log_type: str
    is_enabled: bool
    model_config = {"from_attributes": True}

class AgentOut(BaseModel):
    id: UUID
    name: str
    hostname: str
    group_id: str
    version: str | None
    status: str
    last_seen_at: datetime | None
    enrolled_at: datetime
    log_sources: list[LogSourceOut] = []
    model_config = {"from_attributes": True}

class HeartbeatRequest(BaseModel):
    agent_id: UUID
    status: str = "online"
    version: str | None = None
    buffer_dropped: int = 0

class HeartbeatResponse(BaseModel):
    config_hash: str
    log_sources: list[LogSourceOut]

# ─── Ingest ──────────────────────────────────────────────────────

class LogIngestRequest(BaseModel):
    agent_id: UUID
    agent_token: str
    log_type: str
    raw_message: str
    received_at: datetime
    hostname: str

# ─── Logs & Events ───────────────────────────────────────────────

class RawLogOut(BaseModel):
    id: UUID
    agent_id: UUID | None
    log_type: str | None
    raw_message: str
    received_at: datetime
    model_config = {"from_attributes": True}

class EventOut(BaseModel):
    id: UUID
    agent_id: UUID | None
    group_id: str
    decoded_fields: dict[str, Any]
    event_category: str | None
    event_action: str | None
    source_ip: str | None
    user_name: str | None
    created_at: datetime
    model_config = {"from_attributes": True}

# ─── Rules ───────────────────────────────────────────────────────

class RuleCreate(BaseModel):
    title: str
    description: str | None = None
    content: str
    level: str = "medium"
    tags: list[str] = []
    mitre_tags: list[str] = []
    is_enabled: bool = True
    group_id: str | None = None

class RuleUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    content: str | None = None
    level: str | None = None
    tags: list[str] | None = None
    mitre_tags: list[str] | None = None
    is_enabled: bool | None = None
    group_id: str | None = None

class RuleOut(BaseModel):
    id: UUID
    title: str
    description: str | None
    content: str
    level: str
    tags: list[str]
    mitre_tags: list[str]
    version: int
    is_enabled: bool
    group_id: str | None
    created_at: datetime
    updated_at: datetime
    model_config = {"from_attributes": True}

class RuleTestRequest(BaseModel):
    content: str
    sample_event: dict[str, Any]

class RuleTestResponse(BaseModel):
    matched: bool
    rule_title: str | None = None
    error: str | None = None

# ─── Decoders ────────────────────────────────────────────────────

class DecoderCreate(BaseModel):
    name: str
    log_type: str
    content: str
    priority: int = 100
    is_enabled: bool = True

class DecoderUpdate(BaseModel):
    name: str | None = None
    log_type: str | None = None
    content: str | None = None
    priority: int | None = None
    is_enabled: bool | None = None

class DecoderOut(BaseModel):
    id: UUID
    name: str
    log_type: str
    content: str
    priority: int
    is_enabled: bool
    created_at: datetime
    updated_at: datetime
    model_config = {"from_attributes": True}

class DecoderTestRequest(BaseModel):
    content: str
    raw_message: str

class DecoderTestResponse(BaseModel):
    matched: bool
    decoded_fields: dict[str, Any] = {}
    error: str | None = None

# ─── Alerts ──────────────────────────────────────────────────────

class AlertUpdate(BaseModel):
    status: str | None = None
    assignee_id: UUID | None = None

class AlertNoteCreate(BaseModel):
    content: str

class AlertNoteOut(BaseModel):
    id: UUID
    author_id: UUID | None
    content: str
    created_at: datetime
    model_config = {"from_attributes": True}

class AlertOut(BaseModel):
    id: UUID
    title: str
    severity: str
    status: str
    rule_id: UUID | None
    event_id: UUID | None
    agent_id: UUID | None
    group_id: str
    source_ip: str | None
    hostname: str | None
    assignee_id: UUID | None
    created_at: datetime
    updated_at: datetime
    notes: list[AlertNoteOut] = []
    model_config = {"from_attributes": True}

# ─── Webhooks ────────────────────────────────────────────────────

class WebhookCreate(BaseModel):
    name: str
    url: str
    is_enabled: bool = True
    group_id: str | None = None

class WebhookUpdate(BaseModel):
    name: str | None = None
    url: str | None = None
    is_enabled: bool | None = None
    group_id: str | None = None

class WebhookOut(BaseModel):
    id: UUID
    name: str
    url: str
    is_enabled: bool
    group_id: str | None
    created_at: datetime
    model_config = {"from_attributes": True}

# ─── Pagination ──────────────────────────────────────────────────

class PaginatedResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[Any]
```

- [ ] **Step 2: Commit**

```bash
git add server-api/app/schemas/
git commit -m "feat: add all Pydantic request/response schemas"
```

---

## Task 8: Audit & Ingest Services

**Files:**
- Create: `server-api/app/services/audit.py`
- Create: `server-api/app/services/ingest.py`

- [ ] **Step 1: Write audit.py**

```python
# server-api/app/services/audit.py
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.models import AuditLog

async def audit_log(
    db: AsyncSession,
    actor_id: UUID | None,
    action: str,
    resource_type: str | None = None,
    resource_id: str | None = None,
    detail: dict | None = None,
) -> None:
    entry = AuditLog(
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id else None,
        detail=detail or {},
    )
    db.add(entry)
    await db.commit()
```

- [ ] **Step 2: Write ingest.py**

```python
# server-api/app/services/ingest.py
import json
from datetime import datetime
import redis.asyncio as aioredis
from app.core.config import settings

async def enqueue_log(redis: aioredis.Redis, payload: dict) -> str:
    data = {k: str(v) if isinstance(v, datetime) else json.dumps(v) if isinstance(v, dict) else str(v)
            for k, v in payload.items()}
    return await redis.xadd(settings.REDIS_STREAM_KEY, data)
```

- [ ] **Step 3: Commit**

```bash
git add server-api/app/services/
git commit -m "feat: add audit log and ingest services"
```

---

## Task 9: Auth Routes

**Files:**
- Create: `server-api/app/api/routes/auth.py`

- [ ] **Step 1: Write auth.py**

```python
# server-api/app/api/routes/auth.py
from typing import Annotated
from fastapi import APIRouter, BackgroundTasks, Cookie, Depends, HTTPException, Response, status
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.security import (
    create_access_token, create_refresh_token, decode_token, verify_password
)
from app.models.models import Role, User
from app.schemas.schemas import LoginRequest, TokenResponse, UserMe
from app.services.audit import audit_log

router = APIRouter(prefix="/api/auth", tags=["auth"])

@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    response: Response,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    result = await db.execute(
        select(User).options(selectinload(User.role))
        .where(User.username == body.username, User.is_active == True)
    )
    user = result.scalar_one_or_none()
    if not user or not verify_password(body.password, user.password_hash):
        background.add_task(audit_log, db, None, "login_failed", "user", body.username, {"reason": "bad credentials"})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access_token = create_access_token(str(user.id))
    refresh_token = create_refresh_token(str(user.id))
    response.set_cookie("refresh_token", refresh_token, httponly=True, samesite="lax", max_age=7 * 86400)
    background.add_task(audit_log, db, user.id, "login_success", "user", str(user.id))
    return TokenResponse(access_token=access_token)

@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    db: Annotated[AsyncSession, Depends(get_db)],
    refresh_token: Annotated[str | None, Cookie()] = None,
):
    if not refresh_token:
        raise HTTPException(status_code=401, detail="No refresh token")
    try:
        payload = decode_token(refresh_token)
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user_id = payload["sub"]
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    result = await db.execute(select(User).where(User.id == user_id, User.is_active == True))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return TokenResponse(access_token=create_access_token(str(user.id)))

@router.get("/me", response_model=UserMe)
async def me(current_user: Annotated[User, Depends(get_current_user)]):
    return UserMe(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        role=current_user.role.name,
        group_id=current_user.group_id,
    )
```

- [ ] **Step 2: Commit**

```bash
git add server-api/app/api/routes/auth.py
git commit -m "feat: add auth routes (login, refresh, me)"
```

---

## Task 10: Users Routes

**Files:**
- Create: `server-api/app/api/routes/users.py`

- [ ] **Step 1: Write users.py**

```python
# server-api/app/api/routes/users.py
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, require_permission
from app.core.security import hash_password
from app.models.models import User
from app.schemas.schemas import PaginatedResponse, UserCreate, UserOut, UserUpdate
from app.services.audit import audit_log

router = APIRouter(prefix="/api/users", tags=["users"])
Perm = require_permission("users:manage")

@router.get("", response_model=PaginatedResponse)
async def list_users(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(Perm)],
    page: int = 1,
    page_size: int = 25,
):
    offset = (page - 1) * page_size
    total = (await db.execute(select(func.count()).select_from(User))).scalar()
    result = await db.execute(select(User).offset(offset).limit(page_size))
    users = result.scalars().all()
    return PaginatedResponse(total=total, page=page, page_size=page_size, items=[UserOut.model_validate(u) for u in users])

@router.post("", response_model=UserOut, status_code=201)
async def create_user(
    body: UserCreate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(Perm)],
):
    user = User(
        username=body.username, email=body.email,
        password_hash=hash_password(body.password),
        role_id=body.role_id, group_id=body.group_id,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    background.add_task(audit_log, db, current_user.id, "user_created", "user", str(user.id))
    return UserOut.model_validate(user)

@router.put("/{user_id}", response_model=UserOut)
async def update_user(
    user_id: UUID,
    body: UserUpdate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(Perm)],
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    for field, value in body.model_dump(exclude_none=True).items():
        if field == "password":
            setattr(user, "password_hash", hash_password(value))
        else:
            setattr(user, field, value)
    await db.commit()
    await db.refresh(user)
    background.add_task(audit_log, db, current_user.id, "user_updated", "user", str(user_id))
    return UserOut.model_validate(user)

@router.delete("/{user_id}", status_code=204)
async def delete_user(
    user_id: UUID,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(Perm)],
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    await db.delete(user)
    await db.commit()
    background.add_task(audit_log, db, current_user.id, "user_deleted", "user", str(user_id))
```

- [ ] **Step 2: Commit**

```bash
git add server-api/app/api/routes/users.py
git commit -m "feat: add users CRUD routes"
```

---

## Task 11: Agents Routes

**Files:**
- Create: `server-api/app/api/routes/agents.py`

- [ ] **Step 1: Write agents.py**

```python
# server-api/app/api/routes/agents.py
import hashlib
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.core.deps import get_current_user, require_permission, get_scoped_group
from app.core.security import generate_agent_token, hash_token
from app.models.models import Agent, AgentLogSource, User
from app.schemas.schemas import (
    AgentOut, AgentUpdate, EnrollRequest, EnrollResponse,
    LogSourceIn, LogSourceOut, PaginatedResponse
)
from app.services.audit import audit_log

router = APIRouter(tags=["agents"])
Perm = require_permission("agents:manage")

@router.get("/api/agents", response_model=PaginatedResponse)
async def list_agents(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    page: int = 1, page_size: int = 25,
):
    from sqlalchemy import func
    q = select(Agent).options(selectinload(Agent.log_sources))
    if group_filter:
        q = q.where(Agent.group_id == group_filter)
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    result = await db.execute(q.offset((page - 1) * page_size).limit(page_size))
    agents = result.scalars().all()
    return PaginatedResponse(total=total, page=page, page_size=page_size,
                             items=[AgentOut.model_validate(a) for a in agents])

@router.post("/api/agent/enroll", response_model=EnrollResponse, status_code=201)
async def enroll_agent(
    body: EnrollRequest,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    if body.enrollment_token != settings.AGENT_ENROLLMENT_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid enrollment token")
    raw_token = generate_agent_token()
    agent = Agent(
        name=body.name, hostname=body.hostname,
        group_id=body.group, version=body.version,
        token_hash=hash_token(raw_token), status="online",
    )
    db.add(agent)
    await db.flush()
    for src in body.log_sources:
        db.add(AgentLogSource(agent_id=agent.id, path=src.path, log_type=src.log_type, is_enabled=src.is_enabled))
    await db.commit()
    background.add_task(audit_log, db, None, "agent_enrolled", "agent", str(agent.id), {"hostname": body.hostname})
    return EnrollResponse(agent_id=agent.id, agent_token=raw_token)

@router.put("/api/agents/{agent_id}", response_model=AgentOut)
async def update_agent(
    agent_id: UUID, body: AgentUpdate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(Perm)],
):
    result = await db.execute(select(Agent).options(selectinload(Agent.log_sources)).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    for field, value in body.model_dump(exclude_none=True).items():
        setattr(agent, field, value)
    await db.commit()
    await db.refresh(agent)
    background.add_task(audit_log, db, current_user.id, "agent_updated", "agent", str(agent_id))
    return AgentOut.model_validate(agent)

@router.delete("/api/agents/{agent_id}", status_code=204)
async def delete_agent(
    agent_id: UUID,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(Perm)],
):
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    await db.delete(agent)
    await db.commit()
    background.add_task(audit_log, db, current_user.id, "agent_revoked", "agent", str(agent_id))

# ─── Log Sources ─────────────────────────────────────────────────

@router.get("/api/agents/{agent_id}/log-sources", response_model=list[LogSourceOut])
async def get_log_sources(
    agent_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(select(AgentLogSource).where(AgentLogSource.agent_id == agent_id))
    return [LogSourceOut.model_validate(s) for s in result.scalars().all()]

@router.post("/api/agents/{agent_id}/log-sources", response_model=LogSourceOut, status_code=201)
async def add_log_source(
    agent_id: UUID, body: LogSourceIn,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(Perm)],
):
    src = AgentLogSource(agent_id=agent_id, path=body.path, log_type=body.log_type, is_enabled=body.is_enabled)
    db.add(src)
    await db.commit()
    await db.refresh(src)
    background.add_task(audit_log, db, current_user.id, "log_source_added", "agent_log_source", str(src.id), {"path": body.path})
    return LogSourceOut.model_validate(src)

@router.put("/api/agents/{agent_id}/log-sources/{source_id}", response_model=LogSourceOut)
async def update_log_source(
    agent_id: UUID, source_id: UUID, body: LogSourceIn,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(Perm)],
):
    result = await db.execute(
        select(AgentLogSource).where(AgentLogSource.id == source_id, AgentLogSource.agent_id == agent_id)
    )
    src = result.scalar_one_or_none()
    if not src:
        raise HTTPException(status_code=404, detail="Log source not found")
    for field, value in body.model_dump().items():
        setattr(src, field, value)
    await db.commit()
    await db.refresh(src)
    background.add_task(audit_log, db, current_user.id, "log_source_updated", "agent_log_source", str(source_id))
    return LogSourceOut.model_validate(src)

@router.delete("/api/agents/{agent_id}/log-sources/{source_id}", status_code=204)
async def delete_log_source(
    agent_id: UUID, source_id: UUID,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(Perm)],
):
    result = await db.execute(
        select(AgentLogSource).where(AgentLogSource.id == source_id, AgentLogSource.agent_id == agent_id)
    )
    src = result.scalar_one_or_none()
    if not src:
        raise HTTPException(status_code=404, detail="Log source not found")
    await db.delete(src)
    await db.commit()
    background.add_task(audit_log, db, current_user.id, "log_source_deleted", "agent_log_source", str(source_id))
```

- [ ] **Step 2: Commit**

```bash
git add server-api/app/api/routes/agents.py
git commit -m "feat: add agents enrollment, CRUD, and log-sources routes"
```

---

## Task 12: Ingest Routes

**Files:**
- Create: `server-api/app/api/routes/ingest.py`

- [ ] **Step 1: Write ingest.py**

```python
# server-api/app/api/routes/ingest.py
import hashlib
import json
from datetime import datetime, timezone
from typing import Annotated
from fastapi import APIRouter, BackgroundTasks, Depends
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession
import redis.asyncio as aioredis

from app.core.database import get_db
from app.core.deps import get_agent
from app.core.redis_client import get_redis
from app.core.security import hash_token
from app.models.models import Agent, AgentLogSource
from app.schemas.schemas import HeartbeatRequest, HeartbeatResponse, LogIngestRequest, LogSourceOut
from app.services.ingest import enqueue_log

router = APIRouter(prefix="/api/ingest", tags=["ingest"])

@router.post("/log", status_code=202)
async def ingest_log(
    body: LogIngestRequest,
    agent: Annotated[Agent, Depends(get_agent)],
    redis: Annotated[aioredis.Redis, Depends(get_redis)],
):
    await enqueue_log(redis, {
        "agent_id": str(agent.id),
        "group_id": agent.group_id,
        "hostname": agent.hostname,
        "log_type": body.log_type,
        "raw_message": body.raw_message,
        "received_at": body.received_at.isoformat(),
    })
    return {"status": "queued"}

@router.post("/heartbeat", response_model=HeartbeatResponse)
async def heartbeat(
    body: HeartbeatRequest,
    agent: Annotated[Agent, Depends(get_agent)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    from sqlalchemy import update
    await db.execute(
        update(Agent).where(Agent.id == agent.id)
        .values(status="online", last_seen_at=datetime.now(timezone.utc), version=body.version)
    )
    await db.commit()

    result = await db.execute(
        select(AgentLogSource).where(AgentLogSource.agent_id == agent.id)
    )
    sources = result.scalars().all()
    sources_data = [{"path": s.path, "log_type": s.log_type, "is_enabled": s.is_enabled} for s in sources]
    config_hash = hashlib.sha256(json.dumps(sources_data, sort_keys=True).encode()).hexdigest()

    return HeartbeatResponse(
        config_hash=config_hash,
        log_sources=[LogSourceOut.model_validate(s) for s in sources],
    )
```

- [ ] **Step 2: Write ingest test**

```python
# tests/server-api/test_ingest.py
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from app.services.ingest import enqueue_log

@pytest.mark.asyncio
async def test_enqueue_log_calls_xadd():
    mock_redis = AsyncMock()
    mock_redis.xadd = AsyncMock(return_value="1234567890-0")
    payload = {
        "agent_id": "abc-123",
        "log_type": "linux_auth",
        "raw_message": "Failed password for root",
        "received_at": "2026-05-21T10:00:00+00:00",
        "hostname": "host1",
    }
    result = await enqueue_log(mock_redis, payload)
    assert result == "1234567890-0"
    mock_redis.xadd.assert_called_once()
    call_args = mock_redis.xadd.call_args
    assert call_args[0][0] == "siem:logs"
```

- [ ] **Step 3: Run test**

```bash
python -m pytest tests/server-api/test_ingest.py -v
```

Expected: 1 test PASS.

- [ ] **Step 4: Commit**

```bash
git add server-api/app/api/routes/ingest.py tests/server-api/test_ingest.py
git commit -m "feat: add ingest routes (log + heartbeat with config sync)"
```

---

## Task 13: Logs, Events, Alerts Routes

**Files:**
- Create: `server-api/app/api/routes/logs.py`
- Create: `server-api/app/api/routes/events.py`
- Create: `server-api/app/api/routes/alerts.py`

- [ ] **Step 1: Write logs.py**

```python
# server-api/app/api/routes/logs.py
from typing import Annotated
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_scoped_group, require_permission
from app.models.models import RawLog
from app.schemas.schemas import PaginatedResponse, RawLogOut

router = APIRouter(prefix="/api/logs", tags=["logs"])
Perm = require_permission("logs:read")

@router.get("", response_model=PaginatedResponse)
async def list_logs(
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(Perm),
    page: int = 1, page_size: int = 25,
    log_type: str | None = None, search: str | None = None,
):
    q = select(RawLog).order_by(RawLog.received_at.desc())
    if log_type:
        q = q.where(RawLog.log_type == log_type)
    if search:
        q = q.where(RawLog.raw_message.ilike(f"%{search}%"))
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    result = await db.execute(q.offset((page - 1) * page_size).limit(page_size))
    return PaginatedResponse(total=total, page=page, page_size=page_size,
                             items=[RawLogOut.model_validate(r) for r in result.scalars().all()])
```

- [ ] **Step 2: Write events.py**

```python
# server-api/app/api/routes/events.py
from typing import Annotated
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_scoped_group, require_permission
from app.models.models import Event
from app.schemas.schemas import EventOut, PaginatedResponse

router = APIRouter(prefix="/api/events", tags=["events"])
Perm = require_permission("logs:read")

@router.get("", response_model=PaginatedResponse)
async def list_events(
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(Perm),
    page: int = 1, page_size: int = 25,
    source_ip: str | None = None, event_action: str | None = None,
):
    q = select(Event).order_by(Event.created_at.desc())
    if group_filter:
        q = q.where(Event.group_id == group_filter)
    if source_ip:
        q = q.where(Event.source_ip == source_ip)
    if event_action:
        q = q.where(Event.event_action == event_action)
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    result = await db.execute(q.offset((page - 1) * page_size).limit(page_size))
    return PaginatedResponse(total=total, page=page, page_size=page_size,
                             items=[EventOut.model_validate(e) for e in result.scalars().all()])
```

- [ ] **Step 3: Write alerts.py**

```python
# server-api/app/api/routes/alerts.py
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group, require_permission
from app.models.models import Alert, AlertNote, User
from app.schemas.schemas import AlertNoteCreate, AlertNoteOut, AlertOut, AlertUpdate, PaginatedResponse
from app.services.audit import audit_log

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

@router.get("", response_model=PaginatedResponse)
async def list_alerts(
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(require_permission("alerts:read")),
    page: int = 1, page_size: int = 25,
    status: str | None = None, severity: str | None = None,
):
    q = select(Alert).options(selectinload(Alert.notes)).order_by(Alert.created_at.desc())
    if group_filter:
        q = q.where(Alert.group_id == group_filter)
    if status:
        q = q.where(Alert.status == status)
    if severity:
        q = q.where(Alert.severity == severity)
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    result = await db.execute(q.offset((page - 1) * page_size).limit(page_size))
    return PaginatedResponse(total=total, page=page, page_size=page_size,
                             items=[AlertOut.model_validate(a) for a in result.scalars().all()])

@router.put("/{alert_id}", response_model=AlertOut)
async def update_alert(
    alert_id: UUID, body: AlertUpdate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("alerts:update"))],
):
    result = await db.execute(
        select(Alert).options(selectinload(Alert.notes)).where(Alert.id == alert_id)
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    for field, value in body.model_dump(exclude_none=True).items():
        setattr(alert, field, value)
    await db.commit()
    await db.refresh(alert)
    background.add_task(audit_log, db, current_user.id, "alert_updated", "alert", str(alert_id),
                        {"status": body.status})
    return AlertOut.model_validate(alert)

@router.post("/{alert_id}/notes", response_model=AlertNoteOut, status_code=201)
async def add_note(
    alert_id: UUID, body: AlertNoteCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("alerts:update"))],
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Alert not found")
    note = AlertNote(alert_id=alert_id, author_id=current_user.id, content=body.content)
    db.add(note)
    await db.commit()
    await db.refresh(note)
    return AlertNoteOut.model_validate(note)
```

- [ ] **Step 4: Commit**

```bash
git add server-api/app/api/routes/logs.py server-api/app/api/routes/events.py server-api/app/api/routes/alerts.py
git commit -m "feat: add logs, events, and alerts routes"
```

---

## Task 14: Rules & Decoders Routes

**Files:**
- Create: `server-api/app/api/routes/rules.py`
- Create: `server-api/app/api/routes/decoders.py`

- [ ] **Step 1: Write rules.py**

```python
# server-api/app/api/routes/rules.py
import re
import yaml
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, require_permission
from app.models.models import Rule, User
from app.schemas.schemas import (
    PaginatedResponse, RuleCreate, RuleOut, RuleTestRequest, RuleTestResponse, RuleUpdate
)
from app.services.audit import audit_log

router = APIRouter(prefix="/api/rules", tags=["rules"])

@router.get("", response_model=PaginatedResponse)
async def list_rules(
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(require_permission("logs:read")),
    page: int = 1, page_size: int = 25,
):
    q = select(Rule).order_by(Rule.created_at.desc())
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    result = await db.execute(q.offset((page - 1) * page_size).limit(page_size))
    return PaginatedResponse(total=total, page=page, page_size=page_size,
                             items=[RuleOut.model_validate(r) for r in result.scalars().all()])

@router.post("", response_model=RuleOut, status_code=201)
async def create_rule(
    body: RuleCreate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("rules:create"))],
):
    _validate_rule_yaml(body.content)
    rule = Rule(**body.model_dump())
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    background.add_task(audit_log, db, current_user.id, "rule_created", "rule", str(rule.id))
    return RuleOut.model_validate(rule)

@router.put("/{rule_id}", response_model=RuleOut)
async def update_rule(
    rule_id: UUID, body: RuleUpdate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("rules:update"))],
):
    result = await db.execute(select(Rule).where(Rule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    updates = body.model_dump(exclude_none=True)
    if "content" in updates:
        _validate_rule_yaml(updates["content"])
        updates["version"] = rule.version + 1
    for field, value in updates.items():
        setattr(rule, field, value)
    await db.commit()
    await db.refresh(rule)
    background.add_task(audit_log, db, current_user.id, "rule_updated", "rule", str(rule_id))
    return RuleOut.model_validate(rule)

@router.delete("/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: UUID,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("rules:delete"))],
):
    result = await db.execute(select(Rule).where(Rule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    await db.delete(rule)
    await db.commit()
    background.add_task(audit_log, db, current_user.id, "rule_deleted", "rule", str(rule_id))

@router.post("/test", response_model=RuleTestResponse)
async def test_rule(body: RuleTestRequest, _=Depends(require_permission("rules:create"))):
    try:
        rule_def = yaml.safe_load(body.content)
        from app.core.sigma import evaluate_rule
        matched = evaluate_rule(rule_def, body.sample_event)
        return RuleTestResponse(matched=matched, rule_title=rule_def.get("title"))
    except Exception as e:
        return RuleTestResponse(matched=False, error=str(e))

def _validate_rule_yaml(content: str):
    try:
        parsed = yaml.safe_load(content)
        if not isinstance(parsed, dict):
            raise ValueError("Rule must be a YAML mapping")
        if "detection" not in parsed:
            raise ValueError("Rule must have a 'detection' block")
    except yaml.YAMLError as e:
        raise HTTPException(status_code=422, detail=f"Invalid YAML: {e}")
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
```

- [ ] **Step 2: Write decoders.py**

```python
# server-api/app/api/routes/decoders.py
import re
import yaml
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import require_permission, get_current_user
from app.models.models import Decoder, User
from app.schemas.schemas import (
    DecoderCreate, DecoderOut, DecoderTestRequest, DecoderTestResponse,
    DecoderUpdate, PaginatedResponse
)
from app.services.audit import audit_log

router = APIRouter(prefix="/api/decoders", tags=["decoders"])

@router.get("", response_model=PaginatedResponse)
async def list_decoders(
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(require_permission("logs:read")),
    page: int = 1, page_size: int = 25,
):
    q = select(Decoder).order_by(Decoder.priority)
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    result = await db.execute(q.offset((page - 1) * page_size).limit(page_size))
    return PaginatedResponse(total=total, page=page, page_size=page_size,
                             items=[DecoderOut.model_validate(d) for d in result.scalars().all()])

@router.post("", response_model=DecoderOut, status_code=201)
async def create_decoder(
    body: DecoderCreate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("decoders:create"))],
):
    _validate_decoder_yaml(body.content)
    decoder = Decoder(**body.model_dump())
    db.add(decoder)
    await db.commit()
    await db.refresh(decoder)
    background.add_task(audit_log, db, current_user.id, "decoder_created", "decoder", str(decoder.id))
    return DecoderOut.model_validate(decoder)

@router.put("/{decoder_id}", response_model=DecoderOut)
async def update_decoder(
    decoder_id: UUID, body: DecoderUpdate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("decoders:update"))],
):
    result = await db.execute(select(Decoder).where(Decoder.id == decoder_id))
    decoder = result.scalar_one_or_none()
    if not decoder:
        raise HTTPException(status_code=404, detail="Decoder not found")
    updates = body.model_dump(exclude_none=True)
    if "content" in updates:
        _validate_decoder_yaml(updates["content"])
    for field, value in updates.items():
        setattr(decoder, field, value)
    await db.commit()
    await db.refresh(decoder)
    background.add_task(audit_log, db, current_user.id, "decoder_updated", "decoder", str(decoder_id))
    return DecoderOut.model_validate(decoder)

@router.delete("/{decoder_id}", status_code=204)
async def delete_decoder(
    decoder_id: UUID,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("decoders:delete"))],
):
    result = await db.execute(select(Decoder).where(Decoder.id == decoder_id))
    decoder = result.scalar_one_or_none()
    if not decoder:
        raise HTTPException(status_code=404, detail="Decoder not found")
    await db.delete(decoder)
    await db.commit()
    background.add_task(audit_log, db, current_user.id, "decoder_deleted", "decoder", str(decoder_id))

@router.post("/test", response_model=DecoderTestResponse)
async def test_decoder(body: DecoderTestRequest, _=Depends(require_permission("decoders:create"))):
    try:
        decoder_def = yaml.safe_load(body.content)
        pattern = decoder_def.get("pattern", "")
        match = re.search(pattern, body.raw_message)
        if not match:
            return DecoderTestResponse(matched=False)
        groups = match.groupdict()
        fields_map = decoder_def.get("fields", {})
        decoded = {}
        for field_name, source in fields_map.items():
            decoded[field_name] = groups.get(source, source)
        return DecoderTestResponse(matched=True, decoded_fields=decoded)
    except Exception as e:
        return DecoderTestResponse(matched=False, error=str(e))

def _validate_decoder_yaml(content: str):
    try:
        parsed = yaml.safe_load(content)
        if not isinstance(parsed, dict):
            raise ValueError("Decoder must be a YAML mapping")
        if "pattern" not in parsed:
            raise ValueError("Decoder must have a 'pattern' field")
    except yaml.YAMLError as e:
        raise HTTPException(status_code=422, detail=f"Invalid YAML: {e}")
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
```

- [ ] **Step 3: Write decoder route test**

```python
# tests/server-api/test_decoder_route.py
import pytest
import yaml

def test_decoder_test_regex_match():
    import re
    content = yaml.dump({
        "name": "test",
        "log_type": "linux_auth",
        "type": "regex",
        "pattern": r"Failed password for (?P<user>\S+) from (?P<src_ip>\S+)",
        "fields": {"user.name": "user", "source.ip": "src_ip"}
    })
    raw = "May 21 sshd: Failed password for root from 1.2.3.4 port 22"
    decoder_def = yaml.safe_load(content)
    match = re.search(decoder_def["pattern"], raw)
    assert match is not None
    groups = match.groupdict()
    assert groups["user"] == "root"
    assert groups["src_ip"] == "1.2.3.4"

def test_decoder_test_no_match():
    import re
    pattern = r"Failed password for (?P<user>\S+)"
    raw = "Accepted publickey for admin"
    assert re.search(pattern, raw) is None
```

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/server-api/test_decoder_route.py -v
```

Expected: 2 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add server-api/app/api/routes/rules.py server-api/app/api/routes/decoders.py tests/server-api/test_decoder_route.py
git commit -m "feat: add rules and decoders CRUD + test endpoints"
```

---

## Task 15: Webhooks & System Routes

**Files:**
- Create: `server-api/app/api/routes/webhooks.py`
- Create: `server-api/app/api/routes/system.py`
- Create: `server-api/app/core/sigma.py`

- [ ] **Step 1: Write webhooks.py**

```python
# server-api/app/api/routes/webhooks.py
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import require_permission, get_current_user
from app.models.models import User, WebhookConfig
from app.schemas.schemas import PaginatedResponse, WebhookCreate, WebhookOut, WebhookUpdate
from app.services.audit import audit_log

router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])

@router.get("", response_model=PaginatedResponse)
async def list_webhooks(
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(require_permission("agents:manage")),
    page: int = 1, page_size: int = 25,
):
    q = select(WebhookConfig)
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    result = await db.execute(q.offset((page - 1) * page_size).limit(page_size))
    return PaginatedResponse(total=total, page=page, page_size=page_size,
                             items=[WebhookOut.model_validate(w) for w in result.scalars().all()])

@router.post("", response_model=WebhookOut, status_code=201)
async def create_webhook(
    body: WebhookCreate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("agents:manage"))],
):
    webhook = WebhookConfig(**body.model_dump())
    db.add(webhook)
    await db.commit()
    await db.refresh(webhook)
    background.add_task(audit_log, db, current_user.id, "webhook_created", "webhook", str(webhook.id))
    return WebhookOut.model_validate(webhook)

@router.put("/{webhook_id}", response_model=WebhookOut)
async def update_webhook(
    webhook_id: UUID, body: WebhookUpdate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("agents:manage"))],
):
    result = await db.execute(select(WebhookConfig).where(WebhookConfig.id == webhook_id))
    webhook = result.scalar_one_or_none()
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")
    for field, value in body.model_dump(exclude_none=True).items():
        setattr(webhook, field, value)
    await db.commit()
    await db.refresh(webhook)
    background.add_task(audit_log, db, current_user.id, "webhook_updated", "webhook", str(webhook_id))
    return WebhookOut.model_validate(webhook)

@router.delete("/{webhook_id}", status_code=204)
async def delete_webhook(
    webhook_id: UUID,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("agents:manage"))],
):
    result = await db.execute(select(WebhookConfig).where(WebhookConfig.id == webhook_id))
    webhook = result.scalar_one_or_none()
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")
    await db.delete(webhook)
    await db.commit()
    background.add_task(audit_log, db, current_user.id, "webhook_deleted", "webhook", str(webhook_id))
```

- [ ] **Step 2: Write sigma.py (used by rule test endpoint)**

```python
# server-api/app/core/sigma.py
import re
from typing import Any

def _match_value(field_value: Any, condition_value: Any) -> bool:
    if field_value is None:
        return False
    fv = str(field_value)
    if isinstance(condition_value, list):
        return any(_match_value(field_value, v) for v in condition_value)
    cv = str(condition_value)
    return fv == cv

def _match_field(field_key: str, condition_value: Any, event: dict) -> bool:
    if "|" in field_key:
        field, modifier = field_key.split("|", 1)
    else:
        field, modifier = field_key, None

    field_value = event.get(field) or event.get("decoded_fields", {}).get(field)

    if isinstance(condition_value, list):
        return any(_match_field_with_modifier(field_value, v, modifier) for v in condition_value)
    return _match_field_with_modifier(field_value, condition_value, modifier)

def _match_field_with_modifier(field_value: Any, condition_value: Any, modifier: str | None) -> bool:
    if field_value is None:
        return False
    fv = str(field_value)
    cv = str(condition_value)
    if modifier is None:
        return fv == cv
    elif modifier == "contains":
        return cv in fv
    elif modifier == "startswith":
        return fv.startswith(cv)
    elif modifier == "endswith":
        return fv.endswith(cv)
    elif modifier == "re":
        return bool(re.search(cv, fv))
    return fv == cv

def _evaluate_selection(selection: dict, event: dict) -> bool:
    return all(_match_field(k, v, event) for k, v in selection.items())

def evaluate_rule(rule_def: dict, event: dict) -> bool:
    detection = rule_def.get("detection", {})
    condition_str = detection.get("condition", "selection")

    named_selections: dict[str, bool] = {}
    for key, value in detection.items():
        if key == "condition":
            continue
        if isinstance(value, dict):
            named_selections[key] = _evaluate_selection(value, event)

    condition_str = condition_str.strip()
    return _eval_condition(condition_str, named_selections)

def _eval_condition(expr: str, selections: dict[str, bool]) -> bool:
    expr = expr.strip()
    if " or " in expr:
        parts = [p.strip() for p in expr.split(" or ")]
        return any(_eval_condition(p, selections) for p in parts)
    if " and " in expr:
        parts = [p.strip() for p in expr.split(" and ")]
        return all(_eval_condition(p, selections) for p in parts)
    if expr.startswith("not "):
        return not _eval_condition(expr[4:].strip(), selections)
    return selections.get(expr, False)
```

- [ ] **Step 3: Write system.py**

```python
# server-api/app/api/routes/system.py
import time
from fastapi import APIRouter
from fastapi.responses import PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from app.core.database import engine
from app.core.redis_client import get_redis

router = APIRouter(tags=["system"])
_start_time = time.time()

@router.get("/health")
async def health():
    redis = await get_redis()
    checks = {"postgres": "ok", "redis": "ok"}
    try:
        async with engine.connect() as conn:
            await conn.execute(__import__("sqlalchemy").text("SELECT 1"))
    except Exception:
        checks["postgres"] = "error"
    try:
        await redis.ping()
    except Exception:
        checks["redis"] = "error"
    status = "ok" if all(v == "ok" for v in checks.values()) else "degraded"
    return {"status": status, **checks, "uptime_seconds": int(time.time() - _start_time)}

@router.get("/metrics", response_class=PlainTextResponse)
async def metrics():
    return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)
```

- [ ] **Step 4: Commit**

```bash
git add server-api/app/api/routes/webhooks.py server-api/app/api/routes/system.py server-api/app/core/sigma.py
git commit -m "feat: add webhooks, system health/metrics, and sigma evaluator"
```

---

## Task 16: Main App Entry Point

**Files:**
- Create: `server-api/app/main.py`

- [ ] **Step 1: Write main.py**

```python
# server-api/app/main.py
import structlog
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.api.routes import auth, users, agents, ingest, logs, events, alerts, rules, decoders, webhooks, system

structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(
        __import__("logging").getLevelName(settings.LOG_LEVEL.upper())
    ),
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield

app = FastAPI(title="SIEM Platform API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

for router in [
    auth.router, users.router, agents.router, ingest.router,
    logs.router, events.router, alerts.router, rules.router,
    decoders.router, webhooks.router, system.router,
]:
    app.include_router(router)
```

- [ ] **Step 2: Write conftest.py for tests**

```python
# tests/server-api/conftest.py
import pytest
import asyncio

@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()
```

- [ ] **Step 3: Commit**

```bash
git add server-api/app/main.py tests/server-api/conftest.py
git commit -m "feat: add FastAPI main app entry point"
```

---

## Task 17: End-to-End API Smoke Test

- [ ] **Step 1: Start services**

```bash
cp .env.example .env
docker compose up -d postgres redis
sleep 5
cd server-api && DATABASE_URL="postgresql+asyncpg://soc:soc@localhost:5432/soc_platform" \
  REDIS_URL="redis://localhost:6379/0" \
  uvicorn app.main:app --host 0.0.0.0 --port 8000 &
sleep 3
```

- [ ] **Step 2: Test login**

```bash
curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' | python3 -m json.tool
```

Expected: `{"access_token": "eyJ...", "token_type": "bearer"}`

- [ ] **Step 3: Test health**

```bash
curl -s http://localhost:8000/health | python3 -m json.tool
```

Expected: `{"status": "ok", "postgres": "ok", "redis": "ok", ...}`

- [ ] **Step 4: Test agent enrollment**

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s -X POST http://localhost:8000/api/agent/enroll \
  -H "Content-Type: application/json" \
  -d '{"enrollment_token":"bootstrap-token","hostname":"test-host","version":"1.0.0","group":"default","name":"test-agent","log_sources":[{"path":"/var/log/auth.log","log_type":"linux_auth"}]}' \
  | python3 -m json.tool
```

Expected: `{"agent_id": "...", "agent_token": "..."}`

- [ ] **Step 5: Commit**

```bash
# stop test server
kill %1 2>/dev/null || true
git add -A
git commit -m "feat: complete server-api - all routes implemented and smoke tested"
```
