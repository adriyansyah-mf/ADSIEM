-- db/migrate.sql — run this on existing deployments to apply missing tables
-- Safe to run multiple times (all IF NOT EXISTS)

CREATE TABLE IF NOT EXISTS fim_watch_paths (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    path       TEXT NOT NULL UNIQUE,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_fim_watch_paths_enabled ON fim_watch_paths(is_enabled);

CREATE TABLE IF NOT EXISTS threat_hunts (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ioc_type          VARCHAR(20)  NOT NULL,
    ioc_value         TEXT         NOT NULL,
    status            VARCHAR(20)  NOT NULL DEFAULT 'pending',
    group_id          VARCHAR(64)  NOT NULL DEFAULT 'default',
    alert_count       INTEGER      NOT NULL DEFAULT 0,
    event_count       INTEGER      NOT NULL DEFAULT 0,
    fim_count         INTEGER      NOT NULL DEFAULT 0,
    risk_level        VARCHAR(20),
    timeline          JSONB,
    analysis          TEXT,
    related_alert_ids JSONB,
    created_by        UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    completed_at      TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_threat_hunts_status  ON threat_hunts(status);
CREATE INDEX IF NOT EXISTS idx_threat_hunts_group   ON threat_hunts(group_id);
CREATE INDEX IF NOT EXISTS idx_threat_hunts_created ON threat_hunts(created_at DESC);

CREATE TABLE IF NOT EXISTS fleet_hunts (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name             VARCHAR(255) NOT NULL,
    description      TEXT,
    task_type        VARCHAR(50)  NOT NULL,
    params           JSONB        NOT NULL DEFAULT '{}',
    status           VARCHAR(20)  NOT NULL DEFAULT 'running',
    total_agents     INTEGER      NOT NULL DEFAULT 0,
    completed_agents INTEGER      NOT NULL DEFAULT 0,
    created_by       UUID,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS agent_tasks (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id      UUID REFERENCES agents(id) ON DELETE CASCADE,
    fleet_hunt_id UUID REFERENCES fleet_hunts(id) ON DELETE CASCADE,
    task_type     VARCHAR(50)  NOT NULL,
    params        JSONB        NOT NULL DEFAULT '{}',
    status        VARCHAR(20)  NOT NULL DEFAULT 'pending',
    result        JSONB,
    error         TEXT,
    created_by    UUID,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    completed_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_agent_tasks_agent_status ON agent_tasks(agent_id, status);
CREATE INDEX IF NOT EXISTS idx_agent_tasks_fleet        ON agent_tasks(fleet_hunt_id);

CREATE TABLE IF NOT EXISTS artifacts (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name           VARCHAR(255) UNIQUE NOT NULL,
    description    TEXT,
    task_type      VARCHAR(50)  NOT NULL,
    default_params JSONB        NOT NULL DEFAULT '{}',
    is_enabled     BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS yara_rules (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    content     TEXT         NOT NULL,
    is_enabled  BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash       TEXT NOT NULL UNIQUE,
    label            VARCHAR(255) NOT NULL DEFAULT '',
    group_id         VARCHAR(100) NOT NULL DEFAULT 'default',
    expires_at       TIMESTAMPTZ,
    is_active        BOOLEAN NOT NULL DEFAULT TRUE,
    used_at          TIMESTAMPTZ,
    used_by_agent_id UUID REFERENCES agents(id) ON DELETE SET NULL,
    created_by       UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_active ON enrollment_tokens(is_active, expires_at);

-- Column added later
ALTER TABLE agents ADD COLUMN IF NOT EXISTS is_isolated BOOLEAN NOT NULL DEFAULT FALSE;
