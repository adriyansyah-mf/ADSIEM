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
