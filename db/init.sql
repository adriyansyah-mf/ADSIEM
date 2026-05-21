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
    role_id       INTEGER NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
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
CREATE INDEX idx_alerts_assignee_id ON alerts(assignee_id);
CREATE INDEX idx_agents_group_id ON agents(group_id);
CREATE INDEX idx_rules_group_id ON rules(group_id);

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

-- ─── Cases ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS cases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',
    status VARCHAR(30) NOT NULL DEFAULT 'open',
    alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,
    assignee_id UUID REFERENCES users(id) ON DELETE SET NULL,
    ai_reasoning TEXT,
    ioc_data JSONB NOT NULL DEFAULT '{}',
    search_intel JSONB NOT NULL DEFAULT '{}',
    created_by_ai BOOLEAN NOT NULL DEFAULT false,
    escalated_at TIMESTAMPTZ,
    group_id VARCHAR(100) NOT NULL DEFAULT 'default',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS case_notes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    author_id UUID REFERENCES users(id) ON DELETE SET NULL,
    content TEXT NOT NULL,
    is_ai_generated BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cases_group_id ON cases(group_id);
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_created_at ON cases(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_case_notes_case_id ON case_notes(case_id);

CREATE TABLE IF NOT EXISTS hygiene_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    hostname VARCHAR(255),
    group_id VARCHAR(100) NOT NULL DEFAULT 'default',
    os_name VARCHAR(100),
    os_version VARCHAR(100),
    kernel VARCHAR(100),
    arch VARCHAR(20),
    uptime_seconds BIGINT,
    cpu_count INT,
    mem_total_mb BIGINT,
    mem_used_mb BIGINT,
    disk_partitions JSONB NOT NULL DEFAULT '[]',
    open_ports JSONB NOT NULL DEFAULT '[]',
    users JSONB NOT NULL DEFAULT '[]',
    hygiene_score INT NOT NULL DEFAULT 100,
    issues JSONB NOT NULL DEFAULT '[]',
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_hygiene_agent_id ON hygiene_snapshots(agent_id);
CREATE INDEX IF NOT EXISTS idx_hygiene_collected_at ON hygiene_snapshots(collected_at DESC);

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
    ('alerts:update'),
    ('cases:manage'),
    ('cases:view');

-- superadmin: all permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p WHERE r.name = 'superadmin';

-- admin: agents:manage + rules:* + decoders:* + logs:read + alerts:read + alerts:update + cases:manage + cases:view
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'admin'
  AND p.name IN (
    'agents:manage','rules:create','rules:update','rules:delete',
    'decoders:create','decoders:update','decoders:delete',
    'logs:read','alerts:read','alerts:update','cases:manage','cases:view'
  );

-- analyst: logs:read + alerts:read + alerts:update + cases:manage + cases:view
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'analyst'
  AND p.name IN ('logs:read','alerts:read','alerts:update','cases:manage','cases:view');

-- viewer: logs:read + alerts:read + cases:view
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'viewer'
  AND p.name IN ('logs:read','alerts:read','cases:view');

-- default admin user (password: admin123, argon2id) — CHANGE IN PRODUCTION
INSERT INTO users (username, email, password_hash, role_id, group_id)
SELECT
    'admin',
    'admin@siem.local',
    '$argon2id$v=19$m=65536,t=3,p=4$Pcd47917z5kTQiglRIgxpg$GkRs6NFVHR5v7qWbOwyN6/6afXgLoVBV6nB6Q1XMWv4',
    r.id,
    'default'
FROM roles r WHERE r.name = 'superadmin';

-- ─── Platform Settings ───────────────────────────────────────────

CREATE TABLE IF NOT EXISTS platform_settings (
    key         VARCHAR(100) PRIMARY KEY,
    value       TEXT,
    is_secret   BOOLEAN NOT NULL DEFAULT false,
    description TEXT,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by  UUID REFERENCES users(id) ON DELETE SET NULL
);

-- Default settings (value empty — user must fill in)
INSERT INTO platform_settings (key, value, is_secret, description) VALUES
    ('groq_api_key',        '',    true,  'Groq API key for AI SOC analyst (get from console.groq.com)'),
    ('groq_model',          'llama-3.3-70b-versatile', false, 'Groq model ID'),
    ('searxng_url',         'http://searxng:8080', false, 'Internal SearXNG URL for threat intel search'),
    ('ai_analyst_enabled',  'true', false, 'Enable AI SOC L1 analyst for new alerts'),
    ('virustotal_api_key',  '',    true,  'VirusTotal API key (free tier: 500 req/day) — virustotal.com/gui/my-apikey'),
    ('abuseipdb_api_key',   '',    true,  'AbuseIPDB API key (free tier: 1000 req/day) — abuseipdb.com/account/api'),
    ('otx_api_key',         '',    true,  'AlienVault OTX API key (free) — otx.alienvault.com/api'),
    ('greynoise_api_key',   '',    true,  'GreyNoise API key (optional — community endpoint used if empty)')
ON CONFLICT (key) DO NOTHING;

-- settings:manage permission
INSERT INTO permissions (name) VALUES ('settings:manage') ON CONFLICT DO NOTHING;

-- superadmin and admin get settings:manage
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name IN ('superadmin', 'admin') AND p.name = 'settings:manage'
ON CONFLICT DO NOTHING;

-- ─── UEBA ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ueba_feature_snapshots (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_type    VARCHAR(20)  NOT NULL,
    entity_value   VARCHAR(255) NOT NULL,
    group_id       VARCHAR(100) NOT NULL DEFAULT 'default',
    features       JSONB        NOT NULL,
    snapshot_hour  TIMESTAMPTZ  NOT NULL,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ueba_snap_unique ON ueba_feature_snapshots(entity_type, entity_value, group_id, snapshot_hour);
CREATE INDEX IF NOT EXISTS idx_ueba_snap_lookup ON ueba_feature_snapshots(entity_type, snapshot_hour DESC);

CREATE TABLE IF NOT EXISTS ueba_entity_scores (
    entity_type     VARCHAR(20)  NOT NULL,
    entity_value    VARCHAR(255) NOT NULL,
    group_id        VARCHAR(100) NOT NULL DEFAULT 'default',
    risk_score      FLOAT        NOT NULL DEFAULT 0,
    anomaly_count   INTEGER      NOT NULL DEFAULT 0,
    last_anomaly_at TIMESTAMPTZ,
    last_seen_at    TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (entity_type, entity_value)
);
CREATE INDEX IF NOT EXISTS idx_ueba_scores_risk ON ueba_entity_scores(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_ueba_scores_group ON ueba_entity_scores(group_id);

CREATE TABLE IF NOT EXISTS ueba_anomalies (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_type    VARCHAR(20)  NOT NULL,
    entity_value   VARCHAR(255) NOT NULL,
    group_id       VARCHAR(100) NOT NULL DEFAULT 'default',
    anomaly_score  FLOAT        NOT NULL,
    risk_score     FLOAT        NOT NULL,
    features       JSONB        NOT NULL,
    alert_id       UUID         REFERENCES alerts(id) ON DELETE SET NULL,
    detected_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ueba_anom_entity ON ueba_anomalies(entity_type, entity_value, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_ueba_snap_group ON ueba_feature_snapshots(group_id);
CREATE INDEX IF NOT EXISTS idx_ueba_anom_group ON ueba_anomalies(group_id);

INSERT INTO platform_settings (key, value, is_secret, description) VALUES
    ('ueba_enabled',            'true',  false, 'Enable UEBA ML anomaly detection'),
    ('ueba_anomaly_threshold',  '-0.1',  false, 'Isolation Forest score threshold (negative = anomalous)')
ON CONFLICT (key) DO NOTHING;
