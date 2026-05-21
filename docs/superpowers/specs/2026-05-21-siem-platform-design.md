# SIEM Platform — Design Spec
**Date:** 2026-05-21  
**Status:** Approved  

---

## Overview

A modular, production-grade SIEM platform. Agents tail log files on endpoints and ship logs to a central API. The API enqueues logs to Redis Streams. A Python worker consumes the stream, decodes logs with a regex decoder engine, matches against Sigma-style rules, generates alerts, and triggers webhook notifications. A React dashboard provides full visibility and management.

---

## 1. System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Host Machine                            │
│                                                                 │
│  ┌──────────┐   HTTP POST    ┌─────────────┐                   │
│  │  Agent   │ ─────────────▶ │  server-api │ ◀── Dashboard     │
│  │  (Go)    │   /ingest/log  │  (FastAPI)  │     (React+Vite)  │
│  └──────────┘                └──────┬──────┘                   │
│   • tail log files                  │ XADD                     │
│   • heartbeat + config sync         ▼                          │
│   • fsnotify config reload   ┌─────────────┐                   │
│   • buffer + retry           │    Redis    │                   │
│   • enrollment token         │  Streams    │                   │
│                              └──────┬──────┘                   │
│                                     │ XREADGROUP               │
│                                     ▼                          │
│                              ┌─────────────┐                   │
│                              │   Worker    │                   │
│                              │  (Python)   │                   │
│                              │  ─────────  │                   │
│                              │  Decode     │                   │
│                              │  Sigma      │                   │
│                              │  Alert      │                   │
│                              └──────┬──────┘                   │
│                                     │                          │
│                              ┌──────▼──────┐                   │
│                              │ PostgreSQL  │                   │
│                              └─────────────┘                   │
│                                                                 │
│  Nginx (reverse proxy) → dashboard:3000 + server-api:8000      │
└─────────────────────────────────────────────────────────────────┘
```

### Services

| Service | Language/Runtime | Internal Port | Description |
|---|---|---|---|
| `postgres` | PostgreSQL 16 | 5432 | Primary database |
| `redis` | Redis 7 Alpine | 6379 | Message queue (Streams) + suppression cache |
| `server-api` | Python / FastAPI | 8000 | REST API, auth, ingest |
| `worker` | Python (asyncio) | 8001 (health only) | Log pipeline processor |
| `dashboard` | React+Vite → nginx | — | Frontend SPA |
| `nginx` | nginx:alpine | 80 / 443 | Reverse proxy |
| `agent-demo` | Go | — | Demo agent on host logs |

All services share Docker network `siem-net`.

---

## 2. Database Schema

### Auth & Users
```sql
roles               — id, name, created_at, updated_at
permissions         — id, name, created_at, updated_at
role_permissions    — role_id, permission_id
users               — id, username, email, password_hash, role_id, group_id,
                      is_active, created_at, updated_at
```

### Agents
```sql
agents              — id, name, hostname, group_id, token_hash, version,
                      status, last_seen_at, enrolled_at, created_at, updated_at
agent_log_sources   — id, agent_id, path, log_type, is_enabled, created_at, updated_at
```

### Logs & Events
```sql
raw_logs            — id, agent_id, log_type, raw_message, received_at
                      (append-only, no updated_at, partition by day)
events              — id, raw_log_id, agent_id, group_id, decoded_fields (JSONB),
                      event_category, event_action, source_ip, user_name, created_at
```

### Detections
```sql
rules               — id, title, description, content (YAML text), level,
                      tags (text[]), mitre_tags (text[]), version, is_enabled,
                      group_id, created_at, updated_at
decoders            — id, name, log_type, content (YAML text), priority,
                      is_enabled, created_at, updated_at
alerts              — id, title, severity, status, rule_id, event_id, agent_id,
                      group_id, source_ip, hostname, assignee_id,
                      created_at, updated_at
alert_notes         — id, alert_id, author_id, content, created_at
```

### Operations
```sql
audit_logs          — id, actor_id, action, resource_type, resource_id,
                      detail (JSONB), created_at
webhook_configs     — id, name, url, is_enabled, group_id, created_at, updated_at
webhook_deliveries  — id, alert_id, webhook_config_id, payload (JSONB), status,
                      attempts, last_attempted_at, created_at, updated_at
```

**Design notes:**
- `raw_logs` has no `updated_at` — immutable append-only
- `events.decoded_fields` is JSONB — flexible without schema migrations
- `group_id` on `agents`, `events`, `alerts`, `rules`, `webhook_configs` enables tenant isolation
- Rules and decoders store raw YAML in DB — no volume mounts required at runtime
- Seeds from `/rules/*.yaml` and `/decoders/*.yaml` on first worker startup

---

## 3. API Endpoints

### Auth
```
POST   /api/auth/login
POST   /api/auth/refresh
GET    /api/auth/me
```

### Users
```
GET    /api/users
POST   /api/users
PUT    /api/users/{id}
DELETE /api/users/{id}
```

### Agents
```
GET    /api/agents
POST   /api/agent/enroll
PUT    /api/agents/{id}
DELETE /api/agents/{id}
GET    /api/agents/{id}/log-sources
POST   /api/agents/{id}/log-sources
PUT    /api/agents/{id}/log-sources/{source_id}
DELETE /api/agents/{id}/log-sources/{source_id}
```

### Logs & Events
```
GET    /api/logs
GET    /api/events
```

### Alerts
```
GET    /api/alerts
PUT    /api/alerts/{id}
POST   /api/alerts/{id}/notes
```

### Rules
```
GET    /api/rules
POST   /api/rules
PUT    /api/rules/{id}
DELETE /api/rules/{id}
POST   /api/rules/test
```

### Decoders
```
GET    /api/decoders
POST   /api/decoders
PUT    /api/decoders/{id}
DELETE /api/decoders/{id}
POST   /api/decoders/test
```

### Webhooks
```
GET    /api/webhooks
POST   /api/webhooks
PUT    /api/webhooks/{id}
DELETE /api/webhooks/{id}
```

### Ingest (agent-token protected)
```
POST   /api/ingest/log
POST   /api/ingest/heartbeat
```

### System
```
GET    /health
GET    /metrics
```

---

## 4. Auth & RBAC

### JWT Flow
- Login → `access_token` (15 min) + `refresh_token` (7 days, httpOnly cookie)
- All API calls: `Authorization: Bearer <access_token>`
- On 401: POST `/api/auth/refresh` (reads cookie) → new access_token
- Agent calls: `X-Agent-Token: <token>` header (bcrypt-hashed in `agents.token_hash`)

### Enrollment Flow
```
Agent → POST /api/agent/enroll { enrollment_token, hostname, version, group, log_sources }
Server validates enrollment_token (env: AGENT_ENROLLMENT_TOKEN)
Server creates agents row + agent_log_sources rows from initial config
Server returns unique agent_token
Agent stores token, uses X-Agent-Token for all subsequent calls
```

### Heartbeat + Config Sync
```
Agent → POST /api/ingest/heartbeat { agent_id, status, version, buffer_dropped }
Server response → { config_hash: "sha256...", log_sources: [{path, log_type, is_enabled}] }
Agent compares config_hash — if changed: hot-reload log tailers without restart
```

### RBAC Permission Matrix

| Permission | superadmin | admin | analyst | viewer |
|---|:---:|:---:|:---:|:---:|
| users:manage | ✓ | — | — | — |
| agents:manage | ✓ | ✓ | — | — |
| rules:create | ✓ | ✓ | — | — |
| rules:update | ✓ | ✓ | — | — |
| rules:delete | ✓ | ✓ | — | — |
| decoders:create | ✓ | ✓ | — | — |
| decoders:update | ✓ | ✓ | — | — |
| decoders:delete | ✓ | ✓ | — | — |
| logs:read | ✓ | ✓ | ✓ | ✓ |
| alerts:read | ✓ | ✓ | ✓ | ✓ |
| alerts:update | ✓ | ✓ | ✓ | — |

### Group Isolation
- Each user belongs to exactly one group (or is superadmin = no filter)
- `get_scoped_group()` FastAPI dependency injects group filter into all queries
- Superadmin bypasses all group filters

### Audit Logging
Fired as FastAPI background task (never blocks response) for:
- login success/fail, user create/update/delete
- rule create/update/delete, decoder create/update/delete
- alert update, agent enroll/revoke, agent log source changes

---

## 5. Worker Pipeline

### Startup Sequence
```
1. Connect PostgreSQL + Redis
2. Load enabled decoders from DB into memory (sorted by priority asc)
3. Load enabled rules from DB into memory
4. Seed decoders/rules from YAML files if DB tables are empty
5. Create Redis Stream 'siem:logs' + consumer group 'siem-workers' if not exists
6. Start background reload loop (every 60s)
7. Start webhook retry loop (every 30s)
8. Start health/metrics HTTP server on :8001
9. Start main XREADGROUP consume loop
```

### Per-Message Pipeline
```
XREADGROUP siem-workers worker-{hostname} > siem:logs COUNT 10 BLOCK 5000
  │
  ▼
Deserialize: { agent_id, log_type, raw_message, received_at, hostname }
  │
  ▼
Save → raw_logs (async)
  │
  ▼
Decoder Engine:
  iterate decoders ordered by priority where log_type matches
  first match: run re.match with named groups
  map captured groups + static fields → normalized dict
  on no match: use empty decoded_fields
  │
  ▼
Save → events (decoded_fields as JSONB)
  │
  ▼
Sigma Engine:
  for each enabled rule:
    filter by logsource.product/category (skip non-matching)
    evaluate detection.selection conditions
    evaluate condition expression
    if threshold: COUNT recent events in window (Redis ZSET)
    if suppression: check Redis key siem:suppress:{rule_id}:{src_ip}
    on match: generate alert, set suppression key with TTL
  │
  ▼
Alert Manager:
  save → alerts (status: new)
  enqueue → webhook_deliveries rows for each enabled webhook_config
  │
  ▼
XACK message
on exception: log error, XACK, write to siem:logs:failed stream
```

### Decoder YAML Format
```yaml
name: linux_auth_failed
log_type: linux_auth
type: regex
priority: 10
enabled: true
pattern: 'Failed password for (?P<user>\S+) from (?P<src_ip>\S+) port (?P<port>\d+)'
fields:
  event.category: authentication
  event.action: login_failed
  source.ip: src_ip        # value = name of captured group
  user.name: user
  source.port: port
```

### Sigma YAML Format
```yaml
title: SSH Brute Force
id: rule-ssh-brute-force
logsource:
  product: linux
detection:
  selection:
    event.action: login_failed
  condition: selection
threshold:
  count: 5
  timewindow: 300          # seconds
  group_by: source.ip
suppression:
  timewindow: 3600         # re-alert suppression window (seconds)
level: high
tags:
  - attack.credential_access
  - attack.t1110
```

### Supported Sigma Conditions
- `exact match` — `field: value`
- `contains` — `field|contains: value`
- `startswith` — `field|startswith: value`
- `endswith` — `field|endswith: value`
- `list match` — `field: [val1, val2]`
- `condition` — `selection`, `not selection`, `sel1 and sel2`, `sel1 or sel2`

### Webhook Retry
- Runs as asyncio task inside worker process
- Every 30s: query `webhook_deliveries` where status != 'delivered' and attempts < 5
- Backoff: `attempts² × 30s`
- Max 5 attempts, then status = 'failed'

---

## 6. Go Agent

### Package Structure
```
agent/
├── cmd/agent/main.go
├── internal/
│   ├── config/        — YAML loader + fsnotify watcher
│   ├── tailer/        — log file tailing (one goroutine per source)
│   ├── client/        — HTTP client (retry + backoff)
│   ├── heartbeat/     — heartbeat loop + config sync
│   ├── buffer/        — in-memory ring buffer (10k entries default)
│   └── enrollment/    — first-run enrollment
├── config.yaml
├── go.mod
└── Dockerfile
```

### Goroutine Model
```
main
├── enrollment (once at startup, blocks until success)
├── heartbeat loop (every 30s)
│    └── on config_hash change → signal tailer manager
├── tailer manager
│    ├── tailer goroutine: source 1
│    ├── tailer goroutine: source 2
│    └── ... (starts/stops goroutines dynamically)
├── sender loop (drains buffer → POST /api/ingest/log)
├── fsnotify watcher (config.yaml: agent.name, agent.group, server.url only)
└── signal handler (SIGTERM/SIGINT → flush buffer → exit)
```

### Buffer Behavior
- Ring buffer: 10,000 entries max (configurable via `agent.buffer_size`)
- On server down: tailers write to buffer, sender retries with exponential backoff (1s → 2s → 4s → max 60s)
- On buffer full: oldest entries dropped, `buffer_dropped` counter incremented
- `buffer_dropped` reported in next heartbeat payload
- On reconnect: buffer drains FIFO before new entries

### Log Payload
```json
{
  "agent_id": "agent-001",
  "agent_token": "...",
  "log_type": "linux_auth",
  "raw_message": "May 21 10:23:01 host sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2",
  "received_at": "2026-05-21T10:23:01.123Z",
  "hostname": "webserver-prod"
}
```

### Bootstrap Config (config.yaml)
```yaml
agent:
  id: agent-001
  name: webserver-prod
  group: production
  token: ""              # populated after enrollment
  buffer_size: 10000

server:
  url: http://server-api:8000
  heartbeat_interval: 30

logs:                    # used only for initial enrollment seed
  - path: /host/var/log/auth.log
    type: linux_auth
  - path: /host/var/log/syslog
    type: syslog
```

---

## 7. Dashboard

### Tech Stack
- React 18 + Vite + TypeScript
- TailwindCSS + shadcn/ui
- Dark mode default (`dark` class on `<html>`, toggle available)
- Zustand (auth state), TanStack Query (server state + auto-refresh)
- axios (HTTP client with interceptors for token refresh)
- CodeMirror (YAML editor for rules/decoders)

### Pages & Permissions

| Page | Route | Min Role | Auto-refresh |
|---|---|---|---|
| Login | `/login` | public | — |
| Dashboard | `/` | viewer | 30s |
| Agents | `/agents` | viewer | 30s |
| Agent Log Sources | `/agents/:id/sources` | admin | — |
| Logs | `/logs` | viewer | 15s |
| Events | `/events` | viewer | 15s |
| Alerts | `/alerts` | viewer | 15s |
| Alert Detail | `/alerts/:id` | viewer | — |
| Rules | `/rules` | viewer | — |
| Decoders | `/decoders` | viewer | — |
| Users | `/users` | superadmin | — |
| Webhooks | `/webhooks` | admin | — |

### Key UI Patterns
- All tables: column sort, text search, date-range filter, pagination (25/50/100)
- Severity badges: critical=red, high=orange, medium=yellow, low=blue, info=gray
- Status badges: new=blue, in_progress=yellow, resolved=green, false_positive=gray
- Alert detail modal: full fields + notes thread + status/assignee controls
- YAML editor modal: CodeMirror + validate button (calls `/test` endpoint)
- Decoder test panel: paste raw log → see decoded output live
- Sidebar: menu items not rendered (not just hidden) for unauthorized roles
- Toast notifications on all mutations

---

## 8. Docker & Nginx

### Compose Files
- `docker-compose.yml` — base: all services, healthchecks, restart: unless-stopped
- `docker-compose.dev.yml` — source volume mounts, host port exposure (5432, 6379), vite dev server, LOG_LEVEL=debug
- `docker-compose.prod.yml` — resource limits, SSL in nginx, LOG_LEVEL=info

### Nginx
```
/api/*  → proxy_pass http://server-api:8000
/*      → proxy_pass http://dashboard (static files served by nginx in container)

gzip: text/html, application/json, text/css, application/javascript
security headers: X-Frame-Options DENY, X-Content-Type-Options nosniff, HSTS
client_max_body_size: 10m
proxy_read_timeout: 300
```

### Healthchecks
All services define Docker `HEALTHCHECK`. Server-api and worker expose:
```json
GET /health → { "status": "ok", "postgres": "ok", "redis": "ok", "uptime_seconds": 3600 }
```

### Observability (Prometheus text at /metrics)
```
siem_logs_ingested_total
siem_events_decoded_total
siem_decode_failures_total
siem_alerts_generated_total{severity, rule_id}
siem_sigma_matches_total{rule_id}
siem_worker_queue_lag
siem_webhook_deliveries_total{status}
siem_active_agents
```

Structured JSON logging: Go uses `slog`, Python uses `structlog`.

---

## 9. Seed Data

### Default User
- username: `admin`, password: `admin123`, role: `superadmin`
- **Change immediately in production**

### Sample Decoders (seeded from /decoders/)
- `linux_auth_failed` — SSH failed password
- `linux_sudo` — sudo command execution
- `nginx_access` — nginx access log
- `generic_syslog` — fallback syslog

### Sample Rules (seeded from /rules/)
- SSH Failed Login (medium)
- SSH Brute Force — threshold 5 in 5min (high)
- Sudo Command Executed (low)
- Nginx Suspicious Path (medium)
- Access to /.env (high)
- Access to /etc/passwd (high)
- WordPress Admin Probing (medium)

---

## 10. Project Structure

```
siem-platform/
├── docker-compose.yml
├── docker-compose.dev.yml
├── docker-compose.prod.yml
├── .env.example
├── README.md
├── nginx/
│   ├── nginx.conf
│   └── nginx.prod.conf
├── db/
│   └── init.sql
├── decoders/
│   ├── linux_auth_failed.yaml
│   ├── linux_sudo.yaml
│   ├── nginx_access.yaml
│   └── generic_syslog.yaml
├── rules/
│   ├── ssh_failed_login.yaml
│   ├── ssh_brute_force.yaml
│   ├── sudo_executed.yaml
│   ├── nginx_suspicious_path.yaml
│   ├── access_env_file.yaml
│   ├── access_etc_passwd.yaml
│   └── wordpress_admin_probe.yaml
├── agent/
│   ├── cmd/agent/main.go
│   ├── internal/
│   │   ├── config/
│   │   ├── tailer/
│   │   ├── client/
│   │   ├── heartbeat/
│   │   ├── buffer/
│   │   └── enrollment/
│   ├── config.yaml
│   ├── go.mod
│   └── Dockerfile
├── server-api/
│   ├── app/
│   │   ├── main.py
│   │   ├── api/routes/
│   │   ├── core/
│   │   ├── models/
│   │   ├── schemas/
│   │   └── services/
│   ├── requirements.txt
│   └── Dockerfile
├── worker/
│   ├── worker/
│   │   ├── main.py
│   │   ├── consumer.py
│   │   ├── decoder_engine.py
│   │   ├── sigma_engine.py
│   │   ├── alert_manager.py
│   │   └── webhook_sender.py
│   ├── requirements.txt
│   └── Dockerfile
└── dashboard/
    ├── src/
    │   ├── pages/
    │   ├── components/
    │   ├── stores/
    │   ├── hooks/
    │   ├── api/
    │   └── types/
    ├── package.json
    ├── vite.config.ts
    ├── tailwind.config.ts
    └── Dockerfile
```

---

## 11. Key Decisions Summary

| Decision | Choice | Reason |
|---|---|---|
| Message queue | Redis Streams | Already in .env.example, doubles as suppression cache |
| Worker architecture | Single process, consumer group | Horizontally scalable, simple to debug |
| Config sync | Heartbeat response | Works through NAT, no push infrastructure needed |
| Group isolation | One group per user | Simple query filter, no join complexity |
| Rules/decoders storage | DB (YAML text) | No volume mount dependency, UI-editable |
| Webhook delivery | Retry with backoff | Production reliability requirement |
| Agent logging | structlog (Python), slog (Go) | JSON structured output |
| Dashboard theme | Dark mode default | SIEM/SOC convention |
