# SIEM Platform — Plan 5: Docker Infrastructure & Nginx

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire all services together with Docker Compose, configure Nginx as reverse proxy, write `.env.example`, and produce a README that covers setup, deployment, enrollment, and API examples.

**Architecture:** Base compose file + dev and prod overrides. All services on `siem-net`. Nginx proxies `/api/*` to server-api and `/*` to dashboard. DB initialized via `init.sql` mounted as postgres entrypoint.

**Tech Stack:** Docker Compose v2, nginx:alpine, PostgreSQL 16, Redis 7

**Prerequisite:** Plans 1–4 must be complete. All Dockerfiles must exist.

---

## File Map

```
siem-platform/
├── .env.example
├── docker-compose.yml
├── docker-compose.dev.yml
├── docker-compose.prod.yml
├── nginx/
│   ├── nginx.conf          — development + base
│   └── nginx.prod.conf     — production (SSL, stricter headers)
└── README.md
```

---

## Task 1: Environment File

**Files:**
- Create: `.env.example`

- [ ] **Step 1: Write .env.example**

```env
# Database
POSTGRES_DB=soc_platform
POSTGRES_USER=soc
POSTGRES_PASSWORD=change-me-in-production
DATABASE_URL=postgresql+asyncpg://soc:change-me-in-production@postgres:5432/soc_platform

# Redis
REDIS_URL=redis://redis:6379/0
REDIS_STREAM_KEY=siem:logs
REDIS_CONSUMER_GROUP=siem-workers

# Auth
JWT_SECRET=change-me-very-long-random-secret
AGENT_ENROLLMENT_TOKEN=change-me-enrollment-token

# Logging
LOG_LEVEL=info

# Dashboard (set at build time for Vite)
VITE_API_URL=http://localhost

# Worker tuning
RELOAD_INTERVAL=60
WEBHOOK_RETRY_INTERVAL=30
MAX_WEBHOOK_ATTEMPTS=5
```

- [ ] **Step 2: Commit**

```bash
git add .env.example
git commit -m "feat: add .env.example with all required variables"
```

---

## Task 2: Nginx Config

**Files:**
- Create: `nginx/nginx.conf`
- Create: `nginx/nginx.prod.conf`

- [ ] **Step 1: Write nginx/nginx.conf**

```nginx
# nginx/nginx.conf
worker_processes auto;
events { worker_connections 1024; }

http {
    include       mime.types;
    default_type  application/octet-stream;
    sendfile      on;
    keepalive_timeout 65;
    client_max_body_size 10m;

    gzip on;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml;
    gzip_min_length 1000;

    upstream server_api {
        server server-api:8000;
    }

    upstream dashboard_app {
        server dashboard:80;
    }

    server {
        listen 80;
        server_name _;

        # Security headers
        add_header X-Frame-Options DENY always;
        add_header X-Content-Type-Options nosniff always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;

        # API proxy
        location /api/ {
            proxy_pass http://server_api;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_read_timeout 300;
        }

        location /health {
            proxy_pass http://server_api;
            proxy_set_header Host $host;
        }

        location /metrics {
            proxy_pass http://server_api;
            proxy_set_header Host $host;
        }

        # Dashboard SPA
        location / {
            proxy_pass http://dashboard_app;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }
    }
}
```

- [ ] **Step 2: Write nginx/nginx.prod.conf**

```nginx
# nginx/nginx.prod.conf
worker_processes auto;
events { worker_connections 2048; }

http {
    include       mime.types;
    default_type  application/octet-stream;
    sendfile      on;
    keepalive_timeout 65;
    client_max_body_size 10m;
    server_tokens off;

    gzip on;
    gzip_types text/plain text/css application/json application/javascript;
    gzip_min_length 1000;

    upstream server_api { server server-api:8000; }
    upstream dashboard_app { server dashboard:80; }

    # Redirect HTTP to HTTPS
    server {
        listen 80;
        server_name _;
        return 301 https://$host$request_uri;
    }

    server {
        listen 443 ssl;
        server_name _;

        ssl_certificate     /etc/nginx/certs/cert.pem;
        ssl_certificate_key /etc/nginx/certs/key.pem;
        ssl_protocols       TLSv1.2 TLSv1.3;
        ssl_ciphers         HIGH:!aNULL:!MD5;

        add_header X-Frame-Options DENY always;
        add_header X-Content-Type-Options nosniff always;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;

        location /api/ {
            proxy_pass http://server_api;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_read_timeout 300;
        }

        location /health { proxy_pass http://server_api; }
        location /metrics { proxy_pass http://server_api; }

        location / {
            proxy_pass http://dashboard_app;
            proxy_set_header Host $host;
        }
    }
}
```

- [ ] **Step 3: Commit**

```bash
git add nginx/
git commit -m "feat: add nginx reverse proxy configs (dev and prod)"
```

---

## Task 3: Base Docker Compose

**Files:**
- Create: `docker-compose.yml`

- [ ] **Step 1: Write docker-compose.yml**

```yaml
# docker-compose.yml
name: siem-platform

services:

  postgres:
    image: postgres:16-alpine
    restart: unless-stopped
    environment:
      POSTGRES_DB: ${POSTGRES_DB:-soc_platform}
      POSTGRES_USER: ${POSTGRES_USER:-soc}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-soc}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./db/init.sql:/docker-entrypoint-initdb.d/init.sql:ro
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER:-soc} -d ${POSTGRES_DB:-soc_platform}"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - siem-net

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - siem-net

  server-api:
    build:
      context: ./server-api
      dockerfile: Dockerfile
    restart: unless-stopped
    environment:
      DATABASE_URL: ${DATABASE_URL:-postgresql+asyncpg://soc:soc@postgres:5432/soc_platform}
      REDIS_URL: ${REDIS_URL:-redis://redis:6379/0}
      JWT_SECRET: ${JWT_SECRET:-change-me}
      AGENT_ENROLLMENT_TOKEN: ${AGENT_ENROLLMENT_TOKEN:-bootstrap-token}
      LOG_LEVEL: ${LOG_LEVEL:-info}
      REDIS_STREAM_KEY: ${REDIS_STREAM_KEY:-siem:logs}
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "python -c \"import httpx; httpx.get('http://localhost:8000/health').raise_for_status()\""]
      interval: 30s
      timeout: 10s
      start_period: 20s
      retries: 3
    networks:
      - siem-net

  worker:
    build:
      context: ./worker
      dockerfile: Dockerfile
    restart: unless-stopped
    environment:
      DATABASE_URL: ${DATABASE_URL:-postgresql+asyncpg://soc:soc@postgres:5432/soc_platform}
      REDIS_URL: ${REDIS_URL:-redis://redis:6379/0}
      REDIS_STREAM_KEY: ${REDIS_STREAM_KEY:-siem:logs}
      REDIS_CONSUMER_GROUP: ${REDIS_CONSUMER_GROUP:-siem-workers}
      DECODERS_DIR: /app/decoders
      RULES_DIR: /app/rules
      LOG_LEVEL: ${LOG_LEVEL:-info}
      RELOAD_INTERVAL: ${RELOAD_INTERVAL:-60}
      WEBHOOK_RETRY_INTERVAL: ${WEBHOOK_RETRY_INTERVAL:-30}
      MAX_WEBHOOK_ATTEMPTS: ${MAX_WEBHOOK_ATTEMPTS:-5}
    volumes:
      - ./decoders:/app/decoders:ro
      - ./rules:/app/rules:ro
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
      server-api:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://localhost:8001/health')\""]
      interval: 30s
      timeout: 10s
      start_period: 30s
      retries: 3
    networks:
      - siem-net

  dashboard:
    build:
      context: ./dashboard
      dockerfile: Dockerfile
      args:
        VITE_API_URL: ""
    restart: unless-stopped
    depends_on:
      - server-api
    networks:
      - siem-net

  nginx:
    image: nginx:alpine
    restart: unless-stopped
    ports:
      - "80:80"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - server-api
      - dashboard
    networks:
      - siem-net

  agent-demo:
    build:
      context: ./agent
      dockerfile: Dockerfile
    restart: unless-stopped
    environment:
      AGENT_ENROLLMENT_TOKEN: ${AGENT_ENROLLMENT_TOKEN:-bootstrap-token}
    volumes:
      - /var/log:/host/var/log:ro
    depends_on:
      server-api:
        condition: service_healthy
    networks:
      - siem-net

volumes:
  postgres_data:
  redis_data:

networks:
  siem-net:
    driver: bridge
```

- [ ] **Step 2: Commit**

```bash
git add docker-compose.yml
git commit -m "feat: add base docker-compose.yml with all services"
```

---

## Task 4: Dev & Prod Compose Overrides

**Files:**
- Create: `docker-compose.dev.yml`
- Create: `docker-compose.prod.yml`

- [ ] **Step 1: Write docker-compose.dev.yml**

```yaml
# docker-compose.dev.yml
# Usage: docker compose -f docker-compose.yml -f docker-compose.dev.yml up
services:

  postgres:
    ports:
      - "5432:5432"

  redis:
    ports:
      - "6379:6379"

  server-api:
    environment:
      LOG_LEVEL: debug
    volumes:
      - ./server-api/app:/app/app:ro
    command: uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

  worker:
    environment:
      LOG_LEVEL: debug
    volumes:
      - ./worker/worker:/app/worker:ro
      - ./decoders:/app/decoders:ro
      - ./rules:/app/rules:ro

  dashboard:
    build:
      context: ./dashboard
      dockerfile: Dockerfile.dev
    ports:
      - "5173:5173"
    volumes:
      - ./dashboard/src:/app/src:ro
    environment:
      VITE_API_URL: http://server-api:8000

  nginx:
    ports:
      - "80:80"
```

- [ ] **Step 2: Write Dockerfile.dev for dashboard**

```dockerfile
# dashboard/Dockerfile.dev
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci
COPY . .
EXPOSE 5173
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
```

- [ ] **Step 3: Write docker-compose.prod.yml**

```yaml
# docker-compose.prod.yml
# Usage: docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
services:

  postgres:
    deploy:
      resources:
        limits:
          memory: 1g
          cpus: '1.0'

  redis:
    deploy:
      resources:
        limits:
          memory: 256m

  server-api:
    deploy:
      replicas: 2
      resources:
        limits:
          memory: 512m
          cpus: '0.5'
    environment:
      LOG_LEVEL: info

  worker:
    deploy:
      replicas: 2
      resources:
        limits:
          memory: 512m
          cpus: '0.5'
    environment:
      LOG_LEVEL: info

  nginx:
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.prod.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/certs:/etc/nginx/certs:ro
```

- [ ] **Step 4: Commit**

```bash
git add docker-compose.dev.yml docker-compose.prod.yml dashboard/Dockerfile.dev
git commit -m "feat: add dev and prod docker-compose overrides"
```

---

## Task 5: Full Stack Smoke Test

- [ ] **Step 1: Copy env and start all services**

```bash
cp .env.example .env
docker compose up -d --build
```

Expected: All services start. Check with:
```bash
docker compose ps
```
All services should show `healthy` or `running`.

- [ ] **Step 2: Wait for healthy**

```bash
docker compose ps --format "table {{.Name}}\t{{.Status}}"
```

Expected: All show `Up` and `(healthy)` within 60 seconds.

- [ ] **Step 3: Test full pipeline**

```bash
# Login
TOKEN=$(curl -s -X POST http://localhost/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo "Token acquired: ${TOKEN:0:20}..."

# Health check
curl -s http://localhost/health | python3 -m json.tool

# List agents (should be 0 initially)
curl -s -H "Authorization: Bearer $TOKEN" http://localhost/api/agents

# Enroll a test agent
AGENT=$(curl -s -X POST http://localhost/api/agent/enroll \
  -H "Content-Type: application/json" \
  -d '{"enrollment_token":"bootstrap-token","hostname":"smoke-test","version":"1.0.0","group":"default","name":"smoke-agent","log_sources":[]}')
echo $AGENT | python3 -m json.tool

AGENT_TOKEN=$(echo $AGENT | python3 -c "import sys,json; print(json.load(sys.stdin)['agent_token'])")

# Send a test log
curl -s -X POST http://localhost/api/ingest/log \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: $AGENT_TOKEN" \
  -d "{\"agent_id\":\"$(echo $AGENT | python3 -c 'import sys,json; print(json.load(sys.stdin)[\"agent_id\"])')\",\"agent_token\":\"$AGENT_TOKEN\",\"log_type\":\"linux_auth\",\"raw_message\":\"May 21 10:00:01 host sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2\",\"received_at\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"hostname\":\"smoke-test\"}"

# Wait for worker to process
sleep 5

# Check alerts
curl -s -H "Authorization: Bearer $TOKEN" http://localhost/api/alerts | python3 -m json.tool
```

Expected: At least one alert with `"title": "SSH Failed Login"` and `"source_ip": "1.2.3.4"`.

- [ ] **Step 4: Verify dashboard**

```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost/
```

Expected: `200`

- [ ] **Step 5: Check worker metrics**

```bash
docker compose exec worker curl -s http://localhost:8001/metrics | grep siem_
```

Expected: Lines like `siem_logs_ingested_total 1.0` and `siem_events_decoded_total 1.0`.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: full stack smoke test passed - pipeline agent→alert verified"
```

---

## Task 6: README

**Files:**
- Create: `README.md`

- [ ] **Step 1: Write README.md**

```markdown
# SIEM Platform

A modular, production-grade Security Information and Event Management (SIEM) platform.

> ⚠️ **Security Warning:** Default credentials (`admin` / `admin123`) are for development only.
> Change `JWT_SECRET`, `POSTGRES_PASSWORD`, `AGENT_ENROLLMENT_TOKEN`, and the admin password immediately in production.

## Architecture

```
Agent (Go) → server-api (FastAPI) → Redis Streams → Worker (Python)
                                                        ↓
                                              decoder → sigma → alert
                                                        ↓
                                                   PostgreSQL
                                                        ↑
                                          Dashboard (React) ← nginx
```

## Services

| Service | Description | Port |
|---|---|---|
| `postgres` | Primary database | 5432 (internal) |
| `redis` | Message queue + suppression cache | 6379 (internal) |
| `server-api` | REST API, auth, ingest | 8000 (internal) |
| `worker` | Log pipeline processor | 8001 (health only) |
| `dashboard` | React SPA | 80 via nginx |
| `nginx` | Reverse proxy | 80 / 443 |
| `agent-demo` | Demo agent (host logs) | — |

## Quick Start

```bash
git clone <repo>
cd siem-platform
cp .env.example .env
# Edit .env — change passwords and secrets!
docker compose up -d --build
```

Open http://localhost — login with `admin` / `admin123`.

## Development

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
```

- API hot-reloads from `server-api/app/`
- Dashboard hot-reloads from `dashboard/src/` on port 5173
- Postgres exposed on 5432, Redis on 6379

## Agent Deployment

### Build and run agent on a new host:

```bash
# Build
cd agent && go build -o siem-agent ./cmd/agent/

# Create config.yaml
cat > config.yaml << EOF
agent:
  id: host-001
  name: my-webserver
  group: production
  token: ""
  buffer_size: 10000

server:
  url: http://<your-server-ip>
  heartbeat_interval: 30

logs:
  - path: /var/log/auth.log
    type: linux_auth
  - path: /var/log/syslog
    type: syslog
EOF

# Run (enrollment happens automatically)
AGENT_ENROLLMENT_TOKEN=<your-token> ./siem-agent
```

### Docker agent:

```bash
docker run -d \
  -e AGENT_ENROLLMENT_TOKEN=<your-token> \
  -v /var/log:/host/var/log:ro \
  -v $(pwd)/config.yaml:/app/config.yaml \
  --network host \
  siem-agent:latest
```

After enrollment, manage log sources via the dashboard: **Agents → [agent name] → Log Sources**.

## RBAC

| Role | Capabilities |
|---|---|
| `superadmin` | Full access |
| `admin` | Manage agents, rules, decoders, webhooks |
| `analyst` | Read logs/alerts, update alert status |
| `viewer` | Read-only |

Each user belongs to one group. Users only see agents, logs, and alerts from their group. Superadmin sees all.

## Adding Rules

Via API:
```bash
curl -X POST http://localhost/api/rules \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "My Rule",
    "content": "title: My Rule\ndetection:\n  selection:\n    event.action: login_failed\n  condition: selection\nlevel: medium",
    "level": "medium"
  }'
```

Via Dashboard: **Rules → New Rule** → write YAML in editor → Test → Save.

## Adding Decoders

Via Dashboard: **Decoders → New Decoder** → write YAML → Test with a raw log line → Save.

Decoder format:
```yaml
name: my_decoder
log_type: linux_auth
type: regex
priority: 50
enabled: true
pattern: 'Failed password for (?P<user>\S+) from (?P<src_ip>\S+)'
fields:
  event.action: login_failed
  user.name: user
  source.ip: src_ip
```

## API Examples

```bash
# Login
curl -c cookies.txt -X POST http://localhost/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'

# List alerts
curl -H "Authorization: Bearer $TOKEN" http://localhost/api/alerts

# Update alert status
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status":"resolved"}' \
  http://localhost/api/alerts/<alert-id>

# Test a decoder
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"content":"..yaml..","raw_message":"May 21 sshd: Failed password for root from 1.2.3.4 port 22"}' \
  http://localhost/api/decoders/test
```

## Production Deployment

1. Set strong values for all secrets in `.env`
2. Generate SSL certificate: `openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout nginx/certs/key.pem -out nginx/certs/cert.pem`
3. Start with prod override:
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
   ```

## Observability

- Health: `GET http://localhost/health`
- Metrics (Prometheus): `GET http://localhost/metrics`
- Worker health: `docker compose exec worker curl http://localhost:8001/health`
- Logs: `docker compose logs -f worker`

## Troubleshooting

**Agent not enrolling:** Check `AGENT_ENROLLMENT_TOKEN` matches in `.env` and agent config.

**No alerts generated:** Check worker logs (`docker compose logs worker`). Verify decoders and rules are seeded (`GET /api/decoders`).

**Dashboard 502:** Ensure server-api is healthy (`docker compose ps`).

**Database connection refused:** Wait for postgres healthcheck to pass (up to 30s on first start).

## Roadmap

- [ ] Real-time dashboard via WebSocket
- [ ] Email notification integration
- [ ] Prometheus + Grafana dashboard
- [ ] Agent auto-update mechanism
- [ ] Multi-tenancy group management UI
- [ ] Sigma rule import from community repos
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add comprehensive README with setup, deployment, and API examples"
```

---

## Task 7: Final Validation

- [ ] **Step 1: Validate docker-compose syntax**

```bash
docker compose config --quiet && echo "compose OK"
docker compose -f docker-compose.yml -f docker-compose.dev.yml config --quiet && echo "dev compose OK"
docker compose -f docker-compose.yml -f docker-compose.prod.yml config --quiet && echo "prod compose OK"
```

Expected: All three print `OK`.

- [ ] **Step 2: Verify all services are on siem-net**

```bash
docker compose config | grep -A2 "networks:" | head -30
```

Expected: All services reference `siem-net`.

- [ ] **Step 3: Verify all Dockerfiles exist**

```bash
for f in server-api/Dockerfile worker/Dockerfile agent/Dockerfile dashboard/Dockerfile; do
  [ -f "$f" ] && echo "✓ $f" || echo "✗ MISSING: $f"
done
```

Expected: All 4 print `✓`.

- [ ] **Step 4: Full restart test**

```bash
docker compose down -v
docker compose up -d --build
sleep 30
docker compose ps
curl -s http://localhost/health | python3 -m json.tool
```

Expected: All services healthy, `/health` returns `{"status":"ok",...}`.

- [ ] **Step 5: Final commit**

```bash
git add -A
git commit -m "feat: complete SIEM platform - all services wired, infra validated end-to-end"
```
```

- [ ] **Done.** The full SIEM platform is complete and operational.
```

- [ ] **Step 6: Write final commit message**

```bash
git log --oneline -20
```

Review all commits to ensure the pipeline is fully covered.
