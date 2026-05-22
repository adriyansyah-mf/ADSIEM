# SIEM Platform

A modular, production-grade Security Information and Event Management (SIEM) platform.

> **Security Warning:** Default credentials (`admin` / `admin123`) are for development only.
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
