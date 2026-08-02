# SIEM Platform

A modular, production-grade Security Information and Event Management (SIEM) platform.
It runs a lightweight Go agent on each endpoint, pipes everything through a Python
detection engine, and gives a SOC team one dashboard to triage, investigate, and
respond from — without needing Splunk/QRadar-scale infrastructure or licensing.

**What it does:**

- **Log collection** — a single Go agent per host tails arbitrary log files (with
  rotation handling), collects File Integrity Monitoring events, periodic system
  hygiene snapshots (OS/patch level, open ports, disk), and — via eBPF — real-time
  process-exec telemetry (`Image`/`CommandLine`/`ParentImage`), all shipped over HTTPS.
- **Detection** — Sigma-format rules (bring your own from SigmaHQ, or write your own)
  evaluated against decoded events in real time, with threshold/correlation windows
  and suppression built in. Rules and decoders are just YAML files, seeded from disk.
- **Response** — SOAR playbooks that trigger automatically on alert conditions:
  enrich IOCs, open a case, suppress noise, isolate a host (`iptables`), block a
  source IP, send a webhook — all configurable from the dashboard, no code required.
  A live-response console can also run ad-hoc process lists, netstat, file pulls, YARA
  scans, and persistence checks against any online agent.
- **Threat intel & UEBA** — IOC enrichment (Shodan exposure data and others) feeds
  into alert risk scoring; entity behavior analytics flags anomalous IPs/hosts by
  risk score over time.
- **Case management** — alerts roll up into investigations with AI-assisted triage
  notes, an attack graph view, and MITRE ATT&CK tagging throughout.
- **AI SOC assistant** — a read-only chat assistant embedded in the dashboard that
  can look up alerts, cases, agents, UEBA scores, FIM changes, and rules on request —
  scoped so it can never touch settings, users, or webhook config.
- **RBAC & multi-group** — users belong to a group and only see that group's agents,
  alerts, and cases; superadmins see everything.

Stack: Go (agent) · FastAPI (API) · Python/Redis Streams (detection worker) ·
PostgreSQL + Elasticsearch (storage) · React (dashboard) · Docker Compose (deploy).

> **Security Warning:** Default credentials (`admin` / `admin123`) are for development only.
> Change `JWT_SECRET`, `POSTGRES_PASSWORD`, `AGENT_ENROLLMENT_TOKEN`, and the admin password
> immediately in production. See [Production Deployment](#production-deployment).

## Architecture

```
Endpoint Agent (Go)                    Dashboard (React) ← nginx (TLS)
  - log tailing                                  ↑
  - FIM                                          |
  - hygiene snapshots                    server-api (FastAPI, 2 replicas)
  - eBPF process-exec (sys_enter_execve)         ↓ /api/ingest/log, /heartbeat
  - live response tasks (isolate/block/YARA)     ↓
        |  HTTPS                          Redis Streams
        └────────────────────────────────────────↓
                                          Worker (Python, 2 replicas)
                                                   ↓
                                    decoder → sigma engine → SOAR playbooks
                                                   ↓
                                    PostgreSQL  +  Elasticsearch (raw events)
```

Supporting services: `9router` (LLM router for the AI SOC assistant / AI case analyst),
`searxng` (web search backend for threat-intel enrichment), `package-builder`
(one-shot job that builds agent `.deb`/`.rpm` packages, served from the dashboard's
Agents page).

## Requirements

**Server host:**
- Linux x86_64 (tested on Debian/Kali; anything Docker-supported works)
- Docker Engine 24+ and the Docker Compose plugin (`docker compose`, not the old `docker-compose`)
- 4 vCPU / 8 GB RAM minimum (Elasticsearch + Postgres + 2× server-api + 2× worker); more for real traffic volumes
- Ports 80/443 free (nginx), or adjust `docker-compose.prod.yml`

**Endpoint agent host:**
- Linux (the agent is Linux-only — no Windows/macOS build)
- To run as a systemd service: any systemd-based distro (Debian/Ubuntu → `.deb`, RHEL/Fedora/Rocky/Alma → `.rpm`)
- For the eBPF process-exec monitor specifically (optional, degrades gracefully without it):
  - Kernel with BTF: `ls /sys/kernel/btf/vmlinux` must exist (`CONFIG_DEBUG_INFO_BTF=y`) — true on any mainstream distro kernel from the last ~5 years
  - `CAP_BPF` + `CAP_SYS_ADMIN` (or root) — the agent already needs root for the `iptables`-based isolate/block-IP live-response actions, so this isn't an extra ask in practice
- To build the agent from source: Go 1.25+ and `clang` (only `clang` is needed at build time, to compile `agent/internal/procexec/bpf/execve.bpf.c` — nothing extra is required at runtime, the compiled object is embedded into the binary)

## Services

| Service | Description | Port |
|---|---|---|
| `postgres` | Primary database (pgvector) | 5432 (internal) |
| `redis` | Message queue + suppression/threshold cache | 6379 (internal) |
| `elasticsearch` | Raw log + decoded event store | 9200 (internal) |
| `9router` | LLM router backing the AI SOC assistant | 20128 (internal), 20129 (localhost only) |
| `searxng` | Web search backend for TI enrichment | 8080 (internal) |
| `package-builder` | One-shot: builds agent `.deb`/`.rpm`, then exits | — |
| `server-api` | REST API, auth, ingest (2 replicas in prod) | 8000 (internal) |
| `worker` | Log pipeline: decode → sigma → SOAR (2 replicas in prod) | 8001 (health only) |
| `dashboard` | React SPA, built + served by its own nginx | 80 (internal) |
| `nginx` | Public reverse proxy, TLS termination | 80 / 443 |
| `agent-demo` | Demo agent tailing the host's own `/var/log` | — |

## Server Installation

```bash
git clone <repo>
cd ADSIEM  # or siem-platform, whatever you cloned it as
cp .env.example .env
```

**1. Fill in secrets in `.env`** — at minimum:

```bash
JWT_SECRET=$(openssl rand -hex 32)
POSTGRES_PASSWORD=<strong password>
AGENT_ENROLLMENT_TOKEN=<strong random token>
```
Also update `DATABASE_URL` to match if you changed `POSTGRES_PASSWORD`.

**2. Generate a TLS certificate.** If you have a real domain pointed at this host, use
Let's Encrypt/certbot instead of the steps below. For a self-signed cert (dev, or an
internal-only deployment), it **must** include a `subjectAltName` for however clients
will actually reach it (IP and/or hostname) and `basicConstraints = CA:TRUE` — plain
`openssl req -x509` with just a `CN` will silently fail both browser/curl validation
*and* `update-ca-trust`/`update-ca-certificates` trust-anchor import on agent hosts:

```bash
mkdir -p nginx/certs
cat > /tmp/san.cnf << 'EOF'
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = <your-server-ip-or-hostname>

[v3_req]
subjectAltName = @alt_names
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, keyEncipherment, keyCertSign

[alt_names]
IP.1 = <your-server-ip>
DNS.1 = <your-server-hostname-if-any>
EOF

openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
  -keyout nginx/certs/key.pem -out nginx/certs/cert.pem \
  -config /tmp/san.cnf -extensions v3_req
```

**3. Start the stack:**

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

First start takes a few minutes (Elasticsearch + Postgres init, image builds). Watch it come up:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml ps
# everything should reach "healthy" within ~60s once images are built
```

**4. Log in.** Open `https://<your-server>` — `admin` / `admin123` — then immediately
change the admin password (**Settings → Users**).

For local development instead of a production deploy, see [Development](#development) below.

## Development

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
```

- API hot-reloads from `server-api/app/`
- Dashboard hot-reloads from `dashboard/src/` on port 5173
- Postgres exposed on 5432, Redis on 6379
- Plain HTTP on port 80 (no TLS cert needed for dev)

## Agent Installation

The agent is a single static Go binary. Three ways to get it onto a host, in order of
convenience:

### Option A — Prebuilt package (`.deb` / `.rpm`)

The platform builds these itself on every stack start (`package-builder` service) and
serves them from the dashboard: **Agents → Download Agent**. Or fetch a tagged GitHub
release (`.github/workflows/agent-release.yml`, triggered by pushing a tag like `agent-v1.1.0`).

**Debian/Ubuntu/Kali:**
```bash
sudo dpkg -i siem-agent_<version>_amd64.deb
sudo vi /etc/siem-agent/config.yaml   # set server.url and enrollment token — see below
sudo systemctl enable --now siem-agent
```

**RHEL/Fedora/Rocky/Alma:**
```bash
sudo rpm -i siem-agent-<version>-1.x86_64.rpm
sudo vi /etc/siem-agent/config.yaml
sudo systemctl enable --now siem-agent
```

Both packages install to `/usr/bin/siem-agent`, `/etc/siem-agent/config.yaml`, and a
`siem-agent.service` unit. The packaged `postinst` creates an unprivileged `siem-agent`
system user — but note the unit file as shipped runs the agent with no `User=` directive,
i.e. **as root**, which is what live-response (`iptables` isolate/block-IP) and the eBPF
monitor need. If you harden the unit to run as `siem-agent`, isolate/block-IP and
process-exec monitoring will fail closed (logged as warnings, not fatal) — everything
else (log tailing, FIM, hygiene) still works unprivileged.

### Option B — Build from source

```bash
cd agent
go build -ldflags="-s -w" -o siem-agent ./cmd/agent/
```

This alone is enough for log tailing / FIM / hygiene / live-response. The eBPF
process-exec monitor additionally needs its bytecode object compiled first
(`go:embed` pulls it in at build time — the binary won't build without it):

```bash
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -I internal/procexec/bpf/include \
  -c internal/procexec/bpf/execve.bpf.c \
  -o internal/procexec/bpf/execve.bpf.o
# then: go build ...
```
(`-D__TARGET_ARCH_arm64` on arm64 hosts.) `make build` in `agent/` does a plain Go
build only — it does not run the clang step, so build the `.bpf.o` manually first if
you're not using the Dockerfiles.

### Option C — Docker

```bash
docker run -d \
  -e AGENT_ENROLLMENT_TOKEN=<your-token> \
  -v /var/log:/host/var/log:ro \
  -v $(pwd)/config.yaml:/app/config.yaml \
  --network host \
  --privileged \
  siem-agent:latest
```
`--privileged` (or at least `--cap-add=BPF --cap-add=SYS_ADMIN --cap-add=NET_ADMIN`) is
needed for the eBPF monitor and live-response actions; omit it if you only need log
shipping and accept those features being disabled.

### config.yaml reference

```yaml
agent:
  id: host-001              # stable unique ID; set once, don't change after enrollment
  name: my-webserver
  group: production          # controls dashboard visibility for non-superadmin users
  token: ""                  # filled in automatically after first successful enrollment
  buffer_size: 10000

server:
  url: https://<your-server>   # MUST match the scheme nginx actually serves — see Troubleshooting
  heartbeat_interval: 30

logs:
  - path: /var/log/auth.log
    type: linux_auth
  - path: /var/log/syslog
    type: syslog
  # glob patterns are supported for daily-rotated logs, e.g. /var/log/nginx/access.log*

fim:
  enabled: true
  watch_paths:
    - /etc
    - /usr/bin
```

Run with `AGENT_ENROLLMENT_TOKEN=<matches server's .env value> ./siem-agent -config config.yaml`
the first time — enrollment happens automatically and the agent writes its issued
`token` back into `config.yaml`. After that, log sources and FIM paths can be managed
live from the dashboard (**Agents → [agent name] → Log Sources**) without touching the
config file again; `RELOAD_INTERVAL` on the worker and the agent's heartbeat loop keep
both sides in sync.

### Trusting a self-signed platform certificate

If the platform's TLS cert isn't from a public CA (see step 2 of
[Server Installation](#server-installation)), every agent host needs that cert added to
its own trust store, or all agent→server traffic will fail TLS verification:

```bash
# fetch the cert from the server, e.g.:
scp server:/path/to/ADSIEM/nginx/certs/cert.pem ./adsiem-ca.pem
```

**Debian/Ubuntu/Kali:**
```bash
sudo cp adsiem-ca.pem /usr/local/share/ca-certificates/adsiem-platform.crt
sudo update-ca-certificates
```

**RHEL/Fedora/Rocky/Alma:**
```bash
sudo cp adsiem-ca.pem /etc/pki/ca-trust/source/anchors/adsiem-platform.pem
sudo update-ca-trust extract
```

Then restart the agent: `sudo systemctl restart siem-agent`.

### Verifying an agent is fully working

```bash
sudo journalctl -u siem-agent -f
```

Look for, in order: `tailing` lines (log sources picked up), `procexec: attached to
tracepoint/syscalls/sys_enter_execve` (eBPF monitor active — its absence is non-fatal,
just means that signal isn't available on this host), then steady `buffer stats`
lines with `len` staying near 0 and `pushed`≈`popped` (meaning the server is actually
accepting what's being sent — a growing `len` or repeated `send failed`/`heartbeat
failed` errors mean connectivity or TLS trust is broken, see Troubleshooting).

To confirm detections are reaching the pipeline end-to-end, trigger something a
shipped rule matches and check for the resulting alert, e.g. (safe — doesn't actually
load a kernel module):
```bash
echo not-a-real-module > /tmp/t.ko && sudo insmod /tmp/t.ko   # fails harmlessly
rm /tmp/t.ko
```
then check **Alerts** in the dashboard, or:
```bash
curl -H "Authorization: Bearer $TOKEN" "http://localhost/api/alerts?search=Kernel+Module"
```

## RBAC

| Role | Capabilities |
|---|---|
| `superadmin` | Full access |
| `admin` | Manage agents, rules, decoders, webhooks |
| `analyst` | Read logs/alerts, update alert status |
| `viewer` | Read-only |

Each user belongs to one group. Users only see agents, logs, and alerts from their group. Superadmin sees all.

## Adding Rules

Rules live in `rules/*.yaml` and are auto-seeded into the database on worker startup
(new files only — existing rules by `title` are left alone, so editing a rule in the
dashboard after seeding won't get clobbered by a redeploy). They're plain Sigma:

```yaml
title: My Rule
logsource:
  product: linux
detection:
  selection:
    event.action: login_failed
  condition: selection
level: medium
```

Field names are whatever your decoder emits — this repo mostly uses ECS-style dotted
fields (`event.action`, `user.name`, `source.ip`), **except** the `process_creation`
logsource (from `linux_process_exec` / the eBPF monitor), which intentionally uses
Sigma's own standard field names (`Image`, `CommandLine`, `ParentImage`, `User`,
`ProcessId`, `ParentProcessId`) instead of ECS — that's what lets you drop in public
SigmaHQ `process_creation` rules unmodified.

Also addable via API or **Dashboard → Rules → New Rule** (write YAML → Test → Save):
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

## Adding Decoders

Same seeding mechanism as rules, from `decoders/*.yaml`. Two types:

**regex** — named capture groups map to output fields:
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

**kv** — for `key=value` / `key="quoted value"` formatted logs (FortiGate-style, and
what the eBPF process-exec events use):
```yaml
name: my_kv_decoder
log_type: some_log_type
type: kv
priority: 10
fields:
  event.action: action   # output_field: kv_key
static_fields:
  event.category: network
```

Also addable via **Dashboard → Decoders → New Decoder** (Test with a raw log line → Save).

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

1. Set strong values for **all** secrets in `.env` (`JWT_SECRET`, `POSTGRES_PASSWORD`,
   `AGENT_ENROLLMENT_TOKEN`, `NINEROUTER_*`, `SEARXNG_SECRET`) and change the default
   admin password after first login.
2. Get a real TLS cert if you have a domain (Let's Encrypt); otherwise generate a
   self-signed one **with SAN + `CA:TRUE`** as shown in
   [Server Installation](#server-installation) — a bare `openssl req -x509 -subj
   "/CN=..."` will break both agent TLS verification and later `update-ca-trust`
   import in ways that fail silently/confusingly.
3. Start with the prod override (adds resource limits and `server-api`/`worker` replicas):
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
   ```
4. Point every agent's `config.yaml` `server.url` at `https://...`, not `http://...`
   — nginx 301-redirects HTTP→HTTPS, and Go's HTTP client downgrades POST to GET when
   following a 301, which turns every log/heartbeat POST into a 405. Using `https://`
   directly avoids the redirect hop entirely.
5. Install the platform's CA cert on every agent host if it's self-signed (see
   [Trusting a self-signed platform certificate](#trusting-a-self-signed-platform-certificate)).
6. Confirm both `worker-1` and `worker-2` logs are clean on first boot
   (`docker compose logs worker | grep -i fail`) — decoder/rule seeding races
   between replicas are handled with per-item `SAVEPOINT`s, but it's worth a glance
   after adding a batch of new rules/decoders.

## Observability

- Health: `GET https://<your-server>/health`
- Metrics (Prometheus): `GET https://<your-server>/metrics`
- Worker health: `docker compose exec worker curl http://localhost:8001/health`
- Logs: `docker compose logs -f worker` / `docker compose logs -f server-api`
- Per-service status: `docker compose -f docker-compose.yml -f docker-compose.prod.yml ps`

## Troubleshooting

**Agent not enrolling:** Check `AGENT_ENROLLMENT_TOKEN` matches between `.env` on the
server and the agent's environment/config at first run.

**Agent logs `tls: failed to verify certificate: ... doesn't contain any IP SANs`:**
The server's cert has no `subjectAltName` covering how the agent connects (IP vs
hostname). Regenerate it with a proper SAN (see Server Installation) — `CN` alone is
not enough for modern TLS clients, Go included.

**Agent logs `tls: failed to verify certificate: ... signed by unknown authority`:**
The cert is valid but self-signed and this host doesn't trust it yet. Also check that
the cert itself has `basicConstraints = CA:TRUE` — without it, `update-ca-trust`/
`update-ca-certificates` will silently drop it from the trust bundle even though it's
sitting right there in `source/anchors/`. See
[Trusting a self-signed platform certificate](#trusting-a-self-signed-platform-certificate).

**Agent logs repeated `POST ... 301` immediately followed by `GET ... 405`:**
`server.url` in the agent's config is `http://`, and nginx is redirecting to HTTPS —
Go's client follows the redirect but downgrades the method. Change `server.url` to
`https://` directly.

**`procexec: <error>` warning on agent startup, or no `procexec: attached` line at all:**
Non-fatal by design — the eBPF monitor needs a BTF-enabled kernel
(`/sys/kernel/btf/vmlinux` must exist) and `CAP_BPF`/`CAP_SYS_ADMIN` (root). Everything
else keeps working without it.

**No alerts generated:** Check worker logs (`docker compose logs worker`). Verify
decoders and rules are seeded (`GET /api/decoders`, `GET /api/rules`), and that the
relevant log's `log_type` actually has a decoder — an ingested log with no matching
decoder produces an empty event dict, which no rule will match.

**Dashboard 502:** Ensure server-api is healthy (`docker compose ps`).

**Database connection refused:** Wait for postgres healthcheck to pass (up to 30s on first start).

**nginx container stuck restarting, log says `cannot load certificate ".../cert.pem"`:**
`nginx/certs/cert.pem`/`key.pem` don't exist yet — generate them (Server Installation
step 2) before bringing up `nginx` in the prod compose.

## Roadmap

- [ ] Real-time dashboard via WebSocket
- [ ] Email notification integration
- [ ] Prometheus + Grafana dashboard
- [ ] Agent auto-update mechanism
- [ ] Multi-tenancy group management UI
- [ ] Sigma rule import from community repos
- [ ] Windows/macOS endpoint agent
- [ ] Let's Encrypt automation for the platform's own TLS cert
