# PROJECT KNOWLEDGE BASE

**Generated:** 2026-10-17
**Commit:** 8ac73e7
**Branch:** nightmare-c0de

## OVERVIEW

Modular SIEM platform: Go endpoint agent → FastAPI ingest → Python/Redis-Streams detection worker → React SOC dashboard, backed by PostgreSQL + Elasticsearch, deployed via Docker Compose.

## STRUCTURE

```
.
├── agent/          # Go endpoint agent (Linux-only; eBPF procexec, FIM, hygiene, live response)
├── server-api/     # FastAPI REST API + agent ingest + WebSocket alert push
├── worker/         # Python async detection pipeline (worker/worker/** — package nested one level down)
├── dashboard/      # React 18 + Vite + Tailwind SPA
├── rules/          # 70 Sigma YAML detection rules — seeded to DB on worker start
├── decoders/       # 22 regex/kv YAML decoders — seeded to DB on worker start
├── db/init.sql     # Postgres schema bootstrap (extensions, roles, users, agents, ...)
├── nginx/          # Reverse proxy + TLS term (nginx.conf dev, nginx.prod.conf prod)
├── tests/          # pytest suites split by service: server-api/ agent/ dashboard/ worker/
├── docs/           # PROJECT_OVERVIEW.md + superpowers/ plans & specs
└── docker-compose.yml (+ .dev / .prod overrides)
```

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Agent main loop, wiring of every subsystem | `agent/cmd/agent/main.go` | enrollment → tailer → FIM → hygiene → procexec → heartbeat → sender |
| Log tailing w/ glob + rotation | `agent/internal/tailer/tailer.go` | entries encoded `logType\x00rawMessage`; `Decode()` reverses it |
| eBPF process-exec | `agent/internal/procexec/` | `execve.bpf.c` must be clang-compiled before Go build |
| API app + router registration | `server-api/app/main.py` | all routers listed in one `for router in [...]` loop at EOF |
| API route modules | `server-api/app/api/routes/` | 35 files; `_router` suffix in main.py for name-colliding ones (`cases_router`, `hunts_router`, ...) |
| Auth / RBAC / group scoping | `server-api/app/core/deps.py` | `require_permission()` + `get_scoped_group()` |
| ORM models (all of them) | `server-api/app/models/models.py` | single 26 KB module |
| Pydantic schemas (all of them) | `server-api/app/schemas/schemas.py` | single 20 KB module |
| Detection pipeline entry | `worker/worker/main.py` | `asyncio.gather()` launches 15 concurrent loops |
| Stream consume → decode → sigma → alert | `worker/worker/consumer.py` | DLQ at `{REDIS_STREAM_KEY}:failed`, retried every 300s |
| Rule seeding | `worker/worker/seeder.py` | seeds `rules/` + `decoders/` into DB, new titles only |
| SOAR playbooks | `worker/worker/soar_engine.py` | triggered from alert creation |
| UEBA | `worker/worker/ueba/` | Isolation Forest scorer + trainer + cycles |
| Threat intel providers | `worker/worker/ti/providers/` | abuseipdb, virustotal, shodan, otx, greynoise, urlhaus, geoip, whois, base |
| Dashboard routes | `dashboard/src/App.tsx` | 25+ routes; role gating nested `<ProtectedRoute minRole=...>` |
| Dashboard API client | `dashboard/src/api/client.ts` | axios; token from `stores/auth.ts` |
| Postgres schema | `db/init.sql` | `pgcrypto` + `vector` extensions enabled |

## CODE MAP

| Symbol | Type | Location | Role |
|--------|------|----------|------|
| `main` | func | `agent/cmd/agent/main.go:27` | agent entry — bootstraps every subsystem |
| `Enroll` | func | `agent/internal/enrollment/enrollment.go:36` | first-run enroll; retries w/ exponential backoff |
| `Tail` / `Decode` | func | `agent/internal/tailer/tailer.go:20,218` | log tailing + entry codec |
| `lifespan` | func | `server-api/app/main.py:357` | one-replica-at-a-time migrations via `pg_advisory_lock` |
| `get_current_user` / `require_permission` / `get_scoped_group` / `get_agent` | func | `server-api/app/core/deps.py` | auth + RBAC + group filter + agent-token auth |
| `Agent` | model | `server-api/app/models/models.py:53` | most-referenced model (10 route modules) |
| `main` | func | `worker/worker/main.py:122` | worker entry — seeds, loads engines, gathers loops |
| `consume_loop` / `process_message` / `load_engines` | func | `worker/worker/consumer.py:126,53,36` | stream ingest → decode → sigma → alert (no tests) |
| `App` | func | `dashboard/src/App.tsx:33` | route table + auth rehydrate |

## CONVENTIONS

- **Python**: async-first (SQLAlchemy `AsyncSession`, `redis.asyncio`). Structured logging via `structlog` only — no `print`. `pytest` `asyncio_mode = auto`, so `async def test_*` needs no decorator.
- **Two DBs, two purposes**: Postgres = config/metadata (rules, alerts, cases, users); Elasticsearch = raw + decoded events. Writes go to both.
- **Group scoping is mandatory**: non-superadmin queries filter by `group_id` via `get_scoped_group()`. Never query agents/alerts/cases unfiltered in a route.
- **Rules/decoders are data**: add YAML files to `rules/` / `decoders/` — seeding is idempotent by `title`/`name`, so DB edits are never clobbered. `process_creation` rules use Sigma field names (`Image`, `CommandLine`), everything else ECS dotted fields (`event.action`, `source.ip`).
- **Agent→server contract**: log ingest `POST /api/ingest/log`; FIM `POST /api/fim`; heartbeat drives live log-source/FIM-path updates and task dispatch.
- **Dashboard**: Vite + TS strict; hooks in `src/hooks/` wrap TanStack Query; server state via react-query, auth via zustand.
- **Routers must be registered** in the `main.py` list or they 404 silently.

## ANTI-PATTERNS (THIS PROJECT)

- **NEVER commit real secrets**: `JWT_SECRET`, `POSTGRES_PASSWORD`, `AGENT_ENROLLMENT_TOKEN`, `NINEROUTER_*`, `SEARXNG_SECRET`. Defaults (`admin`/`admin123`) are dev-only.
- **NEVER point the agent at `http://`**: nginx 301-redirects to HTTPS and Go downgrades POST→GET on 301, turning every ingest into a 405. Always `https://`.
- **NEVER ship a self-signed cert without SAN + `basicConstraints = CA:TRUE`** — plain `openssl req -x509 -subj "/CN=..."` breaks agent TLS verification and `update-ca-trust` silently drops it.
- **Do not add `CREATE TABLE` to `db/init.sql` for new features** — API startup runs `Base.metadata.create_all` plus `_migrate_*` helpers; add a migration helper instead.
- **Do not run migrations without the advisory lock** (`_STARTUP_LOCK_KEY`) — concurrent replicas deadlock on `ALTER TABLE`.
- **eBPF/FIM/isolate failures must degrade gracefully** (warn, don't crash) — they need root + BTF kernel and are optional by design.
- **Do not use `as any` / `@ts-ignore`** in dashboard; do not silence type errors in Python either.

## UNIQUE STYLES

- **Worker package nesting**: code lives in `worker/worker/` (repo dir = image root, inner dir = importable package). `worker/tests/` is a *third* layer.
- Two-`DB` writes plus best-effort side effects: UEBA scoring is wrapped in `try/except` and explicitly "never blocks the main pipeline".
- Service tiers split as `docker-compose.yml` (base) + `.dev` (hot reload, 5432/6379 exposed, HTTP:80) + `.prod` (2× server-api, 2× worker, resource limits, TLS).
- Agent's in-memory buffer re-queues on 5xx and drops on 4xx with an error log — deliberate.
- Repository-local docs are mixing English/Indonesian (`docs/PROJECT_OVERVIEW.md`, `prompt.md`) — leave as-is.

## COMMANDS

```bash
# Dev stack (hot reload, HTTP:80, DB ports exposed)
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build

# Prod stack (replicas + limits + TLS)
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build

# Tests — Python (importlib mode is required; see pytest.ini)
pytest                                   # all suites
pytest tests/server-api tests/worker     # per-service
pytest worker/tests                      # worker extras
# Tests — Go agent
cd tests/agent && go test ./...
# Tests — dashboard
cd dashboard && npm run build            # tsc -b && vite build (no unit runner configured)

# Agent build (eBPF object is go:embed'd — compile it first)
cd agent
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -I internal/procexec/bpf/include \
  -c internal/procexec/bpf/execve.bpf.c \
  -o internal/procexec/bpf/execve.bpf.o
go build -ldflags="-s -w" -o siem-agent ./cmd/agent/

# Agent release (tag-triggered CI)
git tag agent-v1.1.0 && git push origin agent-v1.1.0   # .github/workflows/agent-release.yml
```

## NOTES

- 42 LSP servers configured, only `gopls`, `rust`, `dart` installed — Python/TS/JS agents get **no LSP** by default. `dashboard` has zero test runner; `tests/dashboard/*.py` are pytest end-to-end fixtures, not unit tests.
- `agent/bin/agent` (9.8 MB) and `siem-agent_1.0.0_amd64.deb` (5 MB) are committed build artifacts; `dashboard/dist/` is a committed build too.
- `rules/` uses `kernel_module_load_suspicious_path.yaml` etc. — 70 rules, `decoders/` 22. Counts change; treat as data.
- Postgres runs `pgvector/pgvector:pg16` (vector search for RAG over cases/SOPs); `fastembed` in the worker generates embeddings.
- `9router` (LLM router) and `searxng` back the AI SOC assistant; `package-builder` is a one-shot job that emits agent `.deb`/`.rpm` served from the dashboard.
- CI only covers the agent release workflow — **there is no CI job that runs the Python/dashboard tests**.
