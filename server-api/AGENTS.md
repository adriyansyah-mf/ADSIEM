# SERVER-API (FastAPI)

REST API + agent ingest + WebSocket alert push. Async SQLAlchemy (`asyncpg`), Postgres; Elasticsearch for event queries. Runs 2 replicas in prod.

## STRUCTURE

```
server-api/app/
├── main.py              # FastAPI app, lifespan (migrations), router list at EOF
├── api/routes/          # 35 route modules — one file per domain
├── core/                # deps.py (RBAC), database.py, security.py, config.py,
│                        # es_client.py, llm_client.py, sigma.py, query_builder.py, ...
├── models/models.py     # ALL ORM models, single 26 KB module
├── schemas/schemas.py   # ALL Pydantic schemas, single 20 KB module
└── services/            # assistant.py, assistant_tools.py, audit.py, ingest.py, report_pdf.py
```

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Register a new router | `app/main.py` EOF `for router in [...]` | **must** be added or it 404s silently |
| Startup migrations | `app/main.py` `lifespan` (`:357`) | `Base.metadata.create_all` + `_migrate_*` under `pg_advisory_lock(727501001)` |
| Auth / token decode | `app/core/deps.py` `get_current_user` | HTTPBearer; token `type` must be `"access"` |
| Permission gate | `app/core/deps.py` `require_permission("x:y")` | superadmin bypasses; else check role.permissions set |
| Group scoping | `app/core/deps.py` `get_scoped_group` | returns `None` for superadmin, else `user.group_id` |
| Agent-token auth | `app/core/deps.py` `get_agent` | header `X-Agent-Token`, compared by `hash_token` |
| Agent log ingest | `app/api/routes/ingest.py` | `POST /api/ingest/log` |
| Router name collisions | `app/main.py` imports | Aliased `cases_router`, `hunts_router`, `settings_router`, etc. |
| WebSocket push | `app/api/routes/ws.py` + `_ws_redis_listener` in main | Redis pubsub channel `ws:alerts` |

## CONVENTIONS

- **Route module shape**: `router = APIRouter(prefix="/api/<domain>", tags=["<domain>"])`. Some modules omit the prefix and declare full paths per-decorator (`fim.py`, `agents.py`, `cases.py`) — match the file you're editing.
- **Every route** takes `db: Annotated[AsyncSession, Depends(get_db)]` and a `Depends(...)` guard — never a bare public route.
- **Audit logging is a BackgroundTask**: `background.add_task(audit_log, db, user.id, "action", "entity", id)` — do not `await` it inline.
- **Rate limits** via `slowapi`: `@limiter.limit("5/minute")` on auth endpoints.
- **Decoder/rule YAML is validated on write** (`_validate_decoder_yaml`) — regex needs `pattern`, type ∈ `regex|kv`.
- Decoder *test* route imports `worker.decoder_engine` directly — a cross-service import that works because both live in the same repo.

## ANTI-PATTERNS

- **Do not add a new table via `db/init.sql`** — use `Base.metadata.create_all` + a `_migrate_*` helper called from `lifespan`.
- **Do not bypass `get_scoped_group`** on any list/fetch of agents, alerts, cases, logs, FIM — cross-group leakage is a security bug.
- **Do not add routers outside the `main.py` list**, and do not rename a router import without updating the alias there.
- **Do not `await` an `audit_log`** — it's designed as a background task.
- **Do not raise raw `Exception`** for client errors; use `HTTPException` with the right status (422 for YAML validation, 403 for RBAC, 409 for duplicates).
