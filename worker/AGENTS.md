# WORKER (Python detection pipeline)

Async consumer of the Redis stream. **Package nesting is deliberate**: repo dir `worker/` is the Docker image root, `worker/worker/` is the importable package, `worker/tests/` is a third layer. Runs 2 replicas in prod.

## STRUCTURE

```
worker/worker/
├── main.py           # entry — asyncio.gather() of 15 loops + health server (:8001)
├── consumer.py       # stream consume → decode → sigma → alert; DLQ retry
├── decoder_engine.py # regex + kv YAML decoders
├── sigma_engine.py   # rule match + threshold + suppression (Redis-backed)
├── alert_manager.py  # alert creation + webhook fire
├── seeder.py         # seed rules/ + decoders/ into DB (new titles only)
├── soar_engine.py    # playbook execution
├── rag.py / rag_indexer.py   # pgvector RAG over cases/SOPs (fastembed)
├── llm_client.py / ai_analyst.py / ai_consumer.py  # AI triage + analyst
├── hunter.py / hunt_scheduler.py / campaign_analyzer.py / fleet_correlation.py
├── report_sender.py / email_sender.py / webhook_sender.py
├── ueba/             # features.py, scorer.py (Isolation Forest + robust deviation), explain.py (reasons, MITRE, risk), trainer.py, model_codec.py (pickle-free, Tree.__setstate__), loops.py
├── ti/               # aggregator.py, extractor.py, mitre.py, iocs.py
│   └── providers/    # abuseipdb, virustotal, shodan, otx, greynoise, urlhaus, geoip, whois, base
└── models.py         # worker-side ORM (separate from server-api's models.py)
```

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Add a background loop | `worker/worker/main.py` `asyncio.gather(...)` | 15 loops listed — add here or it never runs |
| Message lifecycle | `worker/worker/consumer.py:53` `process_message` | decode → ES index → sigma → `create_alert` → UEBA (best-effort) |
| DLQ behaviour | `consumer.py:153` `dlq_retry_loop` | failed msgs at `{REDIS_STREAM_KEY}:failed`, re-injected every **300s**, batch 50 |
| Engine hot-reload | `consumer.py:178` `reload_loop` | interval from `RELOAD_INTERVAL` env (default 60s) |
| Health/metrics | `main.py` `HealthHandler` | `/health`, `/metrics` on port 8001 |
| Rule/decoder seeding | `worker/worker/seeder.py` | idempotent by `title`/`name`; per-item SAVEPOINT (replica race safe) |
| Sigma threshold/suppression state | Redis | expect Redis to be required for sigma, not just the stream |
| Worker DB session | `worker/worker/database.py` `AsyncSessionLocal` | worker has its own engine, separate from server-api |

## CONVENTIONS

- **`structlog` JSON only**; `structlog.make_filtering_bound_logger` is configured in `main.py` from `LOG_LEVEL`. No `print`, no stdlib logging.
- **Best-effort side effects never block the pipeline**: UEBA scoring is wrapped in `try/except` with a warning and continues — replicate that pattern for enrichment.
- **Every message is `xack`'d** even on failure (then copied to the DLQ) so the pending-entries list doesn't grow.
- **Cross-service import is normal**: `worker.decoder_engine` is imported by server-api's decoder-test route — keep the module import-safe (no side effects at import).
- **Prometheus counters** are module-level in `consumer.py`; add new metrics next to the relevant loop.

## ANTI-PATTERNS

- **Do not assume Elasticsearch is optional** — `ensure_index` runs at startup and every processed message writes there. Postgres alone won't produce a working event view.
- **Do not do blocking I/O** in a loop (no `requests`, no `time.sleep`) — this is a single event loop shared by 15 loops; a blocking call stalls ingest for every loop.
- **Do not scatter `except Exception: pass`** — the worker's established style is log the exception via structlog at `warning`/`error` then continue (see `process_message` UEBA block).
- **Do not edit rule/decoder YAML logic here** — `rules/` and `decoders/` are data, seeded by `seeder.py`; DB rows are never overwritten for existing titles.
- **Do not import server-api modules** into the worker; the two services share only the DB and Redis, and their `models.py` files are intentionally separate.
