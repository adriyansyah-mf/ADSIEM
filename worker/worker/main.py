# worker/worker/main.py
import asyncio
import json
import time
import logging
import structlog
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from prometheus_client import CONTENT_TYPE_LATEST, Gauge, generate_latest

from worker.config import LOG_LEVEL
from worker.database import AsyncSessionLocal, engine
from worker.decoder_engine import DecoderEngine
from worker.redis_client import get_redis
from worker.seeder import seed_if_empty
from worker.sigma_engine import SigmaEngine
from worker.consumer import consume_loop, load_engines, reload_loop, dlq_retry_loop
from worker.webhook_sender import webhook_retry_loop
from worker.ai_consumer import ai_analysis_loop, ai_backfill_loop
from worker.ueba.loops import ueba_snapshot_loop, ueba_train_loop, ueba_ai_loop
from worker.hunter import hunt_loop
from worker.agent_monitor import agent_monitor_loop
from worker.maintenance import maintenance_loop
from worker.report_sender import report_loop
from worker.hunt_scheduler import hunt_scheduler_loop
from worker.rag_indexer import rag_index_loop, sop_index_loop

structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(
        logging.getLevelName(LOG_LEVEL.upper())
    ),
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
)
log = structlog.get_logger()

_start_time = time.time()
queue_lag_gauge = Gauge("siem_worker_queue_lag", "Redis stream pending messages")
active_agents_gauge = Gauge("siem_active_agents", "Active agents count")

# Shared health state updated by the async health probe loop.
_health_state: dict = {"postgres": "ok", "redis": "ok"}


class HealthHandler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def do_GET(self):
        if self.path == "/health":
            pg = _health_state.get("postgres", "ok")
            rd = _health_state.get("redis", "ok")
            status = "ok" if pg == "ok" and rd == "ok" else "degraded"
            payload = {
                "status": status,
                "postgres": pg,
                "redis": rd,
                "uptime_seconds": int(time.time() - _start_time),
            }
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/metrics":
            body = generate_latest()
            self.send_response(200)
            self.send_header("Content-Type", CONTENT_TYPE_LATEST)
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()


async def health_probe_loop():
    """Periodically check postgres/redis health and update Prometheus gauges."""
    import sqlalchemy
    while True:
        redis = await get_redis()
        pg_status = "ok"
        rd_status = "ok"
        try:
            async with engine.connect() as conn:
                await conn.execute(sqlalchemy.text("SELECT 1"))
        except Exception:
            pg_status = "error"
        try:
            await redis.ping()
            # Update queue lag gauge from the Redis stream pending count
            try:
                info = await redis.xinfo_groups(REDIS_STREAM_KEY)
                lag = sum(g.get("pending", 0) for g in info)
                queue_lag_gauge.set(lag)
            except Exception:
                pass
        except Exception:
            rd_status = "error"
        _health_state["postgres"] = pg_status
        _health_state["redis"] = rd_status

        # Update active agents gauge from DB
        try:
            async with AsyncSessionLocal() as db:
                from sqlalchemy import select, func
                from worker.models import Agent
                result = await db.execute(select(func.count()).where(Agent.status == "online"))
                active_agents_gauge.set(result.scalar() or 0)
        except Exception:
            pass

        await asyncio.sleep(30)


def start_health_server():
    server = HTTPServer(("0.0.0.0", 8001), HealthHandler)
    Thread(target=server.serve_forever, daemon=True).start()
    log.info("health_server_started", port=8001)

async def main():
    log.info("worker_starting")
    start_health_server()

    await seed_if_empty()

    async with AsyncSessionLocal() as db:
        dec_engine, sig_engine = await load_engines(db)

    state = {"dec_engine": dec_engine, "sig_engine": sig_engine}
    log.info("engines_loaded", decoders=len(dec_engine._decoders), rules=len(sig_engine._rules))

    async def _consume():
        while True:
            await consume_loop(state["dec_engine"], state["sig_engine"])

    redis = await get_redis()

    await asyncio.gather(
        _consume(),
        reload_loop(state),
        dlq_retry_loop(state),
        webhook_retry_loop(),
        ai_analysis_loop(),
        ai_backfill_loop(),
        ueba_snapshot_loop(),
        ueba_train_loop(),
        ueba_ai_loop(),
        hunt_loop(),
        agent_monitor_loop(),
        maintenance_loop(),
        report_loop(redis),
        hunt_scheduler_loop(),
        rag_index_loop(),
        sop_index_loop(),
        health_probe_loop(),
    )

if __name__ == "__main__":
    asyncio.run(main())
