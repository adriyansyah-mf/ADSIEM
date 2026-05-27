# worker/worker/main.py
import asyncio
import time
import logging
import structlog
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from prometheus_client import CONTENT_TYPE_LATEST, Gauge, generate_latest

from worker.config import LOG_LEVEL
from worker.database import AsyncSessionLocal
from worker.decoder_engine import DecoderEngine
from worker.redis_client import get_redis
from worker.seeder import seed_if_empty
from worker.sigma_engine import SigmaEngine
from worker.consumer import consume_loop, load_engines, reload_loop
from worker.webhook_sender import webhook_retry_loop
from worker.ai_consumer import ai_analysis_loop, ai_backfill_loop
from worker.ueba.loops import ueba_snapshot_loop, ueba_train_loop, ueba_ai_loop
from worker.hunter import hunt_loop

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

class HealthHandler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def do_GET(self):
        if self.path == "/health":
            body = b'{"status":"ok"}'
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

    await asyncio.gather(
        _consume(),
        reload_loop(state),
        webhook_retry_loop(),
        ai_analysis_loop(),
        ai_backfill_loop(),
        ueba_snapshot_loop(),
        ueba_train_loop(),
        ueba_ai_loop(),
        hunt_loop(),
    )

if __name__ == "__main__":
    asyncio.run(main())
