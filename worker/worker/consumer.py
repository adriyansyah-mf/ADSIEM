# worker/worker/consumer.py
import asyncio
import json
import socket
import uuid
from datetime import datetime, timezone
import structlog
from prometheus_client import Counter
from sqlalchemy.ext.asyncio import AsyncSession

from worker.config import REDIS_CONSUMER_GROUP, REDIS_STREAM_KEY
from worker.database import AsyncSessionLocal
from worker.decoder_engine import DecoderEngine
from worker.models import Event, RawLog
from worker.redis_client import get_redis
from worker.sigma_engine import SigmaEngine
from worker.alert_manager import create_alert
from worker.ueba.scorer import score_event as ueba_score_event

log = structlog.get_logger()
CONSUMER_NAME = f"worker-{socket.gethostname()}"

logs_ingested   = Counter("siem_logs_ingested_total", "Total logs ingested")
events_decoded  = Counter("siem_events_decoded_total", "Total events decoded")
decode_failures = Counter("siem_decode_failures_total", "Total decode failures")
alerts_total    = Counter("siem_alerts_generated_total", "Alerts generated", ["severity"])
sigma_matches   = Counter("siem_sigma_matches_total", "Sigma rule matches", ["rule_id"])

async def ensure_stream_group(redis) -> None:
    try:
        await redis.xgroup_create(REDIS_STREAM_KEY, REDIS_CONSUMER_GROUP, id="0", mkstream=True)
    except Exception as e:
        if "BUSYGROUP" not in str(e):
            raise

async def load_engines(db: AsyncSession) -> tuple[DecoderEngine, SigmaEngine]:
    from sqlalchemy import select
    from worker.models import Decoder, Rule

    result = await db.execute(select(Decoder).where(Decoder.is_enabled == True).order_by(Decoder.priority))
    decoder_yamls = [d.content for d in result.scalars().all()]
    dec_engine = DecoderEngine()
    dec_engine.load_from_yaml_list(decoder_yamls)

    result = await db.execute(select(Rule).where(Rule.is_enabled == True))
    rule_yamls = [r.content for r in result.scalars().all()]
    redis = await get_redis()
    sig_engine = SigmaEngine(redis=redis)
    sig_engine.load_from_yaml_list(rule_yamls)

    return dec_engine, sig_engine

async def process_message(
    data: dict,
    dec_engine: DecoderEngine,
    sig_engine: SigmaEngine,
) -> None:
    agent_id_str = data.get("agent_id")
    log_type = data.get("log_type", "")
    raw_message = data.get("raw_message", "")
    received_at_str = data.get("received_at", "")
    hostname = data.get("hostname", "unknown")
    group_id = data.get("group_id", "default")

    try:
        received_at = datetime.fromisoformat(received_at_str)
    except Exception:
        received_at = datetime.now(timezone.utc)

    agent_id = uuid.UUID(agent_id_str) if agent_id_str else None

    async with AsyncSessionLocal() as db:
        raw_log = RawLog(agent_id=agent_id, log_type=log_type, raw_message=raw_message, received_at=received_at)
        db.add(raw_log)
        await db.flush()

        decoded = dec_engine.decode(log_type, raw_message)
        if not decoded:
            decode_failures.inc()

        event = Event(
            raw_log_id=raw_log.id,
            agent_id=agent_id,
            group_id=group_id,
            decoded_fields=decoded,
            event_category=decoded.get("event.category"),
            event_action=decoded.get("event.action"),
            source_ip=decoded.get("source.ip"),
            user_name=decoded.get("user.name"),
        )
        db.add(event)
        await db.commit()
        await db.refresh(event)

    logs_ingested.inc()
    events_decoded.inc()

    flat_event = {**decoded, "group_id": group_id, "hostname": hostname}
    rule_matches = await sig_engine.evaluate(flat_event)
    for match in rule_matches:
        sigma_matches.labels(rule_id=match["id"]).inc()
        alerts_total.labels(severity=match["level"]).inc()
        await create_alert(
            rule_match=match,
            event_id=event.id,
            agent_id=agent_id,
            group_id=group_id,
            source_ip=decoded.get("source.ip"),
            hostname=hostname,
        )
        log.info("alert_generated", title=match["title"], severity=match["level"], source_ip=decoded.get("source.ip"))

    # UEBA scoring — best-effort, never block main pipeline
    try:
        _redis = await get_redis()
        await ueba_score_event(_redis, {**decoded, "hostname": hostname}, group_id)
    except Exception as _ueba_exc:
        log.warning("ueba_score_error", error=str(_ueba_exc))

async def consume_loop(dec_engine: DecoderEngine, sig_engine: SigmaEngine) -> None:
    redis = await get_redis()
    await ensure_stream_group(redis)

    while True:
        try:
            messages = await redis.xreadgroup(
                REDIS_CONSUMER_GROUP, CONSUMER_NAME,
                {REDIS_STREAM_KEY: ">"}, count=10, block=5000
            )
            if not messages:
                continue
            for _stream, entries in messages:
                for msg_id, data in entries:
                    try:
                        await process_message(data, dec_engine, sig_engine)
                        await redis.xack(REDIS_STREAM_KEY, REDIS_CONSUMER_GROUP, msg_id)
                    except Exception as exc:
                        log.error("message_processing_failed", msg_id=msg_id, error=str(exc))
                        await redis.xack(REDIS_STREAM_KEY, REDIS_CONSUMER_GROUP, msg_id)
                        await redis.xadd(f"{REDIS_STREAM_KEY}:failed", data)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            log.error("consume_loop_error", error=str(exc))
            await asyncio.sleep(5)

async def reload_loop(state: dict) -> None:
    from worker.config import RELOAD_INTERVAL
    while True:
        await asyncio.sleep(RELOAD_INTERVAL)
        try:
            async with AsyncSessionLocal() as db:
                dec_engine, sig_engine = await load_engines(db)
            state["dec_engine"] = dec_engine
            state["sig_engine"] = sig_engine
            log.info("engines_reloaded")
        except Exception as exc:
            log.error("reload_failed", error=str(exc))
