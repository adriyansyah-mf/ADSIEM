# worker/worker/consumer.py
import asyncio
import os
import socket
import uuid
from datetime import datetime, timezone
from typing import TypeAlias
import structlog
from prometheus_client import Counter
from sqlalchemy.ext.asyncio import AsyncSession

from worker.config import REDIS_CONSUMER_GROUP, REDIS_STREAM_KEY
from worker.database import AsyncSessionLocal
from worker.decoder_engine import DecoderEngine
from worker.correlation_engine import CorrelationEngine
from worker.correlation_models import CorrelationDefinition
from worker.redis_client import get_redis
from worker.sigma_engine import SigmaEngine
from worker.event_normalizer import normalize_event
from worker.alert_manager import create_alert
from worker.ueba.scorer import score_event as ueba_score_event
from worker.es_client import index_log

log = structlog.get_logger()
CONSUMER_NAME = f"worker-{socket.gethostname()}"

logs_ingested   = Counter("siem_logs_ingested_total", "Total logs ingested")
events_decoded  = Counter("siem_events_decoded_total", "Total events decoded")
decode_failures = Counter("siem_decode_failures_total", "Total decode failures")
alerts_total    = Counter("siem_alerts_generated_total", "Alerts generated", ["severity", "rule_id"])
sigma_matches   = Counter("siem_sigma_matches_total", "Sigma rule matches", ["rule_id"])

CorrelationRuntime: TypeAlias = tuple[
    CorrelationEngine,
    tuple[CorrelationDefinition, ...],
]

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
    correlations: CorrelationRuntime | None = None,
) -> None:
    agent_id_str = data.get("agent_id")
    log_type = data.get("log_type", "").strip()
    raw_message = data.get("raw_message", "").strip()
    received_at_str = data.get("received_at", "")
    hostname = data.get("hostname", "unknown")
    group_id = data.get("group_id", "default")

    if not raw_message:
        log.warning("skipping_empty_message", agent_id=agent_id_str, log_type=log_type)
        return

    try:
        received_at = datetime.fromisoformat(received_at_str)
    except Exception:
        received_at = datetime.now(timezone.utc)

    agent_id = uuid.UUID(agent_id_str) if agent_id_str else None

    if agent_id is not None:
        async with AsyncSessionLocal() as db:
            from worker.models import Agent as AgentModel
            if not await db.get(AgentModel, agent_id):
                agent_id = None

    decoded = dec_engine.decode(log_type, raw_message)
    if not decoded:
        decode_failures.inc()
    else:
        events_decoded.inc()

    event_id = uuid.uuid4()
    normalized_event = normalize_event(decoded, hostname, received_at.isoformat())
    await index_log(str(event_id), {
        "agent_id": str(agent_id) if agent_id else None,
        "group_id": group_id,
        "log_type": log_type,
        "raw_message": raw_message,
        "decoded_fields": decoded,
        "normalized": normalized_event,
        "event_category": decoded.get("event.category"),
        "event_action": decoded.get("event.action"),
        "source_ip": decoded.get("source.ip"),
        "user_name": decoded.get("user.name"),
        "created_at": received_at.isoformat(),
    })

    logs_ingested.inc()

    flat_event = {**decoded, "group_id": group_id, "hostname": hostname}
    flat_event.update({
        "source.ip": normalized_event.get("source", {}).get("ip") if isinstance(normalized_event.get("source"), dict) else None,
        "host.name": normalized_event.get("host", {}).get("name") if isinstance(normalized_event.get("host"), dict) else None,
        "user.name": normalized_event.get("user", {}).get("name") if isinstance(normalized_event.get("user"), dict) else None,
    })
    rule_matches = await sig_engine.evaluate(flat_event)
    if correlations is not None:
        correlation_engine, definitions = correlations
        correlation_event = {
            **normalized_event,
            "event_id": str(event_id),
            "group_id": group_id,
            "decoded_fields": decoded,
        }
        for definition in definitions:
            correlation_match = await correlation_engine.evaluate(definition, correlation_event)
            if correlation_match is not None:
                correlation_rule = {
                    "id": definition.id,
                    "title": f"Correlation: {definition.id}",
                    "level": "high",
                    "correlation_id": definition.id,
                    "correlation_key": correlation_match.correlation_key,
                    "source_event_ids": [str(item["event_id"]) for item in correlation_match.events if item.get("event_id")],
                    "matched_fields": correlation_match.events[-1] if correlation_match.events else correlation_event,
                    "sigma_rule": {"id": definition.id, "title": f"Correlation: {definition.id}"},
                }
                sigma_matches.labels(rule_id=definition.id).inc()
                alerts_total.labels(severity="high", rule_id=definition.id).inc()
                await create_alert(
                    rule_match=correlation_rule,
                    event_id=event_id,
                    agent_id=agent_id,
                    group_id=group_id,
                    source_ip=decoded.get("source.ip"),
                    hostname=hostname,
                    user=decoded.get("user.name"),
                )
    for match in rule_matches:
        sigma_matches.labels(rule_id=match["id"]).inc()
        alerts_total.labels(severity=match["level"], rule_id=match["id"]).inc()
        await create_alert(
            rule_match=match,
            event_id=event_id,
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

async def consume_loop(state: dict) -> None:
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
                        await process_message(
                            data,
                            state["dec_engine"],
                            state["sig_engine"],
                            state.get("correlations"),
                        )
                        await redis.xack(REDIS_STREAM_KEY, REDIS_CONSUMER_GROUP, msg_id)
                    except Exception as exc:
                        log.error("message_processing_failed", msg_id=msg_id, error=str(exc))
                        await redis.xack(REDIS_STREAM_KEY, REDIS_CONSUMER_GROUP, msg_id)
                        failed_data = dict(data)
                        failed_data.setdefault("retry_count", "0")
                        failed_data["error_class"] = type(exc).__name__
                        failed_data["last_error"] = str(exc)[:2000]
                        now_iso = datetime.now(timezone.utc).isoformat()
                        failed_data.setdefault("first_failed_at", now_iso)
                        failed_data["last_failed_at"] = now_iso
                        await redis.xadd(f"{REDIS_STREAM_KEY}:failed", failed_data)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            log.error("consume_loop_error", error=str(exc))
            await asyncio.sleep(5)

MAX_INGEST_DLQ_RETRIES = int(os.environ.get("MAX_INGEST_DLQ_RETRIES", "5"))

async def dlq_retry_loop(state: dict) -> None:
    """Periodically re-inject messages from the failed DLQ back into the main
    stream, bounded by MAX_INGEST_DLQ_RETRIES. A message that has already
    exhausted its retry budget is moved to the `:dead` stream instead of being
    retried forever — without this cap, a permanently-malformed message would
    loop between the main stream and the DLQ indefinitely with no operator
    signal that it can never succeed.
    """
    DLQ_KEY = f"{REDIS_STREAM_KEY}:failed"
    DEAD_KEY = f"{REDIS_STREAM_KEY}:dead"
    RETRY_INTERVAL = 300  # retry every 5 minutes
    MAX_RETRY_BATCH = 50
    while True:
        await asyncio.sleep(RETRY_INTERVAL)
        try:
            redis = await get_redis()
            # Read up to MAX_RETRY_BATCH entries from the DLQ stream
            entries = await redis.xrange(DLQ_KEY, count=MAX_RETRY_BATCH)
            if not entries:
                continue
            pipe = redis.pipeline()
            retried = 0
            dead = 0
            for entry_id, data in entries:
                retry_count = int(data.get("retry_count", "0"))
                if retry_count >= MAX_INGEST_DLQ_RETRIES:
                    pipe.xadd(DEAD_KEY, data)
                    dead += 1
                else:
                    next_data = dict(data)
                    next_data["retry_count"] = str(retry_count + 1)
                    pipe.xadd(REDIS_STREAM_KEY, next_data)
                    retried += 1
                pipe.xdel(DLQ_KEY, entry_id)
            await pipe.execute()
            log.info("dlq_retry", retried=retried, moved_to_dead=dead)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            log.error("dlq_retry_error", error=str(exc))


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
