# worker/worker/consumer.py
import asyncio
import json
import socket
import time
import uuid
from datetime import datetime, timezone
import structlog
from prometheus_client import Counter
from sqlalchemy.ext.asyncio import AsyncSession

from worker.config import CONSUME_BATCH, CONSUME_CONCURRENCY, REDIS_CONSUMER_GROUP, REDIS_STREAM_KEY
from worker.database import AsyncSessionLocal
from worker.decoder_engine import DecoderEngine
from worker.redis_client import get_redis
from worker.sigma_engine import SigmaEngine
from worker.alert_manager import create_alert
from worker.ueba.scorer import score_event as ueba_score_event
from worker.es_client import index_log
from worker import evidence_inbox

log = structlog.get_logger()
CONSUMER_NAME = f"worker-{socket.gethostname()}"

logs_ingested   = Counter("siem_logs_ingested_total", "Total logs ingested")
events_decoded  = Counter("siem_events_decoded_total", "Total events decoded")
decode_failures = Counter("siem_decode_failures_total", "Total decode failures")
alerts_total    = Counter("siem_alerts_generated_total", "Alerts generated", ["severity", "rule_id"])
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
    rule_rows = result.scalars().all()
    redis = await get_redis()
    sig_engine = SigmaEngine(redis=redis)
    sig_engine.load_from_yaml_list([r.content for r in rule_rows], [str(r.id) for r in rule_rows])

    return dec_engine, sig_engine

# agent ids known to exist -> expiry; one DB round trip per agent a minute
# instead of one per log line
_known_agents: dict[uuid.UUID, float] = {}
AGENT_CACHE_TTL = 60.0


async def _agent_exists(agent_id: uuid.UUID) -> bool:
    now = time.monotonic()
    if _known_agents.get(agent_id, 0.0) > now:
        return True
    async with AsyncSessionLocal() as db:
        from worker.models import Agent as AgentModel
        exists = await db.get(AgentModel, agent_id) is not None
    if exists:
        _known_agents[agent_id] = now + AGENT_CACHE_TTL
    return exists


async def process_message(
    data: dict,
    dec_engine: DecoderEngine,
    sig_engine: SigmaEngine,
    predecoded: tuple[dict, str | None] | None = None,
    event_id: uuid.UUID | None = None,
) -> None:
    """Index, evaluate and score one log line. Durable evidence passes its
    stable event_id (evidence_inbox.evidence_event_id); legacy lines get a new one."""
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

    if agent_id is not None and not await _agent_exists(agent_id):
        agent_id = None

    decoded, decoder_name = predecoded or dec_engine.decode_named(log_type, raw_message)
    if not decoded:
        decode_failures.inc()
    else:
        events_decoded.inc()

    event_id = event_id or uuid.uuid4()
    await index_log(str(event_id), {
        "agent_id": str(agent_id) if agent_id else None,
        "group_id": group_id,
        "log_type": log_type,
        "location": data.get("location") or None,  # source file, from agents >= 1.4
        "decoder": decoder_name,
        "raw_message": raw_message,
        "decoded_fields": decoded,
        "event_category": decoded.get("event.category"),
        "event_action": decoded.get("event.action"),
        "source_ip": decoded.get("source.ip"),
        "user_name": decoded.get("user.name"),
        "created_at": received_at.isoformat(),
    })

    logs_ingested.inc()

    # raw_message gives Sigma `keywords` selections the original log line to search;
    # log_type selects which rules apply (their logsource)
    flat_event = {**decoded, "group_id": group_id, "hostname": hostname, "raw_message": raw_message,
                  "log_type": log_type}
    rule_matches = await sig_engine.evaluate(flat_event)
    for match in rule_matches:
        sigma_matches.labels(rule_id=match["id"]).inc()
        alerts_total.labels(severity=match["level"], rule_id=match["id"]).inc()
        alert_id = await create_alert(
            rule_match=match,
            event_id=event_id,
            agent_id=agent_id,
            group_id=group_id,
            source_ip=decoded.get("source.ip"),
            hostname=hostname,
        )
        if alert_id is not None:
            log.info("alert_handled", title=match["title"], severity=match["level"],
                     source_ip=decoded.get("source.ip"), alert_id=str(alert_id))

    # UEBA scoring — best-effort, never block main pipeline
    try:
        _redis = await get_redis()
        await ueba_score_event(_redis, {**decoded, "hostname": hostname}, group_id)
    except Exception as _ueba_exc:
        log.warning("ueba_score_error", error=str(_ueba_exc))

def group_by_source(entries: list, dec_engine: DecoderEngine) -> list[list]:
    """Split a batch into per-source groups of (msg_id, data, predecoded), in
    stream order. Groups run concurrently; a group runs in order, so threshold
    and sequence rules, suppression and alert dedup for one attacker or host
    see its events one at a time, as before."""
    groups: dict[str, list] = {}
    for msg_id, data in entries:
        raw = data.get("raw_message", "").strip()
        try:
            predecoded = dec_engine.decode_named(data.get("log_type", "").strip(), raw) if raw else None
        except Exception:
            predecoded = None  # process_message decodes again and fails that entry alone
        key = (predecoded and predecoded[0].get("source.ip")) or data.get("hostname") or ""
        groups.setdefault(key, []).append((msg_id, data, predecoded))
    return list(groups.values())


async def _process_group(redis, group: list, dec_engine, sig_engine, limit: asyncio.Semaphore) -> None:
    async with limit:
        for msg_id, data, predecoded in group:
            try:
                await process_message(data, dec_engine, sig_engine, predecoded)
                await redis.xack(REDIS_STREAM_KEY, REDIS_CONSUMER_GROUP, msg_id)
            except Exception as exc:
                log.error("message_processing_failed", msg_id=msg_id, error=str(exc))
                await redis.xack(REDIS_STREAM_KEY, REDIS_CONSUMER_GROUP, msg_id)
                await redis.xadd(f"{REDIS_STREAM_KEY}:failed", data)


async def _process_references(redis, group: list, state: dict, limit: asyncio.Semaphore) -> None:
    """Durable inbox references for one host, in order. Every outcome is acked and
    nothing goes to the DLQ: the inbox row, not this stream entry, is the evidence,
    and evidence_inbox's dispatcher resends anything not completed."""
    async with limit:
        for msg_id, data in group:
            try:
                outcome = await evidence_inbox.process_reference(uuid.UUID(data["receipt_id"]), state)
                if outcome not in ("completed", "duplicate"):
                    log.info("evidence_reference_not_completed", receipt_id=data["receipt_id"], outcome=outcome)
            except Exception as exc:
                log.error("evidence_reference_failed", msg_id=msg_id, receipt_id=data.get("receipt_id"),
                          error=str(exc))
            await redis.xack(REDIS_STREAM_KEY, REDIS_CONSUMER_GROUP, msg_id)


def group_references(entries: list) -> list[list]:
    groups: dict[str, list] = {}
    for msg_id, data in entries:
        groups.setdefault(data.get("hostname") or "", []).append((msg_id, data))
    return list(groups.values())


async def consume_loop(state: dict) -> None:
    redis = await get_redis()
    await ensure_stream_group(redis)

    while True:
        try:
            # adaptive_loop moves state["concurrency"]; read it per batch, and read
            # enough entries that there are groups to fill it
            concurrency = state.get("concurrency", CONSUME_CONCURRENCY)
            limit = asyncio.Semaphore(concurrency)
            messages = await redis.xreadgroup(
                REDIS_CONSUMER_GROUP, CONSUMER_NAME,
                {REDIS_STREAM_KEY: ">"}, count=max(CONSUME_BATCH, concurrency * 12), block=5000
            )
            if not messages:
                continue
            dec_engine, sig_engine = state["dec_engine"], state["sig_engine"]
            entries = [entry for _stream, stream_entries in messages for entry in stream_entries]
            # durable inbox references carry no log line: route them before legacy decoding
            references = [e for e in entries if e[1].get("kind") == evidence_inbox.EVIDENCE_KIND]
            legacy = [e for e in entries if e[1].get("kind") != evidence_inbox.EVIDENCE_KIND]
            await asyncio.gather(
                *(_process_group(redis, group, dec_engine, sig_engine, limit)
                  for group in group_by_source(legacy, dec_engine)),
                *(_process_references(redis, group, state, limit) for group in group_references(references)),
            )
        except asyncio.CancelledError:
            break
        except Exception as exc:
            if "NOGROUP" in str(exc):
                # Redis restarted without its data: the stream and group are gone.
                # Recreate them; the evidence dispatcher re-sends its references.
                log.warning("consumer_group_recreated", error=str(exc))
                try:
                    await ensure_stream_group(redis)
                    continue
                except Exception as group_exc:  # noqa: BLE001 - Redis still down: retry below
                    exc = group_exc
            log.error("consume_loop_error", error=str(exc))
            await asyncio.sleep(5)

async def dlq_retry_loop(state: dict) -> None:
    """Periodically re-inject messages from the failed DLQ back into the main stream."""
    DLQ_KEY = f"{REDIS_STREAM_KEY}:failed"
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
            for entry_id, data in entries:
                pipe.xadd(REDIS_STREAM_KEY, data)
                pipe.xdel(DLQ_KEY, entry_id)
            await pipe.execute()
            log.info("dlq_retry", count=len(entries))
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
