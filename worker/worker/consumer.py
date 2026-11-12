# worker/worker/consumer.py
import asyncio
import json
import socket
import time
import uuid
from datetime import datetime, timezone
import httpx
import redis.exceptions
import sqlalchemy.exc
import structlog
from prometheus_client import Counter
from sqlalchemy.ext.asyncio import AsyncSession

from worker.config import (CONSUME_BATCH, CONSUME_CONCURRENCY, DLQ_MAX_ATTEMPTS, DLQ_MAXLEN, DLQ_RETRY_BATCH,
                           DLQ_RETRY_INTERVAL, REDIS_CONSUMER_GROUP, REDIS_STREAM_KEY)
from worker.database import AsyncSessionLocal
from worker.decoder_engine import DecoderEngine
from worker.redis_client import get_redis
from worker.sigma_engine import SigmaEngine
from worker.alert_manager import create_alert
from worker.ueba.scorer import score_event as ueba_score_event
from worker.es_client import bulk_index_items, index_log, ping as es_ping
from worker import evidence_inbox
from worker.policy_exclusions import excluded as excluded_by_policy
from worker.malware_feed import learn_from_event

log = structlog.get_logger()
CONSUMER_NAME = f"worker-{socket.gethostname()}"

logs_ingested   = Counter("siem_logs_ingested_total", "Total logs ingested")
events_decoded  = Counter("siem_events_decoded_total", "Total events decoded")
decode_failures = Counter("siem_decode_failures_total", "Total decode failures")
alerts_total    = Counter("siem_alerts_generated_total", "Alerts generated", ["severity", "rule_id"])
sigma_matches   = Counter("siem_sigma_matches_total", "Sigma rule matches", ["rule_id"])
dlq_dropped     = Counter("siem_dlq_dropped_total", "Log lines dropped after DLQ_MAX_ATTEMPTS failures")

DLQ_KEY = f"{REDIS_STREAM_KEY}:failed"
DLQ_ATTEMPTS_FIELD = "_dlq_attempts"
# A line whose detection ran but whose Elasticsearch write failed carries its
# event_id into the DLQ, so the retry indexes the same document the alerts
# point at; DETECTED_KEY marks that detection already ran for that event_id.
EVENT_ID_FIELD = "_event_id"
DETECTED_KEY = "siem:detected:{}"
DETECTED_TTL = 7 * 86400


class IndexFailed(Exception):
    """Detection ran for this line, but writing it to Elasticsearch failed.
    __cause__ is the underlying error (used to tell an outage from a bad line)."""

    def __init__(self, event_id: uuid.UUID):
        super().__init__(f"elasticsearch write failed for event {event_id}")
        self.event_id = event_id


async def _mark_detected(event_id: uuid.UUID) -> None:
    try:
        await (await get_redis()).set(DETECTED_KEY.format(event_id), "1", ex=DETECTED_TTL)
    except Exception as exc:  # noqa: BLE001 — worst case the retry detects again
        log.warning("detected_mark_failed", event_id=str(event_id), error=str(exc))


async def _already_detected(event_id: uuid.UUID) -> bool:
    try:
        return bool(await (await get_redis()).exists(DETECTED_KEY.format(event_id)))
    except Exception:  # noqa: BLE001
        return False

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
    *,
    defer_index: bool = False,
) -> tuple[uuid.UUID, dict] | None:
    """Evaluate, score and index one log line.

    Detection runs before the Elasticsearch write, so an Elasticsearch outage
    delays search, not alerts. A retry (durable evidence passes its stable
    event_id; a DLQ'd legacy line carries _event_id) skips detection when it
    already ran for that event, so it never alerts twice.

    defer_index=True returns (event_id, document) instead of writing it: the
    legacy consumer writes a whole batch with one _bulk request. Otherwise an
    Elasticsearch failure raises IndexFailed."""
    agent_id_str = data.get("agent_id")
    log_type = data.get("log_type", "").strip()
    raw_message = data.get("raw_message", "").strip()
    received_at_str = data.get("received_at", "")
    hostname = data.get("hostname", "unknown")
    group_id = data.get("group_id", "default")

    if not raw_message:
        log.warning("skipping_empty_message", agent_id=agent_id_str, log_type=log_type)
        return None

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

    retry = event_id is not None or bool(data.get(EVENT_ID_FIELD))
    event_id = event_id or (uuid.UUID(data[EVENT_ID_FIELD]) if data.get(EVENT_ID_FIELD) else uuid.uuid4())
    if not (retry and await _already_detected(event_id)):
        await _detect(decoded, event_id, agent_id, group_id, hostname, raw_message, log_type, sig_engine)

    doc = {
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
    }
    if defer_index:
        return event_id, doc
    try:
        await index_log(str(event_id), doc)
    except Exception as exc:
        await _mark_detected(event_id)
        raise IndexFailed(event_id) from exc
    logs_ingested.inc()
    return None


async def _detect(decoded: dict, event_id: uuid.UUID, agent_id, group_id: str, hostname: str,
                  raw_message: str, log_type: str, sig_engine: SigmaEngine) -> None:
    # raw_message gives Sigma `keywords` selections the original log line to search;
    # log_type selects which rules apply (their logsource)
    flat_event = {**decoded, "group_id": group_id, "hostname": hostname, "raw_message": raw_message,
                  "log_type": log_type}
    rule_matches = await sig_engine.evaluate(flat_event)
    if rule_matches:
        # the group policy's alert exclusions (a known-good program, folder, hash or command line)
        skip = await excluded_by_policy(flat_event, group_id)
        if skip is not None:
            log.info("alert_excluded_by_policy", group_id=group_id, kind=skip.get("kind"),
                     value=skip.get("value"), rules=[m["title"] for m in rule_matches])
            rule_matches = []
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

    # a file matching a critical YARA rule becomes a known-malware hash for every agent
    try:
        await learn_from_event(decoded, hostname)
    except Exception as _learn_exc:  # noqa: BLE001 — never block the pipeline
        log.warning("malware_hash_learn_failed", error=str(_learn_exc))

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


async def _process_group(redis, group: list, dec_engine, sig_engine, limit: asyncio.Semaphore) -> list:
    """Detect each line of one source, in order. Returns the lines still to be
    written to Elasticsearch, as (msg_id, data, event_id, doc): the caller
    writes the whole batch with one _bulk request and acks them after."""
    pending = []
    async with limit:
        for msg_id, data, predecoded in group:
            try:
                result = await process_message(data, dec_engine, sig_engine, predecoded, defer_index=True)
            except Exception as exc:
                log.error("message_processing_failed", msg_id=msg_id, error=str(exc))
                await _fail(redis, msg_id, data, exc)
                continue
            if result is None:  # nothing to index (empty line)
                await redis.xack(REDIS_STREAM_KEY, REDIS_CONSUMER_GROUP, msg_id)
            else:
                pending.append((msg_id, data, *result))
    return pending


async def _fail(redis, msg_id: str, data: dict, exc: BaseException) -> None:
    """DLQ the line, then ack it. If the DLQ write itself fails (e.g. Redis full,
    noeviction), leave it unacked: stream_maintenance hands stale pending entries back."""
    try:
        await dead_letter(redis, data, exc)
    except Exception as dlq_exc:  # noqa: BLE001
        log.error("dlq_write_failed", msg_id=msg_id, error=str(dlq_exc))
        return
    await redis.xack(REDIS_STREAM_KEY, REDIS_CONSUMER_GROUP, msg_id)


async def _index_batch(redis, pending: list) -> None:
    """One _bulk write for the batch's detected lines. A line Elasticsearch
    refuses (or the whole request failing) goes to the DLQ with its event_id,
    marked as detected, so the retry only indexes it."""
    if not pending:
        return
    try:
        failed = await bulk_index_items([(str(event_id), doc) for _m, _d, event_id, doc in pending])
        request_error = None
    except Exception as exc:  # noqa: BLE001 — Elasticsearch down: every line is retried
        failed, request_error = {}, exc
    acked = []
    for msg_id, data, event_id, _doc in pending:
        error = request_error or failed.get(str(event_id))
        if error is None:
            acked.append(msg_id)
            continue
        await _mark_detected(event_id)
        cause = error if isinstance(error, BaseException) else _bulk_item_error(error)
        await _fail(redis, msg_id, {**data, EVENT_ID_FIELD: str(event_id)}, cause)
    if acked:
        logs_ingested.inc(len(acked))
        await redis.xack(REDIS_STREAM_KEY, REDIS_CONSUMER_GROUP, *acked)
    if request_error is not None:
        log.error("es_bulk_failed", lines=len(pending), error=str(request_error))


def _bulk_item_error(item: dict) -> Exception:
    """A _bulk item failure as an exception dead_letter can classify: an
    HTTPStatusError with the item's status, so 429/5xx count as an outage."""
    status = int(item.get("status") or 500)
    request = httpx.Request("POST", "/_bulk")
    return httpx.HTTPStatusError(str(item.get("error"))[:300], request=request,
                                 response=httpx.Response(status, request=request))


# HTTP statuses from Elasticsearch that say "not now" rather than "this document
# is bad": overloaded, read-only (flood-stage disk), timeouts, server errors.
_RETRYABLE_STATUS = {403, 408, 409, 429}


def is_infrastructure_error(exc: BaseException) -> bool:
    """True when the failure is about a dependency (Elasticsearch, Postgres,
    Redis, the network) rather than the line itself. Such failures must not use
    up the line's attempts: an outage would otherwise get its lines dropped."""
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        return code >= 500 or code in _RETRYABLE_STATUS
    return isinstance(exc, (httpx.TransportError, OSError, asyncio.TimeoutError, redis.exceptions.RedisError,
                            sqlalchemy.exc.OperationalError, sqlalchemy.exc.InterfaceError,
                            sqlalchemy.exc.TimeoutError))


async def dead_letter(redis, data: dict, exc: BaseException | None = None) -> bool:
    """Park a failed line in the DLQ. Attempts count only failures caused by the
    line itself; a line that fails that way DLQ_MAX_ATTEMPTS times is a poison
    message and is dropped rather than retried forever. Returns False when
    dropped; raises when the DLQ write itself fails."""
    attempts = int(data.get(DLQ_ATTEMPTS_FIELD) or 0)
    if exc is None or not is_infrastructure_error(exc):
        attempts += 1
    if attempts > DLQ_MAX_ATTEMPTS:
        dlq_dropped.inc()
        log.error("dlq_message_dropped", attempts=DLQ_MAX_ATTEMPTS, log_type=data.get("log_type"),
                  hostname=data.get("hostname"))
        return False
    await redis.xadd(DLQ_KEY, {**data, DLQ_ATTEMPTS_FIELD: str(attempts)},
                     maxlen=DLQ_MAXLEN, approximate=True)
    return True


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
            results = await asyncio.gather(
                *(_process_group(redis, group, dec_engine, sig_engine, limit)
                  for group in group_by_source(legacy, dec_engine)),
                *(_process_references(redis, group, state, limit) for group in group_references(references)),
            )
            await _index_batch(redis, [line for pending in results if pending for line in pending])
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

async def dlq_retry_once(redis, es_up) -> int:
    """Move up to DLQ_RETRY_BATCH lines from the DLQ back into the stream, but
    only while Elasticsearch is up: retrying into an outage would only fail them
    again and use up their attempts. Returns how many were moved."""
    if not await es_up():
        return 0
    entries = await redis.xrange(DLQ_KEY, count=DLQ_RETRY_BATCH)
    if not entries:
        return 0
    pipe = redis.pipeline()
    for entry_id, data in entries:
        pipe.xadd(REDIS_STREAM_KEY, data)
        pipe.xdel(DLQ_KEY, entry_id)
    await pipe.execute()
    return len(entries)


async def dlq_retry_loop(state: dict) -> None:
    """Re-inject DLQ lines into the stream once Elasticsearch is reachable again."""
    while True:
        await asyncio.sleep(DLQ_RETRY_INTERVAL)
        try:
            moved = await dlq_retry_once(await get_redis(), es_ping)
            if moved:
                log.info("dlq_retry", count=moved)
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
