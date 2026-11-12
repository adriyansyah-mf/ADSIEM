# worker/worker/syslog_receiver.py
"""Agentless log intake: firewalls, switches and appliances send syslog (UDP or
TCP, RFC 3164/5424, CEF) here, and each message joins the same Redis stream the
agents feed, so decoding, Sigma, UEBA and alerting work unchanged.

Only senders registered in syslog_sources are accepted: the sender's address
picks the group and the log type (which decoders apply). Anything else is
dropped and remembered in Redis (UNKNOWN_KEY) so an admin can register it.

Run: python -m worker.syslog_receiver
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone

import structlog
from prometheus_client import Counter, Gauge, start_http_server
from sqlalchemy import select, update

from worker import config
from worker.syslog_parse import SourceEntry, SourceTable, StreamFramer, normalize_ip, parse_syslog

log = structlog.get_logger()

# Shared with server-api/app/api/routes/syslog_sources.py
UNKNOWN_KEY = "siem:syslog:unknown"
UNKNOWN_TTL = 7 * 86400
UNKNOWN_MAX = 500          # distinct unknown senders kept per flush
RELOAD_INTERVAL = 15
STATS_INTERVAL = 30
BATCH = 500
TCP_IDLE_TIMEOUT = 600

received = Counter("siem_syslog_received_total", "Syslog frames received", ["proto"])
dropped = Counter("siem_syslog_dropped_total", "Syslog frames dropped", ["reason"])
enqueued = Counter("siem_syslog_enqueued_total", "Syslog messages queued for the worker")
sources_gauge = Gauge("siem_syslog_sources", "Registered syslog sources loaded")
backlog_gauge = Gauge("siem_syslog_backlog", "Messages waiting to be written to Redis")


class Receiver:
    def __init__(self, redis, table: SourceTable | None = None, *, stream_key: str = config.REDIS_STREAM_KEY,
                 maxlen: int = config.REDIS_STREAM_MAXLEN, queue_size: int = config.SYSLOG_QUEUE_SIZE):
        self.redis = redis
        self.table = table or SourceTable()
        self.stream_key = stream_key
        self.maxlen = maxlen
        self.queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=queue_size)
        self.seen: dict[str, list] = defaultdict(lambda: [0, None])      # source id -> [count, last_seen]
        self.unknown: dict[str, dict] = {}                                # sender ip -> {count, last_seen, sample}

    def submit(self, peer_ip: str, frame: bytes, proto: str) -> None:
        """One frame from the network; never blocks and never raises."""
        received.labels(proto=proto).inc()
        try:
            ip = normalize_ip(peer_ip)
        except ValueError:
            dropped.labels(reason="bad_peer").inc()
            return
        source = self.table.lookup(ip)
        msg = parse_syslog(frame)
        if msg is None:
            dropped.labels(reason="empty").inc()
            return
        now = datetime.now(timezone.utc)
        if source is None:
            dropped.labels(reason="unknown_source").inc()
            entry = self.unknown.get(ip)
            if entry is None:
                if len(self.unknown) >= UNKNOWN_MAX:
                    return
                entry = self.unknown[ip] = {"count": 0, "sample": msg.raw_message[:300], "proto": proto}
            entry["count"] += 1
            entry["last_seen"] = now.isoformat()
            return
        payload = {
            "agent_id": "",
            "group_id": source.group_id,
            "hostname": msg.hostname or source.name,
            "log_type": source.log_type,
            "raw_message": msg.raw_message,
            "received_at": now.isoformat(),
            "location": f"syslog://{ip}",
        }
        try:
            self.queue.put_nowait(payload)
        except asyncio.QueueFull:
            dropped.labels(reason="backlog_full").inc()
            return
        stat = self.seen[source.id]
        stat[0] += 1
        stat[1] = now

    async def flush_once(self) -> int:
        """Write up to BATCH queued messages to the stream. On a Redis error the
        batch goes back to the front of the line and the error propagates."""
        batch = [await self.queue.get()]
        while len(batch) < BATCH and not self.queue.empty():
            batch.append(self.queue.get_nowait())
        try:
            pipe = self.redis.pipeline(transaction=False)
            for payload in batch:
                pipe.xadd(self.stream_key, payload, maxlen=self.maxlen, approximate=True)
            await pipe.execute()
        except Exception:
            self._requeue(batch)
            raise
        enqueued.inc(len(batch))
        backlog_gauge.set(self.queue.qsize())
        return len(batch)

    def _requeue(self, batch: list[dict]) -> None:
        # asyncio.Queue has no push-front; rebuild so retried messages keep their order
        rest = []
        while not self.queue.empty():
            rest.append(self.queue.get_nowait())
        for payload in batch + rest:
            try:
                self.queue.put_nowait(payload)
            except asyncio.QueueFull:
                dropped.labels(reason="backlog_full").inc()

    async def flush_loop(self) -> None:
        delay = 1.0
        while True:
            try:
                await self.flush_once()
                delay = 1.0
            except Exception as exc:  # noqa: BLE001 — Redis down: keep the backlog, retry
                log.warning("syslog_enqueue_failed", error=str(exc), backlog=self.queue.qsize())
                await asyncio.sleep(delay)
                delay = min(delay * 2, 30.0)

    async def publish_unknown(self) -> None:
        if not self.unknown:
            return
        pending, self.unknown = self.unknown, {}
        existing = await self.redis.hmget(UNKNOWN_KEY, list(pending)) or [None] * len(pending)
        mapping = {}
        for (ip, entry), old in zip(pending.items(), existing):
            if old:
                try:
                    entry["count"] += int(json.loads(old).get("count", 0))
                except (ValueError, TypeError, AttributeError):
                    pass
            mapping[ip] = json.dumps(entry)
        await self.redis.hset(UNKNOWN_KEY, mapping=mapping)
        await self.redis.expire(UNKNOWN_KEY, UNKNOWN_TTL)
        log.info("syslog_unknown_senders", senders=sorted(pending))

    async def write_stats(self, session_factory) -> None:
        if not self.seen:
            return
        from worker.models import SyslogSource
        pending, self.seen = dict(self.seen), defaultdict(lambda: [0, None])
        async with session_factory() as db:
            for source_id, (count, last_seen) in pending.items():
                await db.execute(update(SyslogSource).where(SyslogSource.id == uuid.UUID(source_id)).values(
                    message_count=SyslogSource.message_count + count, last_seen_at=last_seen))
            await db.commit()


async def load_table(session_factory) -> SourceTable:
    from worker.models import SyslogSource
    async with session_factory() as db:
        rows = (await db.execute(select(SyslogSource).where(SyslogSource.enabled.is_(True)))).scalars().all()
    entries = []
    for row in rows:
        try:
            network = ipaddress.ip_network(row.cidr, strict=False)
        except ValueError:
            log.warning("syslog_source_bad_cidr", source=row.name, cidr=row.cidr)
            continue
        entries.append(SourceEntry(str(row.id), row.name, row.group_id, row.log_type, network))
    return SourceTable(entries)


async def housekeeping_loop(receiver: Receiver, session_factory) -> None:
    last_stats = 0.0
    while True:
        try:
            receiver.table = await load_table(session_factory)
            sources_gauge.set(len(receiver.table))
        except Exception as exc:  # noqa: BLE001 — keep the last good table
            log.warning("syslog_source_reload_failed", error=str(exc))
        if time.monotonic() - last_stats >= STATS_INTERVAL:
            last_stats = time.monotonic()
            for step in (receiver.publish_unknown(), receiver.write_stats(session_factory)):
                try:
                    await step
                except Exception as exc:  # noqa: BLE001
                    log.warning("syslog_stats_failed", error=str(exc))
        await asyncio.sleep(RELOAD_INTERVAL)


class UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, receiver: Receiver):
        self.receiver = receiver

    def datagram_received(self, data: bytes, addr) -> None:
        self.receiver.submit(addr[0], data, "udp")


async def handle_tcp(receiver: Receiver, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")
    peer_ip = peer[0] if peer else ""
    framer = StreamFramer()
    try:
        while True:
            chunk = await asyncio.wait_for(reader.read(65536), timeout=TCP_IDLE_TIMEOUT)
            if not chunk:
                break
            for frame in framer.feed(chunk):
                receiver.submit(peer_ip, frame, "tcp")
        for frame in framer.flush():
            receiver.submit(peer_ip, frame, "tcp")
    except (asyncio.TimeoutError, ConnectionError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass


async def serve(receiver: Receiver, bind: str, udp_port: int, tcp_port: int):
    loop = asyncio.get_running_loop()
    udp, _ = await loop.create_datagram_endpoint(lambda: UDPProtocol(receiver), local_addr=(bind, udp_port))
    tcp = await asyncio.start_server(lambda r, w: handle_tcp(receiver, r, w), bind, tcp_port)
    return udp, tcp


async def main() -> None:
    from worker.database import AsyncSessionLocal
    from worker.redis_client import get_redis

    receiver = Receiver(await get_redis())
    start_http_server(config.SYSLOG_METRICS_PORT)
    try:
        receiver.table = await load_table(AsyncSessionLocal)
    except Exception as exc:  # noqa: BLE001 — table missing until server-api starts; the loop retries
        log.warning("syslog_source_initial_load_failed", error=str(exc))
    udp, tcp = await serve(receiver, config.SYSLOG_BIND, config.SYSLOG_UDP_PORT, config.SYSLOG_TCP_PORT)
    log.info("syslog_receiver_listening", bind=config.SYSLOG_BIND, udp=config.SYSLOG_UDP_PORT,
             tcp=config.SYSLOG_TCP_PORT, sources=len(receiver.table))
    try:
        await asyncio.gather(receiver.flush_loop(), housekeeping_loop(receiver, AsyncSessionLocal))
    finally:
        udp.close()
        tcp.close()


if __name__ == "__main__":
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(config.LOG_LEVEL.upper())),
        processors=[structlog.processors.TimeStamper(fmt="iso"), structlog.processors.JSONRenderer()],
    )
    asyncio.run(main())
