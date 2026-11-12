"""Agentless syslog receiver: real UDP/TCP sockets in, the agent queue's payload out."""
import asyncio
import ipaddress
import json
import socket

import pytest

from worker import syslog_receiver as sr
from worker.syslog_parse import SourceEntry, SourceTable


class FakePipe:
    def __init__(self, redis):
        self.redis, self.ops = redis, []

    def xadd(self, key, fields, **kw):
        self.ops.append((key, dict(fields), kw))

    async def execute(self):
        if self.redis.fail:
            raise ConnectionError("redis down")
        self.redis.stream.extend(self.ops)
        return [b"0-0"] * len(self.ops)


class FakeRedis:
    def __init__(self):
        self.stream, self.hashes, self.fail = [], {}, False

    def pipeline(self, transaction=False):
        return FakePipe(self)

    async def hmget(self, key, fields):
        return [self.hashes.get(key, {}).get(f) for f in fields]

    async def hset(self, key, mapping):
        self.hashes.setdefault(key, {}).update(mapping)

    async def expire(self, key, seconds):
        pass


def _table():
    return SourceTable([
        SourceEntry("11111111-1111-1111-1111-111111111111", "fw-hq", "blue", "fortigate_traffic",
                    ipaddress.ip_network("127.0.0.1/32")),
    ])


def test_registered_sender_becomes_an_agent_shaped_payload():
    rx = sr.Receiver(FakeRedis(), _table(), stream_key="siem:logs", maxlen=10)
    rx.submit("127.0.0.1", b"<189>date=2026-05-01 devname=FGT type=event", "udp")
    payload = rx.queue.get_nowait()
    assert payload["agent_id"] == ""            # the consumer reads "" as no agent
    assert payload["group_id"] == "blue"
    assert payload["log_type"] == "fortigate_traffic"
    assert payload["hostname"] == "fw-hq"       # no syslog header: the source's name
    assert payload["raw_message"] == "date=2026-05-01 devname=FGT type=event"
    assert payload["location"] == "syslog://127.0.0.1"
    assert all(isinstance(v, str) for v in payload.values())


def test_header_hostname_wins_over_the_source_name():
    rx = sr.Receiver(FakeRedis(), _table())
    rx.submit("127.0.0.1", b"<38>May  1 10:00:00 web01 sshd[1]: hi", "udp")
    assert rx.queue.get_nowait()["hostname"] == "web01"


async def test_unknown_sender_is_dropped_and_published_for_the_admin():
    redis = FakeRedis()
    rx = sr.Receiver(redis, _table())
    rx.submit("10.9.9.9", b"<13>hello", "udp")
    rx.submit("10.9.9.9", b"<13>again", "udp")
    assert rx.queue.empty()
    await rx.publish_unknown()
    entry = json.loads(redis.hashes[sr.UNKNOWN_KEY]["10.9.9.9"])
    assert entry["count"] == 2 and entry["sample"] == "hello" and entry["proto"] == "udp"
    rx.submit("10.9.9.9", b"<13>third", "tcp")
    await rx.publish_unknown()
    assert json.loads(redis.hashes[sr.UNKNOWN_KEY]["10.9.9.9"])["count"] == 3


def test_full_backlog_drops_instead_of_blocking():
    rx = sr.Receiver(FakeRedis(), _table(), queue_size=2)
    for _ in range(5):
        rx.submit("127.0.0.1", b"<13>x", "udp")
    assert rx.queue.qsize() == 2


async def test_redis_failure_keeps_the_batch_in_order():
    redis = FakeRedis()
    rx = sr.Receiver(redis, _table())
    for i in range(3):
        rx.submit("127.0.0.1", b"<13>m%d" % i, "udp")
    redis.fail = True
    with pytest.raises(ConnectionError):
        await rx.flush_once()
    assert rx.queue.qsize() == 3
    redis.fail = False
    assert await rx.flush_once() == 3
    assert [op[1]["raw_message"] for op in redis.stream] == ["m0", "m1", "m2"]
    assert redis.stream[0][2] == {"maxlen": rx.maxlen, "approximate": True}


def test_source_stats_count_per_source():
    rx = sr.Receiver(FakeRedis(), _table())
    rx.submit("127.0.0.1", b"<13>a", "udp")
    rx.submit("127.0.0.1", b"<13>b", "tcp")
    count, last_seen = rx.seen["11111111-1111-1111-1111-111111111111"]
    assert count == 2 and last_seen is not None


async def test_udp_and_tcp_listeners_end_to_end():
    redis = FakeRedis()
    rx = sr.Receiver(redis, _table(), stream_key="siem:logs")
    udp, tcp = await sr.serve(rx, "127.0.0.1", 0, 0)
    try:
        udp_port = udp.get_extra_info("sockname")[1]
        tcp_port = tcp.sockets[0].getsockname()[1]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"<13>via udp", ("127.0.0.1", udp_port))
        reader, writer = await asyncio.open_connection("127.0.0.1", tcp_port)
        writer.write(b"<13>via tcp one\n15 <13>via tcp two")
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        for _ in range(50):
            if rx.queue.qsize() >= 3:
                break
            await asyncio.sleep(0.02)
        while not rx.queue.empty():
            await rx.flush_once()
    finally:
        udp.close()
        tcp.close()
        await tcp.wait_closed()
    assert sorted(op[1]["raw_message"] for op in redis.stream) == ["via tcp one", "via tcp two", "via udp"]
    assert {op[0] for op in redis.stream} == {"siem:logs"}
