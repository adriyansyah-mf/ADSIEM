# tests/worker/test_evidence_event_id.py
"""Durable evidence gets a stable, agent-scoped document id, and the consumer
routes inbox references to process_reference: always acked, never copied
into the legacy DLQ, while legacy entries keep their path."""
import asyncio
import os
import sys
from uuid import UUID, uuid4

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

from worker import consumer, evidence_inbox  # noqa: E402

AGENT = UUID("11111111-1111-4111-8111-111111111111")
EVENT = UUID("22222222-2222-4222-8222-222222222222")


def test_stable_evidence_id_is_scoped_to_agent():
    from worker.evidence_inbox import evidence_event_id
    assert evidence_event_id(AGENT, EVENT) == UUID("61396d92-7faa-5629-b99c-b073e1e76122")
    assert evidence_event_id(EVENT, EVENT) != UUID("61396d92-7faa-5629-b99c-b073e1e76122")
    assert evidence_event_id(AGENT, EVENT) == evidence_event_id(AGENT, EVENT)


class FakeRedis:
    def __init__(self, entries):
        self.batches = [[("siem:logs", entries)]]
        self.acked, self.failed = [], []

    async def xgroup_create(self, *a, **k):
        pass

    async def xreadgroup(self, *a, **k):
        if self.batches:
            return self.batches.pop()
        raise asyncio.CancelledError  # ends consume_loop

    async def xack(self, _key, _group, msg_id):
        self.acked.append(msg_id)

    async def xadd(self, key, data):
        self.failed.append((key, data))


def test_consumer_routes_references_and_never_dead_letters_them(monkeypatch):
    good, boom = uuid4(), uuid4()
    entries = [
        ("1-0", {"kind": "evidence_v2", "receipt_id": str(good), "group_id": "g", "hostname": "h1"}),
        ("2-0", {"kind": "evidence_v2", "receipt_id": str(boom), "group_id": "g", "hostname": "h2"}),
        ("3-0", {"kind": "evidence_v2", "receipt_id": "not-a-uuid", "group_id": "g", "hostname": "h3"}),
        ("4-0", {"log_type": "syslog", "hostname": "h1", "raw_message": "legacy line"}),
    ]
    redis = FakeRedis(entries)
    references, legacy = [], []

    async def fake_reference(receipt_id, state):
        references.append(receipt_id)
        if receipt_id == boom:
            raise RuntimeError("database down")
        return "completed"

    async def fake_process(data, dec, sig, predecoded=None, event_id=None):
        legacy.append(data["raw_message"])

    async def fake_get_redis():
        return redis

    class Engine:
        def decode_named(self, log_type, raw):
            return {}, None

    monkeypatch.setattr(evidence_inbox, "process_reference", fake_reference)
    monkeypatch.setattr(consumer, "process_message", fake_process)
    monkeypatch.setattr(consumer, "get_redis", fake_get_redis)
    asyncio.run(consumer.consume_loop({"dec_engine": Engine(), "sig_engine": None}))

    assert sorted(references, key=str) == sorted([good, boom], key=str)
    assert legacy == ["legacy line"]                       # legacy keeps its path
    assert sorted(redis.acked) == ["1-0", "2-0", "3-0", "4-0"]  # the DB owns recovery
    assert redis.failed == []                              # never copied into the DLQ
