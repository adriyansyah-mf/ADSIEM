"""Detection doesn't wait for Elasticsearch: an ES outage delays search, not
alerts; the retry indexes the same event_id and never alerts twice; the batch
is written with one _bulk request."""
import asyncio
import uuid

import httpx
import pytest

from worker import consumer


class Decoder:
    def decode_named(self, log_type, raw):
        return {"source.ip": "203.0.113.9"}, "test_decoder"


class Sigma:
    def __init__(self):
        self.seen = []

    async def evaluate(self, event):
        self.seen.append(event["raw_message"])
        return [{"id": "r1", "title": "brute force", "level": "high"}]


class FakeRedis:
    def __init__(self):
        self.kv, self.dlq, self.acked = {}, [], []

    async def set(self, key, value, ex=None):
        self.kv[key] = value

    async def exists(self, key):
        return int(key in self.kv)

    async def xadd(self, key, data, **kw):
        self.dlq.append((key, dict(data)))

    async def xack(self, _stream, _group, *ids):
        self.acked.extend(ids)


@pytest.fixture
def env(monkeypatch):
    redis, alerts, indexed = FakeRedis(), [], []

    async def get_redis():
        return redis

    async def create_alert(**kw):
        alerts.append(kw["event_id"])
        return uuid.uuid4()

    async def nothing(*a, **kw):
        return None

    async def index_ok(doc_id, doc):
        indexed.append(doc_id)

    monkeypatch.setattr(consumer, "get_redis", get_redis)
    monkeypatch.setattr(consumer, "create_alert", create_alert)
    monkeypatch.setattr(consumer, "excluded_by_policy", nothing)
    monkeypatch.setattr(consumer, "learn_from_event", nothing)
    monkeypatch.setattr(consumer, "ueba_score_event", nothing)
    monkeypatch.setattr(consumer, "index_log", index_ok)
    return redis, alerts, indexed


LINE = {"raw_message": "Failed password for root", "log_type": "linux_auth", "group_id": "blue", "hostname": "h"}


async def test_an_elasticsearch_outage_does_not_stop_alerts(env, monkeypatch):
    redis, alerts, _ = env

    async def es_down(doc_id, doc):
        raise httpx.ConnectError("elasticsearch unreachable")

    monkeypatch.setattr(consumer, "index_log", es_down)
    with pytest.raises(consumer.IndexFailed) as failed:
        await consumer.process_message(dict(LINE), Decoder(), Sigma())
    assert alerts == [failed.value.event_id]                 # the alert exists already
    assert isinstance(failed.value.__cause__, httpx.ConnectError)
    assert redis.kv == {consumer.DETECTED_KEY.format(failed.value.event_id): "1"}


async def test_a_retry_indexes_the_same_event_without_alerting_again(env):
    redis, alerts, indexed = env
    event_id = uuid.uuid4()
    redis.kv[consumer.DETECTED_KEY.format(event_id)] = "1"
    sigma = Sigma()
    await consumer.process_message({**LINE, consumer.EVENT_ID_FIELD: str(event_id)}, Decoder(), sigma)
    assert sigma.seen == [] and alerts == []                  # detection skipped
    assert indexed == [str(event_id)]                         # same document the alert points at


async def test_evidence_retry_with_its_stable_event_id_skips_detection_too(env):
    redis, alerts, indexed = env
    event_id = uuid.uuid4()
    redis.kv[consumer.DETECTED_KEY.format(event_id)] = "1"
    await consumer.process_message(dict(LINE), Decoder(), Sigma(), event_id=event_id)
    assert alerts == [] and indexed == [str(event_id)]


async def test_a_new_line_is_never_checked_against_the_marker(env, monkeypatch):
    redis, alerts, _ = env

    async def boom(key):
        raise AssertionError("first delivery must not pay for a marker lookup")

    redis.exists = boom
    await consumer.process_message(dict(LINE), Decoder(), Sigma())
    assert len(alerts) == 1


async def test_defer_index_returns_the_document(env):
    _, alerts, indexed = env
    event_id, doc = await consumer.process_message(dict(LINE), Decoder(), Sigma(), defer_index=True)
    assert indexed == [] and alerts == [event_id]
    assert doc["raw_message"] == LINE["raw_message"] and doc["source_ip"] == "203.0.113.9"


async def test_batch_is_written_with_one_bulk_and_refused_items_are_dead_lettered(env, monkeypatch):
    redis, _, _ = env
    good, bad = uuid.uuid4(), uuid.uuid4()
    calls = []

    async def bulk(docs):
        calls.append([d for d, _ in docs])
        return {1: {"status": 400, "error": {"type": "mapper_parsing_exception"}}}   # by position

    monkeypatch.setattr(consumer, "bulk_index_items", bulk)
    await consumer._index_batch(redis, [("1-0", dict(LINE), good, {}), ("2-0", dict(LINE), bad, {})])
    assert calls == [[str(good), str(bad)]]
    assert sorted(redis.acked) == ["1-0", "2-0"]              # the refused one is acked after its DLQ write
    (_, parked), = redis.dlq
    assert parked[consumer.EVENT_ID_FIELD] == str(bad)
    assert parked[consumer.DLQ_ATTEMPTS_FIELD] == "1"         # a 400 is the document's fault
    assert redis.kv == {consumer.DETECTED_KEY.format(bad): "1"}


async def test_bulk_request_failure_retries_every_line_without_using_attempts(env, monkeypatch):
    redis, _, _ = env

    async def bulk(docs):
        raise httpx.ConnectError("elasticsearch unreachable")

    monkeypatch.setattr(consumer, "bulk_index_items", bulk)
    ids = [uuid.uuid4(), uuid.uuid4()]
    await consumer._index_batch(redis, [(f"{i}-0", dict(LINE), e, {}) for i, e in enumerate(ids)])
    assert [d[consumer.EVENT_ID_FIELD] for _, d in redis.dlq] == [str(e) for e in ids]
    assert all(d[consumer.DLQ_ATTEMPTS_FIELD] == "0" for _, d in redis.dlq)   # an outage costs no attempt
    assert redis.acked == ["0-0", "1-0"]


def test_bulk_item_errors_classify_like_http_errors():
    assert consumer.is_infrastructure_error(consumer._bulk_item_error({"status": 429, "error": "es_rejected"}))
    assert not consumer.is_infrastructure_error(consumer._bulk_item_error({"status": 400, "error": "mapping"}))



async def test_one_failing_group_does_not_drop_the_others(env, monkeypatch):
    # a Redis error while one source's line is failed out used to abort the
    # whole gather: every other source's already-detected lines were never
    # indexed or acked, and their redelivery alerted again
    redis, _, _ = env
    bulk_calls = []

    async def bulk(docs):
        bulk_calls.append([d for d, _ in docs])
        return {}

    class StreamRedis(FakeRedis):
        def __init__(self):
            super().__init__()
            self.batches = [[("siem:logs", [("1-0", {**LINE, "raw_message": "bad"}),
                                            ("2-0", {**LINE, "hostname": "other", "raw_message": "good"})])]]

        async def xgroup_create(self, *a, **k):
            pass

        async def xreadgroup(self, *a, **k):
            if self.batches:
                return self.batches.pop()
            raise asyncio.CancelledError

        async def xack(self, _stream, _group, *ids):
            if "1-0" in ids:
                raise ConnectionError("redis hiccup")
            self.acked.extend(ids)

    stream = StreamRedis()

    async def get_redis():
        return stream

    async def process(data, dec, sig, predecoded=None, **kw):
        if data["raw_message"] == "bad":
            raise ValueError("bad line")
        return uuid.uuid4(), {"raw_message": data["raw_message"]}

    monkeypatch.setattr(consumer, "get_redis", get_redis)
    monkeypatch.setattr(consumer, "process_message", process)
    monkeypatch.setattr(consumer, "bulk_index_items", bulk)
    monkeypatch.setattr(consumer, "group_by_source",
                        lambda entries, dec: [[(m, d, None)] for m, d in entries])
    await consumer.consume_loop({"dec_engine": None, "sig_engine": None})
    assert len(bulk_calls) == 1 and len(bulk_calls[0]) == 1      # the good line was still indexed
    assert stream.acked == ["2-0"]
