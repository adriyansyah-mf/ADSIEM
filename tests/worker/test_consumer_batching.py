# tests/worker/test_consumer_batching.py
"""A batch is processed as concurrent per-source groups; one source's entries
stay in stream order, every entry is acked, failures go to the DLQ."""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

from worker import consumer  # noqa: E402
from worker.decoder_engine import DecoderEngine  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "../..")


def _engine():
    dec = DecoderEngine()
    dec.load_from_yaml_list([open(os.path.join(ROOT, "decoders/nginx_access_combined.yaml")).read()])
    return dec


def _entry(i, ip):
    return (f"{i}-0", {"log_type": "nginx_access_combined", "hostname": "socwaf",
                       "raw_message": f'{ip} - - [20/Oct/2026:09:00:00 +0700] "GET /p{i} HTTP/1.1" 200 1 "-" "curl"'})


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


def test_group_by_source_keeps_stream_order():
    entries = [_entry(i, ip) for i, ip in enumerate(["1.1.1.1", "2.2.2.2", "1.1.1.1", "2.2.2.2", "1.1.1.1"])]
    groups = consumer.group_by_source(entries, _engine())
    assert [[m for m, _, _ in g] for g in groups] == [["0-0", "2-0", "4-0"], ["1-0", "3-0"]]
    assert groups[0][0][2][0]["url.path"] == "/p0"  # decoded once, handed to process_message


def test_consume_loop_runs_sources_concurrently_in_order(monkeypatch):
    ips = ["10.0.0.%d" % (i % 4) for i in range(20)]
    entries = [_entry(i, ip) for i, ip in enumerate(ips)]
    redis = FakeRedis(entries)
    seen, running, peak = {}, [0], [0]

    async def fake_process(data, dec, sig, predecoded=None):
        running[0] += 1
        peak[0] = max(peak[0], running[0])
        await asyncio.sleep(0.01)
        running[0] -= 1
        ip, path = predecoded[0]["source.ip"], predecoded[0]["url.path"]
        if path == "/p5":
            raise RuntimeError("boom")
        seen.setdefault(ip, []).append(int(path[2:]))

    async def fake_get_redis():
        return redis

    monkeypatch.setattr(consumer, "process_message", fake_process)
    monkeypatch.setattr(consumer, "get_redis", fake_get_redis)
    asyncio.run(consumer.consume_loop({"dec_engine": _engine(), "sig_engine": None}))

    assert peak[0] > 1                                   # sources overlapped
    for ip, order in seen.items():
        assert order == sorted(order), (ip, order)       # one source stays in order
    assert sorted(redis.acked) == sorted(m for m, _ in entries)
    assert [d["raw_message"] for _, d in redis.failed] == [entries[5][1]["raw_message"]]
