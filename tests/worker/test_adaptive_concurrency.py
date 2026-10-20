# tests/worker/test_adaptive_concurrency.py
"""Consume concurrency climbs while the stream lags and the container has room,
backs off on memory pressure, and eases back once caught up."""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

from worker import adaptive  # noqa: E402
from worker.adaptive import next_concurrency  # noqa: E402


def test_climbs_while_lagging_with_room():
    assert next_concurrency(8, lag=50_000, cpu=0.4, mem=0.5, lo=4, hi=16) == 10
    assert next_concurrency(16, lag=50_000, cpu=0.4, mem=0.5, lo=4, hi=16) == 16  # capped
    assert next_concurrency(8, lag=50_000, cpu=None, mem=None, lo=4, hi=16) == 10  # no limits known


def test_holds_when_cpu_or_memory_is_tight():
    assert next_concurrency(8, lag=50_000, cpu=0.95, mem=0.5, lo=4, hi=16) == 8
    assert next_concurrency(8, lag=50_000, cpu=0.4, mem=0.82, lo=4, hi=16) == 8


def test_backs_off_hard_on_memory_pressure_even_when_lagging():
    assert next_concurrency(16, lag=50_000, cpu=0.2, mem=0.93, lo=4, hi=16) == 8
    assert next_concurrency(5, lag=50_000, cpu=0.2, mem=0.93, lo=4, hi=16) == 4  # floor


def test_eases_back_when_caught_up_and_holds_in_between():
    assert next_concurrency(10, lag=50, cpu=0.1, mem=0.3, lo=4, hi=16) == 9
    assert next_concurrency(4, lag=50, cpu=0.1, mem=0.3, lo=4, hi=16) == 4
    assert next_concurrency(10, lag=1000, cpu=0.1, mem=0.3, lo=4, hi=16) == 10


def _fake_cgroup(monkeypatch, files):
    monkeypatch.setattr(adaptive, "_read", lambda p: files.get(p))


def test_cgroup_v2_memory_and_cpu(monkeypatch):
    _fake_cgroup(monkeypatch, {
        "/sys/fs/cgroup/memory.current": str(800 << 20), "/sys/fs/cgroup/memory.max": str(1 << 30),
        "/sys/fs/cgroup/cpu.max": "100000 100000", "/sys/fs/cgroup/cpu.stat": "usage_usec 5000000\nuser_usec 1",
    })
    assert round(adaptive.memory_fraction(), 3) == round(800 / 1024, 3)
    meter = adaptive.CpuMeter()
    assert meter.limit == 1.0
    _fake_cgroup(monkeypatch, {"/sys/fs/cgroup/cpu.stat": "usage_usec 5500000"})
    meter.last = (meter.last[0] - 1.0, meter.last[1])  # one second ago
    assert 0.45 < meter.fraction() < 0.55


def test_cgroup_without_limits_is_unknown(monkeypatch):
    _fake_cgroup(monkeypatch, {"/sys/fs/cgroup/memory.current": "123", "/sys/fs/cgroup/memory.max": "max",
                               "/sys/fs/cgroup/cpu.max": "max 100000"})
    assert adaptive.memory_fraction() is None
    assert adaptive.CpuMeter().fraction() is None


def test_cgroup_v1(monkeypatch):
    _fake_cgroup(monkeypatch, {
        "/sys/fs/cgroup/memory/memory.usage_in_bytes": "512", "/sys/fs/cgroup/memory/memory.limit_in_bytes": "1024",
        "/sys/fs/cgroup/cpu/cpu.cfs_quota_us": "50000", "/sys/fs/cgroup/cpu/cpu.cfs_period_us": "100000",
    })
    assert adaptive.memory_fraction() == 0.5
    assert adaptive._cpu_limit_cores() == 0.5


def test_stream_lag_reads_our_group():
    class R:
        async def xinfo_groups(self, _key):
            return [{"name": "other", "lag": 9}, {"name": adaptive.REDIS_CONSUMER_GROUP, "lag": 4321}]
    assert asyncio.run(adaptive.stream_lag(R())) == 4321
