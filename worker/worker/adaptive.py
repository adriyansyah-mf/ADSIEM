# worker/worker/adaptive.py
"""Adaptive consume concurrency: more source groups in flight while the stream
lags and this container has CPU and memory to spare, fewer as it fills up.

Additive increase, multiplicative decrease — the same shape as TCP congestion
control: climb a step at a time while it helps, back off hard on pressure.
Inputs are the consumer group's lag and this container's cgroup usage against
its own limits (docker-compose deploy.resources.limits)."""
import asyncio
import time

import structlog
from prometheus_client import Gauge

from worker.config import (
    ADAPT_INTERVAL, CONSUME_CONCURRENCY, CONSUME_CONCURRENCY_MAX, CONSUME_CONCURRENCY_MIN,
    LAG_HIGH, LAG_LOW, REDIS_CONSUMER_GROUP, REDIS_STREAM_KEY,
)
from worker.redis_client import get_redis

log = structlog.get_logger()

concurrency_gauge = Gauge("siem_consume_concurrency", "Source groups processed at once")

CPU_BUSY = 0.85   # of the container's CPU limit
MEM_HIGH = 0.80   # stop climbing
MEM_CRITICAL = 0.90  # back off


def next_concurrency(current: int, lag: int, cpu: float | None, mem: float | None,
                     lo: int = CONSUME_CONCURRENCY_MIN, hi: int = CONSUME_CONCURRENCY_MAX) -> int:
    """cpu/mem are fractions of this container's limits (None = unknown)."""
    if mem is not None and mem >= MEM_CRITICAL:
        return max(lo, current // 2)
    if lag >= LAG_HIGH:
        roomy = (cpu is None or cpu < CPU_BUSY) and (mem is None or mem < MEM_HIGH)
        return min(hi, current + 2) if roomy else current
    if lag <= LAG_LOW:
        return max(lo, current - 1)
    return current


# ── cgroup v2 (v1 fallback) ──────────────────────────────────────────────────

def _read(path: str) -> str | None:
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def memory_fraction() -> float | None:
    used, limit = _read("/sys/fs/cgroup/memory.current"), _read("/sys/fs/cgroup/memory.max")
    if used is None:  # cgroup v1
        used = _read("/sys/fs/cgroup/memory/memory.usage_in_bytes")
        limit = _read("/sys/fs/cgroup/memory/memory.limit_in_bytes")
    if not used or not limit or limit == "max" or int(limit) > 1 << 60:
        return None  # no limit set: nothing to measure against
    return int(used) / int(limit)


def _cpu_limit_cores() -> float | None:
    cpu_max = _read("/sys/fs/cgroup/cpu.max")
    if cpu_max:
        quota, period = cpu_max.split()
        return None if quota == "max" else int(quota) / int(period)
    quota, period = _read("/sys/fs/cgroup/cpu/cpu.cfs_quota_us"), _read("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
    if quota and period and int(quota) > 0:
        return int(quota) / int(period)
    return None


def _cpu_usage_seconds() -> float | None:
    stat = _read("/sys/fs/cgroup/cpu.stat")
    if stat:
        for line in stat.splitlines():
            if line.startswith("usage_usec "):
                return int(line.split()[1]) / 1e6
    usage = _read("/sys/fs/cgroup/cpuacct/cpuacct.usage")
    return int(usage) / 1e9 if usage else None


class CpuMeter:
    """CPU used since the previous reading, as a fraction of the container limit."""

    def __init__(self):
        self.limit = _cpu_limit_cores()
        self.last = (time.monotonic(), _cpu_usage_seconds())

    def fraction(self) -> float | None:
        now, used = time.monotonic(), _cpu_usage_seconds()
        (then, before), self.last = self.last, (now, used)
        if not self.limit or used is None or before is None or now <= then:
            return None
        return (used - before) / (now - then) / self.limit


async def stream_lag(redis) -> int:
    for group in await redis.xinfo_groups(REDIS_STREAM_KEY):
        if group.get("name") == REDIS_CONSUMER_GROUP:
            return int(group.get("lag") or 0)
    return 0


async def adaptive_loop(state: dict) -> None:
    state.setdefault("concurrency", CONSUME_CONCURRENCY)
    concurrency_gauge.set(state["concurrency"])
    cpu = CpuMeter()
    redis = await get_redis()
    while True:
        await asyncio.sleep(ADAPT_INTERVAL)
        try:
            lag = await stream_lag(redis)
        except Exception as exc:
            log.warning("adaptive_lag_failed", error=str(exc))
            continue
        cpu_frac, mem_frac = cpu.fraction(), memory_fraction()
        current = state["concurrency"]
        new = next_concurrency(current, lag, cpu_frac, mem_frac)
        if new != current:
            state["concurrency"] = new
            concurrency_gauge.set(new)
            log.info("consume_concurrency_changed", old=current, new=new, lag=lag,
                     cpu=round(cpu_frac, 2) if cpu_frac is not None else None,
                     mem=round(mem_frac, 2) if mem_frac is not None else None)
