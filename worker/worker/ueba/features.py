# worker/worker/ueba/features.py
import asyncio
import json
from datetime import datetime, timezone

WINDOW = 3600          # 1-hour sliding window for counters
KNOWN_IPS_TTL = 7 * 24 * 3600   # 7 days for new-IP detection
TI_CACHE_TTL  = 86400  # 24 hours for TI reputation cache

USER_FEATURE_KEYS = [
    "login_count", "failed_ratio", "unique_ips", "unique_hosts",
    "sudo_count", "new_ip_seen", "hour_of_day", "is_weekend",
    "velocity", "hour_deviation", "ti_reputation",
    "max_ioc_ti_score", "max_ps_score", "max_cmd_score",
]

IP_FEATURE_KEYS = [
    "unique_users", "total_events", "failed_ratio",
    "unique_target_hosts", "hour_of_day", "is_weekend",
    "failed_count", "velocity", "ti_reputation", "max_ioc_ti_score",
    "max_ps_score", "max_cmd_score",
]

HOST_FEATURE_KEYS = [
    "unique_users", "total_events", "failed_ratio",
    "unique_source_ips", "sudo_count",
    "hour_of_day", "is_weekend", "velocity", "ti_reputation", "max_ioc_ti_score",
    "max_ps_score", "max_cmd_score",
]

IOC_SCORE_TTL = 7 * 24 * 3600   # 7 days — written by investigator, decays if no new anomaly


# ── Counter updates ──────────────────────────────────────────────

async def update_user_counters(redis, user: str, decoded: dict) -> None:
    action = decoded.get("event.action", "")
    ip     = decoded.get("source.ip")
    host   = decoded.get("host.hostname") or decoded.get("hostname")
    p = f"ueba:u:{user}"

    await redis.incr(f"{p}:login");  await redis.expire(f"{p}:login",  WINDOW)
    await redis.sadd("ueba:active:users", user)
    await redis.expire("ueba:active:users", WINDOW * 2)

    if "fail" in action.lower():
        await redis.incr(f"{p}:failed"); await redis.expire(f"{p}:failed", WINDOW)
    if "sudo" in action.lower() or "privilege" in action.lower():
        await redis.incr(f"{p}:sudo"); await redis.expire(f"{p}:sudo", WINDOW)

    if ip:
        is_new = not await redis.sismember(f"{p}:known_ips", ip)
        if is_new:
            await redis.set(f"{p}:new_ip", "1", ex=WINDOW)
        await redis.sadd(f"{p}:ips", ip);       await redis.expire(f"{p}:ips",       WINDOW)
        await redis.sadd(f"{p}:known_ips", ip); await redis.expire(f"{p}:known_ips", KNOWN_IPS_TTL)
    if host:
        await redis.sadd(f"{p}:hosts", host); await redis.expire(f"{p}:hosts", WINDOW)


async def update_ip_counters(redis, ip: str, decoded: dict, user: str | None) -> None:
    action = decoded.get("event.action", "")
    host   = decoded.get("host.hostname") or decoded.get("hostname")
    p = f"ueba:ip:{ip}"

    await redis.incr(f"{p}:total"); await redis.expire(f"{p}:total", WINDOW)
    await redis.sadd("ueba:active:ips", ip)
    await redis.expire("ueba:active:ips", WINDOW * 2)

    if "fail" in action.lower():
        await redis.incr(f"{p}:failed"); await redis.expire(f"{p}:failed", WINDOW)
    if user:
        await redis.sadd(f"{p}:users", user); await redis.expire(f"{p}:users", WINDOW)
    if host:
        await redis.sadd(f"{p}:hosts", host); await redis.expire(f"{p}:hosts", WINDOW)


async def update_host_counters(redis, hostname: str, decoded: dict, user: str | None) -> None:
    action = decoded.get("event.action", "")
    ip     = decoded.get("source.ip")
    p = f"ueba:host:{hostname}"

    await redis.incr(f"{p}:total"); await redis.expire(f"{p}:total", WINDOW)
    await redis.sadd("ueba:active:hosts", hostname)
    await redis.expire("ueba:active:hosts", WINDOW * 2)

    if "fail" in action.lower():
        await redis.incr(f"{p}:failed"); await redis.expire(f"{p}:failed", WINDOW)
    if "sudo" in action.lower() or "privilege" in action.lower():
        await redis.incr(f"{p}:sudo"); await redis.expire(f"{p}:sudo", WINDOW)
    if user:
        await redis.sadd(f"{p}:users", user); await redis.expire(f"{p}:users", WINDOW)
    if ip:
        await redis.sadd(f"{p}:src_ips", ip); await redis.expire(f"{p}:src_ips", WINDOW)


# ── Feature vector builders ──────────────────────────────────────

async def _get_redis_float(redis, key: str) -> float:
    raw = await redis.get(key)
    if not raw:
        return 0.0
    try:
        return float(raw)
    except Exception:
        return 0.0


async def _get_max_ioc_ti_score(redis, entity_type: str, entity_value: str) -> float:
    return await _get_redis_float(redis, f"ueba:ioc_score:{entity_type}:{entity_value}")


async def _get_max_ps_score(redis, entity_type: str, entity_value: str) -> float:
    return await _get_redis_float(redis, f"ueba:ps_score:{entity_type}:{entity_value}")


async def _get_max_cmd_score(redis, entity_type: str, entity_value: str) -> float:
    return await _get_redis_float(redis, f"ueba:cmd_score:{entity_type}:{entity_value}")


async def _get_ti_reputation(redis, ip: str) -> float:
    """Read cached TI reputation score (0.0–1.0). Written by investigator after TI lookup."""
    raw = await redis.get(f"ti:cache:{ip}")
    if not raw:
        return 0.0
    try:
        return float(json.loads(raw).get("score", 0.0))
    except Exception:
        return 0.0


async def build_user_vector_dict(
    redis, user: str, login_count: int, failed_count: int,
    prev_login_count: int = 0, mean_hour: float = 12.0,
) -> dict:
    p = f"ueba:u:{user}"
    now = datetime.now(timezone.utc)

    unique_ips      = await redis.scard(f"{p}:ips")
    unique_hosts    = await redis.scard(f"{p}:hosts")
    sudo_count      = int(await redis.get(f"{p}:sudo") or 0)
    new_ip_seen     = int(await redis.get(f"{p}:new_ip") or 0)
    failed_ratio    = (failed_count / login_count) if login_count > 0 else 0.0
    velocity        = login_count / max(prev_login_count, 1)
    hour_deviation  = abs(now.hour - mean_hour)
    user_ips = list(await redis.smembers(f"{p}:ips"))[:5]
    ti_scores = await asyncio.gather(*[_get_ti_reputation(redis, ip) for ip in user_ips])
    ti_reputation = max(ti_scores) if ti_scores else 0.0

    max_ioc_ti_score, max_ps_score, max_cmd_score = await asyncio.gather(
        _get_max_ioc_ti_score(redis, "user", user),
        _get_max_ps_score(redis, "user", user),
        _get_max_cmd_score(redis, "user", user),
    )

    return {
        "login_count":      float(login_count),
        "failed_ratio":     failed_ratio,
        "unique_ips":       float(unique_ips),
        "unique_hosts":     float(unique_hosts),
        "sudo_count":       float(sudo_count),
        "new_ip_seen":      float(new_ip_seen),
        "hour_of_day":      float(now.hour),
        "is_weekend":       float(1 if now.weekday() >= 5 else 0),
        "velocity":         float(velocity),
        "hour_deviation":   float(hour_deviation),
        "ti_reputation":    ti_reputation,
        "max_ioc_ti_score": max_ioc_ti_score,
        "max_ps_score":     max_ps_score,
        "max_cmd_score":    max_cmd_score,
    }


async def build_ip_vector_dict(
    redis, ip: str, total_events: int, failed_count: int,
    prev_total: int = 0,
) -> dict:
    p = f"ueba:ip:{ip}"
    now = datetime.now(timezone.utc)

    unique_users        = await redis.scard(f"{p}:users")
    unique_target_hosts = await redis.scard(f"{p}:hosts")
    failed_ratio     = (failed_count / total_events) if total_events > 0 else 0.0
    velocity         = total_events / max(prev_total, 1)
    ti_reputation, max_ioc_ti_score, max_ps_score, max_cmd_score = await asyncio.gather(
        _get_ti_reputation(redis, ip),
        _get_max_ioc_ti_score(redis, "ip", ip),
        _get_max_ps_score(redis, "ip", ip),
        _get_max_cmd_score(redis, "ip", ip),
    )

    return {
        "unique_users":        float(unique_users),
        "total_events":        float(total_events),
        "failed_ratio":        failed_ratio,
        "unique_target_hosts": float(unique_target_hosts),
        "hour_of_day":         float(now.hour),
        "is_weekend":          float(1 if now.weekday() >= 5 else 0),
        "failed_count":        float(failed_count),
        "velocity":            float(velocity),
        "ti_reputation":       ti_reputation,
        "max_ioc_ti_score":    max_ioc_ti_score,
        "max_ps_score":        max_ps_score,
        "max_cmd_score":       max_cmd_score,
    }


async def build_host_vector_dict(
    redis, hostname: str, total_events: int, failed_count: int,
    prev_total: int = 0,
) -> dict:
    p = f"ueba:host:{hostname}"
    now = datetime.now(timezone.utc)

    unique_users      = await redis.scard(f"{p}:users")
    unique_source_ips = await redis.scard(f"{p}:src_ips")
    sudo_count        = int(await redis.get(f"{p}:sudo") or 0)
    failed_ratio      = (failed_count / total_events) if total_events > 0 else 0.0
    velocity          = total_events / max(prev_total, 1)

    # TI reputation: worst score among source IPs connecting to this host
    src_ips = list(await redis.smembers(f"{p}:src_ips"))[:5]
    ti_scores = await asyncio.gather(*[_get_ti_reputation(redis, ip) for ip in src_ips])
    ti_reputation = max(ti_scores) if ti_scores else 0.0
    max_ioc_ti_score, max_ps_score, max_cmd_score = await asyncio.gather(
        _get_max_ioc_ti_score(redis, "host", hostname),
        _get_max_ps_score(redis, "host", hostname),
        _get_max_cmd_score(redis, "host", hostname),
    )

    return {
        "unique_users":      float(unique_users),
        "total_events":      float(total_events),
        "failed_ratio":      failed_ratio,
        "unique_source_ips": float(unique_source_ips),
        "sudo_count":        float(sudo_count),
        "hour_of_day":       float(now.hour),
        "is_weekend":        float(1 if now.weekday() >= 5 else 0),
        "velocity":          float(velocity),
        "ti_reputation":     ti_reputation,
        "max_ioc_ti_score":  max_ioc_ti_score,
        "max_ps_score":      max_ps_score,
        "max_cmd_score":     max_cmd_score,
    }


def vector_from_dict(d: dict, keys: list[str]) -> list[float]:
    """Convert feature dict to ordered list for sklearn."""
    return [float(d.get(k, 0.0)) for k in keys]
