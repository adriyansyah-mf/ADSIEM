# worker/worker/ueba/features.py
from datetime import datetime, timezone

WINDOW = 3600  # 1 hour TTL for sliding window counters
KNOWN_IPS_TTL = 7 * 24 * 3600  # 7 days

USER_FEATURE_KEYS = [
    "login_count", "failed_ratio", "unique_ips", "unique_hosts",
    "sudo_count", "new_ip_seen", "hour_of_day", "is_weekend",
]

IP_FEATURE_KEYS = [
    "unique_users", "total_events", "failed_ratio",
    "unique_target_hosts", "hour_of_day", "is_weekend", "failed_count",
]


async def update_user_counters(redis, user: str, decoded: dict) -> None:
    action = decoded.get("event.action", "")
    ip     = decoded.get("source.ip")
    host   = decoded.get("host.hostname") or decoded.get("hostname")
    p = f"ueba:u:{user}"

    await redis.incr(f"{p}:login");  await redis.expire(f"{p}:login",  WINDOW)
    await redis.sadd("ueba:active:users", user); await redis.expire("ueba:active:users", WINDOW * 2)

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
    await redis.sadd("ueba:active:ips", ip); await redis.expire("ueba:active:ips", WINDOW * 2)

    if "fail" in action.lower():
        await redis.incr(f"{p}:failed"); await redis.expire(f"{p}:failed", WINDOW)

    if user:
        await redis.sadd(f"{p}:users", user); await redis.expire(f"{p}:users", WINDOW)

    if host:
        await redis.sadd(f"{p}:hosts", host); await redis.expire(f"{p}:hosts", WINDOW)


async def build_user_vector_dict(redis, user: str, login_count: int, failed_count: int) -> dict:
    """Build user feature dict. login_count and failed_count passed in to avoid double-fetch."""
    p = f"ueba:u:{user}"
    now = datetime.now(timezone.utc)

    unique_ips   = await redis.scard(f"{p}:ips")
    unique_hosts = await redis.scard(f"{p}:hosts")
    sudo_count   = int(await redis.get(f"{p}:sudo") or 0)
    new_ip_seen  = int(await redis.get(f"{p}:new_ip") or 0)

    failed_ratio = (failed_count / login_count) if login_count > 0 else 0.0

    return {
        "login_count":  float(login_count),
        "failed_ratio": failed_ratio,
        "unique_ips":   float(unique_ips),
        "unique_hosts": float(unique_hosts),
        "sudo_count":   float(sudo_count),
        "new_ip_seen":  float(new_ip_seen),
        "hour_of_day":  float(now.hour),
        "is_weekend":   float(1 if now.weekday() >= 5 else 0),
    }


async def build_ip_vector_dict(redis, ip: str, total_events: int, failed_count: int) -> dict:
    """Build IP feature dict. total_events and failed_count passed in to avoid double-fetch."""
    p = f"ueba:ip:{ip}"
    now = datetime.now(timezone.utc)

    unique_users        = await redis.scard(f"{p}:users")
    unique_target_hosts = await redis.scard(f"{p}:hosts")

    failed_ratio = (failed_count / total_events) if total_events > 0 else 0.0

    return {
        "unique_users":        float(unique_users),
        "total_events":        float(total_events),
        "failed_ratio":        failed_ratio,
        "unique_target_hosts": float(unique_target_hosts),
        "hour_of_day":         float(now.hour),
        "is_weekend":          float(1 if now.weekday() >= 5 else 0),
        "failed_count":        float(failed_count),
    }


def vector_from_dict(d: dict, keys: list[str]) -> list[float]:
    """Convert feature dict to ordered list for sklearn."""
    return [float(d.get(k, 0.0)) for k in keys]
