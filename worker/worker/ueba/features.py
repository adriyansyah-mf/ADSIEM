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


# ─── host and process entities (agent telemetry) ────────────────────────────
# A host (by hostname): what it runs and where it connects, per hour.
HOST_FEATURE_KEYS = [
    "process_count", "unique_processes", "new_processes", "shell_spawns",
    "user_writable_execs", "outbound_conns", "unique_dest_ips", "unique_dest_ports",
    "hour_of_day", "is_weekend",
]
# A program (file name, per group): where it runs and what it reaches, per hour.
PROCESS_FEATURE_KEYS = [
    "exec_count", "unique_hosts", "unique_parents", "outbound_conns",
    "unique_dest_ips", "unique_dest_ports", "hour_of_day", "is_weekend",
]
SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "fish", "busybox", "cmd.exe", "powershell.exe", "pwsh.exe",
          "pwsh", "wscript.exe", "cscript.exe", "mshta.exe"}
KNOWN_PROCS_TTL = 7 * 24 * 3600
MAX_KNOWN_PROCS = 20_000


def _base(path: str) -> str:
    return str(path).replace("\\", "/").rsplit("/", 1)[-1].lower()


def process_entity(image: str, group: str) -> str:
    """A program's entity value: its file name in its group (powershell.exe@blue)."""
    return f"{_base(image)}@{group or 'default'}"


async def remember_group(redis, entity_type: str, value: str, group: str) -> None:
    """The group an entity belongs to, for its hourly snapshot and group baseline."""
    key = f"ueba:group:{entity_type}"
    await redis.hset(key, value, group or "default")
    await redis.expire(key, WINDOW * 2)


async def update_host_counters(redis, host: str, group: str, *, image: str = "", parent: str = "",
                               user_writable: bool = False, dest: str = "", port: int | None = None) -> None:
    """One process start (image, parent) or one outbound connection (dest, port) of a host."""
    p = f"ueba:h:{host}"
    await redis.sadd("ueba:active:hosts", host); await redis.expire("ueba:active:hosts", WINDOW * 2)
    await remember_group(redis, "host", host, group)
    if image:
        name = image.lower()
        await redis.incr(f"{p}:proc");   await redis.expire(f"{p}:proc", WINDOW)
        await redis.sadd(f"{p}:procs", name); await redis.expire(f"{p}:procs", WINDOW)
        known = f"{p}:known_procs"
        if not await redis.sismember(known, name):
            # the first hour of a host's history makes every program "new": only
            # count programs once the host has a 7-day memory to compare with
            if await redis.scard(known) > 0:
                await redis.incr(f"{p}:newproc"); await redis.expire(f"{p}:newproc", WINDOW)
            if await redis.scard(known) < MAX_KNOWN_PROCS:
                await redis.sadd(known, name)
        await redis.expire(known, KNOWN_PROCS_TTL)
        if parent and _base(image) in SHELLS and _base(parent) not in SHELLS:
            await redis.incr(f"{p}:shell"); await redis.expire(f"{p}:shell", WINDOW)
        if user_writable:
            await redis.incr(f"{p}:uw"); await redis.expire(f"{p}:uw", WINDOW)
    if dest:
        await redis.incr(f"{p}:out"); await redis.expire(f"{p}:out", WINDOW)
        await redis.sadd(f"{p}:dips", dest); await redis.expire(f"{p}:dips", WINDOW)
        if port is not None:
            await redis.sadd(f"{p}:dports", str(port)); await redis.expire(f"{p}:dports", WINDOW)


async def update_process_counters(redis, entity: str, group: str, host: str, *, parent: str = "",
                                  started: bool = False, dest: str = "", port: int | None = None) -> None:
    """One start of the program on host (with its parent), or one outbound connection it made."""
    p = f"ueba:p:{entity}"
    await redis.sadd("ueba:active:processes", entity); await redis.expire("ueba:active:processes", WINDOW * 2)
    await remember_group(redis, "process", entity, group)
    if started:
        await redis.incr(f"{p}:exec"); await redis.expire(f"{p}:exec", WINDOW)
        if host:
            await redis.sadd(f"{p}:hosts", host); await redis.expire(f"{p}:hosts", WINDOW)
        if parent:
            await redis.sadd(f"{p}:parents", _base(parent)); await redis.expire(f"{p}:parents", WINDOW)
    if dest:
        await redis.incr(f"{p}:out"); await redis.expire(f"{p}:out", WINDOW)
        await redis.sadd(f"{p}:dips", dest); await redis.expire(f"{p}:dips", WINDOW)
        if port is not None:
            await redis.sadd(f"{p}:dports", str(port)); await redis.expire(f"{p}:dports", WINDOW)


def _time_features() -> dict:
    now = datetime.now(timezone.utc)
    return {"hour_of_day": float(now.hour), "is_weekend": float(1 if now.weekday() >= 5 else 0)}


async def build_host_vector_dict(redis, host: str) -> dict:
    p = f"ueba:h:{host}"
    return {
        "process_count":       float(int(await redis.get(f"{p}:proc") or 0)),
        "unique_processes":    float(await redis.scard(f"{p}:procs")),
        "new_processes":       float(int(await redis.get(f"{p}:newproc") or 0)),
        "shell_spawns":        float(int(await redis.get(f"{p}:shell") or 0)),
        "user_writable_execs": float(int(await redis.get(f"{p}:uw") or 0)),
        "outbound_conns":      float(int(await redis.get(f"{p}:out") or 0)),
        "unique_dest_ips":     float(await redis.scard(f"{p}:dips")),
        "unique_dest_ports":   float(await redis.scard(f"{p}:dports")),
        **_time_features(),
    }


async def build_process_vector_dict(redis, entity: str) -> dict:
    p = f"ueba:p:{entity}"
    return {
        "exec_count":        float(int(await redis.get(f"{p}:exec") or 0)),
        "unique_hosts":      float(await redis.scard(f"{p}:hosts")),
        "unique_parents":    float(await redis.scard(f"{p}:parents")),
        "outbound_conns":    float(int(await redis.get(f"{p}:out") or 0)),
        "unique_dest_ips":   float(await redis.scard(f"{p}:dips")),
        "unique_dest_ports": float(await redis.scard(f"{p}:dports")),
        **_time_features(),
    }


def vector_from_dict(d: dict, keys: list[str]) -> list[float]:
    """Convert feature dict to ordered list for sklearn."""
    return [float(d.get(k, 0.0)) for k in keys]
