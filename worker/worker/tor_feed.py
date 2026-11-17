# worker/worker/tor_feed.py
"""Tor exit nodes into the IP IoC blocklist (worker/ip_iocs.py), for every
group ("*"), source "feed".

The Tor Project publishes the current exit addresses
(https://check.torproject.org/torbulkexitlist, one IPv4 per line). Every
SYNC_EVERY_SECONDS the list is fetched and each address is upserted with an
expiry of ENTRY_TTL: an address that drops off the list ages out on its own,
one still listed has its expiry pushed back. Agents then drop traffic to and
from Tor exits where the group policy's ip_ioc is block, and report it as
ioc_match where it is detect or block: a browser through Tor, or malware
reaching its C2 over Tor, stops at the host's firewall.

Setting ip_feed_tor_enabled (default true). Turning it off removes the
active Tor entries at the next loop. Only downloads; nothing is sent."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import structlog
from sqlalchemy import text

from worker.database import AsyncSessionLocal
from worker.ip_iocs import ALL_GROUPS, IP_BLOCK_SEQ_LOCK, UPSERT_SQL, IPError, normalize
from worker.settings_cache import get_setting

log = structlog.get_logger()

LIST_URL = "https://check.torproject.org/torbulkexitlist"
REASON = "Tor exit node (check.torproject.org)"
SOURCE = "feed"
SYNC_EVERY_SECONDS = 6 * 3600
ENTRY_TTL = timedelta(hours=48)
LOOP_INTERVAL = 60
STATE_KEY = "siem:ip_feed:tor"
LOCK_KEY = "siem:ip_feed:tor:lock"
# A real list has about a thousand exits; far fewer means a broken answer
# (an error page, a captive portal) that must not replace the good one.
MIN_EXITS = 100
MAX_EXITS = 20000


def parse(body: str) -> list[str]:
    """Canonical /32s from the list body; comments, blanks and anything that
    is not a public address are dropped."""
    out: list[str] = []
    seen: set[str] = set()
    for line in body.splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        try:
            cidr = normalize(value)
        except IPError:
            continue
        if cidr not in seen:
            seen.add(cidr)
            out.append(cidr)
    return out


async def fetch(client: httpx.AsyncClient | None = None) -> list[str]:
    client = client or httpx.AsyncClient(timeout=60, headers={"User-Agent": "adsiem-ip-feed"})
    async with client:
        resp = await client.get(LIST_URL)
        resp.raise_for_status()
    exits = parse(resp.text)
    if not MIN_EXITS <= len(exits) <= MAX_EXITS:
        raise ValueError(f"Tor exit list has {len(exits)} addresses, expected {MIN_EXITS}-{MAX_EXITS}")
    return exits


async def apply(db, exits: list[str], now: datetime) -> int:
    """Upserts every exit under the blocklist's sequence lock. Commits."""
    expires = now + ENTRY_TTL
    await db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": IP_BLOCK_SEQ_LOCK})
    params = [{"cidr": c, "group": ALL_GROUPS, "source": SOURCE, "reason": REASON, "alert": None,
               "expires": expires} for c in exits]
    await db.execute(text(UPSERT_SQL), params)
    await db.commit()
    return len(params)


async def remove_all(db) -> int:
    """Removes the active Tor feed entries (the feed was turned off). Commits."""
    await db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": IP_BLOCK_SEQ_LOCK})
    res = await db.execute(text(
        "UPDATE ip_block_entries SET status = 'removed', seq = nextval('ip_block_seq'), updated_at = now() "
        "WHERE source = :source AND reason = :reason AND status = 'active'"), {"source": SOURCE, "reason": REASON})
    await db.commit()
    return res.rowcount or 0


async def sync_once(redis, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    exits = await fetch()
    async with AsyncSessionLocal() as db:
        n = await apply(db, exits, now)
    out = {"status": "ok", "last_success": now.isoformat(), "last_attempt": now.isoformat(), "exits": n, "error": ""}
    await redis.hset(STATE_KEY, mapping={k: str(v) for k, v in out.items()})
    log.info("tor_feed_synced", exits=n)
    return out


async def enabled() -> bool:
    return (await get_setting("ip_feed_tor_enabled", "true")).strip().lower() != "false"


async def _due(redis) -> bool:
    last = (await redis.hgetall(STATE_KEY)).get("last_attempt")
    if not last:
        return True
    try:
        return (datetime.now(timezone.utc) - datetime.fromisoformat(last)).total_seconds() >= SYNC_EVERY_SECONDS
    except ValueError:
        return True


async def tor_feed_loop() -> None:
    from worker.redis_client import get_redis
    await asyncio.sleep(120)
    while True:
        try:
            redis = await get_redis()
            if not await enabled():
                state = await redis.hgetall(STATE_KEY)
                if state.get("status") != "off":
                    async with AsyncSessionLocal() as db:
                        removed = await remove_all(db)
                    await redis.delete(STATE_KEY)
                    await redis.hset(STATE_KEY, mapping={"status": "off", "error": ""})
                    log.info("tor_feed_disabled", removed=removed)
            elif await _due(redis) and await redis.set(LOCK_KEY, "1", nx=True, ex=600):
                try:
                    await sync_once(redis)
                except Exception as exc:  # noqa: BLE001 - the last good list stays until its entries expire
                    log.warning("tor_feed_failed", error=str(exc))
                    await redis.hset(STATE_KEY, mapping={"status": "error", "error": str(exc)[:500],
                                                         "last_attempt": datetime.now(timezone.utc).isoformat()})
                finally:
                    await redis.delete(LOCK_KEY)
        except asyncio.CancelledError:
            break
        except Exception as exc:  # noqa: BLE001
            log.error("tor_feed_loop_error", error=str(exc))
        await asyncio.sleep(LOOP_INTERVAL)
