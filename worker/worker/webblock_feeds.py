# worker/worker/webblock_feeds.py
"""Web Protection feeds: URLhaus (online URLs) and PhishTank (verified, online
phishing) become global web_block_entries (group_id '*', source urlhaus /
phishtank). Groups receive them when their policy enables feeds (server-api
delta). Hosts on the global allowlist are stored 'suppressed'; entries not seen
for 24 h become 'removed'.

Every statement that assigns web_block_seq runs in a transaction holding
pg_advisory_xact_lock(WEB_BLOCK_SEQ_LOCK) (batches of <= 1000, one commit per
batch) so agents never skip a seq. A row whose status and reason are unchanged
keeps its seq: an unchanged feed makes no agent resync.

State per feed in Redis (STATE_PREFIX + name, JSON); the server queues a sync
now by pushing the feed name on SYNC_QUEUE."""
from __future__ import annotations

import asyncio
import csv
import json
from datetime import datetime, timezone
from typing import Awaitable, Callable

import httpx
import structlog
from sqlalchemy import text

from worker.database import AsyncSessionLocal
from worker.settings_cache import get_setting
from worker.web_domains import WEB_BLOCK_SEQ_LOCK, DomainError, allow_match, normalize

log = structlog.get_logger()

STATE_PREFIX = "siem:webblock_feed:"          # + name; server-api reads it
SYNC_QUEUE = "siem:webblock_feed:sync"
LOCK_PREFIX = "siem:webblock_feed:lock:"
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv_online/"
PHISHTANK_URL = "https://data.phishtank.com/data/{key}/online-valid.json"
INTERVALS = {"urlhaus": 30 * 60, "phishtank": 60 * 60}
LOOP_INTERVAL = 60
BATCH = 1000
MAX_URLS = 200_000
MAX_BYTES = 200 * 1024 * 1024
TIMEOUT = 120
STALE_HOURS = 24

Fetch = Callable[[str], Awaitable[str]]
Parsed = list[tuple[str, str]]  # (url, reason) in feed order


def parse_urlhaus(body: str, limit: int = MAX_URLS) -> Parsed:
    """csv_online: `#` comment lines, then id,dateadded,url,url_status,last_online,threat,tags,..."""
    rows: Parsed = []
    lines = (ln for ln in body.splitlines() if ln.strip() and not ln.lstrip().startswith("#"))
    for cols in csv.reader(lines, skipinitialspace=True):
        if len(cols) < 6 or cols[3].strip().lower() != "online":
            continue
        url, threat = cols[2].strip(), cols[5].strip()
        tags = cols[6].strip() if len(cols) > 6 else ""
        reason = f"URLhaus: {threat or 'malware_download'}"
        first_tag = tags.split(",")[0].strip() if tags else ""
        if first_tag:
            reason += f" ({first_tag})"
        rows.append((url, reason))
        if len(rows) >= limit:
            break
    return rows


def parse_phishtank(body: str, limit: int = MAX_URLS) -> Parsed:
    """online-valid.json: list of {url, verified, online, target, ...}."""
    data = json.loads(body)
    if not isinstance(data, list):
        raise ValueError("PhishTank: unexpected payload")
    rows: Parsed = []
    for item in data:
        if not isinstance(item, dict) or str(item.get("verified")).lower() != "yes" \
                or str(item.get("online")).lower() != "yes" or not item.get("url"):
            continue
        target = str(item.get("target") or "").strip()
        rows.append((str(item["url"]).strip(), f"PhishTank: phishing ({target})" if target else "PhishTank: phishing"))
        if len(rows) >= limit:
            break
    return rows


PARSERS = {"urlhaus": parse_urlhaus, "phishtank": parse_phishtank}


async def _get(url: str, headers: dict) -> str:
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
        async with client.stream("GET", url, headers=headers) as r:
            if r.status_code in (401, 403):
                raise RuntimeError(f"feed refused the key (HTTP {r.status_code})")
            r.raise_for_status()
            buf = bytearray()
            async for chunk in r.aiter_bytes():
                buf += chunk
                if len(buf) > MAX_BYTES:
                    raise RuntimeError("feed response over the 200 MB limit")
    return buf.decode("utf-8", errors="replace")


async def fetch_urlhaus(key: str) -> str:
    return await _get(URLHAUS_URL, {"Auth-Key": key})


async def fetch_phishtank(key: str) -> str:
    return await _get(PHISHTANK_URL.format(key=key), {"User-Agent": "phishtank/adsiem"})


FETCHERS: dict[str, Fetch] = {"urlhaus": fetch_urlhaus, "phishtank": fetch_phishtank}


def prepare(parsed: Parsed, rules: list[tuple[str, bool]]) -> tuple[list[tuple[str, str, str, str]], int]:
    """-> ([(domain, status, reason, sample_url)], skipped). Deduped by domain, first URL wins."""
    seen: dict[str, tuple[str, str, str, str]] = {}
    skipped = 0
    for url, reason in parsed:
        try:
            domain = normalize(url)
        except DomainError:
            skipped += 1
            continue
        if domain in seen:
            continue
        rule = allow_match(domain, rules)
        seen[domain] = (domain, "suppressed", f"allowlisted ({rule})", url) if rule else (domain, "active", reason, url)
    return list(seen.values()), skipped


_UPSERT = text("""
INSERT INTO web_block_entries (id, domain, group_id, source, status, reason, sample_url,
                               created_at, updated_at, last_seen_in_feed, seq)
SELECT gen_random_uuid(), t.d, '*', :source, t.s, t.r, t.u, now(), now(), now(), nextval('web_block_seq')
FROM unnest(CAST(:domains AS text[]), CAST(:statuses AS text[]), CAST(:reasons AS text[]), CAST(:urls AS text[]))
     AS t(d, s, r, u)
ON CONFLICT (group_id, domain, source) DO UPDATE SET
    status = EXCLUDED.status, reason = EXCLUDED.reason, sample_url = EXCLUDED.sample_url,
    last_seen_in_feed = now(), updated_at = now(), seq = EXCLUDED.seq
WHERE (web_block_entries.status, web_block_entries.reason) IS DISTINCT FROM (EXCLUDED.status, EXCLUDED.reason)
""")
# rows the upsert left alone: only last_seen_in_feed moves (no seq)
_TOUCH = text("""
UPDATE web_block_entries SET last_seen_in_feed = now()
WHERE group_id = '*' AND source = :source AND domain = ANY(CAST(:domains AS text[]))
  AND last_seen_in_feed IS DISTINCT FROM now()
""")
_REMOVE = text("""
UPDATE web_block_entries SET status = 'removed', updated_at = now(), seq = nextval('web_block_seq')
WHERE id IN (SELECT id FROM web_block_entries
             WHERE group_id = '*' AND source = :source AND status = 'active'
               AND last_seen_in_feed < now() - make_interval(hours => :hours)
             ORDER BY id LIMIT :batch FOR UPDATE)
""")


async def _lock(db) -> None:
    await db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": WEB_BLOCK_SEQ_LOCK})


async def store(source: str, entries: list[tuple[str, str, str, str]]) -> dict:
    """Upsert entries (batches of BATCH, lock + commit each), then remove the stale ones."""
    for i in range(0, len(entries), BATCH):
        chunk = entries[i:i + BATCH]
        params = {"source": source, "domains": [e[0] for e in chunk], "statuses": [e[1] for e in chunk],
                  "reasons": [e[2] for e in chunk], "urls": [e[3] for e in chunk]}
        async with AsyncSessionLocal() as db:
            await _lock(db)
            await db.execute(_UPSERT, params)
            await db.execute(_TOUCH, {"source": source, "domains": params["domains"]})
            await db.commit()
    removed = 0
    while True:
        async with AsyncSessionLocal() as db:
            await _lock(db)
            n = (await db.execute(_REMOVE, {"source": source, "hours": STALE_HOURS, "batch": BATCH})).rowcount
            await db.commit()
        removed += n
        if n < BATCH:
            break
    return {"entries": sum(1 for e in entries if e[1] == "active"),
            "suppressed": sum(1 for e in entries if e[1] == "suppressed"), "removed": removed}


async def _global_rules() -> list[tuple[str, bool]]:
    async with AsyncSessionLocal() as db:
        res = await db.execute(text("SELECT domain, include_subdomains FROM web_allowlist "
                                    "WHERE group_id = '*' AND enabled"))
        return [(r.domain, r.include_subdomains) for r in res]


async def _get_state(redis, name: str) -> dict:
    try:
        return json.loads(await redis.get(STATE_PREFIX + name) or "{}")
    except ValueError:
        return {}


async def _put_state(redis, name: str, **fields) -> dict:
    state = {**await _get_state(redis, name), **fields}
    await redis.set(STATE_PREFIX + name, json.dumps(state))
    return state


async def _key_for(name: str) -> str:
    if name == "urlhaus":
        return ((await get_setting("abusech_auth_key", "")) or (await get_setting("malwarebazaar_api_key", ""))).strip()
    return (await get_setting("phishtank_app_key", "")).strip()


async def sync_once(redis, name: str, key: str, fetch: Fetch | None = None, now: datetime | None = None) -> dict:
    stamp = (now or datetime.now(timezone.utc)).isoformat()
    body = await (fetch or FETCHERS[name])(key)
    entries, skipped = prepare(PARSERS[name](body), await _global_rules())
    result = await store(name, entries)
    state = await _put_state(redis, name, status="ok", last_success=stamp, last_attempt=stamp, error="",
                             skipped=skipped, **result)
    log.info("webblock_feed_synced", feed=name, skipped=skipped, **result)
    return state


async def _due(redis, name: str, requested: set[str]) -> bool:
    if name in requested:
        return True
    last = (await _get_state(redis, name)).get("last_attempt")
    try:
        when = datetime.fromisoformat(last) if last else None
    except ValueError:
        when = None
    return when is None or (datetime.now(timezone.utc) - when).total_seconds() >= INTERVALS[name]


async def run_feed(redis, name: str, requested: set[str]) -> None:
    if not await _due(redis, name, requested):
        return
    key = await _key_for(name)
    if not key:
        await _put_state(redis, name, status="missing_key", error="")
        return
    if not await redis.set(LOCK_PREFIX + name, "1", nx=True, ex=900):
        return
    try:
        await sync_once(redis, name, key)
    except Exception as exc:  # noqa: BLE001 — shown on the Feeds tab
        log.warning("webblock_feed_failed", feed=name, error=str(exc))
        await _put_state(redis, name, status="error", error=str(exc)[:500],
                         last_attempt=datetime.now(timezone.utc).isoformat())
    finally:
        await redis.delete(LOCK_PREFIX + name)


async def webblock_feeds_loop() -> None:
    from worker.redis_client import get_redis
    await asyncio.sleep(120)
    while True:
        try:
            redis = await get_redis()
            requested: set[str] = set()
            while item := await redis.lpop(SYNC_QUEUE):
                requested.add(item if isinstance(item, str) else item.decode())
            for name in INTERVALS:
                await run_feed(redis, name, requested)
        except asyncio.CancelledError:
            break
        except Exception as exc:  # noqa: BLE001
            log.error("webblock_feeds_loop_error", error=str(exc))
        await asyncio.sleep(LOOP_INTERVAL)
