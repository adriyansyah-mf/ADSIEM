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
import io
import json
from datetime import datetime, timezone
from typing import Awaitable, Callable
from urllib.parse import urlsplit

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
TIMEOUT = 120          # total seconds for one fetch (asyncio.timeout), not per read
REMOVAL_GUARD = 0.5     # skip the sweep when it would remove more than this share of active rows
MAX_REDIRECTS = 5
STALE_HOURS = 24

Fetch = Callable[[str], Awaitable[str]]
Parsed = list[tuple[str, str]]  # (url, reason) in feed order


def parse_urlhaus(body: str, limit: int = MAX_URLS) -> Parsed:
    """csv_online: `#` comment lines, then id,dateadded,url,url_status,last_online,threat,tags,..."""
    rows: Parsed = []
    for cols in csv.reader(io.StringIO(body), skipinitialspace=True):
        if len(cols) < 6 or cols[0].lstrip().startswith("#") or cols[3].strip().lower() != "online":
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
    """GET with a byte cap. Redirects are followed by hand and the key header is
    dropped when the host changes (the PhishTank key is in the URL path, which
    is never re-sent to another host either)."""
    host = urlsplit(url).hostname
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False) as client:
        for _ in range(MAX_REDIRECTS + 1):
            same = urlsplit(url).hostname == host
            async with client.stream("GET", url, headers=headers if same else {}) as r:
                if r.is_redirect and r.headers.get("location"):
                    url = str(r.url.join(r.headers["location"]))
                    if urlsplit(url).hostname != host:
                        headers = {}
                    continue
                if r.status_code in (401, 403):
                    raise RuntimeError(f"feed refused the key (HTTP {r.status_code})")
                try:
                    r.raise_for_status()
                except httpx.HTTPStatusError as exc:  # its message holds the URL, and the URL can hold the key
                    raise RuntimeError(f"HTTP {exc.response.status_code}") from None
                length = r.headers.get("content-length", "")
                if length.isdigit() and int(length) > MAX_BYTES:
                    raise RuntimeError("feed response over the 200 MB limit")
                buf = bytearray()
                async for chunk in r.aiter_bytes():
                    buf += chunk
                    if len(buf) > MAX_BYTES:
                        raise RuntimeError("feed response over the 200 MB limit")
                return buf.decode("utf-8", errors="replace")
    raise RuntimeError("too many redirects")


async def fetch_urlhaus(key: str) -> str:
    return await _get(URLHAUS_URL, {"Auth-Key": key})


async def fetch_phishtank(key: str) -> str:
    return await _get(PHISHTANK_URL.format(key=key), {"User-Agent": "phishtank/adsiem"})


FETCHERS: dict[str, Fetch] = {"urlhaus": fetch_urlhaus, "phishtank": fetch_phishtank}


def prepare(parsed: Parsed, rules: list[tuple[str, bool]]) -> tuple[list[tuple[str, str, str, str]], int]:
    """-> ([(domain, status, reason, sample_url)], skipped). Deduped by domain; the smallest URL (and its reason) represents it."""
    best: dict[str, tuple[str, str]] = {}
    skipped = 0
    for url, reason in parsed:
        try:
            domain = normalize(url)
        except DomainError:
            skipped += 1
            continue
        if domain not in best or (url, reason) < best[domain]:  # smallest URL: feed order never flips a reason
            best[domain] = (url, reason)
    out = []
    for domain, (url, reason) in best.items():
        rule = allow_match(domain, rules)
        out.append((domain, "suppressed", f"allowlisted ({rule})", url) if rule else (domain, "active", reason, url))
    return out, skipped


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
UPDATE web_block_entries e SET last_seen_in_feed = now(), sample_url = t.u
FROM unnest(CAST(:domains AS text[]), CAST(:urls AS text[])) AS t(d, u)
WHERE e.group_id = '*' AND e.source = :source AND e.domain = t.d
  AND e.last_seen_in_feed IS DISTINCT FROM now()
""")
_STALE_COUNT = text("""
SELECT count(*) FILTER (WHERE last_seen_in_feed < now() - make_interval(hours => :hours)) AS stale,
       count(*) AS active
FROM web_block_entries WHERE group_id = '*' AND source = :source AND status = 'active'
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
            await db.execute(_TOUCH, {"source": source, "domains": params["domains"], "urls": params["urls"]})
            await db.commit()
    async with AsyncSessionLocal() as db:
        counts = (await db.execute(_STALE_COUNT, {"source": source, "hours": STALE_HOURS})).one()
    counts_out = {"entries": sum(1 for e in entries if e[1] == "active"),
                  "suppressed": sum(1 for e in entries if e[1] == "suppressed")}
    if counts.stale > counts.active * REMOVAL_GUARD:
        log.warning("webblock_feed_removal_guard", feed=source, stale=counts.stale, active=counts.active)
        return {**counts_out, "removed": 0, "guard": {"stale": counts.stale, "active": counts.active}}
    removed = 0
    while True:
        async with AsyncSessionLocal() as db:
            await _lock(db)
            n = (await db.execute(_REMOVE, {"source": source, "hours": STALE_HOURS, "batch": BATCH})).rowcount
            await db.commit()
        removed += n
        if n < BATCH:
            break
    return {**counts_out, "removed": removed}


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
    async with asyncio.timeout(TIMEOUT):
        body = await (fetch or FETCHERS[name])(key)
    rules = await _global_rules()

    def work():
        parsed = PARSERS[name](body)
        return (len(parsed) >= MAX_URLS, *prepare(parsed, rules))
    truncated, entries, skipped = await asyncio.to_thread(work)
    if not entries:  # a 200 with nothing usable must not age out the whole list
        raise RuntimeError("feed returned no entries")
    if truncated:
        log.warning("webblock_feed_truncated", feed=name, limit=MAX_URLS)
    result = await store(name, entries)
    guard = result.pop("guard", None)
    fields = {"status": "removal_guard" if guard else "ok", "last_success": stamp, "last_attempt": stamp,
              "error": "", "skipped": skipped, "truncated": truncated, "guard": guard or {}, **result}
    state = await _put_state(redis, name, **fields)
    log.info("webblock_feed_synced", feed=name, skipped=skipped, truncated=truncated, status=fields["status"], **result)
    return state


def redact(message: str, keys) -> str:
    for key in keys:
        if key:
            message = message.replace(key, "***")
    return message


async def _all_keys() -> list[str]:
    return [(await get_setting(k, "")).strip() for k in ("abusech_auth_key", "malwarebazaar_api_key", "phishtank_app_key")]


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
        if name in requested:  # a sync asked for while one runs: do it next round
            await redis.rpush(SYNC_QUEUE, name)
        return
    try:
        await sync_once(redis, name, key)
    except Exception as exc:  # noqa: BLE001 — shown on the Feeds tab
        message = redact(str(exc) or type(exc).__name__, [key, *await _all_keys()])
        log.warning("webblock_feed_failed", feed=name, error=message[:500])
        await _put_state(redis, name, status="error", error=message[:500],
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
