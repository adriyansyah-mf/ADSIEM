# worker/worker/vuln_intel.py
"""Vulnerability intelligence for prioritising patches (vuln_priority.py):

- CISA KEV: CVEs exploited in the wild, with CISA's due date; daily.
- FIRST EPSS: each CVE's chance of exploitation in the next 30 days; daily.
- Microsoft CVRF: per CVE, the Windows build and update revision (UBR) that
  fixes it and the KB that ships it, for the last vuln_msrc_months monthly
  releases; a release is downloaded again only when Microsoft revises it.

Downloads only; nothing about the hosts leaves the server. State for the
dashboard is in Redis (STATE_KEY); the server queues a sync on SYNC_QUEUE."""
from __future__ import annotations

import asyncio
import csv
import gzip
import io
import json
import re
from datetime import datetime, timezone

import httpx
import structlog
from sqlalchemy import delete, update
from sqlalchemy.dialects.postgresql import insert

from worker.database import AsyncSessionLocal
from worker.settings_cache import get_setting

log = structlog.get_logger()

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
MSRC_INDEX_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
STATE_KEY = "siem:vuln_intel:state"     # server-api/app/api/routes/vulnerabilities.py
MSRC_SEEN_KEY = "siem:vuln_intel:msrc"  # release id -> CurrentReleaseDate stored
SYNC_QUEUE = "siem:vuln_intel:sync"
LOCK_KEY = "siem:vuln_intel:lock"
SYNC_EVERY_SECONDS = 24 * 3600
LOOP_INTERVAL = 60
TIMEOUT = 300
MAX_BYTES = 150 * 1024 * 1024  # a CVRF month is ~30 MB
MAX_PARAMS = 30000  # asyncpg refuses a statement with more than 32767 bind parameters

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
WINDOWS_BUILD_RE = re.compile(r"^(10\.0\.\d+|6\.[0-3]\.\d+)\.(\d+)$")
MSRC_SEVERITY = {"critical": "critical", "important": "high", "moderate": "medium", "low": "low"}


RETRY_DELAYS = (5, 20)


async def _download(url: str, accept: str = "*/*") -> bytes:
    """GET with retries on connection errors (the feeds' CDNs drop some)."""
    for delay in (*RETRY_DELAYS, None):
        try:
            return await _download_once(url, accept)
        except httpx.TransportError:
            if delay is None:
                raise
            await asyncio.sleep(delay)
    raise RuntimeError("unreachable")


async def _download_once(url: str, accept: str) -> bytes:
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
        async with client.stream("GET", url, headers={"Accept": accept}) as r:
            r.raise_for_status()
            buf = bytearray()
            async for chunk in r.aiter_bytes():
                buf += chunk
                if len(buf) > MAX_BYTES:
                    raise RuntimeError(f"{url}: response over {MAX_BYTES // (1024 * 1024)} MB")
            return bytes(buf)


# ─── parsers (pure) ───────────────────────────────────────────────

def kev_rows(payload: dict) -> list[dict]:
    rows = []
    for v in payload.get("vulnerabilities") or []:
        cve = str(v.get("cveID", "")).strip().upper()
        if not CVE_RE.match(cve):
            continue
        rows.append({"cve_id": cve, "kev": True, "kev_name": (v.get("vulnerabilityName") or "")[:1000],
                     "kev_date_added": (v.get("dateAdded") or "")[:10] or None,
                     "kev_due_date": (v.get("dueDate") or "")[:10] or None,
                     "kev_ransomware": str(v.get("knownRansomwareCampaignUse", "")).lower() == "known"})
    return rows


def epss_rows(raw_gz: bytes) -> list[dict]:
    text = gzip.decompress(raw_gz).decode("utf-8", errors="replace")
    lines = (line for line in text.splitlines() if line and not line.startswith("#"))
    rows = []
    for rec in csv.DictReader(lines):
        cve = (rec.get("cve") or "").strip().upper()
        try:
            if CVE_RE.match(cve):
                rows.append({"cve_id": cve, "epss": float(rec["epss"]), "epss_percentile": float(rec["percentile"])})
        except (KeyError, TypeError, ValueError):
            continue
    return rows


def _by_product(items: list[dict], key) -> dict[str, object]:
    out: dict[str, object] = {}
    for it in items or []:
        for pid in it.get("ProductID") or []:
            out.setdefault(pid, key(it))
    return out


def edition(product_or_os_name: str | None) -> str:
    return "server" if "server" in (product_or_os_name or "").lower() else "client"


def msrc_rows(doc: dict, release: str) -> list[dict]:
    """One row per (CVE, Windows build, edition): the lowest UBR that is no longer vulnerable."""
    products = doc.get("ProductTree", {}).get("FullProductName") or []
    windows = {p["ProductID"]: edition(p.get("Value")) for p in products
               if str(p.get("CPE", "")).startswith("cpe:2.3:o:microsoft:windows")
               or str(p.get("Value", "")).startswith(("Windows 10", "Windows 11", "Windows Server"))}
    out: dict[tuple[str, str, str], dict] = {}
    for v in doc.get("Vulnerability") or []:
        cve = str(v.get("CVE", "")).strip().upper()
        if not CVE_RE.match(cve):
            continue
        threats = v.get("Threats") or []
        sev = _by_product([t for t in threats if t.get("Type") == 3], lambda t: (t.get("Description") or {}).get("Value", ""))
        impact = _by_product([t for t in threats if t.get("Type") == 0], lambda t: (t.get("Description") or {}).get("Value", ""))
        cvss = _by_product(v.get("CVSSScoreSets") or [], lambda s: s.get("BaseScore"))
        title = (v.get("Title") or {}).get("Value", "")
        for rem in v.get("Remediations") or []:
            if rem.get("Type") != 2:
                continue
            m = WINDOWS_BUILD_RE.match(str(rem.get("FixedBuild", "")).strip())
            pids = [pid for pid in rem.get("ProductID") or [] if pid in windows]
            if not m or not pids:
                continue
            build, ubr = m.group(1), int(m.group(2))
            kb = str((rem.get("Description") or {}).get("Value", "")).strip()
            kb = f"KB{kb}" if kb.isdigit() else None
            for pid in pids:
                score = cvss.get(pid)
                row = out.setdefault((cve, build, windows[pid]), {
                    "cve_id": cve, "build": build, "edition": windows[pid], "fixed_ubr": ubr, "kb": kb, "severity": None,
                    "cvss": None, "impact": (impact.get(pid) or "")[:100] or None, "title": title or None,
                    "release": release})
                if ubr > row["fixed_ubr"]:  # several products on one build: the latest fix covers all
                    row["fixed_ubr"], row["kb"] = ubr, kb or row["kb"]
                level = MSRC_SEVERITY.get(str(sev.get(pid, "")).lower())
                if level and (row["severity"] is None
                              or ("critical", "high", "medium", "low").index(level)
                              < ("critical", "high", "medium", "low").index(row["severity"])):
                    row["severity"] = level
                if isinstance(score, (int, float)) and (row["cvss"] is None or score > row["cvss"]):
                    row["cvss"] = float(score)
    return list(out.values())


def msrc_releases(index: dict, months: int) -> list[dict]:
    """The newest `months` monthly releases: [{id, current, url}]."""
    rel = []
    for item in index.get("value") or []:
        if item.get("ID") and item.get("CvrfUrl") and item.get("InitialReleaseDate"):
            rel.append({"id": item["ID"], "initial": item["InitialReleaseDate"],
                        "current": item.get("CurrentReleaseDate") or item["InitialReleaseDate"], "url": item["CvrfUrl"]})
    rel.sort(key=lambda r: r["initial"], reverse=True)
    return rel[:months]


# ─── stores ───────────────────────────────────────────────────────

def batches(model, rows: list[dict]):
    """Multi-row INSERTs that stay under the bind-parameter limit (columns
    with Python defaults are bound too, so count the table's columns)."""
    if not rows:
        return
    size = max(1, MAX_PARAMS // len(model.__table__.columns))
    for i in range(0, len(rows), size):
        yield rows[i:i + size]


async def store_kev(rows: list[dict]) -> int:
    from worker.models import CveIntel
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        for chunk in batches(CveIntel, [{**r, "updated_at": now} for r in rows]):
            stmt = insert(CveIntel).values(chunk)
            await db.execute(stmt.on_conflict_do_update(index_elements=["cve_id"], set_={
                k: stmt.excluded[k] for k in ("kev", "kev_name", "kev_date_added", "kev_due_date",
                                              "kev_ransomware", "updated_at")}))
        if rows:  # removed from the catalogue (rare: a rejected CVE)
            await db.execute(update(CveIntel).where(CveIntel.kev.is_(True),
                                                    CveIntel.cve_id.not_in([r["cve_id"] for r in rows]))
                             .values(kev=False, updated_at=now))
        await db.commit()
    return len(rows)


async def store_epss(rows: list[dict]) -> int:
    from worker.models import CveIntel
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        for chunk in batches(CveIntel, [{**r, "updated_at": now} for r in rows]):
            stmt = insert(CveIntel).values(chunk)
            await db.execute(stmt.on_conflict_do_update(index_elements=["cve_id"], set_={
                "epss": stmt.excluded.epss, "epss_percentile": stmt.excluded.epss_percentile,
                "updated_at": stmt.excluded.updated_at}))
        await db.commit()
    return len(rows)


async def store_msrc(release: str, rows: list[dict]) -> int:
    from worker.models import MsrcFix
    async with AsyncSessionLocal() as db:
        await db.execute(delete(MsrcFix).where(MsrcFix.release == release))
        for chunk in batches(MsrcFix, rows):
            stmt = insert(MsrcFix).values(chunk)
            # the same CVE in two releases (re-released fix): the later fix wins
            await db.execute(stmt.on_conflict_do_update(index_elements=["cve_id", "build", "edition"], set_={
                k: stmt.excluded[k] for k in ("fixed_ubr", "kb", "severity", "cvss", "impact", "title", "release")},
                where=MsrcFix.fixed_ubr <= stmt.excluded.fixed_ubr))
        await db.commit()
    return len(rows)


async def drop_old_msrc(keep: list[str]) -> None:
    from worker.models import MsrcFix
    async with AsyncSessionLocal() as db:
        await db.execute(delete(MsrcFix).where(MsrcFix.release.not_in(keep)))
        await db.commit()


# ─── sync ─────────────────────────────────────────────────────────

async def sync_msrc(redis, months: int) -> dict:
    index = json.loads(await _download(MSRC_INDEX_URL, "application/json"))
    releases = msrc_releases(index, months)
    seen = await redis.hgetall(MSRC_SEEN_KEY)
    fetched = rows = 0
    for rel in releases:
        if seen.get(rel["id"]) == rel["current"]:
            continue
        raw = await _download(rel["url"], "application/json")
        # ~200 MB of Python objects for a month: parsed off the event loop, one month at a time
        parsed = await asyncio.to_thread(lambda b=raw, r=rel["id"]: msrc_rows(json.loads(b), r))
        del raw
        rows += await store_msrc(rel["id"], parsed)
        await redis.hset(MSRC_SEEN_KEY, rel["id"], rel["current"])
        fetched += 1
    keep = [r["id"] for r in releases]
    if keep:
        await drop_old_msrc(keep)
        stale = [k for k in seen if k not in keep]
        if stale:
            await redis.hdel(MSRC_SEEN_KEY, *stale)
    return {"msrc_releases": len(releases), "msrc_fetched": fetched, "msrc_rows": rows}


async def sync_once(redis) -> dict:
    now = datetime.now(timezone.utc)
    out: dict[str, object] = {"last_attempt": now.isoformat()}
    errors = []
    for name, job in (
        ("kev", lambda: _sync_kev()),
        ("epss", lambda: _sync_epss()),
        ("msrc", lambda: _sync_msrc(redis)),
    ):
        try:
            out.update(await job())
        except Exception as exc:  # noqa: BLE001 — one feed down must not stop the others
            reason = f"{type(exc).__name__}: {exc}".strip(": ")[:200]  # a timeout has no message
            log.warning("vuln_intel_feed_failed", feed=name, error=reason)
            errors.append(f"{name}: {reason}")
    out["status"] = "error" if len(errors) == 3 else "partial" if errors else "ok"
    out["error"] = "; ".join(errors)
    if not errors or len(errors) < 3:
        out["last_success"] = now.isoformat()
    await redis.hset(STATE_KEY, mapping={k: str(v) for k, v in out.items()})
    log.info("vuln_intel_synced", **{k: v for k, v in out.items() if k != "error"})
    return out


async def _sync_kev() -> dict:
    return {"kev": await store_kev(kev_rows(json.loads(await _download(KEV_URL, "application/json"))))}


async def _sync_epss() -> dict:
    raw = await _download(EPSS_URL)
    return {"epss": await store_epss(await asyncio.to_thread(epss_rows, raw))}


async def _sync_msrc(redis) -> dict:
    months = max(1, min(24, int((await get_setting("vuln_msrc_months", "6")) or 6)))
    return await sync_msrc(redis, months)


def _parse(ts: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(ts) if ts else None
    except ValueError:
        return None


async def due(redis) -> bool:
    if await redis.lpop(SYNC_QUEUE):
        return True
    if (await get_setting("vuln_intel_enabled", "true")).lower() == "false":
        return False
    last = _parse((await redis.hgetall(STATE_KEY)).get("last_attempt"))
    return last is None or (datetime.now(timezone.utc) - last).total_seconds() >= SYNC_EVERY_SECONDS


async def vuln_intel_loop() -> None:
    from worker.redis_client import get_redis
    await asyncio.sleep(120)
    while True:
        try:
            redis = await get_redis()
            if await due(redis) and await redis.set(LOCK_KEY, "1", nx=True, ex=3600):
                try:
                    await sync_once(redis)
                    from worker.vuln_scan import SCAN_QUEUE
                    await redis.rpush(SCAN_QUEUE, "intel")  # new KEV/EPSS: re-rank the hosts now
                finally:
                    await redis.delete(LOCK_KEY)
        except asyncio.CancelledError:
            break
        except Exception as exc:  # noqa: BLE001
            log.error("vuln_intel_loop_error", error=str(exc))
        await asyncio.sleep(LOOP_INTERVAL)
