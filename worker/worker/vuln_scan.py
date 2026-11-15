# worker/worker/vuln_scan.py
"""Find each host's vulnerabilities from its latest posture report and keep
host_vulnerabilities current (vuln_priority.py ranks them):

- Linux: installed packages (dpkg/rpm/apk, by source package when the agent
  sends it) against OSV.dev for the host's own distro release. OSV answers
  are cached in Redis, so a fleet of the same distro costs one lookup.
- Windows: the build and update revision (kernel 10.0.26100.9711) against
  Microsoft's fixed builds (msrc_fixes, vuln_intel.py): every CVE whose fix
  is a later UBR is open, with the KB that fixes it.

A CVE no longer found is resolved; a CVE on the CISA KEV list that is new on
a host raises one alert for that host."""
from __future__ import annotations

import asyncio
import json
import re
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import structlog
from sqlalchemy import select

from worker.database import AsyncSessionLocal
from worker.settings_cache import get_setting
from worker.vuln_intel import CVE_RE, WINDOWS_BUILD_RE, edition
from worker.vuln_priority import cvss3_base, severity_of

log = structlog.get_logger()

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"
SCAN_QUEUE = "siem:vuln_scan:queue"
STATE_KEY = "siem:vuln_scan:state"
LOCK_KEY = "siem:vuln_scan:lock"
QUERY_CACHE = "siem:osv:q:{}"
VULN_CACHE = "siem:osv:v:{}"
QUERY_TTL = 12 * 3600
VULN_TTL = 7 * 24 * 3600
LOOP_INTERVAL = 60
SNAPSHOT_MAX_AGE = timedelta(days=3)
OSV_CHUNK = 500
OSV_CONCURRENCY = 8
KEV_ALERT_TITLE = "Known Exploited Vulnerability On Host (CISA KEV)"


# ─── which OSV ecosystem a host is ────────────────────────────────

def ecosystem(os_name: str | None, os_version: str | None, source: str) -> str | None:
    name, ver = (os_name or "").lower(), (os_version or "").strip()
    major = ver.split(".")[0]
    if source == "dpkg":
        if "ubuntu" in name and re.match(r"^\d+\.\d+$", ver):
            year, month = ver.split(".")
            return f"Ubuntu:{ver}:LTS" if month == "04" and int(year) % 2 == 0 else f"Ubuntu:{ver}"
        if "debian" in name and major.isdigit():
            return f"Debian:{major}"
        return None
    if source == "apk" and "alpine" in name:
        parts = ver.split(".")
        return f"Alpine:v{parts[0]}.{parts[1]}" if len(parts) >= 2 else None
    if source == "rpm" and major.isdigit():
        if "rocky" in name:
            return f"Rocky Linux:{major}"
        if "alma" in name:
            return f"AlmaLinux:{major}"
        if "red hat" in name:
            return "Red Hat"
    return None


def windows_build(os_name: str | None, kernel: str | None) -> tuple[str, int] | None:
    if "windows" not in (os_name or "").lower():
        return None
    m = WINDOWS_BUILD_RE.match((kernel or "").strip())
    return (m.group(1), int(m.group(2))) if m else None


# ─── OSV ──────────────────────────────────────────────────────────

def compact_vuln(v: dict, eco: str, package: str) -> dict:
    """What a host row needs from an OSV record: CVEs, severity, fix, title."""
    vid = v.get("id", "")
    cves = [vid] if CVE_RE.match(vid) else []
    for alias in (v.get("upstream") or []) + (v.get("aliases") or []) + (v.get("related") or []):
        if CVE_RE.match(str(alias)) and alias not in cves:
            cves.append(alias)
    cvss = None
    vendor = None
    for s in v.get("severity") or []:
        if str(s.get("type", "")).startswith("CVSS_V3"):
            score = cvss3_base(s.get("score"))
            if score is not None and (cvss is None or score > cvss):
                cvss = score
        elif str(s.get("score", "")).lower() in ("negligible", "low", "medium", "high", "critical"):
            vendor = str(s["score"]).lower()  # Ubuntu's own rating
    db_sev = str((v.get("database_specific") or {}).get("severity", "")).lower()
    vendor = vendor or (db_sev if db_sev in ("low", "moderate", "medium", "important", "high", "critical") else None)
    vendor = {"negligible": "low", "moderate": "medium", "important": "high"}.get(vendor, vendor)
    exact, family = None, None  # the host's own release first (one record covers 20.04, 22.04…)
    for aff in v.get("affected") or []:
        pkg = aff.get("package") or {}
        pkg_eco = str(pkg.get("ecosystem", ""))
        if pkg.get("name") != package or not pkg_eco.startswith(eco.split(":")[0]):
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    if pkg_eco == eco:
                        exact = ev["fixed"]
                    else:
                        family = family or ev["fixed"]
    fixed = exact or family
    title = (v.get("summary") or (v.get("details") or "").strip().split("\n")[0])[:300]
    return {"id": vid, "cves": cves or [vid], "cvss": cvss, "severity": severity_of(cvss) or vendor,
            "fixed": fixed, "title": title}


async def _osv_ids(client: httpx.AsyncClient, redis, queries: list[tuple[str, str, str]]) -> dict[tuple, list[str]]:
    """(eco, name, version) -> OSV ids, from cache or querybatch."""
    out: dict[tuple, list[str]] = {}
    missing = []
    for q in queries:
        cached = await redis.get(QUERY_CACHE.format("|".join(q)))
        if cached is not None:
            out[q] = json.loads(cached)
        else:
            missing.append(q)
    for i in range(0, len(missing), OSV_CHUNK):
        chunk = missing[i:i + OSV_CHUNK]
        body = {"queries": [{"package": {"ecosystem": e, "name": n}, "version": ver} for e, n, ver in chunk]}
        r = await client.post(OSV_BATCH_URL, json=body)
        r.raise_for_status()
        for q, res in zip(chunk, r.json().get("results") or []):
            ids = [v["id"] for v in res.get("vulns") or [] if v.get("id")]
            out[q] = ids
            await redis.set(QUERY_CACHE.format("|".join(q)), json.dumps(ids), ex=QUERY_TTL)
    return out


async def _osv_details(client: httpx.AsyncClient, redis, wanted: set[tuple[str, str, str]]) -> dict[tuple, dict]:
    """(osv id, eco, package) -> compact record."""
    out: dict[tuple, dict] = {}
    sem = asyncio.Semaphore(OSV_CONCURRENCY)

    async def one(key: tuple[str, str, str]) -> None:
        vid, eco, pkg = key
        ck = VULN_CACHE.format("|".join(key))
        cached = await redis.get(ck)
        if cached is not None:
            out[key] = json.loads(cached)
            return
        async with sem:
            r = await client.get(OSV_VULN_URL.format(vid))
        if r.status_code != 200:
            return
        rec = compact_vuln(r.json(), eco, pkg)
        out[key] = rec
        await redis.set(ck, json.dumps(rec), ex=VULN_TTL)

    await asyncio.gather(*(one(k) for k in wanted))
    return out


async def linux_findings(client, redis, snap) -> dict[tuple[str, str], dict]:
    """(cve, package) -> row fields, for one Linux snapshot."""
    by_query: dict[tuple, str] = {}
    for p in snap.packages or []:
        if not isinstance(p, dict):
            continue
        eco = ecosystem(snap.os_name, snap.os_version, str(p.get("source", "")))
        name = str(p.get("source_name") or p.get("name") or "").strip()
        version = str(p.get("version") or "").strip()
        if eco and name and version:
            by_query[(eco, name, version)] = name
    if not by_query:
        return {}
    ids = await _osv_ids(client, redis, list(by_query))
    wanted = {(vid, q[0], q[1]) for q, vids in ids.items() for vid in vids}
    details = await _osv_details(client, redis, wanted)
    found: dict[tuple[str, str], dict] = {}
    for (eco, name, version), vids in ids.items():
        for vid in vids:
            rec = details.get((vid, eco, name))
            if rec is None:
                continue
            for cve in rec["cves"]:
                row = found.setdefault((cve, name), {
                    "source": "osv", "installed_version": version, "fixed_version": rec["fixed"], "kb": None,
                    "severity": rec["severity"], "cvss": rec["cvss"], "title": rec["title"]})
                if rec["cvss"] is not None and (row["cvss"] is None or rec["cvss"] > row["cvss"]):
                    row["cvss"], row["severity"] = rec["cvss"], rec["severity"]
    return found


async def windows_findings(db, snap) -> dict[tuple[str, str], dict]:
    from worker.models import MsrcFix
    wb = windows_build(snap.os_name, snap.kernel)
    if wb is None:
        return {}
    build, ubr = wb
    rows = (await db.execute(select(MsrcFix).where(MsrcFix.build == build, MsrcFix.edition == edition(snap.os_name),
                                                   MsrcFix.fixed_ubr > ubr))).scalars()
    return {(f.cve_id, "Windows"): {
        "source": "msrc", "installed_version": snap.kernel, "fixed_version": f"{build}.{f.fixed_ubr}", "kb": f.kb,
        "severity": f.severity, "cvss": f.cvss,
        "title": " · ".join(x for x in (f.impact, f.title) if x) or None} for f in rows}


# ─── store ────────────────────────────────────────────────────────

async def apply(db, snap, found: dict[tuple[str, str], dict], now: datetime) -> list[str]:
    """Upsert the host's open vulnerabilities, resolve the rest. Returns CVEs new on the host."""
    from worker.models import HostVulnerability
    existing = {(r.cve_id, r.package): r for r in (await db.execute(
        select(HostVulnerability).where(HostVulnerability.agent_id == snap.agent_id))).scalars()}
    new: list[str] = []
    for (cve, package), fields in found.items():
        row = existing.get((cve, package))
        if row is None:
            db.add(HostVulnerability(agent_id=snap.agent_id, group_id=snap.group_id or "default",
                                     hostname=snap.hostname, cve_id=cve, package=package,
                                     first_seen=now, last_seen=now, **fields))
            new.append(cve)
            continue
        for k, v in fields.items():
            setattr(row, k, v)
        row.hostname, row.group_id, row.last_seen = snap.hostname, snap.group_id or "default", now
        if row.resolved_at is not None:  # came back (downgrade, reinstall)
            row.resolved_at = None
            new.append(cve)
    for key, row in existing.items():
        if key not in found and row.resolved_at is None:
            row.resolved_at = now
    await db.commit()
    return sorted(set(new))


async def alert_kev(db, snap, new_cves: list[str]) -> bool:
    from worker.models import CveIntel
    if not new_cves:
        return False
    kev = (await db.execute(select(CveIntel.cve_id).where(CveIntel.cve_id.in_(new_cves),
                                                          CveIntel.kev.is_(True)))).scalars().all()
    if not kev:
        return False
    from worker import alert_manager
    await alert_manager.create_alert(
        {"id": "vuln-kev", "title": KEV_ALERT_TITLE, "level": "high",
         "tags": ["vulnerability.kev", "attack.initial_access", "attack.t1190"],
         "mitre_tags": ["attack.t1190"],
         "matched_fields": {"cve": sorted(kev)[:50], "kev_count": len(kev), "hostname": snap.hostname}},
        None, snap.agent_id, snap.group_id or "default", None, snap.hostname)
    return True


async def latest_snapshots(db) -> list:
    from sqlalchemy import func
    from worker.models import Agent, HygieneSnapshot
    since = datetime.now(timezone.utc) - SNAPSHOT_MAX_AGE
    latest = (select(HygieneSnapshot.agent_id, func.max(HygieneSnapshot.collected_at).label("at"))
              .where(HygieneSnapshot.collected_at >= since).group_by(HygieneSnapshot.agent_id).subquery())
    q = (select(HygieneSnapshot).join(latest, (HygieneSnapshot.agent_id == latest.c.agent_id)
                                      & (HygieneSnapshot.collected_at == latest.c.at))
         .join(Agent, Agent.id == HygieneSnapshot.agent_id))
    return list((await db.execute(q)).scalars().unique())


async def scan_once(redis) -> dict:
    now = datetime.now(timezone.utc)
    hosts = vulns = alerts = failed = 0
    async with httpx.AsyncClient(timeout=60) as client:
        async with AsyncSessionLocal() as db:
            snaps = await latest_snapshots(db)
        seen: set[uuid.UUID] = set()
        for snap in snaps:
            if snap.agent_id in seen:
                continue
            seen.add(snap.agent_id)
            try:
                async with AsyncSessionLocal() as db:
                    found = await windows_findings(db, snap) if windows_build(snap.os_name, snap.kernel) \
                        else await linux_findings(client, redis, snap)
                    new = await apply(db, snap, found, now)
                    alerts += await alert_kev(db, snap, new)
                hosts += 1
                vulns += len(found)
            except Exception as exc:  # noqa: BLE001 — one host (or OSV hiccup) must not stop the rest
                failed += 1
                log.warning("vuln_scan_host_failed", agent_id=str(snap.agent_id), error=str(exc))
    out = {"status": "ok" if not failed else "partial", "last_attempt": now.isoformat(), "hosts": hosts,
           "open": vulns, "kev_alerts": alerts, "failed_hosts": failed}
    await redis.hset(STATE_KEY, mapping={k: str(v) for k, v in out.items()})
    log.info("vuln_scan_done", **out)
    return out


async def _due(redis) -> bool:
    if await redis.lpop(SCAN_QUEUE):
        return True
    if (await get_setting("vuln_scan_enabled", "true")).lower() == "false":
        return False
    hours = max(1, int((await get_setting("vuln_scan_hours", "6")) or 6))
    last = (await redis.hgetall(STATE_KEY)).get("last_attempt")
    try:
        return last is None or datetime.now(timezone.utc) - datetime.fromisoformat(last) >= timedelta(hours=hours)
    except ValueError:
        return True


async def vuln_scan_loop() -> None:
    from worker.redis_client import get_redis
    await asyncio.sleep(180)
    while True:
        try:
            redis = await get_redis()
            if await _due(redis) and await redis.set(LOCK_KEY, "1", nx=True, ex=3 * 3600):
                try:
                    await scan_once(redis)
                finally:
                    await redis.delete(LOCK_KEY)
        except asyncio.CancelledError:
            break
        except Exception as exc:  # noqa: BLE001
            log.error("vuln_scan_loop_error", error=str(exc))
        await asyncio.sleep(LOOP_INTERVAL)
