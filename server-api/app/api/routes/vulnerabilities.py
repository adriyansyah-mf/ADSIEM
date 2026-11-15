"""Vulnerabilities on the fleet, ranked for patching: exploited in the wild
(CISA KEV), then likely to be exploited (EPSS), then severe (CVSS)
(worker/vuln_priority.py). Found by worker/vuln_scan.py from the agents'
posture reports; intel from worker/vuln_intel.py."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Annotated, Literal, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group, require_permission
from app.core.redis_client import get_redis
from app.models.models import CveIntel, HostVulnerability, User
from worker.vuln_priority import PRIORITIES, priority

router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])

INTEL_STATE_KEY = "siem:vuln_intel:state"  # worker/worker/vuln_intel.py
INTEL_SYNC_QUEUE = "siem:vuln_intel:sync"
SCAN_STATE_KEY = "siem:vuln_scan:state"    # worker/worker/vuln_scan.py
SCAN_QUEUE = "siem:vuln_scan:queue"
SEVERITY_ORDER = ("critical", "high", "medium", "low")


class CveItem(BaseModel):
    cve_id: str
    title: Optional[str] = None
    priority: str
    score: float
    severity: Optional[str] = None
    cvss: Optional[float] = None
    epss: Optional[float] = None
    epss_percentile: Optional[float] = None
    kev: bool = False
    kev_due_date: Optional[str] = None
    kev_ransomware: bool = False
    hosts: int
    hostnames: list[str]
    packages: list[str]
    fixes: list[str]          # KB numbers or fixed package versions
    first_seen: Optional[datetime] = None
    agent_ids: list[UUID] = Field(default_factory=list, exclude=True)


class HostRow(BaseModel):
    agent_id: UUID
    hostname: Optional[str] = None
    package: str
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    kb: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    model_config = {"from_attributes": True}


def _worse(a: Optional[str], b: Optional[str]) -> Optional[str]:
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    if a is None:
        return b
    if b is None:
        return a
    return a if rank.get(a, 9) <= rank.get(b, 9) else b


async def _intel(db: AsyncSession, cves: list[str]) -> dict[str, CveIntel]:
    out: dict[str, CveIntel] = {}
    for i in range(0, len(cves), 5000):
        for row in (await db.execute(select(CveIntel).where(CveIntel.cve_id.in_(cves[i:i + 5000])))).scalars():
            out[row.cve_id] = row
    return out


async def _ranked(db: AsyncSession, group_filter: str | None, agent_id: UUID | None) -> list[CveItem]:
    q = select(HostVulnerability).where(HostVulnerability.resolved_at.is_(None))
    if group_filter is not None:
        q = q.where(HostVulnerability.group_id == group_filter)
    if agent_id is not None:
        q = q.where(HostVulnerability.agent_id == agent_id)
    by_cve: dict[str, dict] = defaultdict(lambda: {"agents": set(), "hostnames": set(), "packages": set(),
                                                   "fixes": set(), "severity": None, "cvss": None,
                                                   "title": None, "first_seen": None})
    for r in (await db.execute(q)).scalars():
        c = by_cve[r.cve_id]
        c["agents"].add(r.agent_id)
        if r.hostname:
            c["hostnames"].add(r.hostname)
        c["packages"].add(r.package)
        fix = r.kb or (f"{r.package} {r.fixed_version}" if r.fixed_version else None)
        if fix:
            c["fixes"].add(fix)
        c["severity"] = _worse(c["severity"], r.severity)
        if r.cvss is not None and (c["cvss"] is None or r.cvss > c["cvss"]):
            c["cvss"] = r.cvss
        c["title"] = c["title"] or r.title
        if r.first_seen and (c["first_seen"] is None or r.first_seen < c["first_seen"]):
            c["first_seen"] = r.first_seen
    intel = await _intel(db, list(by_cve))
    items = []
    for cve, c in by_cve.items():
        i = intel.get(cve)
        kev = bool(i and i.kev)
        epss = i.epss if i else None
        tier, score = priority(kev, epss, c["cvss"], c["severity"])
        items.append(CveItem(
            cve_id=cve, title=(i.kev_name if kev and i.kev_name else c["title"]), priority=tier,
            score=round(score + len(c["agents"]) * 0.01, 3),  # same rank: the one on more hosts first
            severity=c["severity"], cvss=c["cvss"], epss=epss, epss_percentile=i.epss_percentile if i else None,
            kev=kev, kev_due_date=i.kev_due_date if kev else None, kev_ransomware=bool(kev and i.kev_ransomware),
            hosts=len(c["agents"]), hostnames=sorted(c["hostnames"])[:20], packages=sorted(c["packages"])[:10],
            fixes=sorted(c["fixes"])[:10], first_seen=c["first_seen"], agent_ids=list(c["agents"])))
    items.sort(key=lambda x: x.score, reverse=True)
    return items


async def _state(key: str) -> dict:
    try:
        return await (await get_redis()).hgetall(key)
    except Exception:  # noqa: BLE001 — the page still shows what was found
        return {}


@router.get("")
async def list_vulnerabilities(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
    priority_: Optional[Literal["critical", "high", "medium", "low"]] = Query(None, alias="priority"),
    kev: Optional[bool] = None,
    q: Optional[str] = Query(None, max_length=200),
    agent_id: Optional[UUID] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    items = await _ranked(db, group_filter, agent_id)
    counts = {p: sum(1 for i in items if i.priority == p) for p in PRIORITIES}
    summary = {"cves": len(items), "by_priority": counts, "kev": sum(1 for i in items if i.kev),
               "hosts": len({a for i in items for a in i.agent_ids})}
    if priority_:
        items = [i for i in items if i.priority == priority_]
    if kev is not None:
        items = [i for i in items if i.kev == kev]
    if q:
        needle = q.strip().lower()
        items = [i for i in items if needle in i.cve_id.lower() or needle in (i.title or "").lower()
                 or any(needle in p.lower() for p in i.packages) or any(needle in h.lower() for h in i.hostnames)]
    return {"total": len(items), "summary": summary, "items": items[offset:offset + limit],
            "intel": await _state(INTEL_STATE_KEY), "scan": await _state(SCAN_STATE_KEY)}


@router.get("/{cve_id}/hosts", response_model=list[HostRow])
async def cve_hosts(
    cve_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    q = select(HostVulnerability).where(HostVulnerability.cve_id == cve_id.strip().upper(),
                                        HostVulnerability.resolved_at.is_(None))
    if group_filter is not None:
        q = q.where(HostVulnerability.group_id == group_filter)
    rows = (await db.execute(q.order_by(HostVulnerability.hostname))).scalars().all()
    if not rows:
        raise HTTPException(404, "No open finding for this CVE")
    return rows


@router.post("/sync", status_code=202)
async def sync_now(_: Annotated[User, Depends(require_permission("agents:manage"))]):
    """Refresh KEV/EPSS/Microsoft data, then rescan every host."""
    redis = await get_redis()
    await redis.rpush(INTEL_SYNC_QUEUE, "1")
    await redis.rpush(SCAN_QUEUE, "1")
    await redis.hset(SCAN_STATE_KEY, mapping={"status": "queued"})
    return {"status": "queued"}
