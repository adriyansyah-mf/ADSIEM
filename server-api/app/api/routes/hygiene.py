from typing import Annotated
import httpx
import asyncio
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_agent, get_current_user, require_permission
from app.models.models import Agent, HygieneSnapshot, User
from app.schemas.schemas import HygieneSnapshotIn, HygieneSnapshotOut

router = APIRouter(tags=["hygiene"])

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
_ECOSYSTEM_MAP = {"dpkg": "Debian", "apk": "Alpine", "rpm": "Red Hat"}


def _cvss_severity(cvss_vector: str) -> str:
    parts = {k: v for part in cvss_vector.split("/") if ":" in part for k, v in [part.split(":", 1)]}
    c, i, a = parts.get("C", "N"), parts.get("I", "N"), parts.get("A", "N")
    high_count = sum(1 for x in (c, i, a) if x == "H")
    if high_count >= 2 or (high_count == 1 and parts.get("S") == "C"):
        return "HIGH"
    if high_count == 1 or any(x == "L" for x in (c, i, a)):
        return "MEDIUM"
    return "LOW"


def _parse_vuln(v: dict) -> dict:
    db_sev = (v.get("database_specific") or {}).get("severity", "")
    cvss_entries = v.get("severity") or []
    cvss_vec = next((s["score"] for s in cvss_entries if s.get("type", "").startswith("CVSS")), "")
    if db_sev:
        sev = db_sev.upper()
    elif cvss_vec:
        sev = _cvss_severity(cvss_vec)
    else:
        sev = "UNKNOWN"
    description = v.get("summary") or v.get("details") or ""
    return {"id": v.get("id", ""), "summary": description[:200], "severity": sev}


async def _query_osv(packages: list[dict]) -> list[dict]:
    if not packages:
        return []
    vulnerable = []
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Phase 1: batch query to find which packages have vulns
            queries = [
                {
                    "package": {
                        "name": p["name"],
                        "ecosystem": _ECOSYSTEM_MAP.get(p.get("source", ""), "Debian"),
                    },
                    "version": p.get("version", ""),
                }
                for p in packages
            ]
            chunk = 100
            pkg_vuln_ids: list[tuple[dict, list[str]]] = []
            for i in range(0, len(queries), chunk):
                resp = await client.post(OSV_BATCH_URL, json={"queries": queries[i: i + chunk]})
                resp.raise_for_status()
                for j, result in enumerate(resp.json().get("results", [])):
                    ids = [v["id"] for v in result.get("vulns", []) if "id" in v]
                    if ids:
                        pkg_vuln_ids.append((packages[i + j], ids))

            # Phase 2: fetch full detail for each unique vuln ID (capped to avoid too many calls)
            all_ids = list({vid for _, ids in pkg_vuln_ids for vid in ids[:5]})
            id_detail: dict[str, dict] = {}
            sem = asyncio.Semaphore(10)

            async def fetch_one(vid: str) -> None:
                async with sem:
                    try:
                        r = await client.get(f"https://api.osv.dev/v1/vulns/{vid}")
                        if r.status_code == 200:
                            id_detail[vid] = r.json()
                    except Exception:
                        pass

            await asyncio.gather(*[fetch_one(vid) for vid in all_ids])

            for pkg, ids in pkg_vuln_ids:
                vuln_items = [_parse_vuln(id_detail[vid]) for vid in ids[:5] if vid in id_detail]
                vulnerable.append({
                    "package": pkg,
                    "vulns": vuln_items,
                    "vuln_count": len(ids),
                })
    except Exception:
        pass
    return vulnerable


@router.post("/api/hygiene", status_code=204)
async def ingest_hygiene(
    body: HygieneSnapshotIn,
    db: Annotated[AsyncSession, Depends(get_db)],
    agent: Annotated[Agent, Depends(get_agent)],
):
    snap = HygieneSnapshot(
        agent_id=agent.id,
        hostname=body.hostname or agent.hostname,
        group_id=agent.group_id,
        os_name=body.os_name,
        os_version=body.os_version,
        kernel=body.kernel,
        arch=body.arch,
        uptime_seconds=body.uptime_seconds,
        cpu_count=body.cpu_count,
        mem_total_mb=body.mem_total_mb,
        mem_used_mb=body.mem_used_mb,
        disk_partitions=body.disk_partitions or [],
        open_ports=body.open_ports or [],
        users=body.users or [],
        hygiene_score=body.hygiene_score,
        issues=body.issues or [],
        packages=body.packages or [],
    )
    db.add(snap)
    await db.commit()


@router.get("/api/hygiene/latest", response_model=list[HygieneSnapshotOut])
async def get_latest_snapshots(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Latest snapshot per agent."""
    # Subquery: max collected_at per agent
    sub = (
        select(
            HygieneSnapshot.agent_id,
            func.max(HygieneSnapshot.collected_at).label("max_at"),
        )
        .group_by(HygieneSnapshot.agent_id)
        .subquery()
    )
    result = await db.execute(
        select(HygieneSnapshot)
        .join(sub, (HygieneSnapshot.agent_id == sub.c.agent_id) &
              (HygieneSnapshot.collected_at == sub.c.max_at))
        .order_by(desc(HygieneSnapshot.hygiene_score))
    )
    snaps = result.scalars().all()
    return [_snap_out(s) for s in snaps]


@router.get("/api/hygiene/{agent_id}/vulns")
async def get_agent_vulns(
    agent_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Query osv.dev for known CVEs in the agent's installed packages."""
    result = await db.execute(
        select(HygieneSnapshot)
        .where(HygieneSnapshot.agent_id == agent_id)
        .order_by(desc(HygieneSnapshot.collected_at))
        .limit(1)
    )
    snap = result.scalar_one_or_none()
    if not snap:
        raise HTTPException(status_code=404, detail="No hygiene snapshot found")
    packages = snap.packages or []
    if not packages:
        return {"agent_id": agent_id, "package_count": 0, "vulnerable": [], "checked_at": None}

    vulnerable = await _query_osv(packages)
    return {
        "agent_id": agent_id,
        "package_count": len(packages),
        "vulnerable_count": len(vulnerable),
        "vulnerable": vulnerable,
    }


@router.get("/api/hygiene/{agent_id}", response_model=list[HygieneSnapshotOut])
async def get_agent_hygiene_history(
    agent_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(
        select(HygieneSnapshot)
        .where(HygieneSnapshot.agent_id == agent_id)
        .order_by(desc(HygieneSnapshot.collected_at))
        .limit(24)
    )
    snaps = result.scalars().all()
    return [_snap_out(s) for s in snaps]


def _snap_out(s: HygieneSnapshot) -> HygieneSnapshotOut:
    return HygieneSnapshotOut(
        id=str(s.id),
        agent_id=str(s.agent_id),
        hostname=s.hostname,
        group_id=s.group_id,
        os_name=s.os_name,
        os_version=s.os_version,
        kernel=s.kernel,
        arch=s.arch,
        uptime_seconds=s.uptime_seconds,
        cpu_count=s.cpu_count,
        mem_total_mb=s.mem_total_mb,
        mem_used_mb=s.mem_used_mb,
        disk_partitions=s.disk_partitions or [],
        open_ports=s.open_ports or [],
        users=s.users or [],
        hygiene_score=s.hygiene_score,
        issues=s.issues or [],
        packages=s.packages or [],
        collected_at=s.collected_at,
    )
