# server-api/app/api/routes/lateral.py
"""Lateral movement graph (worker/worker/lateral.py): hosts and the paths
between them seen in a time window, with the paths that were new in it."""
from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_scoped_group, require_permission
from app.models.models import Agent, LateralEdge

router = APIRouter(prefix="/api/lateral", tags=["lateral"])
Read = Depends(require_permission("alerts:read"))
MAX_EDGES = 1000


@router.get("/graph")
async def lateral_graph(
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Read,
    group: Optional[str] = Depends(get_scoped_group),
    hours: int = Query(24, ge=1, le=24 * 30),
    new_only: bool = False,
    host: str = Query("", max_length=255),
):
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    q = select(LateralEdge).where(LateralEdge.last_seen >= since)
    if group is not None:
        q = q.where(LateralEdge.group_id == group)
    if new_only:
        q = q.where(LateralEdge.first_seen >= since)
    if host:
        q = q.where((LateralEdge.src == host) | (LateralEdge.dst == host))
    rows = (await db.execute(q.order_by(LateralEdge.last_seen.desc()).limit(MAX_EDGES))).scalars().all()

    names = {r.src for r in rows} | {r.dst for r in rows}
    agents_q = select(Agent.hostname, Agent.status).where(Agent.hostname.in_(names))
    if group is not None:
        agents_q = agents_q.where(Agent.group_id == group)
    agents = {h: s for h, s in (await db.execute(agents_q)).all()} if names else {}

    degree: dict[str, dict[str, int]] = {n: {"out": 0, "in": 0} for n in names}
    edges = []
    for r in rows:
        degree[r.src]["out"] += 1
        degree[r.dst]["in"] += 1
        edges.append({"group_id": r.group_id, "src": r.src, "dst": r.dst, "protocol": r.protocol,
                      "users": r.users or [], "count": r.count, "new": r.first_seen >= since,
                      "first_seen": r.first_seen.isoformat(), "last_seen": r.last_seen.isoformat()})
    nodes = [{"id": n, "agent": n in agents, "status": agents.get(n), "out": degree[n]["out"], "in": degree[n]["in"]}
             for n in sorted(names)]
    return {"hours": hours, "truncated": len(rows) == MAX_EDGES, "nodes": nodes, "edges": edges}
