# server-api/app/api/routes/iocs.py
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_scoped_group, require_permission
from app.models.models import IocLink, IocObservation, User

router = APIRouter(prefix="/api/iocs", tags=["iocs"])
Perm = require_permission("iocs:read")


def _observation_out(obs: IocObservation) -> dict:
    return {
        "id": str(obs.id),
        "indicator": obs.indicator,
        "ioc_type": obs.ioc_type,
        "confidence": obs.confidence,
        "verdict": obs.verdict,
        "source": obs.source,
        "first_seen": obs.first_seen.isoformat() if obs.first_seen else None,
        "last_seen": obs.last_seen.isoformat() if obs.last_seen else None,
        "expires_at": obs.expires_at.isoformat() if obs.expires_at else None,
    }


@router.get("/{indicator}")
async def get_ioc_pivot(
    indicator: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    _current_user: Annotated[User, Depends(Perm)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
    group_id: str | None = Query(None, description="Superadmin only: which tenant's IOC data to view"),
):
    """Pivot view for one indicator: every observation of it and everything
    it has been linked to (events, alerts, rules, cases). A tenant-scoped
    caller always sees only their own tenant's data; a foreign-tenant
    indicator (or one that doesn't exist) returns 404, not an empty result,
    so cross-tenant existence can't be inferred from the response shape."""
    target_group = group_filter if group_filter is not None else group_id
    if target_group is None:
        raise HTTPException(status_code=422, detail="group_id is required for superadmin callers")

    observations = (
        await db.execute(
            select(IocObservation).where(
                IocObservation.group_id == target_group,
                IocObservation.indicator == indicator,
            )
        )
    ).scalars().all()
    if not observations:
        raise HTTPException(status_code=404, detail="IOC not found")

    ioc_ids = [obs.id for obs in observations]
    links = (
        await db.execute(
            select(IocLink).where(IocLink.group_id == target_group, IocLink.ioc_id.in_(ioc_ids))
        )
    ).scalars().all()

    return {
        "indicator": indicator,
        "observations": [_observation_out(obs) for obs in observations],
        "links": [
            {
                "entity_type": link.entity_type,
                "entity_id": link.entity_id,
                "linked_at": link.linked_at.isoformat() if link.linked_at else None,
            }
            for link in links
        ],
    }
