# server-api/app/api/routes/entities.py
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_scoped_group, require_permission
from app.models.models import Alert, Case, UebaAnomaly, UebaEntityScore, User

router = APIRouter(prefix="/api/entities", tags=["entities"])
Perm = require_permission("logs:read")

# Only entity types with a direct Alert column can pivot to alerts/cases;
# other entity types (e.g. "user") still pivot against UEBA data alone,
# since Alert has no generic entity column to match against.
_ALERT_MATCH_COLUMNS = {"ip": Alert.source_ip, "hostname": Alert.hostname}


def _alert_out(a: Alert) -> dict:
    return {
        "id": str(a.id),
        "title": a.title,
        "severity": a.severity,
        "status": a.status,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "source_ip": a.source_ip,
        "hostname": a.hostname,
    }


def _case_out(c: Case) -> dict:
    return {
        "id": str(c.id),
        "title": c.title,
        "status": c.status,
        "severity": c.severity,
        "created_at": c.created_at.isoformat() if c.created_at else None,
    }


def _anomaly_out(a: UebaAnomaly) -> dict:
    return {
        "id": str(a.id),
        "anomaly_score": a.anomaly_score,
        "risk_score": a.risk_score,
        "ai_narrative": a.ai_narrative,
        "detected_at": a.detected_at.isoformat() if a.detected_at else None,
    }


@router.get("/{entity_type}/{entity_value}")
async def get_entity_pivot(
    entity_type: str,
    entity_value: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    _current_user: Annotated[User, Depends(Perm)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
    group_id: str | None = Query(None, description="Superadmin only: which tenant's data to view"),
    limit: int = Query(50, ge=1, le=200),
):
    """Pivot view for one entity (an IP, a hostname, or any UEBA-tracked
    entity type): every alert, case, and behavioral anomaly involving it.
    Tenant-scoped; a foreign-tenant or entirely-unknown entity returns 404,
    not an empty result."""
    target_group = group_filter if group_filter is not None else group_id
    if target_group is None:
        raise HTTPException(status_code=422, detail="group_id is required for superadmin callers")

    alerts: list[Alert] = []
    match_column = _ALERT_MATCH_COLUMNS.get(entity_type)
    if match_column is not None:
        alerts = (
            await db.execute(
                select(Alert)
                .where(Alert.group_id == target_group, match_column == entity_value)
                .order_by(Alert.created_at.desc())
                .limit(limit)
            )
        ).scalars().all()

    cases: list[Case] = []
    if alerts:
        alert_ids = [a.id for a in alerts]
        cases = (
            await db.execute(
                select(Case).where(Case.group_id == target_group, Case.alert_id.in_(alert_ids))
            )
        ).scalars().all()

    ueba_score = (
        await db.execute(
            select(UebaEntityScore).where(
                UebaEntityScore.group_id == target_group,
                UebaEntityScore.entity_type == entity_type,
                UebaEntityScore.entity_value == entity_value,
            )
        )
    ).scalar_one_or_none()

    anomalies = (
        await db.execute(
            select(UebaAnomaly)
            .where(
                UebaAnomaly.group_id == target_group,
                UebaAnomaly.entity_type == entity_type,
                UebaAnomaly.entity_value == entity_value,
            )
            .order_by(UebaAnomaly.detected_at.desc())
            .limit(limit)
        )
    ).scalars().all()

    if not alerts and not cases and ueba_score is None and not anomalies:
        raise HTTPException(status_code=404, detail="Entity not found")

    return {
        "entity_type": entity_type,
        "entity_value": entity_value,
        "risk_score": ueba_score.risk_score if ueba_score else None,
        "anomaly_count": ueba_score.anomaly_count if ueba_score else 0,
        "alerts": [_alert_out(a) for a in alerts],
        "cases": [_case_out(c) for c in cases],
        "anomalies": [_anomaly_out(a) for a in anomalies],
    }
