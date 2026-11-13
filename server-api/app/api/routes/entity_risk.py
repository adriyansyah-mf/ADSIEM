# server-api/app/api/routes/entity_risk.py
"""Unified host/user risk (worker/worker/entity_risk.py): the riskiest
entities now, with the alerts that made them so. The stored score is the
value at updated_at; the 24 h half-life decay is applied here."""
from datetime import datetime, timezone
from typing import Annotated, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, literal, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_scoped_group, require_permission
from app.models.models import EntityRisk

router = APIRouter(prefix="/api/entity-risk", tags=["entity-risk"])
Read = Depends(require_permission("alerts:read"))
HALF_LIFE = 24 * 3600
TACTIC_WINDOW = 24 * 3600


def _current():
    """risk_score decayed from updated_at to now, in SQL (for ordering and filtering)."""
    age = func.extract("epoch", func.now() - EntityRisk.updated_at)
    return EntityRisk.risk_score * func.power(literal(0.5), age / HALF_LIFE)


def _out(row: EntityRisk, current: float, detail: bool = False) -> dict:
    now = datetime.now(timezone.utc).timestamp()
    tactics = sorted(t for t, at in (row.tactics or {}).items() if now - float(at) <= TACTIC_WINDOW)
    out = {"entity_type": row.entity_type, "entity_value": row.entity_value, "group_id": row.group_id,
           "risk_score": round(float(current), 1), "peak_score": round(row.peak_score, 1),
           "alert_count": row.alert_count, "tactics": tactics, "sources": row.sources or {},
           "last_alert_at": row.last_alert_at.isoformat() if row.last_alert_at else None,
           "risk_alert_at": row.risk_alert_at.isoformat() if row.risk_alert_at else None}
    if detail:
        out["recent"] = row.recent or []
    else:
        out["top_alert"] = (row.recent or [{}])[0].get("title") if row.recent else None
    return out


@router.get("")
async def list_entity_risk(
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Read,
    group: Optional[str] = Depends(get_scoped_group),
    entity_type: Literal["all", "host", "user"] = "all",
    min_risk: float = Query(1.0, ge=0, le=100),
    limit: int = Query(50, ge=1, le=200),
):
    current = _current().label("current")
    q = select(EntityRisk, current).where(_current() >= min_risk)
    if group is not None:
        q = q.where(EntityRisk.group_id == group)
    if entity_type != "all":
        q = q.where(EntityRisk.entity_type == entity_type)
    rows = (await db.execute(q.order_by(current.desc()).limit(limit))).all()
    return {"items": [_out(r, c) for r, c in rows]}


@router.get("/{entity_type}/{entity_value}")
async def get_entity_risk(
    entity_type: Literal["host", "user"],
    entity_value: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Read,
    group: Optional[str] = Depends(get_scoped_group),
    group_id: Optional[str] = None,
):
    q = select(EntityRisk, _current()).where(EntityRisk.entity_type == entity_type,
                                              EntityRisk.entity_value == entity_value)
    if group is not None:
        q = q.where(EntityRisk.group_id == group)
    elif group_id:
        q = q.where(EntityRisk.group_id == group_id)
    row = (await db.execute(q.order_by(EntityRisk.updated_at.desc()).limit(1))).first()
    if row is None:
        raise HTTPException(status_code=404, detail="No risk recorded for this entity")
    return _out(row[0], row[1], detail=True)
