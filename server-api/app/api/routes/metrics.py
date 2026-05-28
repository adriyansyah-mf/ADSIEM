# server-api/app/api/routes/metrics.py
"""SOC KPI metrics: MTTD, MTTR, analyst workload, ad-hoc TI lookup."""
from typing import Annotated
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group, require_permission
from app.models.models import Alert, Case, User

router = APIRouter(prefix="/api/metrics", tags=["metrics"])


@router.get("/soc")
async def soc_metrics(
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(get_current_user),
    days: int = Query(default=30, le=90),
):
    since = datetime.now(timezone.utc) - timedelta(days=days)

    base_q = select(Alert).where(Alert.created_at >= since)
    if group_filter:
        base_q = base_q.where(Alert.group_id == group_filter)
    alerts = (await db.execute(base_q)).scalars().all()

    total = len(alerts)
    by_severity: dict[str, int] = {}
    by_status: dict[str, int] = {}
    mttd_minutes: list[float] = []
    mttr_minutes: list[float] = []
    ack_minutes: list[float] = []

    for a in alerts:
        by_severity[a.severity] = by_severity.get(a.severity, 0) + 1
        by_status[a.status]     = by_status.get(a.status, 0) + 1
        if a.acknowledged_at and a.created_at:
            ack_minutes.append((a.acknowledged_at - a.created_at).total_seconds() / 60)
        if a.resolved_at and a.created_at:
            mttr_minutes.append((a.resolved_at - a.created_at).total_seconds() / 60)

    def avg(lst: list[float]) -> float | None:
        return round(sum(lst) / len(lst), 1) if lst else None

    # open/escalated cases
    case_q = select(func.count()).select_from(Case).where(
        Case.created_at >= since,
        Case.status.in_(["open", "in_review", "escalated"])
    )
    if group_filter:
        case_q = case_q.where(Case.group_id == group_filter)
    open_cases = (await db.execute(case_q)).scalar() or 0

    fp_count = by_status.get("false_positive", 0)
    fp_rate = round(fp_count / total * 100, 1) if total else 0.0

    return {
        "period_days": days,
        "total_alerts": total,
        "open_cases": open_cases,
        "by_severity": by_severity,
        "by_status": by_status,
        "avg_ack_minutes": avg(ack_minutes),
        "avg_mttr_minutes": avg(mttr_minutes),
        "false_positive_rate_pct": fp_rate,
    }


@router.get("/workload")
async def analyst_workload(
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(get_current_user),
):
    """Per-analyst count of open alerts and open cases."""
    # Fetch all analysts in group
    user_q = select(User).where(User.is_active == True)
    if group_filter:
        user_q = user_q.where(User.group_id == group_filter)
    users = (await db.execute(user_q)).scalars().all()

    result = []
    for u in users:
        alert_q = select(func.count()).select_from(Alert).where(
            Alert.assignee_id == u.id,
            Alert.status.in_(["new", "in_progress"])
        )
        case_q = select(func.count()).select_from(Case).where(
            Case.assignee_id == u.id,
            Case.status.in_(["open", "in_review"])
        )
        open_alerts = (await db.execute(alert_q)).scalar() or 0
        open_cases  = (await db.execute(case_q)).scalar()  or 0
        result.append({
            "user_id":     str(u.id),
            "username":    u.username,
            "open_alerts": open_alerts,
            "open_cases":  open_cases,
            "total":       open_alerts + open_cases,
        })

    result.sort(key=lambda x: x["total"], reverse=True)
    return result


@router.get("/ti/quick")
async def quick_ti_lookup(
    ioc: str = Query(..., description="IP, hash, domain, or URL to look up"),
    ioc_type: str = Query(default="ip", description="ip | hash | domain | url"),
    _=Depends(get_current_user),
):
    """Ad-hoc threat intelligence lookup — wraps the worker TI engine via direct HTTP."""
    import httpx, os
    worker_url = os.environ.get("WORKER_TI_URL", "http://worker:8001")
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(f"{worker_url}/ti/quick",
                                    params={"ioc": ioc, "ioc_type": ioc_type})
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass
    # Fallback: return basic info if worker unreachable
    return {"ioc": ioc, "ioc_type": ioc_type, "status": "worker_unreachable",
            "provider_bullets": [], "overall_risk": 0.0}
