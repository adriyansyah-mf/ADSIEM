# server-api/app/api/routes/metrics.py
"""SOC KPI metrics: MTTD, MTTR, analyst workload, ad-hoc TI lookup."""
from typing import Annotated
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group, require_permission
from app.core.geoip import geoip_available, lookup_location
from app.core.http_client import get_http_client
from app.models.models import Agent, Alert, Case, User
from app.services.soc_command import aggregate_geo, backlog_aging, hq_target, worst_severity

router = APIRouter(prefix="/api/metrics", tags=["metrics"])

# The attack map geolocates at most this many distinct source IPs per request
# (the busiest ones); the response says when more exist.
_GEO_IP_SCAN_LIMIT = 2000


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

    # Unassigned pool — always show at top so analysts know what needs picking up
    unassigned_alert_q = select(func.count()).select_from(Alert).where(
        Alert.assignee_id == None,
        Alert.status.in_(["new", "in_progress"])
    )
    unassigned_case_q = select(func.count()).select_from(Case).where(
        Case.assignee_id == None,
        Case.status.in_(["open", "in_review"])
    )
    if group_filter:
        unassigned_alert_q = unassigned_alert_q.where(Alert.group_id == group_filter)
        unassigned_case_q  = unassigned_case_q.where(Case.group_id == group_filter)
    pool_alerts = (await db.execute(unassigned_alert_q)).scalar() or 0
    pool_cases  = (await db.execute(unassigned_case_q)).scalar()  or 0

    result = []
    if pool_alerts + pool_cases > 0:
        result.append({
            "user_id":     "unassigned",
            "username":    "— unassigned —",
            "open_alerts": pool_alerts,
            "open_cases":  pool_cases,
            "total":       pool_alerts + pool_cases,
        })

    for u in users:
        alert_q = select(func.count()).select_from(Alert).where(
            Alert.assignee_id == u.id,
            Alert.status.in_(["new", "in_progress"])
        )
        case_q = select(func.count()).select_from(Case).where(
            Case.assignee_id == u.id,
            Case.status.in_(["open", "in_review"])
        )
        if group_filter:
            alert_q = alert_q.where(Alert.group_id == group_filter)
            case_q  = case_q.where(Case.group_id == group_filter)
        open_alerts = (await db.execute(alert_q)).scalar() or 0
        open_cases  = (await db.execute(case_q)).scalar()  or 0
        result.append({
            "user_id":     str(u.id),
            "username":    u.username,
            "open_alerts": open_alerts,
            "open_cases":  open_cases,
            "total":       open_alerts + open_cases,
        })

    # Sort assigned users by total descending; pool stays at top
    assigned = sorted(result[1:] if result and result[0]["user_id"] == "unassigned" else result,
                      key=lambda x: x["total"], reverse=True)
    pool_row = [result[0]] if result and result[0]["user_id"] == "unassigned" else []
    return pool_row + assigned


@router.get("/ti/quick")
async def quick_ti_lookup(
    ioc: str = Query(..., description="IP, hash, domain, or URL to look up"),
    ioc_type: str = Query(default="ip", description="ip | hash | domain | url"),
    _=Depends(get_current_user),
):
    """Ad-hoc threat intelligence lookup — wraps the worker TI engine via direct HTTP."""
    import os
    worker_url = os.environ.get("WORKER_TI_URL", "http://worker:8001")
    try:
        client = get_http_client()
        resp = await client.get(f"{worker_url}/ti/quick",
                                params={"ioc": ioc, "ioc_type": ioc_type})
        if resp.status_code == 200:
            return resp.json()
    except Exception as exc:
        import structlog
        structlog.get_logger().warning("ti_quick_lookup_failed", ioc=ioc, error=str(exc))
    # Fallback: return basic info if worker unreachable
    return {"ioc": ioc, "ioc_type": ioc_type, "status": "worker_unreachable",
            "provider_bullets": [], "overall_risk": 0.0}


@router.get("/soc/timeseries")
async def soc_timeseries(
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(get_current_user),
    days: int = Query(default=7, le=90),
):
    """Alerts bucketed by hour for the dashboard's trend chart."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    q = select(Alert).where(Alert.created_at >= since)
    if group_filter:
        q = q.where(Alert.group_id == group_filter)
    alerts = (await db.execute(q)).scalars().all()

    buckets: dict[str, dict] = {}
    for a in alerts:
        if not a.created_at:
            continue
        key = a.created_at.replace(minute=0, second=0, microsecond=0).isoformat()
        slot = buckets.setdefault(key, {"t": key, "total": 0})
        slot["total"] += 1
        slot[a.severity] = slot.get(a.severity, 0) + 1

    series = [buckets[k] for k in sorted(buckets.keys())]
    return {"period_days": days, "points": series}


@router.get("/soc/top-sources")
async def soc_top_sources(
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(get_current_user),
    days: int = Query(default=7, le=90),
    limit: int = Query(default=10, le=50),
):
    """Top source IPs by alert volume, for the dashboard's bar chart."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    q = (
        select(Alert.source_ip, func.count().label("n"))
        .where(Alert.created_at >= since, Alert.source_ip.isnot(None))
        .group_by(Alert.source_ip)
        .order_by(func.count().desc())
        .limit(limit)
    )
    if group_filter:
        q = q.where(Alert.group_id == group_filter)
    rows = (await db.execute(q)).all()
    return {"period_days": days, "sources": [{"ip": ip, "count": n} for ip, n in rows]}


@router.get("/soc/mttr-trend")
async def soc_mttr_trend(
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(get_current_user),
    days: int = Query(default=30, le=90),
):
    """Daily average acknowledge/resolve time, for the MTTD/MTTR trend chart."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    q = select(Alert).where(Alert.created_at >= since, Alert.acknowledged_at.isnot(None))
    if group_filter:
        q = q.where(Alert.group_id == group_filter)
    alerts = (await db.execute(q)).scalars().all()

    buckets: dict[str, dict] = {}
    for a in alerts:
        if not a.created_at:
            continue
        day = a.created_at.date().isoformat()
        slot = buckets.setdefault(day, {"day": day, "ack": [], "mttr": []})
        if a.acknowledged_at:
            slot["ack"].append((a.acknowledged_at - a.created_at).total_seconds() / 60)
        if a.resolved_at:
            slot["mttr"].append((a.resolved_at - a.created_at).total_seconds() / 60)

    points = []
    for day in sorted(buckets.keys()):
        slot = buckets[day]
        points.append({
            "day": day,
            "avg_ack_minutes": round(sum(slot["ack"]) / len(slot["ack"]), 1) if slot["ack"] else None,
            "avg_mttr_minutes": round(sum(slot["mttr"]) / len(slot["mttr"]), 1) if slot["mttr"] else None,
        })
    return {"period_days": days, "points": points}


@router.get("/soc/geo")
async def soc_geo(
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(get_current_user),
    days: int = Query(default=7, ge=1, le=90),
    max_points: int = Query(default=300, ge=10, le=1000),
):
    """Attack-origin map: alerts in the window rolled up by geolocated source
    IP and country, the latest geolocated detections for the live feed, and
    the protected site that attack arcs point at (SOC_HQ_LAT/LON)."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    window = [Alert.created_at >= since, Alert.source_ip.isnot(None), Alert.source_ip != ""]
    if group_filter:
        window.append(Alert.group_id == group_filter)

    top_ips = (
        select(Alert.source_ip)
        .where(*window)
        .group_by(Alert.source_ip)
        .order_by(func.count().desc())
        .limit(_GEO_IP_SCAN_LIMIT)
    ).scalar_subquery()
    rows = (await db.execute(
        select(Alert.source_ip, Alert.severity, func.count(), func.max(Alert.created_at))
        .where(*window, Alert.source_ip.in_(top_ips))
        .group_by(Alert.source_ip, Alert.severity)
    )).all()
    distinct_ips = (await db.execute(
        select(func.count(func.distinct(Alert.source_ip))).where(*window)
    )).scalar() or 0

    geo = aggregate_geo(((ip, sev, n, last) for ip, sev, n, last in rows), lookup_location, max_points)

    recent_rows = (await db.execute(
        select(Alert.id, Alert.title, Alert.severity, Alert.status, Alert.source_ip, Alert.hostname, Alert.created_at)
        .where(*window)
        .order_by(Alert.created_at.desc())
        .limit(80)
    )).all()
    recent = []
    for aid, title, severity, status, ip, hostname, created_at in recent_rows:
        loc = lookup_location(ip)
        if not loc:
            continue
        recent.append({
            "id": str(aid), "title": title, "severity": severity, "status": status,
            "source_ip": ip, "hostname": hostname,
            "created_at": created_at.isoformat() if created_at else None, **loc,
        })
        if len(recent) >= 25:
            break

    return {
        "period_days": days,
        "geoip_available": geoip_available(),
        "target": hq_target(),
        "distinct_source_ips": distinct_ips,
        "ip_scan_truncated": distinct_ips > _GEO_IP_SCAN_LIMIT,
        "recent": recent,
        **geo,
    }


@router.get("/soc/posture")
async def soc_posture(
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(get_current_user),
    days: int = Query(default=7, ge=1, le=90),
):
    """Triage posture for the command center: open-alert aging and SLA
    breaches (all time, since a backlog ignores the chart window), plus the
    most-targeted hosts, noisiest detections and agent fleet health."""
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=days)

    open_q = select(Alert.severity, Alert.status, Alert.created_at, Alert.assignee_id.isnot(None)).where(
        Alert.status.in_(["new", "in_progress"]))
    if group_filter:
        open_q = open_q.where(Alert.group_id == group_filter)
    backlog = backlog_aging((await db.execute(open_q)).all(), now)

    windowed = [Alert.created_at >= since]
    if group_filter:
        windowed.append(Alert.group_id == group_filter)

    host_rows = (await db.execute(
        select(Alert.hostname, Alert.severity, func.count())
        .where(*windowed, Alert.hostname.isnot(None), Alert.hostname != "")
        .group_by(Alert.hostname, Alert.severity)
    )).all()
    hosts: dict[str, dict] = {}
    for hostname, severity, n in host_rows:
        h = hosts.setdefault(hostname, {"hostname": hostname, "count": 0, "by_severity": {}})
        h["count"] += n
        h["by_severity"][severity] = h["by_severity"].get(severity, 0) + n
    top_hosts = sorted(hosts.values(), key=lambda h: -h["count"])[:8]
    for h in top_hosts:
        h["max_severity"] = worst_severity(h["by_severity"])

    rule_rows = (await db.execute(
        select(Alert.title, func.count(), func.count().filter(Alert.status == "false_positive"))
        .where(*windowed)
        .group_by(Alert.title)
        .order_by(func.count().desc())
        .limit(8)
    )).all()
    top_detections = [{"title": t, "count": n, "false_positives": fp} for t, n, fp in rule_rows]

    agent_q = select(Agent.status, Agent.is_isolated, func.count()).group_by(Agent.status, Agent.is_isolated)
    if group_filter:
        agent_q = agent_q.where(Agent.group_id == group_filter)
    agents = {"total": 0, "online": 0, "offline": 0, "isolated": 0}
    for status, isolated, n in (await db.execute(agent_q)).all():
        agents["total"] += n
        agents["online" if status == "online" else "offline"] += n
        if isolated:
            agents["isolated"] += n

    return {
        "period_days": days,
        "generated_at": now.isoformat(),
        "backlog": backlog,
        "top_hosts": top_hosts,
        "top_detections": top_detections,
        "agents": agents,
    }
