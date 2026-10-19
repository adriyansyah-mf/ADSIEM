# worker/worker/agent_monitor.py
"""Mark agents offline if they stop sending heartbeats, and time out live-response
tasks that no agent will ever answer."""
import asyncio
from datetime import datetime, timezone, timedelta

import structlog
from sqlalchemy import and_, case, func, or_, select, update

from worker.agent_health import health_event
from worker.config import REDIS_STREAM_KEY
from worker.database import AsyncSessionLocal
from worker.models import Agent, AgentTask, FleetHunt, Flow
from worker.redis_client import get_redis

log = structlog.get_logger()

OFFLINE_AFTER_SECONDS = 300  # 5 minutes without heartbeat → offline
CHECK_INTERVAL = 60
STOP_GRACE = 120             # a stop notice not followed by a heartbeat in this long is reported
MASS_OFFLINE_MIN = 5         # this many (and half the fleet) silent at once → one fleet event
TASK_PICKUP_TIMEOUT = 600    # pending: no heartbeat fetched it in 10 minutes
TASK_RESULT_TIMEOUT = 1800   # dispatched: fetched, but no result in 30 minutes

PICKUP_TIMEOUT_ERROR = "Timed out: agent never picked up the task (offline or unreachable)"
RESULT_TIMEOUT_ERROR = "Timed out: agent received the task but never reported a result"

# Live-response flows wait for offline agents (like Velociraptor), but not forever;
# a running flow gets its own timeout plus a grace period for the final upload.
FLOW_SCHEDULE_EXPIRY = 86400
FLOW_RESULT_GRACE = 300
FLOW_EXPIRED_ERROR = "Expired: agent did not come online within 24h"
FLOW_STALLED_ERROR = "Agent stopped reporting before the flow finished"


async def _mark_offline(db) -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=OFFLINE_AFTER_SECONDS)
    # NULL last_seen_at means the agent enrolled but never sent a heartbeat;
    # `NULL < cutoff` is never true, so it has to be matched explicitly.
    result = await db.execute(
        update(Agent)
        .where(Agent.status == "online")
        .where(or_(Agent.last_seen_at < cutoff, Agent.last_seen_at.is_(None)))
        .values(status="offline")
        .returning(Agent.id, Agent.hostname, Agent.group_id, Agent.approved, Agent.last_seen_at)
    )
    went_offline = result.fetchall()
    if not went_offline:
        return
    await db.commit()
    for agent_id, hostname, *_ in went_offline:
        log.info("agent_went_offline", agent_id=str(agent_id), hostname=hostname)

    # Silent without the stop notice a deliberate stop sends first: killed,
    # network cut, host lost (rules/siem_agent_offline.yaml). Never-seen and
    # unapproved agents aren't news.
    silent = [r for r in went_offline if r[3] and r[4] is not None]
    if not silent:
        return
    approved_total = (await db.execute(
        select(func.count()).select_from(Agent).where(Agent.approved.is_(True)))).scalar_one()
    redis = await get_redis()
    if len(silent) >= MASS_OFFLINE_MIN and len(silent) * 2 >= approved_total:
        # half the fleet at once is the SIEM's own outage or a network one, not
        # tampering on every host: one event per group instead of an alert each
        by_group: dict[str, list[str]] = {}
        for _, hostname, group_id, *_ in silent:
            by_group.setdefault(group_id, []).append(hostname)
        log.warning("agents_offline_together", count=len(silent), total=approved_total)
        for group_id, hosts in by_group.items():
            await redis.xadd(REDIS_STREAM_KEY, health_event(
                "agent_offline_mass", agent_id=None, group_id=group_id, hostname="siem",
                count=len(hosts), hosts=",".join(sorted(hosts)[:50]),
            ))
        return
    for agent_id, hostname, group_id, _, last_seen in silent:
        await redis.xadd(REDIS_STREAM_KEY, health_event(
            "agent_offline", agent_id=agent_id, group_id=group_id, hostname=hostname,
            last_seen=last_seen.isoformat(), silent_seconds=OFFLINE_AFTER_SECONDS,
        ))


async def _report_stops(db) -> None:
    """A stop notice still unanswered after STOP_GRACE is a real stop: report it.
    Restarts and upgrades heartbeat again first, which clears stop_reason."""
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=STOP_GRACE)
    # read, then clear: RETURNING would hand back the cleared reason; the row
    # lock keeps a second worker replica from reporting the same stop
    stopped = (await db.execute(
        select(Agent.id, Agent.hostname, Agent.group_id, Agent.approved, Agent.stop_reason,
               Agent.version, Agent.last_seen_at)
        .where(Agent.stop_reason.is_not(None), Agent.status != "online", Agent.last_seen_at < cutoff)
        .with_for_update(skip_locked=True)
    )).all()
    if not stopped:
        return
    await db.execute(update(Agent).where(Agent.id.in_([r[0] for r in stopped])).values(stop_reason=None))
    await db.commit()
    redis = await get_redis()
    for agent_id, hostname, group_id, approved, reason, version, last_seen in stopped:
        log.info("agent_stopped", agent_id=str(agent_id), hostname=hostname, reason=reason)
        if approved:
            await redis.xadd(REDIS_STREAM_KEY, health_event(
                "agent_stopped", agent_id=agent_id, group_id=group_id, hostname=hostname,
                reason=reason, version=version, stopped_at=last_seen.isoformat(),
            ))


async def _expire_stale_tasks(db) -> None:
    now = datetime.now(timezone.utc)
    result = await db.execute(
        update(AgentTask)
        .where(or_(
            and_(AgentTask.status == "pending",
                 AgentTask.created_at < now - timedelta(seconds=TASK_PICKUP_TIMEOUT)),
            and_(AgentTask.status == "dispatched",
                 AgentTask.created_at < now - timedelta(seconds=TASK_RESULT_TIMEOUT)),
        ))
        .values(
            status="failed",
            error=case((AgentTask.status == "pending", PICKUP_TIMEOUT_ERROR), else_=RESULT_TIMEOUT_ERROR),
            completed_at=now,
        )
        .returning(AgentTask.id, AgentTask.agent_id, AgentTask.fleet_hunt_id)
    )
    expired = result.fetchall()
    if not expired:
        return

    hunt_ids = {row[2] for row in expired if row[2] is not None}
    if hunt_ids:
        finished = (
            select(func.count())
            .where(AgentTask.fleet_hunt_id == FleetHunt.id,
                   AgentTask.status.in_(("done", "failed")))
            .scalar_subquery()
        )
        await db.execute(
            update(FleetHunt)
            .where(FleetHunt.id.in_(hunt_ids))
            .values(
                completed_agents=finished,
                status=case((finished >= FleetHunt.total_agents, "done"), else_="running"),
            )
        )
    await db.commit()
    for row in expired:
        log.info("agent_task_timed_out", task_id=str(row[0]), agent_id=str(row[1]))


async def _expire_stale_flows(db) -> None:
    now = datetime.now(timezone.utc)
    deadline = Flow.started_at + func.make_interval(0, 0, 0, 0, 0, 0, Flow.timeout + FLOW_RESULT_GRACE)
    result = await db.execute(
        update(Flow)
        .where(or_(
            and_(Flow.status == "scheduled",
                 Flow.created_at < now - timedelta(seconds=FLOW_SCHEDULE_EXPIRY)),
            and_(Flow.status == "running", deadline < now),
        ))
        .values(
            status="error",
            error=case((Flow.status == "scheduled", FLOW_EXPIRED_ERROR), else_=FLOW_STALLED_ERROR),
            completed_at=now,
        )
        .returning(Flow.id, Flow.agent_id)
    )
    expired = result.fetchall()
    if expired:
        await db.commit()
        for row in expired:
            log.info("flow_expired", flow_id=str(row[0]), agent_id=str(row[1]))


async def agent_monitor_loop() -> None:
    while True:
        try:
            async with AsyncSessionLocal() as db:
                await _mark_offline(db)
                await _report_stops(db)
                await _expire_stale_tasks(db)
                await _expire_stale_flows(db)
        except Exception as exc:
            log.error("agent_monitor_error", error=str(exc))

        await asyncio.sleep(CHECK_INTERVAL)
