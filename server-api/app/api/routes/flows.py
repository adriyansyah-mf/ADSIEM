# server-api/app/api/routes/flows.py
"""Live response, Velociraptor style: artifacts are compiled into flows, agents
long-poll for them, stream rows/logs back, and the server filters the rows with
each source's Sigma detection before storing them."""
import asyncio
import csv
import io
import json
import time
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
import redis.asyncio as aioredis

from app.core.database import AsyncSessionLocal, get_db
from app.core.deps import get_agent, get_current_user, get_scoped_group, require_permission
from app.core.redis_client import get_redis
from app.models.models import Agent, Flow, FlowArtifact, FlowLog, FlowRowBatch, User, YaraRule
from app.schemas.schemas import (
    AgentFlowUpdate, FlowArtifactIn, FlowCreate, FlowDetailOut, FlowLogOut, FlowOut,
    FlowResultsOut, FlowSourceCount,
)
from app.services.audit import audit_log
from app.services.flow_artifacts import (
    DEFAULT_MAX_ROWS, MAX_MAX_ROWS, MAX_TIMEOUT, ArtifactDef, ArtifactError, RowFilter,
    build_row_filter, builtin_artifacts, column_order, compile_request, parse_artifact, resolve_params,
)

router = APIRouter(prefix="/api/flows", tags=["flows"])
artifact_router = APIRouter(prefix="/api/flow-artifacts", tags=["flows"])
agent_router = APIRouter(prefix="/api/agent/flows", tags=["flows"])

TERMINAL = ("finished", "error", "cancelled")
POLL_SECONDS = 20          # agent HTTP timeout must exceed this
POLL_DB_FALLBACK = 5       # re-check the DB this often even without a Redis wake-up
WAKE_KEY = "siem:flowq:{}"


async def _wake(redis: aioredis.Redis, agent_id: UUID) -> None:
    """Nudge a long-polling agent; the poll loop falls back to DB checks if Redis is down."""
    try:
        await redis.set(WAKE_KEY.format(agent_id), "1", ex=300)
    except Exception:
        pass


def _bad_request(exc: Exception) -> HTTPException:
    return HTTPException(status_code=422, detail=str(exc))


# ─── Artifacts ───────────────────────────────────────────────────

async def _load_artifact(db: AsyncSession, name: str, group_filter: str | None) -> ArtifactDef:
    if name in builtin_artifacts():
        return builtin_artifacts()[name]
    q = select(FlowArtifact).where(FlowArtifact.name == name)
    if group_filter is not None:
        q = q.where(FlowArtifact.group_id == group_filter)
    row = (await db.execute(q)).scalar_one_or_none()
    if not row:
        raise HTTPException(404, "Artifact not found")
    try:
        return parse_artifact(row.content)
    except ArtifactError as exc:
        raise HTTPException(409, f"Stored artifact is invalid: {exc}")


@artifact_router.get("")
async def list_flow_artifacts(
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    out = [a.summary() for a in builtin_artifacts().values()]
    q = select(FlowArtifact)
    if group_filter is not None:
        q = q.where(FlowArtifact.group_id == group_filter)
    for row in (await db.execute(q)).scalars().all():
        try:
            out.append({**parse_artifact(row.content).summary(),
                        "created_by_investigation_id": row.created_by_investigation_id,
                        "promoted_at": row.promoted_at})
        except ArtifactError as exc:
            out.append({"name": row.name, "description": row.description or "", "builtin": False,
                        "parameters": [], "sources": [], "content": row.content, "error": str(exc)})
    return sorted(out, key=lambda a: a["name"].lower())


@artifact_router.get("/{name}")
async def get_flow_artifact(
    name: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    return (await _load_artifact(db, name, group_filter)).summary()


async def _save_artifact(db, body: FlowArtifactIn, user: User, group_filter: str | None,
                         existing_name: str | None) -> dict:
    try:
        art = parse_artifact(body.content)
    except ArtifactError as exc:
        raise _bad_request(exc)
    if art.name in builtin_artifacts():
        raise HTTPException(409, f"'{art.name}' is a built-in artifact; save it under another name")
    group_id = group_filter or user.group_id or "default"

    clash = (await db.execute(select(FlowArtifact).where(FlowArtifact.name == art.name))).scalar_one_or_none()
    if existing_name is None:
        if clash:
            raise HTTPException(409, f"Artifact '{art.name}' already exists")
        row = FlowArtifact(name=art.name, created_by=user.id, group_id=group_id)
        db.add(row)
    else:
        q = select(FlowArtifact).where(FlowArtifact.name == existing_name)
        if group_filter is not None:
            q = q.where(FlowArtifact.group_id == group_filter)
        row = (await db.execute(q)).scalar_one_or_none()
        if not row:
            raise HTTPException(404, "Artifact not found")
        if clash and clash.id != row.id:
            raise HTTPException(409, f"Artifact '{art.name}' already exists")
        row.name = art.name
    row.description = art.description
    row.content = body.content
    if art.name.startswith("AI.") and row.promoted_at is None:
        # a person saved this content: AI investigations may reuse it from now on
        row.promoted_at, row.promoted_by = datetime.now(timezone.utc), user.id
    await db.commit()
    return art.summary()


@artifact_router.post("/{name}/promote")
async def promote_flow_artifact(
    name: str,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission("agents:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    """Let every AI investigation in the group reuse an artifact one of them wrote."""
    q = select(FlowArtifact).where(FlowArtifact.name == name)
    if group_filter is not None:
        q = q.where(FlowArtifact.group_id == group_filter)
    row = (await db.execute(q)).scalar_one_or_none()
    if row is None or not row.name.startswith("AI."):
        raise HTTPException(404, "AI artifact not found")
    if row.promoted_at is None:
        row.promoted_at, row.promoted_by = datetime.now(timezone.utc), user.id
        await db.commit()
        background.add_task(audit_log, db, user.id, "flow_artifact_promoted", "flow_artifact", row.name,
                            {"investigation": str(row.created_by_investigation_id or "")})
    return {"name": row.name, "promoted_at": row.promoted_at,
            "created_by_investigation_id": row.created_by_investigation_id}


@artifact_router.post("", status_code=201)
async def create_flow_artifact(
    body: FlowArtifactIn,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission("agents:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    out = await _save_artifact(db, body, user, group_filter, None)
    background.add_task(audit_log, db, user.id, "flow_artifact_created", "flow_artifact", out["name"])
    return out


@artifact_router.put("/{name}")
async def update_flow_artifact(
    name: str,
    body: FlowArtifactIn,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission("agents:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    if name in builtin_artifacts():
        raise HTTPException(409, "Built-in artifacts are read-only")
    out = await _save_artifact(db, body, user, group_filter, name)
    background.add_task(audit_log, db, user.id, "flow_artifact_updated", "flow_artifact", out["name"])
    return out


@artifact_router.delete("/{name}", status_code=204)
async def delete_flow_artifact(
    name: str,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission("agents:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    if name in builtin_artifacts():
        raise HTTPException(409, "Built-in artifacts are read-only")
    q = select(FlowArtifact).where(FlowArtifact.name == name)
    if group_filter is not None:
        q = q.where(FlowArtifact.group_id == group_filter)
    row = (await db.execute(q)).scalar_one_or_none()
    if not row:
        raise HTTPException(404, "Artifact not found")
    await db.delete(row)
    await db.commit()
    background.add_task(audit_log, db, user.id, "flow_artifact_deleted", "flow_artifact", name)


# ─── Flows (analyst side) ────────────────────────────────────────

def _scoped_flow_query(group_filter: str | None):
    q = select(Flow)
    if group_filter is not None:
        q = q.where(Flow.agent_id.in_(select(Agent.id).where(Agent.group_id == group_filter)))
    return q


async def _get_flow(db: AsyncSession, flow_id: UUID, group_filter: str | None) -> Flow:
    flow = (await db.execute(_scoped_flow_query(group_filter).where(Flow.id == flow_id))).scalar_one_or_none()
    if not flow:
        raise HTTPException(404, "Flow not found")
    return flow


async def schedule_flow(
    db: AsyncSession, redis: aioredis.Redis, *, agent_id: UUID, artifact: str, params: dict,
    group_filter: str | None, created_by: UUID | None, scheduled_by: str,
    timeout: int | None = None, max_rows: int | None = None, flow_id: UUID | None = None,
    only_rules: list[dict] | None = None,
) -> Flow:
    """Validate and queue one flow, then wake the agent. Raises HTTPException
    (404 agent/artifact, 409 no flow runner, 422 bad params). Shared by the
    API and the AI investigator, so both go through the same checks. A caller
    that passes flow_id may stage its own rows referencing it on `db`: they
    commit together with the flow, or not at all."""
    aq = select(Agent).where(Agent.id == agent_id)
    if group_filter is not None:
        aq = aq.where(Agent.group_id == group_filter)
    target = (await db.execute(aq)).scalar_one_or_none()
    if not target:
        raise HTTPException(404, "Agent not found")
    # Capability, not version number: builds in the field use unrelated version
    # schemes, but only agents with a flow runner ever long-poll for flows.
    if target.flow_poll_at is None:
        raise HTTPException(409, f"Agent {target.hostname} (v{target.version or '?'}) has never polled for "
                                 "live-response flows, so it has no flow runner; update it to agent v1.3.0+ "
                                 "(Legacy tasks still work)")

    art = await _load_artifact(db, artifact, group_filter)
    timeout = timeout or art.timeout
    max_rows = max_rows or art.max_rows
    if not 1 <= timeout <= MAX_TIMEOUT:
        raise HTTPException(422, f"timeout must be between 1 and {MAX_TIMEOUT} seconds")
    if not 1 <= max_rows <= MAX_MAX_ROWS:
        raise HTTPException(422, f"max_rows must be between 1 and {MAX_MAX_ROWS}")

    yara_rules = only_rules  # a rule-scoped test scan: exactly these rules, enabled or not
    if yara_rules is None and any(s.plugin == "yara" for s in art.sources):
        rows = (await db.execute(select(YaraRule).where(YaraRule.is_enabled == True))).scalars().all()  # noqa: E712
        if not rows:
            raise HTTPException(422, "No enabled YARA rules — add one on the YARA page first")
        yara_rules = [{"id": str(r.id), "name": r.name, "content": r.content} for r in rows]

    flow_id = flow_id or uuid.uuid4()
    try:
        params = resolve_params(art, params)
        build_row_filter(art.content, params)  # detection must compile with these values
        request = compile_request(art, str(flow_id), params, timeout, max_rows, yara_rules)
    except ArtifactError as exc:
        raise _bad_request(exc)

    flow = Flow(
        id=flow_id, agent_id=agent_id, artifact=art.name, artifact_content=art.content,
        params=params, request=request, timeout=timeout, max_rows=max_rows, created_by=created_by,
    )
    db.add(flow)
    db.add(FlowLog(flow_id=flow_id, level="info", message=f"Scheduled by {scheduled_by}"))
    await db.commit()
    await db.refresh(flow)
    await _wake(redis, agent_id)
    return flow


COMMAND_ARTIFACT = "AI.Command"
_COMMAND_CONTENT = """name: AI.Command
description: A command an analyst approved for an AI investigation (agent exec plugin).
sources:
  - name: Output
    plugin: exec
"""


async def schedule_command_flow(
    db: AsyncSession, redis: aioredis.Redis, *, agent: Agent, command: str, args: list[str],
    timeout: int, created_by: UUID | None, scheduled_by: str, flow_id: UUID | None = None,
) -> Flow:
    """Queue one approved command for the agent's exec plugin. Built here, not
    from an artifact: exec is in no saved artifact (flow_artifacts.INTERNAL_PLUGINS).
    flow_id works as in schedule_flow: rows staged on `db` commit with the flow."""
    if agent.flow_poll_at is None:
        raise HTTPException(409, f"Agent {agent.hostname} has no flow runner; update it")
    flow_id = flow_id or uuid.uuid4()
    flow_timeout = timeout + 30  # the agent kills the command first and still reports
    request = {"id": str(flow_id), "artifact": COMMAND_ARTIFACT, "timeout": flow_timeout,
               "max_rows": DEFAULT_MAX_ROWS,
               "sources": [{"name": "Output", "plugin": "exec",
                            "args": {"command": command, "args": args, "timeout": timeout}}]}
    flow = Flow(id=flow_id, agent_id=agent.id, artifact=COMMAND_ARTIFACT, artifact_content=_COMMAND_CONTENT,
                params={"command": command, "args": args}, request=request, timeout=flow_timeout,
                max_rows=DEFAULT_MAX_ROWS, created_by=created_by)
    db.add(flow)
    db.add(FlowLog(flow_id=flow_id, level="info", message=f"Scheduled by {scheduled_by}"))
    await db.commit()
    await db.refresh(flow)
    await _wake(redis, agent.id)
    return flow


@router.post("", response_model=FlowOut, status_code=201)
async def create_flow(
    body: FlowCreate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    redis: Annotated[aioredis.Redis, Depends(get_redis)],
    user: Annotated[User, Depends(require_permission("agents:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    flow = await schedule_flow(
        db, redis, agent_id=body.agent_id, artifact=body.artifact, params=body.params,
        group_filter=group_filter, created_by=user.id, scheduled_by=user.username,
        timeout=body.timeout, max_rows=body.max_rows,
    )
    background.add_task(audit_log, db, user.id, "flow_created", "flow", str(flow.id),
                        {"artifact": flow.artifact, "agent_id": str(body.agent_id)})
    return flow


@router.get("", response_model=list[FlowOut])
async def list_flows(
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    agent_id: UUID | None = None,
    limit: int = Query(100, ge=1, le=500),
):
    q = _scoped_flow_query(group_filter).order_by(Flow.created_at.desc()).limit(limit)
    if agent_id:
        q = q.where(Flow.agent_id == agent_id)
    return (await db.execute(q)).scalars().all()


@router.get("/{flow_id}", response_model=FlowDetailOut)
async def get_flow(
    flow_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    flow = await _get_flow(db, flow_id, group_filter)
    counts = dict((await db.execute(
        select(FlowRowBatch.source, func.sum(func.jsonb_array_length(FlowRowBatch.rows)))
        .where(FlowRowBatch.flow_id == flow_id).group_by(FlowRowBatch.source)
    )).all())
    names = [s["name"] for s in (flow.request or {}).get("sources", [])]
    out = FlowDetailOut.model_validate(flow)
    out.sources = [FlowSourceCount(name=n, rows=int(counts.get(n) or 0)) for n in names]
    return out


async def _source_rows(db: AsyncSession, flow: Flow, source: str | None) -> tuple[str, list[dict]]:
    names = [s["name"] for s in (flow.request or {}).get("sources", [])]
    if not names:
        return "", []
    source = source or names[0]
    if source not in names:
        raise HTTPException(404, f"Flow has no source '{source}'")
    batches = (await db.execute(
        select(FlowRowBatch.rows).where(FlowRowBatch.flow_id == flow.id, FlowRowBatch.source == source)
        .order_by(FlowRowBatch.id)
    )).scalars().all()
    return source, [row for batch in batches for row in batch]


@router.get("/{flow_id}/results", response_model=FlowResultsOut)
async def get_flow_results(
    flow_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    source: str | None = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(500, ge=1, le=1000),
):
    flow = await _get_flow(db, flow_id, group_filter)
    source, rows = await _source_rows(db, flow, source)
    page = rows[offset:offset + limit]
    return FlowResultsOut(source=source, columns=column_order(flow.artifact_content, source, page),
                          rows=page, total=len(rows))


@router.get("/{flow_id}/results/download")
async def download_flow_results(
    flow_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    source: str | None = None,
    format: Literal["json", "csv"] = "json",
):
    flow = await _get_flow(db, flow_id, group_filter)
    source, rows = await _source_rows(db, flow, source)
    filename = f"{flow.artifact}.{source}.{str(flow.id)[:8]}.{format}"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    if format == "json":
        return StreamingResponse(iter([json.dumps(rows, default=str)]), media_type="application/json", headers=headers)
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=column_order(flow.artifact_content, source, rows), extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({k: json.dumps(v) if isinstance(v, (dict, list)) else v for k, v in row.items()})
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv", headers=headers)


@router.get("/{flow_id}/logs", response_model=list[FlowLogOut])
async def get_flow_logs(
    flow_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    await _get_flow(db, flow_id, group_filter)
    q = select(FlowLog).where(FlowLog.flow_id == flow_id).order_by(FlowLog.id).limit(2000)
    return (await db.execute(q)).scalars().all()


@router.post("/{flow_id}/cancel", response_model=FlowOut)
async def cancel_flow(
    flow_id: UUID,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    redis: Annotated[aioredis.Redis, Depends(get_redis)],
    user: Annotated[User, Depends(require_permission("agents:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    flow = await _get_flow(db, flow_id, group_filter)
    if flow.status in TERMINAL:
        raise HTTPException(409, f"Flow is already {flow.status}")
    was_running = flow.status == "running"
    flow.status = "cancelled"
    flow.completed_at = datetime.now(timezone.utc)
    flow.cancel_pending = was_running  # the agent is told on its next poll or update
    db.add(FlowLog(flow_id=flow.id, level="warn", message=f"Cancelled by {user.username}"))
    await db.commit()
    await db.refresh(flow)
    if was_running:
        await _wake(redis, flow.agent_id)
    background.add_task(audit_log, db, user.id, "flow_cancelled", "flow", str(flow_id))
    return flow


# ─── Agent side ──────────────────────────────────────────────────

async def _claim(agent_id: UUID) -> dict:
    """Hand scheduled flows to the agent (→ running) and collect pending cancels."""
    async with AsyncSessionLocal() as db:
        flows = (await db.execute(
            select(Flow).where(Flow.agent_id == agent_id, Flow.status == "scheduled")
            .order_by(Flow.created_at).with_for_update(skip_locked=True)
        )).scalars().all()
        now = datetime.now(timezone.utc)
        for flow in flows:
            flow.status = "running"
            flow.started_at = now
            db.add(FlowLog(flow_id=flow.id, level="info", message="Delivered to agent"))
        cancels = (await db.execute(
            update(Flow).where(Flow.agent_id == agent_id, Flow.cancel_pending == True)  # noqa: E712
            .values(cancel_pending=False).returning(Flow.id)
        )).scalars().all()
        await db.commit()
        return {"flows": [f.request for f in flows], "cancel": [str(i) for i in cancels]}


@agent_router.post("/poll")
async def poll_flows(
    request: Request,
    agent: Annotated[Agent, Depends(get_agent)],
    db: Annotated[AsyncSession, Depends(get_db)],
    redis: Annotated[aioredis.Redis, Depends(get_redis)],
):
    """Long poll: returns as soon as there is work, or empty after POLL_SECONDS."""
    if not agent.approved:
        # no live response before approval; wait out the poll so the agent doesn't spin
        await asyncio.sleep(POLL_SECONDS)
        return {"flows": [], "cancel": []}
    agent_id = agent.id
    await db.execute(update(Agent).where(Agent.id == agent_id).values(flow_poll_at=datetime.now(timezone.utc)))
    await db.commit()  # also releases the pooled connection for the rest of the poll
    deadline = time.monotonic() + POLL_SECONDS
    last_check = float("-inf")
    while True:
        # A dead agent's poll must not claim flows it can never receive.
        if await request.is_disconnected():
            return {"flows": [], "cancel": []}
        now = time.monotonic()
        try:
            woken = bool(await redis.delete(WAKE_KEY.format(agent_id)))
        except Exception:
            woken = False
        if woken or now - last_check >= POLL_DB_FALLBACK:
            last_check = now
            work = await _claim(agent_id)
            if work["flows"] or work["cancel"]:
                return work
        if now >= deadline:
            return {"flows": [], "cancel": []}
        await asyncio.sleep(0.5)


_FILTER_CACHE: "OrderedDict[UUID, RowFilter]" = OrderedDict()


def _row_filter(flow: Flow) -> RowFilter:
    filt = _FILTER_CACHE.get(flow.id)
    if filt is None:
        filt = build_row_filter(flow.artifact_content, flow.params)
        _FILTER_CACHE[flow.id] = filt
        if len(_FILTER_CACHE) > 256:
            _FILTER_CACHE.popitem(last=False)
    return filt


@agent_router.post("/{flow_id}/update")
async def update_flow(
    flow_id: UUID,
    body: AgentFlowUpdate,
    agent: Annotated[Agent, Depends(get_agent)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    flow = (await db.execute(
        select(Flow).where(Flow.id == flow_id, Flow.agent_id == agent.id).with_for_update()
    )).scalar_one_or_none()
    if not flow:
        raise HTTPException(404, "Flow not found")
    if flow.status in TERMINAL:
        return {"cancel": True}

    now = datetime.now(timezone.utc)
    for entry in body.logs:
        db.add(FlowLog(flow_id=flow.id, ts=now, level=entry.level, message=entry.message))

    if body.rows:
        if not body.source:
            raise HTTPException(422, "rows need a source")
        try:
            rows = _row_filter(flow).apply(body.source, body.rows)
        except ArtifactError as exc:
            raise _bad_request(exc)
        room = max(flow.max_rows - flow.total_rows, 0)
        if len(rows) > room:
            db.add(FlowLog(flow_id=flow.id, ts=now, level="warn",
                           message=f"Row limit {flow.max_rows} reached; {len(rows) - room} rows dropped"))
            rows = rows[:room]
        if rows:
            db.add(FlowRowBatch(flow_id=flow.id, source=body.source, rows=rows))
            flow.total_rows += len(rows)

    if body.state in TERMINAL:
        flow.status = body.state
        flow.completed_at = now
        flow.error = body.error
        _FILTER_CACHE.pop(flow.id, None)
    await db.commit()
    return {"cancel": False}
