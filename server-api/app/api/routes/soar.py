from datetime import datetime, timezone
from typing import Literal, Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import fetch_scoped, get_current_user, get_scoped_group, require_permission
from app.models.models import Alert, SoarAction, SoarPlaybook, SoarRun, SoarRunStep, User
from worker.soar.curl import CurlParseError, parse_curl
from worker.soar.graph import (
    ALERT_STATUSES, BODY_TYPES, CASE_OPS, EVENTS, HTTP_METHODS, NODE_TYPES, NOTIFY_CHANNELS, OPERATORS,
    RESPONSE_OPS, GraphError, from_legacy, trigger_event, trigger_node, validate,
)

router = APIRouter(prefix="/api/soar", tags=["soar"])

# Playbooks can isolate hosts and call arbitrary URLs: editing them is a response privilege.
Manage = require_permission("agents:manage")


class PlaybookIn(BaseModel):
    name: str
    description: Optional[str] = None
    trigger_conditions: dict = {}
    is_enabled: bool = True
    graph: Optional[dict] = None


class PlaybookUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    trigger_conditions: Optional[dict] = None
    is_enabled: Optional[bool] = None


class GraphIn(BaseModel):
    graph: dict


class CurlIn(BaseModel):
    command: str


class RunIn(BaseModel):
    alert_id: Optional[uuid.UUID] = None
    trigger: dict = {}


class DecisionIn(BaseModel):
    decision: Literal["approved", "rejected"]
    comment: Optional[str] = None


ACTION_TYPES = Literal['enrich_ioc', 'send_webhook', 'create_case', 'suppress_alert', 'add_note', 'isolate_agent', 'block_ip']

class ActionIn(BaseModel):
    action_type: ACTION_TYPES
    order_index: int = 0
    params: dict = {}


class ActionUpdate(BaseModel):
    action_type: Optional[ACTION_TYPES] = None
    order_index: Optional[int] = None
    params: Optional[dict] = None


def _graph_of(pb: SoarPlaybook, actions: list[SoarAction]) -> dict:
    if pb.graph:
        return pb.graph
    return from_legacy(pb.trigger_conditions, [
        {"action_type": a.action_type, "order_index": a.order_index, "params": a.params} for a in actions
    ])


def _pb_out(pb: SoarPlaybook, actions: list[SoarAction]) -> dict:
    return {
        "id": str(pb.id),
        "name": pb.name,
        "description": pb.description,
        "trigger_conditions": pb.trigger_conditions,
        "trigger_event": pb.trigger_event or trigger_event(_graph_of(pb, actions)),
        "is_enabled": pb.is_enabled,
        "group_id": pb.group_id,
        "legacy": pb.graph is None,
        "graph": _graph_of(pb, actions),
        "created_at": pb.created_at.isoformat() if pb.created_at else None,
        "updated_at": pb.updated_at.isoformat() if pb.updated_at else None,
        "actions": [
            {
                "id": str(a.id),
                "action_type": a.action_type,
                "order_index": a.order_index,
                "params": a.params,
            }
            for a in sorted(actions, key=lambda x: x.order_index)
        ],
    }


def _validated(graph: dict) -> dict:
    try:
        return validate(graph)
    except GraphError as exc:
        raise HTTPException(status_code=422, detail={"message": "invalid workflow", "errors": exc.errors})


async def _actions(db: AsyncSession, pb: SoarPlaybook) -> list[SoarAction]:
    return list((await db.execute(select(SoarAction).where(SoarAction.playbook_id == pb.id))).scalars().all())


def _run_out(run: SoarRun, steps: list[SoarRunStep] | None = None) -> dict:
    ctx = run.context or {}
    out = {
        "id": str(run.id),
        "playbook_id": str(run.playbook_id),
        "status": run.status,
        "trigger_event": run.trigger_event,
        "alert_id": str(run.alert_id) if run.alert_id else None,
        "waiting_node": run.waiting_node,
        "wait_until": run.wait_until.isoformat() if run.wait_until else None,
        "error": run.error,
        "created_at": run.created_at.isoformat() if run.created_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
    }
    if run.waiting_node:
        out["approval"] = (ctx.get("steps") or {}).get(run.waiting_node)
    if steps is not None:
        out["graph"] = run.graph
        out["trigger"] = ctx.get("trigger")
        out["steps"] = [{
            "id": str(s.id), "node_id": s.node_id, "node_type": s.node_type, "status": s.status,
            "output_name": s.output_name, "input": s.input, "output": s.output, "error": s.error,
            "attempts": s.attempts, "duration_ms": s.duration_ms,
            "started_at": s.started_at.isoformat() if s.started_at else None,
        } for s in steps]
    return out


# ─── Catalog / helpers for the editor ───────────────────────────────────────

@router.get("/catalog")
async def catalog(current_user: User = Depends(get_current_user)):
    return {
        "node_types": NODE_TYPES,
        "events": EVENTS,
        "operators": OPERATORS,
        "response_operations": RESPONSE_OPS,
        "case_operations": CASE_OPS,
        "alert_statuses": ALERT_STATUSES,
        "http_methods": HTTP_METHODS,
        "body_types": BODY_TYPES,
        "notify_channels": NOTIFY_CHANNELS,
        "trigger_fields": ["alert_id", "severity", "rule_title", "tags", "mitre_tags", "source_ip", "hostname",
                           "user_name", "group_id", "ai_verdict", "ai_confidence", "ti_risk_score", "event"],
    }


@router.post("/validate")
async def validate_graph(body: GraphIn, current_user: User = Depends(get_current_user)):
    try:
        return {"ok": True, "errors": [], "graph": validate(body.graph)}
    except GraphError as exc:
        return {"ok": False, "errors": exc.errors}


@router.post("/parse-curl")
async def parse_curl_command(body: CurlIn, current_user: User = Depends(get_current_user)):
    if len(body.command) > 20_000:
        raise HTTPException(status_code=413, detail="command too long")
    try:
        return parse_curl(body.command)
    except CurlParseError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


# ─── Playbooks ──────────────────────────────────────────────────────────────

@router.get("/playbooks")
async def list_playbooks(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_id: Optional[str] = Depends(get_scoped_group),
):
    q = select(SoarPlaybook).order_by(SoarPlaybook.created_at.desc())
    if group_id:
        q = q.where(SoarPlaybook.group_id == group_id)
    playbooks = (await db.execute(q)).scalars().all()
    return [_pb_out(pb, await _actions(db, pb)) for pb in playbooks]


@router.post("/playbooks", status_code=201)
async def create_playbook(
    body: PlaybookIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(Manage),
    group_id: Optional[str] = Depends(get_scoped_group),
):
    graph = _validated(body.graph) if body.graph is not None else None
    pb = SoarPlaybook(
        name=body.name,
        description=body.description,
        trigger_conditions=body.trigger_conditions,
        is_enabled=body.is_enabled,
        group_id=group_id or current_user.group_id or "default",
        graph=graph,
        trigger_event=trigger_event(graph) if graph else None,
    )
    db.add(pb)
    await db.commit()
    await db.refresh(pb)
    return _pb_out(pb, [])


@router.get("/playbooks/{playbook_id}")
async def get_playbook(
    playbook_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_filter: Optional[str] = Depends(get_scoped_group),
):
    pb = await fetch_scoped(db, SoarPlaybook, playbook_id, group_filter, detail="Playbook not found")
    return _pb_out(pb, await _actions(db, pb))


@router.put("/playbooks/{playbook_id}/graph")
async def save_graph(
    playbook_id: uuid.UUID,
    body: GraphIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(Manage),
    group_filter: Optional[str] = Depends(get_scoped_group),
):
    """Save the workflow graph. A legacy playbook becomes a workflow and loses its linear actions."""
    pb = await fetch_scoped(db, SoarPlaybook, playbook_id, group_filter, detail="Playbook not found")
    graph = _validated(body.graph)
    pb.graph = graph
    pb.trigger_event = trigger_event(graph)
    pb.trigger_conditions = {k: v for k, v in trigger_node(graph)["params"].items() if k in ("match", "conditions")}
    for a in await _actions(db, pb):
        await db.delete(a)
    await db.commit()
    await db.refresh(pb)
    return _pb_out(pb, [])


@router.patch("/playbooks/{playbook_id}")
async def update_playbook(
    playbook_id: uuid.UUID,
    body: PlaybookUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(Manage),
    group_filter: Optional[str] = Depends(get_scoped_group),
):
    pb = await fetch_scoped(db, SoarPlaybook, playbook_id, group_filter, detail="Playbook not found")
    changes = body.model_dump(exclude_unset=True)
    if "trigger_conditions" in changes and pb.graph is not None:
        raise HTTPException(status_code=409, detail="this playbook is a workflow; edit its Trigger node instead")
    for field, value in changes.items():
        setattr(pb, field, value)
    await db.commit()
    return {"ok": True}


@router.delete("/playbooks/{playbook_id}", status_code=204)
async def delete_playbook(
    playbook_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(Manage),
    group_filter: Optional[str] = Depends(get_scoped_group),
):
    pb = await fetch_scoped(db, SoarPlaybook, playbook_id, group_filter, detail="Playbook not found")
    await db.delete(pb)
    await db.commit()


# ─── Legacy linear actions (old editor; ignored once a playbook has a graph) ─

async def _legacy_playbook(db: AsyncSession, playbook_id, group_filter) -> SoarPlaybook:
    pb = await fetch_scoped(db, SoarPlaybook, playbook_id, group_filter, detail="Playbook not found")
    if pb.graph is not None:
        raise HTTPException(status_code=409, detail="this playbook is a workflow; edit it in the workflow editor")
    return pb


@router.post("/playbooks/{playbook_id}/actions", status_code=201)
async def add_action(
    playbook_id: uuid.UUID,
    body: ActionIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(Manage),
    group_filter: Optional[str] = Depends(get_scoped_group),
):
    pb = await _legacy_playbook(db, playbook_id, group_filter)
    action = SoarAction(playbook_id=pb.id, action_type=body.action_type,
                        order_index=body.order_index, params=body.params)
    db.add(action)
    await db.commit()
    await db.refresh(action)
    return {"id": str(action.id), "action_type": action.action_type,
            "order_index": action.order_index, "params": action.params}


@router.patch("/actions/{action_id}")
async def update_action(
    action_id: uuid.UUID,
    body: ActionUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(Manage),
    group_filter: Optional[str] = Depends(get_scoped_group),
):
    action = await db.get(SoarAction, action_id)
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    await _legacy_playbook(db, action.playbook_id, group_filter)
    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(action, field, value)
    await db.commit()
    return {"ok": True}


@router.delete("/actions/{action_id}", status_code=204)
async def delete_action(
    action_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(Manage),
    group_filter: Optional[str] = Depends(get_scoped_group),
):
    action = await db.get(SoarAction, action_id)
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    await _legacy_playbook(db, action.playbook_id, group_filter)
    await db.delete(action)
    await db.commit()


# ─── Runs ───────────────────────────────────────────────────────────────────

@router.post("/playbooks/{playbook_id}/run", status_code=202)
async def run_playbook(
    playbook_id: uuid.UUID,
    body: RunIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(Manage),
    group_filter: Optional[str] = Depends(get_scoped_group),
):
    """Run a playbook now, from an alert or a hand-written trigger. Trigger conditions are skipped."""
    pb = await fetch_scoped(db, SoarPlaybook, playbook_id, group_filter, detail="Playbook not found")
    graph = _validated(_graph_of(pb, await _actions(db, pb)))
    trigger = {k: v for k, v in body.trigger.items() if isinstance(k, str)}
    if body.alert_id:
        alert = await fetch_scoped(db, Alert, body.alert_id, group_filter, detail="Alert not found")
        trigger = {
            "alert_id": str(alert.id), "severity": alert.severity, "rule_title": alert.title,
            "source_ip": alert.source_ip, "hostname": alert.hostname,
            "mitre_tags": alert.mitre_techniques or [], "ai_verdict": alert.ai_verdict,
            "user_name": (alert.context or {}).get("user.name") if isinstance(alert.context, dict) else None,
            **trigger,
        }
    trigger.update({"event": "manual", "group_id": pb.group_id})
    run = SoarRun(playbook_id=pb.id, group_id=pb.group_id, status="queued", trigger_event="manual",
                  alert_id=body.alert_id, graph=graph, created_by=current_user.id,
                  context={"trigger": trigger, "steps": {}, "queue": [trigger_node(graph)["id"]], "done": []})
    db.add(run)
    await db.commit()
    await db.refresh(run)
    return _run_out(run)


@router.get("/playbooks/{playbook_id}/runs")
async def list_playbook_runs(
    playbook_id: uuid.UUID,
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_filter: Optional[str] = Depends(get_scoped_group),
):
    pb = await fetch_scoped(db, SoarPlaybook, playbook_id, group_filter, detail="Playbook not found")
    runs = (await db.execute(
        select(SoarRun).where(SoarRun.playbook_id == pb.id).order_by(SoarRun.created_at.desc()).limit(limit)
    )).scalars().all()
    return [_run_out(r) for r in runs]


@router.get("/runs")
async def list_runs(
    status: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_filter: Optional[str] = Depends(get_scoped_group),
):
    """Recent runs across playbooks; ?status=waiting lists pending approvals."""
    q = select(SoarRun).order_by(SoarRun.created_at.desc()).limit(limit)
    if status:
        q = q.where(SoarRun.status == status)
    if group_filter:
        q = q.where(SoarRun.group_id == group_filter)
    return [_run_out(r) for r in (await db.execute(q)).scalars().all()]


@router.get("/runs/{run_id}")
async def get_run(
    run_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_filter: Optional[str] = Depends(get_scoped_group),
):
    run = await fetch_scoped(db, SoarRun, run_id, group_filter, detail="Run not found")
    steps = (await db.execute(
        select(SoarRunStep).where(SoarRunStep.run_id == run.id).order_by(SoarRunStep.started_at)
    )).scalars().all()
    return _run_out(run, list(steps))


@router.post("/runs/{run_id}/decision")
async def decide(
    run_id: uuid.UUID,
    body: DecisionIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(Manage),
    group_filter: Optional[str] = Depends(get_scoped_group),
):
    """Approve or reject the Approval node a run is waiting on; the worker resumes it."""
    run = (await db.execute(
        select(SoarRun).where(SoarRun.id == run_id).with_for_update()
    )).scalar_one_or_none()
    if not run or (group_filter and run.group_id != group_filter):
        raise HTTPException(status_code=404, detail="Run not found")
    if run.status != "waiting" or not run.waiting_node:
        raise HTTPException(status_code=409, detail=f"run is {run.status}, not waiting for approval")
    run.context = {**(run.context or {}), "decision": {
        "node": run.waiting_node, "decision": body.decision, "comment": (body.comment or "")[:2000],
        "by": str(current_user.id), "by_name": getattr(current_user, "username", None),
        "at": datetime.now(timezone.utc).isoformat(),
    }}
    run.status = "resume"
    await db.commit()
    return {"ok": True, "status": "resume"}


@router.post("/runs/{run_id}/cancel")
async def cancel_run(
    run_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(Manage),
    group_filter: Optional[str] = Depends(get_scoped_group),
):
    run = await fetch_scoped(db, SoarRun, run_id, group_filter, detail="Run not found")
    if run.status in ("success", "failed", "cancelled"):
        raise HTTPException(status_code=409, detail=f"run already {run.status}")
    run.status = "cancelled"
    run.finished_at = datetime.now(timezone.utc)
    await db.commit()
    return {"ok": True}
