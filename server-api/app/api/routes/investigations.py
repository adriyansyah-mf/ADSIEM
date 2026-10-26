# server-api/app/api/routes/investigations.py
"""AI case investigations (services/investigator.py): start one from a case, follow its steps, cancel it,
and work its ledger (services/investigation_ledger.py) while it runs: queue, evidence, hypotheses."""
from datetime import datetime, timezone
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import desc, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import fetch_scoped, get_current_user, get_scoped_group, require_permission
from app.models.models import (
    Case, CaseInvestigation, InvestigationAction, InvestigationCommand, InvestigationEvidence,
    InvestigationHypothesis, User,
)
from app.services import investigation_ledger as ledger
from app.services import investigator
from app.services.audit import audit_log

router = APIRouter(tags=["investigations"])


class CommandOut(BaseModel):
    id: UUID
    hostname: str | None = None
    command: str
    args: list[str] = []
    timeout: int
    reason: str | None = None
    status: str
    auto_approved: bool = False
    decided_at: datetime | None = None
    decision_note: str | None = None
    flow_id: UUID | None = None
    created_at: datetime
    model_config = {"from_attributes": True}


class CommandDecision(BaseModel):
    approve: bool
    note: str | None = Field(default=None, max_length=1000)


class InvestigationOut(BaseModel):
    id: UUID
    case_id: UUID
    status: str
    phase: str | None = None
    model: str | None = None
    verdict: str | None = None
    report: str | None = None
    report_json: dict[str, Any] | None = None
    budget_overrides: dict[str, Any] = {}
    error: str | None = None
    steps: list[dict[str, Any]] = []
    commands: list[CommandOut] = []
    created_at: datetime
    finished_at: datetime | None = None
    model_config = {"from_attributes": True}


class ActionOut(BaseModel):
    id: UUID
    ordinal: int
    kind: str
    tool: str
    target: str | None = None
    params: dict[str, Any] = {}
    reason: str | None = None
    risk_tier: int
    approval_reason: str | None = None
    status: str
    source: str
    dependencies: list[str] = []
    result_ref: dict[str, Any] = {}
    error: str | None = None
    attempts: int
    decision_note: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    model_config = {"from_attributes": True}


class ActionIn(BaseModel):
    tool: str = Field(max_length=60)
    host: str | None = Field(default=None, max_length=255)
    params: dict[str, Any] = {}
    reason: str = Field(default="", max_length=2000)
    dependencies: list[UUID] = Field(default=[], max_length=20)


class EvidenceOut(BaseModel):
    id: UUID
    action_id: UUID | None = None
    evidence_type: str
    source_type: str
    source_id: str | None = None
    title: str
    summary: str | None = None
    observed_at: datetime | None = None
    entities: dict[str, Any] = {}
    sensitivity: str
    pinned: bool
    created_at: datetime
    model_config = {"from_attributes": True}


class PinIn(BaseModel):
    pinned: bool = True


class HypothesisOut(BaseModel):
    id: UUID
    ordinal: int
    statement: str
    state: str
    confidence: int
    supporting_evidence_ids: list[str] = []
    contradicting_evidence_ids: list[str] = []
    open_questions: list[str] = []
    source: str
    history: list[dict[str, Any]] = []
    created_at: datetime
    updated_at: datetime | None = None
    model_config = {"from_attributes": True}


class HypothesisIn(BaseModel):
    statement: str = Field(min_length=1, max_length=1000)
    open_questions: list[str] = Field(default=[], max_length=10)


class HypothesisUpdate(BaseModel):
    state: str | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)
    supporting_evidence_ids: list[str] = []
    contradicting_evidence_ids: list[str] = []
    open_questions: list[str] | None = None
    reason: str = Field(default="", max_length=500)


class BudgetIn(BaseModel):
    flows: int = Field(gt=0, le=investigator.MAX_FLOWS)  # at most doubles the live-response budget


def _can_run_live_response(user: User) -> bool:
    return user.role.name == "superadmin" or "agents:manage" in {p.name for p in user.role.permissions}


@router.post("/api/cases/{case_id}/investigations", response_model=InvestigationOut, status_code=202)
async def start_investigation(
    case_id: UUID,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission("cases:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    # the AI runs live response on the case's hosts in this analyst's name
    if not _can_run_live_response(user):
        raise HTTPException(403, "Starting an AI investigation needs the agents:manage permission (live response)")
    case = await fetch_scoped(db, Case, case_id, group_filter, detail="Case not found")
    busy = (await db.execute(select(CaseInvestigation.id).where(
        CaseInvestigation.case_id == case.id, CaseInvestigation.status.in_(("queued", "running"))
    ))).first()
    if busy:
        raise HTTPException(409, "An investigation of this case is already running")
    from app.services.assistant import _graph_config
    api_key, model, _ = await _graph_config(db, case.group_id)
    model = await investigator.investigation_model(db, model)
    if not api_key:
        raise HTTPException(422, "No AI provider configured (Settings → AI: 9router API key)")

    inv = CaseInvestigation(case_id=case.id, group_id=case.group_id, started_by=user.id, model=model,
                            status="queued", steps=[])
    db.add(inv)
    await db.commit()
    await db.refresh(inv)
    investigator.spawn(inv.id)
    background.add_task(audit_log, db, user.id, "ai_investigation_started", "case", str(case.id),
                        {"investigation": str(inv.id)})
    return inv


@router.get("/api/cases/{case_id}/investigations", response_model=list[InvestigationOut])
async def list_investigations(
    case_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    await fetch_scoped(db, Case, case_id, group_filter, detail="Case not found")
    rows = (await db.execute(
        select(CaseInvestigation).where(CaseInvestigation.case_id == case_id)
        .order_by(desc(CaseInvestigation.created_at)).limit(20)
    )).scalars().all()
    return rows


async def _get(db, inv_id: UUID, group_filter: str | None) -> CaseInvestigation:
    inv = await db.get(CaseInvestigation, inv_id)
    if inv is None or (group_filter is not None and inv.group_id != group_filter):
        raise HTTPException(404, "Investigation not found")
    return inv


@router.get("/api/investigations/{inv_id}", response_model=InvestigationOut)
async def get_investigation(
    inv_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    return await _get(db, inv_id, group_filter)


@router.post("/api/investigations/{inv_id}/cancel", response_model=InvestigationOut)
async def cancel_investigation(
    inv_id: UUID,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission("cases:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    inv = await _get(db, inv_id, group_filter)
    if inv.status in ("queued", "running"):
        inv.cancel_requested = True  # the run stops at its next step (flows in flight finish on their own)
        await db.commit()
        await db.refresh(inv)
        background.add_task(audit_log, db, user.id, "ai_investigation_cancelled", "case", str(inv.case_id),
                            {"investigation": str(inv.id)})
    return inv


@router.post("/api/investigation-commands/{cmd_id}/decision", response_model=CommandOut)
async def decide_command(
    cmd_id: UUID,
    body: CommandDecision,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission("cases:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    """Approve or reject a command the AI asked to run. Approving runs it on the
    host as root / SYSTEM, so it needs live-response rights like starting one."""
    if not _can_run_live_response(user):
        raise HTTPException(403, "Deciding on AI commands needs the agents:manage permission (live response)")
    cmd = await db.get(InvestigationCommand, cmd_id)
    if cmd is None or (group_filter is not None and cmd.group_id != group_filter):
        raise HTTPException(404, "Command not found")
    status = "approved" if body.approve else "rejected"
    # only a pending command changes, so two analysts deciding at once can't both win
    done = await db.execute(
        update(InvestigationCommand)
        .where(InvestigationCommand.id == cmd_id, InvestigationCommand.status == "pending")
        .values(status=status, decided_by=user.id, decided_at=datetime.now(timezone.utc),
                decision_note=(body.note or "").strip() or None)
    )
    await db.commit()
    await db.refresh(cmd)
    if done.rowcount == 0:
        raise HTTPException(409, f"This command is already {cmd.status}")
    background.add_task(audit_log, db, user.id, f"ai_command_{status}", "agent", str(cmd.agent_id),
                        {"investigation": str(cmd.investigation_id), "command": cmd.command, "args": cmd.args,
                         "host": cmd.hostname})
    return cmd


# ─── Ledger: queue, evidence, hypotheses ─────────────────────────

async def _case_inv(db, case_id: UUID, inv_id: UUID, group_filter: str | None) -> CaseInvestigation:
    inv = await _get(db, inv_id, group_filter)
    if inv.case_id != case_id:
        raise HTTPException(404, "Investigation not found")
    return inv


async def _scoped(db, model, row_id: UUID, group_filter: str | None, what: str):
    row = await db.get(model, row_id)
    if row is None or (group_filter is not None and row.group_id != group_filter):
        raise HTTPException(404, f"{what} not found")
    return row


@router.get("/api/cases/{case_id}/investigations/{inv_id}/actions", response_model=list[ActionOut])
async def list_actions(
    case_id: UUID,
    inv_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    inv = await _case_inv(db, case_id, inv_id, group_filter)
    return (await db.execute(select(InvestigationAction).where(InvestigationAction.investigation_id == inv.id)
                             .order_by(InvestigationAction.ordinal))).scalars().all()


@router.post("/api/cases/{case_id}/investigations/{inv_id}/actions", response_model=ActionOut, status_code=201)
async def add_action(
    case_id: UUID,
    inv_id: UUID,
    body: ActionIn,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission("cases:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    """Queue an action on a running investigation. It runs at the next round,
    after its dependencies, and counts against the run's budgets."""
    inv = await _case_inv(db, case_id, inv_id, group_filter)
    if inv.status not in ("queued", "running"):
        raise HTTPException(409, f"The investigation is {inv.status}; start a new one to collect more")
    if body.tool not in ledger.ANALYST_TOOLS:
        raise HTTPException(422, f"{body.tool} can't be queued; choose one of {sorted(ledger.ANALYST_TOOLS)}")
    params = dict(body.params)
    host = (body.host or "").strip() or None
    if body.tool == "run_artifact":
        if not _can_run_live_response(user):
            raise HTTPException(403, "Queuing live response needs the agents:manage permission")
        if not host or not str(params.get("artifact") or "").strip():
            raise HTTPException(422, "run_artifact needs a host and params.artifact")
    deps = [str(d) for d in body.dependencies]
    if deps:
        known = {str(i) for (i,) in (await db.execute(select(InvestigationAction.id).where(
            InvestigationAction.investigation_id == inv.id))).all()}
        if set(deps) - known:
            raise HTTPException(422, "dependencies must be actions of this investigation")
    key = ledger.idempotency_key(body.tool, host, params)
    if await ledger.find_action(db, inv.id, key) is not None:
        raise HTTPException(409, "This exact action is already in the queue or has run")
    row = InvestigationAction(
        investigation_id=inv.id, group_id=inv.group_id, ordinal=await ledger.next_ordinal(db, InvestigationAction, inv.id),
        kind=ledger.action_kind(body.tool), tool=body.tool, target=host, params=params, reason=body.reason.strip() or None,
        risk_tier=ledger.tool_tier(body.tool), status="queued", source="analyst", dependencies=deps,
        idempotency_key=key, result_ref={}, attempts=0, created_by=user.id,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    background.add_task(audit_log, db, user.id, "ai_investigation_action_added", "case", str(inv.case_id),
                        {"investigation": str(inv.id), "action": str(row.id), "tool": body.tool, "host": host})
    return row


@router.post("/api/investigation-actions/{action_id}/skip", response_model=ActionOut)
async def skip_action(
    action_id: UUID,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission("cases:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    """Skip a queued action or one awaiting approval; running and finished work stays as it is."""
    row = await _scoped(db, InvestigationAction, action_id, group_filter, "Action")
    at = datetime.now(timezone.utc)
    done = await db.execute(
        update(InvestigationAction)
        .where(InvestigationAction.id == action_id, InvestigationAction.status.in_(ledger.ACTION_OPEN))
        .values(status="skipped", decided_by=user.id, decided_at=at, decision_note="skipped by an analyst")
    )
    command_id = (row.result_ref or {}).get("command_id")
    if done.rowcount and command_id:  # a command waiting for approval: skipping it rejects it
        await db.execute(update(InvestigationCommand).where(
            InvestigationCommand.id == UUID(command_id), InvestigationCommand.status == "pending",
        ).values(status="rejected", decided_by=user.id, decided_at=at, decision_note="skipped by an analyst"))
    await db.commit()
    await db.refresh(row)
    if done.rowcount == 0:
        raise HTTPException(409, f"Only queued or approval-pending actions can be skipped; this one is {row.status}")
    background.add_task(audit_log, db, user.id, "ai_investigation_action_skipped", "case", None,
                        {"investigation": str(row.investigation_id), "action": str(row.id), "tool": row.tool})
    return row


@router.post("/api/investigation-actions/{action_id}/decision", response_model=ActionOut)
async def decide_action(
    action_id: UUID,
    body: CommandDecision,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission("cases:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    """Approve or reject an action the policy held (an unpromoted AI artifact, a
    host over its automatic budget). Commands use their own decision route."""
    if not _can_run_live_response(user):
        raise HTTPException(403, "Deciding on AI actions needs the agents:manage permission (live response)")
    row = await _scoped(db, InvestigationAction, action_id, group_filter, "Action")
    if row.kind == "command":
        raise HTTPException(409, "Decide on commands with /api/investigation-commands/{id}/decision")
    done = await db.execute(
        update(InvestigationAction)
        .where(InvestigationAction.id == action_id, InvestigationAction.status == "awaiting_approval")
        .values(status="queued" if body.approve else "skipped", decided_by=user.id,
                decided_at=datetime.now(timezone.utc), decision_note=(body.note or "").strip() or None)
    )
    await db.commit()
    await db.refresh(row)
    if done.rowcount == 0:
        raise HTTPException(409, f"This action is {row.status}, not awaiting approval")
    background.add_task(audit_log, db, user.id, f"ai_action_{'approved' if body.approve else 'rejected'}", "case", None,
                        {"investigation": str(row.investigation_id), "action": str(row.id), "tool": row.tool,
                         "host": row.target, "params": row.params})
    return row


@router.get("/api/cases/{case_id}/investigations/{inv_id}/evidence", response_model=list[EvidenceOut])
async def list_evidence(
    case_id: UUID,
    inv_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    inv = await _case_inv(db, case_id, inv_id, group_filter)
    return (await db.execute(select(InvestigationEvidence).where(InvestigationEvidence.investigation_id == inv.id)
                             .order_by(desc(InvestigationEvidence.pinned), InvestigationEvidence.created_at))).scalars().all()


@router.post("/api/investigation-evidence/{evidence_id}/pin", response_model=EvidenceOut)
async def pin_evidence(
    evidence_id: UUID,
    body: PinIn,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission("cases:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    row = await _scoped(db, InvestigationEvidence, evidence_id, group_filter, "Evidence")
    row.pinned = body.pinned
    await db.commit()
    await db.refresh(row)
    background.add_task(audit_log, db, user.id, "ai_evidence_pinned" if body.pinned else "ai_evidence_unpinned",
                        "case", None, {"investigation": str(row.investigation_id), "evidence": str(row.id)})
    return row


@router.get("/api/cases/{case_id}/investigations/{inv_id}/hypotheses", response_model=list[HypothesisOut])
async def list_hypotheses(
    case_id: UUID,
    inv_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    inv = await _case_inv(db, case_id, inv_id, group_filter)
    return (await db.execute(select(InvestigationHypothesis).where(InvestigationHypothesis.investigation_id == inv.id)
                             .order_by(InvestigationHypothesis.ordinal))).scalars().all()


@router.post("/api/cases/{case_id}/investigations/{inv_id}/hypotheses", response_model=HypothesisOut, status_code=201)
async def add_hypothesis(
    case_id: UUID,
    inv_id: UUID,
    body: HypothesisIn,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission("cases:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    """An analyst's hypothesis: the AI may link evidence to it, but only an analyst closes it."""
    inv = await _case_inv(db, case_id, inv_id, group_filter)
    h = await ledger.new_hypothesis(db, investigation_id=inv.id, group_id=inv.group_id, statement=body.statement,
                                    source="analyst")
    h.open_questions = [q.strip()[:300] for q in body.open_questions if q.strip()]
    h.history = [{"at": ledger.now().isoformat(), "actor": user.username, "state": "open", "confidence": 50,
                  "reason": "stated by an analyst"}]
    await db.commit()
    await db.refresh(h)
    background.add_task(audit_log, db, user.id, "ai_hypothesis_added", "case", str(inv.case_id),
                        {"investigation": str(inv.id), "hypothesis": str(h.id)})
    return h


@router.post("/api/investigation-hypotheses/{hypothesis_id}", response_model=HypothesisOut)
async def update_hypothesis(
    hypothesis_id: UUID,
    body: HypothesisUpdate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission("cases:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    h = await _scoped(db, InvestigationHypothesis, hypothesis_id, group_filter, "Hypothesis")
    index = await ledger.evidence_index(db, h.investigation_id)
    try:
        ledger.apply_hypothesis_update(
            h, actor=user.username, index=index, state=body.state, confidence=body.confidence,
            supporting=body.supporting_evidence_ids, contradicting=body.contradicting_evidence_ids,
            open_questions=body.open_questions, reason=body.reason)
    except ledger.HypothesisError as exc:
        raise HTTPException(422, str(exc))
    await db.commit()
    await db.refresh(h)
    background.add_task(audit_log, db, user.id, "ai_hypothesis_updated", "case", None,
                        {"investigation": str(h.investigation_id), "hypothesis": str(h.id), "state": h.state,
                         "confidence": h.confidence})
    return h


@router.post("/api/investigations/{inv_id}/budget", response_model=InvestigationOut)
async def raise_budget(
    inv_id: UUID,
    body: BudgetIn,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission("cases:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    """Grant a running investigation more live-response runs, once, at most doubling them."""
    if not _can_run_live_response(user):
        raise HTTPException(403, "Raising the live-response budget needs the agents:manage permission")
    inv = await _get(db, inv_id, group_filter)
    if inv.status not in ("queued", "running"):
        raise HTTPException(409, f"The investigation is {inv.status}")
    if (inv.budget_overrides or {}).get("flows"):
        raise HTTPException(409, "This investigation's budget was already raised once")
    inv.budget_overrides = {**(inv.budget_overrides or {}), "flows": body.flows,
                            "raised_by": user.username, "raised_at": datetime.now(timezone.utc).isoformat()}
    await db.commit()
    await db.refresh(inv)
    background.add_task(audit_log, db, user.id, "ai_investigation_budget_raised", "case", str(inv.case_id),
                        {"investigation": str(inv.id), "extra_flows": body.flows})
    return inv
