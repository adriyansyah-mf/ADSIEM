# server-api/app/api/routes/yara_drafts.py
"""Malware candidates of an AI investigation and the YARA drafts analysts ask
for (services/yara_drafting.py). Drafts are saved as disabled rules only."""
from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group, require_permission
from app.models.models import (
    CaseInvestigation, InvestigationEvidence, InvestigationHypothesis, User, YaraDraft, YaraRule,
)
from app.services import investigation_ledger as ledger
from app.services import yara_drafting as drafting
from app.services.audit import audit_log

router = APIRouter(tags=["yara-drafts"])

OPEN = ("collecting", "drafting", "draft")


class DraftOut(BaseModel):
    id: UUID
    investigation_id: UUID
    case_id: UUID
    host: str | None
    path: str | None
    sha256: str
    status: str
    flow_id: UUID | None
    features: dict[str, Any] | None
    support: list[dict[str, Any]]
    rule_name: str | None
    rule_text: str | None
    rationale: list[dict[str, Any]]
    limitations: list[str]
    false_positives: list[str]
    quality: dict[str, Any]
    confidence: int | None
    mitre: list[str]
    tags: list[str]
    error: str | None
    yara_rule_id: UUID | None
    created_at: datetime
    updated_at: datetime | None
    model_config = {"from_attributes": True}


class DraftRequest(BaseModel):
    sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")


class DraftEdit(BaseModel):
    rule_text: str = Field(min_length=10, max_length=100_000)


def _can_run_live_response(user: User) -> bool:
    return user.role.name == "superadmin" or "agents:manage" in {p.name for p in user.role.permissions}


async def _investigation(db, inv_id: UUID, group_filter: str | None, case_id: UUID | None = None) -> CaseInvestigation:
    inv = await db.get(CaseInvestigation, inv_id)
    if inv is None or (group_filter is not None and inv.group_id != group_filter) \
            or (case_id is not None and inv.case_id != case_id):
        raise HTTPException(404, "Investigation not found")
    return inv


async def _draft(db, draft_id: UUID, group_filter: str | None) -> YaraDraft:
    d = await db.get(YaraDraft, draft_id)
    if d is None or (group_filter is not None and d.group_id != group_filter):
        raise HTTPException(404, "Draft not found")
    return d


async def _candidates(db, inv: CaseInvestigation) -> list[dict]:
    evidence = (await db.execute(select(InvestigationEvidence).where(
        InvestigationEvidence.investigation_id == inv.id))).scalars().all()
    hypotheses = (await db.execute(select(InvestigationHypothesis).where(
        InvestigationHypothesis.investigation_id == inv.id))).scalars().all()
    return ledger.malware_candidates(list(evidence), list(hypotheses))


@router.get("/api/cases/{case_id}/investigations/{inv_id}/malware-candidates")
async def malware_candidates(
    case_id: UUID, inv_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    """Files the investigation observed, which of them a draft may be asked for, and the drafts so far."""
    inv = await _investigation(db, inv_id, group_filter, case_id)
    await drafting.expire_stale(db, inv.id)
    await db.commit()
    mode, mode_note = await drafting.generation_mode(db)
    drafts = (await db.execute(select(YaraDraft).where(YaraDraft.investigation_id == inv.id)
                               .order_by(YaraDraft.created_at.desc()))).scalars().all()
    latest = {}
    for d in drafts:
        latest.setdefault(d.sha256, d)
    out = []
    for c in await _candidates(db, inv):
        d = latest.get(c["sha256"])
        out.append({**c, "draft_id": str(d.id) if d else None, "draft_status": d.status if d else None})
    return {"mode": mode, "mode_note": mode_note, "candidates": out}


@router.post("/api/investigations/{inv_id}/yara-drafts", response_model=DraftOut, status_code=202)
async def request_draft(
    inv_id: UUID, body: DraftRequest, background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission("cases:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    """Describe the file on its host (live response) and draft a disabled YARA rule from its features."""
    if not _can_run_live_response(user):
        raise HTTPException(403, "Collecting file features is live response: it needs the agents:manage permission")
    inv = await _investigation(db, inv_id, group_filter)
    mode, _ = await drafting.generation_mode(db)
    if mode == "off":
        raise HTTPException(409, "AI YARA drafting is turned off (Settings → yara_ai_generation)")
    sha = body.sha256.lower()
    candidate = next((c for c in await _candidates(db, inv) if c["sha256"] == sha), None)
    if candidate is None:
        raise HTTPException(404, "This investigation did not observe a file with that SHA-256 on a host")
    if not candidate["eligible"]:
        raise HTTPException(409, "Nothing in the evidence supports a malware hypothesis about this file yet "
                                 "(reputation match, YARA match, alert or event naming it, a supported hypothesis, "
                                 "or pin its evidence); a bare hash is not enough")
    busy = (await db.execute(select(YaraDraft.id).where(
        YaraDraft.investigation_id == inv.id, YaraDraft.sha256 == sha, YaraDraft.status.in_(OPEN)))).first()
    if busy:
        raise HTTPException(409, "A draft for this file already exists in this investigation")
    draft = YaraDraft(group_id=inv.group_id, investigation_id=inv.id, case_id=inv.case_id,
                      evidence_id=UUID(candidate["evidence_id"]), host=candidate["host"], path=candidate["path"],
                      sha256=sha, status="collecting", support=candidate["support"], created_by=user.id,
                      rationale=[], limitations=[], false_positives=[], quality={}, mitre=[], tags=[])
    db.add(draft)
    await db.commit()
    await db.refresh(draft)
    drafting.spawn(draft.id, f"AI draft requested by {user.username}")
    background.add_task(audit_log, db, user.id, "yara_draft_requested", "case", str(inv.case_id),
                        {"investigation": str(inv.id), "draft": str(draft.id), "sha256": sha, "host": draft.host})
    return draft


@router.post("/api/investigations/{inv_id}/malware-candidates/dismiss", status_code=204)
async def dismiss_candidate(
    inv_id: UUID, body: DraftRequest, background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission("cases:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    inv = await _investigation(db, inv_id, group_filter)
    sha = body.sha256.lower()
    candidate = next((c for c in await _candidates(db, inv) if c["sha256"] == sha), None)
    if candidate is None:
        raise HTTPException(404, "This investigation did not observe a file with that SHA-256 on a host")
    db.add(YaraDraft(group_id=inv.group_id, investigation_id=inv.id, case_id=inv.case_id, host=candidate["host"],
                     path=candidate["path"], sha256=sha, status="dismissed", support=candidate["support"],
                     created_by=user.id, rationale=[], limitations=[], false_positives=[], quality={}, mitre=[],
                     tags=[]))
    await db.commit()
    background.add_task(audit_log, db, user.id, "malware_candidate_dismissed", "case", str(inv.case_id),
                        {"investigation": str(inv.id), "sha256": sha})


@router.get("/api/investigations/{inv_id}/yara-drafts", response_model=list[DraftOut])
async def list_drafts(
    inv_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    inv = await _investigation(db, inv_id, group_filter)
    return (await db.execute(select(YaraDraft).where(YaraDraft.investigation_id == inv.id, YaraDraft.status != "dismissed")
                             .order_by(YaraDraft.created_at.desc()))).scalars().all()


@router.get("/api/yara-drafts/{draft_id}", response_model=DraftOut)
async def get_draft(
    draft_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    return await _draft(db, draft_id, group_filter)


@router.put("/api/yara-drafts/{draft_id}", response_model=DraftOut)
async def edit_draft(
    draft_id: UUID, body: DraftEdit, background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission("cases:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    """An analyst's edit; quality is checked again on the new text."""
    d = await _draft(db, draft_id, group_filter)
    if d.status != "draft" or d.yara_rule_id is not None:
        raise HTTPException(409, f"Only an unsaved draft can be edited; this one is {d.status}")
    d.rule_text = body.rule_text
    names = drafting.parse_rule(body.rule_text)["names"]
    d.rule_name = names[0][:128] if names else d.rule_name
    d.quality = drafting.quality(body.rule_text)
    await db.commit()
    await db.refresh(d)
    background.add_task(audit_log, db, user.id, "yara_draft_edited", "case", str(d.case_id), {"draft": str(d.id)})
    return d


@router.post("/api/yara-drafts/{draft_id}/save", response_model=DraftOut)
async def save_draft_as_rule(
    draft_id: UUID, background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission("rules:update"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    """Add the draft to the YARA rules, disabled. It cannot be enabled until validation and test
    scans exist for AI drafts (Phase 4); routes/yara_rules.py enforces that."""
    d = await _draft(db, draft_id, group_filter)
    if d.status != "draft" or not d.rule_text:
        raise HTTPException(409, f"Only a finished draft can be saved; this one is {d.status}")
    if d.yara_rule_id is not None:
        raise HTTPException(409, "This draft is already saved as a rule")
    q = drafting.quality(d.rule_text)
    if q["blocking"]:
        raise HTTPException(422, {"message": "fix the blocking quality problems first", "problems": q["blocking"]})
    name = drafting.parse_rule(d.rule_text)["names"][0]
    if (await db.execute(select(YaraRule.id).where(YaraRule.name == name))).first():
        raise HTTPException(409, f"A YARA rule named {name} already exists; rename the draft")
    rule = YaraRule(name=name, content=d.rule_text, is_enabled=False, origin="ai_draft", draft_id=d.id,
                    description=f"AI draft from case {d.case_id}, sample {d.sha256} on {d.host}. Disabled until "
                                "validated and tested.")
    db.add(rule)
    await db.flush()
    d.yara_rule_id, d.quality = rule.id, q
    await db.commit()
    await db.refresh(d)
    background.add_task(audit_log, db, user.id, "yara_draft_saved", "yara_rule", str(rule.id),
                        {"draft": str(d.id), "case": str(d.case_id), "sha256": d.sha256, "enabled": False})
    return d
