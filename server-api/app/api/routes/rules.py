# server-api/app/api/routes/rules.py
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel
from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_scoped_group, require_permission, fetch_scoped
from app.models.models import Rule, User
from app.schemas.schemas import (
    PaginatedResponse, RuleCreate, RuleListItem, RuleOut, RuleTestRequest, RuleTestResponse, RuleUpdate,
    SigmaHQImportRequest, SigmaHQImportResult,
)
from app.services import sigmahq
from app.services.audit import audit_log
from app.services.rule_content import (
    collected, compile_errors, content_hash, known_log_types, logsource_of, rule_metadata,
)

router = APIRouter(prefix="/api/rules", tags=["rules"])


def _filtered(q: str | None, source: str | None, enabled: bool | None, level: str | None,
              group_filter: str | None):
    stmt = select(Rule)
    if group_filter is not None:
        stmt = stmt.where(Rule.group_id == group_filter)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(Rule.title.ilike(like), Rule.external_id.ilike(like),
                              Rule.description.ilike(like), Rule.content.ilike(like)))
    if source:
        stmt = stmt.where(Rule.source == source)
    if enabled is not None:
        stmt = stmt.where(Rule.is_enabled == enabled)
    if level:
        stmt = stmt.where(Rule.level == level)
    return stmt


@router.get("", response_model=PaginatedResponse)
async def list_rules(
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(require_permission("logs:read")),
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
    page: int = 1, page_size: int = 25,
    q: str | None = None, source: str | None = None, enabled: bool | None = None, level: str | None = None,
):
    stmt = _filtered(q, source, enabled, level, group_filter)
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar()
    rows = (await db.execute(
        stmt.order_by(Rule.created_at.desc(), Rule.title).offset((page - 1) * page_size).limit(page_size)
    )).scalars().all()
    log_types = await known_log_types(db)
    items = []
    for r in rows:
        item = RuleListItem.model_validate(r)
        item.logsource = logsource_of(r.content)
        item.collected = collected(r.content, log_types)
        item.modified_locally = bool(r.upstream_hash) and content_hash(r.content) != r.upstream_hash
        items.append(item)
    return PaginatedResponse(total=total, page=page, page_size=page_size, items=items)


@router.get("/stats")
async def rule_stats(
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(require_permission("logs:read")),
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    stmt = select(Rule.source, Rule.is_enabled, func.count()).group_by(Rule.source, Rule.is_enabled)
    if group_filter is not None:
        stmt = stmt.where(Rule.group_id == group_filter)
    out: dict[str, dict[str, int]] = {}
    for source, enabled, n in await db.execute(stmt):
        bucket = out.setdefault(source or "custom", {"enabled": 0, "disabled": 0})
        bucket["enabled" if enabled else "disabled"] += n
    return out


@router.post("", response_model=RuleOut, status_code=201)
async def create_rule(
    body: RuleCreate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("rules:create"))],
):
    _validate_rule_yaml(body.content)
    # title/level/tags come from the YAML so the list matches what the engine runs
    rule = Rule(**{**body.model_dump(), **rule_metadata(body.content)})
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    background.add_task(audit_log, db, current_user.id, "rule_created", "rule", str(rule.id))
    return RuleOut.model_validate(rule)


class RuleBulkUpdate(BaseModel):
    is_enabled: bool
    ids: list[UUID] | None = None
    # or every rule matching these filters (same as the list endpoint)
    q: str | None = None
    source: str | None = None
    level: str | None = None


@router.post("/bulk")
async def bulk_update_rules(
    body: RuleBulkUpdate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("rules:update"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    if body.ids is None and not (body.q or body.source or body.level):
        raise HTTPException(status_code=422, detail="Give ids or at least one filter")
    ids_stmt = _filtered(body.q, body.source, None, body.level, group_filter).with_only_columns(Rule.id)
    if body.ids is not None:
        ids_stmt = ids_stmt.where(Rule.id.in_(body.ids))
    result = await db.execute(update(Rule).where(Rule.id.in_(ids_stmt)).values(is_enabled=body.is_enabled))
    await db.commit()
    background.add_task(audit_log, db, current_user.id, "rules_bulk_updated", "rule", None,
                        {"is_enabled": body.is_enabled, "count": result.rowcount, "source": body.source,
                         "level": body.level, "q": body.q})
    return {"updated": result.rowcount}


async def _run_import(db, contents, release, enable_levels, enable_statuses, background, user) -> SigmaHQImportResult:
    stats = await sigmahq.import_rules(db, contents, release, enable_levels, enable_statuses)
    background.add_task(audit_log, db, user.id, "sigmahq_imported", "rule", None,
                        {k: v for k, v in stats.__dict__.items() if k != "rejected_examples"})
    return SigmaHQImportResult(**stats.__dict__)


@router.post("/sigmahq/import", response_model=SigmaHQImportResult)
async def import_sigmahq(
    body: SigmaHQImportRequest,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("rules:create"))],
):
    """Download a SigmaHQ release package from GitHub and import (or update) its rules."""
    try:
        data, tag = await sigmahq.download(body.ruleset, body.release)
        contents = sigmahq.read_rules(data)
    except sigmahq.SigmaHQError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return await _run_import(db, contents, f"{tag} ({body.ruleset})", body.enable_levels,
                             body.enable_statuses, background, current_user)


@router.post("/sigmahq/upload", response_model=SigmaHQImportResult)
async def upload_sigmahq(
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("rules:create"))],
    file: UploadFile = File(...),
    enable_levels: str = Form("high,critical"),
    enable_statuses: str = Form("stable,test"),
):
    """Same as /sigmahq/import for servers without internet access: upload the release zip."""
    data = await file.read(sigmahq._MAX_DOWNLOAD + 1)
    if len(data) > sigmahq._MAX_DOWNLOAD:
        raise HTTPException(status_code=413, detail="archive exceeds 64 MB")
    try:
        contents = sigmahq.read_rules(data)
    except sigmahq.SigmaHQError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    split = lambda s: [x.strip() for x in s.split(",") if x.strip()]  # noqa: E731
    return await _run_import(db, contents, file.filename or "upload", split(enable_levels),
                             split(enable_statuses), background, current_user)


@router.put("/{rule_id}", response_model=RuleOut)
async def update_rule(
    rule_id: UUID, body: RuleUpdate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("rules:update"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    rule = await fetch_scoped(db, Rule, rule_id, group_filter, detail="Rule not found")
    updates = body.model_dump(exclude_none=True)
    if "content" in updates:
        _validate_rule_yaml(updates["content"])
        updates = {**updates, **rule_metadata(updates["content"])}
        updates["version"] = rule.version + 1
    for field, value in updates.items():
        setattr(rule, field, value)
    await db.commit()
    await db.refresh(rule)
    background.add_task(audit_log, db, current_user.id, "rule_updated", "rule", str(rule_id))
    return RuleOut.model_validate(rule)

@router.delete("/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: UUID,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("rules:delete"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    rule = await fetch_scoped(db, Rule, rule_id, group_filter, detail="Rule not found")
    await db.delete(rule)
    await db.commit()
    background.add_task(audit_log, db, current_user.id, "rule_deleted", "rule", str(rule_id))

@router.post("/test", response_model=RuleTestResponse)
async def test_rule(body: RuleTestRequest, _=Depends(require_permission("rules:create"))):
    """Evaluate the rule's detection against one sample event (flat decoded fields;
    add log_type and raw_message to also check the logsource and keywords)."""
    from worker.sigma_engine import SigmaEngine

    errors = compile_errors(body.content)
    if errors:
        return RuleTestResponse(matched=False, error="; ".join(errors))
    engine = SigmaEngine()
    engine.load_from_yaml_list([body.content])
    if not engine.rules:
        return RuleTestResponse(matched=False, error="no detection rule in content (correlation rules need events)")
    rule = engine.rules[0]
    candidates, view = engine.candidates(body.sample_event)
    applies = (rule in candidates) if body.sample_event.get("log_type") else None
    try:
        matched = bool(rule.matcher(view)) and applies is not False
    except Exception as exc:  # noqa: BLE001 — report, don't 500
        return RuleTestResponse(matched=False, rule_title=rule.title, error=str(exc))
    return RuleTestResponse(matched=matched, rule_title=rule.title, logsource_applies=applies)

def _validate_rule_yaml(content: str):
    errors = compile_errors(content)
    if errors:
        raise HTTPException(status_code=422, detail="; ".join(errors)[:2000])
