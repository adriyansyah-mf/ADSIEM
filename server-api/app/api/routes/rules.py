# server-api/app/api/routes/rules.py
from difflib import unified_diff
from typing import Annotated
from uuid import UUID

import httpx
import yaml
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_scoped_group, require_permission
from app.core.es_client import search as es_search
from app.core.outbound_url import (
    OutboundUrlRejected,
    PinnedAsyncHTTPTransport,
    ValidatedOutboundUrl,
    validate_outbound_url,
)
from app.core.rate_limit import rate_limit_by_user_group
from app.core.sigma import JsonValue, SigmaRuleError, evaluate_rule, validate_rule
from app.core.sigma_query import compile_sigma_query
from app.core.sigma_validator import validate_sigma_yaml
from app.models.models import Rule, RuleRevision, User
from app.schemas.schemas import (
    PaginatedResponse,
    RuleCreate,
    RuleOut,
    RuleTestRequest,
    RuleTestResponse,
    RuleUpdate,
)
from app.schemas.sigma import SigmaDiffResponse, SigmaHuntRequest, SigmaHuntResponse, SigmaImportRequest, SigmaImportResponse, SigmaQualityResponse, SigmaRepositoryImportRequest, SigmaRevisionOut
from app.services.audit import audit_log

router = APIRouter(prefix="/api/rules", tags=["rules"])
RateLimitRepositoryImport = rate_limit_by_user_group("repository_import")

REPOSITORY_ALLOWED_HOSTS = frozenset({"github.com", "gitlab.com", "raw.githubusercontent.com"})
MAX_REPOSITORY_RESPONSE_BYTES = 2_000_000


async def fetch_repository_content(validated_url: ValidatedOutboundUrl) -> str:
    timeout = httpx.Timeout(connect=5.0, read=15.0, write=15.0, pool=5.0)
    transport = PinnedAsyncHTTPTransport(validated_url)
    async with httpx.AsyncClient(
        transport=transport,
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
    ) as client:
        async with client.stream("GET", validated_url.url) as response:
            response.raise_for_status()
            content_length = response.headers.get("content-length")
            if content_length is not None and content_length.isdecimal() and int(content_length) > MAX_REPOSITORY_RESPONSE_BYTES:
                raise HTTPException(status_code=413, detail="Repository rule payload is too large")
            content = bytearray()
            async for chunk in response.aiter_bytes():
                content.extend(chunk)
                if len(content) > MAX_REPOSITORY_RESPONSE_BYTES:
                    raise HTTPException(status_code=413, detail="Repository rule payload is too large")
    return content.decode(response.encoding or "utf-8")


@router.get("", response_model=PaginatedResponse)
async def list_rules(
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(require_permission("logs:read")),
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
    page: int = 1,
    page_size: int = 25,
):
    q = select(Rule).order_by(Rule.created_at.desc())
    if group_filter is not None:
        q = q.where(Rule.group_id == group_filter)
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    result = await db.execute(q.offset((page - 1) * page_size).limit(page_size))
    return PaginatedResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=[RuleOut.model_validate(r) for r in result.scalars().all()],
    )


@router.post("", response_model=RuleOut, status_code=201)
async def create_rule(
    body: RuleCreate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("rules:create"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    _validate_rule_yaml(body.content)
    data = body.model_dump()
    if group_filter is not None:
        data["group_id"] = group_filter
    rule = Rule(**data)
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    db.add(RuleRevision(rule_id=rule.id, version=rule.version, content=rule.content, created_by=current_user.id))
    await db.commit()
    background.add_task(
        audit_log, db, current_user, "rule_created", "rule", str(rule.id)
    )
    return RuleOut.model_validate(rule)


@router.put("/{rule_id}", response_model=RuleOut)
async def update_rule(
    rule_id: UUID,
    body: RuleUpdate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("rules:update"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    query = select(Rule).where(Rule.id == rule_id)
    if group_filter is not None:
        query = query.where(Rule.group_id == group_filter)
    result = await db.execute(query)
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    updates = body.model_dump(exclude_none=True)
    if "content" in updates:
        _validate_rule_yaml(updates["content"])
        updates["version"] = rule.version + 1
    for field, value in updates.items():
        setattr(rule, field, value)
    await db.commit()
    await db.refresh(rule)
    if "content" in updates:
        db.add(RuleRevision(rule_id=rule.id, version=rule.version, content=rule.content, created_by=current_user.id))
        await db.commit()
    background.add_task(
        audit_log, db, current_user, "rule_updated", "rule", str(rule_id)
    )
    return RuleOut.model_validate(rule)


@router.delete("/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: UUID,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("rules:delete"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    query = select(Rule).where(Rule.id == rule_id)
    if group_filter is not None:
        query = query.where(Rule.group_id == group_filter)
    result = await db.execute(query)
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    await db.delete(rule)
    await db.commit()
    background.add_task(
        audit_log, db, current_user, "rule_deleted", "rule", str(rule_id)
    )


@router.post("/test", response_model=RuleTestResponse)
async def test_rule(
    body: RuleTestRequest, _=Depends(require_permission("rules:create"))
):
    try:
        rule_def = yaml.safe_load(body.content)
        if not isinstance(rule_def, dict):
            raise SigmaRuleError("rule must be a YAML mapping")
        rule_title = rule_def.get("title", "")
        if not isinstance(rule_title, str):
            raise SigmaRuleError("rule title must be a string")
        validate_sigma_yaml(body.content)
        matched = evaluate_rule(rule_def, body.sample_event)
        return RuleTestResponse(matched=matched, rule_title=rule_title)
    except (SigmaRuleError, yaml.YAMLError) as exc:
        return RuleTestResponse(matched=False, error=str(exc))


@router.post("/hunt", response_model=SigmaHuntResponse)
async def hunt_sigma(
    body: SigmaHuntRequest,
    current_user: Annotated[User, Depends(require_permission("logs:read"))],
):
    try:
        compiled = compile_sigma_query(body.content)
        query: dict[str, JsonValue] = {
            "bool": {
                "must": [
                    compiled.body,
                    {"term": {"group_id": current_user.group_id}},
                ]
            }
        }
        matches, total, next_cursor = await es_search(
            query, size=body.size, search_after=body.search_after
        )
    except SigmaRuleError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=503, detail="Elasticsearch unavailable"
        ) from exc
    return SigmaHuntResponse(
        lucene_query=compiled.lucene,
        matches=matches,
        total=total,
        next_cursor=next_cursor,
    )


@router.post("/import", response_model=SigmaImportResponse, status_code=201)
async def import_sigma_rules(
    body: SigmaImportRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("rules:create"))],
):
    imported: list[dict[str, JsonValue]] = []
    try:
        documents = list(yaml.safe_load_all(body.content))
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid YAML: {exc}") from exc
    for document in documents:
        if not isinstance(document, dict):
            raise HTTPException(status_code=422, detail="Each imported document must be a YAML mapping")
        raw_content = yaml.safe_dump(document, sort_keys=False)
        _validate_rule_yaml(raw_content)
        raw_tags = document.get("tags", [])
        tags = [tag for tag in raw_tags if isinstance(tag, str)] if isinstance(raw_tags, list) else []
        description = document.get("description")
        if not isinstance(description, str):
            description = None
        rule = Rule(
            title=str(document.get("title", "Untitled")),
            description=description,
            content=raw_content,
            level=str(document.get("level", "medium")),
            tags=tags,
            mitre_tags=[tag for tag in tags if isinstance(tag, str) and tag.startswith("attack.")],
            is_enabled=False,
            group_id=current_user.group_id,
        )
        db.add(rule)
        await db.flush()
        db.add(RuleRevision(rule_id=rule.id, version=rule.version, content=rule.content, created_by=current_user.id))
        imported.append({"id": str(rule.id), "title": rule.title, "version": rule.version})
    await db.commit()
    return SigmaImportResponse(imported=imported)


@router.post("/import/repository", response_model=SigmaImportResponse, status_code=201)
async def import_sigma_repository(
    body: SigmaRepositoryImportRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("rules:create"))],
    _rate_limit: Annotated[None, Depends(RateLimitRepositoryImport)],
):
    try:
        validated_url = await validate_outbound_url(
            body.url,
            allowed_hosts=REPOSITORY_ALLOWED_HOSTS,
        )
    except OutboundUrlRejected as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    try:
        content = await fetch_repository_content(validated_url)
    except (httpx.HTTPError, httpx.TimeoutException) as exc:
        raise HTTPException(status_code=502, detail="Unable to fetch repository rule") from exc
    return await import_sigma_rules(SigmaImportRequest(content=content), db, current_user)


@router.get("/{rule_id}/export", response_class=PlainTextResponse)
async def export_sigma_rule(
    rule_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
    _=Depends(require_permission("logs:read")),
):
    query = select(Rule).where(Rule.id == rule_id)
    if group_filter is not None:
        query = query.where(Rule.group_id == group_filter)
    rule = (await db.execute(query)).scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return PlainTextResponse(rule.content, media_type="application/yaml")


@router.get("/{rule_id}/quality", response_model=SigmaQualityResponse)
async def sigma_rule_quality(
    rule_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
    _=Depends(require_permission("logs:read")),
):
    query = select(Rule).where(Rule.id == rule_id)
    if group_filter is not None:
        query = query.where(Rule.group_id == group_filter)
    rule = (await db.execute(query)).scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    try:
        parsed = yaml.safe_load(rule.content)
        validate_sigma_yaml(rule.content)
        detection = parsed.get("detection") if isinstance(parsed, dict) else None
        checks = {
            "valid_sigma": True,
            "has_logsource": isinstance(parsed, dict) and bool(parsed.get("logsource")),
            "has_condition": isinstance(detection, dict) and bool(detection.get("condition")),
            "has_tags": bool(rule.tags),
            "has_description": bool(rule.description),
        }
    except (SigmaRuleError, yaml.YAMLError):
        checks = {"valid_sigma": False, "has_logsource": False, "has_condition": False, "has_tags": False, "has_description": False}
    score = round(sum(checks.values()) / len(checks) * 100)
    recommendation = "Ready for approval" if score >= 80 else "Add missing metadata or fix validation errors"
    return SigmaQualityResponse(rule_id=str(rule.id), score=score, checks=checks, recommendation=recommendation)


@router.post("/{rule_id}/approve", response_model=RuleOut)
async def approve_sigma_rule(
    rule_id: UUID,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("rules:update"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    query = select(Rule).where(Rule.id == rule_id)
    if group_filter is not None:
        query = query.where(Rule.group_id == group_filter)
    result = await db.execute(query)
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    _validate_rule_yaml(rule.content)
    rule.is_enabled = True
    await db.commit()
    await db.refresh(rule)
    background.add_task(audit_log, db, current_user, "rule_approved", "rule", str(rule.id))
    return RuleOut.model_validate(rule)


@router.get("/{rule_id}/revisions", response_model=list[SigmaRevisionOut])
async def list_sigma_revisions(
    rule_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
    _=Depends(require_permission("logs:read")),
):
    rule_query = select(Rule).where(Rule.id == rule_id)
    if group_filter is not None:
        rule_query = rule_query.where(Rule.group_id == group_filter)
    if not (await db.execute(rule_query)).scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Rule not found")
    revisions = (await db.execute(select(RuleRevision).where(RuleRevision.rule_id == rule_id).order_by(RuleRevision.version.desc()))).scalars().all()
    return [SigmaRevisionOut(id=str(item.id), version=item.version, content=item.content, created_by=str(item.created_by) if item.created_by else None, created_at=item.created_at.isoformat()) for item in revisions]


@router.get("/{rule_id}/diff", response_model=SigmaDiffResponse)
async def diff_sigma_revisions(
    rule_id: UUID,
    from_version: int,
    to_version: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
    _=Depends(require_permission("logs:read")),
):
    rule_query = select(Rule).where(Rule.id == rule_id)
    if group_filter is not None:
        rule_query = rule_query.where(Rule.group_id == group_filter)
    if not (await db.execute(rule_query)).scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Rule not found")
    revisions = (await db.execute(select(RuleRevision).where(RuleRevision.rule_id == rule_id, RuleRevision.version.in_([from_version, to_version])))).scalars().all()
    by_version = {item.version: item.content for item in revisions}
    if from_version not in by_version or to_version not in by_version:
        raise HTTPException(status_code=404, detail="Revision not found")
    diff = "".join(unified_diff(by_version[from_version].splitlines(True), by_version[to_version].splitlines(True), fromfile=f"v{from_version}", tofile=f"v{to_version}"))
    return SigmaDiffResponse(rule_id=str(rule_id), from_version=from_version, to_version=to_version, diff=diff)


@router.post("/{rule_id}/rollback/{version}", response_model=RuleOut)
async def rollback_sigma_rule(
    rule_id: UUID,
    version: int,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("rules:update"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    rule_query = select(Rule).where(Rule.id == rule_id)
    if group_filter is not None:
        rule_query = rule_query.where(Rule.group_id == group_filter)
    rule = (await db.execute(rule_query)).scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule or revision not found")
    revision = (await db.execute(select(RuleRevision).where(RuleRevision.rule_id == rule.id, RuleRevision.version == version))).scalar_one_or_none()
    if not revision:
        raise HTTPException(status_code=404, detail="Rule or revision not found")
    _validate_rule_yaml(revision.content)
    rule.content = revision.content
    rule.version += 1
    db.add(RuleRevision(rule_id=rule.id, version=rule.version, content=rule.content, created_by=current_user.id))
    await db.commit()
    await db.refresh(rule)
    background.add_task(audit_log, db, current_user, "rule_rolled_back", "rule", str(rule.id), {"source_version": version, "new_version": rule.version})
    return RuleOut.model_validate(rule)


def _validate_rule_yaml(content: str) -> None:
    try:
        parsed = yaml.safe_load(content)
        if not isinstance(parsed, dict):
            raise SigmaRuleError("rule must be a YAML mapping")
        validate_sigma_yaml(content)
        validate_rule(parsed)
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid YAML: {exc}") from exc
    except SigmaRuleError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
