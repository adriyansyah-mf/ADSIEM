# server-api/app/api/routes/web_protection.py
"""Web Protection (spec B1): agents sync the blocklist here; the dashboard
manages the blocklist, allowlist, policy and block page."""
from datetime import datetime
from typing import Annotated, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from pydantic import Field
from sqlalchemy import func, select, true
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_agent, get_scoped_group, require_permission
from app.models.models import Agent, User, WebAllowRule, WebBlockEntry, WebBlockPolicy
from app.services import web_blocks, web_page
from app.services.audit import audit_log
from worker.web_domains import DomainError, allow_match, normalize

agent_router = APIRouter(prefix="/api/ingest", tags=["ingest"])


class DeltaRequest(BaseModel):
    since: int = 0
    continuing: bool = False
    rules: int = 0


@agent_router.post("/web-blocklist")
async def agent_web_blocklist(
    body: DeltaRequest,
    agent: Annotated[Agent, Depends(get_agent)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    if not agent.approved:
        raise HTTPException(status_code=403, detail="agent not approved")
    out = await web_blocks.delta(db, agent.group_id or "default", max(body.since, 0), body.continuing,
                                  rules=body.rules)
    # the version the agent stores once it has every page; equals the heartbeat's when caught up
    version = str(out["seq"]) if out["policy"]["enabled"] and not out["more"] else ""
    return {**out, "version": version}


router = APIRouter(tags=["web-protection"])
Read = Depends(require_permission("alerts:read"))
Manage = Depends(require_permission("agents:manage"))


def _target_group(group_filter: Optional[str], requested: Optional[str]) -> str:
    """The group a change applies to: the caller's own, or any group for a superadmin."""
    if group_filter is not None:
        if requested and requested != group_filter:
            raise HTTPException(status_code=404, detail="Group not found")
        return group_filter
    return requested or "default"


async def _actor(db: AsyncSession, user: User) -> Optional[UUID]:
    """created_by is a foreign key to users; tolerate a caller without a users row (the audit log still names them)."""
    return user.id if await db.get(User, user.id) is not None else None


def _visible(group_filter: Optional[str], column):
    return true() if group_filter is None else column.in_((group_filter, web_blocks.FEED_GROUP))


def _block_out(r: WebBlockEntry) -> dict:
    return {"id": str(r.id), "domain": r.domain, "group_id": r.group_id, "source": r.source, "status": r.status,
            "reason": r.reason, "sample_url": r.sample_url, "alert_id": str(r.alert_id) if r.alert_id else None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "expires_at": r.expires_at.isoformat() if r.expires_at else None}


def _rule_out(r: WebAllowRule) -> dict:
    return {"id": str(r.id), "group_id": r.group_id, "domain": r.domain,
            "include_subdomains": r.include_subdomains, "builtin": r.builtin, "enabled": r.enabled}


class BlockIn(BaseModel):
    value: str = Field(..., max_length=2048)
    reason: str = Field("", max_length=500)
    expires_at: Optional[datetime] = None
    group_id: Optional[str] = None


@router.get("/api/web-blocks")
async def list_blocks(
    q: str = Query("", max_length=253), source: str = "", status: str = "active",
    limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db), _=Read, group: Optional[str] = Depends(get_scoped_group),
):
    query = select(WebBlockEntry).where(_visible(group, WebBlockEntry.group_id))
    if q.strip():
        query = query.where(WebBlockEntry.domain.ilike(f"%{q.strip().lower()}%"))
    if source:
        query = query.where(WebBlockEntry.source == source)
    if status:
        query = query.where(WebBlockEntry.status == status)
    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    rows = (await db.execute(query.order_by(WebBlockEntry.updated_at.desc()).offset(offset).limit(limit))).scalars().all()
    return {"total": total, "items": [_block_out(r) for r in rows]}


@router.post("/api/web-blocks", status_code=201)
async def add_block(body: BlockIn, db: AsyncSession = Depends(get_db), user: User = Manage,
                    group: Optional[str] = Depends(get_scoped_group)):
    target = _target_group(group, body.group_id)
    try:
        domain = normalize(body.value)
    except DomainError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    rule = allow_match(domain, await web_blocks.allow_rules(db, target))
    if rule:
        raise HTTPException(status_code=409, detail=f"{domain} is allowlisted ({rule})")
    row = (await db.execute(select(WebBlockEntry).where(
        WebBlockEntry.group_id == target, WebBlockEntry.domain == domain, WebBlockEntry.source == "manual"))).scalar_one_or_none()
    if row is None:
        row = WebBlockEntry(domain=domain, group_id=target, source="manual", created_by=await _actor(db, user))
        db.add(row)
    row.status, row.reason, row.expires_at, row.seq = "active", body.reason.strip(), body.expires_at, web_blocks.next_seq()
    await db.commit()
    await db.refresh(row)
    web_blocks.invalidate()
    await audit_log(db, user.id, "web_block.add", "web_block", str(row.id), {"domain": domain, "group_id": target})
    return _block_out(row)


@router.delete("/api/web-blocks/{entry_id}")
async def remove_block(entry_id: UUID, db: AsyncSession = Depends(get_db), user: User = Manage,
                       group: Optional[str] = Depends(get_scoped_group)):
    row = await db.get(WebBlockEntry, entry_id)
    if row is None or (group is not None and row.group_id not in (group, web_blocks.FEED_GROUP)):
        raise HTTPException(status_code=404, detail="Block not found")
    if row.group_id == web_blocks.FEED_GROUP and group is not None:
        # a feed entry is shared: allowlist it for this group so the next feed sync cannot re-block it
        exists = (await db.execute(select(WebAllowRule).where(
            WebAllowRule.group_id == group, WebAllowRule.domain == row.domain))).scalar_one_or_none()
        if exists is None:
            db.add(WebAllowRule(group_id=group, domain=row.domain, created_by=await _actor(db, user)))
        elif not exists.enabled:
            exists.enabled = True
        await web_blocks.mark_rules_changed(db)
        await db.commit()
        await audit_log(db, user.id, "web_block.allowlist_feed", "web_block", str(row.id), {"domain": row.domain, "group_id": group})
        return {"status": "allowlisted"}
    row.status, row.seq = "removed", web_blocks.next_seq()
    await db.commit()
    web_blocks.invalidate()
    await audit_log(db, user.id, "web_block.remove", "web_block", str(row.id), {"domain": row.domain})
    return {"status": "removed"}


class RuleIn(BaseModel):
    domain: str = Field(..., max_length=2048)
    include_subdomains: bool = False
    group_id: Optional[str] = None


class RulePatch(BaseModel):
    enabled: Optional[bool] = None
    include_subdomains: Optional[bool] = None


@router.get("/api/web-allowlist")
async def list_rules(db: AsyncSession = Depends(get_db), _=Read, group: Optional[str] = Depends(get_scoped_group)):
    rows = (await db.execute(select(WebAllowRule).where(_visible(group, WebAllowRule.group_id))
                             .order_by(WebAllowRule.builtin, WebAllowRule.domain))).scalars().all()
    return {"items": [_rule_out(r) for r in rows]}


@router.post("/api/web-allowlist", status_code=201)
async def add_rule(body: RuleIn, db: AsyncSession = Depends(get_db), user: User = Manage,
                   group: Optional[str] = Depends(get_scoped_group)):
    target = _target_group(group, body.group_id)
    try:
        domain = normalize(body.domain)
    except DomainError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    row = (await db.execute(select(WebAllowRule).where(
        WebAllowRule.group_id == target, WebAllowRule.domain == domain))).scalar_one_or_none()
    if row is None:
        row = WebAllowRule(group_id=target, domain=domain, created_by=await _actor(db, user))
        db.add(row)
    row.include_subdomains, row.enabled = body.include_subdomains, True
    await web_blocks.mark_rules_changed(db)
    await db.commit()
    await db.refresh(row)
    await audit_log(db, user.id, "web_allowlist.add", "web_allowlist", str(row.id), {"domain": domain, "group_id": target})
    return _rule_out(row)


async def _own_rule(db, rule_id: UUID, group: Optional[str]) -> WebAllowRule:
    row = await db.get(WebAllowRule, rule_id)
    if row is None or (group is not None and row.group_id not in (group, web_blocks.FEED_GROUP)):
        raise HTTPException(status_code=404, detail="Rule not found")
    if group is not None and row.group_id == web_blocks.FEED_GROUP:
        raise HTTPException(status_code=403, detail="Only a superadmin can change rules for every group")
    return row


@router.patch("/api/web-allowlist/{rule_id}")
async def update_rule(rule_id: UUID, body: RulePatch, db: AsyncSession = Depends(get_db), user: User = Manage,
                      group: Optional[str] = Depends(get_scoped_group)):
    row = await _own_rule(db, rule_id, group)
    if body.enabled is not None:
        row.enabled = body.enabled
    if body.include_subdomains is not None:
        row.include_subdomains = body.include_subdomains
    await web_blocks.mark_rules_changed(db)
    await db.commit()
    await audit_log(db, user.id, "web_allowlist.update", "web_allowlist", str(row.id), body.model_dump(exclude_none=True))
    return _rule_out(row)


@router.delete("/api/web-allowlist/{rule_id}")
async def delete_rule(rule_id: UUID, db: AsyncSession = Depends(get_db), user: User = Manage,
                      group: Optional[str] = Depends(get_scoped_group)):
    row = await _own_rule(db, rule_id, group)
    if row.builtin:
        raise HTTPException(status_code=409, detail="Built-in rules can be disabled, not deleted")
    await db.delete(row)
    await web_blocks.mark_rules_changed(db)
    await db.commit()
    await audit_log(db, user.id, "web_allowlist.delete", "web_allowlist", str(rule_id), {"domain": row.domain})
    return {"status": "deleted"}


class PolicyIn(BaseModel):
    enabled: bool
    feed_enabled: bool = False
    alert_enabled: bool = False
    alert_block_days: int = Field(30, ge=1, le=365)
    max_entries: int = Field(50000, ge=100, le=200000)
    page_html: Optional[str] = None
    contact: str = Field("", max_length=255)


class PreviewIn(BaseModel):
    page_html: Optional[str] = None


def _policy_group(group_filter: Optional[str], group_id: str) -> str:
    if group_filter is not None and group_id != group_filter:
        raise HTTPException(status_code=404, detail="Group not found")
    return group_id


@router.get("/api/web-block-policies/{group_id}")
async def get_policy(group_id: str, db: AsyncSession = Depends(get_db), _=Read,
                     group: Optional[str] = Depends(get_scoped_group)):
    target = _policy_group(group, group_id)
    policy = await web_blocks.policy_for(db, target)
    return {"group_id": target, **{k: v for k, v in policy.items() if k != "seq"}}


@router.put("/api/web-block-policies/{group_id}")
async def put_policy(group_id: str, body: PolicyIn, db: AsyncSession = Depends(get_db), user: User = Manage,
                     group: Optional[str] = Depends(get_scoped_group)):
    target = _policy_group(group, group_id)
    try:
        page = web_page.sanitize(body.page_html) if body.page_html is not None else None
    except web_page.PageError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    row = await db.get(WebBlockPolicy, target) or WebBlockPolicy(group_id=target)
    for key in ("enabled", "feed_enabled", "alert_enabled", "alert_block_days", "max_entries", "contact"):
        setattr(row, key, getattr(body, key))
    row.page_html, row.seq = page, web_blocks.next_seq()
    db.add(row)
    await db.commit()
    await db.refresh(row)  # seq was a SQL expression; policy_for reads it below
    web_blocks.invalidate()
    await audit_log(db, user.id, "web_block_policy.update", "web_block_policy", target,
                    body.model_dump(exclude={"page_html"}) | {"custom_page": page is not None})
    policy = await web_blocks.policy_for(db, target)
    return {"group_id": target, **{k: v for k, v in policy.items() if k != "seq"}}


@router.post("/api/web-block-policies/{group_id}/preview")
async def preview_page(group_id: str, body: PreviewIn, db: AsyncSession = Depends(get_db), _=Read,
                       group: Optional[str] = Depends(get_scoped_group)):
    target = _policy_group(group, group_id)
    policy = await web_blocks.policy_for(db, target)
    try:
        page = web_page.sanitize(body.page_html) if body.page_html is not None else policy["page_html"]
    except web_page.PageError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    values = {**web_page.SAMPLE, "contact": policy["contact"] or web_page.SAMPLE["contact"]}
    return {"html": web_page.document(page, values)}
