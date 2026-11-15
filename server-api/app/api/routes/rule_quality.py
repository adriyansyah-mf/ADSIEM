"""Rule quality: which rules make noise, which ones analysts keep closing as
false positives, how much their suppressions hide, and a per-rule level
override that the worker applies on its next rule reload."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import fetch_scoped, get_scoped_group, require_permission
from app.models.models import Alert, AlertSuppression, Rule, User
from app.services.audit import audit_log

router = APIRouter(prefix="/api/rule-quality", tags=["rule-quality"])

LEVELS = ("informational", "low", "medium", "high", "critical")
CLOSED = ("resolved", "closed")
# advice thresholds
NOISY_PER_DAY = 50
MOSTLY_FP = 0.8
MIN_TRIAGED = 5
IGNORED_SHARE = 0.9
MIN_IGNORED = 20


class RuleQualityItem(BaseModel):
    rule_id: UUID
    title: str
    level: str
    level_override: Optional[str] = None
    is_enabled: bool
    source: str
    alerts: int
    alerts_per_day: float
    duplicates: int
    false_positives: int
    resolved: int
    untriaged: int
    fp_rate: Optional[float] = None  # false positives / triaged; None until something is triaged
    last_alert_at: Optional[datetime] = None
    suppressed_hits: int = 0
    advice: list[str] = []


class RuleQualityOut(BaseModel):
    days: int
    rules_enabled: int
    rules_alerting: int
    alerts: int
    false_positives: int
    items: list[RuleQualityItem]


class LevelOverrideIn(BaseModel):
    level_override: Optional[str] = None


class LevelOverrideOut(BaseModel):
    rule_id: UUID
    level: str
    level_override: Optional[str] = None


def advise(item: RuleQualityItem) -> list[str]:
    out = []
    triaged = item.false_positives + item.resolved
    if item.fp_rate is not None and triaged >= MIN_TRIAGED and item.fp_rate >= MOSTLY_FP:
        out.append(f"{round(item.fp_rate * 100)}% of triaged alerts were false positives: "
                   "tune the rule or suppress the entity that trips it")
    if item.alerts_per_day >= NOISY_PER_DAY:
        out.append(f"{item.alerts_per_day:g} alerts a day: consider a lower level or a threshold")
    if item.alerts >= MIN_IGNORED and item.untriaged / item.alerts >= IGNORED_SHARE:
        out.append("Almost nobody triages these alerts: lower the level or disable the rule")
    return out


@router.get("", response_model=RuleQualityOut)
async def rule_quality(
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(require_permission("logs:read")),
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
    days: int = Query(30, ge=1, le=365),
    limit: int = Query(200, ge=1, le=1000),
):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    stmt = (select(Alert.rule_id, func.count(),
                   func.sum(case((Alert.status == "false_positive", 1), else_=0)),
                   func.sum(case((Alert.status.in_(CLOSED), 1), else_=0)),
                   func.coalesce(func.sum(Alert.duplicate_count), 0),
                   func.max(Alert.created_at))
            .where(Alert.created_at >= since, Alert.rule_id.is_not(None))
            .group_by(Alert.rule_id))
    if group_filter is not None:
        stmt = stmt.where(Alert.group_id == group_filter)
    counts = {row[0]: row[1:] for row in await db.execute(stmt)}

    rules = {}
    if counts:
        rules = {r.id: r for r in (await db.execute(select(Rule).where(Rule.id.in_(list(counts))))).scalars()}
    enabled_q = select(func.count()).select_from(Rule).where(Rule.is_enabled.is_(True))
    if group_filter is not None:
        enabled_q = enabled_q.where(Rule.group_id == group_filter)
    rules_enabled = (await db.execute(enabled_q)).scalar() or 0

    sup_q = select(AlertSuppression.entity_value, func.sum(AlertSuppression.hit_count)).where(
        AlertSuppression.entity_type == "rule_title", AlertSuppression.is_active.is_(True),
    ).group_by(AlertSuppression.entity_value)
    if group_filter is not None:
        sup_q = sup_q.where(AlertSuppression.group_id.in_((group_filter, "default")))
    suppressed = {title: int(n or 0) for title, n in await db.execute(sup_q)}

    items = []
    for rule_id, (total, fp, closed, dups, last) in counts.items():
        rule = rules.get(rule_id)
        if rule is None:
            continue
        fp, closed = int(fp or 0), int(closed or 0)
        item = RuleQualityItem(
            rule_id=rule.id, title=rule.title, level=rule.level, level_override=rule.level_override,
            is_enabled=rule.is_enabled, source=rule.source or "custom", alerts=total,
            alerts_per_day=round(total / days, 1), duplicates=int(dups or 0), false_positives=fp,
            resolved=closed, untriaged=total - fp - closed,
            fp_rate=round(fp / (fp + closed), 3) if fp + closed else None,
            last_alert_at=last, suppressed_hits=suppressed.get(rule.title, 0),
        )
        item.advice = advise(item)
        items.append(item)
    items.sort(key=lambda i: (len(i.advice), i.alerts + i.duplicates), reverse=True)
    return RuleQualityOut(days=days, rules_enabled=rules_enabled, rules_alerting=len(items),
                          alerts=sum(i.alerts for i in items),
                          false_positives=sum(i.false_positives for i in items), items=items[:limit])


@router.put("/{rule_id}/level", response_model=LevelOverrideOut)
async def set_level_override(
    rule_id: UUID,
    body: LevelOverrideIn,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission("rules:update"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    level = (body.level_override or "").strip().lower() or None
    if level is not None and level not in LEVELS:
        raise HTTPException(422, f"level_override must be one of: {', '.join(LEVELS)}, or null")
    rule = await fetch_scoped(db, Rule, rule_id, group_filter, detail="Rule not found")
    before = rule.level_override
    rule.level_override = None if level == rule.level else level
    await db.commit()
    background.add_task(audit_log, db, user.id, "rule_level_override", "rule", str(rule_id),
                        {"from": before, "to": rule.level_override, "rule_level": rule.level})
    return LevelOverrideOut(rule_id=rule.id, level=rule.level, level_override=rule.level_override)
