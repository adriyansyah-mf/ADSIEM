# server-api/app/api/routes/sla_policies.py
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_scoped_group, require_permission
from app.models.models import SlaPolicy, User
from app.services.audit import audit_log

router = APIRouter(prefix="/api/sla-policies", tags=["sla-policies"])
Perm = require_permission("settings:manage")

# Defaults mirror alerts.py's existing hardcoded _SLA_MINUTES, used as a
# tenant's effective policy until it sets its own override.
DEFAULT_WARN_MINUTES = {"critical": 10, "high": 45, "medium": 180, "low": 1080, "info": 2160}
DEFAULT_BREACH_MINUTES = {"critical": 15, "high": 60, "medium": 240, "low": 1440, "info": 2880}
SEVERITIES = ("critical", "high", "medium", "low", "info")


class SlaPolicyUpdate(BaseModel):
    warn_minutes: int = Field(gt=0)
    breach_minutes: int = Field(gt=0)


def _policy_out(severity: str, warn_minutes: int, breach_minutes: int, is_default: bool) -> dict:
    return {
        "severity": severity,
        "warn_minutes": warn_minutes,
        "breach_minutes": breach_minutes,
        "is_default": is_default,
    }


@router.get("")
async def list_sla_policies(
    db: Annotated[AsyncSession, Depends(get_db)],
    _current_user: Annotated[User, Depends(Perm)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
    group_id: str | None = Query(None, description="Superadmin only: which tenant's policies to view"),
):
    """Effective policy per severity for the caller's tenant: an override if
    one exists, else the platform default. A tenant-scoped caller always sees
    their own tenant (the group_id query param is ignored for them, matching
    the audit-logs/verify pattern); a superadmin may pass ?group_id= to view
    a specific tenant, and sees only defaults if it's omitted (there is no
    single "all tenants" override)."""
    target_group = group_filter if group_filter is not None else group_id
    overrides: dict[str, SlaPolicy] = {}
    if target_group is not None:
        rows = (
            await db.execute(select(SlaPolicy).where(SlaPolicy.group_id == target_group))
        ).scalars().all()
        overrides = {row.severity: row for row in rows}

    return [
        _policy_out(
            severity,
            overrides[severity].warn_minutes if severity in overrides else DEFAULT_WARN_MINUTES[severity],
            overrides[severity].breach_minutes if severity in overrides else DEFAULT_BREACH_MINUTES[severity],
            is_default=severity not in overrides,
        )
        for severity in SEVERITIES
    ]


@router.put("/{severity}")
async def upsert_sla_policy(
    severity: str,
    body: SlaPolicyUpdate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(Perm)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
    group_id: str | None = Query(None, description="Superadmin only: which tenant to set the override for"),
):
    if severity not in SEVERITIES:
        raise HTTPException(status_code=422, detail=f"severity must be one of {SEVERITIES}")
    if body.warn_minutes >= body.breach_minutes:
        raise HTTPException(status_code=422, detail="warn_minutes must be less than breach_minutes")

    target_group = group_filter if group_filter is not None else (group_id or current_user.group_id or "default")
    existing = (
        await db.execute(
            select(SlaPolicy).where(SlaPolicy.group_id == target_group, SlaPolicy.severity == severity)
        )
    ).scalar_one_or_none()
    if existing is None:
        policy = SlaPolicy(
            group_id=target_group, severity=severity,
            warn_minutes=body.warn_minutes, breach_minutes=body.breach_minutes,
        )
        db.add(policy)
    else:
        existing.warn_minutes = body.warn_minutes
        existing.breach_minutes = body.breach_minutes
    await db.commit()
    background.add_task(
        audit_log, db, current_user, "sla_policy_updated", "sla_policy", severity,
        {"warn_minutes": body.warn_minutes, "breach_minutes": body.breach_minutes},
    )
    return _policy_out(severity, body.warn_minutes, body.breach_minutes, is_default=False)
