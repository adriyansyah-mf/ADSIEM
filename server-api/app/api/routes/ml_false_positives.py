# server-api/app/api/routes/ml_false_positives.py
"""Fleet-wide static ML false positives (models.MlFalsePositive).

An analyst marks a file the ML check flagged as clean (from its ml_detection
alert, or by hash); every agent gets it with its next policy fetch as a
sha256 exclusion with the ml scope (services/agent_policy.for_agent), so a
false positive is fixed in minutes instead of with a retrained model and an
agent release. Removing the entry puts the file back under the model.

Changing it changes every group's agents, so only a superadmin or a user of
the default group (who already sets the policy other groups fall back to)
may add or remove entries."""
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group, require_permission
from app.models.models import MlFalsePositive, User
from app.services import agent_policy
from app.services.audit import audit_log
from worker import malware_hashes as mh

router = APIRouter(prefix="/api/ml-false-positives", tags=["ml"])


def _out(r: MlFalsePositive) -> dict:
    return {"sha256": r.sha256, "engine": r.engine, "path": r.path, "comment": r.comment,
            "added_by": r.added_by, "added_at": r.added_at.isoformat() if r.added_at else None}


def _fleet_wide(scope: str | None) -> None:
    if scope is not None and scope != agent_policy.DEFAULT_GROUP:
        raise HTTPException(403, "ML false positives apply to every group: ask a superadmin or a default group admin")


@router.get("")
async def list_false_positives(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    rows = (await db.execute(select(MlFalsePositive).order_by(MlFalsePositive.added_at.desc()))).scalars().all()
    return {"items": [_out(r) for r in rows], "limit": agent_policy.MAX_ML_FALSE_POSITIVES}


class FalsePositiveIn(BaseModel):
    sha256: str
    engine: str = Field(default="", max_length=40)
    path: str = Field(default="", max_length=1024)
    comment: str = Field(default="", max_length=500)


@router.post("", status_code=201)
async def add_false_positive(
    body: FalsePositiveIn,
    db: Annotated[AsyncSession, Depends(get_db)],
    scope: Annotated[str | None, Depends(get_scoped_group)],
    user: Annotated[User, Depends(require_permission("agents:manage"))],
):
    _fleet_wide(scope)
    sha = mh.clean_sha256(body.sha256)
    if not sha:
        raise HTTPException(422, "sha256: 64 hex characters")
    row = await db.get(MlFalsePositive, sha)
    if row is None:
        count = (await db.execute(select(func.count()).select_from(MlFalsePositive))).scalar_one()
        if count >= agent_policy.MAX_ML_FALSE_POSITIVES:
            raise HTTPException(409, f"at most {agent_policy.MAX_ML_FALSE_POSITIVES} ML false positives: "
                                     "remove old ones, or exclude a folder in the group policy")
        row = MlFalsePositive(sha256=sha, engine=body.engine.strip(), path=body.path.strip(),
                              comment=body.comment.strip(),
                              added_by=getattr(user, "email", None) or user.username)
        db.add(row)
        await db.commit()
        agent_policy.invalidate()
        await audit_log(db, user.id, "ml_false_positive_added", "ml_false_positive", sha,
                        {"engine": row.engine, "path": row.path})
    return _out(row)


@router.delete("/{sha256}", status_code=204)
async def remove_false_positive(
    sha256: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    scope: Annotated[str | None, Depends(get_scoped_group)],
    user: Annotated[User, Depends(require_permission("agents:manage"))],
):
    _fleet_wide(scope)
    row = await db.get(MlFalsePositive, (sha256 or "").strip().lower())
    if row is None:
        raise HTTPException(404, "Not an ML false positive")
    await db.delete(row)
    await db.commit()
    agent_policy.invalidate()
    await audit_log(db, user.id, "ml_false_positive_removed", "ml_false_positive", row.sha256, {})
