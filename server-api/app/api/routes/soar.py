from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Literal, Optional
import uuid

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group
from app.models.models import SoarAction, SoarPlaybook, User

router = APIRouter(prefix="/api/soar", tags=["soar"])


class PlaybookIn(BaseModel):
    name: str
    description: Optional[str] = None
    trigger_conditions: dict = {}
    is_enabled: bool = True


class PlaybookUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    trigger_conditions: Optional[dict] = None
    is_enabled: Optional[bool] = None


ACTION_TYPES = Literal['enrich_ioc', 'send_webhook', 'create_case', 'suppress_alert', 'add_note', 'isolate_agent', 'block_ip']

class ActionIn(BaseModel):
    action_type: ACTION_TYPES
    order_index: int = 0
    params: dict = {}


class ActionUpdate(BaseModel):
    action_type: Optional[str] = None
    order_index: Optional[int] = None
    params: Optional[dict] = None


def _pb_out(pb: SoarPlaybook, actions: list[SoarAction]) -> dict:
    return {
        "id": str(pb.id),
        "name": pb.name,
        "description": pb.description,
        "trigger_conditions": pb.trigger_conditions,
        "is_enabled": pb.is_enabled,
        "group_id": pb.group_id,
        "created_at": pb.created_at.isoformat() if pb.created_at else None,
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
    result = []
    for pb in playbooks:
        actions = (await db.execute(
            select(SoarAction).where(SoarAction.playbook_id == pb.id)
        )).scalars().all()
        result.append(_pb_out(pb, list(actions)))
    return result


@router.post("/playbooks", status_code=201)
async def create_playbook(
    body: PlaybookIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_id: Optional[str] = Depends(get_scoped_group),
):
    pb = SoarPlaybook(
        name=body.name,
        description=body.description,
        trigger_conditions=body.trigger_conditions,
        is_enabled=body.is_enabled,
        group_id=group_id or current_user.group_id or "default",
    )
    db.add(pb)
    await db.commit()
    await db.refresh(pb)
    return _pb_out(pb, [])


@router.get("/playbooks/{playbook_id}")
async def get_playbook(
    playbook_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_filter: Optional[str] = Depends(get_scoped_group),
):
    pb = await db.get(SoarPlaybook, uuid.UUID(playbook_id))
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    if group_filter and pb.group_id != group_filter:
        raise HTTPException(status_code=403, detail="Forbidden")
    actions = (await db.execute(
        select(SoarAction).where(SoarAction.playbook_id == pb.id)
    )).scalars().all()
    return _pb_out(pb, list(actions))


@router.patch("/playbooks/{playbook_id}")
async def update_playbook(
    playbook_id: str,
    body: PlaybookUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_filter: Optional[str] = Depends(get_scoped_group),
):
    pb = await db.get(SoarPlaybook, uuid.UUID(playbook_id))
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    if group_filter and pb.group_id != group_filter:
        raise HTTPException(status_code=403, detail="Forbidden")
    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(pb, field, value)
    await db.commit()
    return {"ok": True}


@router.delete("/playbooks/{playbook_id}", status_code=204)
async def delete_playbook(
    playbook_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_filter: Optional[str] = Depends(get_scoped_group),
):
    pb = await db.get(SoarPlaybook, uuid.UUID(playbook_id))
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    if group_filter and pb.group_id != group_filter:
        raise HTTPException(status_code=403, detail="Forbidden")
    await db.delete(pb)
    await db.commit()


@router.post("/playbooks/{playbook_id}/actions", status_code=201)
async def add_action(
    playbook_id: str,
    body: ActionIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_filter: Optional[str] = Depends(get_scoped_group),
):
    pb = await db.get(SoarPlaybook, uuid.UUID(playbook_id))
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    if group_filter and pb.group_id != group_filter:
        raise HTTPException(status_code=403, detail="Forbidden")
    action = SoarAction(
        playbook_id=pb.id,
        action_type=body.action_type,
        order_index=body.order_index,
        params=body.params,
    )
    db.add(action)
    await db.commit()
    await db.refresh(action)
    return {"id": str(action.id), "action_type": action.action_type,
            "order_index": action.order_index, "params": action.params}


@router.patch("/actions/{action_id}")
async def update_action(
    action_id: str,
    body: ActionUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_filter: Optional[str] = Depends(get_scoped_group),
):
    action = await db.get(SoarAction, uuid.UUID(action_id))
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    if group_filter:
        pb = await db.get(SoarPlaybook, action.playbook_id)
        if not pb or pb.group_id != group_filter:
            raise HTTPException(status_code=403, detail="Forbidden")
    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(action, field, value)
    await db.commit()
    return {"ok": True}


@router.delete("/actions/{action_id}", status_code=204)
async def delete_action(
    action_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_filter: Optional[str] = Depends(get_scoped_group),
):
    action = await db.get(SoarAction, uuid.UUID(action_id))
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    if group_filter:
        pb = await db.get(SoarPlaybook, action.playbook_id)
        if not pb or pb.group_id != group_filter:
            raise HTTPException(status_code=403, detail="Forbidden")
    await db.delete(action)
    await db.commit()
