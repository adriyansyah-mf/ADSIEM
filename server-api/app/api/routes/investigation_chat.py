# server-api/app/api/routes/investigation_chat.py
"""Follow-up chat on an AI investigation that has ended (services/investigation_chat.py):
read the conversation and its proposed actions, send the next message."""
from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import fetch_scoped, get_scoped_group, require_permission
from app.models.models import CaseInvestigation, User
from app.services import investigation_chat as chat

router = APIRouter(tags=["investigations"])


class ChatMessageOut(BaseModel):
    id: UUID
    investigation_id: UUID
    role: str
    content: str
    author_id: UUID | None = None
    tool_calls: list[dict[str, Any]] = []
    created_at: datetime
    model_config = {"from_attributes": True}


class ChatActionOut(BaseModel):
    id: UUID
    investigation_id: UUID
    message_id: UUID | None = None
    tool: str
    target: str | None = None
    params: dict[str, Any] = {}
    reason: str | None = None
    status: str
    result: dict[str, Any] | None = None
    error: str | None = None
    requested_by: UUID | None = None
    decided_by: UUID | None = None
    decided_at: datetime | None = None
    executed_at: datetime | None = None
    created_at: datetime
    model_config = {"from_attributes": True}


class ChatOut(BaseModel):
    messages: list[ChatMessageOut]
    actions: list[ChatActionOut]


class ChatIn(BaseModel):
    message: str = Field(min_length=1, max_length=4000)


async def _investigation(db: AsyncSession, inv_id: UUID, group_filter: str | None) -> CaseInvestigation:
    return await fetch_scoped(db, CaseInvestigation, inv_id, group_filter, detail="Investigation not found")


@router.get("/api/investigations/{inv_id}/chat", response_model=ChatOut)
async def get_chat(
    inv_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_permission("alerts:read"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    inv = await _investigation(db, inv_id, group_filter)
    messages, actions = await chat.transcript(db, inv.id)
    return ChatOut(messages=messages, actions=actions)


@router.post("/api/investigations/{inv_id}/chat", response_model=ChatOut)
async def post_chat(
    inv_id: UUID,
    body: ChatIn,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission("cases:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    """One bounded AI turn, synchronously: returns the new messages and the actions it proposed."""
    inv = await _investigation(db, inv_id, group_filter)
    if inv.status in chat.ACTIVE:
        raise HTTPException(409, "The investigation is still running; chat opens when it ends")
    text = body.message.strip()
    if not text:
        raise HTTPException(422, "Empty message")
    try:
        messages, actions = await chat.run_turn(db, inv, user, text)
    except chat.ChatUnavailable as exc:
        raise HTTPException(422, str(exc)) from None
    except chat.ChatBusy as exc:
        raise HTTPException(409, str(exc)) from None
    except chat.ChatFailed as exc:
        raise HTTPException(502, str(exc)) from None
    return ChatOut(messages=messages, actions=actions)
