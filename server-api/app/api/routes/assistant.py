# server-api/app/api/routes/assistant.py
from typing import Annotated
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_scoped_group, require_permission
from app.core.rate_limit import rate_limit_by_user_group
from app.schemas.schemas import AssistantChatRequest, AssistantChatResponse
from app.services.assistant import run_assistant_chat

router = APIRouter(prefix="/api/assistant", tags=["assistant"])
Perm = require_permission("alerts:read")
RateLimitAiChat = rate_limit_by_user_group("ai_chat")


@router.post("/chat", response_model=AssistantChatResponse)
async def assistant_chat(
    body: AssistantChatRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _rate_limit: Annotated[None, Depends(RateLimitAiChat)],
    _=Depends(Perm),
):
    result = await run_assistant_chat(
        db=db,
        group_filter=group_filter,
        history=[h.model_dump() for h in body.history],
        user_message=body.message,
    )
    return AssistantChatResponse(**result)
