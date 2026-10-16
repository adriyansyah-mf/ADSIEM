# server-api/app/api/routes/assistant.py
import json
from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_scoped_group, require_permission
from app.schemas.schemas import AssistantChatRequest, AssistantChatResponse
from app.services.assistant import run_assistant_chat, stream_assistant_chat

router = APIRouter(prefix="/api/assistant", tags=["assistant"])
Perm = require_permission("alerts:read")


@router.post("/chat", response_model=AssistantChatResponse)
async def assistant_chat(
    body: AssistantChatRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(Perm),
):
    result = await run_assistant_chat(
        db=db,
        group_filter=group_filter,
        history=[h.model_dump() for h in body.history],
        user_message=body.message,
    )
    return AssistantChatResponse(**result)


@router.post("/chat/stream")
async def assistant_chat_stream(
    body: AssistantChatRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(Perm),
):
    """Server-Sent Events variant of /chat.

    Emits `data: {json}` frames carrying the same chunk types the gateway
    produces (start / text-delta / reasoning-delta / tool-call / finish /
    error), so the dashboard can render tokens as they arrive.
    """
    history = [h.model_dump() for h in body.history]

    async def event_source():
        async for chunk in stream_assistant_chat(
            db=db,
            group_filter=group_filter,
            history=history,
            user_message=body.message,
        ):
            yield f"data: {json.dumps(chunk)}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(
        event_source(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
