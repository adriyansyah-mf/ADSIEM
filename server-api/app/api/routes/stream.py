# server-api/app/api/routes/stream.py
"""Multiplexed Server-Sent Events feed.

One connection per browser, carrying several topics selected by the `topics`
query parameter:

- `alerts` — fanned out from the Redis channel the worker publishes to
  (worker/worker/alert_manager.py).
- `events` — Elasticsearch has no push, so this topic tails the log index by
  created_at on an interval and emits documents newer than the cursor.

Every topic is group-scoped for non-superadmin callers.

Frame shape:
    event: <topic>
    data: {json}

plus periodic `event: ping` keep-alives so proxies don't close an idle stream.
"""
import asyncio
import json
from datetime import datetime, timedelta, timezone
from typing import Annotated

import redis.asyncio as aioredis
import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.database import get_db
from app.core.es_client import search as es_search
from app.core.security import decode_token
from app.models.models import User

router = APIRouter(prefix="/api/stream", tags=["stream"])
log = structlog.get_logger()

_ALERT_CHANNEL = "ws:alerts"
_ES_TOPIC = "events"

_REDIS_TOPICS = {"alerts": _ALERT_CHANNEL}
_SUPPORTED_TOPICS = set(_REDIS_TOPICS) | {_ES_TOPIC}

_PING_INTERVAL = 20.0
_ES_POLL_INTERVAL = 5.0
_ES_BATCH = 50


def _parse_topics(raw: str | None) -> list[str]:
    if not raw:
        return ["alerts"]
    requested = [t.strip() for t in raw.split(",") if t.strip()]
    return [t for t in requested if t in _SUPPORTED_TOPICS] or ["alerts"]


def _event_from_hit(hit: dict) -> dict:
    return {
        "id": hit.get("id"),
        "agent_id": hit.get("agent_id"),
        "log_type": hit.get("log_type"),
        "event_action": hit.get("event_action"),
        "event_category": hit.get("event_category"),
        "source_ip": hit.get("source_ip"),
        "user_name": hit.get("user_name"),
        "created_at": hit.get("created_at"),
        "fields": hit.get("decoded_fields") or {},
    }


@router.get("/events")
async def stream_events(
    request: Request,
    topics: Annotated[str | None, Query(description="comma-separated: alerts,events")] = None,
    token: Annotated[str | None, Query(description="access token; EventSource cannot send headers")] = None,
    db: Annotated[AsyncSession, Depends(get_db)] = None,
):
    """Multiplexed SSE stream. One connection, N topics.

    EventSource cannot set an Authorization header, so this endpoint
    authenticates from the `token` query parameter — the same approach
    /api/ws/alerts uses. The group scope comes from the user row rather than
    Depends(get_scoped_group), which would require the header; the token itself
    carries only sub/exp/type, so it is not enough to derive a scope.
    """
    try:
        payload = decode_token(token or "")
        if payload.get("type") != "access" or not payload.get("sub"):
            raise ValueError("invalid token")
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token")

    user = (
        await db.execute(
            select(User).options(selectinload(User.role)).where(
                User.id == payload["sub"], User.is_active == True
            )
        )
    ).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="user not found or inactive")

    group_filter = None if user.role.name == "superadmin" else user.group_id

    selected = _parse_topics(topics)

    async def event_source():
        redis = None
        pubsub = None
        redis_topics = [t for t in selected if t in _REDIS_TOPICS]
        want_events = _ES_TOPIC in selected

        if redis_topics:
            redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
            pubsub = redis.pubsub()
            await pubsub.subscribe(*[_REDIS_TOPICS[t] for t in redis_topics])

        yield f"event: ready\ndata: {json.dumps({'topics': selected})}\n\n"

        channel_map = {_REDIS_TOPICS[t]: t for t in redis_topics}
        cursor = datetime.now(timezone.utc).isoformat()

        try:
            while True:
                if await request.is_disconnected():
                    break

                if pubsub is not None:
                    message = await pubsub.get_message(
                        ignore_subscribe_messages=True, timeout=0.5
                    )
                    if message is not None:
                        topic = channel_map.get(message.get("channel"), "alerts")
                        payload = message.get("data")
                        if not isinstance(payload, str):
                            try:
                                payload = json.dumps(payload, default=str)
                            except Exception:
                                payload = None
                        if payload:
                            yield f"event: {topic}\ndata: {payload}\n\n"
                            continue

                if want_events:
                    cursor, frames = await _tail_events(cursor, group_filter)
                    for frame in frames:
                        yield frame

                await asyncio.sleep(_ES_POLL_INTERVAL if want_events else _PING_INTERVAL)

                if not want_events and pubsub is None:
                    yield "event: ping\ndata: {}\n\n"
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("sse_stream_error", error=str(exc))
            yield f"event: error\ndata: {json.dumps({'message': str(exc)})}\n\n"
        finally:
            if pubsub is not None:
                try:
                    await pubsub.unsubscribe()
                    await pubsub.aclose()
                except Exception:
                    pass
            if redis is not None:
                try:
                    await redis.aclose()
                except Exception:
                    pass

    return StreamingResponse(
        event_source(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


async def _tail_events(cursor: str, group_filter: str | None = None) -> tuple[str, list[str]]:
    """Fetch documents created after `cursor`; return the new cursor and frames."""
    filters: list[dict] = [{"range": {"created_at": {"gt": cursor}}}]
    if group_filter:
        filters.append({"term": {"group_id": group_filter}})
    try:
        hits, _total, _next = await es_search(
            {"bool": {"filter": filters}},
            size=_ES_BATCH,
            sort=[{"created_at": "asc"}],
        )
    except Exception as exc:
        log.warning("sse_events_tail_failed", error=str(exc))
        return cursor, []

    if not hits:
        return cursor, []

    frames = [
        f"event: {_ES_TOPIC}\ndata: {json.dumps(_event_from_hit(h))}\n\n"
        for h in hits
    ]
    newest = hits[-1].get("created_at") or cursor
    return newest, frames
