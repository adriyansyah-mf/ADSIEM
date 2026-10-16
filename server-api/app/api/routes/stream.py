# server-api/app/api/routes/stream.py
"""Multiplexed Server-Sent Events feed.

One connection per browser, carrying several topics selected by the
`topics` query parameter. Alert events are fanned out from the Redis channel
the worker already publishes to (worker/worker/alert_manager.py), so this
endpoint adds a transport, not a second source of truth.

Frame shape:
    event: <topic>
    data: {json}

plus periodic `event: ping` keep-alives so proxies don't close an idle stream.
"""
import asyncio
import json
from typing import Annotated

import redis.asyncio as aioredis
import structlog
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse

from app.core.config import settings
from app.core.deps import get_current_user, require_permission
from app.models.models import User

router = APIRouter(prefix="/api/stream", tags=["stream"])
log = structlog.get_logger()

_ALERT_CHANNEL = "ws:alerts"

_SUPPORTED_TOPICS = {
    "alerts": _ALERT_CHANNEL,
}

_PING_INTERVAL = 20.0


def _parse_topics(raw: str | None) -> list[str]:
    if not raw:
        return ["alerts"]
    requested = [t.strip() for t in raw.split(",") if t.strip()]
    return [t for t in requested if t in _SUPPORTED_TOPICS] or ["alerts"]


@router.get("/events")
async def stream_events(
    request: Request,
    topics: Annotated[str | None, Query(description="comma-separated topics, e.g. alerts")] = None,
    _: Annotated[User, Depends(require_permission("alerts:read"))] = None,
):
    """Multiplexed SSE stream. One connection, N topics."""
    selected = _parse_topics(topics)

    async def event_source():
        redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        pubsub = redis.pubsub()
        channels = {_SUPPORTED_TOPICS[t]: t for t in selected}
        await pubsub.subscribe(*channels.keys())

        yield f"event: ready\ndata: {json.dumps({'topics': selected})}\n\n"

        try:
            while True:
                if await request.is_disconnected():
                    break
                message = await pubsub.get_message(
                    ignore_subscribe_messages=True, timeout=_PING_INTERVAL
                )
                if message is None:
                    yield "event: ping\ndata: {}\n\n"
                    continue
                topic = channels.get(message.get("channel"), "alerts")
                payload = message.get("data")
                if not isinstance(payload, str):
                    try:
                        payload = json.dumps(payload, default=str)
                    except Exception:
                        continue
                yield f"event: {topic}\ndata: {payload}\n\n"
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("sse_stream_error", error=str(exc))
            yield f"event: error\ndata: {json.dumps({'message': str(exc)})}\n\n"
        finally:
            try:
                await pubsub.unsubscribe()
                await pubsub.aclose()
            except Exception:
                pass
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
