"""Consumes alert notifications published by the worker and starts runs."""
from __future__ import annotations

import asyncio
import json
from typing import Any

import structlog
from sqlalchemy import select

from app.core.database import AsyncSessionLocal
from app.core.redis_client import get_redis
from app.models.models import PlatformSetting, SoarNode, SoarWorkflow
from app.services.soar_executor import start_run

log = structlog.get_logger()

TRIGGER_QUEUE = "siem:soar-triggers"
_BLOCK_SECONDS = 5


def trigger_matches(config: dict[str, Any], event: dict[str, Any]) -> bool:
    severities = config.get("severities")
    if severities and event.get("severity") not in severities:
        return False
    needle = config.get("title_contains")
    if needle and needle.lower() not in (event.get("title") or "").lower():
        return False
    return True


async def _dispatch(event: dict[str, Any]) -> None:
    async with AsyncSessionLocal() as db:
        async with db.begin():
            setting = await db.get(PlatformSetting, "soar_v2_enabled")
            if not (setting and setting.value.lower() == "true"):
                return
            workflows = (await db.execute(
                select(SoarWorkflow).where(
                    SoarWorkflow.is_enabled == True,
                    SoarWorkflow.group_id == event.get("group_id", "default"),
                )
            )).scalars().all()
            for workflow in workflows:
                triggers = (await db.execute(
                    select(SoarNode).where(
                        SoarNode.workflow_id == workflow.id,
                        SoarNode.node_type == "alert_trigger",
                    )
                )).scalars().all()
                if not any(trigger_matches(t.config or {}, event) for t in triggers):
                    continue
                await start_run(db, workflow, "alert", {"alert": event})
                log.info("soar_run_started", workflow_id=str(workflow.id),
                         alert_id=event.get("alert_id"))


async def soar_trigger_consumer_loop() -> None:
    redis = await get_redis()
    while True:
        try:
            popped = await redis.brpop(TRIGGER_QUEUE, timeout=_BLOCK_SECONDS)
            if popped is None:
                continue
            await _dispatch(json.loads(popped[1]))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.error("soar_trigger_consumer_failed", error=str(exc))
            await asyncio.sleep(_BLOCK_SECONDS)
