# server-api/app/api/routes/web_protection.py
"""Web Protection (spec B1): agents sync the blocklist here; the dashboard
manages the blocklist, allowlist, policy and block page."""
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_agent
from app.models.models import Agent
from app.services import web_blocks

agent_router = APIRouter(prefix="/api/ingest", tags=["ingest"])


class DeltaRequest(BaseModel):
    since: int = 0
    continuing: bool = False
    rules: int = 0


@agent_router.post("/web-blocklist")
async def agent_web_blocklist(
    body: DeltaRequest,
    agent: Annotated[Agent, Depends(get_agent)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    if not agent.approved:
        raise HTTPException(status_code=403, detail="agent not approved")
    out = await web_blocks.delta(db, agent.group_id or "default", max(body.since, 0), body.continuing,
                                  rules=body.rules)
    # the version the agent stores once it has every page; equals the heartbeat's when caught up
    version = str(out["seq"]) if out["policy"]["enabled"] and not out["more"] else ""
    return {**out, "version": version}
