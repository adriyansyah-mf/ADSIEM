"""A case's alerts as a step-by-step entity graph: which host, user, process,
file, hash, IP and domain each alert involved, in time order."""
import asyncio
import ipaddress
from datetime import datetime, timezone
from typing import Annotated, Literal
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.routes.case_evidence import evidence_for
from app.core.database import get_db
from app.core.deps import fetch_scoped, get_current_user, get_scoped_group, require_permission
from app.core.es_client import get_log as es_get_log
from app.models.models import Agent, Alert, Case, CaseNote
from app.services.case_graph import alert_entities

router = APIRouter(prefix="/api/cases", tags=["cases"])
log = structlog.get_logger()
MAX_STEPS = 40


class GraphStep(BaseModel):
    alert_id: UUID
    title: str
    severity: str
    at: datetime
    kill_chain_stage: str | None
    entities: list[str]


class GraphNode(BaseModel):
    key: str
    kind: str
    value: str
    first_step: int
    alerts: int
    facts: dict[str, str] = {}
    asset_tier: int | None = None
    asset_role: str | None = None


class GraphEdge(BaseModel):
    a: str
    b: str
    first_step: int


class CaseGraph(BaseModel):
    steps: list[GraphStep]
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    truncated: int


async def _fields(alert: Alert) -> dict:
    fields: dict = {}
    if alert.event_id:
        try:
            doc = await es_get_log(str(alert.event_id))
            fields = dict((doc or {}).get("decoded_fields") or {})
        except Exception as exc:  # the graph still shows host and IP without the event
            log.warning("case_graph_event_unavailable", alert_id=str(alert.id), error=str(exc))
    return {**fields, **((alert.context or {}).get("matched_fields") or {})}


class CaseIocAdd(BaseModel):
    kind: Literal["ip", "domain", "url", "hash", "host"]
    value: str = Field(min_length=1, max_length=2048)


def _ioc_key(body: CaseIocAdd) -> str:
    value = body.value.strip()
    if body.kind == "ip":
        try:
            value = str(ipaddress.ip_address(value))
        except ValueError:
            raise HTTPException(422, "Not an IP address") from None
    elif body.kind == "hash":
        value = value.lower()
        if len(value) not in (32, 40, 64) or any(c not in "0123456789abcdef" for c in value):
            raise HTTPException(422, "Not an MD5, SHA-1 or SHA-256 hash")
    elif body.kind == "domain":
        value = value.lower().rstrip(".")
    return f"{body.kind}:{value}"


@router.post("/{case_id}/iocs")
async def add_case_ioc(case_id: UUID, body: CaseIocAdd, db: Annotated[AsyncSession, Depends(get_db)],
                       group: Annotated[str | None, Depends(get_scoped_group)],
                       user=Depends(require_permission("cases:manage"))):
    """Adds an indicator (or an affected host) the analyst found in the graph to the case."""
    case = await fetch_scoped(db, Case, case_id, group, detail="Case not found")
    case = (await db.execute(select(Case).where(Case.id == case.id).with_for_update()
                             .execution_options(populate_existing=True))).scalar_one()
    ioc = dict(case.ioc_data or {})
    key = _ioc_key(body)
    field_name, item = ("affected_hosts", key[5:]) if body.kind == "host" else ("ioc_keys", key)
    current = list(ioc.get(field_name) or [])
    added = item not in current
    if added:
        ioc[field_name] = sorted([*current, item])
        case.ioc_data = ioc
        case.updated_at = datetime.now(timezone.utc)
        db.add(CaseNote(case_id=case.id, author_id=user.id, is_ai_generated=False,
                        content=f"**{user.username}** added `{item}` to the case from the relation graph."))
        await db.commit()
    return {"added": added, "ioc_data": ioc}


@router.get("/{case_id}/entity-graph", response_model=CaseGraph)
async def case_entity_graph(case_id: UUID, db: Annotated[AsyncSession, Depends(get_db)],
                            group: Annotated[str | None, Depends(get_scoped_group)],
                            _=Depends(get_current_user)):
    case = await fetch_scoped(db, Case, case_id, group, detail="Case not found")
    linked = [a.id for a in (await evidence_for(case, db)).alerts if a.status == "linked"]
    alerts = (await db.execute(select(Alert).where(Alert.id.in_(linked), Alert.group_id == case.group_id)
                               .order_by(Alert.created_at.asc(), Alert.id))).scalars().all() if linked else []
    shown = alerts[:MAX_STEPS]
    fields = await asyncio.gather(*(_fields(a) for a in shown))

    steps: list[GraphStep] = []
    nodes: dict[str, GraphNode] = {}
    edges: dict[tuple[str, str], GraphEdge] = {}
    for n, (alert, data) in enumerate(zip(shown, fields)):
        found = alert_entities(data, alert.hostname, alert.source_ip)
        keys = [f"{kind}:{value}" for kind, value in found.entities]
        for kind, value in found.entities:
            key = f"{kind}:{value}"
            if key in nodes:
                nodes[key].alerts += 1
            else:
                nodes[key] = GraphNode(key=key, kind=kind, value=value, first_step=n, alerts=1)
        for a, b in found.edges:
            if (a, b) not in edges and (b, a) not in edges:
                edges[(a, b)] = GraphEdge(a=a, b=b, first_step=n)
        steps.append(GraphStep(alert_id=alert.id, title=alert.title, severity=alert.severity, at=alert.created_at,
                               kill_chain_stage=alert.kill_chain_stage, entities=keys))

    hosts = [node.value for node in nodes.values() if node.kind == "host"]
    if hosts:
        agents = (await db.execute(select(Agent).where(Agent.group_id == case.group_id, Agent.hostname.in_(hosts)))).scalars().all()
        for agent in agents:
            node = nodes.get(f"host:{agent.hostname}")
            if node is None:
                continue
            node.asset_tier, node.asset_role = agent.asset_tier, agent.asset_role
            node.facts = {k: v for k, v in {
                "Agent": f"v{agent.version}" if agent.version else None,
                "Status": "isolated" if agent.is_isolated else agent.status,
                "Last seen": agent.last_seen_at.strftime("%d %b %H:%M UTC") if agent.last_seen_at else None,
            }.items() if v}
    for node in nodes.values():
        node.facts = {"Alerts in case": str(node.alerts), **node.facts}
    return CaseGraph(steps=steps, nodes=list(nodes.values()), edges=list(edges.values()),
                     truncated=max(0, len(alerts) - MAX_STEPS))
