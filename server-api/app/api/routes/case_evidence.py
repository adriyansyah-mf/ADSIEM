"""Case membership review and explicitly requested multi-IP remediation."""
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, IPvAnyAddress
from sqlalchemy import or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import fetch_scoped, get_current_user, get_scoped_group, require_permission
from app.models.models import Agent, AgentTask, Alert, Case, CaseAlert, CaseNote, User
from app.schemas.schemas import AgentTaskOut

router = APIRouter(prefix="/api/cases", tags=["cases"])
Database = Annotated[AsyncSession, Depends(get_db)]
Scope = Annotated[str | None, Depends(get_scoped_group)]


class EvidenceAlert(BaseModel):
    id: UUID
    title: str
    severity: str
    hostname: str | None
    agent_id: UUID | None
    source_ip: str | None
    created_at: datetime
    status: str
    method: str
    reason: str
    confidence: float | None
    indicators: list[str]
    accounts: list[str]


class Evidence(BaseModel):
    alerts: list[EvidenceAlert]
    blockable_ips: list[str]


async def evidence_for(case: Case, db: AsyncSession) -> Evidence:
    rows = (await db.execute(select(Alert, CaseAlert).outerjoin(
        CaseAlert, (CaseAlert.alert_id == Alert.id) & (CaseAlert.case_id == case.id),
    ).where(Alert.group_id == case.group_id, or_(CaseAlert.case_id == case.id, Alert.id == case.alert_id))
        .order_by(Alert.created_at.desc()))).all()
    alerts = []
    ips = set()
    for alert, link in rows:
        indicators = set(link.indicators if link else [])
        if alert.source_ip:
            indicators.add(f"ip:{alert.source_ip}")
        status = link.status if link else "linked"
        if status == "linked":
            for key in indicators:
                if key.startswith("ip:"):
                    try:
                        ips.add(str(ip_address(key[3:])))
                    except ValueError:
                        continue
        alerts.append(EvidenceAlert(
            id=alert.id, title=alert.title, severity=alert.severity, hostname=alert.hostname,
            agent_id=alert.agent_id, source_ip=alert.source_ip, created_at=alert.created_at,
            status=status, method=link.method if link else "primary",
            reason=link.reason if link else "Original case alert", confidence=link.confidence if link else None,
            indicators=sorted(indicators), accounts=link.accounts if link else [],
        ))
    return Evidence(alerts=alerts, blockable_ips=sorted(ips))


@router.get("/{case_id}/evidence", response_model=Evidence)
async def case_evidence(case_id: UUID, db: Database, group: Scope, _=Depends(get_current_user)):
    case = await fetch_scoped(db, Case, case_id, group, detail="Case not found")
    return await evidence_for(case, db)


class MembershipUpdate(BaseModel):
    status: Literal["linked", "detached"]


@router.put("/{case_id}/alerts/{alert_id}")
async def update_membership(case_id: UUID, alert_id: UUID, body: MembershipUpdate,
                            db: Database, group: Scope, user=Depends(require_permission("cases:manage"))):
    case = await fetch_scoped(db, Case, case_id, group, detail="Case not found")
    case = (await db.execute(select(Case).where(Case.id == case.id).with_for_update()
                            .execution_options(populate_existing=True))).scalar_one()
    if case.status != "open":
        raise HTTPException(409, "Only open cases accept grouping changes")
    alert = await fetch_scoped(db, Alert, alert_id, case.group_id, detail="Alert not found")
    link = await db.get(CaseAlert, (case.id, alert.id))
    if link is None:
        if alert.id != case.alert_id:
            raise HTTPException(404, "Case alert not found")
        link = CaseAlert(case_id=case.id, alert_id=alert.id,
                         indicators=[f"ip:{alert.source_ip}"] if alert.source_ip else [], accounts=[])
        db.add(link)
    link.status, link.method = body.status, "analyst"
    link.reason = f"Analyst {user.username} {'accepted' if body.status == 'linked' else 'removed'} this association."
    if body.status == "detached" and case.alert_id == alert.id:
        case.alert_id = None
    await db.flush()
    evidence = await evidence_for(case, db)
    linked = [a for a in evidence.alerts if a.status == "linked"]
    ioc = dict(case.ioc_data or {})
    ioc["ioc_keys"] = sorted({key for a in linked for key in a.indicators})
    ioc["affected_hosts"] = sorted({a.hostname for a in linked if a.hostname})
    ioc.pop("source_ip", None)
    ioc.pop("hostname", None)
    case.ioc_data = ioc
    case.ai_reasoning = (f"{len(linked)} linked alerts across {len(ioc['affected_hosts'])} hosts; "
                         f"{len(ioc['ioc_keys'])} indicators. {link.reason} "
                         "See per-alert evidence and notes for the incident analysis.")
    case.updated_at = datetime.now(timezone.utc)
    db.add(CaseNote(case_id=case.id, author_id=user.id, content=f"{link.reason} Alert: {alert.id}"))
    await db.commit()
    return {"status": link.status}


class BlockSelection(BaseModel):
    request_id: UUID
    agent_ids: list[UUID] = Field(min_length=1, max_length=50)
    ips: list[IPvAnyAddress] = Field(min_length=1, max_length=100)
    duration_seconds: Literal[3600, 86400, 604800] = 3600


@router.post("/{case_id}/remediations", response_model=list[AgentTaskOut], status_code=201)
async def block_case_ips(case_id: UUID, body: BlockSelection, db: Database, group: Scope,
                         user: User = Depends(require_permission("agents:manage"))):
    case = await fetch_scoped(db, Case, case_id, group, detail="Case not found")
    await db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                     {"key": f"case-remediation:{case.id}:{body.request_id}"})
    case = (await db.execute(select(Case).where(Case.id == case.id).with_for_update()
                            .execution_options(populate_existing=True))).scalar_one()
    agent_ids, ips = set(body.agent_ids), {str(ip) for ip in body.ips}
    if len(agent_ids) * len(ips) > 100:
        raise HTTPException(422, "Select at most 100 IP/host pairs per request")
    existing = (await db.execute(select(AgentTask).join(Agent, Agent.id == AgentTask.agent_id).where(
        Agent.group_id == case.group_id,
        AgentTask.params["case_id"].astext == str(case.id),
        AgentTask.params["request_id"].astext == str(body.request_id),
    ))).scalars().all()
    if existing:
        if ({(t.agent_id, t.params["ip"], t.params["duration_seconds"]) for t in existing}
                != {(a, ip, body.duration_seconds) for a in agent_ids for ip in ips}):
            raise HTTPException(409, "Request ID already used for a different selection")
        return existing
    evidence = await evidence_for(case, db)
    eligible_agents = {a.agent_id for a in evidence.alerts if a.status == "linked" and a.agent_id}
    if not agent_ids <= eligible_agents or not ips <= set(evidence.blockable_ips):
        raise HTTPException(422, "Select IPs and hosts from linked case evidence")
    agents = (await db.execute(select(Agent).where(Agent.id.in_(agent_ids), Agent.group_id == case.group_id))).scalars().all()
    if {a.id for a in agents} != agent_ids:
        raise HTTPException(404, "Agent not found in case group")
    tasks = [AgentTask(agent_id=agent, task_type="block_ip", created_by=user.id,
                       params={"ip": ip, "duration_seconds": body.duration_seconds,
                               "case_id": str(case.id), "request_id": str(body.request_id)})
             for agent in sorted(agent_ids) for ip in sorted(ips)]
    db.add_all(tasks)
    db.add(CaseNote(case_id=case.id, author_id=user.id,
                    content=f"Remediation requested by {user.username}: block {', '.join(sorted(ips))} "
                            f"on {len(agents)} selected hosts for {body.duration_seconds}s. "
                            f"Request {body.request_id}; {len(tasks)} tasks queued, execution pending."))
    await db.commit()
    return tasks


@router.get("/{case_id}/remediations", response_model=list[AgentTaskOut])
async def remediation_tasks(case_id: UUID, db: Database, group: Scope, _=Depends(get_current_user)):
    case = await fetch_scoped(db, Case, case_id, group, detail="Case not found")
    return (await db.execute(select(AgentTask).join(Agent, Agent.id == AgentTask.agent_id).where(
        Agent.group_id == case.group_id, AgentTask.params["case_id"].astext == str(case.id),
    ).order_by(AgentTask.created_at.desc()).limit(100))).scalars().all()
