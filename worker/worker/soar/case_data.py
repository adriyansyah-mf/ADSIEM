"""Group-scoped, explicitly linked evidence for case workflows."""
from datetime import datetime
from ipaddress import ip_address
from uuid import UUID

from pydantic import BaseModel, ConfigDict
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from worker.models import Alert, Case, CaseAlert


class CaseEvidence(BaseModel):
    model_config = ConfigDict(frozen=True)
    alert_id: UUID
    agent_id: UUID | None
    hostname: str | None
    indicators: list[str]
    ips: list[str]
    created_at: datetime


class CaseSnapshot(BaseModel):
    model_config = ConfigDict(frozen=True)
    case_id: UUID
    group_id: str
    title: str
    status: str
    severity: str
    created_by_ai: bool
    ai_confidence: float | None
    evidence: list[CaseEvidence]


async def read_case_evidence(db: AsyncSession, case: Case) -> CaseSnapshot:
    """Keep indicators paired with their actual alert/agent; exclude suggestions and removals."""
    rows = (await db.execute(select(Alert, CaseAlert).outerjoin(CaseAlert, and_(
        CaseAlert.alert_id == Alert.id, CaseAlert.case_id == case.id,
    )).where(Alert.group_id == case.group_id, or_(
        CaseAlert.status == "linked", and_(CaseAlert.alert_id.is_(None), Alert.id == case.alert_id),
    )).order_by(Alert.created_at))).all()
    evidence = []
    for alert, link in rows:
        indicators = set(link.indicators if link else [])
        if alert.source_ip:
            indicators.add(f"ip:{alert.source_ip}")
        ips = set()
        for indicator in indicators:
            if indicator.startswith("ip:"):
                try:
                    ips.add(str(ip_address(indicator[3:])))
                except ValueError:
                    continue
        evidence.append(CaseEvidence(alert_id=alert.id, agent_id=alert.agent_id, hostname=alert.hostname,
                                     indicators=sorted(indicators), ips=sorted(ips), created_at=alert.created_at))
    return CaseSnapshot(case_id=case.id, group_id=case.group_id, title=case.title, status=case.status,
                        severity=case.severity, created_by_ai=case.created_by_ai, ai_confidence=case.ai_confidence,
                        evidence=evidence)
