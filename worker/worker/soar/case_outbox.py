"""Shared transactional case event writer; imports no service-specific models."""
from dataclasses import dataclass
from typing import Literal
from uuid import NAMESPACE_URL, UUID, uuid5

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(frozen=True, slots=True)
class CaseEvent:
    case_id: UUID
    group_id: str
    event: Literal["case.created", "case.alert_linked"]
    alert_id: UUID | None = None
    ready: bool = True


async def enqueue_case_event(db: AsyncSession, event: CaseEvent) -> None:
    """One event per case creation or case/alert association, committed by the caller."""
    event_id = uuid5(NAMESPACE_URL, f"adsiem:{event.event}:{event.case_id}:{event.alert_id}")
    await db.execute(text("""
        INSERT INTO soar_case_events (id, case_id, group_id, event, alert_id, ready, created_at)
        VALUES (:id, :case_id, :group_id, :event, :alert_id, :ready, CURRENT_TIMESTAMP)
        ON CONFLICT (id) DO UPDATE SET ready = soar_case_events.ready OR EXCLUDED.ready
    """), {"id": event_id, "case_id": event.case_id, "group_id": event.group_id,
           "event": event.event, "alert_id": event.alert_id, "ready": event.ready})
