"""Drain committed case events and create SOAR runs in the same transaction."""
from datetime import datetime, timezone

from sqlalchemy import select

from worker.database import AsyncSessionLocal
from worker.models import Case, SoarCaseEvent
from worker.soar.case_data import read_case_evidence


async def dispatch_case_events() -> int:
    # Imported here because the engine calls this pump from its polling loop.
    from worker.soar.engine import dispatch

    async with AsyncSessionLocal() as db:
        events = (await db.execute(select(SoarCaseEvent).where(SoarCaseEvent.processed_at.is_(None), SoarCaseEvent.ready.is_(True))
                                  .order_by(SoarCaseEvent.created_at).limit(20)
                                  .with_for_update(skip_locked=True))).scalars().all()
        for event in events:
            case = (await db.execute(select(Case).where(
                Case.id == event.case_id, Case.group_id == event.group_id, Case.status == "open",
            ))).scalar_one_or_none()
            if case is not None:
                snapshot = await read_case_evidence(db, case)
                alert = next((a for a in snapshot.evidence if a.alert_id == event.alert_id), None)
                # A suggestion removed before dispatch must never initiate containment.
                if event.event == "case.created" or alert is not None:
                    trigger = {
                        "case_id": str(case.id), "case_title": case.title, "case_status": case.status,
                        "created_by_ai": case.created_by_ai, "severity": case.severity,
                        "ai_confidence": case.ai_confidence, "rule_title": case.title,
                        "alert_id": str(alert.alert_id) if alert else None,
                        "source_ip": alert.ips[0] if alert and len(alert.ips) == 1 else None,
                        "hostname": alert.hostname if alert else None,
                        "alert_count": len(snapshot.evidence),
                        "ioc_count": len({k for a in snapshot.evidence for k in a.indicators}),
                        "event_id": str(event.id),
                    }
                    await dispatch(event.event, trigger, group_id=case.group_id, db=db)
            event.processed_at = datetime.now(timezone.utc)
        await db.commit()
    return len(events)
