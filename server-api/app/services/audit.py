from uuid import UUID
from app.models.models import AuditLog

async def audit_log(
    db,  # kept for backwards-compatible signature but ignored — opens own session
    actor_id: UUID | None,
    action: str,
    resource_type: str | None = None,
    resource_id: str | None = None,
    detail: dict | None = None,
) -> None:
    # Always open a fresh session so this can run safely as a BackgroundTask
    # after the route's request-scoped session has already been closed.
    from app.core.database import AsyncSessionLocal
    async with AsyncSessionLocal() as session:
        entry = AuditLog(
            actor_id=actor_id,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id else None,
            detail=detail or {},
        )
        session.add(entry)
        await session.commit()
