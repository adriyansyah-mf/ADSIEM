from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.models import AuditLog

async def audit_log(
    db: AsyncSession,
    actor_id: UUID | None,
    action: str,
    resource_type: str | None = None,
    resource_id: str | None = None,
    detail: dict | None = None,
) -> None:
    entry = AuditLog(
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id else None,
        detail=detail or {},
    )
    db.add(entry)
    await db.commit()
