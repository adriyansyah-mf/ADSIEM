"""Write one audit row. The database chains and guards it (services/audit_chain.py);
this fills in who and from where: the actor's name (kept even after the user is
deleted) and the request's client address, user agent and request line
(core/request_context.py)."""
from uuid import UUID

from app.core import request_context
from app.models.models import AuditLog, User


async def audit_log(
    db,  # kept for backwards-compatible signature but ignored — opens own session
    actor_id: UUID | None,
    action: str,
    resource_type: str | None = None,
    resource_id: str | None = None,
    detail: dict | None = None,
    *,
    outcome: str = "success",
    actor_name: str | None = None,
    group_id: str | None = None,
) -> None:
    """outcome: success, failure (e.g. a wrong password) or denied (no permission).
    actor_name names an actor that has no account, such as the username a failed
    login tried."""
    # Always open a fresh session so this can run safely as a BackgroundTask
    # after the route's request-scoped session has already been closed.
    from app.core.database import AsyncSessionLocal
    ctx = request_context.current()
    async with AsyncSessionLocal() as session:
        group = group_id or "default"
        if actor_id is not None:
            actor = await session.get(User, actor_id)
            if actor is not None:
                group = group_id or actor.group_id or "default"
                actor_name = actor_name or actor.username
        entry = AuditLog(
            actor_id=actor_id,
            actor_name=(actor_name or "")[:255] or None,
            group_id=group,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id else None,
            detail=detail or {},
            outcome=outcome,
            ip_address=ctx.get("ip"),
            user_agent=ctx.get("user_agent"),
            request=ctx.get("request"),
        )
        session.add(entry)
        await session.commit()


async def audit_safe(*args, **kwargs) -> None:
    """audit_log for code that is about to refuse a request (failed login, 403):
    a broken audit write is logged but never turns the refusal into a 500."""
    try:
        await audit_log(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001
        import structlog
        structlog.get_logger().warning("audit_write_failed", action=args[2] if len(args) > 2 else None,
                                       error=str(exc))
