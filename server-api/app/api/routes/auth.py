# server-api/app/api/routes/auth.py
from typing import Annotated
import pyotp
import qrcode
import io
import base64
from fastapi import APIRouter, BackgroundTasks, Cookie, Depends, HTTPException, Request, Response, status
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

import uuid

import redis.asyncio as aioredis
import structlog

from app.core.config import settings
from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.redis_client import get_redis
from app.core.security import (
    create_access_token, create_refresh_token, decode_token, verify_password
)
from app.models.models import Role, User
from app.schemas.schemas import LoginRequest, TokenResponse, UserMe
from app.services.audit import audit_log
from app.core.limiter import limiter

router = APIRouter(prefix="/api/auth", tags=["auth"])
log = structlog.get_logger()

# Refresh tokens carry a jti that must be live in Redis. Each refresh replaces
# the jti (rotation); the old one keeps working for REUSE_GRACE seconds so
# concurrent requests and tabs don't log each other out, then it's refused.
# Logout deletes it. If Redis can't be reached the JWT signature and expiry
# still apply (fail open): a Redis outage must not log every analyst out.
REFRESH_KEY = "siem:rt:{}"
REUSE_GRACE = 30


async def _issue_refresh(response: Response, redis: aioredis.Redis, user_id: str) -> None:
    jti: str | None = uuid.uuid4().hex
    ttl = settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400
    try:
        await redis.set(REFRESH_KEY.format(jti), user_id, ex=ttl)
    except Exception as exc:  # noqa: BLE001
        # a jti Redis doesn't know would be refused once Redis is back: issue a
        # token without one, which the next refresh accepts and replaces
        log.warning("refresh_token_store_failed", error=str(exc))
        jti = None
    response.set_cookie("refresh_token", create_refresh_token(user_id, jti), httponly=True, samesite="lax",
                        secure=settings.REFRESH_COOKIE_SECURE, max_age=ttl)

@router.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")
async def login(
    request: Request,
    body: LoginRequest,
    response: Response,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    redis: Annotated[aioredis.Redis, Depends(get_redis)],
):
    result = await db.execute(
        select(User).options(selectinload(User.role))
        .where(User.username == body.username, User.is_active == True)
    )
    user = result.scalar_one_or_none()
    if not user or not verify_password(body.password, user.password_hash):
        background.add_task(audit_log, db, None, "login_failed", "user", body.username, {"reason": "bad credentials"})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # MFA enforcement
    if user.mfa_enabled and user.mfa_secret:
        mfa_code = body.mfa_code
        if not mfa_code:
            # Client must re-submit with mfa_code
            return {"mfa_required": True, "access_token": ""}
        totp = pyotp.TOTP(user.mfa_secret)
        if not totp.verify(mfa_code, valid_window=1):
            raise HTTPException(status_code=401, detail="Invalid MFA code")

    access_token = create_access_token(str(user.id))
    await _issue_refresh(response, redis, str(user.id))
    background.add_task(audit_log, db, user.id, "login_success", "user", str(user.id))
    return TokenResponse(access_token=access_token)

@router.post("/refresh", response_model=TokenResponse)
@limiter.limit("30/minute")
async def refresh(
    request: Request,
    response: Response,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    redis: Annotated[aioredis.Redis, Depends(get_redis)],
    refresh_token: Annotated[str | None, Cookie()] = None,
):
    if not refresh_token:
        raise HTTPException(status_code=401, detail="No refresh token")
    try:
        payload = decode_token(refresh_token)
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user_id = payload["sub"]
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    result = await db.execute(select(User).where(User.id == user_id, User.is_active == True))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    jti = payload.get("jti")  # tokens from before rotation have none: accepted once, then replaced
    rotate = True
    if jti:
        try:
            state = await redis.get(REFRESH_KEY.format(jti))
        except Exception as exc:  # noqa: BLE001 — fail open, see REFRESH_KEY
            log.warning("refresh_token_check_failed", error=str(exc))
            state, rotate = user_id, False
        if state is None:
            # revoked (logout), expired, or replaced longer ago than the grace: a
            # replayed old token is a theft signal, so it's audited
            # inline, not a background task: those only run when the response succeeds
            await audit_log(db, user.id, "refresh_token_rejected", "user", str(user.id))
            raise HTTPException(status_code=401, detail="Refresh token revoked")
        if state == "rotated":
            rotate = False  # a concurrent refresh already replaced it; its cookie is on the way
        elif rotate:
            try:
                await redis.set(REFRESH_KEY.format(jti), "rotated", ex=REUSE_GRACE)
            except Exception as exc:  # noqa: BLE001
                log.warning("refresh_token_rotate_failed", error=str(exc))
    if rotate:
        await _issue_refresh(response, redis, str(user.id))
    return TokenResponse(access_token=create_access_token(str(user.id)))


@router.post("/logout", status_code=204)
async def logout(
    response: Response,
    redis: Annotated[aioredis.Redis, Depends(get_redis)],
    refresh_token: Annotated[str | None, Cookie()] = None,
):
    """Revoke this session's refresh token and clear its cookie. Needs no access
    token: an expired session must still be able to log out."""
    if refresh_token:
        try:
            jti = decode_token(refresh_token).get("jti")
            if jti:
                await redis.delete(REFRESH_KEY.format(jti))
        except Exception as exc:  # noqa: BLE001 — bad/expired token or Redis down: still clear the cookie
            log.info("logout_revoke_skipped", error=str(exc))
    response.delete_cookie("refresh_token", httponly=True, samesite="lax", secure=settings.REFRESH_COOKIE_SECURE)
    response.status_code = 204
    return response

@router.get("/me", response_model=UserMe)
async def me(current_user: Annotated[User, Depends(get_current_user)]):
    return UserMe(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        role=current_user.role.name,
        group_id=current_user.group_id,
        mfa_enabled=current_user.mfa_enabled or False,
    )


@router.post("/mfa/setup")
async def mfa_setup(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Generate a TOTP secret and QR code PNG for the current user (not yet enabled)."""
    if current_user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is already enabled. Disable it first before re-configuring.")
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=current_user.username, issuer_name="SIEM Platform")
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()
    current_user.mfa_secret = secret
    current_user.mfa_enabled = False
    await db.commit()
    return {"secret": secret, "qr_code": f"data:image/png;base64,{qr_b64}", "uri": uri}


@router.post("/mfa/enable")
async def mfa_enable(
    body: dict,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Verify a TOTP code and enable MFA for the current user."""
    if not current_user.mfa_secret:
        raise HTTPException(status_code=400, detail="MFA setup not started. Call /mfa/setup first.")
    totp = pyotp.TOTP(current_user.mfa_secret)
    if not totp.verify(str(body.get("code", "")), valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")
    current_user.mfa_enabled = True
    await db.commit()
    return {"ok": True, "message": "MFA enabled successfully"}


@router.post("/mfa/disable")
async def mfa_disable(
    body: dict,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Disable MFA after verifying the current TOTP code."""
    if current_user.mfa_enabled and current_user.mfa_secret:
        totp = pyotp.TOTP(current_user.mfa_secret)
        if not totp.verify(str(body.get("code", "")), valid_window=1):
            raise HTTPException(status_code=400, detail="Invalid TOTP code")
    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    await db.commit()
    return {"ok": True}
