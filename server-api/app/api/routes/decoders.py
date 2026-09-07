# server-api/app/api/routes/decoders.py
import yaml
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import require_permission
from app.models.models import Decoder, User
from app.schemas.schemas import (
    DecoderCreate, DecoderOut, DecoderTestRequest, DecoderTestResponse,
    DecoderUpdate, PaginatedResponse
)
from app.services.audit import audit_log

router = APIRouter(prefix="/api/decoders", tags=["decoders"])

@router.get("", response_model=PaginatedResponse)
async def list_decoders(
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(require_permission("logs:read")),
    page: int = 1, page_size: int = 25,
):
    q = select(Decoder).order_by(Decoder.priority)
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    result = await db.execute(q.offset((page - 1) * page_size).limit(page_size))
    return PaginatedResponse(total=total, page=page, page_size=page_size,
                             items=[DecoderOut.model_validate(d) for d in result.scalars().all()])

@router.post("", response_model=DecoderOut, status_code=201)
async def create_decoder(
    body: DecoderCreate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("decoders:create"))],
):
    _validate_decoder_yaml(body.content)
    decoder = Decoder(**body.model_dump())
    db.add(decoder)
    await db.commit()
    await db.refresh(decoder)
    background.add_task(audit_log, db, current_user, "decoder_created", "decoder", str(decoder.id))
    return DecoderOut.model_validate(decoder)

@router.put("/{decoder_id}", response_model=DecoderOut)
async def update_decoder(
    decoder_id: UUID, body: DecoderUpdate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("decoders:update"))],
):
    result = await db.execute(select(Decoder).where(Decoder.id == decoder_id))
    decoder = result.scalar_one_or_none()
    if not decoder:
        raise HTTPException(status_code=404, detail="Decoder not found")
    updates = body.model_dump(exclude_none=True)
    if "content" in updates:
        _validate_decoder_yaml(updates["content"])
    for field, value in updates.items():
        setattr(decoder, field, value)
    await db.commit()
    await db.refresh(decoder)
    background.add_task(audit_log, db, current_user, "decoder_updated", "decoder", str(decoder_id))
    return DecoderOut.model_validate(decoder)

@router.delete("/{decoder_id}", status_code=204)
async def delete_decoder(
    decoder_id: UUID,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("decoders:delete"))],
):
    result = await db.execute(select(Decoder).where(Decoder.id == decoder_id))
    decoder = result.scalar_one_or_none()
    if not decoder:
        raise HTTPException(status_code=404, detail="Decoder not found")
    await db.delete(decoder)
    await db.commit()
    background.add_task(audit_log, db, current_user, "decoder_deleted", "decoder", str(decoder_id))

@router.post("/test", response_model=DecoderTestResponse)
async def test_decoder(body: DecoderTestRequest, _=Depends(require_permission("decoders:create"))):
    try:
        from worker.decoder_engine import DecoderEngine
        engine = DecoderEngine()
        engine.load_from_yaml_list([body.content])
        decoder_def = yaml.safe_load(body.content)
        log_type = decoder_def.get("log_type", "")
        decoded = engine.decode(log_type, body.raw_message)
        if not decoded:
            return DecoderTestResponse(matched=False)
        return DecoderTestResponse(matched=True, decoded_fields=decoded)
    except Exception as e:
        return DecoderTestResponse(matched=False, error=str(e))

def _validate_decoder_yaml(content: str):
    try:
        parsed = yaml.safe_load(content)
        if not isinstance(parsed, dict):
            raise ValueError("Decoder must be a YAML mapping")
        decoder_type = parsed.get("type", "regex")
        if decoder_type == "regex" and "pattern" not in parsed:
            raise ValueError("Decoder must have a 'pattern' field")
        if decoder_type not in ("regex", "kv"):
            raise ValueError(f"Unsupported decoder type '{decoder_type}'; use 'regex' or 'kv'")
    except yaml.YAMLError as e:
        raise HTTPException(status_code=422, detail=f"Invalid YAML: {e}")
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
