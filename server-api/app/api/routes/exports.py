# server-api/app/api/routes/exports.py
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.core.deps import get_current_user
from app.models.models import User
from app.services.custody_export import verify_bundle

router = APIRouter(prefix="/api/exports", tags=["exports"])


class VerifyExportRequest(BaseModel):
    export: dict
    signature: str


@router.post("/verify")
async def verify_export(
    body: VerifyExportRequest,
    _current_user: Annotated[User, Depends(get_current_user)],
):
    """Verify a chain-of-custody export bundle previously produced by
    `GET /api/cases/{case_id}/export`. Works on the bundle alone -- no
    database lookup -- so it can verify an export handed over long after the
    case (or even the exporting tenant) has changed or been deleted."""
    return verify_bundle(body.export, body.signature)
