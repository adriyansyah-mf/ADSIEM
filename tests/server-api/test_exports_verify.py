from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.routes.exports import router as exports_router
from app.core.deps import get_current_user
from app.services.custody_export import build_export_bundle, sign_bundle


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(exports_router)
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(id=uuid4())
    return TestClient(app)


def _bundle():
    return build_export_bundle(
        case={"id": "c1"}, timeline_items=[], alerts=[],
        exported_by="u1", exported_at="2026-09-07T00:00:00Z",
    )


def test_verify_endpoint_confirms_valid_bundle():
    bundle = _bundle()
    signature = sign_bundle(bundle)
    client = _client()

    response = client.post("/api/exports/verify", json={"export": bundle, "signature": signature})

    assert response.status_code == 200
    assert response.json()["valid"] is True


def test_verify_endpoint_rejects_tampered_bundle():
    bundle = _bundle()
    signature = sign_bundle(bundle)
    bundle["sections"]["case"]["id"] = "tampered"
    client = _client()

    response = client.post("/api/exports/verify", json={"export": bundle, "signature": signature})

    assert response.status_code == 200
    assert response.json()["valid"] is False


def test_verify_endpoint_requires_authentication():
    app = FastAPI()
    app.include_router(exports_router)
    client = TestClient(app)

    response = client.post("/api/exports/verify", json={"export": _bundle(), "signature": "x"})

    assert response.status_code in (401, 403)
