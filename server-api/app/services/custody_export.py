# server-api/app/services/custody_export.py
"""Signed chain-of-custody incident export: bundles a case, its full
unified timeline, and the alerts it touches into a canonical document,
hashes each section, and signs the whole bundle with HMAC-SHA256 so a
recipient can later prove the export was not altered after it left the
platform."""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from app.core.config import settings

EXPORT_SCHEMA_VERSION = "1.0"
SIGNATURE_ALGORITHM = "HMAC-SHA256"


def _canonical_json(data: Any) -> str:
    """Deterministic JSON: sorted keys, no incidental whitespace, so the same
    logical content always hashes/signs to the same bytes."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def _sha256_hex(data: Any) -> str:
    return hashlib.sha256(_canonical_json(data).encode("utf-8")).hexdigest()


def _signing_key() -> bytes:
    secret = settings.EXPORT_SIGNING_SECRET or settings.JWT_SECRET
    # Domain-separate the derived fallback key from the raw JWT secret so an
    # export signature can never be reconstructed from JWT-signing context
    # alone, even when no dedicated EXPORT_SIGNING_SECRET has been set.
    if not settings.EXPORT_SIGNING_SECRET:
        secret = hashlib.sha256(f"export-signing:{secret}".encode("utf-8")).hexdigest()
    return secret.encode("utf-8")


def build_export_bundle(
    *,
    case: dict,
    timeline_items: list[dict],
    alerts: list[dict],
    exported_by: str,
    exported_at: str,
) -> dict:
    """Build the unsigned export bundle. Each section carries its own
    SHA-256 hash (an "artifact hash") so a section can be checked
    independently of the whole, in addition to the overall bundle signature."""
    sections = {
        "case": case,
        "timeline": timeline_items,
        "alerts": alerts,
    }
    artifact_hashes = {name: _sha256_hex(content) for name, content in sections.items()}
    return {
        "schema_version": EXPORT_SCHEMA_VERSION,
        "exported_by": exported_by,
        "exported_at": exported_at,
        "sections": sections,
        "artifact_hashes": artifact_hashes,
    }


def sign_bundle(bundle: dict) -> str:
    mac = hmac.new(_signing_key(), _canonical_json(bundle).encode("utf-8"), hashlib.sha256)
    return mac.hexdigest()


def verify_bundle(bundle: dict, signature: str) -> dict:
    """Re-derive the signature and each artifact hash and compare. Returns a
    verdict dict rather than a bare bool so a caller can see exactly what
    diverged (the signature itself, or one specific section) rather than
    just "tampered"."""
    expected_signature = sign_bundle(bundle)
    signature_valid = hmac.compare_digest(expected_signature, signature)

    recorded_hashes = bundle.get("artifact_hashes", {})
    sections = bundle.get("sections", {})
    section_results = {}
    for name, content in sections.items():
        recomputed = _sha256_hex(content)
        section_results[name] = recomputed == recorded_hashes.get(name)

    return {
        "signature_valid": signature_valid,
        "sections_valid": section_results,
        "valid": signature_valid and all(section_results.values()),
    }
