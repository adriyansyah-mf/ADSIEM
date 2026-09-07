from __future__ import annotations

from app.services.custody_export import build_export_bundle, sign_bundle, verify_bundle


def _bundle():
    return build_export_bundle(
        case={"id": "case-1", "title": "Brute force"},
        timeline_items=[{"type": "alert", "id": "a1", "ts": "2026-09-07T00:00:00Z"}],
        alerts=[{"id": "a1", "title": "Brute force", "severity": "high"}],
        exported_by="analyst-1",
        exported_at="2026-09-07T12:00:00Z",
    )


def test_build_export_bundle_includes_artifact_hash_per_section():
    bundle = _bundle()

    assert set(bundle["artifact_hashes"].keys()) == {"case", "timeline", "alerts"}
    assert all(len(h) == 64 for h in bundle["artifact_hashes"].values())


def test_sign_and_verify_round_trip_succeeds_on_untampered_bundle():
    bundle = _bundle()
    signature = sign_bundle(bundle)

    result = verify_bundle(bundle, signature)

    assert result["valid"] is True
    assert result["signature_valid"] is True
    assert all(result["sections_valid"].values())


def test_verify_detects_tampered_section_content():
    bundle = _bundle()
    signature = sign_bundle(bundle)

    bundle["sections"]["alerts"][0]["severity"] = "low"  # tamper after signing

    result = verify_bundle(bundle, signature)

    assert result["valid"] is False
    assert result["sections_valid"]["alerts"] is False
    # untouched sections still verify independently
    assert result["sections_valid"]["case"] is True


def test_verify_detects_wrong_signature():
    bundle = _bundle()

    result = verify_bundle(bundle, "0" * 64)

    assert result["valid"] is False
    assert result["signature_valid"] is False


def test_two_identical_bundles_produce_identical_signatures():
    bundle_a = _bundle()
    bundle_b = _bundle()

    assert sign_bundle(bundle_a) == sign_bundle(bundle_b)


def test_signature_changes_if_exported_by_changes():
    bundle_a = _bundle()
    bundle_b = build_export_bundle(
        case={"id": "case-1", "title": "Brute force"},
        timeline_items=[{"type": "alert", "id": "a1", "ts": "2026-09-07T00:00:00Z"}],
        alerts=[{"id": "a1", "title": "Brute force", "severity": "high"}],
        exported_by="analyst-2",
        exported_at="2026-09-07T12:00:00Z",
    )

    assert sign_bundle(bundle_a) != sign_bundle(bundle_b)
