from types import SimpleNamespace

import pytest
from app.api.routes.rules import _validate_rule_yaml, hunt_sigma
from app.api.routes.rules import test_rule as preview_rule
from app.core.sigma import JsonValue, evaluate_rule
from app.schemas.schemas import RuleTestRequest
from app.schemas.sigma import SigmaHuntRequest
from fastapi import HTTPException


def test_api_evaluator_supports_quantifiers_modifiers_and_nested_fields():
    # Given
    rule: dict[str, JsonValue] = {
        "detection": {
            "selection_shell": {"Image|endswith|nocase": "\\POWERSHELL.EXE"},
            "selection_network": {"source.ip|cidr": "10.0.0.0/8"},
            "condition": "all of selection_*",
        }
    }
    event: dict[str, JsonValue] = {
        "decoded_fields": {
            "Image": "C:\\Windows\\PowerShell.exe",
            "source.ip": "10.4.5.6",
        }
    }

    # When
    matched = evaluate_rule(rule, event)

    # Then
    assert matched is True


@pytest.mark.asyncio
async def test_rule_preview_evaluates_sample_event():
    # Given
    request = RuleTestRequest(
        content="""
title: Failed login
detection:
  selection:
    event.action: login_failed
  condition: selection
""",
        sample_event={"event.action": "login_success"},
    )

    # When
    response = await preview_rule(request, None)

    # Then
    assert response.matched is False
    assert response.rule_title == "Failed login"


def test_rule_validation_rejects_unknown_modifier():
    # Given
    rule = """
title: Invalid modifier
detection:
  selection:
    Image|unsupported: value
  condition: selection
"""

    # When / Then
    with pytest.raises(HTTPException) as exc_info:
        _validate_rule_yaml(rule)
    assert exc_info.value.status_code == 422


def test_rule_validation_accepts_legacy_internal_identifier():
    # Given
    from app.core.sigma_validator import validate_sigma_yaml

    rule = (
        "title: Legacy internal rule\n"
        "id: internal-ssh-rule\n"
        "detection:\n"
        "  selection:\n"
        "    event.action: login_failed\n"
        "  condition: selection\n"
    )

    # When
    validated = validate_sigma_yaml(rule)

    # Then
    assert validated is None


def test_sigma_query_compiler_maps_log_fields_to_logs_index_shape():
    # Given
    from app.core.sigma_query import compile_sigma_query

    rule = (
        "title: Historical shell hunt\n"
        "logsource:\n"
        "  product: windows\n"
        "detection:\n"
        "  selection:\n"
        "    Image|endswith: .exe\n"
        "    source.ip|cidr: 10.0.0.0/8\n"
        "  condition: selection\n"
    )

    # When
    compiled = compile_sigma_query(rule)

    # Then
    assert "decoded_fields.Image" in compiled.lucene
    assert "source_ip" in compiled.lucene
    assert compiled.body == {"query_string": {"query": compiled.lucene}}


@pytest.mark.asyncio
async def test_sigma_hunt_scopes_compiled_query_to_user_group(monkeypatch):
    # Given
    from app.api.routes import rules as rules_route

    captured: dict[str, JsonValue] = {}

    async def fake_search(
        query: dict[str, JsonValue], size: int, search_after: list[JsonValue] | None
    ) -> tuple[list[dict[str, JsonValue]], int, list[JsonValue] | None]:
        captured["query"] = query
        captured["size"] = size
        captured["search_after"] = search_after
        return ([{"id": "event-1", "group_id": "blue"}], 1, ["cursor"])

    monkeypatch.setattr(rules_route, "es_search", fake_search)
    request = SigmaHuntRequest(
        content=(
            "title: Grouped hunt\n"
            "logsource: {product: test}\n"
            "detection:\n"
            "  selection:\n"
            "    event.action: login_failed\n"
            "  condition: selection\n"
        ),
        size=25,
    )

    # When
    response = await hunt_sigma(request, SimpleNamespace(group_id="blue"))

    # Then
    assert response.total == 1
    assert response.matches[0]["id"] == "event-1"
    assert captured["query"]["bool"]["must"][1] == {"term": {"group_id": "blue"}}


def test_sigma_query_compiler_handles_or_selection_maps():
    # Given
    from app.core.sigma_query import compile_sigma_query

    rule = (
        "title: Alternate shell hunt\n"
        "logsource: {product: windows}\n"
        "detection:\n"
        "  selection:\n"
        "    - Image|endswith: powershell.exe\n"
        "    - Image|endswith: cmd.exe\n"
        "  condition: selection\n"
    )

    # When
    compiled = compile_sigma_query(rule)

    # Then
    assert "decoded_fields.Image" in compiled.lucene
