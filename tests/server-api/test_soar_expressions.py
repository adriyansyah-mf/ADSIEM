import pytest

from app.services.soar_expressions import resolve_config, resolve_value

CONTEXT = {
    "trigger": {"alert": {"severity": "critical", "score": 91, "src": None}},
    "nodes": {"enrich": {"output": {"risk": 0.8, "tags": ["tor", "scanner"]}}},
    "vars": {"channel": "soc-alerts"},
}


def test_whole_string_expression_preserves_type():
    assert resolve_value("{{ trigger.alert.score }}", CONTEXT) == 91


def test_whole_string_expression_preserves_list():
    assert resolve_value("{{ nodes.enrich.output.tags }}", CONTEXT) == ["tor", "scanner"]


def test_interpolation_returns_string():
    assert resolve_value("sev={{ trigger.alert.severity }}!", CONTEXT) == "sev=critical!"


def test_missing_path_resolves_to_none():
    assert resolve_value("{{ trigger.alert.nothere }}", CONTEXT) is None


def test_missing_path_in_interpolation_renders_empty():
    assert resolve_value("x={{ a.b.c }}", CONTEXT) == "x="


def test_default_filter_applies_to_missing_path():
    assert resolve_value("{{ trigger.alert.nothere | default(7) }}", CONTEXT) == 7


def test_default_filter_ignored_when_path_resolves():
    assert resolve_value("{{ trigger.alert.score | default(7) }}", CONTEXT) == 91


def test_default_filter_applies_to_explicit_none():
    assert resolve_value("{{ trigger.alert.src | default('unknown') }}", CONTEXT) == "unknown"


def test_upper_and_lower_filters():
    assert resolve_value("{{ trigger.alert.severity | upper }}", CONTEXT) == "CRITICAL"
    assert resolve_value("{{ vars.channel | upper | lower }}", CONTEXT) == "soc-alerts"


def test_json_filter_serialises():
    assert resolve_value("{{ nodes.enrich.output.tags | json }}", CONTEXT) == '["tor", "scanner"]'


def test_unknown_filter_is_rejected():
    with pytest.raises(ValueError, match="unsupported filter"):
        resolve_value("{{ vars.channel | eval }}", CONTEXT)


def test_dunder_path_segment_is_rejected():
    with pytest.raises(ValueError, match="invalid path"):
        resolve_value("{{ vars.__class__ }}", CONTEXT)


def test_non_template_string_passes_through():
    assert resolve_value("plain text", CONTEXT) == "plain text"


def test_two_expressions_in_one_string_interpolate_separately():
    # Guards a real trap: a naive "^{{...}}$" test treats this whole string
    # as one expression whose path is `channel }} {{ trigger.alert.severity`.
    assert (
        resolve_value("{{ vars.channel }} {{ trigger.alert.severity }}", CONTEXT)
        == "soc-alerts critical"
    )


def test_resolve_config_walks_nested_structures():
    config = {
        "title": "Alert {{ trigger.alert.severity }}",
        "meta": {"risk": "{{ nodes.enrich.output.risk }}"},
        "tags": ["{{ vars.channel }}", "static"],
        "count": 3,
    }
    assert resolve_config(config, CONTEXT) == {
        "title": "Alert critical",
        "meta": {"risk": 0.8},
        "tags": ["soc-alerts", "static"],
        "count": 3,
    }
