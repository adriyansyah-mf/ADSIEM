import os
import sys

import anyio

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

from worker.sigma_engine import SigmaEngine
from worker.sigma_matcher import JsonValue


def _matches_single_rule(rule: str, event: dict[str, JsonValue]) -> bool:
    engine = SigmaEngine()
    _ = engine.load_from_yaml_list([rule])
    return bool(anyio.run(engine.evaluate, event))


def test_one_of_wildcard_selector_matches_one_selection():
    # Given
    rule = """
title: Suspicious shell
detection:
  selection_bash:
    Image|endswith: /bash
  selection_zsh:
    Image|endswith: /zsh
  condition: 1 of selection_*
"""

    # When
    matched = _matches_single_rule(rule, {"Image": "/usr/bin/zsh"})

    # Then
    assert matched is True


def test_all_of_them_requires_every_selection():
    # Given
    rule = """
title: Encoded shell
detection:
  shell:
    Image|endswith: /bash
  encoded:
    CommandLine|contains: base64
  condition: all of them
"""

    # When
    matched = (
        _matches_single_rule(
            rule,
            {"Image": "/usr/bin/bash", "CommandLine": "bash -c base64 payload"},
        ),
        _matches_single_rule(rule, {"Image": "/usr/bin/bash"}),
    )

    # Then
    assert matched == (True, False)


def test_parentheses_override_boolean_precedence():
    # Given
    rule = """
title: Grouped condition
detection:
  selection_a:
    event.action: denied
  selection_b:
    event.action: login
  selection_c:
    source.ip: 10.0.0.1
  condition: (selection_a or selection_b) and selection_c
"""

    # When
    matched = _matches_single_rule(
        rule,
        {"event.action": "login", "source.ip": "10.0.0.1"},
    )

    # Then
    assert matched is True


def test_list_of_selection_maps_uses_or_semantics():
    # Given
    rule = """
title: Shell family
detection:
  selection:
    - Image|endswith: /bash
    - Image|endswith: /zsh
  condition: selection
"""

    # When
    matched = _matches_single_rule(rule, {"Image": "/usr/bin/zsh"})

    # Then
    assert matched is True


def test_all_modifier_requires_every_list_value():
    # Given
    rule = """
title: Download and execute
detection:
  selection:
    CommandLine|contains|all:
      - curl
      - chmod
  condition: selection
"""

    # When
    matched = (
        _matches_single_rule(rule, {"CommandLine": "curl payload && chmod +x payload"}),
        _matches_single_rule(rule, {"CommandLine": "curl payload"}),
    )

    # Then
    assert matched == (True, False)


def test_default_string_matching_supports_sigma_wildcards():
    # Given
    rule = """
title: PowerShell executable
detection:
  selection:
    Image: '*\\\\powershell?.exe'
  condition: selection
"""

    # When
    matched = _matches_single_rule(rule, {"Image": "C:\\Windows\\powershell7.exe"})

    # Then
    assert matched is True


def test_nocase_modifier_normalizes_string_matching():
    # Given
    rule = """
title: Case-insensitive command
detection:
  selection:
    CommandLine|contains|nocase: WHOAMI
  condition: selection
"""

    # When
    matched = _matches_single_rule(rule, {"CommandLine": "cmd /c whoami"})

    # Then
    assert matched is True


def test_exists_modifier_matches_missing_field():
    # Given
    rule = """
title: Missing image
detection:
  selection:
    Image|exists: false
  condition: selection
"""

    # When
    matched = _matches_single_rule(rule, {"CommandLine": "id"})

    # Then
    assert matched is True


def test_cidr_modifier_matches_ip_inside_network():
    # Given
    rule = """
title: Internal source
detection:
  selection:
    source.ip|cidr: 10.0.0.0/8
  condition: selection
"""

    # When
    matched = _matches_single_rule(rule, {"source.ip": "10.20.30.40"})

    # Then
    assert matched is True


def test_invalid_modifier_is_reported_and_rule_is_not_loaded():
    # Given
    engine = SigmaEngine()
    rule = """
title: Unsupported modifier
detection:
  selection:
    Image|unsupported: value
  condition: selection
"""

    # When
    errors = engine.load_from_yaml_list([rule])

    # Then
    assert errors is not None
    assert len(errors) == 1
    assert errors[0].title == "Unsupported modifier"


def test_pysigma_validator_accepts_legacy_internal_identifier():
    # Given
    from worker.sigma_validator import validate_sigma_yaml

    rule = (
        "title: Legacy internal rule\n"
        "id: internal-ssh-rule\n"
        "detection:\n"
        "  selection:\n"
        "    event.action: login_failed\n"
        "  condition: selection\n"
    )

    # When
    assert validate_sigma_yaml(rule) is None

    # Then


def test_sigma_match_carries_rule_context_for_ai_triage():
    # Given
    engine = SigmaEngine()
    rule = (
        "title: PowerShell download\n"
        "logsource:\n"
        "  product: windows\n"
        "  service: powershell\n"
        "tags: [attack.execution]\n"
        "detection:\n"
        "  selection:\n"
        "    process.command_line|contains: Invoke-WebRequest\n"
        "  condition: selection\n"
    )

    # When
    assert engine.load_from_yaml_list([rule]) == []
    matches = anyio.run(engine.evaluate, {"process.command_line": "Invoke-WebRequest https://example.test"})

    # Then
    assert matches[0]["sigma_rule"]["title"] == "PowerShell download"
    assert matches[0]["sigma_rule"]["condition"] == "selection"
    assert matches[0]["sigma_rule"]["logsource"]["service"] == "powershell"
    assert matches[0]["sigma_rule"]["tags"] == ["attack.execution"]
    assert matches[0]["matched_fields"]["process.command_line"].startswith("Invoke-WebRequest")
