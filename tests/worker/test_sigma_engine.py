# tests/worker/test_sigma_engine.py
import sys, os, asyncio
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../worker'))
import pytest
from worker.sigma_engine import SigmaEngine

RULE_SSH_FAILED = """
title: SSH Failed Login
id: rule-ssh-failed
logsource:
  product: linux
detection:
  selection:
    event.action: login_failed
  condition: selection
level: medium
"""

RULE_NGINX_ENV = """
title: Access to .env file
id: rule-nginx-env
logsource:
  product: nginx
detection:
  selection:
    request|contains: ".env"
  condition: selection
level: high
"""

RULE_COMPOUND = """
title: Compound Rule
id: rule-compound
logsource:
  product: linux
detection:
  selection_a:
    event.action: login_failed
  selection_b:
    source.ip|startswith: "10."
  condition: selection_a and selection_b
level: medium
"""

@pytest.fixture
def engine():
    e = SigmaEngine()
    e.load_from_yaml_list([RULE_SSH_FAILED, RULE_NGINX_ENV, RULE_COMPOUND])
    return e

def test_exact_match(engine):
    event = {"event.action": "login_failed"}
    matches = asyncio.run(engine.evaluate(event))
    titles = [m["title"] for m in matches]
    assert "SSH Failed Login" in titles

def test_no_match(engine):
    event = {"event.action": "login_success"}
    matches = asyncio.run(engine.evaluate(event))
    assert not any(m["title"] == "SSH Failed Login" for m in matches)

def test_contains_modifier(engine):
    event = {"request": "GET /.env HTTP/1.1"}
    matches = asyncio.run(engine.evaluate(event))
    titles = [m["title"] for m in matches]
    assert "Access to .env file" in titles

def test_compound_and_condition(engine):
    event = {"event.action": "login_failed", "source.ip": "10.0.0.1"}
    matches = asyncio.run(engine.evaluate(event))
    titles = [m["title"] for m in matches]
    assert "Compound Rule" in titles

def test_compound_and_fails_when_one_part_missing(engine):
    event = {"event.action": "login_failed", "source.ip": "8.8.8.8"}
    matches = asyncio.run(engine.evaluate(event))
    titles = [m["title"] for m in matches]
    assert "Compound Rule" not in titles

def test_startswith_modifier(engine):
    event = {"source.ip": "10.5.6.7", "event.action": "login_failed"}
    matches = asyncio.run(engine.evaluate(event))
    titles = [m["title"] for m in matches]
    assert "Compound Rule" in titles


# ─── Sigma spec coverage ─────────────────────────────────────────

def _titles(rules: list[str], event: dict) -> list[str]:
    e = SigmaEngine()
    e.load_from_yaml_list(rules)
    assert not e.load_errors, e.load_errors
    return [m["title"] for m in asyncio.run(e.evaluate(event))]


def _rule(detection: str, title: str = "t") -> str:
    return f"title: {title}\nid: {title}\ndetection:\n" + detection


@pytest.mark.parametrize("detection,event,expected", [
    # default string matching is case-insensitive; `cased` opts out
    ("  s:\n    CommandLine|contains: 'base64 -d'\n  condition: s", {"CommandLine": "echo x | BASE64 -D"}, True),
    ("  s:\n    CommandLine|contains|cased: 'base64 -d'\n  condition: s", {"CommandLine": "echo x | BASE64 -D"}, False),
    # wildcards, and escaped wildcards
    ("  s:\n    Image: '/tmp/*'\n  condition: s", {"Image": "/tmp/payload"}, True),
    ("  s:\n    Image: '/tmp/?.sh'\n  condition: s", {"Image": "/tmp/ab.sh"}, False),
    # per spec `\*` is a literal star; a backslash followed by a wildcard is `\\*`
    ("  s:\n    Path: 'C:\\Windows\\\\*'\n  condition: s", {"Path": "c:\\windows\\system32"}, True),
    ("  s:\n    Path: 'C:\\Windows\\*'\n  condition: s", {"Path": "c:\\windows\\system32"}, False),
    ("  s:\n    Name: 'a\\*b'\n  condition: s", {"Name": "axxb"}, False),
    # contains|all needs every value; plain list needs any
    ("  s:\n    CommandLine|contains|all: ['curl', '| sh']\n  condition: s", {"CommandLine": "curl http://x | sh"}, True),
    ("  s:\n    CommandLine|contains|all: ['curl', '| sh']\n  condition: s", {"CommandLine": "curl http://x"}, False),
    # list of maps is an OR of ANDs
    ("  s:\n    - Image|endswith: '/nc'\n    - Image|endswith: '/ncat'\n  condition: s", {"Image": "/usr/bin/ncat"}, True),
    # keywords search the raw log line
    ("  keywords:\n    - 'mimikatz'\n  condition: keywords", {"raw_message": "running Mimikatz now"}, True),
    # cidr, numeric comparisons, exists, null
    ("  s:\n    source.ip|cidr: '10.0.0.0/8'\n  condition: s", {"source.ip": "10.1.2.3"}, True),
    ("  s:\n    source.ip|cidr: '10.0.0.0/8'\n  condition: s", {"source.ip": "not-an-ip"}, False),
    ("  s:\n    bytes|gte: 1000\n  condition: s", {"bytes": "4096"}, True),
    ("  s:\n    bytes|lt: 1000\n  condition: s", {"bytes": 4096}, False),
    ("  s:\n    user.name|exists: true\n  condition: s", {"user.name": "root"}, True),
    ("  s:\n    user.name|exists: false\n  condition: s", {"user.name": "root"}, False),
    ("  s:\n    ParentImage: null\n  condition: s", {"Image": "/bin/sh"}, True),
    # regex with sub-modifier flags
    ("  s:\n    CommandLine|re: 'WGET'\n  condition: s", {"CommandLine": "wget x"}, False),
    ("  s:\n    CommandLine|re|i: 'WGET'\n  condition: s", {"CommandLine": "wget x"}, True),
    # encodings
    ("  s:\n    CommandLine|base64offset|contains: 'http://'\n  condition: s", {"CommandLine": "echo aHR0cDovL2V2aWw= | base64 -d"}, True),
    ("  s:\n    CommandLine|windash|contains: ' -enc '\n  condition: s", {"CommandLine": "powershell /enc AAA"}, True),
    # fieldref
    ("  s:\n    user.name|fieldref: user.target\n  condition: s", {"user.name": "bob", "user.target": "BOB"}, True),
    # list-valued event fields match on any element
    ("  s:\n    tags: 'evil'\n  condition: s", {"tags": ["ok", "evil"]}, True),
    # nested event dicts resolve dotted names
    ("  s:\n    process.name: sshd\n  condition: s", {"process": {"name": "sshd"}}, True),
])
def test_value_matching(detection, event, expected):
    assert bool(_titles([_rule(detection)], event)) is expected


@pytest.mark.parametrize("condition,event,expected", [
    ("a and (b or c)", {"Image": "/bin/bash", "User": "www-data"}, True),
    ("a and (b or c)", {"Image": "/bin/bash", "User": "nobody"}, False),
    ("a and not b", {"Image": "/bin/bash", "User": "root"}, False),
    ("not a or b", {"Image": "/bin/zsh"}, True),
    ("1 of sel_*", {"Image": "/usr/bin/wget"}, True),
    ("all of sel_*", {"Image": "/usr/bin/wget"}, False),
    ("1 of them", {"User": "www-data"}, True),
    ("all of them", {"Image": "/bin/bash", "User": "root"}, False),
    ("2 of them", {"Image": "/bin/bash", "User": "root"}, True),
])
def test_condition_grammar(condition, event, expected):
    detection = (
        "  a:\n    Image|endswith: '/bash'\n"
        "  b:\n    User: root\n"
        "  c:\n    User: www-data\n"
        "  sel_curl:\n    Image|endswith: '/curl'\n"
        "  sel_wget:\n    Image|endswith: '/wget'\n"
        f"  condition: {condition}\n"
    )
    assert bool(_titles([_rule(detection)], event)) is expected


def test_underscore_selections_are_excluded_from_them():
    detection = "  a:\n    User: root\n  _helper:\n    User: nobody\n  condition: all of them\n"
    assert _titles([_rule(detection)], {"User": "root"}) == ["t"]


@pytest.mark.parametrize("detection,fragment", [
    ("  s:\n    Image|bogus: x\n  condition: s", "unsupported modifier"),
    ("  s:\n    Image: x\n  condition: s and missing", "unknown selection"),
    ("  s:\n    Image: x\n  condition: (s", "missing ')'"),
    ("  s:\n    Image: x\n  condition: s | count() > 5", "aggregations"),
    ("  s:\n    Image|re: '('\n  condition: s", "invalid regex"),
    ("  s:\n    Image: x\n", "no 'condition'"),
])
def test_unsupported_syntax_is_rejected_not_silently_ignored(detection, fragment):
    e = SigmaEngine()
    e.load_from_yaml_list([_rule(detection, "bad"), _rule("  s:\n    Image: x\n  condition: s", "good")])
    assert [r.title for r in e._rules] == ["good"]
    assert len(e.load_errors) == 1 and fragment in e.load_errors[0][1]


# ─── Sigma correlation rules ─────────────────────────────────────

BASE_FAILED = """
title: Failed SSH
name: failed_ssh
detection:
  s:
    event.action: login_failed
  condition: s
level: low
"""


def _run(engine: SigmaEngine, events: list[dict]) -> list[list[str]]:
    return [[m["title"] for m in asyncio.run(engine.evaluate(ev))] for ev in events]


def test_event_count_correlation_groups_and_silences_base_rule():
    corr = """
title: SSH brute force
correlation:
  type: event_count
  rules: [failed_ssh]
  group-by: [source.ip]
  timespan: 5m
  condition:
    gte: 3
level: high
"""
    e = SigmaEngine()
    e.load_from_yaml_list([BASE_FAILED, corr])
    ev = lambda ip: {"event.action": "login_failed", "source.ip": ip}
    out = _run(e, [ev("1.1.1.1"), ev("2.2.2.2"), ev("1.1.1.1"), ev("1.1.1.1")])
    # generate defaults to false: the base rule only feeds the correlation
    assert out[:3] == [[], [], []]
    assert out[3] == ["SSH brute force [3 events in 300s for 1.1.1.1]"]
    # window resets after firing
    assert _run(e, [ev("1.1.1.1")]) == [[]]


def test_value_count_correlation_counts_distinct_values():
    corr = """
title: Password spraying
correlation:
  type: value_count
  rules: [failed_ssh]
  group-by: [source.ip]
  timespan: 10m
  condition:
    field: user.name
    gt: 2
  generate: true
"""
    e = SigmaEngine()
    e.load_from_yaml_list([BASE_FAILED, corr])
    ev = lambda user: {"event.action": "login_failed", "source.ip": "9.9.9.9", "user.name": user}
    out = _run(e, [ev("a"), ev("a"), ev("b"), ev("c")])
    assert out[0] == ["Failed SSH"]  # generate: true keeps the base alert
    assert not any("Password spraying" in t for t in out[0] + out[1] + out[2])
    assert "Password spraying [3 distinct user.name in 600s for 9.9.9.9]" in out[3]


def test_temporal_correlation_needs_every_rule_in_window():
    success = """
title: Successful SSH
name: ssh_success
detection:
  s:
    event.action: login_success
  condition: s
"""
    corr = """
title: Brute force then success
correlation:
  type: temporal
  rules: [failed_ssh, ssh_success]
  group-by: [source.ip]
  timespan: 1h
level: critical
"""
    e = SigmaEngine()
    e.load_from_yaml_list([BASE_FAILED + "\n---\n" + success, corr])
    assert not e.load_errors
    out = _run(e, [
        {"event.action": "login_failed", "source.ip": "5.5.5.5"},
        {"event.action": "login_success", "source.ip": "6.6.6.6"},
        {"event.action": "login_success", "source.ip": "5.5.5.5"},
    ])
    assert out[0] == [] and out[1] == []
    assert out[2] == ["Brute force then success [2 correlated rules in 3600s for 5.5.5.5]"]


def test_correlation_with_unknown_rule_is_rejected():
    corr = "title: c\ncorrelation:\n  type: event_count\n  rules: [nope]\n  timespan: 1m\n  condition:\n    gte: 2\n"
    e = SigmaEngine()
    e.load_from_yaml_list([BASE_FAILED, corr])
    assert e._correlations == []
    assert "unknown rule" in e.load_errors[0][1]
    # with the correlation rejected, the base rule alerts normally again
    assert _run(e, [{"event.action": "login_failed"}]) == [["Failed SSH"]]
