# tests/worker/test_sigma_engine.py
import sys, os
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
    matches = engine.evaluate(event)
    titles = [m["title"] for m in matches]
    assert "SSH Failed Login" in titles

def test_no_match(engine):
    event = {"event.action": "login_success"}
    matches = engine.evaluate(event)
    assert not any(m["title"] == "SSH Failed Login" for m in matches)

def test_contains_modifier(engine):
    event = {"request": "GET /.env HTTP/1.1"}
    matches = engine.evaluate(event)
    titles = [m["title"] for m in matches]
    assert "Access to .env file" in titles

def test_compound_and_condition(engine):
    event = {"event.action": "login_failed", "source.ip": "10.0.0.1"}
    matches = engine.evaluate(event)
    titles = [m["title"] for m in matches]
    assert "Compound Rule" in titles

def test_compound_and_fails_when_one_part_missing(engine):
    event = {"event.action": "login_failed", "source.ip": "8.8.8.8"}
    matches = engine.evaluate(event)
    titles = [m["title"] for m in matches]
    assert "Compound Rule" not in titles

def test_startswith_modifier(engine):
    event = {"source.ip": "10.5.6.7", "event.action": "login_failed"}
    matches = engine.evaluate(event)
    titles = [m["title"] for m in matches]
    assert "Compound Rule" in titles
