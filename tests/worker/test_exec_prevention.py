# tests/worker/test_exec_prevention.py
"""Decision lines from agent/internal/prevent decode and raise the blocked
(high) or detect-only (medium) alert."""
import asyncio
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest

from worker.decoder_engine import DecoderEngine
from worker.sigma_engine import SigmaEngine

ROOT = os.path.join(os.path.dirname(__file__), "../..")

# As TestDecisionLine / the e2e test produce them.
BLOCKED = ('action=blocked rule="web \\"shell\\"" rule_id="r1" rule_type=parent engine=lsm Image="/usr/bin/dash" '
           'ParentImage="php-fpm8.2" Comm="php-fpm8.2" PID=9 PPID=1 User=33')
DETECTED = ('action=detected rule="known bad hash" rule_id="r4" rule_type=hash engine=fanotify '
            'Image="/tmp/x.sh" ParentImage="/usr/bin/dash" '
            'SHA256=0ea5c28eb7118117abeeb88db1e298096acc7d057f0cb613189601f03515607a Comm="dash" PID=10 PPID=9 User=0')


def _load(pattern):
    return [open(p).read() for p in sorted(glob.glob(os.path.join(ROOT, pattern)))]


@pytest.fixture(scope="module")
def decoders():
    import yaml
    dec = DecoderEngine()
    dec.load_from_yaml_list(sorted(_load("decoders/*.yaml"), key=lambda c: yaml.safe_load(c).get("priority", 100)))
    return dec


@pytest.fixture(scope="module")
def rules():
    sig = SigmaEngine()
    sig.load_from_yaml_list(_load("rules/*.yaml"))
    assert not sig.load_errors, sig.load_errors
    return sig


def test_decode(decoders):
    event, name = decoders.decode_named("linux_exec_prevention", DETECTED)
    assert name == "linux_exec_prevention"
    assert event["rule.name"] == "known bad hash"
    assert event["prevention.engine"] == "fanotify"
    assert event["file.hash.sha256"].startswith("0ea5c2")
    assert event["process.executable"] == "/tmp/x.sh"
    event, _ = decoders.decode_named("linux_exec_prevention", BLOCKED)
    assert event["rule.name"] == 'web "shell"'
    assert event["rule.category"] == "parent"


@pytest.mark.parametrize("line,title,level", [
    (BLOCKED, "Execution Blocked By Prevention Rule On Linux", "high"),
    (DETECTED, "Execution Matched Detect-Only Prevention Rule On Linux", "medium"),
])
def test_alerts(decoders, rules, line, title, level):
    event, _ = decoders.decode_named("linux_exec_prevention", line)
    view = dict(event, raw_message=line, log_type="linux_exec_prevention", hostname="web01")
    assert [(m["title"], m["level"]) for m in asyncio.run(rules.evaluate(view))] == [(title, level)]
