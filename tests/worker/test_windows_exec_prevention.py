# tests/worker/test_windows_exec_prevention.py
"""Windows execution prevention lines (agent/internal/prevent, engine=etw):
a terminated block-rule match is a high alert, a detect-only match is
telemetry; Windows paths escaped by kv() decode back."""
import asyncio
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest

from worker.decoder_engine import DecoderEngine
from worker.sigma_engine import SigmaEngine

ROOT = os.path.join(os.path.dirname(__file__), "../..")

# As Decision.line formats them (kv escapes backslashes).
TERMINATED = ('action=terminated rule="no nc" rule_id="r1" rule_type=path engine=etw '
              'Image="C:\\\\Tools\\\\nc.exe" ParentImage="C:\\\\Windows\\\\System32\\\\cmd.exe" '
              'Comm="nc.exe" PID=4040 PPID=3030 User=0')
DETECTED = TERMINATED.replace("action=terminated", "action=detected")
REFUSED = DETECTED + ' Error="protected Windows process cmd.exe"'


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
    event, name = decoders.decode_named("windows_exec_prevention", TERMINATED)
    assert name == "windows_exec_prevention"
    assert event["prevention.action"] == "terminated" and event["prevention.engine"] == "etw"
    assert event["Image"] == "C:\\Tools\\nc.exe"
    assert event["ParentImage"] == "C:\\Windows\\System32\\cmd.exe"
    assert event["rule.name"] == "no nc" and event["process.pid"] == "4040"
    event, _ = decoders.decode_named("windows_exec_prevention", REFUSED)
    assert event["prevention.error"] == "protected Windows process cmd.exe"


@pytest.mark.parametrize("line,expected", [
    (TERMINATED, [("Execution Terminated By Prevention Rule On Windows", "high")]),
    (DETECTED, []),
    (REFUSED, []),
])
def test_alerts(decoders, rules, line, expected):
    event, _ = decoders.decode_named("windows_exec_prevention", line)
    view = dict(event, raw_message=line, log_type="windows_exec_prevention", hostname="win01")
    got = [(m["title"], m["level"]) for m in asyncio.run(rules.evaluate(view))]
    assert got == expected
