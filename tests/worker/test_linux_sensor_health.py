# tests/worker/test_linux_sensor_health.py
"""The Linux sensor's own tamper checks (agent/internal/linsensor/health.go)
decode and alert: an overwritten self map is critical, a blind sensor high,
a recovery is only logged."""
import asyncio
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest

from worker.decoder_engine import DecoderEngine
from worker.sigma_engine import SigmaEngine

ROOT = os.path.join(os.path.dirname(__file__), "../..")

# As TestSelfLine / TestCanaryReportsOnlyChanges format them.
SELF = "event=self_map_overwritten expected_tgid=812 found_tgid=4242 restored=true"
BLIND = ('event=sensor_blind check=canary waited_seconds=15 last_seen=2026-11-02T02:00:00Z '
         'canary="/var/tmp/.siem-sensor-canary-812"')
RECOVERED = 'event=sensor_recovered check=canary canary="/var/tmp/.siem-sensor-canary-812"'


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
    event, name = decoders.decode_named("linux_sensor_health", SELF)
    assert name == "linux_sensor_health"
    assert event["event.action"] == "self_map_overwritten"
    assert event["sensor.found_tgid"] == "4242" and event["sensor.restored"] == "true"
    event, _ = decoders.decode_named("linux_sensor_health", BLIND)
    assert event["sensor.check"] == "canary" and event["sensor.last_seen"] == "2026-11-02T02:00:00Z"
    assert event["file.path"] == "/var/tmp/.siem-sensor-canary-812"


@pytest.mark.parametrize("line,expected", [
    (SELF, [("SIEM Agent Sensor Exclusion Tampered", "critical")]),
    (BLIND, [("SIEM Agent Sensor Blind", "high")]),
    (RECOVERED, []),
])
def test_alerts(decoders, rules, line, expected):
    event, _ = decoders.decode_named("linux_sensor_health", line)
    view = dict(event, raw_message=line, log_type="linux_sensor_health", hostname="web01")
    assert [(m["title"], m["level"]) for m in asyncio.run(rules.evaluate(view))] == expected
