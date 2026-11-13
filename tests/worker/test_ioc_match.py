# tests/worker/test_ioc_match.py
"""ioc_match lines from agent/internal/ipblock: the decoder and the two rules
(blocked: medium, not blocked: high). Lines are what Watcher.report writes."""
import asyncio
import glob
import json
import os

import pytest
import yaml

from worker.decoder_engine import DecoderEngine
from worker.sigma_engine import SigmaEngine

ROOT = os.path.join(os.path.dirname(__file__), "../..")


def _load(pattern):
    return [open(p).read() for p in sorted(glob.glob(os.path.join(ROOT, pattern)))]


@pytest.fixture(scope="module")
def decoders():
    dec = DecoderEngine()
    dec.load_from_yaml_list(sorted(_load("decoders/*.yaml"), key=lambda c: yaml.safe_load(c).get("priority", 100)))
    return dec


@pytest.fixture(scope="module")
def rules():
    sig = SigmaEngine()
    sig.load_from_yaml_list(_load("rules/*.yaml"))
    assert not sig.load_errors, sig.load_errors
    return sig


def line(blocked, mode):
    return json.dumps({"event": "ip_ioc_match", "ip": "45.33.32.156", "cidr": "45.33.32.156/32", "mode": mode,
                       "blocked": blocked, "direction": "outbound", "pid": "4242", "image": "C:\\Users\\a\\evil.exe",
                       "source": "soar", "reason": "SOAR run 7: Cobalt Strike beacon",
                       "telemetry": "windows_etw_network", "ts": "2026-11-13T08:00:00Z"})


def titles(decoders, rules, raw):
    event, name = decoders.decode_named("ioc_match", raw)
    assert name == "ioc_match"
    view = dict(event, raw_message=raw, log_type="ioc_match", hostname="win-01")
    return event, {m["title"] for m in asyncio.run(rules.evaluate(view))}


def test_decoder_fields(decoders, rules):
    event, _ = titles(decoders, rules, line(True, "block"))
    assert event["threat.indicator.ip"] == "45.33.32.156" and event["threat.indicator.cidr"] == "45.33.32.156/32"
    assert event["process.executable"] == "C:\\Users\\a\\evil.exe" and event["process.pid"] == "4242"
    assert event["threat.indicator.provider"] == "soar" and event["event.action"] == "ip_ioc_match"


@pytest.mark.parametrize("blocked,mode,want", [
    (True, "block", "Connection To IP IoC Blocked"),
    (False, "detect", "Connection To IP IoC Not Blocked"),
    (False, "block", "Connection To IP IoC Not Blocked"),  # the firewall could not take the list
])
def test_one_rule_per_outcome(decoders, rules, blocked, mode, want):
    _, fired = titles(decoders, rules, line(blocked, mode))
    assert {t for t in fired if "IP IoC" in t} == {want}
