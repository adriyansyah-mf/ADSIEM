# tests/worker/test_app_control.py
"""Windows App Control (agent/internal/appcontrol): the agent's policy events
and the CodeIntegrity blocks they cause, through the shipped decoders and rules."""
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
def engines():
    dec = DecoderEngine()
    dec.load_from_yaml_list(sorted(_load("decoders/*.yaml"), key=lambda c: yaml.safe_load(c).get("priority", 100)))
    sig = SigmaEngine()
    sig.load_from_yaml_list(_load("rules/*.yaml"))
    assert not sig.load_errors, sig.load_errors
    return dec, sig


def titles(engines, log_type, line):
    dec, sig = engines
    event, name = dec.decode_named(log_type, line)
    return event, name, {m["title"] for m in asyncio.run(sig.evaluate(dict(event, raw_message=line, log_type=log_type)))}


# EventID=... line as agent/internal/winevent writes CodeIntegrity 3077 / 3076
CI = ('EventID={id} Channel="Microsoft-Windows-CodeIntegrity/Operational" '
      'Provider="Microsoft-Windows-CodeIntegrity" Computer="WIN01" RecordID="812" '
      'FileName="\\Device\\HarddiskVolume3\\Users\\Public\\evil.exe" '
      'PolicyName="SIEM Agent App Control" ProcessName="\\Device\\HarddiskVolume3\\Windows\\explorer.exe" '
      'SHA256Hash="AB12"')


@pytest.mark.parametrize("event_id,title", [
    ("3077", "App Control Blocked A Program"),
    ("3076", "App Control Would Block A Program (Audit)"),
])
def test_codeintegrity_events(engines, event_id, title):
    event, name, fired = titles(engines, "windows_codeintegrity", CI.format(id=event_id))
    assert name == "win_codeintegrity_generic"
    assert event["file.path"].endswith("\\Users\\Public\\evil.exe") and event["rule.name"] == "SIEM Agent App Control"
    assert {t for t in fired if t.startswith("App Control")} == {title}


def test_policy_failure_is_an_alert_and_success_is_not(engines):
    failed = json.dumps({"event": "app_control_failed", "mode": "enforce", "rules": 3, "method": "",
                         "error": "powershell: Import-Module ConfigCI: not found", "policy_id": "{X}"})
    event, name, fired = titles(engines, "app_control", failed)
    assert name == "app_control" and event["app_control.mode"] == "enforce"
    assert "Agent Could Not Apply App Control Policy" in fired
    applied = json.dumps({"event": "app_control_applied", "mode": "enforce", "rules": 3, "method": "citool"})
    assert "Agent Could Not Apply App Control Policy" not in titles(engines, "app_control", applied)[2]
