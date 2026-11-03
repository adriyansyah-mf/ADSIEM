# tests/worker/test_ml_detection.py
"""The agent's ml_detection lines (agent/internal/mlscan) decode with
decoders/ml_detection.yaml and raise the Static ML rules by level and action."""
import asyncio
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest

from worker.decoder_engine import DecoderEngine
from worker.sigma_engine import SigmaEngine

ROOT = os.path.join(os.path.dirname(__file__), "../..")
SHA = "ab" * 32


def line(action="detected", level="malicious", kind="pe", engine="ember_lgbm", path="C:\\\\Users\\\\bob\\\\d.exe",
         extra=""):
    # As mlscan.Event.Line formats it (see TestCheckerModes).
    return (f"event=ml_detection action={action} level={level} kind={kind} engine={engine} score=0.9731 "
            f'threshold=0.8512 sha256={SHA} path="{path}" size=73728{extra}')


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


def test_pe_line_decodes(decoders):
    event, name = decoders.decode_named("ml_detection", line())
    assert name == "ml_detection"
    assert event["ml.level"] == "malicious" and event["ml.kind"] == "pe" and event["ml.engine"] == "ember_lgbm"
    assert event["ml.score"] == "0.9731" and event["ml.threshold"] == "0.8512"
    assert event["file.path"] == "C:\\Users\\bob\\d.exe" and event["file.hash.sha256"] == SHA
    assert event["event.category"] == "malware" and event["event.action"] == "ml_detection"


def test_elf_reasons_and_error(decoders):
    event, _ = decoders.decode_named("ml_detection", line(
        kind="elf", engine="elf_heuristic", path="/tmp/kdevtmpfsi",
        extra=' reasons="mining pool URL (stratum); XMRig miner" error="permission denied"'))
    assert event["ml.reasons"] == "mining pool URL (stratum); XMRig miner"
    assert event["error.message"] == "permission denied" and event["file.path"] == "/tmp/kdevtmpfsi"


def _titles(decoders, rules, raw):
    event, _ = decoders.decode_named("ml_detection", raw)
    flat = {**event, "log_type": "ml_detection", "raw_message": raw, "hostname": "h", "group_id": "default"}
    return {(m["title"], m["level"]) for m in asyncio.run(rules.evaluate(flat))}


@pytest.mark.parametrize("action,level,title,severity", [
    ("detected", "malicious", "Static ML Malicious File", "high"),
    ("quarantined", "malicious", "Static ML Malicious File Quarantined", "medium"),
    ("detected", "suspicious", "Static ML Suspicious File", "low"),
])
def test_alerts(decoders, rules, action, level, title, severity):
    assert _titles(decoders, rules, line(action=action, level=level)) == {(title, severity)}
