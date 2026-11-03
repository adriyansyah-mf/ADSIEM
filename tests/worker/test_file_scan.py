# tests/worker/test_file_scan.py
"""The agent's file_scan lines (agent/internal/fullscan) decode with
decoders/file_scan.yaml; ml_detection lines carry the scan as trigger."""
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest

from worker.decoder_engine import DecoderEngine

ROOT = os.path.join(os.path.dirname(__file__), "../..")


@pytest.fixture(scope="module")
def decoders():
    import yaml
    dec = DecoderEngine()
    files = sorted(glob.glob(os.path.join(ROOT, "decoders/*.yaml")))
    dec.load_from_yaml_list(sorted([open(p).read() for p in files], key=lambda c: yaml.safe_load(c).get("priority", 100)))
    return dec


def test_summary_line(decoders):
    # as fullscan.Summary.line formats it (see TestCustomScanWalksSkipsAndCounts)
    raw = ('event=file_scan status=completed scan_id=414eaf0699592b1b kind=full files=120394 bytes=9876543210 '
           'detections=2 errors=3 skipped=40 duration=3712 requested="task 7c1d" roots="C:\\\\;D:\\\\"')
    event, name = decoders.decode_named("file_scan", raw)
    assert name == "file_scan"
    assert event["scan.status"] == "completed" and event["scan.kind"] == "full"
    assert event["scan.files"] == "120394" and event["scan.detections"] == "2"
    assert event["scan.requested"] == "task 7c1d" and event["scan.roots"] == "C:\\;D:\\"
    assert event["event.action"] == "file_scan"


def test_ml_line_names_the_scan(decoders):
    raw = ('event=ml_detection action=detected level=malicious kind=pe engine=ember2024_lgbm score=0.9990 '
           'threshold=0.9500 sha256=' + "ab" * 32 + ' path="C:\\\\old\\\\x.exe" size=10 trigger=full_scan')
    event, _ = decoders.decode_named("ml_detection", raw)
    assert event["ml.trigger"] == "full_scan"
