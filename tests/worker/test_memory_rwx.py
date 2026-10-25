# tests/worker/test_memory_rwx.py
"""RWX sweep lines from agent/internal/memscan decode and alert, except for
JIT runtimes."""
import asyncio
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest

from worker.decoder_engine import DecoderEngine
from worker.sigma_engine import SigmaEngine

ROOT = os.path.join(os.path.dirname(__file__), "../..")


def line(image, kind="private"):
    # As TestSweepReportsOncePerRegion formats it (memscan.RWXLine).
    return f'Image="{image}" PID=42 Address=0x1f0000 Size=4096 Perms=rwx Kind={kind} Path=""'


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


def titles(decoders, rules, raw):
    event, name = decoders.decode_named("process_memory_rwx", raw)
    assert name == "process_memory_rwx"
    view = dict(event, raw_message=raw, log_type="process_memory_rwx", hostname="h")
    return [m["title"] for m in asyncio.run(rules.evaluate(view))]


def test_decode(decoders):
    event, _ = decoders.decode_named("process_memory_rwx", line("C:\\\\Users\\\\bob\\\\AppData\\\\Local\\\\Temp\\\\upd.exe"))
    assert event["process.executable"] == "C:\\Users\\bob\\AppData\\Local\\Temp\\upd.exe"
    assert event["memory.address"] == "0x1f0000" and event["memory.permissions"] == "rwx"


@pytest.mark.parametrize("image,alert", [
    ("/tmp/.x/implant", True),
    ("C:\\\\Users\\\\bob\\\\AppData\\\\Local\\\\Temp\\\\upd.exe", True),
    ("/usr/lib/jvm/java-17/bin/java", False),
    ("/usr/lib/firefox-esr/firefox-esr", False),
    ("C:\\\\Program Files\\\\Google\\\\Chrome\\\\Application\\\\chrome.exe", False),
])
def test_alert(decoders, rules, image, alert):
    assert titles(decoders, rules, line(image)) == (["Writable And Executable Memory In Process"] if alert else [])
