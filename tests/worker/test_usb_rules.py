"""usb lines from agent/internal/usbguard: the decoder and one rule per
outcome (unapproved connect: low, blocked: medium, block failed: high;
allowed devices and removals: none). Lines are what Guard.report writes."""
import asyncio
import glob
import json
import os

import pytest
import yaml

from worker.decoder_engine import DecoderEngine
from worker.sigma_engine import SigmaEngine

ROOT = os.path.join(os.path.dirname(__file__), "../..")
_LOOP = asyncio.new_event_loop()


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


def line(action, mode, allowed=False, error=None):
    rec = {"event": "usb_storage", "action": action, "mode": mode, "device": "/devices/pci0000:00/usb1/1-2",
           "vendor_id": "0781", "product_id": "5567", "serial": "4C5300012311", "vendor": "SanDisk",
           "product": "Cruzer Blade", "allowed": allowed, "blocked": action == "blocked",
           "time": "2026-11-15T08:00:00Z"}
    if error:
        rec["error"] = error
    return json.dumps(rec)


def titles(decoders, rules, raw):
    event, name = decoders.decode_named("usb", raw)
    assert name == "usb"
    view = dict(event, raw_message=raw, log_type="usb", hostname="ws-07")
    return event, {m["title"] for m in _LOOP.run_until_complete(rules.evaluate(view))}


def test_decoder_fields(decoders, rules):
    event, _ = titles(decoders, rules, line("blocked", "block"))
    assert (event["device.vendor_id"], event["device.product_id"], event["device.serial_number"]) == \
        ("0781", "5567", "4C5300012311")
    assert event["device.manufacturer"] == "SanDisk" and event["device.model.name"] == "Cruzer Blade"
    assert event["event.action"] == "usb_storage" and event["usb.action"] == "blocked"


@pytest.mark.parametrize("action,mode,allowed,error,want", [
    ("connected", "audit", False, None, {"USB Storage Device Connected"}),
    ("connected", "audit", True, None, set()),          # on the allow list
    ("connected", "block", True, None, set()),
    ("blocked", "block", False, None, {"USB Storage Device Blocked"}),
    ("block_failed", "block", False, "eject vetoed (type 6) by explorer.exe", {"USB Storage Device Not Blocked"}),
    ("removed", "audit", False, None, set()),
])
def test_one_rule_per_outcome(decoders, rules, action, mode, allowed, error, want):
    _, fired = titles(decoders, rules, line(action, mode, allowed, error))
    assert {t for t in fired if "USB" in t} == want
