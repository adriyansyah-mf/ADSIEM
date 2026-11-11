# tests/worker/test_credential_access.py
"""The agent's credential_access lines (agent/internal/credwatch) decode and
raise the alert for their store."""
import asyncio
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest

from worker.decoder_engine import DecoderEngine
from worker.sigma_engine import SigmaEngine

ROOT = os.path.join(os.path.dirname(__file__), "../..")


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


def line(store, target, image="C:\\\\Program Files\\\\nodejs\\\\node.exe"):
    # As credwatch.Line formats it.
    return (f'event=credential_access store={store} target="{target}" image="{image}" pid=4242 ppid=40 '
            'user="CORP\\\\alice"')


LOGIN = "C:\\\\Users\\\\alice\\\\AppData\\\\Local\\\\Google\\\\Chrome\\\\User Data\\\\Default\\\\Login Data"


def test_decodes(decoders):
    ev, name = decoders.decode_named("credential_access", line("browser_passwords", LOGIN))
    assert name == "credential_access" and ev["event.action"] == "credential_store_access"
    assert ev["credential.store"] == "browser_passwords"
    assert ev["file.path"] == "C:\\Users\\alice\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"
    assert ev["process.executable"] == "C:\\Program Files\\nodejs\\node.exe" and ev["process.pid"] == "4242"
    assert ev["process.parent.pid"] == "40" and ev["user.name"] == "CORP\\alice"


@pytest.mark.parametrize("store,title,level", [
    ("browser_passwords", "Browser or Wallet Credential Store Read by an Unexpected Program", "medium"),
    ("browser_master_key", "Browser or Wallet Credential Store Read by an Unexpected Program", "medium"),
    ("wallet_extension", "Browser or Wallet Credential Store Read by an Unexpected Program", "medium"),
    ("ssh_key", "SSH Key or Cloud Token Read by an Unexpected Program", "low"),
    ("cloud_credentials", "SSH Key or Cloud Token Read by an Unexpected Program", "low"),
])
def test_alerts(decoders, rules, store, title, level):
    raw = line(store, "/home/dev/x")
    ev, _ = decoders.decode_named("credential_access", raw)
    flat = {**ev, "log_type": "credential_access", "raw_message": raw, "hostname": "h", "group_id": "default"}
    got = {(m["title"], m["level"]) for m in asyncio.run(rules.evaluate(flat))}
    assert got == {(title, level)}
