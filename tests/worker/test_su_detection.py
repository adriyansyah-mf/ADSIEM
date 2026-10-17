# tests/worker/test_su_detection.py
"""su to root / failed su: the shipped decoders and rules, end to end."""
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
def engines():
    import yaml
    # the worker loads decoders ordered by priority (consumer.load_engines)
    decoders = sorted(_load("decoders/*.yaml"), key=lambda c: yaml.safe_load(c).get("priority", 100))
    dec = DecoderEngine()
    dec.load_from_yaml_list(decoders)
    sig = SigmaEngine()
    sig.load_from_yaml_list(_load("rules/*.yaml"))
    assert not sig.load_errors, sig.load_errors
    return dec, sig


def _alerts(engines, line):
    dec, sig = engines
    event = dec.decode("linux_auth", line)
    return event, [m["title"] for m in asyncio.run(sig.evaluate(dict(event, raw_message=line)))]


def test_su_to_root_is_decoded_and_alerts(engines):
    event, titles = _alerts(engines, "Oct 18 02:41:06 cortex su[3190011]: (to root) solusi247 on pts/3")
    assert event["event.action"] == "su_command"
    assert (event["user.name"], event["user.target"], event["process.tty"]) == ("solusi247", "root", "pts/3")
    assert "Interactive Switch to Root via su" in titles


def test_su_to_another_user_does_not_alert(engines):
    event, titles = _alerts(engines, "Oct 18 02:41:06 cortex su[1]: (to postgres) solusi247 on pts/3")
    assert event["event.action"] == "su_command" and event["user.target"] == "postgres"
    assert "Interactive Switch to Root via su" not in titles


@pytest.mark.parametrize("line,user", [
    ("Oct 18 02:50:00 cortex su[9]: FAILED SU (to root) mallory on pts/1", "mallory"),
    ("Oct 18 02:50:00 socwaf su[9]: pam_unix(su-l:auth): authentication failure; logname=mallory "
     "uid=1001 euid=0 tty=pts/1 ruser=mallory rhost=  user=root", "mallory"),
])
def test_failed_su_is_decoded_and_alerts(engines, line, user):
    event, titles = _alerts(engines, line)
    assert event["event.action"] == "su_failed" and event["user.name"] == user
    assert event["user.target"] == "root"
    assert "Failed su Authentication" in titles


def test_repeated_failed_su_escalates(engines):
    dec, _ = engines
    sig = SigmaEngine()  # fresh engine: threshold windows are per instance without Redis
    sig.load_from_yaml_list(_load("rules/su_failed*.yaml"))
    line = "Oct 18 02:50:00 cortex su[9]: FAILED SU (to root) eve on pts/1"
    titles = []
    for _ in range(3):
        event = dec.decode("linux_auth", line)
        titles.append([m["title"] for m in asyncio.run(sig.evaluate(event))])
    assert not any(t.startswith("Repeated Failed su Attempts") for t in titles[0] + titles[1])
    assert any(t.startswith("Repeated Failed su Attempts [3x in 300s from eve]") for t in titles[2])


def test_existing_auth_decoders_still_win_for_their_lines(engines):
    dec, _ = engines
    assert dec.decode("linux_auth", "sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2")["event.action"] == "login_failed"
    assert dec.decode("linux_auth", "sudo:  alice : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash")["event.action"] == "sudo_command"
    assert dec.decode("linux_auth", "su: pam_unix(su:session): session opened for user root by alice(uid=1000)")["event.action"] == "session_opened"
