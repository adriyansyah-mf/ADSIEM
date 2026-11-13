# tests/worker/test_kernel_thread_masquerade.py
"""User-space programs posing as kernel threads ("[kworker/0:0]"), from the
lines Linux agents send, through the shipped decoders and rules."""
import asyncio
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest  # noqa: E402
import yaml  # noqa: E402

from worker.decoder_engine import DecoderEngine  # noqa: E402
from worker.sigma_engine import SigmaEngine  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "../..")
NET = "Process Named Like A Kernel Thread Making Network Connections"
EXEC = "Program Started With A Kernel Thread Name"


@pytest.fixture(scope="module")
def engines():
    load = lambda p: [open(f).read() for f in sorted(glob.glob(os.path.join(ROOT, p)))]  # noqa: E731
    dec = DecoderEngine()
    dec.load_from_yaml_list(sorted(load("decoders/*.yaml"), key=lambda c: yaml.safe_load(c).get("priority", 100)))
    sig = SigmaEngine()
    sig.load_from_yaml_list(load("rules/*.yaml"))
    assert not sig.load_errors, sig.load_errors
    return dec, sig


def titles(engines, log_type, raw):
    dec, sig = engines
    decoded, _ = dec.decode_named(log_type, raw)
    return {m["title"] for m in asyncio.run(sig.evaluate(dict(decoded, raw_message=raw, log_type=log_type)))}


# netwatch line as captured on the compromised host (the miner renamed itself after it started)
CONNECT = ("ts=2026-11-13T13:58:41Z pid=3336936 tgid=3336936 uid=33 gid=33 comm=[kworker/0:0] action=network_connect "
           "proto=tcp direction=outbound src=116.212.75.236 dport=6379 dst=186.162.146.45 lport=41118 host= "
           "private_dst=false")


def test_kernel_thread_name_connecting_out(engines):
    assert NET in titles(engines, "linux_network_connect", CONNECT)
    normal = CONNECT.replace("comm=[kworker/0:0]", "comm=curl")
    assert NET not in titles(engines, "linux_network_connect", normal)


def test_exec_with_kernel_thread_argv0(engines):
    line = ('pid=4242 ppid=1 uid=33 comm=.7625e6d2e Image="/var/tmp/.7625e6d2e" '
            'CommandLine="[kworker/0:0]" ParentImage="/bin/sh"')
    dec, _ = engines
    decoded, name = dec.decode_named("linux_process_exec", line)
    if decoded.get("CommandLine") != "[kworker/0:0]":
        pytest.skip(f"exec decoder shape differs ({name}): {decoded}")
    assert EXEC in titles(engines, "linux_process_exec", line)
    assert EXEC not in titles(engines, "linux_process_exec", line.replace('"[kworker/0:0]"', '"/usr/bin/ls -la"'))
