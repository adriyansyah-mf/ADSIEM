# tests/worker/test_ip_iocs.py
"""IP IoC normalisation shared by server-api and the worker."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest  # noqa: E402

from worker.ip_iocs import IPError, normalize  # noqa: E402


@pytest.mark.parametrize("value,want", [
    ("45.33.32.156", "45.33.32.156/32"),
    (" 45.33.32.156/24 ", "45.33.32.0/24"),
    ("2606:4700:4700::1111", "2606:4700:4700::1111/128"),
    ("[2606:4700:4700::1111]", "2606:4700:4700::1111/128"),
    ("::ffff:45.33.32.156", "45.33.32.156/32"),
])
def test_normalize(value, want):
    assert normalize(value) == want


@pytest.mark.parametrize("value,why", [
    ("", "empty"), ("evil.example", "not an IP"), ("8.0.0.0/8", "too broad"), ("2606:4700::/32", "too broad"),
    ("127.0.0.1", "loopback"), ("0.0.0.0", "unspecified"), ("224.0.0.1", "multicast"),
    ("169.254.1.1", "link-local"), ("fe80::1", "link-local"), ("240.0.0.1", "reserved"),
    ("192.168.1.10", "private"), ("10.0.0.0/16", "private"), ("100.64.0.1", "private"),
])
def test_refused(value, why):
    with pytest.raises(IPError, match=why):
        normalize(value)


def test_an_analyst_may_block_private_space():
    assert normalize("192.168.1.10", allow_private=True) == "192.168.1.10/32"
    with pytest.raises(IPError, match="loopback"):
        normalize("127.0.0.1", allow_private=True)
