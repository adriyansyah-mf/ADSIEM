# tests/worker/test_web_domains.py
"""Web Protection domain rules (worker/web_domains.py), shared with server-api."""
import pytest

from worker.web_domains import BUILTIN_ALLOWLIST, DomainError, allow_match, normalize


@pytest.mark.parametrize("value,expected", [
    ("evil.example", "evil.example"),
    ("EVIL.Example.", "evil.example"),
    ("https://user:pw@Evil.example:8443/path?q=1", "evil.example"),
    ("evil.example/path", "evil.example"),
    ("evil.example:8080", "evil.example"),
    ("bücher.example", "xn--bcher-kva.example"),
    ("http://bücher.example/a", "xn--bcher-kva.example"),
    ("  sub.evil.example  ", "sub.evil.example"),
    ("a1.example", "a1.example"),
    ("123.example", "123.example"),
    ("http://evil.com\\@victim.com/", "evil.com"),
    ("HTTPS://evil.com\\.victim.com/x", "evil.com"),
])
def test_normalize(value, expected):
    assert normalize(value) == expected


@pytest.mark.parametrize("value", [
    "", "   ", "localhost", "45.33.32.156", "http://45.33.32.156/a", "[2001:4860::8888]",
    "http://[2001:4860::8888]/", "-bad.example", "a..example", "x" * 64 + ".example", "ex ample.com", "http://",
    "10.1", "1.2.3", "0x7f.0.0.1", "http://10.1/x",
])
def test_normalize_rejects(value):
    with pytest.raises(DomainError):
        normalize(value)


def test_ip_rejection_says_why():
    with pytest.raises(DomainError, match="IP addresses cannot be web-blocked"):
        normalize("45.33.32.156")


def test_allow_match_apex_and_subdomains():
    rules = [("github.com", True), ("weebly.com", False)]
    assert allow_match("github.com", rules) == "github.com"
    assert allow_match("raw.github.com", rules) == "github.com"
    assert allow_match("weebly.com", rules) == "weebly.com"
    assert allow_match("evil.weebly.com", rules) is None
    assert allow_match("notgithub.com", rules) is None


def test_builtin_allowlist_is_normalized():
    for domain, _ in BUILTIN_ALLOWLIST:
        assert normalize(domain) == domain
    assert ("github.com", True) in BUILTIN_ALLOWLIST
    assert ("weebly.com", False) in BUILTIN_ALLOWLIST
    assert len({d for d, _ in BUILTIN_ALLOWLIST}) == len(BUILTIN_ALLOWLIST)
