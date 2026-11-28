# tests/worker/test_web_rules_apache.py
"""Web rules see Apache access logs as well as nginx ones.

Eight platform rules had `logsource: product: nginx`, which only maps to
nginx_access* log types: /.env, /etc/passwd, path traversal, WordPress and
xmlrpc probes against an Apache host raised nothing. The requests below are
real lines from an Apache host scanned on 2026-11-28."""
import asyncio
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest  # noqa: E402
import yaml  # noqa: E402

from worker.decoder_engine import DecoderEngine  # noqa: E402
from worker.sigma_engine import SigmaEngine  # noqa: E402
from worker.sigma_logsource import is_collected  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "../..")
RULE_FILES = sorted(glob.glob(os.path.join(ROOT, "rules/*.yaml")))
WEB_LOG_TYPES = ("nginx_access_combined", "apache_access")


@pytest.fixture()
def engines():
    decs = sorted((open(p).read() for p in glob.glob(os.path.join(ROOT, "decoders/*.yaml"))),
                  key=lambda c: yaml.safe_load(c).get("priority", 100))
    dec = DecoderEngine()
    dec.load_from_yaml_list(decs)
    sig = SigmaEngine()
    sig.load_from_yaml_list([open(p).read() for p in RULE_FILES])
    assert not sig.load_errors, sig.load_errors
    return dec, sig


def _titles(engines, path, ip="45.156.87.6", status=404, times=1):
    dec, sig = engines
    titles = set()
    for _ in range(times):
        line = (f'{ip} - - [28/Nov/2026:03:13:54 +0000] "GET {path} HTTP/1.1" {status} 450 "-" '
                '"Mozilla/5.0 (X11; Linux x86_64)"')
        event = dec.decode("apache_access", line)
        assert event.get("url.path"), line
        matches = asyncio.run(sig.evaluate(dict(event, raw_message=line, log_type="apache_access")))
        titles |= {m["title"] for m in matches}
    return titles


@pytest.mark.parametrize("path,title", [
    ("/.env", "Access to .env File"),
    ("/var/www/html/.env", "Access to .env File"),
    ("/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php"
     "?ajax_path=/etc/passwd", "Access to /etc/passwd"),
    ("/..%2f..%2f..%2f..%2f.env", "Nginx Suspicious Path Access"),
    ("/wp-content/uploads/2026/11/shell.php", "PHP Execution Probe in WordPress Uploads Directory"),
])
def test_single_request_rules_fire_on_apache(engines, path, title):
    titles = _titles(engines, path)
    assert title in titles, sorted(titles)


@pytest.mark.parametrize("path,times,title", [
    ("/wp-login.php", 10, "WordPress Admin Login Probing"),
    ("/?author=1", 5, "WordPress User Enumeration Attempt"),
    ("/xmlrpc.php", 5, "WordPress XML-RPC Abuse"),
])
def test_threshold_rules_fire_on_apache(engines, path, times, title):
    titles = _titles(engines, path, ip="195.178.110.159", status=200, times=times)
    assert any(t.startswith(title) for t in titles), sorted(titles)


def test_html_injection_probe_is_xss(engines):
    path = "/?next=%22%22%3E%3Ch1%3EWBM-XSS-PROBE%3C/h1%3Etest"
    assert "Cross-Site Scripting (XSS) Attempt" in _titles(engines, path, status=200)


def test_plain_quotes_are_not_xss(engines):
    for path in ("/search?q=%22best+laptop%22", "/blog/it's-here/", "/a?x=1>0", "/q?a=%22x%22>%20<"):
        assert "Cross-Site Scripting (XSS) Attempt" not in _titles(engines, path, status=200), path


def test_every_web_rule_sees_both_web_servers():
    """A platform web rule visible to nginx logs must also see Apache logs."""
    for p in RULE_FILES:
        for d in yaml.safe_load_all(open(p)):
            ls = (d or {}).get("logsource") or {}
            seen = {lt for lt in WEB_LOG_TYPES if is_collected(ls, [lt])}
            if seen and ls.get("product") not in ("nginx", "apache"):
                assert seen == set(WEB_LOG_TYPES), (os.path.basename(p), ls, seen)
