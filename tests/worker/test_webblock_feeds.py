# tests/worker/test_webblock_feeds.py
"""URLhaus / PhishTank parsers and domain preparation (no network, no DB)."""
import json

from worker import webblock_feeds as wf

URLHAUS = '''################################################################
# abuse.ch URLhaus Database Dump (CSV - online URLs only)
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
################################################################
"1","2026-11-01 10:00:00","http://evil.example/a.exe","online","2026-11-08","malware_download","elf,Mozi","https://urlhaus.abuse.ch/url/1/","rep"
"2","2026-11-01 10:00:00","http://gone.example/b.exe","offline","2026-11-02","malware_download","exe","https://urlhaus.abuse.ch/url/2/","rep"
"3","2026-11-01 10:00:00","http://203.0.113.9/c.sh","online","2026-11-08","malware_download","","https://urlhaus.abuse.ch/url/3/","rep"
"4","2026-11-01 10:00:00","http://bücher.example/x","online","2026-11-08","malware_download","","https://urlhaus.abuse.ch/url/4/","rep"
"5","2026-11-01 10:00:00","http://evil.example/other","online","2026-11-08","malware_download","","https://urlhaus.abuse.ch/url/5/","rep"
'''

PHISH = json.dumps([
    {"url": "http://phish.example/login", "verified": "yes", "online": "yes", "target": "PayPal"},
    {"url": "http://unverified.example/", "verified": "no", "online": "yes", "target": "Other"},
    {"url": "http://down.example/", "verified": "yes", "online": "no", "target": "Other"},
    {"url": "http://198.51.100.7/x", "verified": "yes", "online": "yes", "target": "Bank"},
])


def test_urlhaus_keeps_online_rows_and_builds_reason():
    rows = wf.parse_urlhaus(URLHAUS)
    assert [u for u, _ in rows] == ["http://evil.example/a.exe", "http://203.0.113.9/c.sh",
                                    "http://bücher.example/x", "http://evil.example/other"]
    assert rows[0][1] == "URLhaus: malware_download (elf)"
    assert rows[1][1] == "URLhaus: malware_download"


def test_urlhaus_limit():
    assert len(wf.parse_urlhaus(URLHAUS, limit=2)) == 2


def test_phishtank_keeps_verified_online():
    rows = wf.parse_phishtank(PHISH)
    assert [u for u, _ in rows] == ["http://phish.example/login", "http://198.51.100.7/x"]
    assert rows[0][1] == "PhishTank: phishing (PayPal)"


def test_prepare_skips_ips_dedupes_punycodes_and_suppresses():
    entries, skipped = wf.prepare(wf.parse_urlhaus(URLHAUS), [("evil.example", False)])
    assert skipped == 1  # the IP host
    by = {e[0]: e for e in entries}
    assert set(by) == {"evil.example", "xn--bcher-kva.example"}
    assert by["evil.example"][1:3] == ("suppressed", "allowlisted (evil.example)")
    assert by["xn--bcher-kva.example"][1] == "active"


def test_prepare_first_url_wins_and_subdomain_rule():
    entries, _ = wf.prepare(wf.parse_urlhaus(URLHAUS), [("example", True), ("bad.test", True)])
    assert [e[1] for e in entries] == ["suppressed", "suppressed"]
    entries, _ = wf.prepare([("http://a.bad.test/1", "r")], [("bad.test", True)])
    assert entries[0][1:3] == ("suppressed", "allowlisted (bad.test)")
    entries, _ = wf.prepare([("http://a.bad.test/1", "r"), ("http://a.bad.test/2", "r2")], [])
    assert entries == [("a.bad.test", "active", "r", "http://a.bad.test/1")]
