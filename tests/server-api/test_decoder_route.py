# tests/server-api/test_decoder_route.py
import pytest
import yaml

def test_decoder_test_regex_match():
    import re
    content = yaml.dump({
        "name": "test",
        "log_type": "linux_auth",
        "type": "regex",
        "pattern": r"Failed password for (?P<user>\S+) from (?P<src_ip>\S+)",
        "fields": {"user.name": "user", "source.ip": "src_ip"}
    })
    raw = "May 21 sshd: Failed password for root from 1.2.3.4 port 22"
    decoder_def = yaml.safe_load(content)
    match = re.search(decoder_def["pattern"], raw)
    assert match is not None
    groups = match.groupdict()
    assert groups["user"] == "root"
    assert groups["src_ip"] == "1.2.3.4"

def test_decoder_test_no_match():
    import re
    pattern = r"Failed password for (?P<user>\S+)"
    raw = "Accepted publickey for admin"
    assert re.search(pattern, raw) is None
