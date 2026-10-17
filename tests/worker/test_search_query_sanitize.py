# tests/worker/test_search_query_sanitize.py
"""Queries the LLM chose for web research must be public threat-intel queries.

The model occasionally expresses local telemetry as a filtered query
(src_ip=..., uri CONTAINS ...). Those are correct for analysis but the public
search backend rejects them as internal-host lookups, and they waste a search
round trip per alert.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

from worker.ai_analyst import _derive_public_query, _sanitize_search_query  # noqa: E402


def test_blocks_splunk_field_query():
    assert _sanitize_search_query("index=auth host=agent-demo src_ip=203.0.113.152 action=failure") is None


def test_blocks_splunk_pipe_commands():
    assert _sanitize_search_query("src_ip=203.0.113.152 OR dest_host=agent-demo | stats count by user") is None


def test_derive_uses_alert_title():
    derived = _derive_public_query("SSH Brute Force Attack", "T1110.001")
    assert derived is not None
    assert "SSH Brute Force Attack" in derived
    assert "T1110" in derived


def test_derive_strips_internal_indicators():
    derived = _derive_public_query("Scan from 203.0.113.9 on agent-demo", None)
    assert derived is not None
    assert "203.0.113" not in derived
    assert "agent-demo" not in derived


def test_derive_returns_none_when_nothing_usable():
    assert _derive_public_query(None, None) is None


def test_blocks_field_syntax_with_equals():
    assert _sanitize_search_query('src_ip=203.0.113.224 AND uri="*.env*"') is None


def test_blocks_field_syntax_with_contains():
    assert _sanitize_search_query('host="agent-demo" AND http.request.uri CONTAINS ".env"') is None


def test_blocks_field_syntax_with_colon():
    assert _sanitize_search_query("src_ip:203.0.113.19 AND (uri:*/.env* OR url:*/.env*)") is None


def test_blocks_bare_private_ip():
    assert _sanitize_search_query("203.0.113.224 /etc/passwd") is None


def test_blocks_internal_hostname():
    assert _sanitize_search_query("source IP 10.1.2.3 host agent-demo") is None


def test_blocks_rfc1918():
    assert _sanitize_search_query("scan from 192.168.1.5") is None


def test_allows_generic_technique_query():
    assert _sanitize_search_query("SSH brute force T1110 mitigation") == (
        "SSH brute force T1110 mitigation"
    )


def test_allows_cve_query():
    assert _sanitize_search_query("Log4Shell CVE-2021-44228 indicators") is not None


def test_allows_language_modifier():
    """language: is a legit search operator and must not be mistaken for a
    telemetry field filter."""
    assert _sanitize_search_query("SSH Authorized Keys Modified language:en") is not None


def test_empty_returns_none():
    assert _sanitize_search_query("   ") is None
