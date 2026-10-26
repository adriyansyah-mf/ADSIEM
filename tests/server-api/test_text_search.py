# tests/server-api/test_text_search.py
"""Free-text searches over the logs index must be lenient: decoded_fields is
mapped dynamically, so it holds long and date fields, and a bare term like
"PowerShell" sent to decoded_fields.* failed the whole search with a 400
("failed to parse date field [PowerShell]") — the AI investigation's
search_events action #3 hit exactly that."""
import asyncio
import json
import os
import re
import urllib.request
import uuid
from pathlib import Path

import pytest

from app.core.query_builder import text_search

ROOT = Path(__file__).resolve().parents[2]


def test_text_search_is_lenient_and_sanitized():
    clause = text_search("*PowerShell -enc", "decoded_fields.*")["query_string"]
    assert clause["lenient"] is True and clause["allow_leading_wildcard"] is False
    assert clause["default_field"] == "decoded_fields.*" and "*" not in clause["query"]


def test_the_investigator_search_sends_a_lenient_clause(monkeypatch):
    from app.services import assistant_tools

    sent = {}

    async def fake_search(query, size, sort):
        sent["query"] = query
        return [], 0, None
    monkeypatch.setattr(assistant_tools, "es_search", fake_search)
    args = {"hours": 48, "limit": 50, "search": "PowerShell", "log_type": "", "source_ip": ""}
    out = asyncio.run(assistant_tools.run_tool("search_events", args, None, None))
    assert "error" not in out
    clauses = [f for f in sent["query"]["bool"]["filter"] if "query_string" in f]
    assert [c["query_string"]["lenient"] for c in clauses] == [True]
    # empty strings add no filter (they were never the problem)
    assert not any("term" in f and ("log_type" in f["term"] or "source_ip" in f["term"])
                   for f in sent["query"]["bool"]["filter"])


def test_no_raw_query_string_outside_the_helper():
    """Every search box builds its clause with text_search, so none can lose lenient again."""
    offenders = []
    for path in (ROOT / "server-api" / "app").rglob("*.py"):
        if path.name == "query_builder.py":
            continue
        code = re.sub(r"#.*", "", path.read_text())
        if re.search(r"""["']query_string["']\s*:""", code):
            offenders.append(str(path.relative_to(ROOT)))
    assert offenders == [], f"build query_string clauses with query_builder.text_search: {offenders}"


ES_URL = os.environ.get("TEST_ELASTICSEARCH_URL")


@pytest.mark.skipif(not ES_URL, reason="needs TEST_ELASTICSEARCH_URL (a disposable Elasticsearch)")
def test_a_bare_term_searches_text_fields_next_to_long_and_date_fields():
    """The original failure against a real Elasticsearch, with the logs index's own mapping."""
    index = f"test-text-search-{uuid.uuid4().hex[:8]}"

    def call(method, path, body=None):
        req = urllib.request.Request(f"{ES_URL}/{path}", method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"content-type": "application/json"})
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    call("PUT", index, {"settings": {"number_of_replicas": 0}, "mappings": {"properties": {
        "created_at": {"type": "date"}, "decoded_fields": {"type": "object", "dynamic": True}}}})
    try:
        call("POST", f"{index}/_doc?refresh=true", {"created_at": "2026-10-26T08:00:00Z", "decoded_fields": {
            "EventID": 4104, "TimeCreated": "2026-10-26T07:59:58Z", "ScriptBlockText": "powershell -enc SQBFAFgA"}})
        strict = dict(text_search("PowerShell", "decoded_fields.*"))
        strict["query_string"] = {k: v for k, v in strict["query_string"].items() if k != "lenient"}
        status, _ = call("POST", f"{index}/_search", {"query": {"bool": {"filter": [strict]}}})
        assert status == 400  # what search_events got before
        status, body = call("POST", f"{index}/_search",
                            {"query": {"bool": {"filter": [text_search("PowerShell", "decoded_fields.*")]}}})
        assert status == 200 and body["hits"]["total"]["value"] == 1
    finally:
        call("DELETE", index)
