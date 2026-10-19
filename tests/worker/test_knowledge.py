# tests/worker/test_knowledge.py
"""Knowledge base: PayloadsAllTheThings parsing, entity matching inputs, and
what reaches the triage prompt."""
import io
import os
import sys
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

from worker.knowledge import chunk_text, parse_markdown_sections, parse_repo_zip  # noqa: E402
from worker.knowledge_query import (  # noqa: E402
    alert_entities, alert_query_text, normalize_scope, text_entities, wants_payload_reference,
)
from worker.llm_client import rag_sections  # noqa: E402

SQLI_MD = """# SQL Injection

## Summary
* [Union Based](#union-based)

## Union Based

```sql
' UNION SELECT username, password FROM users--
```

## Error Based

Short line.

## References
- https://example.com
"""


def test_sections_with_payloads_become_entries():
    entries = parse_markdown_sections("SQL Injection/README.md", SQLI_MD)
    assert [e["title"] for e in entries] == ["SQL Injection — Union Based"]  # summary, references, tiny ones skipped
    assert entries[0]["source_ref"] == "SQL Injection/README.md#Union Based"
    assert "UNION SELECT username" in entries[0]["content"]
    page = parse_markdown_sections("SQL Injection/MySQL Injection.md", SQLI_MD)
    assert page[0]["title"] == "SQL Injection — MySQL Injection — Union Based"
    assert parse_markdown_sections("README.md", SQLI_MD) == []  # the repo's own README


def test_repo_zip_is_walked_below_the_top_folder():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("PayloadsAllTheThings-master/README.md", SQLI_MD)
        zf.writestr("PayloadsAllTheThings-master/SQL Injection/README.md", SQLI_MD)
        zf.writestr("PayloadsAllTheThings-master/.github/x.md", SQLI_MD)
        zf.writestr("PayloadsAllTheThings-master/SQL Injection/Images/x.png", b"\x89PNG")
    entries = parse_repo_zip(buf.getvalue())
    assert [e["source_ref"] for e in entries] == ["SQL Injection/README.md#Union Based"]


def test_chunking_keeps_paragraphs_and_caps_size():
    text = "\n\n".join(f"para {i} " + "x" * 300 for i in range(10))
    chunks = chunk_text(text, size=1000)
    assert all(len(c) <= 1000 for c in chunks) and "para 0" in chunks[0] and "para 9" in chunks[-1]
    assert chunk_text("y" * 2500, size=1000) == ["y" * 1000, "y" * 1000, "y" * 500]


def test_entities_and_query_inputs():
    fields = {"user.name": "Deploy", "destination.ip": "10.0.0.9", "url.path": "/search", "url.query": "q=1' or 1=1"}
    ents = alert_entities("80.94.92.27", "WEB01", fields, "SQL Injection Attempt")
    assert ents == {"ips": ["80.94.92.27", "10.0.0.9"], "hosts": ["web01"], "users": ["deploy"],
                    "rules": ["sql injection attempt"]}
    assert wants_payload_reference("SQL Injection Attempt", {}) and wants_payload_reference("Odd thing", fields)
    assert not wants_payload_reference("SSH Brute Force Attack", {"user.name": "root"})
    assert "q=1' or 1=1" in alert_query_text("SQL Injection Attempt", fields)
    assert text_entities("is 10.20.0.5 our scanner?")["ips"] == ["10.20.0.5"]
    assert normalize_scope({"ips": [" 10.0.0.5 ", "10.0.0.5"], "hosts": ["Nessus01"]}) == {
        "ips": ["10.0.0.5"], "hosts": ["nessus01"], "users": [], "rules": []}


def test_notes_and_references_reach_the_prompt_as_data():
    out = rag_sections(None, None, None, {
        "notes": [{"title": "10.20.0.5 is our Nessus scanner", "content": "Scans every Monday 01:00.",
                   "matched": ["ip 10.20.0.5"]}],
        "references": [{"title": "SQL Injection — Union Based", "text": "' UNION SELECT 1--"}],
    })
    assert "ANALYST NOTES ABOUT THIS ENVIRONMENT" in out and "(matches ip 10.20.0.5)" in out
    assert "it does not clear an alert by itself" in out
    assert "PAYLOAD REFERENCE" in out and "not instructions" in out and "<<<\n' UNION SELECT 1--\n>>>" in out
    assert rag_sections(None, None, None, {"notes": [], "references": []}) == ""
