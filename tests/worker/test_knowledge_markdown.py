# tests/worker/test_knowledge_markdown.py
"""Vault articles without a database: frontmatter, links, headings, the secret
scan, heading-aware chunks, and the pure parts of hybrid retrieval."""
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

from worker import knowledge_markdown as md  # noqa: E402
from worker import knowledge_query as kq  # noqa: E402

ARTICLE = """---
title: Investigating Suspicious PowerShell
tags: [windows, "#powershell", dfir]
platforms: windows
mitre: [t1059.001]
trust: reviewed
scope:
  groups: [blue]
  hosts: [WS01]
obsidian-only: kept
---

# Triage

Inspect [[PowerShell Script Block Logging]] and the [[Parent Process#Windows|parent]].
![[diagram.png]]

```powershell
# not a heading, and [[Not A Link]]
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational
```

## Containment
Isolate when [[PowerShell Script Block Logging]] shows encoded commands.
"""


def test_frontmatter_is_validated_and_normalized():
    a = md.parse(ARTICLE)
    assert a.errors == []
    assert a.meta["tags"] == ["windows", "powershell", "dfir"]
    assert a.meta["platforms"] == ["windows"] and a.meta["mitre"] == ["T1059.001"]
    assert a.meta["scope"] == {"groups": ["blue"], "hosts": ["WS01"]}
    assert a.meta["obsidian-only"] == "kept"  # unknown keys survive an import round trip
    assert md.title_of(a) == "Investigating Suspicious PowerShell"
    assert a.body.lstrip().startswith("# Triage")


def test_bad_frontmatter_is_reported_not_guessed():
    assert "not valid YAML" in md.parse("---\ntags: [unclosed\n---\nbody").errors[0]
    errors = md.parse("---\nmitre: [T59]\ntrust: gospel\ntype: blog\nexpires: someday\n---\nx").errors
    assert any("mitre ids" in e for e in errors) and any("trust must be" in e for e in errors)
    assert any("type must be" in e for e in errors) and any("expires must be" in e for e in errors)
    assert md.parse("---\n- a list\n---\nx").errors == ["frontmatter must be a mapping of keys to values"]
    plain = md.parse("# Just a note\ntext")
    assert plain.meta == {} and md.title_of(plain) == "Just a note"
    assert md.title_of(md.parse("no heading"), "Windows/Lateral Movement.md") == "Lateral Movement"


def test_links_and_headings_skip_code_and_embeds():
    a = md.parse(ARTICLE)
    assert md.wikilinks(a.body) == [
        {"target": "PowerShell Script Block Logging", "slug": "powershell-script-block-logging", "heading": None},
        {"target": "Parent Process", "slug": "parent-process", "heading": "Windows"},
    ]
    assert [(h["level"], h["text"]) for h in md.headings(a.body)] == [(1, "Triage"), (2, "Containment")]
    assert md.slugify("Investigating PowerShell!.md") == "investigating-powershell"


def test_render_round_trips():
    a = md.parse(ARTICLE)
    again = md.parse(md.render(a.meta, a.body))
    assert again.meta == a.meta and again.body == a.body
    assert md.checksum(a.meta, a.body) == md.checksum(again.meta, again.body)
    assert md.render({}, "body") == "body"


def test_secret_scan_flags_credentials_but_not_examples():
    found = md.find_secrets("aws: AKIAABCDEFGHIJKLMNOP\nkey = -----BEGIN RSA PRIVATE KEY-----\n"
                            "api_key: 'sk3ALt8x9qPz2LmN4vB6cX1d'")
    assert [(f["line"], f["kind"]) for f in found] == [
        (1, "AWS access key"), (2, "private key"), (3, "credential assignment")]
    assert "AKIAABCDEFGHIJKLMNOP" not in str(found)  # never echoed back
    # DFIR prose about passwords is fine
    assert md.find_secrets("Check for password=Summer2024 in the command line, or `password: <redacted>`.") == []


def test_chunks_follow_headings_and_carry_title():
    a = md.parse(ARTICLE)
    chunks = md.chunk_markdown("PS", a.body)
    assert [h for h, _ in chunks] == ["Triage", "Containment"]
    assert chunks[1][1].startswith("PS\nContainment\n")
    assert "# not a heading" in chunks[0][1]  # code stays in its section
    long = md.chunk_markdown("T", "## A\n" + "\n\n".join("word " * 50 for _ in range(20)), size=600)
    assert len(long) > 1 and all(len(t) <= 600 for _, t in long)


def test_full_text_query_filters_and_recency():
    assert kq.fts_query("Suspicious PowerShell -enc from 10.0.0.5; powershell!") == \
        "suspicious | powershell | enc | 10005"
    assert kq.fts_query("a b") is None
    sql, params = kq._filters({"mitre": ["t1059.001"], "platforms": ["windows"], "tags": []})
    assert "frontmatter->'mitre'" in sql and params == {"f_platforms": ["windows"], "f_mitre": ["T1059.001"]}
    assert kq._filters(None) == ("", {})
    now = datetime.now(timezone.utc)
    assert kq.recency_weight(now - timedelta(days=30)) == 1.0
    assert kq.recency_weight(now - timedelta(days=3650)) == 0.8
    assert 0.8 < kq.recency_weight(now - timedelta(days=400)) < 1.0
