# tests/server-api/test_yara_drafting.py
"""YARA drafting without a database: the rule text the server writes, the
quality checks that block weak drafts, feature sanitizing, and which files are
eligible for a draft."""
import re
import uuid
from pathlib import Path
from types import SimpleNamespace

from app.services import investigation_ledger as ledger
from app.services import yara_drafting as d

ROOT = Path(__file__).resolve().parents[2]
SHA = "a" * 64

SPEC = {
    "label": "Stage2 Loader!", "description": "AI-drafted rule from investigation evidence", "confidence": 85,
    "tags": ["loader"], "mitre": ["t1055"],
    "strings": [
        {"id": "$pdb", "kind": "text", "value": "C:\\build\\stage2\\loader.pdb", "why": "build path"},
        {"id": "$mutex", "kind": "text", "value": "Global\\s2_mtx_91", "modifiers": ["wide", "ascii", "evil"], "why": "mutex"},
        {"id": "$ua", "kind": "text", "value": 'Mozilla/5.0 (s2"loader)', "modifiers": ["nocase"], "why": "user agent"},
        {"id": "$hex", "kind": "hex", "value": "{ 4D 5A ?? 90 [2-4] 50 45 }", "why": "header"},
        {"id": "$re", "kind": "regex", "value": "/stage2_[0-9a-f]{8}\\.dat/", "why": "dropped file"},
        {"id": "bad id", "kind": "hex", "value": "not hex; DROP", "why": "rejected"},
    ],
    "condition": "uint16(0) == 0x5A4D and filesize < 2MB and 2 of them",
}


def _rule(spec=SPEC):
    return d.build_rule(spec, sha256=SHA, case_id=uuid.uuid4(), investigation_id=uuid.uuid4(),
                        author="AI draft requested by ana")


def test_the_server_writes_the_rule_shape_the_agent_engine_compiles():
    name, text, rationale = _rule()
    assert name == "AI_Stage2_Loader_aaaaaaaa"
    # agent/internal/yara/ai_draft_test.go compiles and runs testdata/ai_draft.yar with the agents'
    # engine; it must stay the shape this function writes.
    fixture = (ROOT / "agent/internal/yara/testdata/ai_draft.yar").read_text()
    section = re.compile(r"strings:\n(.*?)\n    condition:\n(.*?)\n}", re.S)
    assert section.search(text).groups() == section.search(fixture).groups()
    assert 'sample_sha256 = "' + SHA + '"' in text and 'mitre = "T1055"' in text
    assert [r["id"] for r in rationale] == ["$pdb", "$mutex", "$ua", "$hex", "$re"]  # invalid hex dropped
    assert "evil" not in text  # unknown modifiers dropped


def test_names_ids_and_literals_cannot_break_out_of_the_rule():
    spec = {"label": "x\n}\nrule Evil {", "strings": [
        {"id": "$a } condition: true", "value": 'line1\nline2 "q" \\ é'}], "condition": "$s1"}
    name, text, _ = _rule(spec)
    assert re.fullmatch(r"AI_[A-Za-z0-9_]+_aaaaaaaa", name)
    assert len(re.findall(r"^\s*rule ", text, re.M)) == 1
    assert '$s1 = "line1\\x0aline2 \\"q\\" \\\\ \\xc3\\xa9"' in text


def test_condition_checks_refuse_unsupported_syntax_and_undefined_strings():
    assert d.check_condition("2 of them and filesize < 1MB", {"$a", "$b"}) == []
    assert d.check_condition("$a and #b > 2 and @a[1] < 100 and for any of ($a*) : ( $ )", {"$a", "$b"}) == []
    assert d.check_condition("$a and import_something()", {"$a"})[0].startswith("condition uses unsupported syntax")
    assert d.check_condition("$a or $zz", {"$a"}) == ["condition references $zz, which is not defined"]
    assert d.check_condition("any of ($x*)", {"$a"}) == ["condition references $x*, which matches no defined string"]
    assert d.check_condition("  ", set()) == ["the rule has no condition"]


def test_quality_blocks_hash_only_tiny_and_all_common_rules():
    _, good, _ = _rule()
    q = d.quality(good)
    assert q["blocking"] == [] and any("regular expression" in w for w in q["warnings"])

    hash_only = 'import "hash"\nrule H { condition: hash.sha256(0, filesize) == "' + SHA + '" }'
    assert any("hash-based" in b for b in d.quality(hash_only)["blocking"])
    assert any("no strings" in b for b in d.quality(hash_only)["blocking"])
    tiny = 'rule T { strings: $a = "MZ" condition: uint16(0) == 0x5A4D and filesize < 1MB and $a }'
    assert any("$a is only 2 characters" in b for b in d.quality(tiny)["blocking"])
    common = ('rule C { strings: $a = "kernel32.dll" $b = "GetProcAddress" '
              'condition: uint16(0) == 0x5A4D and filesize < 1MB and all of them }')
    q = d.quality(common)
    assert any("every string is short or common" in b for b in q["blocking"])
    loose = 'rule L { strings: $a = "unique_marker_1" $b = "unique_marker_2" condition: any of them }'
    q = d.quality(loose)
    assert q["blocking"] == []
    assert {w.split(" ")[0] for w in q["warnings"]} >= {"one", "no"}  # one string fires it; no type guard / filesize


def test_features_are_bounded_and_credentials_redacted_again():
    row = {"Path": "/tmp/x", "SHA256": SHA, "Size": 10, "Type": "ELF", "Redacted": 1, "Data": "base64 bytes",
           "Imports": [f"f{i}" for i in range(500)],
           "Strings": [{"Offset": 1, "Encoding": "ascii", "Value": "ghp_" + "a" * 40},
                       {"Offset": 9, "Encoding": "ascii", "Value": "/tmp/.x/kworkerd"}]}
    out = d.sanitize_features(row)
    assert "Data" not in out and len(out["Imports"]) == d.MAX_LIST
    assert [s["value"] for s in out["Strings"]] == ["[redacted: credential]", "/tmp/.x/kworkerd"]
    assert out["Redacted"] == 2


def _ev(kind, entities, summary="", pinned=False):
    return SimpleNamespace(id=uuid.uuid4(), evidence_type=kind, entities=entities, summary=summary, title=kind,
                           pinned=pinned)


def test_a_file_needs_a_supporting_finding_to_be_eligible():
    seen = _ev("flow_row", {"hosts": ["web01"], "files": [{"path": "/tmp/.x/kworkerd", "sha256": SHA, "size": 812}]})
    other = _ev("flow_row", {"hosts": ["web01"], "files": [{"path": "/usr/bin/ls", "sha256": "b" * 64, "size": 9}]})
    [c1, c2] = sorted(ledger.malware_candidates([seen, other], []), key=lambda c: c["path"])
    assert not c1["eligible"] and not c2["eligible"]  # a bare hash proves nothing

    rep = _ev("ti_result", {"hashes": [SHA], "status": "found"})
    nf = _ev("ti_result", {"hashes": ["b" * 64], "status": "not_found"})  # a gap, not support
    alert = _ev("alert", {}, summary="process /tmp/.x/kworkerd connected to 203.0.113.9")
    yara = _ev("flow_row", {"hosts": ["web01"], "yara_matches": [{"file": "/tmp/.x/kworkerd", "rule": "Miner"}]})
    cands = {c["path"]: c for c in ledger.malware_candidates([seen, other, rep, nf, alert, yara], [])}
    assert cands["/tmp/.x/kworkerd"]["eligible"]
    assert {s["kind"] for s in cands["/tmp/.x/kworkerd"]["support"]} == {"reputation", "mentioned", "yara"}
    assert not cands["/usr/bin/ls"]["eligible"]

    pinned = _ev("flow_row", {"hosts": ["web01"], "files": [{"path": "/usr/bin/ls", "sha256": "b" * 64, "size": 9}]},
                 pinned=True)
    hyp = SimpleNamespace(state="supported", supporting_evidence_ids=[str(other.id)], statement="ls was replaced")
    c = next(c for c in ledger.malware_candidates([other, pinned], [hyp]) if c["path"] == "/usr/bin/ls")
    assert c["eligible"] and {s["kind"] for s in c["support"]} == {"analyst", "hypothesis"}


def test_file_entities_skip_truncated_reads_and_keep_yara_matches():
    rows = [{"Path": "/tmp/a", "SHA256": SHA, "Size": 5, "Type": "ELF"},
            {"Path": "/tmp/b", "SHA256": "c" * 64, "Size": 5, "Truncated": True},  # hash of a prefix only
            {"Rule": "Miner", "File": "/tmp/a"}]
    assert ledger._file_entities(rows) == {
        "files": [{"path": "/tmp/a", "sha256": SHA, "size": 5, "type": "ELF"}],
        "yara_matches": [{"file": "/tmp/a", "rule": "Miner"}]}
