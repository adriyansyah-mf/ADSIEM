# tests/server-api/test_sigmahq_import.py
"""SigmaHQ import: package reading, enable policy, idempotent updates that keep local edits."""
import asyncio
import io
import zipfile

import pytest

from app.schemas.schemas import RuleTestRequest
from app.services import sigmahq
from app.services.rule_content import collected, compile_errors, content_hash, rule_metadata


def _rule(rid, title, level="high", status="test", product="windows", category="process_creation",
          detection="selection:\n    Image|endswith: '\\\\whoami.exe'\n  condition: selection"):
    return (f"title: {title}\nid: {rid}\nstatus: {status}\nlevel: {level}\n"
            f"tags:\n  - attack.discovery\n  - attack.t1033\n"
            f"logsource:\n  product: {product}\n  category: {category}\n"
            f"detection:\n  {detection}\n")


def _zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("rules/", "")
        for name, body in files.items():
            zf.writestr(name, body)
    return buf.getvalue()


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return iter(self._rows)

    def __iter__(self):
        return iter(self._rows)


class FakeDB:
    """Just enough AsyncSession for import_rules: the decoder log types and the sigmahq rows."""

    def __init__(self, log_types=("linux_auth",)):
        self.rules = []
        self.log_types = [(lt,) for lt in log_types]

    async def execute(self, stmt):
        if "decoders" in str(stmt):
            return _Result(self.log_types)
        return _Result([r for r in self.rules if r.source == "sigmahq"])

    def add(self, obj):
        self.rules.append(obj)

    async def commit(self):
        pass


def _import(db, contents):
    return asyncio.run(sigmahq.import_rules(db, contents, "r-test", ["high", "critical"], ["stable", "test"]))


def test_read_rules_takes_only_yaml_members():
    data = _zip({"rules/windows/a.yml": "title: a", "rules/b.yaml": "title: b", "README.md": "x"})
    assert sorted(sigmahq.read_rules(data)) == ["title: a", "title: b"]
    with pytest.raises(sigmahq.SigmaHQError):
        sigmahq.read_rules(b"not a zip")


def test_unknown_ruleset_is_rejected():
    with pytest.raises(sigmahq.SigmaHQError):
        asyncio.run(sigmahq.download("everything"))


def test_import_applies_enable_policy():
    db = FakeDB()
    stats = _import(db, [
        _rule("id-high", "Whoami Execution"),
        _rule("id-low", "Low Noise", level="low"),
        _rule("id-exp", "Experimental", status="experimental"),
        _rule("id-mac", "Mac Thing", product="macos"),
        _rule("id-bad", "Broken", detection="selection:\n    Image|nosuchmod: x\n  condition: selection"),
        _rule("id-old", "Old", status="deprecated"),
        "title: not a rule\n",
    ])
    rows = {r.external_id: r for r in db.rules}
    assert (stats.total, stats.created, stats.rejected) == (5, 4, 1)
    assert "nosuchmod" in stats.rejected_examples[0]
    assert rows["id-high"].is_enabled and rows["id-high"].title == "Whoami Execution"
    assert rows["id-high"].mitre_tags == ["attack.discovery", "attack.t1033"]
    assert rows["id-high"].sigma_status == "test" and rows["id-high"].source == "sigmahq"
    assert not rows["id-low"].is_enabled and not rows["id-exp"].is_enabled
    assert not rows["id-mac"].is_enabled and stats.not_collected == 1
    assert stats.enabled == 1


def test_reimport_updates_upstream_changes_but_keeps_local_edits():
    db = FakeDB()
    _import(db, [_rule("a", "Rule A"), _rule("b", "Rule B")])
    rows = {r.external_id: r for r in db.rules}
    for r in rows.values():
        r.version = 1
    rows["b"].content += "falsepositives:\n  - tuned locally\n"  # analyst edit

    stats = _import(db, [_rule("a", "Rule A v2"), _rule("b", "Rule B v2"), _rule("c", "Rule C")])
    assert (stats.updated, stats.kept_local_edits, stats.created, stats.unchanged) == (1, 1, 1, 0)
    assert rows["a"].title == "Rule A v2" and rows["a"].version == 2
    assert rows["a"].upstream_hash == content_hash(rows["a"].content)
    assert rows["b"].title == "Rule B" and "tuned locally" in rows["b"].content

    stats = _import(db, [_rule("a", "Rule A v2")])
    assert stats.unchanged == 1 and stats.updated == 0


def test_rule_metadata_and_validation():
    content = _rule("x", "Title From YAML", level="critical")
    meta = rule_metadata(content)
    assert meta["title"] == "Title From YAML" and meta["level"] == "critical"
    assert compile_errors(content) == []
    assert compile_errors("title: t\n") and compile_errors("")
    assert collected(content, {"windows_sysmon"}) and not collected(content, {"linux_auth"})


def test_rule_test_endpoint_evaluates_detection_and_logsource():
    from app.api.routes.rules import test_rule

    content = _rule("x", "Whoami")
    hit = {"Image": "C:\\Windows\\System32\\whoami.exe"}
    r = asyncio.run(test_rule(RuleTestRequest(content=content, sample_event=hit), _=None))
    assert r.matched and r.rule_title == "Whoami" and r.logsource_applies is None
    r = asyncio.run(test_rule(RuleTestRequest(content=content, sample_event={**hit, "log_type": "linux_auth"}), _=None))
    assert not r.matched and r.logsource_applies is False
    line = 'EventID=1 Channel="Microsoft-Windows-Sysmon/Operational" Image="C:\\Windows\\System32\\whoami.exe"'
    r = asyncio.run(test_rule(RuleTestRequest(content=content, sample_event={
        "log_type": "windows_sysmon", "raw_message": line}), _=None))
    assert r.matched and r.logsource_applies is True
    r = asyncio.run(test_rule(RuleTestRequest(content="title: x\ndetection: {}\n", sample_event={}), _=None))
    assert not r.matched and r.error
