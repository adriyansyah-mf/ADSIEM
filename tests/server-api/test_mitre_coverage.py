"""ATT&CK coverage: Sigma tags on rules -> technique codes and tactic (app/api/routes/mitre.py)."""
from app.api.routes.mitre import _rule_techniques


def test_sigma_tags_to_techniques_and_tactic():
    codes, tactic = _rule_techniques(["attack.execution", "attack.t1059.001", "attack.T1105", "cve.2021-44228"])
    assert codes == {"T1059.001", "T1105"}
    assert tactic == "Execution"


def test_multi_word_tactics():
    assert _rule_techniques(["attack.command_and_control", "attack.t1071"])[1] == "Command & Control"
    assert _rule_techniques(["attack.credential_access"])[1] == "Credential Access"


def test_no_tags():
    assert _rule_techniques(None) == (set(), None)
    assert _rule_techniques(["attack.g0016", "attack.s0002"]) == (set(), None)
