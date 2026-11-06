"""The AI may only select supplied candidates; low confidence needs review."""
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from worker.case_correlation import Candidate, Decision, validate_decision


def candidate():
    return Candidate(case_id=uuid4(), title="Brute force", summary="Repeated failures against admin",
                     keys=["ip:8.8.8.8"], hosts=["web01"], accounts=["admin"], updated_at=datetime.now(timezone.utc))


def test_high_confidence_can_select_eligible_candidate():
    case = candidate()
    decision = validate_decision(Decision(action="join", case_id=case.case_id, confidence=0.95,
                                         reason="Same account and host within five minutes"), [case])
    assert decision.action == "join" and decision.case_id == case.case_id


def test_unknown_candidate_is_never_joined():
    decision = validate_decision(Decision(action="join", case_id=uuid4(), confidence=1), [candidate()])
    assert decision.action == "new" and decision.case_id is None


def test_low_confidence_becomes_suggestion():
    case = candidate()
    decision = validate_decision(Decision(action="join", case_id=case.case_id, confidence=0.89), [case])
    assert decision.action == "suggest"


@pytest.mark.parametrize("confidence", [-1, 1.1, float("nan")])
def test_invalid_confidence_is_rejected(confidence):
    with pytest.raises(ValidationError):
        Decision(action="join", case_id=uuid4(), confidence=confidence)


def test_new_decision_cannot_carry_an_association():
    case = candidate()
    decision = validate_decision(Decision(action="new", case_id=case.case_id), [case])
    assert decision.case_id is None
