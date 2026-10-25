# tests/evidence/test_acceptance.py
"""The acceptance assertions themselves: they compare ID sets, not counts,
so a duplicate can never hide a missing event, and a scenario that injected a
loss cannot pass with a healthy report. No Docker needed."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from assertions import (  # noqa: E402
    assert_delivery, assert_loss_visible, assert_no_receipt, assert_stable_identity,
)


def receipt(event_id, receipt_id=None, status="accepted"):
    return {"event_id": event_id, "receipt_id": receipt_id or f"r-{event_id}", "status": status}


def doc(event_id):
    return {"event_id": event_id}


def test_duplicate_id_cannot_hide_missing_event():
    with pytest.raises(AssertionError):
        assert_delivery({"a", "b"}, [{"event_id": "a"}, {"event_id": "a"}],
                        [{"event_id": "a"}, {"event_id": "a"}])


def test_delivery_needs_every_admitted_event_once():
    assert_delivery({"a", "b"}, [receipt("a"), receipt("b")], [doc("a"), doc("b")])
    with pytest.raises(AssertionError, match="missing"):
        assert_delivery({"a", "b"}, [receipt("a"), receipt("b")], [doc("a")])
    with pytest.raises(AssertionError, match="duplicate"):
        assert_delivery({"a"}, [receipt("a")], [doc("a"), doc("a")])
    with pytest.raises(AssertionError, match="unexpected"):
        assert_delivery({"a"}, [receipt("a"), receipt("z")], [doc("a"), doc("z")])


def test_retries_must_share_one_logical_receipt():
    # a lost response retried: duplicate status, same receipt
    assert_delivery({"a"}, [receipt("a", "r1"), receipt("a", "r1", "duplicate")], [doc("a")])
    with pytest.raises(AssertionError, match="receipt"):
        assert_delivery({"a"}, [receipt("a", "r1"), receipt("a", "r2", "duplicate")], [doc("a")])
    with pytest.raises(AssertionError, match="receipt"):
        assert_delivery({"a"}, [receipt("a", "r1"), receipt("a", "r1", "accepted")], [doc("a")])


def test_injected_loss_must_be_visible():
    assert_loss_visible({"state": "degraded", "reason": "capacity", "known_loss": {"capacity": 3}}, "capacity")
    assert_loss_visible({"state": "healthy", "pending_loss": {"capacity": 1}, "known_loss": {}}, "capacity")
    with pytest.raises(AssertionError):
        assert_loss_visible({"state": "healthy", "reason": "", "known_loss": {}}, "capacity")
    with pytest.raises(AssertionError):
        assert_loss_visible({"state": "degraded", "known_loss": {"oversize": 1}}, "capacity")
    with pytest.raises(AssertionError):
        assert_loss_visible(None, "capacity")


def test_rejected_records_get_no_receipt():
    assert_no_receipt({"x"}, [receipt("a")])
    with pytest.raises(AssertionError):
        assert_no_receipt({"a"}, [receipt("a")])


def test_identities_and_collection_times_stay_stable():
    first = {"a": "2026-10-25T01:00:00Z", "b": "2026-10-25T01:00:01Z"}
    assert_stable_identity(first, dict(first))
    with pytest.raises(AssertionError):
        assert_stable_identity(first, {"a": "2026-10-25T01:00:00Z", "b": "2026-10-25T02:00:00Z"})
    with pytest.raises(AssertionError):
        assert_stable_identity(first, {"a": "2026-10-25T01:00:00Z"})
