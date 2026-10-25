# tests/evidence/assertions.py
"""Acceptance checks for durable agent evidence. They compare full ID sets:
a count can match while one event is duplicated and another missing."""
from collections import Counter, defaultdict


def _ids(rows, what):
    ids = [r.get("event_id") for r in rows]
    if None in ids:
        raise AssertionError(f"{what} without event_id")
    return ids


def _set_equal(expected: set, got: list, what: str) -> None:
    dupes = sorted(i for i, n in Counter(got).items() if n > 1)
    missing = sorted(expected - set(got))
    unexpected = sorted(set(got) - expected)
    problems = []
    if missing:
        problems.append(f"{len(missing)} missing {what} (e.g. {missing[:5]})")
    if dupes:
        problems.append(f"{len(dupes)} duplicate {what} (e.g. {dupes[:5]})")
    if unexpected:
        problems.append(f"{len(unexpected)} unexpected {what} (e.g. {unexpected[:5]})")
    if problems:
        raise AssertionError("; ".join(problems))


def assert_delivery(admitted: set[str], receipts: list[dict], documents: list[dict]) -> None:
    """Every successfully admitted event has exactly one logical receipt and
    exactly one Elasticsearch document, and nothing else does.

    Several receipt responses for one event are allowed (a lost response is
    retried and answered "duplicate") only if they carry the same receipt_id,
    and only the first may be "accepted"."""
    by_event = defaultdict(list)
    for r in receipts:
        by_event[r.get("event_id")].append(r)
    logical = []
    for event_id, rs in by_event.items():
        if len({r.get("receipt_id") for r in rs}) != 1:
            raise AssertionError(f"event {event_id} got different receipt ids: {[r.get('receipt_id') for r in rs]}")
        if sum(r.get("status") == "accepted" for r in rs) > 1:
            raise AssertionError(f"event {event_id} was accepted more than once (receipt ids repeat)")
        logical.append(event_id)
    if None in by_event:
        raise AssertionError("receipt without event_id")
    _set_equal(set(admitted), logical, "receipts")
    _set_equal(set(admitted), _ids(documents, "document"), "documents")


def assert_loss_visible(health: dict | None, reason: str) -> None:
    """A scenario that injected a loss of `reason` must see it counted, durably
    or pending, never a clean healthy report."""
    if not health:
        raise AssertionError(f"no evidence health reported after injecting {reason}")
    known = (health.get("known_loss") or {}).get(reason, 0)
    pending = (health.get("pending_loss") or {}).get(reason, 0)
    if known <= 0 and pending <= 0:
        raise AssertionError(f"injected {reason} loss is not counted: state={health.get('state')} "
                             f"known={health.get('known_loss')} pending={health.get('pending_loss')}")


def assert_no_receipt(rejected: set[str], receipts: list[dict]) -> None:
    """Records the agent refused (or quarantined) must not have been receipted."""
    receipted = rejected & {r.get("event_id") for r in receipts}
    if receipted:
        raise AssertionError(f"rejected records were receipted: {sorted(receipted)[:5]}")


def assert_stable_identity(first: dict[str, str], later: dict[str, str]) -> None:
    """Event IDs and their collection times survive restarts and retries."""
    _set_equal(set(first), list(later), "events after restart")
    changed = sorted(i for i in first if first[i] != later[i])
    if changed:
        raise AssertionError(f"collection time changed for {len(changed)} events (e.g. {changed[:5]})")
