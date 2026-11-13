# tests/server-api/test_sensor_health.py
"""Sensor tamper detection from heartbeat sensor_health (app/services/sensor_health.py)."""
from app.services.sensor_health import LOST_MIN, LOST_REPORT_EVERY, MIN_BASELINE, evaluate

HOUR = 3600


def stat(events, running=True, lost=0, error=""):
    return {"running": running, "events": events, "lost": lost, "error": error}


def names(events):
    return [(e, f["sensor"]) for e, f in events]


def test_first_heartbeat_only_records():
    state, events = evaluate(None, {"etw": stat(500)}, 0, HOUR)
    assert events == [] and state["etw"]["events"] == 500


def test_a_running_sensor_that_stops_is_reported():
    state, _ = evaluate(None, {"etw": stat(500)}, 0, HOUR)
    _, events = evaluate(state, {"etw": stat(510, running=False, error="session stopped")}, 30, HOUR)
    assert events == [("agent_sensor_stopped", {"sensor": "etw", "error": "session stopped"})]
    # a sensor that disappears from the heartbeat counts as stopped too
    _, events = evaluate(state, {}, 30, HOUR)
    assert names(events) == [("agent_sensor_stopped", "etw")]


def test_silence_is_reported_once_and_clears_when_events_flow():
    state, _ = evaluate(None, {"procexec": stat(900)}, 0, HOUR)
    state, events = evaluate(state, {"procexec": stat(900)}, HOUR - 60, HOUR)
    assert events == []  # not yet an hour
    state, events = evaluate(state, {"procexec": stat(900)}, HOUR, HOUR)
    assert events == [("agent_sensor_silent", {"sensor": "procexec", "silent_minutes": 60, "events": 900})]
    state, events = evaluate(state, {"procexec": stat(900)}, 2 * HOUR, HOUR)
    assert events == []  # once per silence
    state, events = evaluate(state, {"procexec": stat(901)}, 2 * HOUR + 30, HOUR)
    assert events == [] and state["procexec"]["silent"] is False
    _, events = evaluate(state, {"procexec": stat(901)}, 3 * HOUR + 60, HOUR)
    assert names(events) == [("agent_sensor_silent", "procexec")]  # a new silence


def test_quiet_sensors_without_a_baseline_and_restarts_are_not_silence():
    state, _ = evaluate(None, {"netwatch": stat(MIN_BASELINE - 1)}, 0, HOUR)
    _, events = evaluate(state, {"netwatch": stat(MIN_BASELINE - 1)}, 5 * HOUR, HOUR)
    assert events == []
    state, _ = evaluate(None, {"etw": stat(5000)}, 0, HOUR)
    state, events = evaluate(state, {"etw": stat(40)}, 2 * HOUR, HOUR)  # agent restarted: counters reset
    assert events == [] and state["etw"]["changed_at"] == 2 * HOUR
    # silence 0 turns the check off
    state, _ = evaluate(None, {"etw": stat(500)}, 0, 0)
    assert evaluate(state, {"etw": stat(500)}, 10 * HOUR, 0)[1] == []


def test_lost_events_are_rate_limited():
    state, _ = evaluate(None, {"etw": stat(10, lost=0)}, 0, HOUR)
    state, events = evaluate(state, {"etw": stat(20, lost=LOST_MIN - 1)}, 30, HOUR)
    assert events == []
    state, events = evaluate(state, {"etw": stat(30, lost=LOST_MIN + 500)}, 60, HOUR)
    assert events == [("agent_sensor_events_lost", {"sensor": "etw", "lost": 501, "lost_total": LOST_MIN + 500})]
    state, events = evaluate(state, {"etw": stat(40, lost=LOST_MIN + 5000)}, 90, HOUR)
    assert events == []  # within the hour
    _, events = evaluate(state, {"etw": stat(50, lost=LOST_MIN + 9000)}, 60 + LOST_REPORT_EVERY, HOUR)
    assert names(events) == [("agent_sensor_events_lost", "etw")]
