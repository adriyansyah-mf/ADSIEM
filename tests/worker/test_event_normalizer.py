from worker.event_normalizer import normalize_event


def test_normalize_event_prefers_canonical_values_and_keeps_ecs_shape():
    # Given
    decoded = {
        "source.ip": "10.0.0.5",
        "host.name": "web-01",
        "user.name": "alice",
        "event.action": "login_failed",
        "event.category": "authentication",
    }

    # When
    normalized = normalize_event(decoded, "agent-host", "2026-09-06T00:00:00+00:00")

    # Then
    assert normalized["source"] == {"ip": "10.0.0.5"}
    assert normalized["host"] == {"name": "web-01"}
    assert normalized["user"] == {"name": "alice"}
    assert normalized["event"] == {"action": "login_failed", "category": "authentication"}


def test_normalize_event_falls_back_to_agent_hostname():
    # Given
    decoded = {"event.action": "process_start"}

    # When
    normalized = normalize_event(decoded, "agent-host", "2026-09-06T00:00:00+00:00")

    # Then
    assert normalized["host"] == {"name": "agent-host"}


def test_normalize_event_maps_authentication_category_to_ocsf():
    decoded = {
        "source.ip": "10.0.0.5", "host.name": "web-01", "user.name": "alice",
        "event.action": "login_failed", "event.category": "authentication",
        "event_id": "4625",
    }

    normalized = normalize_event(decoded, "agent-host", "2026-09-06T00:00:00+00:00")

    assert normalized["ocsf"]["class_uid"] == 3002
    assert normalized["ocsf"]["activity_name"] == "Logon Failure"


def test_normalize_event_falls_back_to_base_event_for_unknown_category():
    decoded = {"event.action": "something_weird", "event.category": "unheard_of"}

    normalized = normalize_event(decoded, "agent-host", "2026-09-06T00:00:00+00:00")

    assert normalized["ocsf"]["class_uid"] == 0
