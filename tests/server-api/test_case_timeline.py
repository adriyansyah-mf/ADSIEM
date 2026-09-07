from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.routes.cases import router as cases_router
from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group

NOW = datetime(2026, 9, 7, 12, 0, 0, tzinfo=timezone.utc)


def _case(alert_id=None, created_at=NOW, group_id="blue"):
    return SimpleNamespace(id=uuid4(), alert_id=alert_id, created_at=created_at, group_id=group_id)


def _alert(**kwargs):
    defaults = dict(
        id=uuid4(), created_at=NOW, title="Suspicious login", severity="high",
        source_ip="10.0.0.5", hostname="host-1", mitre_techniques=[], kill_chain_stage=None,
        correlation_id=None, correlation_key=None, source_event_ids=[], agent_id=uuid4(),
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def _alert_note(content="note", created_at=NOW):
    return SimpleNamespace(id=uuid4(), content=content, created_at=created_at)


def _case_note(content="case note", created_at=NOW, is_ai_generated=False):
    return SimpleNamespace(id=uuid4(), content=content, created_at=created_at, is_ai_generated=is_ai_generated)


def _fim_event(created_at=NOW, path="/etc/passwd", event_type="modified", sha256="abc"):
    return SimpleNamespace(id=uuid4(), detected_at=created_at, path=path, event_type=event_type, sha256=sha256)


def _ioc_pair(created_at=NOW, indicator="1.2.3.4", verdict="malicious"):
    link = SimpleNamespace(id=uuid4(), linked_at=created_at)
    obs = SimpleNamespace(indicator=indicator, ioc_type="ipv4", verdict=verdict, confidence=0.9, source="ti")
    return link, obs


def _soar_step(created_at=NOW, action_type="isolate_agent", status="completed"):
    return SimpleNamespace(
        id=uuid4(), acted_at=created_at, action_type=action_type, status=status,
        is_destructive=True, is_reversible=True,
    )


class _ScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


class _ScalarsResult:
    def __init__(self, values):
        self._values = values

    def scalars(self):
        return self

    def all(self):
        return self._values


class _RowsResult:
    def __init__(self, values):
        self._values = values

    def all(self):
        return self._values


class _FakeSession:
    def __init__(self, *, case, triggering=None, related_alerts=None, alert_notes=None,
                 case_notes=None, fim_events=None, ioc_rows=None, soar_steps=None):
        self._case = case
        self._triggering = triggering
        self._related_alerts = related_alerts or []
        self._alert_notes = alert_notes or []
        self._case_notes = case_notes or []
        self._fim_events = fim_events or []
        self._ioc_rows = ioc_rows or []
        self._soar_steps = soar_steps or []

    async def get(self, model, id_):
        return self._triggering

    async def execute(self, stmt, *args, **kwargs):
        sql = str(stmt)
        if "FROM cases" in sql:
            return _ScalarResult(self._case)
        if "FROM ioc_links" in sql:
            return _RowsResult(self._ioc_rows)
        if "FROM soar_run_steps" in sql:
            return _ScalarsResult(self._soar_steps)
        if "FROM fim_events" in sql:
            return _ScalarsResult(self._fim_events)
        if "FROM case_notes" in sql:
            return _ScalarsResult(self._case_notes)
        if "FROM alert_notes" in sql:
            return _ScalarsResult(self._alert_notes)
        if "FROM alerts" in sql:
            return _ScalarsResult(self._related_alerts)
        raise AssertionError(f"unexpected query: {sql[:200]}")


def _client(session: _FakeSession, group_id: str | None = "blue") -> TestClient:
    app = FastAPI()
    app.include_router(cases_router)

    async def override_db():
        yield session

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(id=uuid4())
    app.dependency_overrides[get_scoped_group] = lambda: group_id
    return TestClient(app)


def test_returns_404_for_missing_case():
    session = _FakeSession(case=None)
    client = _client(session)

    response = client.get(f"/api/cases/{uuid4()}/timeline")

    assert response.status_code == 404


def test_merges_alert_and_case_notes_tagged_by_source():
    case_id = uuid4()
    alert_id = uuid4()
    case = _case(alert_id=alert_id)
    case.id = case_id
    triggering = _alert(id=alert_id)
    alert_note = _alert_note(content="from alert")
    case_note = _case_note(content="from case")
    session = _FakeSession(
        case=case, triggering=triggering, alert_notes=[alert_note], case_notes=[case_note],
    )
    client = _client(session)

    response = client.get(f"/api/cases/{case_id}/timeline")

    assert response.status_code == 200
    notes = [i for i in response.json()["items"] if i["type"] == "note"]
    sources = {n["note_source"] for n in notes}
    assert sources == {"alert", "case"}


def test_includes_fim_events_for_triggering_agent():
    case_id = uuid4()
    alert_id = uuid4()
    case = _case(alert_id=alert_id)
    case.id = case_id
    triggering = _alert(id=alert_id)
    fim = _fim_event(path="/etc/shadow", event_type="modified")
    session = _FakeSession(case=case, triggering=triggering, fim_events=[fim])
    client = _client(session)

    response = client.get(f"/api/cases/{case_id}/timeline")

    fim_items = [i for i in response.json()["items"] if i["type"] == "fim"]
    assert len(fim_items) == 1
    assert fim_items[0]["path"] == "/etc/shadow"


def test_includes_ioc_enrichment_linked_to_alert():
    case_id = uuid4()
    alert_id = uuid4()
    case = _case(alert_id=alert_id)
    case.id = case_id
    triggering = _alert(id=alert_id)
    link, obs = _ioc_pair(indicator="203.0.113.9", verdict="malicious")
    session = _FakeSession(case=case, triggering=triggering, ioc_rows=[(link, obs)])
    client = _client(session)

    response = client.get(f"/api/cases/{case_id}/timeline")

    enrichment_items = [i for i in response.json()["items"] if i["type"] == "enrichment"]
    assert len(enrichment_items) == 1
    assert enrichment_items[0]["indicator"] == "203.0.113.9"
    assert enrichment_items[0]["verdict"] == "malicious"


def test_includes_soar_execution_steps():
    case_id = uuid4()
    alert_id = uuid4()
    case = _case(alert_id=alert_id)
    case.id = case_id
    triggering = _alert(id=alert_id)
    step = _soar_step(action_type="block_ip", status="completed")
    session = _FakeSession(case=case, triggering=triggering, soar_steps=[step])
    client = _client(session)

    response = client.get(f"/api/cases/{case_id}/timeline")

    soar_items = [i for i in response.json()["items"] if i["type"] == "soar_step"]
    assert len(soar_items) == 1
    assert soar_items[0]["action_type"] == "block_ip"


def test_cursor_pagination_splits_items_across_pages():
    case_id = uuid4()
    alert_id = uuid4()
    case = _case(alert_id=alert_id)
    case.id = case_id
    triggering = _alert(id=alert_id)
    notes = [_alert_note(content=f"note-{i}", created_at=NOW + timedelta(minutes=i)) for i in range(5)]
    session = _FakeSession(case=case, triggering=triggering, alert_notes=notes)
    client = _client(session)

    first_page = client.get(f"/api/cases/{case_id}/timeline?limit=2").json()
    assert len(first_page["items"]) == 2
    assert first_page["total"] == 5
    assert first_page["next_cursor"] is not None

    second_page = client.get(
        f"/api/cases/{case_id}/timeline?limit=2&cursor={first_page['next_cursor']}"
    ).json()
    assert len(second_page["items"]) == 2
    assert second_page["items"][0]["title"] == "note-2"

    third_page = client.get(
        f"/api/cases/{case_id}/timeline?limit=2&cursor={second_page['next_cursor']}"
    ).json()
    assert len(third_page["items"]) == 1
    assert third_page["next_cursor"] is None


def test_invalid_cursor_returns_422():
    case = _case()
    session = _FakeSession(case=case)
    client = _client(session)

    response = client.get(f"/api/cases/{case.id}/timeline?cursor=not-valid-base64!!!")

    assert response.status_code == 422


def test_case_with_no_alert_still_returns_case_notes_only():
    case = _case(alert_id=None)
    case_note = _case_note(content="standalone case note")
    session = _FakeSession(case=case, case_notes=[case_note])
    client = _client(session)

    response = client.get(f"/api/cases/{case.id}/timeline")

    assert response.status_code == 200
    items = response.json()["items"]
    assert len(items) == 1
    assert items[0]["type"] == "note"
    assert items[0]["note_source"] == "case"
