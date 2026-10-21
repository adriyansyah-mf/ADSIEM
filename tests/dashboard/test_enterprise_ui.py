"""UI regressions with isolated API fixtures; never writes to a real backend.

Start Vite, then run DASHBOARD_TEST_URL=http://127.0.0.1:5173 pytest
tests/dashboard/test_enterprise_ui.py. Requires Playwright Chromium.
"""
import json
import os
import re
from urllib.parse import parse_qs, quote, urlparse

import pytest

BASE_URL = os.environ.get("DASHBOARD_TEST_URL", "http://localhost:5173")
USER = {"id": "analyst-fixture", "username": "alex.morgan", "email": "alex@example.test",
        "role": "superadmin", "group_id": None, "is_active": True}
ALERT = {"id": "alert-fixture", "title": "Suspicious PowerShell execution", "severity": "critical",
         "status": "new", "hostname": "WIN-FIN-042", "source_ip": "192.0.2.42", "agent_id": None,
         "group_id": "finance", "created_at": "2026-10-21T07:32:00Z", "updated_at": "2026-10-21T07:32:00Z", "notes": [],
         "mitre_techniques": ["T1059.001"], "duplicate_count": 1}
CASE = {"id": "case-fixture", "title": "Investigate suspicious PowerShell activity",
        "description": "Review endpoint evidence and document the response.", "severity": "critical",
        "status": "open", "alert_id": None, "assignee_id": None, "group_id": "finance",
        "created_at": ALERT["created_at"], "updated_at": ALERT["created_at"], "notes": [],
        "ioc_data": {}, "search_intel": {"results": []}, "created_by_ai": False}
AGENT = {"id": "agent-fixture", "name": "Finance workstation", "hostname": "WIN-FIN-042",
         "group_id": "finance", "version": "1.7.0", "status": "online", "approved": True,
         "is_isolated": False, "last_seen_at": ALERT["created_at"], "enrolled_at": ALERT["created_at"],
         "log_sources": []}
RAW_LOG = {"id": "log-fixture", "agent_id": "agent-fixture", "log_type": "linux_auth",
           "raw_message": "sshd: Failed password for invalid user backup from 192.0.2.42 port 49218 ssh2\n" + "evidence-" * 80 + "END-OF-RAW-EVIDENCE",
           "received_at": ALERT["created_at"]}
EVENT = {"id": "event-fixture", "agent_id": "agent-fixture", "group_id": "finance",
         "event_category": "authentication", "event_action": "login_failed", "source_ip": "192.0.2.42",
         "user_name": "backup", "created_at": ALERT["created_at"],
         "decoded_fields": {"process.command_line": "powershell.exe -NoProfile " + "evidence-" * 80 + "END-OF-DECODED-EVIDENCE", "source.ip": "192.0.2.42"}}


HUNT = {"id": "hunt-fixture", "ioc_type": "ip", "ioc_value": "192.0.2.42", "status": "done",
        "group_id": "finance", "alert_count": 2, "event_count": 7, "fim_count": 1, "risk_level": "high",
        "analysis": json.dumps({"attack_narrative": "Review **suspicious activity** before containment.",
                                "mitre_techniques": ["T1059.001"], "kill_chain_phase": "execution",
                                "recommended_actions": ["Validate the endpoint owner"]}),
        "timeline": [{"id": "alert-fixture", "time": ALERT["created_at"], "type": "alert", "severity": "high",
                      "title": "evidence-" * 100 + "END-OF-HUNT-EVIDENCE"}],
        "related_alert_ids": ["alert-fixture"], "created_at": ALERT["created_at"], "completed_at": ALERT["created_at"]}
SCHEDULE = {"id": "schedule-fixture", "name": "Nightly finance hunt", "ioc_type": "ip", "ioc_value": "192.0.2.42",
            "interval_hours": 24, "group_id": "finance", "is_enabled": True, "last_run_at": None,
            "created_at": ALERT["created_at"]}
UEBA_SCORE = {"entity_type": "user", "entity_value": "finance\\alex@example.test", "group_id": "finance",
              "risk_score": 84.5, "anomaly_count": 3, "last_anomaly_at": ALERT["created_at"],
              "last_seen_at": ALERT["created_at"], "updated_at": ALERT["created_at"]}
UEBA_ANOMALY = {"id": "anomaly-fixture", "entity_type": "user", "entity_value": UEBA_SCORE["entity_value"],
                "anomaly_score": 0.823, "risk_score": 84.5, "features": {"failed_ratio": 0.75, "unique_ips": 4},
                "alert_id": "alert-fixture", "case_id": "case-fixture", "ai_action": "monitor",
                "ai_narrative": "Verify the endpoint owner before response.", "detected_at": ALERT["created_at"],
                "mitre_techniques": [{"id": "T1110", "name": "Brute Force"}],
                "reasons": [{"feature": "failed_ratio", "value": 0.75, "z": 3.2,
                             "text": "evidence-" * 90 + "END-OF-UEBA-EVIDENCE"}]}


@pytest.fixture
def enterprise(page):
    from playwright.sync_api import expect

    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.add_init_script("localStorage.setItem('siem-auth', " + json.dumps(json.dumps({
        "state": {"accessToken": "fixture-only", "user": USER}, "version": 0,
    })) + ")")
    state = {"mode": "normal", "requests": [], "writes": [], "agent": dict(AGENT),
             "case": dict(CASE), "role": "superadmin", "write_error": False, "investigations": [],
             "hunts": [dict(HUNT)], "schedules": [dict(SCHEDULE)], "ueba_errors": [],
             "ueba_status": {"status": "ready", "trained_at": ALERT["created_at"], "user_snapshot_count": 72, "ip_snapshot_count": 48, "host_snapshot_count": 12},
             "ueba_anomalies": [dict(UEBA_ANOMALY)], "ueba_history": [{"day": "2026-10-20", "max_risk": 60, "anomaly_count": 1}, {"day": "2026-10-21", "max_risk": 84.5, "anomaly_count": 2}]}

    def respond(route):
        url = urlparse(route.request.url)
        state["requests"].append(url)
        path = url.path
        if route.request.method not in ("GET", "HEAD", "OPTIONS"):
            state["writes"].append((route.request.method, path, route.request.post_data_json))
            if state["write_error"]:
                route.fulfill(status=503, content_type="application/json", body='{"detail":"Fixture outage"}')
                return
        status = 200
        body = []
        if path == "/api/auth/me":
            body = {**USER, "role": state["role"]}
        elif path.startswith("/api/ueba/"):
            part = "status" if path.endswith("/status") else "entities" if path.endswith("/entities") else "history" if path.endswith("/history") else "detail"
            if part in state["ueba_errors"] or state["mode"] == "error":
                status, body = 503, {"detail": "Fixture outage"}
            elif part == "status":
                body = state["ueba_status"]
            elif part == "entities":
                query = parse_qs(url.query)
                entity_type = query.get("entity_type", ["user"])[0]
                item = {**UEBA_SCORE, "entity_type": entity_type, "entity_value": "192.0.2.42" if entity_type == "ip" else UEBA_SCORE["entity_value"]}
                body = [] if state["mode"] == "empty" or float(query.get("min_risk", [0])[0]) > 84.5 else [item]
            elif part == "detail":
                body = {"score": UEBA_SCORE, "anomalies": state["ueba_anomalies"]}
            else:
                body = {"entity_type": "user", "entity_value": UEBA_SCORE["entity_value"], "days": 30, "history": state["ueba_history"]}
        elif path in ("/api/hunts", "/api/hunt-schedules"):
            key = "hunts" if path == "/api/hunts" else "schedules"
            if route.request.method == "POST":
                template = HUNT if key == "hunts" else SCHEDULE
                body = {**template, **route.request.post_data_json, "id": "created-fixture"}
                if key == "hunts":
                    body.update(status="pending", analysis=None, timeline=None, alert_count=0, event_count=0, fim_count=0, risk_level=None, completed_at=None)
                state[key].insert(0, body)
            else:
                body = [] if state["mode"] == "empty" else state[key]
                if state["mode"] == "error":
                    status, body = 503, {"detail": "Fixture outage"}
        elif path == "/api/hunt-schedules/schedule-fixture/toggle":
            state["schedules"][0]["is_enabled"] = not state["schedules"][0]["is_enabled"]
            body = state["schedules"][0]
        elif path == "/api/hunt-schedules/schedule-fixture":
            state["schedules"] = []
            status, body = 204, None
        elif path == "/api/alerts":
            if state["mode"] == "error":
                status, body = 503, {"detail": "Fixture outage"}
            else:
                items = [] if state["mode"] == "empty" else [ALERT]
                body = {"items": items, "total": len(items), "page": 1, "page_size": 25}
        elif path == "/api/alerts/alert-fixture":
            body = {**ALERT, "rule": None, "rule_fired_24h": 1, "mitre": [], "event": None,
                    "agent": None, "ueba": None, "related": []}
        elif path == "/api/cases/case-fixture/investigations":
            body = state["investigations"]
        elif path == "/api/cases/case-fixture":
            if route.request.method == "PUT":
                state["case"].update(route.request.post_data_json)
            body = state["case"]
        elif path == "/api/cases/case-fixture/escalate":
            state["case"]["status"] = "escalated"
            body = state["case"]
        elif path == "/api/agents/agent-fixture/isolate":
            state["agent"]["is_isolated"] = route.request.method == "POST"
            body = state["agent"]
        elif path == "/api/agents/agent-fixture/approve":
            state["agent"]["approved"] = True
            body = state["agent"]
        elif path == "/api/agents/agent-fixture/uninstall-token":
            body = {"token": "synthetic-uninstall-token", "commands": {
                "windows": "fixture Windows command", "debian": "fixture Debian command", "rhel": "fixture RHEL command"}}
        elif path.endswith("/timeline"):
            body = {"items": []}
        elif path in ("/api/cases", "/api/agents"):
            items = [state["case"]] if path == "/api/cases" else [state["agent"]]
            body = {"items": [] if state["mode"] == "empty" else items, "total": 0 if state["mode"] == "empty" else 1,
                    "page": 1, "page_size": 25}
            if state["mode"] == "error":
                status, body = 503, {"detail": "Fixture outage"}
        elif path in ("/api/logs", "/api/events"):
            query = parse_qs(url.query)
            size = int(query.get("page_size", [25])[0])
            offset = int(query.get("after", [0])[0])
            template = RAW_LOG if path == "/api/logs" else EVENT
            total = 0 if state["mode"] == "empty" else 51
            items = [{**template, "id": f"{template['id']}-{i}"} for i in range(offset, min(offset + size, total))]
            body = {"items": items, "total": total, "page": 1, "page_size": size,
                    "next_after": str(offset + size) if offset + size < total else None}
            if state["mode"] == "error":
                status, body = 503, {"detail": "Fixture outage"}
        elif path == "/api/users":
            body = {"items": [], "total": 0, "page": 1, "page_size": 25}
        elif path == "/api/metrics/soc":
            body = {"period_days": 7, "total_alerts": 1842, "open_cases": 18,
                    "by_severity": {"critical": 42}, "by_status": {"new": 247},
                    "avg_ack_minutes": 8.4, "avg_mttr_minutes": 74, "false_positive_rate_pct": 0}
        elif path.endswith("/timeseries") or path.endswith("/mttr-trend"):
            body = {"period_days": 7, "points": []}
        elif path.endswith("/top-sources"):
            body = {"period_days": 7, "sources": []}
        elif path == "/api/search":
            body = {"alerts": [ALERT], "cases": [CASE]}
        route.fulfill(status=status, content_type="application/json", body=json.dumps(body))

    page.route(BASE_URL + "/api/**", respond)
    yield state, expect
    assert not errors, errors


@pytest.mark.parametrize("status, message", [
    ("found", "Known malware record"),
    ("not_found", "Unknown to this provider — not a clean verdict"),
    ("unavailable", "Provider unavailable — investigation continues"),
])
def test_investigation_displays_hash_enrichment_evidence(page, enterprise, status, message, tmp_path):
    # Given persisted hash evidence from an AI-selected lookup.
    state, expect = enterprise
    h = "a" * 64
    state["investigations"] = [{
        "id": "investigation-fixture", "case_id": CASE["id"], "status": "finished",
        "model": "scripted-fixture", "verdict": "inconclusive", "report": None,
        "error": None, "commands": [], "created_at": ALERT["created_at"], "finished_at": ALERT["created_at"],
        "steps": [{"kind": "enrichment", "ts": ALERT["created_at"], "reason": "Validate suspicious file",
                   "result": {"provider": "MalwareBazaar", "status": status, "queried_hash": h,
                              "checked_at": ALERT["created_at"], "cached": False,
                              "sample": {"signature": "ExampleFamily", "tags": ["trojan"]} if status == "found" else None,
                              "report_url": f"https://bazaar.abuse.ch/sample/{h}/" if status == "found" else None}}],
    }]
    # When the analyst opens the case's investigation activity.
    page.set_viewport_size({"width": 390, "height": 844})
    page.goto(BASE_URL + "/cases/case-fixture")
    # Then provenance and distinct outcomes are visible without starting a new lookup.
    expect(page.get_by_text("MalwareBazaar enrichment", exact=True)).to_be_visible()
    expect(page.get_by_text(message, exact=False)).to_be_visible()
    expect(page.get_by_text(h, exact=True)).to_be_visible()
    if status == "found":
        expect(page.get_by_text("ExampleFamily", exact=False)).to_be_visible()
        expect(page.get_by_role("link", name="Provider report")).to_have_attribute(
            "href", f"https://bazaar.abuse.ch/sample/{h}/")
    assert not state["writes"]
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    page.screenshot(path=str(tmp_path / f"malwarebazaar-{status}.png"))


@pytest.mark.parametrize("width", [390, 768, 1440, 1920])
@pytest.mark.parametrize("route,title", [
    ("/", "Operations overview"), ("/alerts", "Alerts"),
    ("/cases/case-fixture", CASE["title"]),
    ("/cases", "Cases"), ("/agents", "Agents"),
    ("/logs", "Raw logs"), ("/events", "Events"),
    ("/hunts", "Threat hunting"),
    ("/ueba", "Behavior analytics"),
])
def test_workspace_responsive(page, enterprise, width, route, title, tmp_path):
    _, expect = enterprise
    page.set_viewport_size({"width": width, "height": 900})
    page.goto(BASE_URL + route)
    expect(page.get_by_role("heading", name=title, exact=True)).to_be_visible()
    if route == "/alerts":
        expect(page.get_by_role("cell", name=ALERT["title"], exact=False)).to_be_visible()
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    assert page.locator("main").evaluate("el => el.scrollWidth <= el.clientWidth")
    page.screenshot(path=str(tmp_path / f"workspace-{width}.png"))
    page.locator("main").evaluate("el => el.scrollTop = el.scrollHeight")
    page.screenshot(path=str(tmp_path / f"workspace-{width}-end.png"))


def test_filters_table_and_keyboard_navigation(page, enterprise):
    state, expect = enterprise
    page.goto(BASE_URL + "/alerts?severity=critical&search=PowerShell")
    expect(page.get_by_label("Search detections")).to_have_value("PowerShell")
    expect(page.get_by_role("cell", name=ALERT["title"], exact=False)).to_be_visible()
    page.get_by_label("Row density").select_option("compact")
    expect(page.get_by_label("Row density")).to_have_value("compact")
    page.locator("summary").filter(has_text="Columns").click()
    page.get_by_label("Country", exact=True).check()
    expect(page.get_by_role("columnheader", name="Country", exact=True)).to_be_visible()
    page.keyboard.press("Escape")
    assert not page.locator("details").first.evaluate("el => el.open")
    row = page.locator("tbody tr[tabindex]").first
    row.focus()
    page.keyboard.press("Enter")
    expect(page).to_have_url(BASE_URL + "/alerts/alert-fixture")
    assert any(parse_qs(url.query).get("severity") == ["critical"] for url in state["requests"])


def test_mobile_navigation_escape_and_focus_return(page, enterprise):
    _, expect = enterprise
    page.set_viewport_size({"width": 390, "height": 844})
    page.goto(BASE_URL + "/alerts")
    trigger = page.get_by_role("button", name="Open navigation", exact=True)
    trigger.click()
    expect(page.get_by_role("dialog", name="Navigation")).to_be_visible()
    page.keyboard.press("Escape")
    expect(page.get_by_role("dialog", name="Navigation")).not_to_be_visible()
    expect(trigger).to_be_focused()


@pytest.mark.parametrize("mode,text", [("empty", "No alerts match this view"),
                                       ("error", "Could not load alerts")])
def test_distinct_query_states(page, enterprise, mode, text):
    state, expect = enterprise
    state["mode"] = mode
    page.goto(BASE_URL + "/alerts?severity=critical")
    expect(page.get_by_role("heading", name=text, exact=True)).to_be_visible(timeout=15000)
    expect(page.get_by_role("combobox", name="Severity", exact=True)).to_have_value("critical")


def test_aggregate_metrics_and_global_search(page, enterprise):
    _, expect = enterprise
    page.goto(BASE_URL + "/")
    expect(page.locator(".metric-card").filter(has_text="New alerts")).to_contain_text("247")
    page.get_by_role("textbox", name="Search alerts and cases").fill("PowerShell")
    expect(page.locator("#global-search-results").get_by_role("link", name=ALERT["title"])).to_be_visible()
    page.keyboard.press("Escape")
    expect(page.locator("#global-search-results")).not_to_be_visible()


def test_search_restored_when_navigating_history(page, enterprise):
    _, expect = enterprise
    page.goto(BASE_URL + "/alerts")
    search = page.get_by_role("textbox", name="Search detections")
    search.fill("PowerShell")
    expect(page).to_have_url(re.compile(r"search=PowerShell"))
    search.fill("ransomware")
    expect(page).to_have_url(re.compile(r"search=ransomware"))
    page.go_back()
    expect(search).to_have_value("PowerShell")


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_dark_workspace_and_reduced_motion_policy(page, enterprise, scheme):
    _, expect = enterprise
    page.emulate_media(color_scheme=scheme, reduced_motion="reduce")
    page.goto(BASE_URL + "/alerts")
    expect(page.get_by_role("heading", name="Alerts", exact=True)).to_be_visible()
    assert page.evaluate("getComputedStyle(document.body).backgroundColor") == "rgb(16, 19, 24)"
    assert page.evaluate("matchMedia('(prefers-reduced-motion: reduce)').matches")


def test_cases_deep_link_filters_and_row_opening(page, enterprise):
    state, expect = enterprise
    page.goto(BASE_URL + "/cases?status=open&severity=critical&search=PowerShell")
    expect(page.get_by_role("textbox", name="Search cases")).to_have_value("PowerShell")
    expect(page.get_by_role("combobox", name="Status", exact=True)).to_have_value("open")
    expect(page.get_by_role("combobox", name="Severity", exact=True)).to_have_value("critical")
    row = page.get_by_role("row").filter(has_text=CASE["title"])
    row.focus()
    page.keyboard.press("Enter")
    expect(page).to_have_url(BASE_URL + "/cases/case-fixture")
    assert any(url.path == "/api/cases" and parse_qs(url.query).get("status") == ["open"]
               for url in state["requests"])


def test_case_quick_assignment(page, enterprise):
    state, expect = enterprise
    page.goto(BASE_URL + "/cases")
    page.get_by_role("button", name="Expand record").click()
    page.get_by_role("button", name="Assign to me", exact=True).click()
    expect(page.get_by_role("button", name="Assigned to you")).to_be_disabled()
    assert ("PUT", "/api/cases/case-fixture", {"assignee_id": USER["id"]}) in state["writes"]


@pytest.mark.parametrize("width", [390, 1440])
def test_agent_isolation_requires_confirmation(page, enterprise, tmp_path, width):
    state, expect = enterprise
    page.set_viewport_size({"width": width, "height": 900})
    page.goto(BASE_URL + "/agents")
    page.get_by_role("button", name="Expand record", exact=True).click()
    page.get_by_role("button", name="Isolate host", exact=True).click()
    dialog = page.get_by_role("dialog", name="Isolate WIN-FIN-042?")
    expect(dialog).to_be_visible()
    assert not state["writes"]
    page.screenshot(path=str(tmp_path / "isolation-confirmation.png"))
    dialog.get_by_role("button", name="Cancel", exact=True).click()
    assert not state["writes"]
    page.get_by_role("button", name="Isolate host", exact=True).click()
    dialog.get_by_role("button", name="Isolate host", exact=True).click()
    expect(page.get_by_role("button", name="Lift isolation", exact=True)).to_be_visible()
    assert any(method == "POST" and path.endswith("/isolate") for method, path, _ in state["writes"])


@pytest.mark.parametrize("width", [390, 1440])
def test_agent_token_dialog_escape_returns_focus(page, enterprise, width, tmp_path):
    _, expect = enterprise
    page.set_viewport_size({"width": width, "height": 900})
    page.goto(BASE_URL + "/agents")
    page.get_by_role("button", name="Expand record", exact=True).click()
    trigger = page.get_by_role("button", name="Uninstall token", exact=True)
    trigger.click()
    expect(page.get_by_role("dialog", name="Uninstall token · WIN-FIN-042")).to_be_visible()
    expect(page.get_by_text("synthetic-uninstall-token", exact=True)).to_be_visible()
    page.screenshot(path=str(tmp_path / "uninstall-token-dialog.png"))
    page.keyboard.press("Escape")
    expect(page.get_by_role("dialog")).not_to_be_visible()
    expect(trigger).to_be_focused()


@pytest.mark.parametrize("resource", ["cases", "agents"])
def test_list_errors_are_not_empty_states(page, enterprise, resource, tmp_path):
    state, expect = enterprise
    state["mode"] = "error"
    page.goto(BASE_URL + "/" + resource)
    expect(page.get_by_role("heading", name="Could not load " + resource, exact=True)).to_be_visible(timeout=15000)
    expect(page.get_by_role("button", name="Try again")).to_be_visible()
    page.screenshot(path=str(tmp_path / "list-error.png"))


@pytest.mark.parametrize("width", [390, 1440])
def test_case_closing_requires_confirmation(page, enterprise, width, tmp_path):
    state, expect = enterprise
    page.set_viewport_size({"width": width, "height": 900})
    page.goto(BASE_URL + "/cases")
    page.get_by_role("button", name="Expand record").click()
    page.get_by_role("button", name="Close case", exact=True).click()
    dialog = page.get_by_role("dialog", name="Close this case?")
    expect(dialog).to_contain_text(CASE["title"])
    page.screenshot(path=str(tmp_path / "close-case-dialog.png"))
    assert not state["writes"]
    dialog.get_by_role("button", name="Cancel", exact=True).click()
    assert not state["writes"]
    page.get_by_role("button", name="Close case", exact=True).click()
    dialog.get_by_role("button", name="Close case", exact=True).click()
    expect(page.locator("tbody tr[tabindex]").filter(has_text=CASE["title"])).to_contain_text("Closed")
    assert ("PUT", "/api/cases/case-fixture", {"status": "closed"}) in state["writes"]


def test_case_escalation_preserves_quick_action(page, enterprise):
    state, expect = enterprise
    page.goto(BASE_URL + "/cases")
    page.get_by_role("button", name="Expand record").click()
    page.get_by_role("button", name="Escalate to L2").click()
    expect(page.locator("tbody tr[tabindex]").filter(has_text=CASE["title"])).to_contain_text("Escalated")
    assert any(path.endswith("/escalate") for _, path, _ in state["writes"])


@pytest.mark.parametrize("width", [390, 1440])
def test_deployment_dialog_responsive_and_dismissible(page, enterprise, width, tmp_path):
    _, expect = enterprise
    page.set_viewport_size({"width": width, "height": 900})
    page.goto(BASE_URL + "/agents")
    trigger = page.get_by_role("button", name="Deploy agent", exact=True)
    trigger.click()
    dialog = page.get_by_role("dialog", name="Deploy agent", exact=True)
    expect(dialog).to_be_visible()
    expect(dialog.get_by_role("textbox", name="Server address", exact=True)).to_be_visible()
    assert dialog.evaluate("el => el.scrollWidth <= el.clientWidth")
    page.screenshot(path=str(tmp_path / "deploy-dialog.png"))
    dialog.evaluate("el => el.scrollTop = el.scrollHeight")
    page.screenshot(path=str(tmp_path / "deploy-dialog-end.png"))
    page.keyboard.press("Escape")
    expect(dialog).not_to_be_visible()
    expect(trigger).to_be_focused()


@pytest.mark.parametrize("resource", ["cases", "agents"])
def test_viewer_cannot_see_mutation_controls(page, enterprise, resource):
    state, expect = enterprise
    state["role"] = "viewer"
    page.goto(BASE_URL + "/" + resource)
    expect(page.get_by_role("heading", name=resource.capitalize(), exact=True)).to_be_visible()
    expect(page.get_by_role("button", name="Deploy agent", exact=True)).not_to_be_visible()
    expect(page.get_by_role("button", name="Isolate host", exact=True)).not_to_be_visible()
    expect(page.get_by_role("button", name="Expand record", exact=True)).not_to_be_visible()
    assert not state["writes"]


def test_agent_response_failure_stays_retryable(page, enterprise):
    state, expect = enterprise
    state["write_error"] = True
    page.goto(BASE_URL + "/agents")
    page.get_by_role("button", name="Expand record").click()
    page.get_by_role("button", name="Isolate host", exact=True).click()
    dialog = page.get_by_role("dialog", name="Isolate WIN-FIN-042?")
    dialog.get_by_role("button", name="Isolate host", exact=True).click()
    expect(dialog.get_by_role("alert")).to_contain_text("Could not complete this request")
    expect(dialog).to_be_visible()
    assert state["agent"]["is_isolated"] is False
    state["write_error"] = False
    dialog.get_by_role("button", name="Isolate host", exact=True).click()
    expect(page.get_by_role("button", name="Lift isolation", exact=True)).to_be_visible()


@pytest.mark.parametrize("resource", ["cases", "agents"])
def test_empty_lists_keep_recovery_controls(page, enterprise, resource, tmp_path):
    state, expect = enterprise
    state["mode"] = "empty"
    page.goto(BASE_URL + "/" + resource + "?search=unknown")
    expect(page.get_by_role("heading", name="No " + resource + " match this view", exact=True)).to_be_visible()
    expect(page.get_by_role("button", name="Clear filters", exact=True)).to_be_visible()
    page.screenshot(path=str(tmp_path / "empty-list.png"))


@pytest.mark.parametrize("resource", ["logs", "events"])
def test_lucene_deep_link_and_explicit_search(page, enterprise, resource):
    state, expect = enterprise
    query = 'source_ip:"192.0.2.42"'
    page.goto(BASE_URL + "/" + resource + "?q=" + quote(query))
    box = page.get_by_role("textbox", name="Lucene query", exact=True)
    expect(box).to_have_value(query)
    box.fill("login_failed")
    page.get_by_role("button", name="Search", exact=True).click()
    expect(page).to_have_url(BASE_URL + "/" + resource + "?q=login_failed")
    assert any(url.path == "/api/" + resource and parse_qs(url.query).get("search") == ["login_failed"] for url in state["requests"])
    page.go_back()
    expect(box).to_have_value(query)


@pytest.mark.parametrize("resource", ["logs", "events"])
@pytest.mark.parametrize("width", [390, 1440])
def test_full_evidence_and_dialog_focus(page, enterprise, resource, width, tmp_path):
    _, expect = enterprise
    page.set_viewport_size({"width": width, "height": 900})
    page.goto(BASE_URL + "/" + resource)
    row = page.locator("tbody tr[tabindex]").first
    row.focus()
    page.keyboard.press("Enter")
    dialog = page.get_by_role("dialog", name="Raw log details" if resource == "logs" else "Event details", exact=True)
    expect(dialog).to_be_visible()
    expect(dialog).to_contain_text("END-OF-RAW-EVIDENCE" if resource == "logs" else "END-OF-DECODED-EVIDENCE")
    assert dialog.evaluate("el => el.scrollWidth <= el.clientWidth")
    page.screenshot(path=str(tmp_path / "evidence-dialog.png"))
    dialog.evaluate("el => el.scrollTop = el.scrollHeight")
    page.screenshot(path=str(tmp_path / "evidence-dialog-end.png"))
    page.keyboard.press("Escape")
    expect(dialog).not_to_be_visible()
    expect(row).to_be_focused()


@pytest.mark.parametrize("resource", ["logs", "events"])
def test_cursor_navigation_and_new_search_reset(page, enterprise, resource):
    state, expect = enterprise
    page.goto(BASE_URL + "/" + resource)
    next_button = page.get_by_role("button", name="Next", exact=True)
    expect(page.get_by_text("Page 1", exact=True)).to_be_visible()
    next_button.click()
    expect(page.get_by_text("Page 2", exact=True)).to_be_visible()
    expect(next_button).to_be_enabled()
    next_button.click()
    expect(page.get_by_text("Page 3", exact=True)).to_be_visible()
    expect(next_button).to_be_disabled()
    assert any(parse_qs(url.query).get("after") == ["50"] for url in state["requests"])
    page.get_by_role("textbox", name="Lucene query", exact=True).fill("new-query")
    page.get_by_role("button", name="Search", exact=True).click()
    expect(page.get_by_text("Page 1", exact=True)).to_be_visible()
    expect(next_button).to_be_enabled()
    requests = [parse_qs(url.query) for url in state["requests"] if url.path == "/api/" + resource and parse_qs(url.query).get("search") == ["new-query"]]
    assert requests and all("after" not in query for query in requests)


@pytest.mark.parametrize("resource", ["logs", "events"])
def test_advanced_filter_apply_and_clear(page, enterprise, resource, tmp_path):
    state, expect = enterprise
    page.set_viewport_size({"width": 390, "height": 900})
    page.goto(BASE_URL + "/" + resource)
    page.get_by_role("button", name="Advanced filters", exact=True).click()
    page.get_by_role("button", name="Add condition", exact=True).first.click()
    page.get_by_role("combobox", name="Field 1", exact=True).first.fill("source_ip")
    page.get_by_role("combobox", name="Operator 1", exact=True).first.select_option("equals")
    page.get_by_role("textbox", name="Value 1", exact=True).first.fill("192.0.2.42")
    page.get_by_role("button", name="Apply filters", exact=True).click()
    expect(page.get_by_text("Advanced filters applied", exact=True)).to_be_visible()
    assert page.locator("main").evaluate("el => el.scrollWidth <= el.clientWidth")
    filtered = [parse_qs(url.query) for url in state["requests"] if "filter_tree" in parse_qs(url.query)]
    assert filtered and '"source_ip"' in filtered[-1]["filter_tree"][0]
    page.screenshot(path=str(tmp_path / "advanced-filter.png"))
    page.get_by_role("button", name="Clear filters", exact=True).click()
    expect(page.get_by_text("Advanced filters applied", exact=True)).not_to_be_visible()


@pytest.mark.parametrize("resource", ["logs", "events"])
def test_page_size_survives_query_change(page, enterprise, resource):
    state, expect = enterprise
    page.goto(BASE_URL + "/" + resource)
    size = page.get_by_role("combobox", name="Results per page", exact=True)
    expect(size).to_be_enabled()
    size.select_option("50")
    expect(page.get_by_text("50 records on this page · 51 matching", exact=True)).to_be_visible()
    page.get_by_role("button", name="Next", exact=True).click()
    expect(page.get_by_text("Page 2", exact=True)).to_be_visible()
    page.get_by_role("textbox", name="Lucene query", exact=True).fill("changed-query")
    page.get_by_role("button", name="Search", exact=True).click()
    expect(size).to_have_value("50")
    expect(page.get_by_text("Page 1", exact=True)).to_be_visible()
    expect(page.get_by_text("50 records on this page · 51 matching", exact=True)).to_be_visible()
    requests = [parse_qs(url.query) for url in state["requests"] if url.path == "/api/" + resource and parse_qs(url.query).get("search") == ["changed-query"]]
    assert requests and all(query.get("page_size") == ["50"] and "after" not in query for query in requests)


def test_nested_filters_are_draft_until_applied(page, enterprise):
    state, expect = enterprise
    page.goto(BASE_URL + "/events")
    page.get_by_role("button", name="Advanced filters", exact=True).click()
    page.get_by_role("button", name="Add group", exact=True).click()
    nested = page.get_by_role("group", name="Nested filter group 1", exact=True)
    nested.get_by_role("button", name="Add condition", exact=True).click()
    nested.get_by_role("combobox", name="Field 1", exact=True).fill("source_ip")
    nested.get_by_role("combobox", name="Operator 1", exact=True).select_option("exists")
    expect(nested.get_by_role("textbox", name="Value 1", exact=True)).to_have_count(0)
    assert not any("filter_tree" in parse_qs(url.query) for url in state["requests"])
    page.get_by_role("button", name="Apply filters", exact=True).click()
    expect(page.get_by_text("Advanced filters applied", exact=True)).to_be_visible()
    expect(page.locator("tbody tr[tabindex]").first).to_be_visible()
    filtered = [parse_qs(url.query) for url in state["requests"] if "filter_tree" in parse_qs(url.query)]
    assert json.loads(filtered[-1]["filter_tree"][0])["children"][0]["children"][0] == {"field": "source_ip", "operator": "exists", "value": ""}


@pytest.mark.parametrize("resource", ["logs", "events"])
@pytest.mark.parametrize("mode", ["empty", "error"])
def test_query_states_preserve_search(page, enterprise, resource, mode, tmp_path):
    state, expect = enterprise
    state["mode"] = mode
    page.goto(BASE_URL + "/" + resource + "?q=unknown")
    title = "Could not load " + resource if mode == "error" else "No " + resource + " match this query"
    expect(page.get_by_role("heading", name=title, exact=True)).to_be_visible(timeout=15000)
    expect(page.get_by_role("textbox", name="Lucene query", exact=True)).to_have_value("unknown")
    page.screenshot(path=str(tmp_path / "query-state.png"))


def test_hunt_submission_trims_input_and_preserves_failure(page, enterprise):
    state, expect = enterprise
    page.goto(BASE_URL + "/hunts")
    value = page.get_by_role("textbox", name="Indicator value", exact=True)
    value.fill("  finance-server  ")
    page.get_by_role("combobox", name="Indicator type", exact=True).select_option("hostname")
    state["write_error"] = True
    value.press("Enter")
    expect(page.get_by_role("alert").filter(has_text="Fixture outage")).to_be_visible()
    expect(value).to_have_value("  finance-server  ")
    state["write_error"] = False
    page.get_by_role("button", name="Start hunt", exact=True).click()
    expect(value).to_have_value("")
    expect(page.get_by_role("cell", name="finance-server HOSTNAME", exact=True)).to_be_visible()
    assert state["writes"][-1] == ("POST", "/api/hunts", {"ioc_type": "hostname", "ioc_value": "finance-server"})


@pytest.mark.parametrize("width", [390, 1440])
def test_hunt_details_preserve_long_evidence(page, enterprise, width, tmp_path):
    _, expect = enterprise
    page.set_viewport_size({"width": width, "height": 900})
    page.goto(BASE_URL + "/hunts")
    row = page.locator("tbody tr[tabindex]").filter(has_text="192.0.2.42").last
    row.focus()
    page.keyboard.press("Enter")
    dialog = page.get_by_role("dialog", name="Hunt · 192.0.2.42", exact=True)
    expect(dialog).to_be_visible()
    expect(dialog).to_contain_text("END-OF-HUNT-EVIDENCE")
    expect(dialog).to_contain_text("suspicious activity")
    expect(dialog).to_contain_text("T1059.001")
    assert dialog.evaluate("el => el.scrollWidth <= el.clientWidth")
    page.screenshot(path=str(tmp_path / "hunt-detail.png"))
    dialog.evaluate("el => el.scrollTop = el.scrollHeight")
    page.screenshot(path=str(tmp_path / "hunt-detail-end.png"))
    page.keyboard.press("Escape")
    expect(row).to_be_focused()


@pytest.mark.parametrize("width", [390, 1440])
def test_schedule_delete_requires_confirmation_and_retries(page, enterprise, tmp_path, width):
    state, expect = enterprise
    page.set_viewport_size({"width": width, "height": 900})
    page.goto(BASE_URL + "/hunts")
    trigger = page.get_by_role("button", name="Delete Nightly finance hunt", exact=True)
    trigger.click()
    dialog = page.get_by_role("dialog", name="Delete Nightly finance hunt?", exact=True)
    expect(dialog).to_be_visible()
    assert not state["writes"]
    dialog.get_by_role("button", name="Cancel", exact=True).click()
    expect(trigger).to_be_focused()
    assert not state["writes"]
    trigger.click()
    state["write_error"] = True
    dialog.get_by_role("button", name="Delete schedule", exact=True).click()
    expect(dialog.get_by_role("alert")).to_contain_text("Fixture outage")
    page.screenshot(path=str(tmp_path / "delete-schedule-error.png"))
    state["write_error"] = False
    dialog.get_by_role("button", name="Delete schedule", exact=True).click()
    expect(dialog).not_to_be_visible()
    expect(page.get_by_role("heading", name="No scheduled hunts", exact=True)).to_be_visible()


def test_schedule_create_and_toggle(page, enterprise):
    state, expect = enterprise
    page.goto(BASE_URL + "/hunts")
    page.get_by_role("button", name="Pause Nightly finance hunt", exact=True).click()
    expect(page.get_by_role("button", name="Resume Nightly finance hunt", exact=True)).to_be_visible()
    page.get_by_role("button", name="New schedule", exact=True).click()
    page.get_by_role("textbox", name="Schedule name", exact=True).fill("  Weekly review  ")
    page.get_by_role("textbox", name="Scheduled indicator value", exact=True).fill("  198.51.100.9  ")
    page.get_by_role("spinbutton", name="Interval (hours)", exact=True).fill("48")
    page.get_by_role("button", name="Create schedule", exact=True).click()
    expect(page.get_by_role("cell", name="Weekly review", exact=True)).to_be_visible()
    assert state["writes"][-1] == ("POST", "/api/hunt-schedules", {"name": "Weekly review", "ioc_type": "ip", "ioc_value": "198.51.100.9", "interval_hours": 48})


@pytest.mark.parametrize("mode", ["empty", "error"])
def test_hunt_history_and_schedule_query_states(page, enterprise, mode):
    state, expect = enterprise
    state["mode"] = mode
    page.goto(BASE_URL + "/hunts")
    titles = ["Could not load hunt history", "Could not load schedules"] if mode == "error" else ["No hunts yet", "No scheduled hunts"]
    for title in titles:
        expect(page.get_by_role("heading", name=title, exact=True)).to_be_visible(timeout=15000)
    if mode == "error":
        assert page.get_by_role("heading", name="No hunts yet", exact=True).count() == 0


def test_hunt_submission_locks_draft_while_pending(page, enterprise):
    _, expect = enterprise
    held = []

    def delay_start(route):
        if route.request.method == "POST":
            held.append(route)
        else:
            route.fallback()

    page.route(BASE_URL + "/api/hunts", delay_start)
    page.goto(BASE_URL + "/hunts")
    value = page.get_by_role("textbox", name="Indicator value", exact=True)
    value.fill("192.0.2.77")
    page.get_by_role("button", name="Start hunt", exact=True).click()
    expect(page.get_by_role("button", name="Starting…", exact=True)).to_be_disabled()
    expect(value).to_be_disabled()
    assert len(held) == 1
    held[0].fulfill(status=201, content_type="application/json", body=json.dumps({**HUNT, "status": "pending"}))
    expect(value).to_be_enabled()
    expect(value).to_have_value("")


def test_open_hunt_updates_when_polling_completes(page, enterprise):
    state, expect = enterprise
    state["hunts"] = [{**HUNT, "status": "running", "analysis": None, "timeline": None, "completed_at": None}]
    page.clock.install()
    page.goto(BASE_URL + "/hunts")
    page.get_by_role("region", name="Hunt history", exact=True).get_by_role("cell", name="192.0.2.42 IP", exact=True).click()
    dialog = page.get_by_role("dialog", name="Hunt · 192.0.2.42", exact=True)
    expect(dialog.get_by_role("heading", name="Hunt in progress…", exact=True)).to_be_visible()
    state["hunts"] = [dict(HUNT)]
    page.clock.fast_forward(8000)
    expect(dialog).to_contain_text("suspicious activity")
    expect(dialog).to_contain_text("END-OF-HUNT-EVIDENCE")


@pytest.mark.parametrize("analysis", ["not-json-original-evidence", '{"attack_narrative":12,"mitre_techniques":{},"recommended_actions":[false]}'])
def test_unexpected_hunt_analysis_does_not_crash(page, enterprise, analysis):
    state, expect = enterprise
    state["hunts"] = [{**HUNT, "analysis": analysis}]
    page.goto(BASE_URL + "/hunts")
    page.get_by_role("region", name="Hunt history", exact=True).get_by_role("cell", name="192.0.2.42 IP", exact=True).click()
    dialog = page.get_by_role("dialog", name="Hunt · 192.0.2.42", exact=True)
    expect(dialog).to_contain_text("END-OF-HUNT-EVIDENCE")
    if analysis == "not-json-original-evidence":
        expect(dialog).to_contain_text("not-json-original-evidence")
    else:
        expect(dialog).to_contain_text("No narrative was returned.")


def test_schedule_creation_failure_preserves_draft(page, enterprise, tmp_path):
    state, expect = enterprise
    state["write_error"] = True
    page.set_viewport_size({"width": 390, "height": 900})
    page.goto(BASE_URL + "/hunts")
    page.get_by_role("button", name="New schedule", exact=True).click()
    page.get_by_role("textbox", name="Schedule name", exact=True).fill("Analyst review")
    value = page.get_by_role("textbox", name="Scheduled indicator value", exact=True)
    value.fill("finance-server")
    page.get_by_role("button", name="Create schedule", exact=True).click()
    expect(page.get_by_role("alert")).to_contain_text("Fixture outage")
    expect(value).to_have_value("finance-server")
    assert page.locator("main").evaluate("el => el.scrollWidth <= el.clientWidth")
    page.screenshot(path=str(tmp_path / "schedule-form-error.png"))


def test_hunt_rejects_whitespace_without_request(page, enterprise):
    state, expect = enterprise
    page.goto(BASE_URL + "/hunts")
    page.get_by_role("textbox", name="Indicator value", exact=True).fill("   ")
    page.get_by_role("button", name="Start hunt", exact=True).click()
    expect(page.get_by_role("alert")).to_contain_text("Enter an indicator value.")
    assert not state["writes"]


def test_schedule_interval_must_be_in_range(page, enterprise):
    state, expect = enterprise
    page.goto(BASE_URL + "/hunts")
    page.get_by_role("button", name="New schedule", exact=True).click()
    page.get_by_role("textbox", name="Schedule name", exact=True).fill("Review")
    page.get_by_role("textbox", name="Scheduled indicator value", exact=True).fill("192.0.2.42")
    interval = page.get_by_role("spinbutton", name="Interval (hours)", exact=True)
    for invalid in ["0", "169", "1.5"]:
        interval.fill(invalid)
        page.get_by_role("button", name="Create schedule", exact=True).click()
        assert not interval.evaluate("el => el.validity.valid")
        assert not state["writes"]
    interval.fill("168")
    page.get_by_role("button", name="Create schedule", exact=True).click()
    expect(page.get_by_role("cell", name="Review", exact=True)).to_be_visible()


def test_failed_hunt_shows_returned_error(page, enterprise):
    state, expect = enterprise
    state["hunts"] = [{**HUNT, "status": "failed", "analysis": '{"attack_narrative":"Provider timeout; start a new hunt."}', "timeline": None}]
    page.goto(BASE_URL + "/hunts")
    page.get_by_role("region", name="Hunt history", exact=True).get_by_role("cell", name="192.0.2.42 IP", exact=True).click()
    expect(page.get_by_role("dialog").get_by_role("alert")).to_contain_text("Provider timeout; start a new hunt.")


def test_hunt_export_preserves_evidence_counts(page, enterprise):
    _, expect = enterprise
    page.goto(BASE_URL + "/hunts")
    export = page.get_by_role("button", name="Export page", exact=True)
    expect(export).to_be_enabled()
    with page.expect_download() as pending:
        export.click()
    download = pending.value
    assert download.suggested_filename == "hunts-recent.csv"
    content = download.path().read_text()
    assert '"192.0.2.42"' in content
    assert '"2 alerts · 7 events · 1 FIM"' in content
    assert '"2026-10-21T07:32:00Z"' in content


def test_ueba_model_failure_is_not_collecting_data(page, enterprise):
    state, expect = enterprise
    state["ueba_errors"] = ["status"]
    page.goto(BASE_URL + "/ueba")
    expect(page.get_by_role("heading", name="Could not load model status", exact=True)).to_be_visible(timeout=15000)
    expect(page.get_by_text("Collecting baseline data", exact=True)).to_have_count(0)
    expect(page.get_by_role("cell", name=UEBA_SCORE["entity_value"], exact=True)).to_be_visible()


@pytest.mark.parametrize("width", [390, 1440])
def test_ueba_detail_keyboard_evidence_and_encoded_history(page, enterprise, width, tmp_path):
    state, expect = enterprise
    page.set_viewport_size({"width": width, "height": 900})
    page.goto(BASE_URL + "/ueba")
    row = page.locator("tbody tr[tabindex]").first
    row.focus()
    page.keyboard.press("Enter")
    dialog = page.get_by_role("dialog", name="Entity · " + UEBA_SCORE["entity_value"], exact=True)
    expect(dialog).to_be_visible()
    expect(dialog).to_contain_text("END-OF-UEBA-EVIDENCE")
    expect(dialog).to_contain_text("failed_ratio")
    expect(dialog).to_contain_text("Verify the endpoint owner before response.")
    expect(dialog.get_by_role("link", name="Open case", exact=True)).to_have_attribute("href", "/cases/case-fixture")
    expect(dialog.get_by_role("img", name="Daily maximum risk over the last 30 days", exact=True)).to_be_visible()
    dialog.locator("summary").filter(has_text="Feature values").click()
    expect(dialog.get_by_role("cell", name="0.75", exact=True)).to_be_visible()
    dialog.locator("summary").filter(has_text="Daily risk values").click()
    expect(dialog.get_by_role("cell", name="84.5", exact=True)).to_be_visible()
    assert any(url.path == "/api/ueba/user/finance%5Calex%40example.test/history" and parse_qs(url.query).get("days") == ["30"] for url in state["requests"])
    assert dialog.evaluate("el => el.scrollWidth <= el.clientWidth")
    page.screenshot(path=str(tmp_path / "ueba-detail.png"))
    dialog.evaluate("el => el.scrollTop = el.scrollHeight")
    page.screenshot(path=str(tmp_path / "ueba-detail-end.png"))
    page.keyboard.press("Escape")
    expect(row).to_be_focused()


def test_ueba_entity_type_and_risk_filter_contract(page, enterprise):
    state, expect = enterprise
    page.goto(BASE_URL + "/ueba")
    page.get_by_role("combobox", name="Entity type", exact=True).select_option("ip")
    expect(page.get_by_role("cell", name="192.0.2.42", exact=True)).to_be_visible()
    page.get_by_role("combobox", name="Minimum risk", exact=True).select_option("60")
    expect(page.get_by_role("cell", name="192.0.2.42", exact=True)).to_be_visible()
    assert any(parse_qs(url.query).get("entity_type") == ["ip"] and parse_qs(url.query).get("min_risk") == ["60"] for url in state["requests"])


@pytest.mark.parametrize("mode", ["empty", "error"])
def test_ueba_entities_empty_and_error_are_distinct(page, enterprise, mode):
    state, expect = enterprise
    if mode == "error":
        state["ueba_errors"] = ["entities"]
    else:
        state["mode"] = mode
    page.goto(BASE_URL + "/ueba")
    expect(page.get_by_role("heading", name="Could not load entities" if mode == "error" else "No entities match this view", exact=True)).to_be_visible(timeout=15000)
    if mode == "error":
        expect(page.get_by_role("heading", name="No entities match this view", exact=True)).to_have_count(0)


def test_ueba_cold_model_shows_actual_snapshots(page, enterprise):
    state, expect = enterprise
    state["ueba_status"].update(status="cold", trained_at=None, user_snapshot_count=7, ip_snapshot_count=4)
    page.goto(BASE_URL + "/ueba")
    expect(page.get_by_text("Collecting baseline data", exact=True)).to_be_visible()
    summary = page.get_by_role("region", name="Detection model", exact=True)
    expect(summary).to_contain_text("User snapshots7")
    expect(summary).to_contain_text("IP snapshots4")


@pytest.mark.parametrize("part", ["detail", "history"])
def test_ueba_detail_queries_fail_independently(page, enterprise, part, tmp_path):
    state, expect = enterprise
    state["ueba_errors"] = [part]
    page.goto(BASE_URL + "/ueba")
    page.get_by_role("cell", name=UEBA_SCORE["entity_value"], exact=True).click()
    dialog = page.get_by_role("dialog", name="Entity · " + UEBA_SCORE["entity_value"], exact=True)
    expect(dialog.get_by_role("heading", name="Could not load entity details" if part == "detail" else "Could not load risk history", exact=True)).to_be_visible(timeout=15000)
    if part == "history":
        expect(dialog).to_contain_text("END-OF-UEBA-EVIDENCE")
    page.screenshot(path=str(tmp_path / "ueba-query-error.png"))
    state["ueba_errors"] = []
    dialog.get_by_role("button", name="Try again", exact=True).click()
    expect(dialog).to_contain_text("END-OF-UEBA-EVIDENCE")
    expect(dialog.get_by_role("img", name="Daily maximum risk over the last 30 days", exact=True)).to_be_visible()


@pytest.mark.parametrize("history", [[], [{"day": "2026-10-21", "max_risk": 84.5, "anomaly_count": 2}]])
def test_ueba_empty_and_single_day_history(page, enterprise, history, tmp_path):
    state, expect = enterprise
    state["ueba_history"] = history
    state["ueba_anomalies"] = []
    page.goto(BASE_URL + "/ueba")
    page.get_by_role("cell", name=UEBA_SCORE["entity_value"], exact=True).click()
    dialog = page.get_by_role("dialog", name="Entity · " + UEBA_SCORE["entity_value"], exact=True)
    expect(dialog).to_contain_text("No anomalies recorded for this entity.")
    if history:
        chart = dialog.get_by_role("img", name="Daily maximum risk over the last 30 days", exact=True)
        expect(chart).to_be_visible()
        expect(chart.locator("circle")).to_have_count(1)
        dialog.locator("summary").filter(has_text="Daily risk values").click()
        expect(dialog.get_by_role("cell", name="84.5", exact=True)).to_be_visible()
    else:
        expect(dialog).to_contain_text("No risk history recorded in the last 30 days.")
    page.screenshot(path=str(tmp_path / "ueba-history.png"))


def test_ueba_csv_retains_numeric_risk_and_anomaly_counts(page, enterprise):
    _, expect = enterprise
    page.goto(BASE_URL + "/ueba")
    export = page.get_by_role("button", name="Export page", exact=True)
    expect(export).to_be_enabled()
    with page.expect_download() as pending:
        export.click()
    download = pending.value
    assert download.suggested_filename == "ueba-user-entities.csv"
    content = download.path().read_text()
    assert '"84.5","3","2026-10-21T07:32:00Z"' in content


def test_ueba_loading_status_does_not_claim_cold_model(page, enterprise):
    _, expect = enterprise
    held = []
    page.route(BASE_URL + "/api/ueba/status", lambda route: held.append(route))
    page.goto(BASE_URL + "/ueba")
    try:
        expect(page.get_by_role("heading", name="Loading model status…", exact=True)).to_be_visible()
        expect(page.get_by_text("Collecting baseline data", exact=True)).to_have_count(0)
        expect(page.get_by_role("cell", name=UEBA_SCORE["entity_value"], exact=True)).to_be_visible()
    finally:
        for route in held:
            route.fulfill(status=200, content_type="application/json", body='{"status":"ready","trained_at":null,"user_snapshot_count":72,"ip_snapshot_count":48,"host_snapshot_count":12}')
    expect(page.get_by_text("Ready", exact=True)).to_be_visible()
