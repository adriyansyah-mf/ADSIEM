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


@pytest.fixture
def enterprise(page):
    from playwright.sync_api import expect

    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.add_init_script("localStorage.setItem('siem-auth', " + json.dumps(json.dumps({
        "state": {"accessToken": "fixture-only", "user": USER}, "version": 0,
    })) + ")")
    state = {"mode": "normal", "requests": [], "writes": [], "agent": dict(AGENT),
             "case": dict(CASE), "role": "superadmin", "write_error": False}

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
        elif path == "/api/alerts":
            if state["mode"] == "error":
                status, body = 503, {"detail": "Fixture outage"}
            else:
                items = [] if state["mode"] == "empty" else [ALERT]
                body = {"items": items, "total": len(items), "page": 1, "page_size": 25}
        elif path == "/api/alerts/alert-fixture":
            body = {**ALERT, "rule": None, "rule_fired_24h": 1, "mitre": [], "event": None,
                    "agent": None, "ueba": None, "related": []}
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


@pytest.mark.parametrize("width", [390, 768, 1440, 1920])
@pytest.mark.parametrize("route,title", [
    ("/", "Operations overview"), ("/alerts", "Alerts"),
    ("/cases/case-fixture", CASE["title"]),
    ("/cases", "Cases"), ("/agents", "Agents"),
    ("/logs", "Raw logs"), ("/events", "Events"),
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
