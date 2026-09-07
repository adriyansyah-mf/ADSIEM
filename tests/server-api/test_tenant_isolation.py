from __future__ import annotations

import json
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import NamedTuple
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from uuid import UUID, uuid4

import pytest


REPOSITORY_ROOT = Path(__file__).parents[2]
BASE_URL = "http://127.0.0.1"
PASSWORD = "admin123"


class ApiResponse(NamedTuple):
    status: int
    body: bytes


class TenantFixture(NamedTuple):
    blue_token: str
    superadmin_token: str
    ids: dict[str, UUID]


def _psql(sql: str) -> str:
    result = subprocess.run(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "postgres",
            "sh",
            "-lc",
            'psql -At -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"',
        ],
        cwd=REPOSITORY_ROOT,
        input=sql,
        check=True,
        text=True,
        capture_output=True,
    )
    return result.stdout


def _request(
    method: str,
    path: str,
    token: str,
    payload: dict[str, str | bool] | None = None,
) -> ApiResponse:
    data = json.dumps(payload).encode() if payload is not None else None
    request = Request(
        f"{BASE_URL}{path}",
        data=data,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method=method,
    )
    try:
        with urlopen(request, timeout=30) as response:
            return ApiResponse(response.status, response.read())
    except HTTPError as error:
        return ApiResponse(error.code, error.read())


def _login(username: str) -> str:
    response = _request("POST", "/api/auth/login", "", {"username": username, "password": PASSWORD})
    assert response.status == 200
    parsed = json.loads(response.body)
    assert isinstance(parsed["access_token"], str)
    return parsed["access_token"]


@pytest.fixture(scope="module")
def tenant_resources() -> Iterator[TenantFixture]:
    ids = {name: uuid4() for name in (
        "blue_user", "red_user", "alert", "case", "agent", "log_source", "rule",
        "revision", "webhook", "suppression", "schedule", "workflow", "node", "run",
        "step", "hunt", "token", "blue_alert",
    )}
    suffix = uuid4().hex[:10]
    role_name = f"tenant_test_{suffix}"
    blue_username = f"tenant_blue_{suffix}"
    red_username = f"tenant_red_{suffix}"
    alerts_manage_existed = _psql(
        "SELECT EXISTS (SELECT 1 FROM permissions WHERE name = 'alerts:manage');"
    ).strip() == "t"
    _psql(f"""
        INSERT INTO permissions (name) VALUES ('alerts:manage') ON CONFLICT (name) DO NOTHING;
        INSERT INTO roles (name) VALUES ('{role_name}');
        INSERT INTO role_permissions (role_id, permission_id)
        SELECT roles.id, permissions.id FROM roles, permissions
        WHERE roles.name = '{role_name}';
        INSERT INTO users (id, username, email, password_hash, role_id, group_id)
        SELECT '{ids['blue_user']}', '{blue_username}', '{blue_username}@example.test',
               password_hash, (SELECT id FROM roles WHERE name = '{role_name}'), 'blue'
        FROM users WHERE username = 'admin';
        INSERT INTO users (id, username, email, password_hash, role_id, group_id)
        SELECT '{ids['red_user']}', '{red_username}', '{red_username}@example.test',
               password_hash, (SELECT id FROM roles WHERE name = '{role_name}'), 'red'
        FROM users WHERE username = 'admin';
        INSERT INTO alerts (id, title, severity, status, group_id)
        VALUES ('{ids['alert']}', 'red alert', 'high', 'new', 'red'),
               ('{ids['blue_alert']}', 'blue alert', 'low', 'new', 'blue');
        INSERT INTO cases (id, title, severity, status, group_id)
        VALUES ('{ids['case']}', 'red case', 'high', 'open', 'red');
        INSERT INTO agents (id, name, hostname, group_id, token_hash, status)
        VALUES ('{ids['agent']}', 'red agent', 'red-host', 'red', 'tenant-test-token', 'online');
        INSERT INTO agent_log_sources (id, agent_id, path, log_type)
        VALUES ('{ids['log_source']}', '{ids['agent']}', '/var/log/red.log', 'syslog');
        INSERT INTO rules (id, title, content, group_id)
        VALUES ('{ids['rule']}', 'red rule', 'title: red-rule\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    EventID: 1\n  condition: selection\n', 'red');
        INSERT INTO rule_revisions (id, rule_id, version, content, created_by, created_at)
        VALUES ('{ids['revision']}', '{ids['rule']}', 1, 'title: red-rule', '{ids['red_user']}', NOW());
        INSERT INTO webhook_configs (id, name, url, group_id)
        VALUES ('{ids['webhook']}', 'red webhook', 'https://example.com/hook', 'red');
        INSERT INTO alert_suppressions
            (id, entity_type, entity_value, group_id, is_active, created_by, created_at)
        VALUES ('{ids['suppression']}', 'ip', '203.0.113.2', 'red', TRUE, '{ids['red_user']}', NOW());
        INSERT INTO hunt_schedules
            (id, name, ioc_type, ioc_value, interval_hours, group_id, is_enabled, created_by, created_at)
        VALUES ('{ids['schedule']}', 'red schedule', 'ip', '203.0.113.3', 24, 'red', TRUE,
                '{ids['red_user']}', NOW());
        INSERT INTO soar_workflows (id, name, group_id)
        VALUES ('{ids['workflow']}', 'red workflow', 'red');
        INSERT INTO soar_nodes (id, workflow_id, node_type, name)
        VALUES ('{ids['node']}', '{ids['workflow']}', 'action', 'red node');
        INSERT INTO soar_runs (id, workflow_id, status, trigger_type, group_id)
        VALUES ('{ids['run']}', '{ids['workflow']}', 'pending_approval', 'manual', 'red');
        INSERT INTO soar_run_steps
            (id, run_id, node_id, status, action_type, idempotency_key, input_hash)
        VALUES ('{ids['step']}', '{ids['run']}', '{ids['node']}', 'pending_approval', 'noop',
                'seed-key-{suffix}', 'seed-hash');
        INSERT INTO threat_hunts (id, ioc_type, ioc_value, status, group_id, created_by)
        VALUES ('{ids['hunt']}', 'ip', '203.0.113.4', 'pending', 'red', '{ids['red_user']}');
        INSERT INTO enrollment_tokens (id, token_hash, label, group_id, created_by)
        VALUES ('{ids['token']}', 'token-{suffix}', 'red token', 'red', '{ids['red_user']}');
    """)
    try:
        yield TenantFixture(
            blue_token=_login(blue_username),
            superadmin_token=_login("admin"),
            ids=ids,
        )
    finally:
        _psql(f"""
            DELETE FROM soar_run_steps WHERE id = '{ids['step']}';
            DELETE FROM soar_runs WHERE id = '{ids['run']}';
            DELETE FROM soar_nodes WHERE id = '{ids['node']}';
            DELETE FROM soar_workflows WHERE id = '{ids['workflow']}';
            DELETE FROM enrollment_tokens WHERE id = '{ids['token']}';
            DELETE FROM hunt_schedules WHERE id = '{ids['schedule']}';
            DELETE FROM alert_suppressions WHERE id = '{ids['suppression']}';
            DELETE FROM webhook_configs WHERE id = '{ids['webhook']}';
            DELETE FROM rule_revisions WHERE id = '{ids['revision']}';
            DELETE FROM rules WHERE id = '{ids['rule']}';
            DELETE FROM agent_log_sources WHERE id = '{ids['log_source']}';
            DELETE FROM agents WHERE id = '{ids['agent']}';
            DELETE FROM cases WHERE id = '{ids['case']}';
            DELETE FROM alerts WHERE id IN ('{ids['alert']}', '{ids['blue_alert']}');
            DELETE FROM users WHERE id IN ('{ids['blue_user']}', '{ids['red_user']}');
            DELETE FROM role_permissions WHERE role_id = (SELECT id FROM roles WHERE name = '{role_name}');
            DELETE FROM roles WHERE name = '{role_name}';
            {"" if alerts_manage_existed else "DELETE FROM permissions WHERE name = 'alerts:manage';"}
        """)


@pytest.mark.service_e2e
def test_foreign_resources_return_not_found_across_resource_families(
    tenant_resources: TenantFixture,
) -> None:
    # Given
    resource_ids = tenant_resources.ids
    scenarios = (
        ("alert update", "PUT", f"/api/alerts/{resource_ids['alert']}", {"status": "investigating"}),
        ("alert note", "POST", f"/api/alerts/{resource_ids['alert']}/notes", {"content": "foreign"}),
        ("alert feedback", "GET", f"/api/alerts/{resource_ids['alert']}/feedback", None),
        ("case delete", "DELETE", f"/api/cases/{resource_ids['case']}", None),
        ("case feedback", "GET", f"/api/cases/{resource_ids['case']}/feedback", None),
        ("agent read", "GET", f"/api/agents/{resource_ids['agent']}", None),
        ("agent isolate", "POST", f"/api/agents/{resource_ids['agent']}/isolate", None),
        ("agent log source", "PUT", f"/api/agents/{resource_ids['agent']}/log-sources/{resource_ids['log_source']}", {"path": "/tmp/foreign", "log_type": "syslog", "is_enabled": True}),
        ("rule update", "PUT", f"/api/rules/{resource_ids['rule']}", {"title": "foreign"}),
        ("rule revisions", "GET", f"/api/rules/{resource_ids['rule']}/revisions", None),
        ("webhook delete", "DELETE", f"/api/webhooks/{resource_ids['webhook']}", None),
        ("suppression delete", "DELETE", f"/api/suppressions/{resource_ids['suppression']}", None),
        ("schedule toggle", "PATCH", f"/api/hunt-schedules/{resource_ids['schedule']}/toggle", None),
        ("SOAR execution", "POST", f"/api/soar/executions/{resource_ids['run']}/approve", {"idempotency_key": "foreign-approval-key"}),
        ("saved investigation", "GET", f"/api/hunts/{resource_ids['hunt']}", None),
        ("enrollment token", "DELETE", f"/api/enrollment-tokens/{resource_ids['token']}", None),
    )

    # When
    observed = [
        (name, _request(method, path, tenant_resources.blue_token, payload).status)
        for name, method, path, payload in scenarios
    ]

    # Then
    assert observed == [(name, 404) for name, *_ in scenarios], observed


@pytest.mark.service_e2e
def test_same_tenant_and_superadmin_can_read_resources(
    tenant_resources: TenantFixture,
) -> None:
    # Given
    blue_alert_path = f"/api/alerts/{tenant_resources.ids['blue_alert']}"
    red_alert_path = f"/api/alerts/{tenant_resources.ids['alert']}"

    # When
    same_tenant = _request("GET", blue_alert_path, tenant_resources.blue_token)
    cross_group_superadmin = _request("GET", red_alert_path, tenant_resources.superadmin_token)

    # Then
    assert same_tenant.status == 200
    assert cross_group_superadmin.status == 200


@pytest.mark.service_e2e
def test_tenant_export_excludes_foreign_alerts(tenant_resources: TenantFixture) -> None:
    # Given
    foreign_id = str(tenant_resources.ids["alert"]).encode()
    same_tenant_id = str(tenant_resources.ids["blue_alert"]).encode()

    # When
    response = _request("GET", "/api/export/alerts", tenant_resources.blue_token)

    # Then
    assert response.status == 200
    assert same_tenant_id in response.body
    assert foreign_id not in response.body
