from __future__ import annotations

from worker.ocsf_mappers import (
    MAPPERS,
    map_cloud_audit,
    map_dns,
    map_endpoint_fim,
    map_event,
    map_fallback,
    map_firewall_network,
    map_linux_auth,
    map_proxy_web,
    map_windows_authentication,
    map_windows_process,
)


def test_windows_authentication_success_maps_to_logon() -> None:
    event = map_windows_authentication({
        "user": "alice", "source_ip": "10.0.0.5", "hostname": "DC01",
        "logon_type": "3", "event_id": "4624", "severity": "low",
    })
    assert event["class_uid"] == 3002
    assert event["category_uid"] == 3
    assert event["activity_name"] == "Logon"
    assert event["status_id"] == 1
    assert event["user"]["name"] == "alice"
    assert event["src_endpoint"]["ip"] == "10.0.0.5"
    assert event["unmapped_fields"] == []


def test_windows_authentication_failure_maps_to_logon_failure() -> None:
    event = map_windows_authentication({"user": "bob", "event_id": "4625"})
    assert event["activity_name"] == "Logon Failure"
    assert event["status_id"] == 2


def test_windows_process_maps_to_process_activity() -> None:
    event = map_windows_process({
        "process_name": "powershell.exe", "command_line": "-enc AAAA",
        "parent_process": "explorer.exe", "user": "alice", "hostname": "WS01",
    })
    assert event["class_uid"] == 1007
    assert event["category_uid"] == 1
    assert event["process"]["name"] == "powershell.exe"
    assert event["process"]["parent_process"]["name"] == "explorer.exe"
    assert event["unmapped_fields"] == []


def test_linux_auth_success() -> None:
    event = map_linux_auth({"user": "root", "source_ip": "1.2.3.4", "event.action": "session_opened"})
    assert event["class_uid"] == 3002
    assert event["activity_name"] == "Logon"
    assert event["status_id"] == 1


def test_linux_auth_failure_detected_from_action() -> None:
    event = map_linux_auth({"user": "root", "event.action": "authentication_failure"})
    assert event["activity_name"] == "Logon Failure"
    assert event["status_id"] == 2


def test_firewall_allowed_traffic() -> None:
    event = map_firewall_network({
        "source_ip": "10.1.1.1", "destination_ip": "8.8.8.8", "source_port": "5555",
        "destination_port": "443", "protocol": "tcp", "action": "allow", "bytes": "1024",
    })
    assert event["class_uid"] == 4001
    assert event["disposition"] == "Allowed"
    assert event["dst_endpoint"]["ip"] == "8.8.8.8"


def test_firewall_denied_traffic() -> None:
    event = map_firewall_network({"source_ip": "10.1.1.1", "destination_ip": "8.8.8.8", "action": "deny"})
    assert event["disposition"] == "Blocked"
    assert event["activity_name"] == "Denied"


def test_dns_query_maps_correctly() -> None:
    event = map_dns({"query": "evil.test", "query_type": "A", "answer": "1.2.3.4", "source_ip": "10.0.0.1"})
    assert event["class_uid"] == 4003
    assert event["query"]["hostname"] == "evil.test"


def test_proxy_web_maps_to_http_activity() -> None:
    event = map_proxy_web({
        "url": "http://evil.test/path", "http_method": "GET", "status_code": "200",
        "user_agent": "curl/8.0", "source_ip": "10.0.0.9",
    })
    assert event["class_uid"] == 4002
    assert event["http_request"]["url"]["text"] == "http://evil.test/path"
    assert event["http_response"]["code"] == "200"


def test_cloud_audit_maps_to_api_activity() -> None:
    event = map_cloud_audit({"event_name": "ConsoleLogin", "user": "admin", "aws_region": "us-east-1"})
    assert event["class_uid"] == 3005
    assert event["activity_name"] == "ConsoleLogin"
    assert event["cloud"]["region"] == "us-east-1"


def test_endpoint_fim_maps_file_activity() -> None:
    event = map_endpoint_fim({
        "path": "/etc/passwd", "event_type": "modified", "sha256": "abc123", "hostname": "srv01",
    })
    assert event["class_uid"] == 1001
    assert event["file"]["path"] == "/etc/passwd"
    assert event["file"]["hashes"][0]["value"] == "abc123"


def test_unrecognized_field_is_reported_as_unmapped() -> None:
    event = map_windows_authentication({"user": "alice", "totally_custom_field": "x"})
    assert "totally_custom_field" in event["unmapped_fields"]


def test_fallback_reports_all_fields_unmapped_and_uses_base_event() -> None:
    event = map_fallback({"anything": "goes", "here": 1})
    assert event["class_uid"] == 0
    assert event["category_uid"] == 0
    assert set(event["unmapped_fields"]) == {"anything", "here"}
    assert event["raw"] == {"anything": "goes", "here": 1}


def test_map_event_dispatches_by_log_type() -> None:
    event = map_event("dns", {"query": "x.test"})
    assert event["class_uid"] == 4003


def test_map_event_falls_back_for_unknown_log_type() -> None:
    event = map_event("some_unrecognized_family", {"a": 1})
    assert event["class_uid"] == 0


def test_every_registered_mapper_is_reachable_via_map_event() -> None:
    for log_type in MAPPERS:
        event = map_event(log_type, {})
        assert event["class_uid"] != 0 or log_type == "fallback"


def test_severity_maps_to_expected_ocsf_severity_id() -> None:
    assert map_dns({"severity": "critical"})["severity_id"] == 6
    assert map_dns({"severity": "info"})["severity_id"] == 2
    assert map_dns({})["severity_id"] == 1
