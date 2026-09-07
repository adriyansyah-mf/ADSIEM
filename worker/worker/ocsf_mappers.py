# worker/worker/ocsf_mappers.py
"""Versioned OCSF (Open Cybersecurity Schema Framework) mappers, one per log
family. Each mapper takes decoded/normalized fields and returns an
OCSF-shaped dict: class_uid/category_uid/activity_name, canonical entities,
source product metadata, severity, and a list of input fields the mapper
did not recognize (an "unmapped_fields" diagnostic, not a failure -- callers
decide whether to surface it).

Every mapper's schema_version defends against a future mapper revision
silently changing field semantics out from under existing consumers: bump it
whenever a mapper's output shape changes."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

OCSF_SCHEMA_VERSION = "1.1.0"

_SEVERITY_MAP = {
    "critical": 6, "high": 5, "medium": 4, "low": 3, "info": 2, "informational": 2,
}


def _severity_id(level: str | None) -> int:
    return _SEVERITY_MAP.get((level or "").lower(), 1)  # 1 = Unknown


def _product_metadata(product_name: str) -> dict[str, Any]:
    return {"product": {"name": product_name, "vendor_name": "AD-SIEM"}, "version": OCSF_SCHEMA_VERSION}


def _envelope(
    *,
    class_uid: int,
    class_name: str,
    category_uid: int,
    category_name: str,
    activity_id: int,
    activity_name: str,
    product_name: str,
    severity: str | None,
    entities: dict[str, Any],
    consumed_keys: set[str],
    fields: Mapping[str, Any],
) -> dict[str, Any]:
    unmapped = sorted(set(fields.keys()) - consumed_keys)
    return {
        "class_uid": class_uid,
        "class_name": class_name,
        "category_uid": category_uid,
        "category_name": category_name,
        "activity_id": activity_id,
        "activity_name": activity_name,
        "severity_id": _severity_id(severity),
        "metadata": _product_metadata(product_name),
        **entities,
        "unmapped_fields": unmapped,
    }


def _get(fields: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in fields and fields[key] not in (None, ""):
            return fields[key]
    return None


def map_windows_authentication(fields: Mapping[str, Any]) -> dict[str, Any]:
    """Windows Security 4624/4625-style logon events -> OCSF Authentication (3002)."""
    consumed = {"user", "user_name", "source_ip", "source.ip", "hostname", "host.name",
                "logon_type", "event_id", "event.action", "severity"}
    success = str(_get(fields, "event_id")) not in ("4625",) and _get(fields, "event.action") != "login_failed"
    return _envelope(
        class_uid=3002, class_name="Authentication",
        category_uid=3, category_name="Identity & Access Management",
        activity_id=1 if success else 2, activity_name="Logon" if success else "Logon Failure",
        product_name="Windows Security", severity=_get(fields, "severity"),
        entities={
            "user": {"name": _get(fields, "user", "user_name")},
            "src_endpoint": {"ip": _get(fields, "source_ip", "source.ip")},
            "dst_endpoint": {"hostname": _get(fields, "hostname", "host.name")},
            "logon_type": _get(fields, "logon_type"),
            "status_id": 1 if success else 2,
        },
        consumed_keys=consumed, fields=fields,
    )


def map_windows_process(fields: Mapping[str, Any]) -> dict[str, Any]:
    """Windows Sysmon/4688-style process creation -> OCSF Process Activity (1007)."""
    consumed = {"process_name", "process.name", "command_line", "parent_process", "user", "user_name",
                "hostname", "host.name", "severity"}
    return _envelope(
        class_uid=1007, class_name="Process Activity",
        category_uid=1, category_name="System Activity",
        activity_id=1, activity_name="Launch",
        product_name="Windows Sysmon", severity=_get(fields, "severity"),
        entities={
            "process": {
                "name": _get(fields, "process_name", "process.name"),
                "cmd_line": _get(fields, "command_line"),
                "parent_process": {"name": _get(fields, "parent_process")},
            },
            "actor": {"user": {"name": _get(fields, "user", "user_name")}},
            "device": {"hostname": _get(fields, "hostname", "host.name")},
        },
        consumed_keys=consumed, fields=fields,
    )


def map_linux_auth(fields: Mapping[str, Any]) -> dict[str, Any]:
    """Linux /var/log/auth.log (sshd, sudo, su) -> OCSF Authentication (3002)."""
    consumed = {"user", "user_name", "source_ip", "source.ip", "hostname", "host.name",
                "event.action", "auth_method", "severity"}
    action = str(_get(fields, "event.action") or "").lower()
    success = "fail" not in action and "invalid" not in action
    return _envelope(
        class_uid=3002, class_name="Authentication",
        category_uid=3, category_name="Identity & Access Management",
        activity_id=1 if success else 2, activity_name="Logon" if success else "Logon Failure",
        product_name="Linux PAM", severity=_get(fields, "severity"),
        entities={
            "user": {"name": _get(fields, "user", "user_name")},
            "src_endpoint": {"ip": _get(fields, "source_ip", "source.ip")},
            "dst_endpoint": {"hostname": _get(fields, "hostname", "host.name")},
            "auth_protocol": _get(fields, "auth_method"),
            "status_id": 1 if success else 2,
        },
        consumed_keys=consumed, fields=fields,
    )


def map_firewall_network(fields: Mapping[str, Any]) -> dict[str, Any]:
    """Firewall/network flow logs -> OCSF Network Activity (4001)."""
    consumed = {"source_ip", "source.ip", "destination_ip", "destination.ip", "source_port",
                "destination_port", "protocol", "action", "bytes", "severity"}
    action = str(_get(fields, "action") or "").lower()
    allowed = action in ("allow", "allowed", "permit", "") or not action
    return _envelope(
        class_uid=4001, class_name="Network Activity",
        category_uid=4, category_name="Network Activity",
        activity_id=1 if allowed else 2, activity_name="Allowed" if allowed else "Denied",
        product_name="Firewall", severity=_get(fields, "severity"),
        entities={
            "src_endpoint": {"ip": _get(fields, "source_ip", "source.ip"), "port": _get(fields, "source_port")},
            "dst_endpoint": {"ip": _get(fields, "destination_ip", "destination.ip"), "port": _get(fields, "destination_port")},
            "connection_info": {"protocol_name": _get(fields, "protocol")},
            "traffic": {"bytes": _get(fields, "bytes")},
            "disposition": "Allowed" if allowed else "Blocked",
        },
        consumed_keys=consumed, fields=fields,
    )


def map_dns(fields: Mapping[str, Any]) -> dict[str, Any]:
    """DNS query/response logs -> OCSF DNS Activity (4003)."""
    consumed = {"query", "domain", "query_type", "answer", "source_ip", "source.ip", "severity"}
    return _envelope(
        class_uid=4003, class_name="DNS Activity",
        category_uid=4, category_name="Network Activity",
        activity_id=1, activity_name="Query",
        product_name="DNS", severity=_get(fields, "severity"),
        entities={
            "query": {"hostname": _get(fields, "query", "domain"), "type": _get(fields, "query_type")},
            "answers": _get(fields, "answer"),
            "src_endpoint": {"ip": _get(fields, "source_ip", "source.ip")},
        },
        consumed_keys=consumed, fields=fields,
    )


def map_proxy_web(fields: Mapping[str, Any]) -> dict[str, Any]:
    """Proxy/web access logs -> OCSF HTTP Activity (4002)."""
    consumed = {"url", "http_method", "status_code", "user_agent", "source_ip", "source.ip",
                "bytes", "severity"}
    return _envelope(
        class_uid=4002, class_name="HTTP Activity",
        category_uid=4, category_name="Network Activity",
        activity_id=1, activity_name="Request",
        product_name="Web Proxy", severity=_get(fields, "severity"),
        entities={
            "http_request": {
                "url": {"text": _get(fields, "url")},
                "http_method": _get(fields, "http_method"),
                "user_agent": _get(fields, "user_agent"),
            },
            "http_response": {"code": _get(fields, "status_code")},
            "src_endpoint": {"ip": _get(fields, "source_ip", "source.ip")},
            "traffic": {"bytes": _get(fields, "bytes")},
        },
        consumed_keys=consumed, fields=fields,
    )


def map_cloud_audit(fields: Mapping[str, Any]) -> dict[str, Any]:
    """Cloud provider audit-trail events (CloudTrail/Azure AD/GCP audit-style) -> OCSF API Activity (3005)."""
    consumed = {"event_name", "user", "user_name", "source_ip", "source.ip", "aws_region",
                "region", "resource", "severity"}
    return _envelope(
        class_uid=3005, class_name="API Activity",
        category_uid=3, category_name="Identity & Access Management",
        activity_id=1, activity_name=str(_get(fields, "event_name") or "API Call"),
        product_name="Cloud Audit", severity=_get(fields, "severity"),
        entities={
            "actor": {"user": {"name": _get(fields, "user", "user_name")}},
            "src_endpoint": {"ip": _get(fields, "source_ip", "source.ip")},
            "cloud": {"region": _get(fields, "aws_region", "region")},
            "resources": [{"name": _get(fields, "resource")}] if _get(fields, "resource") else [],
        },
        consumed_keys=consumed, fields=fields,
    )


def map_endpoint_fim(fields: Mapping[str, Any]) -> dict[str, Any]:
    """Endpoint / File Integrity Monitoring events -> OCSF File System Activity (1001)."""
    consumed = {"path", "event_type", "sha256", "hostname", "host.name", "size_bytes", "severity"}
    return _envelope(
        class_uid=1001, class_name="File System Activity",
        category_uid=1, category_name="System Activity",
        activity_id=1, activity_name=str(_get(fields, "event_type") or "Change"),
        product_name="FIM Agent", severity=_get(fields, "severity"),
        entities={
            "file": {
                "path": _get(fields, "path"),
                "hashes": [{"algorithm": "SHA-256", "value": _get(fields, "sha256")}] if _get(fields, "sha256") else [],
                "size": _get(fields, "size_bytes"),
            },
            "device": {"hostname": _get(fields, "hostname", "host.name")},
        },
        consumed_keys=consumed, fields=fields,
    )


def map_fallback(fields: Mapping[str, Any]) -> dict[str, Any]:
    """Any log family without a dedicated mapper -> OCSF Base Event (0).
    Every input field is reported as unmapped by design -- this mapper makes
    no assumptions about field meaning."""
    return _envelope(
        class_uid=0, class_name="Base Event",
        category_uid=0, category_name="Uncategorized",
        activity_id=0, activity_name="Unknown",
        product_name="AD-SIEM", severity=_get(fields, "severity"),
        entities={"raw": dict(fields)},
        consumed_keys=set(),
        fields=fields,
    )


# Dispatch table: log_type (as used by the decoder pipeline) -> mapper.
# `map_fallback` is deliberately not registered here -- callers should use it
# explicitly as the default when `MAPPERS.get(log_type)` misses.
MAPPERS = {
    "windows_authentication": map_windows_authentication,
    "windows_process": map_windows_process,
    "linux_auth": map_linux_auth,
    "firewall": map_firewall_network,
    "dns": map_dns,
    "proxy": map_proxy_web,
    "cloud_audit": map_cloud_audit,
    "fim": map_endpoint_fim,
}


def map_event(log_type: str, fields: Mapping[str, Any]) -> dict[str, Any]:
    """Look up the mapper for `log_type`, falling back to the generic mapper
    for any unrecognized family rather than raising."""
    mapper = MAPPERS.get(log_type, map_fallback)
    return mapper(fields)


def _map_authentication(fields: Mapping[str, Any]) -> dict[str, Any]:
    if _get(fields, "event_id", "logon_type") is not None:
        return map_windows_authentication(fields)
    return map_linux_auth(fields)


# ECS-style `event.category` values (the one taxonomy every decoder --
# built-in or user-configured -- is asked to populate) to a mapper. Decoder
# *names* are free-form and user-configurable, so they can't be dispatch
# keys; `event.category` is the only stable signal available at this layer.
_CATEGORY_MAPPERS = {
    "authentication": _map_authentication,
    "process": map_windows_process,
    "network": map_firewall_network,
    "dns": map_dns,
    "web": map_proxy_web,
    "http": map_proxy_web,
    "iam": map_cloud_audit,
    "api": map_cloud_audit,
    "file": map_endpoint_fim,
    "file_integrity": map_endpoint_fim,
}


def map_by_category(category: str | None, fields: Mapping[str, Any]) -> dict[str, Any]:
    """Dispatch on ECS `event.category` rather than a decoder name, since
    decoders are user-configurable and their names carry no fixed taxonomy.
    Falls back to the generic OCSF Base Event mapper for any category this
    layer doesn't (yet) recognize."""
    mapper = _CATEGORY_MAPPERS.get((category or "").lower(), map_fallback)
    return mapper(fields)
