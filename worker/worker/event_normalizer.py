"""Canonical event projection shared by ingestion and Sigma evaluation."""

from collections.abc import Mapping
from typing import TypeAlias

from worker.ocsf_mappers import map_by_category

JsonScalar: TypeAlias = str | int | float | bool | None
NormalizedValue: TypeAlias = JsonScalar | dict[str, "NormalizedValue"]


def normalize_event(
    decoded_fields: Mapping[str, JsonScalar],
    hostname: str | None,
    received_at: str,
) -> dict[str, NormalizedValue]:
    """Project decoder output into stable ECS-like fields without dropping legacy keys."""
    source_ip = _first_value(decoded_fields, "source.ip", "source_ip")
    host_name = _first_value(decoded_fields, "host.name", "hostname") or hostname
    user_name = _first_value(decoded_fields, "user.name", "user_name")
    event_action = _first_value(decoded_fields, "event.action", "event_action")
    event_category = _first_value(decoded_fields, "event.category", "event_category")

    normalized: dict[str, NormalizedValue] = {
        "@timestamp": received_at,
        "source": {"ip": source_ip},
        "host": {"name": host_name},
        "user": {"name": user_name},
        "event": {"action": event_action, "category": event_category},
        "ocsf": map_by_category(event_category, decoded_fields),
    }
    return {key: value for key, value in normalized.items() if _has_value(value)}


def _first_value(fields: Mapping[str, JsonScalar], *keys: str) -> JsonScalar:
    for key in keys:
        value = fields.get(key)
        if value is not None and value != "":
            return value
    return None


def _has_value(value: NormalizedValue) -> bool:
    if isinstance(value, dict):
        return any(item is not None and item != "" for item in value.values())
    return value is not None and value != ""
