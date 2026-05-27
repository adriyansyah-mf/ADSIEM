# worker/worker/ueba/mitre_mapper.py
"""
Rule-based mapping from UEBA feature values to MITRE ATT&CK techniques.
Each rule specifies: technique ID, name, applicable entity types, and a condition function.
"""

_RULES = [
    {
        "id": "T1110",
        "name": "Brute Force",
        "entity_types": {"user", "ip"},
        "condition": lambda f, t: f.get("failed_ratio", 0) >= 0.5 and f.get("login_count", 0) >= 5,
    },
    {
        "id": "T1110.003",
        "name": "Password Spraying",
        "entity_types": {"ip"},
        "condition": lambda f, t: f.get("unique_users", 0) >= 5 and f.get("failed_ratio", 0) >= 0.2,
    },
    {
        "id": "T1078",
        "name": "Valid Accounts",
        "entity_types": {"user"},
        "condition": lambda f, t: f.get("new_ip_seen", 0) >= 1 and f.get("unique_ips", 0) >= 3,
    },
    {
        "id": "T1078.001",
        "name": "Valid Accounts: Unusual Time Access",
        "entity_types": {"user"},
        "condition": lambda f, t: f.get("hour_deviation", 0) >= 6 and f.get("login_count", 0) >= 2,
    },
    {
        "id": "T1548",
        "name": "Abuse Elevation Control Mechanism",
        "entity_types": {"user", "host"},
        "condition": lambda f, t: f.get("sudo_count", 0) >= 3,
    },
    {
        "id": "T1021",
        "name": "Remote Services (Lateral Movement)",
        "entity_types": {"host"},
        "condition": lambda f, t: f.get("unique_source_ips", 0) >= 5 or f.get("unique_users", 0) >= 4,
    },
    {
        "id": "T1078.003",
        "name": "Valid Accounts: Local Accounts",
        "entity_types": {"user"},
        "condition": lambda f, t: f.get("sudo_count", 0) >= 2 and f.get("is_weekend", 0) == 1,
    },
]


def map_to_mitre(features: dict, entity_type: str) -> list[dict]:
    """
    Given a feature dict and entity type, return list of matched MITRE techniques.
    Each result is {"id": "T1110", "name": "Brute Force"}.
    """
    return [
        {"id": r["id"], "name": r["name"]}
        for r in _RULES
        if entity_type in r["entity_types"] and r["condition"](features, entity_type)
    ]
