# server-api/app/core/query_builder.py
"""Converts the dashboard's visual query-builder tree (nested AND/OR groups
of field/operator/value conditions) into an Elasticsearch bool query.

Tree shape (JSON, sent by the frontend as-is):
  group     := {"logic": "AND"|"OR", "children": [group|condition, ...]}
  condition := {"field": str, "operator": str, "value": str}
"""

# Fields mapped as `keyword` (or otherwise exact-match safe) in the logs index —
# term/wildcard queries work directly on these without a `.keyword` sub-field.
_KEYWORD_FIELDS = {"log_type", "agent_id", "group_id", "event_category", "event_action", "source_ip", "user_name"}


def _keyword_field(field: str) -> str:
    """Field name to use for exact-match (term/wildcard) queries."""
    if field in _KEYWORD_FIELDS:
        return field
    if field.startswith("decoded_fields.") and not field.endswith(".keyword"):
        # decoded_fields is dynamically mapped — ES's default dynamic mapping
        # gives every string sub-field a parallel `.keyword` multi-field.
        return f"{field}.keyword"
    return field


def _condition_to_query(node: dict) -> dict | None:
    field = (node.get("field") or "").strip()
    if not field:
        return None
    op = node.get("operator", "contains")
    value = node.get("value", "")

    if op == "exists":
        return {"exists": {"field": field}}
    if op == "not_exists":
        return {"bool": {"must_not": [{"exists": {"field": field}}]}}
    if op in ("gt", "gte", "lt", "lte"):
        return {"range": {field: {op: value}}}
    if op == "equals":
        return {"term": {_keyword_field(field): value}}
    if op == "not_equals":
        return {"bool": {"must_not": [{"term": {_keyword_field(field): value}}]}}
    if op == "starts_with":
        return {"prefix": {_keyword_field(field): value}}
    # default: contains — analyzed match on the plain (non-keyword) field
    return {"match": {field: value}}


def tree_to_query(node: dict | None) -> dict | None:
    """Recursively convert a builder tree node into an ES query clause, or
    None if the node is empty/invalid (so callers can skip it entirely)."""
    if not node:
        return None
    if "children" in node:
        children = [tree_to_query(c) for c in node.get("children", [])]
        children = [c for c in children if c]
        if not children:
            return None
        if node.get("logic", "AND").upper() == "OR":
            return {"bool": {"should": children, "minimum_should_match": 1}}
        return {"bool": {"must": children}}
    return _condition_to_query(node)
