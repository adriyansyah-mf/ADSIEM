from collections.abc import Iterator
from dataclasses import dataclass
from typing import assert_never

from sigma.backends.elasticsearch import LuceneBackend
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation
from sigma.rule.detection import SigmaDetection, SigmaDetectionItem

from app.core.sigma import JsonValue, SigmaRuleError
from app.core.sigma_validator import load_sigma_collection

_ROOT_FIELD_MAPPING = {
    "agent.id": "agent_id",
    "event.action": "event_action",
    "event.category": "event_category",
    "host.name": "hostname",
    "source.ip": "source_ip",
    "user.name": "user_name",
}


@dataclass(frozen=True, slots=True)
class CompiledSigmaQuery:
    lucene: str
    body: dict[str, JsonValue]


def compile_sigma_query(content: str) -> CompiledSigmaQuery:
    collection = load_sigma_collection(content)
    if len(collection.rules) != 1:
        raise SigmaRuleError("rule must contain exactly one Sigma rule")
    rule = collection.rules[0]
    mapping = {
        field: _map_field(field)
        for detection in rule.detection.detections.values()
        for field in _iter_detection_fields(detection)
    }
    pipeline = ProcessingPipeline(
        items=[ProcessingItem(FieldMappingTransformation(mapping))]
    )
    queries = LuceneBackend(processing_pipeline=pipeline).convert(collection)
    if not isinstance(queries, list) or len(queries) != 1:
        raise SigmaRuleError("rule must compile to exactly one Elasticsearch query")
    query = queries[0]
    if not isinstance(query, str):
        raise SigmaRuleError("Elasticsearch backend returned a non-string query")
    return CompiledSigmaQuery(
        lucene=query,
        body={"query_string": {"query": query}},
    )


def _map_field(field: str) -> str:
    if field in _ROOT_FIELD_MAPPING:
        return _ROOT_FIELD_MAPPING[field]
    if field.startswith("decoded_fields."):
        return field
    return f"decoded_fields.{field}"


def _iter_detection_fields(detection: SigmaDetection) -> Iterator[str]:
    for item in detection.detection_items:
        match item:
            case SigmaDetectionItem(field=field) if field is not None:
                yield field
            case SigmaDetection() as nested:
                yield from _iter_detection_fields(nested)
            case unreachable:
                assert_never(unreachable)
