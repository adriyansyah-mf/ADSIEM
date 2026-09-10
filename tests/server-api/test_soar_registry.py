import uuid

import pytest

from app.services.soar_nodes import (
    catalogue,
    clear_registry,
    get_node_type,
    register,
)
from app.services.soar_nodes.base import NodeContext, NodeResult, NodeType


async def _noop_handler(db, context, config):
    return NodeResult(output={})


def _node_type(name="demo", **overrides):
    defaults = dict(
        node_type=name,
        label="Demo",
        category="logic",
        config_schema={"type": "object", "properties": {}},
        handler=_noop_handler,
    )
    defaults.update(overrides)
    return NodeType(**defaults)


@pytest.fixture(autouse=True)
def _clean_registry():
    clear_registry()
    yield
    clear_registry()


def test_registered_node_type_is_retrievable():
    register(_node_type())
    assert get_node_type("demo").label == "Demo"


def test_unknown_node_type_raises():
    with pytest.raises(KeyError, match="unknown node type"):
        get_node_type("nope")


def test_duplicate_registration_is_rejected():
    register(_node_type())
    with pytest.raises(ValueError, match="already registered"):
        register(_node_type())


def test_catalogue_excludes_the_handler():
    register(_node_type())
    entry = catalogue()[0]
    assert "handler" not in entry
    assert entry["node_type"] == "demo"
    assert entry["config_schema"] == {"type": "object", "properties": {}}


def test_catalogue_reports_handles_and_destructive_flag():
    register(_node_type("if", handles=("true", "false")))
    register(_node_type("block_ip", is_destructive=True))
    by_type = {entry["node_type"]: entry for entry in catalogue()}
    assert by_type["if"]["handles"] == ["true", "false"]
    assert by_type["block_ip"]["is_destructive"] is True
    assert by_type["if"]["is_destructive"] is False


def test_catalogue_is_sorted_by_category_then_type():
    register(_node_type("zebra", category="action"))
    register(_node_type("alpha", category="trigger"))
    register(_node_type("beta", category="action"))
    assert [e["node_type"] for e in catalogue()] == ["beta", "zebra", "alpha"]


def test_node_context_as_dict_shape():
    context = NodeContext(
        run_id=uuid.uuid4(),
        node_id=uuid.uuid4(),
        group_id="default",
        trigger={"alert": {"id": "a1"}},
        nodes={"enrich": {"output": {"risk": 1}}},
        vars={"x": 2},
    )
    assert context.as_dict() == {
        "trigger": {"alert": {"id": "a1"}},
        "nodes": {"enrich": {"output": {"risk": 1}}},
        "vars": {"x": 2},
    }
