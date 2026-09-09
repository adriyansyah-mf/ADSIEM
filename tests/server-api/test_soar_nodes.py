import uuid

import pytest

from app.services.soar_nodes import clear_registry, get_node_type
from app.services.soar_nodes.base import NodeContext
from app.services.soar_nodes.builtin import register_builtin_nodes


class FakeSession:
    """Captures db.add() without touching a database."""

    def __init__(self):
        self.added = []

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        return None


@pytest.fixture(autouse=True)
def _registry():
    clear_registry()
    register_builtin_nodes()
    yield
    clear_registry()


def _context(**overrides):
    defaults = dict(
        run_id=uuid.uuid4(),
        node_id=uuid.uuid4(),
        group_id="acme",
        trigger={"alert": {"id": str(uuid.uuid4()), "severity": "critical", "source_ip": "1.2.3.4"}},
        nodes={},
        vars={},
    )
    defaults.update(overrides)
    return NodeContext(**defaults)


async def _run(node_type_name, config, context, db=None):
    node = get_node_type(node_type_name)
    return await node.handler(db or FakeSession(), context, config)


@pytest.mark.asyncio
async def test_all_six_nodes_are_registered():
    for name in ["alert_trigger", "if", "create_case", "add_note", "block_ip", "isolate_agent"]:
        assert get_node_type(name).node_type == name


@pytest.mark.asyncio
async def test_alert_trigger_passes_the_alert_through():
    context = _context()
    result = await _run("alert_trigger", {}, context)
    assert result.output == {"alert": context.trigger["alert"]}
    assert result.handle == "out"


@pytest.mark.asyncio
async def test_if_node_true_branch():
    result = await _run(
        "if",
        {"left": "{{ trigger.alert.severity }}", "operator": "eq", "right": "critical"},
        _context(),
    )
    assert result.handle == "true"
    assert result.output == {"matched": True}


@pytest.mark.asyncio
async def test_if_node_false_branch():
    result = await _run(
        "if",
        {"left": "{{ trigger.alert.severity }}", "operator": "eq", "right": "low"},
        _context(),
    )
    assert result.handle == "false"


@pytest.mark.asyncio
async def test_if_node_numeric_comparison():
    context = _context(nodes={"enrich": {"output": {"risk": 0.9}}})
    result = await _run(
        "if",
        {"left": "{{ nodes.enrich.output.risk }}", "operator": "gt", "right": 0.5},
        context,
    )
    assert result.handle == "true"


@pytest.mark.asyncio
async def test_if_node_contains_operator():
    context = _context(nodes={"enrich": {"output": {"tags": ["tor", "scanner"]}}})
    result = await _run(
        "if",
        {"left": "{{ nodes.enrich.output.tags }}", "operator": "contains", "right": "tor"},
        context,
    )
    assert result.handle == "true"


@pytest.mark.asyncio
async def test_if_node_rejects_unknown_operator():
    with pytest.raises(ValueError, match="unsupported operator"):
        await _run("if", {"left": "a", "operator": "regex", "right": "b"}, _context())


@pytest.mark.asyncio
async def test_create_case_adds_a_case_with_resolved_title():
    db = FakeSession()
    result = await _run(
        "create_case",
        {"title": "Investigate {{ trigger.alert.severity }}", "severity": "high"},
        _context(),
        db,
    )
    assert len(db.added) == 1
    case = db.added[0]
    assert case.title == "Investigate critical"
    assert case.severity == "high"
    assert case.group_id == "acme"
    assert result.output["case_id"] == str(case.id)


@pytest.mark.asyncio
async def test_add_note_requires_a_case_id():
    with pytest.raises(ValueError, match="case_id"):
        await _run("add_note", {"content": "hello"}, _context())


@pytest.mark.asyncio
async def test_add_note_attaches_to_the_referenced_case():
    case_id = str(uuid.uuid4())
    context = _context(nodes={"open": {"output": {"case_id": case_id}}})
    db = FakeSession()
    await _run(
        "add_note",
        {"case_id": "{{ nodes.open.output.case_id }}", "content": "sev {{ trigger.alert.severity }}"},
        context,
        db,
    )
    note = db.added[0]
    assert str(note.case_id) == case_id
    assert note.content == "sev critical"
    assert note.is_ai_generated is False


@pytest.mark.asyncio
async def test_block_ip_parks_the_run_and_never_executes():
    db = FakeSession()
    result = await _run(
        "block_ip",
        {"ip": "{{ trigger.alert.source_ip }}", "agent_id": str(uuid.uuid4())},
        _context(),
        db,
    )
    assert len(db.added) == 1
    step = db.added[0]
    assert result.wait is True
    assert step.action_type == "block_ip"
    assert step.status == "pending_approval"
    assert step.is_destructive is True
    assert step.input["ip"] == "1.2.3.4"


@pytest.mark.asyncio
async def test_isolate_agent_parks_the_run_and_is_reversible():
    db = FakeSession()
    result = await _run("isolate_agent", {"agent_id": str(uuid.uuid4())}, _context(), db)
    assert len(db.added) == 1
    step = db.added[0]
    assert result.wait is True
    assert step.status == "pending_approval"
    assert step.is_reversible is True


@pytest.mark.asyncio
async def test_destructive_nodes_are_flagged_in_the_registry():
    assert get_node_type("block_ip").is_destructive is True
    assert get_node_type("isolate_agent").is_destructive is True
    assert get_node_type("create_case").is_destructive is False
