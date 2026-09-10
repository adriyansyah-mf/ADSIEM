from types import SimpleNamespace

import pytest

from app.services.soar_executor import (
    CyclicWorkflowError,
    ConvergentWorkflowError,
    DisconnectedWorkflowError,
    DuplicateNodeNameError,
    UnknownNodeTypeError,
    advance_frontier,
    build_snapshot,
    find_entry_node_id,
    next_node_ids,
    validate_acyclic,
    validate_graph,
    validate_node_types,
    validate_single_entry,
    validate_single_inbound,
    validate_unique_names,
)
from app.services.soar_nodes import clear_registry
from app.services.soar_nodes.builtin import register_builtin_nodes


@pytest.fixture(autouse=True)
def _registered_builtin_nodes():
    # validate_node_types (called from validate_graph) consults the
    # registry, so every snapshot built from real node types here needs the
    # builtins registered -- same pattern as test_soar_nodes.py.
    clear_registry()
    register_builtin_nodes()
    yield
    clear_registry()


def _node(node_id, node_type="if", name=None):
    return SimpleNamespace(
        id=node_id, node_type=node_type, name=name or node_id, config={}, pos_x=0.0, pos_y=0.0
    )


def _edge(source, target, handle="out"):
    return SimpleNamespace(source_node_id=source, source_handle=handle, target_node_id=target)


def _linear_snapshot():
    return build_snapshot(
        [_node("a", "alert_trigger"), _node("b", "create_case")],
        [_edge("a", "b")],
    )


def _branching_snapshot():
    return build_snapshot(
        [_node("a", "alert_trigger"), _node("cond"), _node("yes"), _node("no")],
        [
            _edge("a", "cond"),
            _edge("cond", "yes", "true"),
            _edge("cond", "no", "false"),
        ],
    )


def test_snapshot_records_nodes_by_id():
    snapshot = _linear_snapshot()
    assert snapshot["nodes"]["a"]["node_type"] == "alert_trigger"
    assert snapshot["nodes"]["b"]["name"] == "b"


def test_snapshot_is_json_safe():
    import json

    json.dumps(_branching_snapshot())


def test_entry_node_is_the_one_with_no_inbound_edge():
    assert find_entry_node_id(_branching_snapshot()) == "a"


def test_entry_node_is_none_when_every_node_has_an_inbound_edge():
    snapshot = build_snapshot([_node("a"), _node("b")], [_edge("a", "b"), _edge("b", "a")])
    assert find_entry_node_id(snapshot) is None


def test_next_node_ids_follows_the_matching_handle():
    snapshot = _branching_snapshot()
    assert next_node_ids(snapshot, "cond", "true") == ["yes"]
    assert next_node_ids(snapshot, "cond", "false") == ["no"]


def test_next_node_ids_is_empty_at_a_terminal_node():
    assert next_node_ids(_linear_snapshot(), "b", "out") == []


def test_next_node_ids_ignores_other_handles():
    assert next_node_ids(_branching_snapshot(), "cond", "out") == []


def test_advance_frontier_returns_the_single_successor():
    snapshot = _linear_snapshot()
    current, pending = advance_frontier(snapshot, "a", "out", [])
    assert current == "b"
    assert pending == []


def test_advance_frontier_queues_fan_out_depth_first():
    snapshot = build_snapshot(
        [_node("a"), _node("x"), _node("y"), _node("z")],
        [_edge("a", "x"), _edge("a", "y"), _edge("a", "z")],
    )
    current, pending = advance_frontier(snapshot, "a", "out", [])
    assert current == "x"
    assert pending == ["y", "z"]


def test_advance_frontier_drains_pending_when_a_branch_ends():
    snapshot = _linear_snapshot()
    current, pending = advance_frontier(snapshot, "b", "out", ["y", "z"])
    assert current == "y"
    assert pending == ["z"]


def test_advance_frontier_returns_none_when_everything_is_done():
    current, pending = advance_frontier(_linear_snapshot(), "b", "out", [])
    assert current is None
    assert pending == []


def test_validate_acyclic_accepts_a_dag():
    validate_acyclic(_branching_snapshot())


def test_validate_acyclic_rejects_a_cycle():
    snapshot = build_snapshot(
        [_node("a"), _node("b"), _node("c")],
        [_edge("a", "b"), _edge("b", "c"), _edge("c", "a")],
    )
    with pytest.raises(CyclicWorkflowError):
        validate_acyclic(snapshot)


def test_validate_acyclic_rejects_a_self_loop():
    snapshot = build_snapshot([_node("a")], [_edge("a", "a")])
    with pytest.raises(CyclicWorkflowError):
        validate_acyclic(snapshot)


def test_validate_single_inbound_accepts_a_tree():
    validate_single_inbound(_branching_snapshot())


def test_validate_single_inbound_rejects_a_reconverging_diamond():
    snapshot = build_snapshot(
        [_node("a"), _node("x"), _node("y"), _node("z")],
        [_edge("a", "x"), _edge("a", "y"), _edge("x", "z"), _edge("y", "z")],
    )
    with pytest.raises(ConvergentWorkflowError):
        validate_single_inbound(snapshot)


def test_validate_graph_rejects_a_cycle():
    snapshot = build_snapshot([_node("a")], [_edge("a", "a")])
    with pytest.raises(CyclicWorkflowError):
        validate_graph(snapshot)


def test_validate_graph_rejects_a_reconverging_diamond():
    snapshot = build_snapshot(
        [_node("a"), _node("x"), _node("y"), _node("z")],
        [_edge("a", "x"), _edge("a", "y"), _edge("x", "z"), _edge("y", "z")],
    )
    with pytest.raises(ConvergentWorkflowError):
        validate_graph(snapshot)


def test_validate_graph_accepts_a_valid_tree():
    validate_graph(_branching_snapshot())


def test_validate_single_entry_accepts_one_root():
    validate_single_entry(_branching_snapshot())


def test_validate_single_entry_rejects_two_disconnected_trees():
    snapshot = build_snapshot(
        [_node("a"), _node("b"), _node("c"), _node("d")],
        [_edge("a", "b"), _edge("c", "d")],
    )
    with pytest.raises(DisconnectedWorkflowError):
        validate_single_entry(snapshot)


def test_validate_single_entry_rejects_a_graph_with_no_root():
    snapshot = build_snapshot([_node("a"), _node("b")], [_edge("a", "b"), _edge("b", "a")])
    with pytest.raises(DisconnectedWorkflowError):
        validate_single_entry(snapshot)


def test_validate_graph_rejects_two_disconnected_trees():
    snapshot = build_snapshot(
        [_node("a"), _node("b"), _node("c"), _node("d")],
        [_edge("a", "b"), _edge("c", "d")],
    )
    with pytest.raises(DisconnectedWorkflowError):
        validate_graph(snapshot)


def test_validate_unique_names_accepts_distinct_names():
    validate_unique_names(_linear_snapshot())


def test_validate_unique_names_rejects_two_nodes_sharing_a_name():
    snapshot = build_snapshot(
        [_node("a", name="Enrich"), _node("b", name="Enrich")],
        [_edge("a", "b")],
    )
    with pytest.raises(DuplicateNodeNameError):
        validate_unique_names(snapshot)


def test_validate_graph_rejects_two_nodes_sharing_a_name():
    snapshot = build_snapshot(
        [_node("a", name="Enrich"), _node("b", name="Enrich")],
        [_edge("a", "b")],
    )
    with pytest.raises(DuplicateNodeNameError):
        validate_graph(snapshot)


def test_validate_node_types_rejects_an_unregistered_node_type():
    snapshot = build_snapshot([_node("a", "does_not_exist")], [])
    with pytest.raises(UnknownNodeTypeError):
        validate_node_types(snapshot)


def test_validate_node_types_rejects_an_edge_using_a_handle_the_source_never_emits():
    # "if" only ever emits "true"/"false" (see builtin.py), so an edge
    # routed off its default "out" handle would find no successor at run
    # time and the run would silently stop short while reporting succeeded.
    snapshot = build_snapshot(
        [_node("a", "alert_trigger"), _node("b", "if"), _node("c", "create_case")],
        [_edge("a", "b"), _edge("b", "c", "out")],
    )
    with pytest.raises(UnknownNodeTypeError):
        validate_node_types(snapshot)


def test_validate_node_types_accepts_a_graph_of_registered_types_with_correct_handles():
    validate_node_types(_branching_snapshot())


def test_validate_graph_rejects_an_unregistered_node_type():
    snapshot = build_snapshot([_node("a", "does_not_exist")], [])
    with pytest.raises(UnknownNodeTypeError):
        validate_graph(snapshot)


def test_validate_graph_rejects_an_edge_using_a_handle_the_source_never_emits():
    snapshot = build_snapshot(
        [_node("a", "alert_trigger"), _node("b", "if"), _node("c", "create_case")],
        [_edge("a", "b"), _edge("b", "c", "out")],
    )
    with pytest.raises(UnknownNodeTypeError):
        validate_graph(snapshot)


# test_validate_graph_accepts_a_valid_tree (above) already covers a valid
# graph built from real registered node types now that builtins are
# registered for every test in this file.
