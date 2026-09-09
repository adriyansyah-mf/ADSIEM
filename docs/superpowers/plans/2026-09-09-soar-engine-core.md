# SOAR Engine Core (Headless) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the graph executor, node registry, and workflow API that let a SOAR workflow run end-to-end from an alert, with no UI.

**Architecture:** A background asyncio loop in server-api claims runnable `soar_runs` rows with `SELECT ... FOR UPDATE SKIP LOCKED`, executes exactly one node per tick against a graph snapshot stored on the run, and persists each node's input and output to `soar_run_steps`. Destructive nodes only *prepare* steps; execution stays with the already-live approve route. Alerts reach the executor from the worker over a Redis queue.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy async, PostgreSQL 16, Redis 7, pytest.

**Spec:** `docs/superpowers/specs/2026-09-09-soar-visual-workflow-design.md` (slice 1 of §13)

## Global Constraints

- The executor runs in **server-api**, never the worker. server-api and worker have separate Docker build contexts and cannot share code (spec §5).
- Step status values come from `soar_service.py` and must not be extended beyond the one addition the spec permits: `pending`, `pending_approval`, `approved`, `running`, `succeeded`, `rolled_back`, plus `failed` — which only the executor writes, for a node whose handler raised (spec §5).
- Run status values: `pending`, `running`, `waiting`, `succeeded`, `failed`, `cancelled` (spec §5).
- The expression filter set is closed to exactly four: `default`, `lower`, `upper`, `json`. Adding one requires a spec change (spec §5.4).
- No template engine and no `eval` in the resolver. Dotted-path lookup only (spec §5.4, §10).
- Destructive nodes (`block_ip`, `isolate_agent`) must never execute inline. They create a step via `build_step_record` and park the run (spec §7).
- The HTTP node — and any future outbound call — must use `app.core.outbound_url`, never a new guard (spec §10). *(No HTTP node in this slice; the constraint is recorded because Task 3's registry is where a later one plugs in.)*
- Everything ships behind the `soar_v2_enabled` platform setting, default `"false"` (spec §12).
- Graphs are acyclic; validated on save (spec §9).
- The executor must commit its DB transaction before any outbound HTTP or LLM call (spec §9).
- Tests: **all tests in this plan are pure-logic with fakes** and run on the host. No test needs a *running* database — but any test importing `app.models.models` transitively imports `app.core.database`, which needs the `asyncpg` driver installed to import at all. Install it if collection fails: `pip install --user asyncpg==0.30.0` (the version already pinned in `server-api/requirements.txt`). (`structlog` is a real server-api dependency and is safe to import in application code.)

**Deliberately deferred from the spec, and why.** Spec §9's per-node `on_error` policy, retry-with-backoff, and per-node timeouts are *not* built here. None of slice 1's six nodes performs I/O beyond the local database session, so there is nothing to time out or retry; those mechanisms belong with the slice that introduces the HTTP Request and AI Analyze nodes, where they are load-bearing. A node that raises fails its run, which is the correct conservative default in the meantime. Spec §9's run-duration cap and per-tenant concurrency cap are deferred for the same reason; the step ceiling (`MAX_STEPS_PER_RUN`) is implemented because it is the guard against a runaway graph, which slice 1 *can* produce.

---

## File Structure

**Created:**
- `server-api/app/services/soar_expressions.py` — the restricted `{{ }}` resolver. Pure, no I/O.
- `server-api/app/services/soar_nodes/__init__.py` — registry: register, lookup, catalogue.
- `server-api/app/services/soar_nodes/base.py` — `NodeContext`, `NodeResult`, `NodeType` types.
- `server-api/app/services/soar_nodes/builtin.py` — the six node implementations.
- `server-api/app/services/soar_executor.py` — snapshot, traversal, claim, tick, loop.
- `server-api/app/api/routes/soar_workflows.py` — workflow/node/edge CRUD + `GET /node-types`.
- `tests/server-api/test_soar_expressions.py`
- `tests/server-api/test_soar_registry.py`
- `tests/server-api/test_soar_traversal.py`
- `tests/server-api/test_soar_nodes.py`

**Modified:**
- `server-api/app/models/models.py` — two columns on `SoarRun`.
- `server-api/app/main.py` — migration function, lifespan task, setting seed.
- `server-api/app/core/permission_matrix.py` — new route entries.
- `server-api/app/api/routes/soar.py` — mount the new router.
- `worker/worker/ai_analyst.py` — publish alert ids to the trigger queue.

Traversal logic is deliberately separated from database access inside `soar_executor.py`: the pure functions (`build_snapshot`, `next_node_ids`, `advance_frontier`) are what Task 5 tests, while the claim/tick functions wrap them in I/O that this plan does not unit-test.

---

### Task 1: Schema columns for snapshot and frontier

**Files:**
- Modify: `server-api/app/models/models.py:669-681` (`SoarRun`)
- Modify: `server-api/app/main.py` (new `_migrate_soar_v2_engine_columns`, called in `lifespan`)

**Interfaces:**
- Consumes: nothing.
- Produces: `SoarRun.graph_snapshot: dict | None` and `SoarRun.pending_node_ids: list | None`, both JSONB, used by Tasks 5 and 8.

- [ ] **Step 1: Add the two columns to the model**

In `server-api/app/models/models.py`, inside `class SoarRun`, after the `variables` column:

```python
    graph_snapshot  = Column(JSONB, nullable=True)
    pending_node_ids = Column(JSONB, nullable=False, default=list)
```

- [ ] **Step 2: Add the migration function**

In `server-api/app/main.py`, next to the other `_migrate_*` functions:

```python
async def _migrate_soar_v2_engine_columns() -> None:
    """Graph snapshot + depth-first frontier for the v2 executor.

    The snapshot makes a run immune to later edits of its workflow; see
    docs/superpowers/specs/2026-09-09-soar-visual-workflow-design.md §5.2.
    """
    from sqlalchemy import text
    async with engine.begin() as conn:
        await conn.execute(text(
            "ALTER TABLE soar_runs ADD COLUMN IF NOT EXISTS graph_snapshot JSONB"
        ))
        await conn.execute(text(
            "ALTER TABLE soar_runs ADD COLUMN IF NOT EXISTS "
            "pending_node_ids JSONB NOT NULL DEFAULT '[]'::jsonb"
        ))
```

- [ ] **Step 3: Call it from `lifespan`**

In `server-api/app/main.py`, in the migration block inside `lifespan`, add after `await _migrate_soar_v2_tables()`:

```python
        await _migrate_soar_v2_engine_columns()
```

- [ ] **Step 4: Seed the rollout setting**

In `server-api/app/main.py`, add to the `_DEFAULT_SETTINGS` list, next to the other SOAR entry:

```python
    ("soar_v2_enabled", "false", False, "Enable the v2 visual workflow executor (true/false)"),
```

- [ ] **Step 5: Verify the module still imports**

Run: `python -c "import ast;ast.parse(open('server-api/app/main.py').read());ast.parse(open('server-api/app/models/models.py').read())"`
Expected: no output, exit code 0.

- [ ] **Step 6: Commit**

```bash
git add server-api/app/models/models.py server-api/app/main.py
git commit -m "feat(soar): add graph snapshot and frontier columns to soar_runs"
```

---

### Task 2: Restricted expression resolver

**Files:**
- Create: `server-api/app/services/soar_expressions.py`
- Test: `tests/server-api/test_soar_expressions.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `resolve_value(template: str, context: dict) -> Any` and `resolve_config(config: dict, context: dict) -> dict`. Task 4 and Task 5 call `resolve_config`.

Semantics: a string that is *exactly* one expression returns the resolved value with its type intact (so `{{ trigger.alert.severity }}` used by an If node compares as a string, and a number stays a number). A string with surrounding text interpolates and returns a string. An unresolvable path yields `None`.

- [ ] **Step 1: Write the failing tests**

Create `tests/server-api/test_soar_expressions.py`:

```python
import pytest

from app.services.soar_expressions import resolve_config, resolve_value

CONTEXT = {
    "trigger": {"alert": {"severity": "critical", "score": 91, "src": None}},
    "nodes": {"enrich": {"output": {"risk": 0.8, "tags": ["tor", "scanner"]}}},
    "vars": {"channel": "soc-alerts"},
}


def test_whole_string_expression_preserves_type():
    assert resolve_value("{{ trigger.alert.score }}", CONTEXT) == 91


def test_whole_string_expression_preserves_list():
    assert resolve_value("{{ nodes.enrich.output.tags }}", CONTEXT) == ["tor", "scanner"]


def test_interpolation_returns_string():
    assert resolve_value("sev={{ trigger.alert.severity }}!", CONTEXT) == "sev=critical!"


def test_missing_path_resolves_to_none():
    assert resolve_value("{{ trigger.alert.nothere }}", CONTEXT) is None


def test_missing_path_in_interpolation_renders_empty():
    assert resolve_value("x={{ a.b.c }}", CONTEXT) == "x="


def test_default_filter_applies_to_missing_path():
    assert resolve_value("{{ trigger.alert.nothere | default(7) }}", CONTEXT) == 7


def test_default_filter_ignored_when_path_resolves():
    assert resolve_value("{{ trigger.alert.score | default(7) }}", CONTEXT) == 91


def test_default_filter_applies_to_explicit_none():
    assert resolve_value("{{ trigger.alert.src | default('unknown') }}", CONTEXT) == "unknown"


def test_upper_and_lower_filters():
    assert resolve_value("{{ trigger.alert.severity | upper }}", CONTEXT) == "CRITICAL"
    assert resolve_value("{{ vars.channel | upper | lower }}", CONTEXT) == "soc-alerts"


def test_json_filter_serialises():
    assert resolve_value("{{ nodes.enrich.output.tags | json }}", CONTEXT) == '["tor", "scanner"]'


def test_unknown_filter_is_rejected():
    with pytest.raises(ValueError, match="unsupported filter"):
        resolve_value("{{ vars.channel | eval }}", CONTEXT)


def test_dunder_path_segment_is_rejected():
    with pytest.raises(ValueError, match="invalid path"):
        resolve_value("{{ vars.__class__ }}", CONTEXT)


def test_non_template_string_passes_through():
    assert resolve_value("plain text", CONTEXT) == "plain text"


def test_two_expressions_in_one_string_interpolate_separately():
    # Guards a real trap: a naive "^{{...}}$" test treats this whole string
    # as one expression whose path is `channel }} {{ trigger.alert.severity`.
    assert (
        resolve_value("{{ vars.channel }} {{ trigger.alert.severity }}", CONTEXT)
        == "soc-alerts critical"
    )


def test_resolve_config_walks_nested_structures():
    config = {
        "title": "Alert {{ trigger.alert.severity }}",
        "meta": {"risk": "{{ nodes.enrich.output.risk }}"},
        "tags": ["{{ vars.channel }}", "static"],
        "count": 3,
    }
    assert resolve_config(config, CONTEXT) == {
        "title": "Alert critical",
        "meta": {"risk": 0.8},
        "tags": ["soc-alerts", "static"],
        "count": 3,
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/server-api/test_soar_expressions.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.services.soar_expressions'`

- [ ] **Step 3: Implement the resolver**

Create `server-api/app/services/soar_expressions.py`:

```python
"""Restricted `{{ path | filter }}` resolution for SOAR node configuration.

Deliberately not a template engine and never `eval`: a general-purpose
evaluator would reintroduce the arbitrary-code-execution node the design
rejected, through a side door. Dotted-path lookup with a closed filter set
only — see the design doc, sections 5.4 and 10.
"""
from __future__ import annotations

import json
import re
from typing import Any

_EXPRESSION = re.compile(r"\{\{(.+?)\}\}", re.DOTALL)
_SEGMENT = re.compile(r"^[A-Za-z0-9_-]+$")
_DEFAULT_CALL = re.compile(r"^default\((.*)\)$", re.DOTALL)

_MISSING = object()


def _lookup(path: str, context: dict) -> Any:
    current: Any = context
    for segment in path.split("."):
        segment = segment.strip()
        if not _SEGMENT.match(segment) or segment.startswith("__"):
            raise ValueError(f"invalid path segment {segment!r}")
        if isinstance(current, dict) and segment in current:
            current = current[segment]
        else:
            return _MISSING
    return current


def _parse_default_argument(raw: str) -> Any:
    raw = raw.strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        pass
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "'\"":
        return raw[1:-1]
    return raw


def _apply_filter(name: str, value: Any) -> Any:
    default_call = _DEFAULT_CALL.match(name)
    if default_call:
        fallback = _parse_default_argument(default_call.group(1))
        return fallback if value is _MISSING or value is None else value
    value = None if value is _MISSING else value
    match name:
        case "lower":
            return value.lower() if isinstance(value, str) else value
        case "upper":
            return value.upper() if isinstance(value, str) else value
        case "json":
            return json.dumps(value)
        case _:
            raise ValueError(f"unsupported filter {name!r}")


def _evaluate(expression: str, context: dict) -> Any:
    parts = [part.strip() for part in expression.split("|")]
    value = _lookup(parts[0], context)
    for filter_name in parts[1:]:
        value = _apply_filter(filter_name, value)
    return None if value is _MISSING else value


def resolve_value(template: Any, context: dict) -> Any:
    """Resolve one config value. Non-strings pass through untouched.

    A string that is exactly one expression keeps the resolved value's type,
    so an If node can compare numbers as numbers. The single-expression test
    is a span check rather than an anchored regex: `^\\s*\\{\\{(.+?)\\}\\}\\s*$`
    matches "{{a}} {{b}}" as one expression with the path `a}} {{b`.
    """
    if not isinstance(template, str):
        return template
    stripped = template.strip()
    matches = list(_EXPRESSION.finditer(stripped))
    if len(matches) == 1 and matches[0].span() == (0, len(stripped)):
        return _evaluate(matches[0].group(1), context)

    def _replace(match: re.Match[str]) -> str:
        resolved = _evaluate(match.group(1), context)
        return "" if resolved is None else str(resolved)

    return _EXPRESSION.sub(_replace, template)


def resolve_config(config: Any, context: dict) -> Any:
    """Recursively resolve every string in a node's configuration."""
    match config:
        case dict():
            return {key: resolve_config(value, context) for key, value in config.items()}
        case list():
            return [resolve_config(item, context) for item in config]
        case _:
            return resolve_value(config, context)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/server-api/test_soar_expressions.py -v`
Expected: PASS, 15 tests.

- [ ] **Step 5: Commit**

```bash
git add server-api/app/services/soar_expressions.py tests/server-api/test_soar_expressions.py
git commit -m "feat(soar): add restricted dotted-path expression resolver"
```

---

### Task 3: Node registry and type contract

**Files:**
- Create: `server-api/app/services/soar_nodes/base.py`
- Create: `server-api/app/services/soar_nodes/__init__.py`
- Test: `tests/server-api/test_soar_registry.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `NodeContext(run_id, node_id, group_id, trigger, nodes, vars)` — frozen dataclass; `as_dict()` returns the resolver context.
  - `NodeResult(output: dict, handle: str = "out", wait: bool = False)`
  - `NodeType(node_type, label, category, config_schema, handler, handles, is_destructive)`
  - `register(node_type)`, `get_node_type(name)`, `catalogue()`, `clear_registry()`
  - Task 4 registers into it; Tasks 5 and 6 read from it.

- [ ] **Step 1: Write the failing tests**

Create `tests/server-api/test_soar_registry.py`:

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/server-api/test_soar_registry.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.services.soar_nodes'`

- [ ] **Step 3: Implement the types**

Create `server-api/app/services/soar_nodes/base.py`:

```python
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(frozen=True, slots=True)
class NodeContext:
    """Everything a node may read. Deliberately not the ORM session's world:
    a node sees resolved data, not arbitrary database reach."""
    run_id: uuid.UUID
    node_id: uuid.UUID
    group_id: str
    trigger: dict[str, Any] = field(default_factory=dict)
    nodes: dict[str, Any] = field(default_factory=dict)
    vars: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"trigger": self.trigger, "nodes": self.nodes, "vars": self.vars}


@dataclass(frozen=True, slots=True)
class NodeResult:
    output: dict[str, Any]
    handle: str = "out"
    wait: bool = False


NodeHandler = Callable[[AsyncSession, NodeContext, dict[str, Any]], Awaitable[NodeResult]]


@dataclass(frozen=True, slots=True)
class NodeType:
    node_type: str
    label: str
    category: str
    config_schema: dict[str, Any]
    handler: NodeHandler
    handles: tuple[str, ...] = ("out",)
    is_destructive: bool = False
```

- [ ] **Step 4: Implement the registry**

Create `server-api/app/services/soar_nodes/__init__.py`:

```python
"""Registry of SOAR node types.

Adding a node is one module plus one `register()` call: the API serves the
catalogue and the frontend renders each node's configuration form from its
JSON Schema, so no frontend change is needed for a new node.
"""
from __future__ import annotations

from typing import Any

from app.services.soar_nodes.base import (
    NodeContext,
    NodeHandler,
    NodeResult,
    NodeType,
)

_REGISTRY: dict[str, NodeType] = {}

__all__ = [
    "NodeContext",
    "NodeHandler",
    "NodeResult",
    "NodeType",
    "catalogue",
    "clear_registry",
    "get_node_type",
    "register",
]


def register(node_type: NodeType) -> None:
    if node_type.node_type in _REGISTRY:
        raise ValueError(f"node type {node_type.node_type!r} already registered")
    _REGISTRY[node_type.node_type] = node_type


def get_node_type(name: str) -> NodeType:
    try:
        return _REGISTRY[name]
    except KeyError as error:
        raise KeyError(f"unknown node type {name!r}") from error


def clear_registry() -> None:
    """Test seam. Production never calls this."""
    _REGISTRY.clear()


def catalogue() -> list[dict[str, Any]]:
    entries = [
        {
            "node_type": node.node_type,
            "label": node.label,
            "category": node.category,
            "config_schema": node.config_schema,
            "handles": list(node.handles),
            "is_destructive": node.is_destructive,
        }
        for node in _REGISTRY.values()
    ]
    return sorted(entries, key=lambda entry: (entry["category"], entry["node_type"]))
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python -m pytest tests/server-api/test_soar_registry.py -v`
Expected: PASS, 7 tests.

- [ ] **Step 6: Commit**

```bash
git add server-api/app/services/soar_nodes/ tests/server-api/test_soar_registry.py
git commit -m "feat(soar): add node type registry and node contract"
```

---

### Task 4: The six built-in nodes

**Files:**
- Create: `server-api/app/services/soar_nodes/builtin.py`
- Test: `tests/server-api/test_soar_nodes.py`

**Interfaces:**
- Consumes: `NodeContext`, `NodeResult`, `NodeType`, `register` from Task 3; `resolve_config` from Task 2; `build_step_record`, `StepPreparation` from `app.services.soar_service`.
- Produces: six registered node types — `alert_trigger`, `if`, `create_case`, `add_note`, `block_ip`, `isolate_agent` — plus `register_builtin_nodes()`, called once at startup by Task 8.

The two destructive nodes create a `SoarRunStep` through `build_step_record` and return `NodeResult(wait=True)`. They never call `execute_approved_step`; the live `POST /api/soar/executions/{id}/approve` route does that.

- [ ] **Step 1: Write the failing tests**

Create `tests/server-api/test_soar_nodes.py`:

```python
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
    step = db.added[0]
    assert result.wait is True
    assert step.status == "pending_approval"
    assert step.is_reversible is True


@pytest.mark.asyncio
async def test_destructive_nodes_are_flagged_in_the_registry():
    assert get_node_type("block_ip").is_destructive is True
    assert get_node_type("isolate_agent").is_destructive is True
    assert get_node_type("create_case").is_destructive is False
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/server-api/test_soar_nodes.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.services.soar_nodes.builtin'`

- [ ] **Step 3: Implement the nodes**

Create `server-api/app/services/soar_nodes/builtin.py`:

```python
"""The six node types of engine-core slice 1.

Destructive nodes (block_ip, isolate_agent) deliberately only *prepare* a
step and park the run. Execution belongs to the already-live approve route,
so approval, idempotency, and rollback keep their single implementation in
soar_service.py.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import Case, CaseNote
from app.services.soar_expressions import resolve_config
from app.services.soar_nodes import NodeContext, NodeResult, NodeType, register
from app.services.soar_service import StepPreparation, build_step_record

_SEVERITIES = ["info", "low", "medium", "high", "critical"]


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _alert_trigger(db: AsyncSession, context: NodeContext, config: dict) -> NodeResult:
    return NodeResult(output={"alert": context.trigger.get("alert", {})})


def _compare(left: Any, operator: str, right: Any) -> bool:
    match operator:
        case "eq":
            return left == right
        case "ne":
            return left != right
        case "gt":
            return float(left) > float(right)
        case "gte":
            return float(left) >= float(right)
        case "lt":
            return float(left) < float(right)
        case "lte":
            return float(left) <= float(right)
        case "contains":
            return right in (left or [])
        case _:
            raise ValueError(f"unsupported operator {operator!r}")


async def _if_node(db: AsyncSession, context: NodeContext, config: dict) -> NodeResult:
    resolved = resolve_config(config, context.as_dict())
    matched = _compare(resolved.get("left"), resolved.get("operator", "eq"), resolved.get("right"))
    return NodeResult(output={"matched": matched}, handle="true" if matched else "false")


async def _create_case(db: AsyncSession, context: NodeContext, config: dict) -> NodeResult:
    resolved = resolve_config(config, context.as_dict())
    severity = resolved.get("severity", "medium")
    if severity not in _SEVERITIES:
        raise ValueError(f"invalid severity {severity!r}")
    case = Case(
        id=uuid.uuid4(),
        title=resolved.get("title") or "SOAR case",
        description=resolved.get("description"),
        severity=severity,
        status="open",
        created_by_ai=False,
        group_id=context.group_id,
    )
    db.add(case)
    await db.flush()
    return NodeResult(output={"case_id": str(case.id)})


async def _add_note(db: AsyncSession, context: NodeContext, config: dict) -> NodeResult:
    resolved = resolve_config(config, context.as_dict())
    raw_case_id = resolved.get("case_id")
    if not isinstance(raw_case_id, str) or not raw_case_id:
        raise ValueError("add_note requires a case_id")
    note = CaseNote(
        id=uuid.uuid4(),
        case_id=uuid.UUID(raw_case_id),
        author_id=None,
        content=resolved.get("content") or "",
        is_ai_generated=False,
    )
    db.add(note)
    return NodeResult(output={"case_id": raw_case_id})


def _prepare_destructive(
    db: AsyncSession,
    context: NodeContext,
    action_type: str,
    payload: dict[str, Any],
) -> NodeResult:
    preparation = StepPreparation(
        run_id=context.run_id,
        node_id=context.node_id,
        action_type=action_type,
        input_payload=payload,
        idempotency_key=f"{context.run_id}:{context.node_id}:{action_type}",
        started_at=_now(),
    )
    step = build_step_record(preparation)
    db.add(step)
    return NodeResult(output={"step_id": str(step.id), "awaiting_approval": True}, wait=True)


async def _block_ip(db: AsyncSession, context: NodeContext, config: dict) -> NodeResult:
    resolved = resolve_config(config, context.as_dict())
    ip = resolved.get("ip")
    agent_id = resolved.get("agent_id")
    if not isinstance(ip, str) or not isinstance(agent_id, str):
        raise ValueError("block_ip requires ip and agent_id")
    payload: dict[str, Any] = {"ip": ip, "agent_id": agent_id}
    duration = resolved.get("duration_seconds")
    if isinstance(duration, int):
        payload["duration_seconds"] = duration
    return _prepare_destructive(db, context, "block_ip", payload)


async def _isolate_agent(db: AsyncSession, context: NodeContext, config: dict) -> NodeResult:
    resolved = resolve_config(config, context.as_dict())
    agent_id = resolved.get("agent_id")
    if not isinstance(agent_id, str):
        raise ValueError("isolate_agent requires agent_id")
    return _prepare_destructive(db, context, "isolate_agent", {"agent_id": agent_id})


_STRING = {"type": "string"}

_BUILTIN = [
    NodeType(
        node_type="alert_trigger",
        label="Alert Trigger",
        category="trigger",
        config_schema={
            "type": "object",
            "properties": {
                "severities": {"type": "array", "items": {"enum": _SEVERITIES}},
                "title_contains": _STRING,
            },
        },
        handler=_alert_trigger,
    ),
    NodeType(
        node_type="if",
        label="If",
        category="logic",
        config_schema={
            "type": "object",
            "required": ["left", "operator"],
            "properties": {
                "left": _STRING,
                "operator": {"enum": ["eq", "ne", "gt", "gte", "lt", "lte", "contains"]},
                "right": {},
            },
        },
        handler=_if_node,
        handles=("true", "false"),
    ),
    NodeType(
        node_type="create_case",
        label="Create Case",
        category="action",
        config_schema={
            "type": "object",
            "required": ["title"],
            "properties": {
                "title": _STRING,
                "description": _STRING,
                "severity": {"enum": _SEVERITIES},
            },
        },
        handler=_create_case,
    ),
    NodeType(
        node_type="add_note",
        label="Add Note",
        category="action",
        config_schema={
            "type": "object",
            "required": ["case_id", "content"],
            "properties": {"case_id": _STRING, "content": _STRING},
        },
        handler=_add_note,
    ),
    NodeType(
        node_type="block_ip",
        label="Block IP",
        category="response",
        config_schema={
            "type": "object",
            "required": ["ip", "agent_id"],
            "properties": {
                "ip": _STRING,
                "agent_id": _STRING,
                "duration_seconds": {"type": "integer", "minimum": 60},
            },
        },
        handler=_block_ip,
        is_destructive=True,
    ),
    NodeType(
        node_type="isolate_agent",
        label="Isolate Host",
        category="response",
        config_schema={
            "type": "object",
            "required": ["agent_id"],
            "properties": {"agent_id": _STRING},
        },
        handler=_isolate_agent,
        is_destructive=True,
    ),
]


def register_builtin_nodes() -> None:
    for node_type in _BUILTIN:
        register(node_type)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/server-api/test_soar_nodes.py -v`
Expected: PASS, 13 tests.

- [ ] **Step 5: Commit**

```bash
git add server-api/app/services/soar_nodes/builtin.py tests/server-api/test_soar_nodes.py
git commit -m "feat(soar): add the six built-in workflow nodes"
```

---

### Task 5: Graph snapshot and traversal

**Files:**
- Create: `server-api/app/services/soar_executor.py`
- Test: `tests/server-api/test_soar_traversal.py`

**Interfaces:**
- Consumes: Task 1's columns; Task 3's registry.
- Produces, all pure and database-free:
  - `build_snapshot(nodes, edges) -> dict` — `nodes` and `edges` are ORM rows or any objects with the same attributes.
  - `find_entry_node_id(snapshot) -> str | None`
  - `next_node_ids(snapshot, node_id, handle) -> list[str]`
  - `advance_frontier(snapshot, node_id, handle, pending) -> tuple[str | None, list[str]]`
  - `validate_acyclic(snapshot) -> None` (raises `CyclicWorkflowError`)
  - Task 6 imports `build_snapshot` and `validate_acyclic`; Task 8 imports the rest.

- [ ] **Step 1: Write the failing tests**

Create `tests/server-api/test_soar_traversal.py`:

```python
from types import SimpleNamespace

import pytest

from app.services.soar_executor import (
    CyclicWorkflowError,
    advance_frontier,
    build_snapshot,
    find_entry_node_id,
    next_node_ids,
    validate_acyclic,
)


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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/server-api/test_soar_traversal.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.services.soar_executor'`

- [ ] **Step 3: Implement snapshot and traversal**

Create `server-api/app/services/soar_executor.py`:

```python
"""Graph snapshot and traversal for the SOAR v2 executor.

The functions in this module are pure so they can be tested without a
database. A run executes against the snapshot taken when it started, never
the live tables, so editing a workflow cannot corrupt a run in flight or
make an old run unrenderable — see the design doc, section 5.2.
"""
from __future__ import annotations

from typing import Any, Iterable


class CyclicWorkflowError(ValueError):
    """A workflow graph contains a cycle. Phase 1 supports DAGs only."""


def build_snapshot(nodes: Iterable[Any], edges: Iterable[Any]) -> dict[str, Any]:
    return {
        "nodes": {
            str(node.id): {
                "id": str(node.id),
                "node_type": node.node_type,
                "name": node.name,
                "config": node.config or {},
                "pos_x": float(node.pos_x or 0),
                "pos_y": float(node.pos_y or 0),
            }
            for node in nodes
        },
        "edges": [
            {
                "source_node_id": str(edge.source_node_id),
                "source_handle": edge.source_handle,
                "target_node_id": str(edge.target_node_id),
            }
            for edge in edges
        ],
    }


def find_entry_node_id(snapshot: dict[str, Any]) -> str | None:
    targets = {edge["target_node_id"] for edge in snapshot["edges"]}
    for node_id in snapshot["nodes"]:
        if node_id not in targets:
            return node_id
    return None


def next_node_ids(snapshot: dict[str, Any], node_id: str, handle: str) -> list[str]:
    return [
        edge["target_node_id"]
        for edge in snapshot["edges"]
        if edge["source_node_id"] == node_id and edge["source_handle"] == handle
    ]


def advance_frontier(
    snapshot: dict[str, Any],
    node_id: str,
    handle: str,
    pending: list[str],
) -> tuple[str | None, list[str]]:
    """Pick the next node and the frontier that remains after it.

    Fan-out is depth-first and sequential: the first successor becomes
    current, the rest wait ahead of whatever was already pending. A single
    active path is all `soar_runs.current_node_id` can represent, so true
    parallel branches are out of scope (design doc, section 5.3).
    """
    successors = next_node_ids(snapshot, node_id, handle)
    queue = [*successors, *pending]
    if not queue:
        return None, []
    return queue[0], queue[1:]


def validate_acyclic(snapshot: dict[str, Any]) -> None:
    adjacency: dict[str, list[str]] = {node_id: [] for node_id in snapshot["nodes"]}
    for edge in snapshot["edges"]:
        adjacency.setdefault(edge["source_node_id"], []).append(edge["target_node_id"])

    visiting: set[str] = set()
    visited: set[str] = set()

    def walk(node_id: str) -> None:
        if node_id in visiting:
            raise CyclicWorkflowError(f"cycle through node {node_id}")
        if node_id in visited:
            return
        visiting.add(node_id)
        for target in adjacency.get(node_id, []):
            walk(target)
        visiting.discard(node_id)
        visited.add(node_id)

    for node_id in list(adjacency):
        walk(node_id)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/server-api/test_soar_traversal.py -v`
Expected: PASS, 14 tests.

- [ ] **Step 5: Commit**

```bash
git add server-api/app/services/soar_executor.py tests/server-api/test_soar_traversal.py
git commit -m "feat(soar): add graph snapshot and DAG traversal"
```

---

### Task 6: Step execution and the claiming loop

**Files:**
- Modify: `server-api/app/services/soar_executor.py`

**Interfaces:**
- Consumes: Tasks 2, 3, 4, 5; `SoarRun`, `SoarNode`, `SoarEdge`, `SoarRunStep` models; `AsyncSessionLocal`.
- Produces: `start_run(db, workflow, trigger_type, trigger_ref) -> SoarRun`, `claim_runnable_run(db) -> SoarRun | None`, `execute_one_step(db, run) -> bool`, `executor_tick() -> bool`, `soar_executor_loop() -> None`. Task 8 calls `start_run` and `soar_executor_loop`.

This task has no unit tests: every function is a thin wrapper over database I/O whose logic was already tested in Task 5. It is verified by the manual check in Step 4.

- [ ] **Step 1: Add the imports and run creation**

Append to `server-api/app/services/soar_executor.py`:

```python
import asyncio
import uuid
from datetime import datetime, timezone

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import AsyncSessionLocal
from app.models.models import PlatformSetting, SoarEdge, SoarNode, SoarRun, SoarRunStep
from app.services.soar_nodes import NodeContext, get_node_type
from app.services.soar_service import input_hash

log = structlog.get_logger()

POLL_INTERVAL_SECONDS = 5
MAX_STEPS_PER_RUN = 200


async def start_run(
    db: AsyncSession,
    workflow,
    trigger_type: str,
    trigger_ref: dict[str, Any],
) -> SoarRun:
    """Snapshot the workflow and queue a run at its entry node."""
    nodes = (await db.execute(
        select(SoarNode).where(SoarNode.workflow_id == workflow.id)
    )).scalars().all()
    edges = (await db.execute(
        select(SoarEdge).where(SoarEdge.workflow_id == workflow.id)
    )).scalars().all()
    snapshot = build_snapshot(nodes, edges)
    validate_acyclic(snapshot)
    entry_node_id = find_entry_node_id(snapshot)
    if entry_node_id is None:
        raise ValueError(f"workflow {workflow.id} has no entry node")
    run = SoarRun(
        id=uuid.uuid4(),
        workflow_id=workflow.id,
        status="pending",
        trigger_type=trigger_type,
        trigger_ref=trigger_ref,
        current_node_id=uuid.UUID(entry_node_id),
        variables={},
        graph_snapshot=snapshot,
        pending_node_ids=[],
        group_id=workflow.group_id,
    )
    db.add(run)
    return run
```

- [ ] **Step 2: Add claiming**

Append:

```python
async def claim_runnable_run(db: AsyncSession) -> SoarRun | None:
    """Claim one run for this replica.

    Both server-api replicas run this loop, so the row lock is a
    correctness requirement: without SKIP LOCKED two replicas could execute
    the same node twice (design doc, section 5.1).
    """
    now = datetime.now(timezone.utc)
    query = (
        select(SoarRun)
        .where(
            SoarRun.status.in_(["pending", "running"])
            | ((SoarRun.status == "waiting") & (SoarRun.resume_at != None) & (SoarRun.resume_at <= now))
        )
        .order_by(SoarRun.started_at)
        .limit(1)
        .with_for_update(skip_locked=True)
    )
    return (await db.execute(query)).scalars().first()
```

- [ ] **Step 3: Add step execution and the loop**

Append:

```python
async def _build_context(db: AsyncSession, run: SoarRun, node_id: uuid.UUID) -> NodeContext:
    steps = (await db.execute(
        select(SoarRunStep).where(SoarRunStep.run_id == run.id)
    )).scalars().all()
    snapshot_nodes = run.graph_snapshot["nodes"]
    outputs: dict[str, Any] = {}
    for step in steps:
        node = snapshot_nodes.get(str(step.node_id))
        if node is not None and step.output is not None:
            outputs[node["name"]] = {"output": step.output}
    return NodeContext(
        run_id=run.id,
        node_id=node_id,
        group_id=run.group_id,
        trigger=run.trigger_ref or {},
        nodes=outputs,
        vars=run.variables or {},
    )


async def execute_one_step(db: AsyncSession, run: SoarRun) -> bool:
    """Execute exactly one node. Returns True if the run is still active."""
    if run.current_node_id is None:
        run.status = "succeeded"
        run.finished_at = datetime.now(timezone.utc)
        return False

    node_id = run.current_node_id
    node = run.graph_snapshot["nodes"].get(str(node_id))
    if node is None:
        run.status = "failed"
        run.finished_at = datetime.now(timezone.utc)
        log.error("soar_node_missing_from_snapshot", run_id=str(run.id), node_id=str(node_id))
        return False

    executed = (await db.execute(
        select(SoarRunStep).where(SoarRunStep.run_id == run.id)
    )).scalars().all()
    if len(executed) >= MAX_STEPS_PER_RUN:
        run.status = "failed"
        run.finished_at = datetime.now(timezone.utc)
        log.error("soar_run_step_ceiling", run_id=str(run.id))
        return False

    run.status = "running"
    context = await _build_context(db, run, node_id)
    started_at = datetime.now(timezone.utc)
    try:
        node_type = get_node_type(node["node_type"])
        result = await node_type.handler(db, context, node["config"])
    except Exception as exc:
        db.add(SoarRunStep(
            id=uuid.uuid4(), run_id=run.id, node_id=node_id,
            action_type=node["node_type"], status="failed",
            is_destructive=False, is_reversible=False,
            idempotency_key=f"{run.id}:{node_id}:error",
            input_hash=input_hash({}), input={}, error=str(exc),
            started_at=started_at, finished_at=datetime.now(timezone.utc),
        ))
        run.status = "failed"
        run.finished_at = datetime.now(timezone.utc)
        log.error("soar_node_failed", run_id=str(run.id), node=node["name"], error=str(exc))
        return False

    if not node_type.is_destructive:
        db.add(SoarRunStep(
            id=uuid.uuid4(), run_id=run.id, node_id=node_id,
            action_type=node["node_type"], status="succeeded",
            is_destructive=False, is_reversible=False,
            idempotency_key=f"{run.id}:{node_id}",
            input_hash=input_hash(node["config"]), input=node["config"],
            output=result.output,
            started_at=started_at, finished_at=datetime.now(timezone.utc),
        ))

    if result.wait:
        run.status = "waiting"
        return False

    current, pending = advance_frontier(
        run.graph_snapshot, str(node_id), result.handle, list(run.pending_node_ids or [])
    )
    run.current_node_id = uuid.UUID(current) if current else None
    run.pending_node_ids = pending
    if current is None:
        run.status = "succeeded"
        run.finished_at = datetime.now(timezone.utc)
        return False
    return True


async def _enabled(db: AsyncSession) -> bool:
    row = await db.get(PlatformSetting, "soar_v2_enabled")
    return bool(row and row.value.lower() == "true")


async def executor_tick() -> bool:
    """One claim-and-execute cycle. Returns True if work was done."""
    async with AsyncSessionLocal() as db:
        async with db.begin():
            if not await _enabled(db):
                return False
            run = await claim_runnable_run(db)
            if run is None:
                return False
            await execute_one_step(db, run)
            return True


async def soar_executor_loop() -> None:
    while True:
        try:
            did_work = await executor_tick()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.error("soar_executor_tick_failed", error=str(exc))
            did_work = False
        if not did_work:
            await asyncio.sleep(POLL_INTERVAL_SECONDS)
```

- [ ] **Step 4: Verify the module parses and the pure tests still pass**

Run: `python -c "import ast;ast.parse(open('server-api/app/services/soar_executor.py').read())" && python -m pytest tests/server-api/test_soar_traversal.py -v`
Expected: no parse output; 14 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add server-api/app/services/soar_executor.py
git commit -m "feat(soar): add step executor with SKIP LOCKED run claiming"
```

---

### Task 7: Workflow CRUD and node-type catalogue API

**Files:**
- Create: `server-api/app/api/routes/soar_workflows.py`
- Modify: `server-api/app/api/routes/soar.py:13-14`
- Modify: `server-api/app/core/permission_matrix.py`

**Interfaces:**
- Consumes: `build_snapshot`, `validate_acyclic`, `CyclicWorkflowError` from Task 5; `catalogue` from Task 3.
- Produces: routes under `/api/soar` — `GET /node-types`, `GET|POST /workflows`, `GET|PUT|DELETE /workflows/{id}`. Task 8 relies on none of them; the canvas slice consumes all of them.

Saving a workflow replaces its whole node and edge set in one request, which is what a canvas edit is. In-flight runs are unaffected because they execute from their snapshot.

- [ ] **Step 1: Write the routes**

Create `server-api/app/api/routes/soar_workflows.py`:

```python
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group
from app.models.models import SoarEdge, SoarNode, SoarWorkflow, User
from app.services.soar_executor import CyclicWorkflowError, build_snapshot, validate_acyclic
from app.services.soar_nodes import catalogue

router = APIRouter()


class NodeIn(BaseModel):
    id: Optional[uuid.UUID] = None
    node_type: str
    name: str
    config: dict = {}
    pos_x: float = 0
    pos_y: float = 0


class EdgeIn(BaseModel):
    source_node_id: uuid.UUID
    source_handle: str = "out"
    target_node_id: uuid.UUID


class WorkflowIn(BaseModel):
    name: str
    description: Optional[str] = None
    is_enabled: bool = True
    nodes: list[NodeIn] = []
    edges: list[EdgeIn] = []


def _workflow_out(workflow: SoarWorkflow, nodes: list[SoarNode], edges: list[SoarEdge]) -> dict:
    return {
        "id": str(workflow.id),
        "name": workflow.name,
        "description": workflow.description,
        "is_enabled": workflow.is_enabled,
        "nodes": [
            {
                "id": str(n.id), "node_type": n.node_type, "name": n.name,
                "config": n.config, "pos_x": n.pos_x, "pos_y": n.pos_y,
            }
            for n in nodes
        ],
        "edges": [
            {
                "id": str(e.id), "source_node_id": str(e.source_node_id),
                "source_handle": e.source_handle, "target_node_id": str(e.target_node_id),
            }
            for e in edges
        ],
    }


async def _load_graph(db: AsyncSession, workflow_id: uuid.UUID):
    nodes = (await db.execute(
        select(SoarNode).where(SoarNode.workflow_id == workflow_id)
    )).scalars().all()
    edges = (await db.execute(
        select(SoarEdge).where(SoarEdge.workflow_id == workflow_id)
    )).scalars().all()
    return nodes, edges


async def _require_workflow(db: AsyncSession, workflow_id: uuid.UUID, group_id: Optional[str]):
    workflow = await db.get(SoarWorkflow, workflow_id)
    if workflow is None or (group_id and workflow.group_id != group_id):
        raise HTTPException(status_code=404, detail="Workflow not found")
    return workflow


async def _replace_graph(db: AsyncSession, workflow: SoarWorkflow, body: WorkflowIn) -> None:
    """Rewrite the whole graph, rejecting cycles before anything is persisted."""
    id_map = {node.id or uuid.uuid4(): node for node in body.nodes}
    staged_nodes = [
        SoarNode(
            id=node_id, workflow_id=workflow.id, node_type=node.node_type,
            name=node.name, config=node.config, pos_x=node.pos_x, pos_y=node.pos_y,
        )
        for node_id, node in id_map.items()
    ]
    staged_edges = [
        SoarEdge(
            id=uuid.uuid4(), workflow_id=workflow.id,
            source_node_id=edge.source_node_id, source_handle=edge.source_handle,
            target_node_id=edge.target_node_id,
        )
        for edge in body.edges
    ]
    try:
        validate_acyclic(build_snapshot(staged_nodes, staged_edges))
    except CyclicWorkflowError as error:
        raise HTTPException(status_code=422, detail=f"Workflow graph must be acyclic: {error}")

    await db.execute(delete(SoarEdge).where(SoarEdge.workflow_id == workflow.id))
    await db.execute(delete(SoarNode).where(SoarNode.workflow_id == workflow.id))
    for node in staged_nodes:
        db.add(node)
    for edge in staged_edges:
        db.add(edge)


@router.get("/node-types")
async def list_node_types(_: User = Depends(get_current_user)):
    return catalogue()


@router.get("/workflows")
async def list_workflows(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_id: Optional[str] = Depends(get_scoped_group),
):
    query = select(SoarWorkflow)
    if group_id:
        query = query.where(SoarWorkflow.group_id == group_id)
    workflows = (await db.execute(query.order_by(SoarWorkflow.created_at.desc()))).scalars().all()
    return [
        {
            "id": str(w.id), "name": w.name, "description": w.description,
            "is_enabled": w.is_enabled,
        }
        for w in workflows
    ]


@router.post("/workflows", status_code=201)
async def create_workflow(
    body: WorkflowIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_id: Optional[str] = Depends(get_scoped_group),
):
    workflow = SoarWorkflow(
        id=uuid.uuid4(), name=body.name, description=body.description,
        is_enabled=body.is_enabled,
        group_id=group_id or current_user.group_id or "default",
    )
    db.add(workflow)
    await db.flush()
    await _replace_graph(db, workflow, body)
    await db.commit()
    nodes, edges = await _load_graph(db, workflow.id)
    return _workflow_out(workflow, nodes, edges)


@router.get("/workflows/{workflow_id}")
async def get_workflow(
    workflow_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_id: Optional[str] = Depends(get_scoped_group),
):
    workflow = await _require_workflow(db, workflow_id, group_id)
    nodes, edges = await _load_graph(db, workflow.id)
    return _workflow_out(workflow, nodes, edges)


@router.put("/workflows/{workflow_id}")
async def update_workflow(
    workflow_id: uuid.UUID,
    body: WorkflowIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_id: Optional[str] = Depends(get_scoped_group),
):
    workflow = await _require_workflow(db, workflow_id, group_id)
    workflow.name = body.name
    workflow.description = body.description
    workflow.is_enabled = body.is_enabled
    await _replace_graph(db, workflow, body)
    await db.commit()
    nodes, edges = await _load_graph(db, workflow.id)
    return _workflow_out(workflow, nodes, edges)


@router.delete("/workflows/{workflow_id}", status_code=204)
async def delete_workflow(
    workflow_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_id: Optional[str] = Depends(get_scoped_group),
):
    workflow = await _require_workflow(db, workflow_id, group_id)
    await db.delete(workflow)
    await db.commit()
```

- [ ] **Step 2: Mount the router**

In `server-api/app/api/routes/soar.py`, after the existing execution-router import and include (lines 11 and 14):

```python
from app.api.routes.soar_workflows import router as workflow_router
```

and below `router.include_router(execution_router)`:

```python
router.include_router(workflow_router)
```

- [ ] **Step 3: Register the routes in the permission matrix**

In `server-api/app/core/permission_matrix.py`, beside the existing `"GET /api/soar/executions"` entries:

```python
    "GET /api/soar/node-types": RouteAccess.AUTHENTICATED,
    "GET /api/soar/workflows": RouteAccess.AUTHENTICATED,
    "POST /api/soar/workflows": RouteAccess.AUTHENTICATED,
    "GET /api/soar/workflows/{workflow_id}": RouteAccess.AUTHENTICATED,
    "PUT /api/soar/workflows/{workflow_id}": RouteAccess.AUTHENTICATED,
    "DELETE /api/soar/workflows/{workflow_id}": RouteAccess.AUTHENTICATED,
```

- [ ] **Step 4: Verify the modules parse**

Run: `python -c "import ast;[ast.parse(open(p).read()) for p in ['server-api/app/api/routes/soar_workflows.py','server-api/app/api/routes/soar.py','server-api/app/core/permission_matrix.py']]"`
Expected: no output, exit code 0.

- [ ] **Step 5: Commit**

```bash
git add server-api/app/api/routes/soar_workflows.py server-api/app/api/routes/soar.py server-api/app/core/permission_matrix.py
git commit -m "feat(soar): add workflow CRUD and node-type catalogue routes"
```

---

### Task 8: Alert trigger bridge and startup wiring

**Files:**
- Modify: `worker/worker/ai_analyst.py` (beside the existing `run_soar_playbooks` dispatch)
- Modify: `server-api/app/main.py` (lifespan)
- Create: `server-api/app/services/soar_triggers.py`

**Interfaces:**
- Consumes: `start_run` and `soar_executor_loop` from Task 6; `register_builtin_nodes` from Task 4.
- Produces: `soar_trigger_consumer_loop()`, started from `lifespan`.

The worker publishes; server-api decides. Trigger matching reads workflow definitions, which only server-api has models for, so no SOAR model is duplicated into the worker (spec §5.6).

- [ ] **Step 1: Publish alert ids from the worker**

In `worker/worker/ai_analyst.py`, immediately after the existing `run_soar_playbooks` dispatch block, add:

```python
    # v2 workflow engine lives in server-api (separate build context), so the
    # hand-off is a Redis queue, matching the siem:ai-analysis pattern.
    try:
        _trigger_redis = await get_redis()
        await _trigger_redis.lpush("siem:soar-triggers", json.dumps({
            "alert_id": alert_id,
            "group_id": group_id,
            "severity": effective_severity,
            "title": title,
            "source_ip": source_ip,
            "hostname": hostname,
        }))
    except Exception as exc:
        log.warning("soar_trigger_publish_failed", alert_id=alert_id, error=str(exc))
```

- [ ] **Step 2: Write the consumer**

Create `server-api/app/services/soar_triggers.py`:

```python
"""Consumes alert notifications published by the worker and starts runs."""
from __future__ import annotations

import asyncio
import json
from typing import Any

import structlog
from sqlalchemy import select

from app.core.database import AsyncSessionLocal
from app.core.redis_client import get_redis
from app.models.models import PlatformSetting, SoarNode, SoarWorkflow
from app.services.soar_executor import start_run

log = structlog.get_logger()

TRIGGER_QUEUE = "siem:soar-triggers"
_BLOCK_SECONDS = 5


def trigger_matches(config: dict[str, Any], event: dict[str, Any]) -> bool:
    severities = config.get("severities")
    if severities and event.get("severity") not in severities:
        return False
    needle = config.get("title_contains")
    if needle and needle.lower() not in (event.get("title") or "").lower():
        return False
    return True


async def _dispatch(event: dict[str, Any]) -> None:
    async with AsyncSessionLocal() as db:
        async with db.begin():
            setting = await db.get(PlatformSetting, "soar_v2_enabled")
            if not (setting and setting.value.lower() == "true"):
                return
            workflows = (await db.execute(
                select(SoarWorkflow).where(
                    SoarWorkflow.is_enabled == True,
                    SoarWorkflow.group_id == event.get("group_id", "default"),
                )
            )).scalars().all()
            for workflow in workflows:
                triggers = (await db.execute(
                    select(SoarNode).where(
                        SoarNode.workflow_id == workflow.id,
                        SoarNode.node_type == "alert_trigger",
                    )
                )).scalars().all()
                if not any(trigger_matches(t.config or {}, event) for t in triggers):
                    continue
                await start_run(db, workflow, "alert", {"alert": event})
                log.info("soar_run_started", workflow_id=str(workflow.id),
                         alert_id=event.get("alert_id"))


async def soar_trigger_consumer_loop() -> None:
    redis = await get_redis()
    while True:
        try:
            popped = await redis.brpop(TRIGGER_QUEUE, timeout=_BLOCK_SECONDS)
            if popped is None:
                continue
            await _dispatch(json.loads(popped[1]))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.error("soar_trigger_consumer_failed", error=str(exc))
            await asyncio.sleep(_BLOCK_SECONDS)
```

- [ ] **Step 3: Wire both loops into `lifespan`**

In `server-api/app/main.py`, replace the two existing lines that create and cancel `_listener_task`:

```python
    import asyncio
    from app.services.soar_executor import soar_executor_loop
    from app.services.soar_nodes.builtin import register_builtin_nodes
    from app.services.soar_triggers import soar_trigger_consumer_loop

    register_builtin_nodes()
    _listener_task = asyncio.create_task(_ws_redis_listener())
    _soar_tasks = [
        asyncio.create_task(soar_executor_loop()),
        asyncio.create_task(soar_trigger_consumer_loop()),
    ]
    yield
    _listener_task.cancel()
    for task in _soar_tasks:
        task.cancel()
```

- [ ] **Step 4: Write the trigger-matching tests**

Append to `tests/server-api/test_soar_nodes.py`:

```python
from app.services.soar_triggers import trigger_matches


def test_empty_trigger_config_matches_everything():
    assert trigger_matches({}, {"severity": "low", "title": "anything"}) is True


def test_severity_filter_excludes_other_severities():
    config = {"severities": ["critical", "high"]}
    assert trigger_matches(config, {"severity": "critical", "title": "x"}) is True
    assert trigger_matches(config, {"severity": "low", "title": "x"}) is False


def test_title_filter_is_case_insensitive():
    config = {"title_contains": "brute force"}
    assert trigger_matches(config, {"severity": "high", "title": "SSH Brute Force"}) is True
    assert trigger_matches(config, {"severity": "high", "title": "port scan"}) is False


def test_filters_combine_with_and():
    config = {"severities": ["critical"], "title_contains": "waf"}
    assert trigger_matches(config, {"severity": "critical", "title": "WAF block"}) is True
    assert trigger_matches(config, {"severity": "low", "title": "WAF block"}) is False
```

- [ ] **Step 5: Run the full plan's test suite**

Run: `python -m pytest tests/server-api/test_soar_expressions.py tests/server-api/test_soar_registry.py tests/server-api/test_soar_traversal.py tests/server-api/test_soar_nodes.py -v`
Expected: PASS, 53 tests (15 + 7 + 14 + 17).

- [ ] **Step 6: Commit**

```bash
git add worker/worker/ai_analyst.py server-api/app/services/soar_triggers.py server-api/app/main.py tests/server-api/test_soar_nodes.py
git commit -m "feat(soar): bridge alert triggers to the v2 executor over Redis"
```

---

## Verification

The slice is done when, with `soar_v2_enabled` set to `true` on a dev stack:

1. `GET /api/soar/node-types` returns six entries, with `block_ip` and `isolate_agent` flagged `is_destructive`.
2. `POST /api/soar/workflows` accepts a graph of Alert Trigger → If → Create Case → Add Note and rejects a cyclic one with 422.
3. An ingested critical alert produces a `soar_runs` row whose `graph_snapshot` is populated, and `soar_run_steps` rows carrying real `input` and `output`.
4. A workflow ending in Block IP leaves the run `waiting` and a step `pending_approval`, with no `AgentTask` created until `POST /api/soar/executions/{id}/approve` is called.
5. Editing the workflow mid-run does not change the in-flight run's behaviour.
6. **Concurrency**, which spec §11 requires but no unit test here can cover, because it needs a real PostgreSQL row lock: with both `server-api` replicas running, queue a workflow whose first node is Create Case and confirm exactly one `soar_run_steps` row appears per node — not two. Run it against the dev stack with `docker compose up -d --scale server-api=2`. If `SELECT ... FOR UPDATE SKIP LOCKED` were dropped from `claim_runnable_run`, this check is what would catch it.

Point 4 is the security-critical one: it proves the executor cannot take a destructive action on its own.
