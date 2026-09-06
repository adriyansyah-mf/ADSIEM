from pathlib import Path

from app.main import app
from app.core.permission_matrix import (
    PUBLIC_OPERATIONS,
    ROUTE_PERMISSION_MATRIX,
    RouteAccess,
)


HTTP_METHODS = frozenset({"delete", "get", "head", "options", "patch", "post", "put", "trace"})
SEED_SQL_PATH = Path(__file__).parents[2] / "db" / "init.sql"


def _openapi_operation_keys() -> frozenset[str]:
    schema = app.openapi()
    return frozenset(
        f"{method.upper()} {path}"
        for path, path_item in schema["paths"].items()
        for method in path_item
        if method in HTTP_METHODS
    )


def _seeded_permission_names() -> frozenset[str]:
    seed_sql = SEED_SQL_PATH.read_text(encoding="utf-8")
    start = seed_sql.index("INSERT INTO permissions (name) VALUES")
    end = seed_sql.index(";", start)
    return frozenset(
        line.split("'")[1]
        for line in seed_sql[start:end].splitlines()
        if line.lstrip().startswith("('")
    ) | frozenset(
        line.split("'")[1]
        for line in seed_sql[end:].splitlines()
        if "INSERT INTO permissions (name) VALUES" in line
    )


def test_route_permission_matrix_covers_each_openapi_operation() -> None:
    # Given
    openapi_operations = _openapi_operation_keys()

    # When
    matrix_operations = frozenset(ROUTE_PERMISSION_MATRIX)

    # Then
    assert matrix_operations == openapi_operations
    assert PUBLIC_OPERATIONS == frozenset(
        operation
        for operation, access in ROUTE_PERMISSION_MATRIX.items()
        if access is RouteAccess.PUBLIC
    )


def test_route_permission_matrix_permissions_are_seeded() -> None:
    # Given
    seeded_permissions = _seeded_permission_names()

    # When
    declared_permissions = frozenset(
        access
        for access in ROUTE_PERMISSION_MATRIX.values()
        if isinstance(access, str)
    )

    # Then
    assert declared_permissions <= seeded_permissions
