# Post-commit verification: Task 2A

Commit checked: `d1dd227 feat(security): add OpenAPI permission inventory`.

## Permission inventory contract

Invocation:

```sh
docker compose run --rm --no-deps -w /workspace/server-api \
  -e PYTHONPATH=/workspace/server-api \
  -v "$PWD/server-api:/workspace/server-api:ro" \
  -v "$PWD/tests/server-api:/workspace/tests/server-api:ro" \
  -v "$PWD/db:/workspace/db:ro" server-api \
  pytest -q -p no:cacheprovider /workspace/tests/server-api/test_route_permission_matrix.py
```

Observed output: `2 passed, 2 warnings in 3.94s`.

Assessment: The checked-in matrix exactly matches the current generated OpenAPI operation set, explicitly identifies public operations, and contains only permissions seeded by `db/init.sql`.

Raw output: `postcommit-container-pytest.log`.

## Compile and lint

Compile invocation used the dependency-complete container with a writable temporary bytecode prefix.

Observed output: `compileall_exit=0`.

Raw output: `postcommit-compileall.log`.

Ruff invocation:

```sh
ruff check server-api/app/core/permission_matrix.py \
  tests/server-api/test_route_permission_matrix.py
```

Observed output: `All checks passed!`.

Raw output: `postcommit-ruff.log`.

## OpenAPI generation and live API QA

Source-container OpenAPI generation observed `openapi_operations=148` and `paths=110`.

Raw output: `postcommit-openapi-generation.log`.

Live server API invocation against `http://127.0.0.1:8000/openapi.json` observed `status=200 openapi_operations=148`.

Raw output: `postcommit-live-openapi-qa.log`.

## Commit scope

`git show --stat --oneline --summary d1dd227` confirms exactly three committed paths:

- `db/init.sql` (one seeded permission)
- `server-api/app/core/permission_matrix.py`
- `tests/server-api/test_route_permission_matrix.py`

The shared worktree still reports an unstaged `db/init.sql` modification that pre-dated Task 2A and was not included in the commit. Raw scope output: `postcommit-git-scope.log`.
