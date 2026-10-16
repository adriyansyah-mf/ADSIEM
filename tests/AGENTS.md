# TESTS

**Multi-root and non-obvious.** There is no single test tree. Three independent layers, plus Go tests that live outside `tests/`.

```
tests/                        # pytest — service + e2e
├── conftest.py               # inserts server-api/ onto sys.path
├── test_siem_platform.service.e2e.test.py
├── server-api/               # conftest.py + test_auth, test_ingest, test_rbac, test_decoder_route
├── worker/                   # conftest.py + test_decoder_engine, test_sigma_engine, test_ueba_features, test_pipeline.int.test.py
├── dashboard/                # conftest.py + test_siem_platform.fixture.e2e.test.py  ← e2e fixture, NOT a unit test
└── agent/                    # Go: buffer_test.go, config_test.go, own go.mod
worker/tests/                 # pytest — test_rag.py, test_soar_engine.py (third layer)
```

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| pytest global config | `pytest.ini` | `--import-mode=importlib` (**required**), `asyncio_mode = auto` |
| sys.path bootstrap | root `conftest.py` | adds `server-api/` so `app.*` imports resolve |
| Per-suite fixtures | `tests/<suite>/conftest.py` | DB/Redis/ES wiring lives here, not in the root one |
| Go agent tests | `tests/agent/` | separate `go.mod`; run with `cd tests/agent && go test ./...` |
| Worker-only tests | `worker/tests/` | rag + soar; import `worker.*` package |

## CONVENTIONS

- **`asyncio_mode = auto`** — write `async def test_x(...)` with **no** `@pytest.mark.asyncio`.
- **`--import-mode=importlib` is mandatory** — test filenames contain dots (e.g. `test_siem_platform.fixture.e2e.test.py`); without it pytest tries to treat the dots as package separators and collection fails.
- **Place new tests by service**: server-api routes → `tests/server-api/`; worker engines → `tests/worker/`; worker-only modules (rag, soar) → `worker/tests/`.
- **Naming encodes intent**: `.int.test.py` = integration-style, `.fixture.e2e.test.py` = end-to-end fixture. Preserve the suffix.
- **Test discovery is by explicit path in practice** — run `pytest tests/server-api tests/worker`, `pytest worker/tests`; don't assume `pytest` picks up `tests/agent/` (that's Go).

## COMMANDS

```bash
pytest                                   # all Python suites
pytest tests/server-api tests/worker     # per-service
pytest worker/tests                      # worker extras
cd tests/agent && go test ./...          # Go agent (own module)
```

## ANTI-PATTERNS

- **Do not drop `--import-mode=importlib`** or the dotted e2e filenames stop collecting.
- **Do not add `@pytest.mark.asyncio`** — `asyncio_mode = auto` already applies it; the marker is noise here.
- **Do not treat `tests/dashboard/*.py` as unit tests** — they are pytest e2e fixtures that exercise the platform, not the React code. Dashboard has no JS unit runner; its gate is `npm run build`.
- **Do not rely on CI** — the only workflow is `.github/workflows/agent-release.yml`; nothing in CI runs pytest or the dashboard build.
- **Do not put a new suite at repo root** without a matching `conftest.py` — the root conftest only fixes `server-api` imports.
