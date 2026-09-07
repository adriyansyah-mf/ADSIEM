import sys
from pathlib import Path

# Add server-api directory to Python path
server_api_path = Path(__file__).parent / "server-api"
if str(server_api_path) not in sys.path:
    sys.path.insert(0, str(server_api_path))

# Add worker/ to Python path too, and import the real `worker` package right
# now so it's cached in sys.modules before pytest's own conftest-loading path
# insertion for tests/worker/ (which is itself a package named "worker", with
# its own __init__.py) can shadow it. Without this, `import worker.<module>`
# inside tests/worker/*.py resolves to tests/worker/__init__.py instead of
# the real worker/worker/ package, failing with a misleading
# "No module named 'worker.<module>'" even though `worker` itself "exists".
worker_path = Path(__file__).parent / "worker"
if str(worker_path) not in sys.path:
    sys.path.insert(0, str(worker_path))
if "worker" not in sys.modules:
    try:
        import worker  # noqa: F401
    except ImportError:
        # worker/'s own dependencies (e.g. pgvector, fastembed) aren't
        # installed in every environment that runs this conftest (e.g. a
        # server-api-only test run) -- only worker-side tests need the
        # pre-import fix above; skip it gracefully everywhere else.
        pass
