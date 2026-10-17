import sys
from pathlib import Path

# Add server-api directory to Python path
server_api_path = Path(__file__).parent / "server-api"
if str(server_api_path) not in sys.path:
    sys.path.insert(0, str(server_api_path))

# server-api imports worker.sigma_engine (shared, not copied — see server-api/Dockerfile)
worker_path = Path(__file__).parent / "worker"
if str(worker_path) not in sys.path:
    sys.path.insert(0, str(worker_path))
