"""A stand-in SIEM server for the Windows agent smoke test (tests/windows/smoke-msi.ps1).

Answers the agent's endpoints like server-api does and records what arrives:
<out>/enroll.json (the enrollment request) and <out>/logs.jsonl (one ingested
log per line). Stdlib only.

    python mock_siem.py <port> <out dir>
"""
import json
import os
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PORT, OUT = int(sys.argv[1]), Path(sys.argv[2])
OUT.mkdir(parents=True, exist_ok=True)
SOURCES = json.loads(os.environ.get("MOCK_SOURCES") or "null") or [
    {"path": "eventlog:Application", "log_type": "windows_application", "is_enabled": True},
    {"path": "eventlog:System", "log_type": "windows_system", "is_enabled": True},
]


class Handler(BaseHTTPRequestHandler):
    def _reply(self, code, body=None):
        data = json.dumps(body).encode() if body is not None else b""
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        try:
            payload = json.loads(body or b"{}")
        except ValueError:
            payload = {}
        path = self.path.split("?")[0]
        if path == "/api/agent/enroll":
            (OUT / "enroll.json").write_text(json.dumps(payload))
            return self._reply(201, {"agent_id": str(uuid.uuid4()), "agent_token": "mock-agent-token"})
        if self.headers.get("X-Agent-Token") != "mock-agent-token":
            return self._reply(401, {"detail": "Invalid agent token"})
        if path == "/api/ingest/heartbeat":
            return self._reply(200, {"config_hash": "mock", "log_sources": SOURCES, "fim_paths": [], "tasks": []})
        if path == "/api/ingest/log":
            with open(OUT / "logs.jsonl", "a") as fh:
                fh.write(json.dumps(payload) + "\n")
            return self._reply(202, {"status": "queued"})
        if path == "/api/agent/flows/poll":
            time.sleep(2)
            return self._reply(200, {"flows": [], "cancel": []})
        if path in ("/api/fim", "/api/hygiene"):
            return self._reply(204)
        return self._reply(404, {"detail": "not found"})

    def log_message(self, fmt, *args):
        sys.stderr.write("mock: " + (fmt % args) + "\n")


ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
