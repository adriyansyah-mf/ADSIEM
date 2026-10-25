"""A stand-in SIEM server for the Windows agent smoke test (tests/windows/smoke-msi.ps1).

Answers the agent's endpoints like server-api does and records what arrives:
<out>/enroll.json (the enrollment request) and <out>/logs.jsonl (one ingested
log per line). Stdlib only.

    python mock_siem.py <port> <out dir> [<cert.pem> <key.pem>]   (TLS with the cert when given)
"""
import hashlib
import json
import os
import ssl
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PORT, OUT = int(sys.argv[1]), Path(sys.argv[2])
OUT.mkdir(parents=True, exist_ok=True)
# the agent gets only its hash; the smoke test passes the token to msiexec /x
UNINSTALL_TOKEN = "SMOKE-UNINS-TALLT-OKEN1"
# MOCK_FLOW=1: hand the agent one live-response flow running every Windows plugin
# (as server-api would after compile_request); its updates go to <out>/flows.jsonl.
FLOW = {
    "id": str(uuid.uuid4()), "artifact": "Smoke.Windows.Plugins", "timeout": 300, "max_rows": 20000,
    "sources": [
        {"name": "Info", "plugin": "info", "args": {}},
        {"name": "Pslist", "plugin": "pslist", "args": {}},
        {"name": "Users", "plugin": "users", "args": {}},
        {"name": "Persistence", "plugin": "persistence", "args": {}},
        {"name": "Services", "plugin": "services", "args": {}},
        {"name": "Programs", "plugin": "programs", "args": {}},
        {"name": "Netstat", "plugin": "netstat", "args": {}},
        {"name": "Events", "plugin": "eventlog",
         "args": {"channel": "Application", "event_ids": "999", "hours": "1", "limit": "50"}},
    ],
} if os.environ.get("MOCK_FLOW") else None
_flow_sent = False

# MOCK_EVIDENCE=1: advertise durable ingest (evidence_protocols [2]) and answer
# POST /api/ingest/v2/log (and the /v2/logs batch endpoint, evidence_batch_max
# 500) with matching receipts, recorded in <out>/evidence.jsonl.
# Receipts are stable per event ID (accepted, then duplicate) like server-api's,
# but this is memory: it exercises the agent's durable mode, not PostgreSQL.
EVIDENCE = bool(os.environ.get("MOCK_EVIDENCE"))
_receipts: dict[str, str] = {}


def _accept(envelope) -> dict:
    """One result as server-api's batch endpoint returns it (also the single
    endpoint's receipt minus protocol_version)."""
    event_id = envelope.get("event_id") if isinstance(envelope, dict) else None
    if not isinstance(envelope, dict) or envelope.get("protocol_version") != 2 or not event_id:
        return {"event_id": event_id, "status": "rejected", "code": 422}
    status = "duplicate" if event_id in _receipts else "accepted"
    receipt = _receipts.setdefault(event_id, str(uuid.uuid4()))
    if status == "accepted":
        with open(OUT / "evidence.jsonl", "a") as fh:
            fh.write(json.dumps(envelope) + "\n")
    return {"event_id": event_id, "status": status, "receipt_id": receipt}

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
            with open(OUT / "heartbeats.jsonl", "a") as fh:
                fh.write(json.dumps(payload) + "\n")
            # The test queues response tasks in <out>/tasks.json; they go out once.
            tasks, queued = [], OUT / "tasks.json"
            if queued.exists():
                tasks = json.loads(queued.read_text())
                queued.replace(OUT / "tasks.sent.json")
            return self._reply(200, {"config_hash": "mock", "log_sources": SOURCES, "fim_paths": [], "tasks": tasks,
                                     "uninstall_token_sha256": hashlib.sha256(UNINSTALL_TOKEN.encode()).hexdigest(),
                                     "evidence_protocols": [2] if EVIDENCE else [],
                                     "evidence_batch_max": 500 if EVIDENCE else 0})
        if path == "/api/ingest/v2/log" and EVIDENCE:
            result = _accept(payload)
            if result["status"] == "rejected":
                return self._reply(422, {"detail": "invalid_evidence_envelope"})
            return self._reply(202, {"protocol_version": 2, **result})
        if path == "/api/ingest/v2/logs" and EVIDENCE:
            events = payload.get("events")
            if payload.get("protocol_version") != 2 or not isinstance(events, list) or not 1 <= len(events) <= 500:
                return self._reply(422, {"detail": "invalid_evidence_batch"})
            return self._reply(200, {"protocol_version": 2, "results": [_accept(e) for e in events]})
        if path.startswith("/api/tasks/") and path.endswith("/result"):
            with open(OUT / "task_results.jsonl", "a") as fh:
                fh.write(json.dumps({"id": path.split("/")[3], **payload}) + "\n")
            return self._reply(200, {"status": "ok"})
        if path == "/api/ingest/log":
            with open(OUT / "logs.jsonl", "a") as fh:
                fh.write(json.dumps(payload) + "\n")
            return self._reply(202, {"status": "queued"})
        if path == "/api/agent/flows/poll":
            global _flow_sent
            if FLOW and not _flow_sent and (OUT / "send_flow").exists():  # the test says when
                _flow_sent = True
                return self._reply(200, {"flows": [FLOW], "cancel": []})
            time.sleep(2)
            return self._reply(200, {"flows": [], "cancel": []})
        if path.startswith("/api/agent/flows/") and path.endswith("/update"):
            with open(OUT / "flows.jsonl", "a") as fh:
                fh.write(json.dumps(payload) + "\n")
            return self._reply(200, {"cancel": False})
        if path == "/api/hygiene":
            (OUT / "hygiene.json").write_text(json.dumps(payload))
            return self._reply(204)
        if path == "/api/fim":
            return self._reply(204)
        return self._reply(404, {"detail": "not found"})

    def do_GET(self):  # noqa: N802 — lets the smoke test check TLS trust with Invoke-WebRequest
        return self._reply(200, {"status": "ok"}) if self.path == "/health" else self._reply(404, {})

    def log_message(self, fmt, *args):
        sys.stderr.write("mock: " + (fmt % args) + "\n")


server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
if len(sys.argv) >= 5:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(sys.argv[3], sys.argv[4])
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
server.serve_forever()
