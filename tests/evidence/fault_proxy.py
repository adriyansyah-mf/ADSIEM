# tests/evidence/fault_proxy.py
"""HTTP fault proxy between the agent and server-api (evidence harness).

The agent's server.url points here; requests are forwarded round robin to the
API replicas in UPSTREAMS (comma-separated).
A control listener (CONTROL_PORT) switches the mode with
POST /mode {"mode": ..., "rate": 0.3}:

- pass: forward everything
- down: close every agent connection without forwarding (server unreachable)
- drop_response: forward durable evidence requests, then close the agent's
  connection without the response at `rate` (committed, receipt lost)

GET / returns the mode and counters, GET /progress the producer's progress.
Standard library only."""
import http.client
import json
import os
import random
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

UPSTREAMS = [urlsplit(u) for u in os.environ.get("UPSTREAMS", "http://api:8000").split(",")]
EVIDENCE_PATHS = ("/api/ingest/v2/log", "/api/ingest/v2/logs")
_lock = threading.Lock()
_state = {"mode": "pass", "rate": 0.0}
_stats = {"forwarded": 0, "refused": 0, "dropped_responses": 0, "requests": 0}


def _next_upstream():
    """Round robin across the API replicas."""
    with _lock:
        _stats["requests"] += 1
        return UPSTREAMS[_stats["requests"] % len(UPSTREAMS)]


def _count(key):
    with _lock:
        _stats[key] += 1


def _abort(handler):
    handler.close_connection = True
    try:
        handler.connection.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


class Proxy(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # quiet: the harness keeps its own timeline
        pass

    def _forward(self):
        with _lock:
            mode, rate = _state["mode"], _state["rate"]
        if mode == "down":
            _count("refused")
            return _abort(self)
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        headers = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "connection")}
        target = _next_upstream()
        upstream = http.client.HTTPConnection(target.hostname, target.port or 80, timeout=60)
        try:
            upstream.request(self.command, self.path, body=body or None, headers=headers)
            resp = upstream.getresponse()
            data = resp.read()
        except OSError:
            _count("refused")
            return _abort(self)
        finally:
            upstream.close()
        path = self.path.split("?")[0]
        if mode == "drop_response" and path in EVIDENCE_PATHS and random.random() < rate:
            _count("dropped_responses")
            return _abort(self)
        _count("forwarded")
        self.send_response(resp.status)
        for k, v in resp.getheaders():
            if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _forward


class Control(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _reply(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        if self.path == "/progress":  # the producer's progress file (source volume, read-only)
            try:
                with open(os.environ.get("PROGRESS_FILE", "/data/source.log.progress")) as fh:
                    return self._reply(200, json.load(fh))
            except (OSError, ValueError):
                return self._reply(200, {"written": 0})
        with _lock:
            return self._reply(200, {**_state, **_stats})

    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        if body.get("mode") not in ("pass", "down", "drop_response"):
            return self._reply(422, {"detail": "unknown mode"})
        with _lock:
            _state.update(mode=body["mode"], rate=float(body.get("rate", 0.0)))
            return self._reply(200, {**_state, **_stats})


if __name__ == "__main__":
    control = ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("CONTROL_PORT", "8081"))), Control)
    threading.Thread(target=control.serve_forever, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PROXY_PORT", "8080"))), Proxy).serve_forever()
