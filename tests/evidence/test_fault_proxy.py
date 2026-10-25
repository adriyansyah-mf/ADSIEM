# tests/evidence/test_fault_proxy.py
"""The harness fault proxy (no Docker): forwards round robin across replicas,
refuses everything when down, and drops only durable evidence responses
after the upstream answered (the request was committed)."""
import http.client
import importlib
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))


def upstream(name: str, seen: list):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):  # noqa: N802
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            seen.append((name, self.path, body))
            data = json.dumps({"replica": name}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture
def proxy(monkeypatch):
    seen: list = []
    a, b = upstream("a", seen), upstream("b", seen)
    monkeypatch.setenv("UPSTREAMS", f"http://127.0.0.1:{a.server_port},http://127.0.0.1:{b.server_port}")
    import fault_proxy
    fp = importlib.reload(fault_proxy)
    p = ThreadingHTTPServer(("127.0.0.1", 0), fp.Proxy)
    c = ThreadingHTTPServer(("127.0.0.1", 0), fp.Control)
    for s in (p, c):
        threading.Thread(target=s.serve_forever, daemon=True).start()

    def post(port, path, body):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        try:
            conn.request("POST", path, body=json.dumps(body), headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            return resp.status, json.loads(resp.read() or b"null")
        except (ConnectionError, http.client.RemoteDisconnected):
            return None, None
        finally:
            conn.close()

    yield (lambda path, body=None: post(p.server_port, path, body or {}),
           lambda mode, rate=0.0: post(c.server_port, "/mode", {"mode": mode, "rate": rate})[1],
           seen)
    for s in (p, c, a, b):
        s.shutdown()


def test_pass_forwards_round_robin(proxy):
    send, _mode, seen = proxy
    replies = [send("/api/ingest/heartbeat")[1]["replica"] for _ in range(4)]
    assert sorted(replies) == ["a", "a", "b", "b"] and replies[0] != replies[1]
    assert [s[1] for s in seen] == ["/api/ingest/heartbeat"] * 4


def test_down_refuses_without_forwarding(proxy):
    send, mode, seen = proxy
    assert mode("down")["mode"] == "down"
    assert send("/api/ingest/v2/logs") == (None, None)
    assert seen == []


def test_drop_response_commits_then_loses_only_evidence_responses(proxy):
    send, mode, seen = proxy
    mode("drop_response", 1.0)
    assert send("/api/ingest/v2/logs", {"events": [1]}) == (None, None)  # answered upstream, lost here
    assert send("/api/ingest/v2/log") == (None, None)
    assert send("/api/ingest/heartbeat")[0] == 200                       # control traffic still flows
    assert [s[1] for s in seen] == ["/api/ingest/v2/logs", "/api/ingest/v2/log", "/api/ingest/heartbeat"]
    assert mode("pass")["dropped_responses"] == 2


def test_unknown_mode_is_refused(proxy):
    _send, mode, _seen = proxy
    assert mode("chaos") == {"detail": "unknown mode"}
