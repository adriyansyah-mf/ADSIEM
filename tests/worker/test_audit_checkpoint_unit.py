"""worker/audit_checkpoint.py: the newest audit chain link goes to Elasticsearch
once, under its seq, and is never overwritten."""
import asyncio

import httpx

from worker import audit_checkpoint

_LOOP = asyncio.new_event_loop()


def _client(existing_index: bool, existing_docs: set):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path, dict(request.url.params)))
        if request.method == "HEAD":
            return httpx.Response(200 if existing_index else 404)
        if request.url.path.startswith(f"/{audit_checkpoint.INDEX}/_doc/"):
            seq = request.url.path.rsplit("/", 1)[1]
            if seq in existing_docs:
                return httpx.Response(409, json={"error": "version_conflict"})
            existing_docs.add(seq)
            return httpx.Response(201, json={"result": "created"})
        return httpx.Response(200, json={"acknowledged": True})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://es"), calls


def test_a_head_is_written_once_and_never_overwritten():
    docs: set = set()
    client, calls = _client(existing_index=False, existing_docs=docs)
    _LOOP.run_until_complete(audit_checkpoint.record(client, 41, "a" * 64))
    assert ("PUT", "/audit_checkpoints", {}) in calls  # index created with its mapping
    put_doc = [c for c in calls if c[1] == "/audit_checkpoints/_doc/41"]
    assert put_doc and put_doc[0][2] == {"op_type": "create"}

    client, calls = _client(existing_index=True, existing_docs=docs)
    _LOOP.run_until_complete(audit_checkpoint.record(client, 41, "b" * 64))  # 409: kept, no error
    assert not any(c[1] == "/audit_checkpoints" and c[0] == "PUT" for c in calls)
