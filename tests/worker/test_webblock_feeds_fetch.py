"""Credential-bearing feed HTTP boundary (no external network or database)."""
import logging
from urllib.parse import quote

import httpx
import pytest

from worker import webblock_feeds as wf


@pytest.fixture
def mock_http(monkeypatch):
    real = httpx.AsyncClient

    def install(handler):
        monkeypatch.setattr(wf.httpx, "AsyncClient",
                            lambda **kw: real(**{**kw, "transport": httpx.MockTransport(handler)}))
    return install


@pytest.mark.parametrize("feed,base", [
    ("urlhaus", "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/online.csv"),
    ("phishtank", "https://data.phishtank.com/data/{key}/online-valid.json"),
])
async def test_encoded_key_endpoint_and_private_transport_logs(mock_http, caplog, feed, base):
    key = "SECRET/with ?#%key"
    seen = []

    def handler(request):
        seen.append(request)
        logging.getLogger("httpcore.http11").debug("receive_response_headers.complete %r", [(b'location', str(request.url).encode())])
        return httpx.Response(200, text="ok")
    mock_http(handler)
    with caplog.at_level(logging.DEBUG):
        assert await wf.FETCHERS[feed](key) == "ok"
        logging.getLogger("httpx").info("unrelated request remains visible")
    assert str(seen[0].url) == base.format(key=quote(key, safe=""))
    assert "auth-key" not in seen[0].headers
    assert key not in caplog.text and quote(key, safe="") not in caplog.text
    assert "unrelated request remains visible" in caplog.text


@pytest.mark.parametrize("feed,host", [("urlhaus", "urlhaus-api.abuse.ch"), ("phishtank", "data.phishtank.com")])
@pytest.mark.parametrize("destination", ["http://{host}/SECRET", "https://{host}:444/SECRET", "https://foreign.example/SECRET", "https://user:pass@{host}/SECRET"])
async def test_unsafe_redirect_is_rejected_before_second_request(mock_http, feed, host, destination):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(302, headers={"location": destination.format(host=host)})
    mock_http(handler)
    with pytest.raises(RuntimeError, match="unsafe feed redirect"):
        await wf.FETCHERS[feed]("SECRET")
    assert len(seen) == 1


@pytest.mark.parametrize("destination", ["/new/SECRET", "https://urlhaus-api.abuse.ch:443/new/SECRET"])
async def test_same_origin_https_redirect_succeeds(mock_http, destination):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(302, headers={"location": destination}) if len(seen) == 1 else httpx.Response(200, text="ok")
    mock_http(handler)
    assert await wf.fetch_urlhaus("SECRET") == "ok"
    assert len(seen) == 2


@pytest.mark.parametrize("status", [401, 403, 410, 503])
async def test_status_errors_do_not_expose_key(mock_http, caplog, status):
    mock_http(lambda request: httpx.Response(status))
    with caplog.at_level(logging.DEBUG), pytest.raises(RuntimeError) as exc:
        await wf.fetch_urlhaus("SECRET")
    assert str(status) in str(exc.value)
    assert "SECRET" not in str(exc.value) + caplog.text


def test_redact_encoded_key():
    key = "SECRET/with ?#%key"
    assert wf.redact(f"{key} {quote(key, safe='')}", [key]) == "*** ***"
