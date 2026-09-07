from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi import BackgroundTasks, HTTPException
import httpcore
import httpx

from app.api.routes import rules
from app.api.routes import webhooks
from app.core.outbound_url import (
    OutboundUrlRejected,
    PinnedAddressNetworkBackend,
    ValidatedOutboundUrl,
    validate_outbound_url,
)
from app.models.models import WebhookConfig
from app.schemas.schemas import WebhookCreate, WebhookUpdate


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1/admin",
        "https://169.254.169.254/latest/meta-data",
        "https://10.0.0.7/internal",
        "https://[::1]/",
        "https://224.0.0.1/",
    ],
)
async def test_rejects_non_public_destinations(url: str) -> None:
    with pytest.raises(OutboundUrlRejected):
        await validate_outbound_url(url)


@pytest.mark.asyncio
async def test_rejects_resolved_private_address_for_https_url(monkeypatch: pytest.MonkeyPatch) -> None:
    class PrivateAddressLoop:
        async def getaddrinfo(self, *args: object, **kwargs: object) -> list[tuple[object, object, object, object, tuple[str, int]]]:
            return [(2, 1, 6, "", ("10.0.0.7", 443))]

    monkeypatch.setattr("app.core.outbound_url.asyncio.get_running_loop", lambda: PrivateAddressLoop())

    with pytest.raises(OutboundUrlRejected):
        await validate_outbound_url("https://repository.example/rules.yml")


@pytest.mark.asyncio
async def test_normalizes_public_allowlisted_url(monkeypatch: pytest.MonkeyPatch) -> None:
    class PublicAddressLoop:
        async def getaddrinfo(self, *args: object, **kwargs: object) -> list[tuple[object, object, object, object, tuple[str, int]]]:
            return [(2, 1, 6, "", ("93.184.216.34", 443))]

    monkeypatch.setattr("app.core.outbound_url.asyncio.get_running_loop", lambda: PublicAddressLoop())

    validated = await validate_outbound_url(
        "https://REPOSITORY.example:443/rules.yml",
        allowed_hosts=frozenset({"repository.example"}),
    )

    assert validated.url == "https://repository.example/rules.yml"
    assert validated.host == "repository.example"
    assert validated.resolved_addresses == ("93.184.216.34",)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "https://user:password@repository.example/rules.yml",
        "https:///rules.yml",
        "https://repository.example:22/rules.yml",
    ],
)
async def test_rejects_unsafe_url_components(url: str) -> None:
    with pytest.raises(OutboundUrlRejected):
        await validate_outbound_url(url)


@pytest.mark.asyncio
async def test_rejects_url_query_value_before_it_can_be_persisted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class PublicAddressLoop:
        async def getaddrinfo(self, *args: object, **kwargs: object) -> list[tuple[object, object, object, object, tuple[str, int]]]:
            return [(2, 1, 6, "", ("93.184.216.34", 443))]

    monkeypatch.setattr("app.core.outbound_url.asyncio.get_running_loop", lambda: PublicAddressLoop())

    with pytest.raises(OutboundUrlRejected):
        await validate_outbound_url("https://hooks.example/endpoint?token=secret-value")


class _WebhookResult:
    def __init__(self, webhook: WebhookConfig | None) -> None:
        self._webhook = webhook

    def scalar_one_or_none(self) -> WebhookConfig | None:
        return self._webhook


class _WebhookSession:
    def __init__(self, webhook: WebhookConfig | None = None) -> None:
        self.added: list[WebhookConfig] = []
        self.commits = 0
        self.webhook = webhook

    async def execute(self, statement: object) -> _WebhookResult:
        return _WebhookResult(self.webhook)

    def add(self, webhook: WebhookConfig) -> None:
        self.added.append(webhook)

    async def commit(self) -> None:
        self.commits += 1

    async def refresh(self, webhook: WebhookConfig) -> None:
        webhook.id = webhook.id or uuid4()
        webhook.created_at = webhook.created_at or datetime.now(UTC)


class _CurrentUser:
    def __init__(self, group_id: str) -> None:
        self.id = uuid4()
        self.group_id = group_id


@pytest.mark.asyncio
async def test_create_webhook_uses_caller_tenant_over_supplied_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def validate(url: str) -> ValidatedOutboundUrl:
        return ValidatedOutboundUrl(
            url="https://hooks.example/endpoint",
            host="hooks.example",
            resolved_addresses=("93.184.216.34",),
        )

    monkeypatch.setattr(webhooks, "validate_outbound_url", validate)
    db = _WebhookSession()

    result = await webhooks.create_webhook(
        WebhookCreate(name="tenant webhook", url="https://hooks.example/endpoint", group_id="tenant-b"),
        BackgroundTasks(),
        db,
        _CurrentUser("tenant-a"),
        group_filter="tenant-a",
    )

    assert db.added[0].group_id == "tenant-a"
    assert result.group_id == "tenant-a"


@pytest.mark.asyncio
async def test_update_webhook_rejects_a_different_tenant() -> None:
    webhook = WebhookConfig(
        id=uuid4(),
        name="other tenant webhook",
        url="https://hooks.example/endpoint",
        group_id="tenant-b",
        payload_format="default",
        is_enabled=True,
        created_at=datetime.now(UTC),
    )
    db = _WebhookSession(webhook)

    with pytest.raises(HTTPException, match="Webhook not found") as exc_info:
        await webhooks.update_webhook(
            webhook.id,
            WebhookUpdate(name="attempted change"),
            BackgroundTasks(),
            db,
            _CurrentUser("tenant-a"),
            group_filter="tenant-a",
        )

    assert exc_info.value.status_code == 404
    assert db.commits == 0


@pytest.mark.asyncio
async def test_update_webhook_preserves_caller_tenant_over_supplied_group() -> None:
    webhook = WebhookConfig(
        id=uuid4(),
        name="tenant webhook",
        url="https://hooks.example/endpoint",
        group_id="tenant-a",
        payload_format="default",
        is_enabled=True,
        created_at=datetime.now(UTC),
    )
    db = _WebhookSession(webhook)

    result = await webhooks.update_webhook(
        webhook.id,
        WebhookUpdate(group_id="tenant-b"),
        BackgroundTasks(),
        db,
        _CurrentUser("tenant-a"),
        group_filter="tenant-a",
    )

    assert webhook.group_id == "tenant-a"
    assert result.group_id == "tenant-a"


class _RecordingNetworkBackend:
    def __init__(self) -> None:
        self.connected_hosts: list[str] = []

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: object = None,
    ) -> object:
        self.connected_hosts.append(host)
        raise httpcore.ConnectError("network disabled for test")

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: object = None,
    ) -> object:
        raise httpcore.ConnectError("network disabled for test")

    async def sleep(self, seconds: float) -> None:
        return None


@pytest.mark.asyncio
async def test_pinned_connection_backend_uses_validated_address_not_hostname() -> None:
    validated = ValidatedOutboundUrl(
        url="https://repository.example/rules.yml",
        host="repository.example",
        resolved_addresses=("93.184.216.34",),
    )
    delegate = _RecordingNetworkBackend()
    backend = PinnedAddressNetworkBackend(validated, delegate)

    with pytest.raises(httpcore.ConnectError):
        await backend.connect_tcp("repository.example", 443)

    assert delegate.connected_hosts == ["93.184.216.34"]


@pytest.mark.asyncio
async def test_pinned_connection_backend_rejects_unvalidated_destination() -> None:
    validated = ValidatedOutboundUrl(
        url="https://repository.example/rules.yml",
        host="repository.example",
        resolved_addresses=("93.184.216.34",),
    )
    delegate = _RecordingNetworkBackend()
    backend = PinnedAddressNetworkBackend(validated, delegate)

    with pytest.raises(httpcore.ConnectError):
        await backend.connect_tcp("169.254.169.254", 443)

    assert delegate.connected_hosts == []


@pytest.mark.asyncio
async def test_repository_fetch_stops_stream_when_response_exceeds_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class OversizedStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"x" * 2_000_000
            yield b"x"

        async def aclose(self) -> None:
            return None

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=OversizedStream())

    monkeypatch.setattr(rules, "PinnedAsyncHTTPTransport", lambda validated: httpx.MockTransport(handler))
    validated = ValidatedOutboundUrl(
        url="https://repository.example/rules.yml",
        host="repository.example",
        resolved_addresses=("93.184.216.34",),
    )

    with pytest.raises(HTTPException) as exc_info:
        await rules.fetch_repository_content(validated)

    assert exc_info.value.status_code == 413
