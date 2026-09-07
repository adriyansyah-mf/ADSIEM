import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from collections.abc import AsyncIterator, Iterable
from typing import Final
from urllib.parse import urlsplit, urlunsplit

import httpcore
import httpx

PROHIBITED_PORTS: Final[frozenset[int]] = frozenset(
    {22, 25, 53, 110, 143, 2375, 2376, 3306, 3389, 5432, 6379, 9200, 9300}
)


@dataclass(frozen=True, slots=True)
class ValidatedOutboundUrl:
    url: str
    host: str
    resolved_addresses: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class OutboundUrlRejected(ValueError):
    reason: str

    def __str__(self) -> str:
        return self.reason


class PinnedAddressNetworkBackend(httpcore.AsyncNetworkBackend):
    def __init__(
        self,
        validated_url: ValidatedOutboundUrl,
        delegate: httpcore.AsyncNetworkBackend | None = None,
    ) -> None:
        parsed = urlsplit(validated_url.url)
        self._host = validated_url.host
        self._port = parsed.port or 443
        self._resolved_addresses = validated_url.resolved_addresses
        self._delegate = delegate or httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[tuple[int, int, int]] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        if host != self._host or port != self._port:
            raise httpcore.ConnectError("Outbound connection destination was not validated")

        last_error: httpcore.ConnectError | httpcore.ConnectTimeout | None = None
        for address in self._resolved_addresses:
            try:
                return await self._delegate.connect_tcp(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_error = exc
        if last_error is not None:
            raise last_error
        raise httpcore.ConnectError("Outbound URL has no validated connection address")

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[tuple[int, int, int]] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise httpcore.ConnectError("Unix sockets are not valid outbound destinations")

    async def sleep(self, seconds: float) -> None:
        await self._delegate.sleep(seconds)


class PinnedResponseStream(httpx.AsyncByteStream):
    def __init__(self, stream: AsyncIterator[bytes]) -> None:
        self._stream = stream

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for chunk in self._stream:
            yield chunk

    async def aclose(self) -> None:
        await self._stream.aclose()


class PinnedAsyncHTTPTransport(httpx.AsyncBaseTransport):
    def __init__(self, validated_url: ValidatedOutboundUrl) -> None:
        self._pool = httpcore.AsyncConnectionPool(
            max_connections=1,
            max_keepalive_connections=0,
            retries=0,
            network_backend=PinnedAddressNetworkBackend(validated_url),
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await self._pool.handle_async_request(
            httpcore.Request(
                method=request.method,
                url=httpcore.URL(
                    scheme=request.url.raw_scheme,
                    host=request.url.raw_host,
                    port=request.url.port,
                    target=request.url.raw_path,
                ),
                headers=request.headers.raw,
                content=request.stream,
                extensions=request.extensions,
            )
        )
        return httpx.Response(
            status_code=response.status,
            headers=response.headers,
            stream=PinnedResponseStream(response.stream),
            extensions=response.extensions,
        )

    async def aclose(self) -> None:
        await self._pool.aclose()


async def validate_outbound_url(
    url: str,
    *,
    allowed_hosts: frozenset[str] = frozenset(),
) -> ValidatedOutboundUrl:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise OutboundUrlRejected("URL is malformed") from exc

    host = parsed.hostname
    if parsed.scheme.lower() != "https":
        raise OutboundUrlRejected("Outbound URLs must use HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise OutboundUrlRejected("Outbound URLs cannot contain credentials")
    if host is None:
        raise OutboundUrlRejected("Outbound URL must include a host")
    if parsed.query:
        raise OutboundUrlRejected("Outbound URLs cannot contain query values")
    if port in PROHIBITED_PORTS:
        raise OutboundUrlRejected("Outbound URL uses a prohibited port")
    if allowed_hosts and host not in allowed_hosts:
        raise OutboundUrlRejected("Outbound URL host is not allowlisted")

    try:
        address_infos = await asyncio.get_running_loop().getaddrinfo(
            host,
            port or 443,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise OutboundUrlRejected("Outbound URL host could not be resolved") from exc

    resolved_addresses = tuple(
        dict.fromkeys(str(address_info[4][0]) for address_info in address_infos)
    )
    if not resolved_addresses:
        raise OutboundUrlRejected("Outbound URL host resolved to no addresses")
    for resolved_address in resolved_addresses:
        address = ipaddress.ip_address(resolved_address)
        if not address.is_global or address.is_multicast:
            raise OutboundUrlRejected("Outbound URL resolves to a non-public address")

    normalized_host = f"[{host}]" if ":" in host else host
    normalized_netloc = normalized_host if port in (None, 443) else f"{normalized_host}:{port}"
    normalized_url = urlunsplit(
        ("https", normalized_netloc, parsed.path or "/", parsed.query, "")
    )
    return ValidatedOutboundUrl(
        url=normalized_url,
        host=host,
        resolved_addresses=resolved_addresses,
    )
