"""Investigation-scoped, metadata-only MalwareBazaar hash enrichment."""
from __future__ import annotations

import re
import socket
from datetime import datetime, timezone
from typing import Annotated, ClassVar, Final, Literal

import anyio
import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

ENDPOINT: Final = "https://mb-api.abuse.ch/api/v1/"
MAX_LOOKUPS: Final = 10
HASH_PATTERN: Final = re.compile(r"(?i)(?<![a-z0-9])(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})(?![a-z0-9])")
HashValue = Annotated[str, Field(pattern=r"^(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})$")]
ShortText = Annotated[str, Field(max_length=256)]
Status = Literal[
    "found", "not_found", "invalid_hash", "unobserved_hash", "not_configured",
    "rate_limited", "auth_error", "unavailable", "invalid_response", "budget_exhausted", "disabled",
]


class Sample(BaseModel):
    """Curated provider metadata; comments and vendor blobs never reach the model."""
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="ignore")
    sha256_hash: Annotated[str, Field(pattern=r"^[a-fA-F0-9]{64}$")]
    sha1_hash: HashValue | None = None
    md5_hash: HashValue | None = None
    file_name: ShortText | None = None
    file_type: ShortText | None = None
    file_size: int | None = Field(default=None, ge=0)
    signature: ShortText | None = None
    tags: list[ShortText] | None = Field(default=None, max_length=40)
    first_seen: ShortText | None = None
    last_seen: ShortText | None = None


class ProviderResponse(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)
    query_status: str
    data: list[Sample] = Field(default_factory=list, max_length=20)


class EnrichmentResult(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)
    provider: Literal["MalwareBazaar"] = "MalwareBazaar"
    status: Status
    queried_hash: str
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    cached: bool = False
    sample: Sample | None = None
    report_url: str | None = None


class HashEnrichment:
    """Mutable evidence allowlist, request budget and cache owned by ONE investigation.

    No cross-group cache or secret is retained. Cached results expire with the run.
    Only case context and internal collection/search results may feed observe().
    """

    def __init__(self) -> None:
        self.observed: set[str] = set()
        self.cache: dict[str, EnrichmentResult] = {}
        self.requests: int = 0
        self.blocked: Literal["rate_limited", "auth_error"] | None = None

    def observe(self, evidence: str) -> None:
        self.observed.update(m.group().lower() for m in HASH_PATTERN.finditer(evidence))

    async def lookup(self, hash_value: str, api_key: str) -> EnrichmentResult:
        h = hash_value.strip().lower()
        if not HASH_PATTERN.fullmatch(h):
            return EnrichmentResult(status="invalid_hash", queried_hash=h[:128])
        if h not in self.observed:
            return EnrichmentResult(status="unobserved_hash", queried_hash=h)
        if not api_key.strip():
            return EnrichmentResult(status="not_configured", queried_hash=h)
        if h in self.cache:
            return self.cache[h].model_copy(update={"cached": True})
        if self.blocked:
            return EnrichmentResult(status=self.blocked, queried_hash=h)
        if self.requests >= MAX_LOOKUPS:
            return EnrichmentResult(status="budget_exhausted", queried_hash=h)
        self.requests += 1
        result = await _query(h, api_key.strip())
        self.cache[h] = result
        if result.status in ("rate_limited", "auth_error"):
            self.blocked = result.status
        return result


async def _query(h: str, api_key: str) -> EnrichmentResult:
    # Keep the repository's pinned httpx client. Fixed URL + no redirects prevents
    # an upstream redirect from forwarding the Auth-Key to another host.
    transport = httpx.AsyncHTTPTransport(
        retries=1, socket_options=[(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)],
    )
    try:
        with anyio.fail_after(15):
            async with httpx.AsyncClient(
                transport=transport, timeout=httpx.Timeout(10, connect=5),
                follow_redirects=False, trust_env=False,
            ) as client:
                async with client.stream(
                    "POST", ENDPOINT, headers={"Auth-Key": api_key},
                    data={"query": "get_info", "hash": h},
                ) as response:
                    match response.status_code:  # noqa: MATCH_OK — open HTTP status space
                        case 200:
                            body = bytearray()
                            async for chunk in response.aiter_bytes():
                                body.extend(chunk)
                                if len(body) > 1_048_576:
                                    return EnrichmentResult(status="invalid_response", queried_hash=h)
                        case 401 | 403:
                            return EnrichmentResult(status="auth_error", queried_hash=h)
                        case 429:
                            return EnrichmentResult(status="rate_limited", queried_hash=h)
                        case _:
                            return EnrichmentResult(status="unavailable", queried_hash=h)
    except (httpx.HTTPError, TimeoutError):
        return EnrichmentResult(status="unavailable", queried_hash=h)
    try:
        parsed = ProviderResponse.model_validate_json(body)
    except ValidationError:
        return EnrichmentResult(status="invalid_response", queried_hash=h)
    match parsed.query_status:  # noqa: MATCH_OK — provider may add undocumented statuses
        case "hash_not_found":
            return EnrichmentResult(status="not_found", queried_hash=h)
        case "no_api_key" | "invalid_auth_key" | "user_blacklisted":
            return EnrichmentResult(status="auth_error", queried_hash=h)
        case "ok":
            for sample in parsed.data:
                hashes = (sample.sha256_hash.lower(), sample.sha1_hash, sample.md5_hash)
                if h in hashes:
                    return EnrichmentResult(
                        status="found", queried_hash=h, sample=sample,
                        report_url=f"https://bazaar.abuse.ch/sample/{sample.sha256_hash.lower()}/",
                    )
            return EnrichmentResult(status="invalid_response", queried_hash=h)
        case _:
            return EnrichmentResult(status="invalid_response", queried_hash=h)
