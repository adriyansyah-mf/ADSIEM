# Task 1 outbound URL policy live-container evidence, fix round 1

Date: 2026-09-06

## Rebuilt service

```text
docker compose build server-api
siem-platform-server-api  Built
docker compose up -d --no-deps server-api
Container siem-platform-server-api-1  Running
```

## Pinned allowlisted repository fetch

Command exercised `validate_outbound_url` followed by `fetch_repository_content` inside the rebuilt `server-api` container against the allowlisted raw GitHub README.

```text
pinned allowlisted fetch bytes: 12738
addresses: ('185.199.108.133', '185.199.109.133', '185.199.110.133', '185.199.111.133', '2606:50c0:8000::154', '2606:50c0:8001::154', '2606:50c0:8002::154', '2606:50c0:8003::154')
```

The fetch used `PinnedAsyncHTTPTransport`, whose `httpcore.AsyncConnectionPool` TCP backend accepts only the validated address set while TLS/SNI remains bound to the validated hostname.

## Negative checks

```text
https://127.0.0.1/ -> OutboundUrlRejected: Outbound URL resolves to a non-public address
https://hooks.example/path?token=secret -> OutboundUrlRejected: Outbound URLs cannot contain query values
```

Both negative checks ran inside the rebuilt `server-api` container and were rejected before a request or persistence operation.
