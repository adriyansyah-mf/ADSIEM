# P0 Correlation Redis Smoke

- Image rebuilt: `siem-platform-worker`
- Scenario: grouped two-stage sequence (`failed` → `success`) for one source IP.
- Backend: live Redis from Docker Compose, not a fake client.
- Result: `real_redis_correlation_smoke=pass`
- Assertions: first stage did not alert; second stage returned `stage_count == 2`.
- Deployment verification: `docker compose build worker && docker compose up -d worker` followed by an in-container parser and Redis evaluation script returned `deployed_correlation_loader_and_redis_smoke=pass`.
