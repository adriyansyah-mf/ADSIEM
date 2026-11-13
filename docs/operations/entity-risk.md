# Entity risk (risk-based alerting)

Every new alert, whatever produced it (Sigma rules, IOA chains, IoC matches, behaviour findings, UEBA, YARA, known malware, agent tamper, network IDS, App Control), adds risk to the **host** and the **user** it names. Many small signals on one machine add up to one ranked view instead of sitting in separate queues (`worker/worker/entity_risk.py`).

## Scoring

| | |
|---|---|
| Points per alert | informational 2, low 5, medium 15, high 30, critical 50 |
| Tactic bonus | +10 for each MITRE tactic the entity has not shown in the last 24 h (Sigma `attack.<tactic>` tags; for UEBA alerts, the kill-chain stage of their techniques) |
| Decay | halves every 24 h without new alerts |
| Cap | 100 |

Deduplicated (same title within 30 min) and suppressed alerts add nothing. Users come from the alert's user or its `user.name` / `User` / `TargetUserName` field.

## Risk-based alerts

When an entity reaches `entity_risk_alert_threshold` (platform setting, default 70) **and** shows at least two tactics in the last 24 h, one alert is raised:

`[Risk] Host web-01: risk 100/100 across 3 tactics` — high (critical at 90+), tagged with those tactics, carrying the contributing alerts for the AI analyst. At most one per entity per 24 h; risk alerts add no risk themselves. They go through triage, SOAR and notifications like any alert.

## Where to see it

- Dashboard → **Entity risk**: hosts and users by current risk, their tactics, sources, latest alert; open one for every contributing alert with the points it added.
- API: `GET /api/entity-risk?entity_type=host|user|all&min_risk=&limit=`, `GET /api/entity-risk/{host|user}/{value}` (group scoped; the decay is applied when read).
- Table `entity_risk` (one row per entity and group; the score stored is the value at `updated_at`).

Tests: `tests/worker/test_entity_risk_scoring.py`, `tests/worker/test_entity_risk.int.py`, `tests/server-api/test_entity_risk_api.int.py`.
