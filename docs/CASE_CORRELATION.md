# AI case correlation and remediation

New alerts that triage marks `create_case` or `escalate` are evaluated against
open cases in the same group. Existing `monitor` and false-positive policies
remain in effect. This does not bulk-merge historical cases.

Candidate retrieval considers the 100 most recently updated open cases in the
last 24 hours and sends at most 12 related candidates to the configured LLM
gateway. Candidates must share an indicator, account, or affected host. The
model evaluates timestamps, recent alert titles, accounts, targets, attack
sequence, and incident summaries. Attack type alone is insufficient.

- `join` with confidence at least 0.90 attaches the alert automatically.
- Lower-confidence joins become suggestions for analyst review.
- `new`, an invalid candidate ID, or no candidate keeps the normal case-creation
  path. A suggestion does not suppress the alert's own case.
- An unavailable or malformed AI response falls back to a unique matching
  indicator plus host within 30 minutes of the alert. Otherwise a new case is
  created according to the existing triage verdict.

Group-level PostgreSQL advisory locks serialize selection/creation across worker
replicas. Membership writes recheck the case's group and `open` status while
holding its row lock. Closed, resolved, in-review and escalated cases are not
grouping destinations. Severity may rise to critical without changing the open
status. AI correlation never queues remediation itself.

`case_alerts` stores the alert ID, indicator/account evidence, decision reason,
confidence, method, and linked/suggested/detached state. An analyst can accept a
suggestion or detach an association on an open case. Detaching preserves the
original alert and the decision record; automatic retries cannot restore a
detached association. Legacy cases expose their primary alert as evidence;
historical note text is not guessed into additional alert associations.

The case list shows linked-alert counts and last activity. The detail view
shows per-alert provenance, review controls, and an attack timeline based on
explicit associations. Associated alerts are also included in case filters.

## Remediation

Administrators select IPs and agent hosts from linked case evidence, choose a
duration, and explicitly queue the displayed IP × host selection. Maximum:
100 tasks per request. Each pair creates one existing `block_ip` agent task;
the existing agent executor remains responsible for validation and execution.
Domain, URL, command, and file-hash evidence is displayed but is not sent to an
IP firewall action. Both IPv4 and IPv6 literals are accepted by the API.

The API enforces `agents:manage`, case/agent group isolation, eligible evidence,
valid IP syntax, and supported durations before queuing any task. An idempotency
request ID prevents duplicate tasks on retries; changing a selection with the
same request ID returns 409. Case notes record the request and the UI polls
per-target execution status. Queued does not mean executed successfully.

## Deployment and validation

Start/restart the updated API before the updated worker. The normal API startup
`Base.metadata.create_all` creates `case_alerts` under the existing startup
advisory lock; no change to `db/init.sql` is needed. Build/redeploy the dashboard
to expose the new panels. There is no backfill that rewrites old cases.

Run the targeted regression suites with an isolated PostgreSQL test database:

```sh
PYTHONPATH=worker:server-api pytest tests/server-api/test_case_evidence.py \
  tests/worker/test_case_correlation.py tests/worker/test_case_grouping.py \
  tests/worker/test_ueba_ai_triage.py
cd dashboard && npm run build
```

The API integration suite uses `TEST_DATABASE_URL` and creates/drops its own
unique schema. Tests replace the external LLM response, so passing them verifies
routing, persistence, isolation, and fallback behavior, not model quality on
production traffic.
