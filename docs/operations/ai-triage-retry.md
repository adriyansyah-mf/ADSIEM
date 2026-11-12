# AI triage when the LLM is unavailable

AI L1 triage (`worker/graph/triage_graph.py`) calls the LLM through 9router. The client retries up to 4 times, waiting out a 429's `Retry-After`. If every attempt fails (rate limit, quota, timeout, router down), the alert is queued again with backoff. It no longer gets a canned "AI analyst unavailable" verdict straight away:

| Alert | What happens |
|---|---|
| critical / high | Escalated right away, as before: a case for L2, SOAR playbooks run. The note says AI triage will be retried. When the retry succeeds, the AI's analysis is added to the alert as a "delayed" note, with the verdict and MITRE tags. No second case is made, and the alert is never auto-closed: if the AI calls it a false positive, L2 decides. |
| medium / low | Stays `new` with a "PENDING" note, and nothing is decided. A retry that succeeds triages it normally: monitor, close as false positive, or a case. |
| retries used up | medium/low: the old fallback (acknowledged, note says "gave up after N attempts"). critical/high: a "GAVE UP" note; the case stays with L2. |

**Backoff:** 2, 5, 15 and 30 minutes, then 1 hour, each plus up to 20% jitter. That is 5 retries over about 1 h 50 m. The jitter keeps a burst of rate-limited alerts from coming back as a burst. Due retries go back onto the AI queue, and the consumer spaces dispatches 3 s apart.

**Where it lives:**
- `worker/worker/ai_retry.py`.
- Redis zset `siem:ai-retry` (payload → due time) and set `siem:ai-retry:pending` (alert IDs).
- The `ai_retry` loop in the worker polls every 10 s. `ZREM` decides which replica moves an item.
- The hourly backfill skips alerts that are waiting for a retry.

An LLM reply that isn't valid JSON is not retried: it still falls back at once.

**Logs:**
- `ai_l1_triage_failed`: shows `attempt` and the error. The last 429 now reads `rate limited (429)`.
- `ai_l1_triage_deferred`
- `ai_retry_requeued`

Tests: `tests/worker/test_ai_retry.py`.
