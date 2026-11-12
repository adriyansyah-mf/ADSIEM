# Alert statuses

| Status | Set by | Meaning |
|---|---|---|
| `new` | worker, at creation | At or above **Minimum Alert Severity for AI** (`ai_min_severity`, default `high`). Waiting for AI triage or an analyst. |
| `below_threshold` | worker, at creation | Under `ai_min_severity`. The AI leaves it alone, and so does the hourly backfill. It stays out of the New queue, unassigned counts and the SLA. An analyst can still open it and change the status. |
| `acknowledged` | AI triage | Verdict "monitor", or a case was opened. Only alerts that reached the threshold get here. |
| `in_progress` | analyst | Being worked on. |
| `resolved`, `closed`, `false_positive` | analyst, AI (false positive), SOAR | Done. |

**Changing the threshold.** Set it in Settings → *Minimum Alert Severity for AI*. It's a select, and the API refuses anything but `info`, `low`, `medium`, `high` or `critical`. The worker treats an unknown stored value as `high`. A new value applies to alerts created after the change. Existing `below_threshold` alerts keep that status.

**Duplicates.** A repeat of a `below_threshold` alert within 30 minutes increments its duplicate count, the same as for `new` and `in_progress`.

A SOAR playbook can also set `below_threshold` (`set_alert_status`).

Tests:
- `tests/worker/test_alert_below_threshold.py`
- `tests/server-api/test_settings_ai_min_severity.py`
