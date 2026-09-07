# P0 SOAR Approval Gate

- Added a live-worker guard for destructive `isolate_agent` and `block_ip` actions.
- Default setting: `soar_destructive_approval_required=true`.
- When enabled, the legacy worker skips the destructive handler and writes an alert note stating that explicit approval is required.
- Verification: `python -m compileall` passed; worker image rebuilt and recreated; `docker compose ps worker` reports `running`.
- In-container service smoke passed: destructive step starts `pending_approval`, runnable assertion raises until approval, and approval transitions it to `approved`.
- The staged execution API remains available at `/api/soar/executions`, with approve and rollback endpoints.
