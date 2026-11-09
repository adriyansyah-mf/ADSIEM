# Investigation follow-up chat — design

Status: approved by the user 2026-11-09 (scope, model, approval rule; plus "the AI can add to Threat IoCs").

## Goal

After an AI investigation of a case ends (`finished`, `error`, `cancelled`, `interrupted`), the analyst can keep talking to the AI in the investigation panel with free-form instructions — "upload this hash to VirusTotal", "remove IoC 8.8.8.8, it is Google DNS", "block this C2 domain", "isolate host1", "check other processes on host2 talking to this IP", "add this domain to Threat IoCs". The AI answers in text and proposes actions; read-only actions run at once, every action that changes data or touches an endpoint waits for an explicit **Approve** by an analyst who is allowed to do it.

## Scope (user decisions)

- In: evidence and IoC management, adding to the Threat IoCs list, endpoint response (isolate/unisolate, block domain, block IP, kill process, quarantine file, extra live response).
- Out (for now): case management (status, assign, close), SOAR playbooks.
- Model: the investigation model (`investigation_model` setting, else the assistant model), same provider/key path as the investigator.
- Approval: **always** for anything that changes data or touches an endpoint. Read-only tools run immediately.

## Behaviour

1. Chat is available on an investigation whose status is not `queued`/`running`. One conversation per investigation; history persisted.
2. A user message runs one bounded tool-calling turn (≤ 8 tool calls, ≤ 5 proposed actions, ≤ 90 s). Context: the case (title, status, hosts, `ioc_data`), the investigation report/verdict, hypotheses, the last N evidence items (pinned first), case IoCs, prior chat turns (last 20 messages), and a system prompt that says: use tools, never invent results, propose actions only through proposal tools, explain why.
3. Tools
   - Read (immediate): the investigator's READ_ONLY_TOOLS (assistant `run_tool` allow-list), plus `list_evidence`, `get_evidence`, `list_hypotheses`, `case_iocs`, and `ti_lookup(value)` (hash/IP/domain/URL through the worker's TI aggregator; see below).
   - Proposals (create a pending action, never execute): `pin_evidence(evidence_id)`, `add_case_ioc(type, value, reason)`, `remove_case_ioc(type, value, reason)`, `add_threat_ioc(type, value, reason)`, `isolate_host(agent_id, reason)`, `unisolate_host(agent_id, reason)`, `block_domain(domain, reason, days?)`, `block_ip(agent_ids, ip, duration_seconds, reason)`, `kill_process(agent_id, pid, reason)`, `quarantine_file(agent_id, path, reason)`, `run_live_response(agent_id, artifact, params, reason)`.
4. Each proposal is a row with status `proposed`, shown as a card (what, target, reason) with Approve/Reject. Approve re-validates and **executes immediately in the request** using the existing code paths; the result (or error) is stored on the row and appended to the chat as a system message. Reject stores the decision. Proposals expire after 24 h.
5. Live response: the flow is scheduled on approval; its id is stored; the chat shows its status/rows when the analyst asks or the panel refreshes (GET resolves flow status).

## Security

- Permissions are checked on the **approver**, at decision time: IoC/evidence actions need `cases:manage`; endpoint actions need `agents:manage` (superadmin bypasses as elsewhere). Sending chat messages needs `cases:manage`.
- Every target must belong to the case's group (agents via `fetch_scoped`, domains/IoCs filed under the case group). Agent targets must exist and, for isolate/kill/quarantine/live response, be online.
- Arguments validated server-side (IoC types/values normalised, `web_domains.normalize` for domains, public IP check for block_ip, pid int, absolute path for quarantine, artifact must exist/be enabled).
- The AI has no free shell: no `run_command`; live response only through registered artifacts.
- Audit log for every proposal decision and execution (`ai_chat_action_approved|rejected|executed|failed`), with requester (message author), approver, target, result.
- Prompt injection: tool results and evidence are data; proposals still need a human approve with the full target shown.

## Threat IoCs

`add_threat_ioc` writes a document to the ES `alert_iocs` index in the same shape the worker writes, tied to the case instead of an alert: `doc_id = sha1("case:<case_id>|<type>|<value>")`, `alert_id = "case:<case_id>"`, `origin = "analyst"`, `rule_title = "Added from investigation chat"`, case group, created_at now; it then appears on the Threat IoCs page. `remove_case_ioc` removes it from the case (`ioc_data.ioc_keys`) and deletes the case-scoped Threat IoC doc if one exists (alert-derived docs are not deleted; the page shows the alerts they came from).

## TI lookup bridge

server-api cannot import the worker's TI code. `ti_lookup` pushes `{id, value, group}` to Redis list `siem:ti:lookup`, a worker loop runs `EnrichmentAggregator.enrich(value)` and writes the summary JSON to `siem:ti:result:<id>` (TTL 10 min); the server waits up to 25 s, else returns "pending — ask again". Results are recorded as investigation evidence (`ti_result`).

## Data

- `investigation_messages`: id, investigation_id FK CASCADE, group_id, role (user|assistant|system), content, author_id, tool_calls JSONB, created_at.
- `investigation_chat_actions`: id, investigation_id FK CASCADE, message_id, group_id, tool, target, params JSONB, reason, status (proposed|approved|rejected|executed|failed|expired), result JSONB, error, requested_by, decided_by, decided_at, executed_at, created_at.
Both created by `create_all` (new tables).

## API

- `GET /api/investigations/{id}/chat` → messages + actions (flow status resolved).
- `POST /api/investigations/{id}/chat` `{message}` → runs the turn, returns new messages + proposals. 409 while the investigation is queued/running; 422 when no AI provider.
- `POST /api/investigation-chat-actions/{id}/decision` `{approve, note}` → executes on approve; 409 if not `proposed`; 403 if the approver lacks the permission.

## Dashboard

A "Chat" tab in `AiInvestigationPanel` (visible when the current run is not active): message list (markdown), action cards with Approve/Reject and result, input box; polls while a turn runs or a live-response flow is pending. Help text updated (response actions are no longer "left to you" only).

## Out of scope / later

Case status changes, SOAR, streaming tokens, multi-investigation chat.
