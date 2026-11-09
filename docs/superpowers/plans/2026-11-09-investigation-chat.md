# Investigation follow-up chat — implementation plan

Spec: docs/superpowers/specs/2026-11-09-investigation-chat-design.md

## Global Constraints

- server-api code under server-api/app; investigator runtime facts: `services/investigator.py` (`make_chat_model`, `investigation_model`, READ_ONLY_TOOLS, `_graph_config` in services/assistant.py, tools via `run_tool` in services/assistant_tools.py), ledger helpers in `services/investigation_ledger.py` (`record_evidence`).
- New tables only (create_all); no edits to existing table columns.
- Permissions: chat send `cases:manage`; IoC/evidence decisions `cases:manage`; endpoint decisions `agents:manage`; checked on the approver at decision time; superadmin bypass as `require_permission` does.
- Group scoping on every target (case group). Never trust tool args: validate server-side.
- No free shell tool. Limits per turn: ≤ 8 tool calls, ≤ 5 proposals, ≤ 90 s; history window 20 messages.
- Audit every decision/execution with `services/audit.audit_log`.
- Tests: server-api tests are `.int.py` with the `evidence_api`-style disposable schema fixtures; LLM faked with a scripted chat model (pattern: tests/server-api/test_investigator.int.py `Scripted`). CI pins pytest-asyncio 0.24 (use /tmp/adsiem-ci-venv); worker and server tests run in separate processes.
- Linux/Windows parity is not affected (server/dashboard only), but endpoint tasks must use the same task types the agent already supports on both OSes (isolate_host, unisolate_host, kill_process, quarantine_file, block_ip).
- Commit trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

### Test commands
```
export JWT_SECRET=ci-test-secret-0123456789abcdef0123456789abcdef TEST_DATABASE_URL=postgresql+asyncpg://soc:soc@localhost:55433/test DATABASE_URL=postgresql+asyncpg://soc:soc@localhost:55433/test
PY=/tmp/adsiem-ci-venv/bin/python
$PY -m pytest tests/server-api tests/evidence -q -p no:cacheprovider
$PY -m pytest tests/worker worker/tests -q -p no:cacheprovider --ignore=tests/worker/test_pipeline.int.test.py --deselect worker/tests/test_rag.py::test_embed_text_returns_384_dimensions --deselect worker/tests/test_rag.py::test_embed_text_different_inputs_differ
cd dashboard && npx tsc --noEmit -p . && npx vite build
```

---

### Task 1: Data model, chat turn engine, chat routes (server-api)

Files: `server-api/app/models/models.py` (InvestigationMessage, InvestigationChatAction per spec "Data"), new `server-api/app/services/investigation_chat.py`, new `server-api/app/api/routes/investigation_chat.py` (registered in main.py), tests `tests/server-api/test_investigation_chat.int.py`.

- `run_turn(db, inv, user, text) -> (messages, actions)`: builds context (spec Behaviour 2), binds read tools (READ_ONLY_TOOLS via run_tool + list_evidence/get_evidence/list_hypotheses/case_iocs; `ti_lookup` is added in Task 3 — leave a hook) and the proposal tools (spec list); proposal tools validate args (Task 2 provides validators; here: shape checks) and insert `investigation_chat_actions` rows with status `proposed`, returning "proposed, awaiting analyst approval" to the model. Enforce limits. Persist the user message, assistant reply (text) and tool calls.
- Model: `investigation_model(db, default)` over `_graph_config`; 422 when no api key. Use `make_chat_model` and `bind_tools`; reuse the investigator's text-tool-call fallback if the provider returns tool calls in text.
- Routes: GET/POST `/api/investigations/{id}/chat` (spec API), 409 while queued/running, scoped by group, `cases:manage` for POST, `alerts:read` for GET.
- Tests: scripted model proposing an isolate + reading evidence → one proposal row, assistant text saved; limits (9th tool call refused, 6th proposal refused); 409 on running investigation; group isolation (other group's investigation 404); 422 without provider.

Commit: `feat(investigations): follow-up chat after a run — messages, proposals, routes`.

### Task 2: Decision route and executors (server-api)

Files: `server-api/app/services/investigation_chat_actions.py` (validators + executors), decision route in `routes/investigation_chat.py`, refactor `routes/web_protection.py::_block_one` into `services/web_blocks.py::block_domain(db, user, group, value, reason, expires_at)` (route keeps behaviour, now calls the service), tests `tests/server-api/test_investigation_chat_actions.int.py`.

- `POST /api/investigation-chat-actions/{id}/decision {approve, note}`: atomic `proposed → approved|rejected` (409 otherwise); permission per tool class on the approver (403); re-validate; execute; store `result`/`error`, status `executed|failed`; append a `system` chat message with the outcome; audit (`ai_chat_action_*`). Expire proposals older than 24 h on read.
- Executors (reuse existing paths): pin_evidence (InvestigationEvidence.pinned); add_case_ioc/remove_case_ioc (Case.ioc_data["ioc_keys"] as "type:value", normalised, dedup); add_threat_ioc (ES doc per spec "Threat IoCs" through `core/es_client` — add an index/delete helper there; remove_case_ioc deletes the case-scoped doc); isolate/unisolate (same as agents.py routes: online check, is_isolated, AgentTask); block_domain (service above, source "manual", reason prefixed "AI chat:"); block_ip (AgentTask block_ip {ip, duration_seconds ∈ {3600,86400,604800}, case_id} per agent, public IPs only, ≤ 20 agents, agents in case group); kill_process (AgentTask kill_process {pid}); quarantine_file (AgentTask quarantine_file {path}, absolute path); run_live_response (`routes/flows.schedule_flow` with an enabled artifact; store flow_id; GET chat resolves flow status/row count).
- Tests: each executor happy path (task/doc/row created with exact params) and refusal (wrong group, offline agent, private IP, bad path, unknown artifact, already decided 409); approver without agents:manage gets 403 for isolate but can approve add_case_ioc with cases:manage; audit rows; web-protection route tests still pass after the refactor.

Commit: `feat(investigations): approve chat proposals and run them through the existing response paths`.

### Task 3: TI lookup bridge (worker + server)

Files: worker `worker/worker/ti_lookup.py` (loop over Redis list `siem:ti:lookup`, `EnrichmentAggregator(_build_ti_config()).enrich(value)` → `siem:ti:result:<id>` JSON TTL 600 s; bounded concurrency, never crashes the loop; registered in worker main gather via `_supervise`), server `services/investigation_chat.py` `ti_lookup` tool (push + wait ≤ 25 s polling, else "pending"), record evidence `ti_result` via ledger. Tests: worker unit test with a fake aggregator and fake redis; server test with fake redis that has the result / times out.

Commit: `feat(ti): on-demand TI lookups for the investigation chat`.

### Task 4: Dashboard chat tab

Files: `dashboard/src/components/AiInvestigationPanel.tsx` (5th tab "Chat", shown when the run is not active), new `dashboard/src/components/InvestigationChat.tsx`, hook in `dashboard/src/hooks/useInvestigationLedger.ts` or new `useInvestigationChat.ts`.

- Message list (markdown for assistant), proposal cards (tool label, target, params summary, reason, status, result/error; Approve/Reject buttons when `proposed`; disabled with a tooltip when the user lacks the permission — decide by role like other pages: endpoint actions need admin+), input box with send (disabled while a turn runs), polling while a turn is pending or a flow is running, error toasts. Update the panel help text.
- `npx tsc --noEmit` and `vite build` clean.

Commit: `feat(dashboard): follow-up chat in the AI investigation panel`.
