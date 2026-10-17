# LLM Gateway — Interface Spec

**Status:** design only — implementation blocked on the A/B/C architecture choice (see [Open Decision](#open-decision))
**Scope:** replaces the four duplicated 9router clients with one gateway per service
**Requirements:** provider fallback · unified retry/backoff · streaming · token/cost metrics · structured-output validation · tool calling · thinking/reasoning

---

## 1. Problem (verified against code)

Four call paths re-implement the same three concerns, with drifting behaviour:

| Client | Retry | Rate-limit cap | SSE-quirk parsing | Used by |
|---|---|---|---|---|
| `worker/worker/llm_client.py::_llm_post` | 4 attempts | wait `min(max(retry_after, delay), 20)` then delay doubles to **60** | `raw_decode` | ai_analyst, ai_consumer, campaign_analyzer, **hunter**, **report_sender** |
| `server-api/app/core/llm_client.py::_post_chat` | 3 attempts | `min(..., 20)` then delay doubles to **30** | `raw_decode` | assistant chat, report PDF |
| `worker/worker/ninerouter_search.py` | 0 (fail-fast) | — | `raw_decode` | hunter |

Concrete defects this causes:
- `hunter.py:16` and `report_sender.py:25` import **`_llm_post`** — a private symbol — across module boundaries. The worker's retry policy is now load-bearing for two callers that never opted into it.
- The 20-vs-60-vs-30 second cap inconsistency means the same 429 is handled differently depending on which entry point the alert arrived through.
- `ninerouter_search.py` has no retry at all, so a transient 429 silently degrades hunt results to the SearXNG fallback.
- No usage accounting anywhere: `usage` in the 9router response is discarded, so there is no way to answer "what did this cost" or "which model answered".

## 2. Required capability → why each is missing today

| Capability | Today | Needed because |
|---|---|---|
| Provider fallback chain | only `search` has it | a rate-limited `combo` currently degrades straight to the deterministic `_fallback_verdict` |
| Streaming | none (all calls `await` a full body) | `AssistantWidget.tsx` blocks on `api.post`; the user sees a spinner, not tokens |
| Token/cost metrics | none | `usage` is parsed away; no Prometheus counters for LLM calls |
| Structured-output validation | `json.loads()` after stripping code fences | a malformed model reply raises and falls back; no schema check, no repair |
| Tool calling | ad-hoc ReAct JSON loop in `assistant.py` | the assistant hand-rolls tool dispatch instead of the provider's native tool protocol |
| Thinking / reasoning | discarded | 9router models emit `reasoning_content` which is currently thrown away; the system prompt even compensates by asking for 2500 `max_tokens` of "headroom" |

## 3. Interface (language-neutral, maps 1:1 onto A/B/C)

Both services expose the same surface so call sites are identical:

```
complete(req) -> Completion
stream(req)   -> Iterator[Chunk]
```

### Request

| Field | Type | Notes |
|---|---|---|
| `messages` | `[{role, content}]` | `system` / `user` / `assistant` / `tool` |
| `model` | `string?` | defaults to the configured combo; overridden by `settings_cache` |
| `fallbacks` | `[string]` | ordered model/provider chain to try on rate-limit or 5xx |
| `temperature` | `float` | |
| `max_tokens` | `int` | reasoning models need real headroom — keep this explicit, not a fixed 2500 |
| `tools` | `[Tool]?` | `{name, description, parameters}` — passed through as the provider's native tool schema |
| `response_schema` | `Schema?` | if set, the gateway validates and repairs the JSON before returning |
| `stream` | `bool` | |

### Completion

| Field | Notes |
|---|---|
| `text` | final answer |
| `reasoning` | `reasoning_content`, exposed not discarded |
| `tool_calls` | `[{id, name, arguments}]` |
| `usage` | `{prompt_tokens, completion_tokens, total_tokens}` |
| `model_used` | which fallback actually answered |
| `attempts` | retry count, for metrics |

### Chunk (streaming)

Discriminated by `type`, mirroring the AI SDK's event names so a Node layer can forward verbatim:

`start` · `text-delta` · `reasoning-delta` · `tool-call` · `tool-input-delta` · `tool-result` · `finish` (carries `usage`) · `error`

## 4. Behaviour to specify once (currently four ways)

- **Retry:** one policy. Retry on 429 and 5xx. Read `retry-after`; cap the wait at a single configured ceiling.
- **Fallback:** on retry exhaustion for model *n*, advance to model *n+1*. Record `model_used` and emit a `fallback_used` metric.
- **SSE quirk:** 9router returns `text/event-stream` even for non-streaming requests — a JSON object followed by `data: [DONE]`. The gateway owns this parsing in exactly one place.
- **Structured output:** validate against `response_schema`; on failure attempt one repair pass; only then fall back.
- **Reasoning:** surface `reasoning_content` on the result rather than discarding it.
- **Empty body:** treat as retryable (the server-api client already does; the worker client does not).

## 5. Metrics

| Metric | Type | Labels |
|---|---|---|
| `siem_llm_requests_total` | counter | `service`, `model`, `outcome` (`ok`/`rate_limited`/`error`) |
| `siem_llm_tokens_total` | counter | `service`, `model`, `kind` (`prompt`/`completion`) |
| `siem_llm_latency_seconds` | histogram | `service`, `model` |
| `siem_llm_fallbacks_total` | counter | `service`, `from_model`, `to_model` |
| `siem_llm_cost_usd_total` | counter | `service`, `model` — only if a price table is configured |

`service` is `worker` or `server-api`, so the two per-service gateways are distinguishable in one dashboard.

## 6. Open Decision

AI SDK is TypeScript-only; there is no Python package. Its integration point is a Node runtime:

```typescript
createOpenAICompatible({ apiKey, baseURL: 'http://9router:20128/v1' })
streamText({ model, messages, tools }).toUIMessageStreamResponse({ sendReasoning: true })
```

The dashboard is a static SPA on nginx with no Node server, and FastAPI cannot host `streamText`. Pick one:

| | Shape | AI SDK | New service | Satisfies §3–§5 |
|---|---|---|---|---|
| **A** | Python gateway in worker + server-api; FastAPI SSE | no | no | yes |
| **B** | Node `llm-gateway` for the dashboard chat + Python gateway for worker | yes (dashboard) | yes | yes |
| **C** | Single Node gateway; worker also calls it over HTTP | yes | yes | yes |

- **A** — no new runtime or nginx route; removes the duplication and delivers all six capabilities. Not literally the AI SDK.
- **B** — the only shape where "AI SDK" is literally true *and* the worker's Python triage path stays as-is. Adds a container, Dockerfile, nginx route; the assistant moves off FastAPI.
- **C** — cleanest conceptually, largest change; the worker's LLM path becomes cross-service HTTP, which adds a failure mode to the detection pipeline.

§1–§5 apply unchanged to all three, so this spec can be reviewed before the choice is made. The only section that moves is §3's transport — `complete`/`stream` become either FastAPI endpoints or AI SDK routes.
