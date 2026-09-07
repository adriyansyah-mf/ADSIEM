# Code Quality Review — P0 production detection / Task 1

## Scope and evidence inspected

- Goal and success criteria: `.superpowers/sdd/2026-09-06-p0-production-detection/task-1-brief.md`; `docs/superpowers/specs/2026-09-06-p0-production-detection-design.md`; Task 1 plan.
- Reviewed production files: `worker/worker/correlation_engine.py`, `worker/worker/correlation_models.py`, and the Task 1 changes in `worker/worker/consumer.py`.
- Reviewed tests: `tests/worker/test_correlation_engine.py`.
- Reviewed runtime composition: `worker/worker/main.py`.
- Reviewed claimed evidence: `.superpowers/sdd/2026-09-06-p0-production-detection/progress.md`. `omo ulw-loop status --json` reported `ULW_LOOP_PLAN_MISSING`, so the normal attempt directory was unavailable and this fallback artifact is used.

## Independent checks

- `pytest -q tests/worker/test_correlation_engine.py` — PASS: 5 passed in 0.21s.
- `python -m compileall -q worker/worker/correlation_engine.py worker/worker/correlation_models.py worker/worker/consumer.py` — PASS.
- No Task 1 Redis-container smoke-test command, output, or artifact was found. The only claim of completion in the progress ledger has no artifact path and does not substantiate the required Redis smoke test.

## Skill-perspective check

Ran: yes. I loaded and applied `omo:remove-ai-slops` and `omo:programming` (including its Python reference).

- `remove-ai-slops`: production code is within the 250 pure-LOC limit and has no deletion-only or tautological test. However, the in-memory Redis fake leaves the behavior that needs the most protection—`WATCH` conflict retries and Redis TTL—uncovered.
- `programming`: the models are immutable typed dataclasses and no untyped escape hatch was introduced in the new engine. The diff violates the test/real-adapter perspective because the only adapter test double deliberately does not implement expiry or optimistic-concurrency behavior, and the required runtime wiring is not covered.

## Findings

### CRITICAL

None.

### HIGH

1. **The correlation engine is never enabled in the running worker.** `process_message` evaluates definitions only when its optional `correlations` argument is non-null ([consumer.py](/home/wonka/Documents/ADSIEM/worker/worker/consumer.py:123)). Normal startup builds `state` with only `dec_engine` and `sig_engine` ([main.py](/home/wonka/Documents/ADSIEM/worker/worker/main.py:132)); `consume_loop` therefore passes `None` through to `process_message` ([consumer.py](/home/wonka/Documents/ADSIEM/worker/worker/consumer.py:168)). No code constructs a `CorrelationEngine` or loads any `CorrelationDefinition`. Consequently, normalized production events never enter the new Redis state engine, failing Task 1's required wiring.

2. **The required real-Redis verification is absent, and the unit fake cannot verify the claimed properties.** Task 1 explicitly requires a Redis-container smoke test, but no evidence exists. The fake discards `WATCH` keys ([test_correlation_engine.py](/home/wonka/Documents/ADSIEM/tests/worker/test_correlation_engine.py:25)) and `px` TTLs ([test_correlation_engine.py](/home/wonka/Documents/ADSIEM/tests/worker/test_correlation_engine.py:31)), so the green suite cannot detect a broken optimistic-concurrency retry or expiry. The progress ledger nonetheless labels Task 1 “complete” ([progress.md](/home/wonka/Documents/ADSIEM/.superpowers/sdd/2026-09-06-p0-production-detection/progress.md:23)) without a Redis-smoke artifact path. This is insufficient and misleading success evidence for a required criterion.

### MEDIUM

1. **Malformed definitions fail unpredictably or silently rather than being rejected at a configuration boundary.** A runtime `Literal` does not validate `mode`; the `match` in `_advance` has no fallback ([correlation_engine.py](/home/wonka/Documents/ADSIEM/worker/worker/correlation_engine.py:143)), so an invalid mode returns `None` and silently disables correlation. Empty `stages` makes sequence evaluation index `definition.stages[count]` ([correlation_engine.py](/home/wonka/Documents/ADSIEM/worker/worker/correlation_engine.py:146)), and non-positive windows are not rejected. Since definitions are declarative configuration, these conditions should be parsed/validated before evaluation. Tests cover none of them.

2. **The test suite has no tenant-isolation or consumer-wiring scenario.** The Redis key implementation does put the tenant in the key prefix ([correlation_engine.py](/home/wonka/Documents/ADSIEM/worker/worker/correlation_engine.py:205)), which is the correct mechanism, but the test only exercises one tenant and unit-tests `evaluate` directly. It does not establish that a normalized event from tenant B cannot complete tenant A's state, nor that `process_message` supplies normalized data to an active engine while leaving Sigma behavior intact. This creates false confidence around the two Task 1 integration requirements.

### LOW

None.

## Verdict

- `codeQualityStatus`: **BLOCK**
- `recommendation`: **REQUEST_CHANGES**
- `blockers`:
  1. Construct/load the correlation runtime in the normal worker startup/reload path and pass it in state so `process_message` evaluates definitions in production.
  2. Add and preserve artifact-backed real-Redis smoke coverage for TTL and `WATCH`/concurrency behavior; do not represent the Task as complete without that evidence.

---

## Re-review after runtime and smoke-report updates

**New evidence inspected:** `worker/worker/main.py`, the running `siem-platform-worker-1` container, and `reports/p0-correlation-redis-smoke-2026-09-06.md`. The container's `/app/worker/main.py` contains the new runtime tuple, and the focused test suite remains green (5 passed). The image and container share the same image ID.

### CRITICAL

None.

### HIGH

1. **Production correlation remains disabled because startup supplies no definitions.** The new runtime is `(CorrelationEngine(redis), ())` ([main.py](/home/wonka/Documents/ADSIEM/worker/worker/main.py:137)). `process_message` obtains that tuple but can only evaluate inside `for definition in definitions` ([consumer.py](/home/wonka/Documents/ADSIEM/worker/worker/consumer.py:123)); with the literal empty tuple it always executes zero iterations. A repository-wide search found no other construction or loading path for `CorrelationDefinition`. This repairs object reachability only; it does not wire any normalized production event into an actual correlation definition, so the Task 1 behavior remains unavailable.

### MEDIUM

1. **The live-Redis report is a claim summary, not reproducible verification evidence for the risk it is meant to cover.** It records only a two-stage success assertion ([p0-correlation-redis-smoke-2026-09-06.md](/home/wonka/Documents/ADSIEM/reports/p0-correlation-redis-smoke-2026-09-06.md:1)) and contains no command, timestamped output, key/TTL observation, or concurrent contender result. It therefore cannot substantiate the required atomic-expiry/concurrency behavior. The in-memory tests still ignore both `WATCH` and `px` TTLs ([test_correlation_engine.py](/home/wonka/Documents/ADSIEM/tests/worker/test_correlation_engine.py:25), [test_correlation_engine.py](/home/wonka/Documents/ADSIEM/tests/worker/test_correlation_engine.py:31)).

2. **Definition validation remains absent.** Invalid `mode`, empty stages, and non-positive windows are not parsed at a configuration boundary. In particular, a sequence definition dereferences the first stage ([correlation_engine.py](/home/wonka/Documents/ADSIEM/worker/worker/correlation_engine.py:148)) while an invalid mode silently falls through the `match` ([correlation_engine.py](/home/wonka/Documents/ADSIEM/worker/worker/correlation_engine.py:145)).

### LOW

1. `REDIS_STREAM_KEY` is imported but unused in [main.py](/home/wonka/Documents/ADSIEM/worker/worker/main.py:11).

### Final re-review verdict

- `codeQualityStatus`: **BLOCK**
- `recommendation`: **REQUEST_CHANGES**
- `blockers`:
  1. Supply validated, enabled `CorrelationDefinition` values through the normal startup/reload path; replacing the empty tuple is required before correlation can work.
  2. Produce executable real-Redis evidence that covers at least state TTL and concurrent `WATCH` retry behavior, with output/artifact paths.

---

## Final re-review after definition-loader change

**Skill-perspective check:** previously run and still applicable (`omo:remove-ai-slops` and `omo:programming`, including Python guidance). The new parser is a justified configuration-boundary validation, not needless production parsing; its tests assert observable parsed/rejected configuration, not prose or implementation constants. No new slop violation was found.

### CRITICAL

None.

### HIGH

1. **The actual worker deployment is stale and still runs the disabled implementation.** The live `siem-platform-worker-1` container's `/app/worker/main.py` still sets `"correlations": (CorrelationEngine(redis), ())` at line 137 and does not contain `load_correlation_definitions`. Its `/app/worker/main.py` SHA-256 (`217fa...91242b`) and `/app/worker/correlation_engine.py` SHA-256 (`72b493...51399`) differ from the current worktree (`0a59c...237c83` and `664be...038fb`). The container is not bind-mounted to `./worker/worker`, so it cannot receive these source edits until a new image is built and the service recreated. This invalidates the earlier rebuilt-image/smoke assertion for the current Task 1 code and leaves production correlation disabled.

### MEDIUM

1. **A setting update will not take effect until worker restart.** Definitions are loaded once during startup ([main.py](/home/wonka/Documents/ADSIEM/worker/worker/main.py:135)), but the existing reload loop reloads only decoders and Sigma rules ([consumer.py](/home/wonka/Documents/ADSIEM/worker/worker/consumer.py:210)). This does not block Task 1's backend contract; whether live configuration refresh is required belongs to the Task 5 UI/configuration decision. If Task 5 promises live edits, it must extend the reload path and add a corresponding integration test.

2. **The checked-in Redis smoke report still lacks reproducible command output for TTL and optimistic-concurrency behavior.** It documents only a two-stage real-Redis result ([p0-correlation-redis-smoke-2026-09-06.md](/home/wonka/Documents/ADSIEM/reports/p0-correlation-redis-smoke-2026-09-06.md:1)). This is not a source-code approval blocker once the updated image is rebuilt, but it is insufficient evidence for the explicitly required atomic-expiry claim.

### LOW

1. `REDIS_STREAM_KEY` remains unused in [main.py](/home/wonka/Documents/ADSIEM/worker/worker/main.py:11).

### Final verdict

- `codeQualityStatus`: **BLOCK**
- `recommendation`: **REQUEST_CHANGES**
- `blockers`:
  1. Rebuild/recreate the worker from the current worktree, then verify the container has the same hashes (or at least the loader and non-empty configured definitions) before claiming production reachability.
  2. Re-run and retain reproducible real-Redis smoke evidence for the deployed revision, including TTL and concurrent `WATCH` behavior.

**Verified current-source evidence:** `pytest -q tests/worker/test_correlation_engine.py` passed, 7 tests in 0.29s; `compileall` passed. The source parser loads and validates `correlation_definitions` from `platform_settings`. UI/configuration authoring itself is deferred to Task 5 as requested.
