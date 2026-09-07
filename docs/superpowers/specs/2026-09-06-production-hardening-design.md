# AD-SIEM Production Hardening Design

## Goal

Move AD-SIEM from an integrated early-production SIEM into a defensible multi-tenant platform with enforceable security boundaries, repeatable releases, reliable enrichment and observability, complete investigation workflows, controlled data growth, and maintainable frontend modules.

## Delivery model

Work ships as five vertical sub-projects. Every sub-project includes backend behavior, tenant isolation, UI integration where applicable, automated tests, live-service verification, operational evidence, and a `CHANGELOG.md` entry. A sub-project may depend only on contracts completed by an earlier sub-project.

## Global constraints

- Every database query, Redis key, Elasticsearch query, export, service credential, and background job is scoped by tenant/group unless explicitly global and superadmin-only.
- Network destinations supplied by users are validated against an allowlist policy and resolved addresses; loopback, link-local, private, multicast, metadata, and rebinding targets are rejected unless an administrator explicitly allowlists them.
- Secrets are never returned in API responses, audit payloads, AI prompts, metrics labels, logs, exports, or reports.
- Destructive response actions require approval and idempotency protection.
- Existing Sigma, alert, case, SOAR, agent, and dashboard contracts remain compatible unless a versioned migration is included.
- No production-complete claim is allowed without focused tests, container health checks, and manual UI verification for changed surfaces.

## Sub-project 1: Security and governance

### Network egress protection

Introduce one reusable outbound-URL policy used by repository imports, webhooks, threat-intelligence callbacks, and operator-configured HTTP actions. Validation occurs before connection and after DNS resolution. Redirects are disabled by default; each redirect destination must pass the same validation when enabled. HTTP clients receive bounded connect/read timeouts and response-size limits.

### Authorization and tenant isolation

Define a machine-readable permission matrix for users, API keys, and service accounts. Route dependencies enforce permissions consistently. Negative tests exercise cross-group resource IDs and confirm `404` or `403` according to the endpoint’s disclosure policy. Background tasks receive an explicit group identifier instead of deriving it from mutable global state.

### Service identities and audit integrity

API keys are stored as hashes with a visible prefix, scoped permissions, tenant, expiry, last-used timestamp, and revocation state. Immutable audit rows include actor type/id, tenant, action, target, request correlation ID, timestamp, canonical payload hash, and previous-row hash per tenant. Verification reports broken chains without rewriting history.

### Acceptance criteria

- SSRF tests reject loopback, RFC1918, link-local, metadata endpoints, unsafe redirects, and DNS rebinding simulations.
- Cross-tenant negative tests cover every mutable resource route.
- A scoped API key can perform allowed reads, cannot escalate permissions, and stops working after revocation or expiry.
- Audit-chain verification succeeds for valid rows and detects a modified historical payload.

## Sub-project 2: CI and reliability

### Integration and release gates

CI starts PostgreSQL, Redis, and Elasticsearch containers, applies migrations, seeds a tenant fixture, runs API/worker integration tests, builds the dashboard, and performs contract checks against generated OpenAPI. Golden fixtures cover Sigma parsing/evaluation and decoder normalization. Security scanning and migration forward-compatibility are blocking gates.

### Runtime reliability

Define bounded retries with exponential backoff and jitter for ingestion, indexing, webhook, AI, and enrichment queues. Failed records enter typed dead-letter queues containing retry count, last error class, first/last failure time, tenant, and a reference to the original payload. Operator endpoints and UI expose queue depth, oldest age, retry, and discard actions with permissions and audit records.

### SLA escalation

Alert SLA policies are tenant-configurable by severity. A periodic worker emits approaching-breach and breached events once per threshold, routes them through configured email/Slack/Teams/webhook destinations, and records delivery state without leaking secrets.

### Acceptance criteria

- A clean CI run proves migrations, real-service integration, frontend build, Sigma/decoder goldens, and API contracts.
- Forced Elasticsearch, webhook, and AI failures show bounded retries and DLQ creation.
- SLA notifications are deduplicated and auditable.
- Metrics expose ingestion/indexing lag, queue depth/age, rule latency, dropped events, delivery failures, and worker saturation.

## Sub-project 3: Threat intelligence and OCSF

### Enrichment contract

All providers return a common result containing indicator, type, verdict, confidence, source, observed time, expiry, raw-reference identifier, and error status. Redis caches provider results by tenant/provider/indicator with provider-specific TTL. Stale cached data is clearly marked and may be used only when live enrichment fails.

### IOC propagation

Enrichment references attach to normalized events, alerts, rules created from indicators, and cases. Automatic rule creation remains disabled until an analyst approves the proposed rule. Case exports include attribution and observation timestamps.

### OCSF mapping

Create versioned mappers for Windows authentication/process events, Linux auth/audit, firewall/network, DNS, proxy/web, cloud audit, endpoint/FIM, and generic fallback logs. Each mapper emits class/category/activity IDs, canonical entities, source product metadata, severity, and unmapped-field diagnostics.

### Acceptance criteria

- Cache hit, expiry, stale fallback, confidence aggregation, and source attribution have deterministic tests.
- IOC pivots show the same canonical indicator across events, alerts, rules, and cases.
- Golden fixtures validate required OCSF fields for every supported log family.

## Sub-project 4: Investigation workspace

### Unified timeline and pivots

The case workspace merges alert, event, FIM, SOAR task, analyst note, enrichment, and provenance records into a cursor-paginated chronological feed. Entity pivots support IP, domain, URL, hash, user, host, process, and agent while preserving tenant scope and time-range context.

### Analyst state

Saved queries store a validated query document, owner, tenant, visibility, and timestamps. Bookmarks reference immutable entity/event IDs and optional analyst notes. Shared objects require explicit permissions.

### Chain-of-custody export

Incident exports contain a manifest, generated timestamp, tenant/case identifiers, source references, per-artifact SHA-256 hashes, audit-chain head, and report signature metadata. Export generation is asynchronous, permission-gated, and auditable.

### Acceptance criteria

- Timeline ordering and cursor pagination remain stable while new events arrive.
- Every pivot rejects foreign-tenant identifiers.
- Saved query/bookmark CRUD and sharing permissions are tested.
- Recomputing export hashes verifies an untouched package and detects tampering.

## Sub-project 5: Data lifecycle and frontend maintainability

### Data controls

Retention policies are configurable per tenant and data class. Elasticsearch index lifecycle policies provide hot/warm/delete phases; archive export is explicit and verifiable. PostgreSQL cleanup uses bounded batches. Storage quotas, query timeouts, maximum result windows, and cancellation protect shared resources.

### Frontend boundaries

Split large pages along existing product responsibilities. `HuntsPage` becomes IoC hunt, Sigma hunt, schedule, and history panels. `SoarPage` becomes playbook editor/list and execution panels. Shared API hooks own query keys, mutations, errors, and invalidation. UI behavior and accessibility remain unchanged except where the new feature requires new states.

### Acceptance criteria

- Tenant retention and quota tests prove isolation and bounded cleanup.
- ILM policy and query-limit behavior are verified against Elasticsearch.
- Refactored pages pass build and responsive visual QA at 375, 768, and 1280 pixels for empty, loading, error, populated, and interactive states.

## Execution order and dependency boundaries

1. Security/governance establishes identity, authorization, egress, and audit contracts.
2. CI/reliability makes those contracts continuously testable and observable.
3. TI/OCSF uses the security and retry foundations.
4. Investigation workspace consumes canonical events, enrichment, and audit provenance.
5. Data lifecycle and frontend extraction stabilize operating cost and maintainability after the feature contracts settle.

Each sub-project receives its own implementation plan and review gate. Work does not advance past a failed security, tenant-isolation, migration, build, or manual-QA gate.
