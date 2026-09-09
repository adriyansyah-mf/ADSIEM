# Ironwatch AI-SIEM UI/UX Design

## Status and scope

Status: proposed design contract, awaiting user review. This document changes no runtime behavior.

This design turns AD-SIEM from a collection of security feature pages into an AI-first security operations workspace. It covers the dashboard shell, four priority workflows, component rules, and the UI data required by the endpoint-agent production roadmap.

The work is intentionally phased. It does not redesign every existing page in one release, and it does not introduce autonomous destructive response actions.

## 1. Product decision

### Chosen direction: Ironwatch industrial SOC

Ironwatch uses compact gunmetal surfaces, a rationed steel-blue interactive accent, and copper only for urgent attention. It rejects blur, glow, and decorative cyberpunk effects. This better supports long-running SOC work than the existing navy-glass direction: hierarchy comes from layout, typography, borders, and sparse semantic color rather than translucent decoration.

The existing `DESIGN.md` navy-glass contract and the current Ironwatch implementation notes conflict. Before frontend implementation begins, `DESIGN.md` must be reconciled to this specification so a single source of truth governs all touched components.

### Product promise

An analyst should be able to answer these questions without switching between disconnected pages:

1. What needs attention now?
2. Why does it matter and what evidence supports it?
3. What is the safest next action?
4. What happened after that action?

AI assists at every step but cannot obscure evidence, invent certainty, or execute destructive work without the existing approval boundary.

## 2. Users and jobs

| User | Primary job | Information needed first |
|---|---|---|
| L1 analyst | Triage a fresh alert quickly | severity, confidence, affected entity, recommended next step, related evidence |
| L2 investigator | Build an incident narrative | timeline, pivots, Sigma/correlation context, enrichment, analyst notes, case ownership |
| Incident lead | Coordinate containment and escalation | priority queue, case state, approvals, SLA risk, assignment, response progress |
| Platform administrator | Keep telemetry trustworthy | agent health, ingestion lag, policy/version drift, collector coverage, audit status |

## 3. Information architecture

The primary navigation follows the analyst workflow rather than backend feature taxonomy.

```text
Command Center
Detection
  Alerts · Events · Hunts · Rules
Investigation
  Cases · Entities · Threat Intelligence
Agent Fleet
  Fleet · Live Response · FIM · Hygiene · Artifacts
Automation
  Playbooks · Executions · Approvals
Governance
  Audit · Users · API Keys · Integrations · Settings
```

Role and permission checks continue to decide visibility. Hiding a navigation item never replaces API authorization.

### Shell anatomy

Desktop uses three stable zones:

```text
┌──────────────┬─────────────────────────────────────────────┬─────────────────────┐
│ Navigation   │ Primary workspace                           │ Context rail        │
│ 216 px       │ fluid, 12-column grid                       │ 320 px, contextual  │
│              │                                             │                     │
│ workflow     │ page header + decision-oriented content     │ AI evidence/action  │
│ groups       │                                             │ or details          │
└──────────────┴─────────────────────────────────────────────┴─────────────────────┘
```

The context rail is present only when it adds decision value. On 768px it becomes a collapsible panel; at 375px it becomes an explicit, keyboard-accessible bottom sheet. It must never create page-level horizontal scrolling.

The top bar contains a global entity command palette, time range, system-connection state, and identity/menu controls. Search accepts IP, hostname, user, hash, agent, alert, and case identifiers, then routes to the appropriate detail workspace.

## 4. Priority workflows

### 4.1 Command Center

The Command Center is the landing surface, answering “what needs action now?” before showing broad analytics.

1. **AI Situation Brief** — top of page; concise observed changes, cited alert/case IDs, confidence, and a link to evidence. It has loading, unavailable, stale, and error states.
2. **Priority Queue** — ranked actionable alerts/cases with severity, SLA state, owner, entity, detection source, AI confidence, and a single clear next action.
3. **Operational Health** — ingestion lag, queue age/depth, detector health, delivery failures, and fleet health. Every degraded state links to its diagnosis.
4. **Exposure and Coverage** — high-risk entities, active campaigns/correlations, MITRE coverage gaps, and agents with source/policy drift.

Charts are summaries, never the sole way to understand urgency. All chart values have adjacent readable text/table alternatives.

### 4.2 Alert Investigation

An alert opens an investigation workspace instead of a modal-only experience.

| Region | Content | Decision supported |
|---|---|---|
| Header | severity, state, owner, SLA, source rule, affected entity, action cluster | establish responsibility and urgency |
| Evidence timeline | alert/event/FIM/task/IOC items in time order | understand sequence and causality |
| Entity context | IP, host, user, hash, related alerts/cases, UEBA and TI | pivot and scope blast radius |
| AI context rail | cited summary, confidence, hypotheses, recommended actions | decide what to do next |

Every AI statement that claims a fact links to one or more visible evidence items. A recommendation exposes impact, required permission, approval state, and rollback availability before the action control appears.

### 4.3 Agent Fleet

Agent Fleet turns the endpoint agent into an observable product surface, aligned with `docs/AGENT_PRODUCTION_IMPROVEMENT_ROADMAP.md`.

Fleet overview metrics:

- healthy, degraded, offline, and untrusted agents;
- ingestion lag and oldest buffered-event age;
- spool fullness/loss, collector failures, stale certificates, and version/config drift;
- pending or failed response tasks; and
- source coverage by environment and collector type.

The agent list defaults to health risk, not alphabetical order. Each row has an explainable health score, last acknowledged event, spool state, current version, policy/config hash, capabilities, and limited context-sensitive actions.

Agent detail uses tabs only when each tab is independently valuable: Overview, Delivery, Collectors, Hygiene/FIM, Tasks, and Audit. Its timeline combines configuration changes, telemetry degradation, acknowledgement gaps, response-task transitions, and remediation actions.

### 4.4 Automation and Governance

The Automation workspace separates *definition* from *execution*:

- Playbooks: trigger, permissions, expected scope, destructive-action marker, rollback support.
- Executions: step timeline, approval state, target count, output/artifact hashes, retry and rollback status.
- Approval inbox: requested action, evidence, target/scope, risk, requester, expiry, and approver decision.

Governance gives administrators audit-chain health, API/service account context, integration status, policy drift, retention state, and key security warnings. It must not overload operational triage pages.

## 5. Visual and component contract

### Tokens

The reconciled design system uses these semantic roles, rather than component-local hex values:

| Role | Token direction | Usage |
|---|---|---|
| Canvas | deep gunmetal | application background |
| Surface | graphite panel | workspace and data region |
| Elevated surface | lighter steel panel | menus, sheets, dialogs |
| Interactive accent | steel blue | focus, links, selected controls, primary action |
| Attention-now | copper | urgent non-severity operational attention only |
| Severity/health | semantic ramp | labeled critical/high/medium/low and health states |
| Data text | JetBrains Mono | timestamps, hashes, IDs, query/code snippets |

Typography: Archivo for compact headings, Public Sans for UI/body, and JetBrains Mono for technical data. Use tabular numerals for counts and time. Decorative type, glow, gradients, and glass effects are out of scope.

### Reusable primitives

- `AppShell`, `WorkflowSidebar`, `OperationalTopbar`, and `EntityCommandPalette`;
- `PageHeader`, `StatusStrip`, `MetricCard`, and `DataTable`;
- `SeverityBadge`, `HealthBadge`, `ConfidenceBadge`, and `ApprovalStateBadge`;
- `EvidenceTimeline`, `EntitySummary`, `ActionReviewSheet`, and `AiRecommendationCard`;
- `AgentHealthScore`, `CollectorStateList`, `SpoolState`, and `DriftIndicator`.

Each primitive has default, hover, focus-visible, disabled, loading, empty, error, and reduced-motion behavior where relevant. New source files stay below the project's 250 pure-line limit; `Layout.tsx` must be decomposed by responsibility before adding further shell behavior.

## 6. Safety, accessibility, and responsiveness

- WCAG 2.2 AA; all interactive controls have a visible 2px focus treatment.
- Semantic color is always paired with text/icon/shape; severity and health cannot rely on color alone.
- Minimum 44 × 44 touch targets on narrow layouts.
- Keyboard flow: skip link → navigation → top-bar search → page header actions → main content → context rail.
- Tables own a labelled horizontal scroll region on narrow screens; the page itself never scrolls horizontally.
- `prefers-reduced-motion` removes non-essential animation; all state changes remain visible.
- Breakpoints are verified at 375px, 768px, 1280px, and 200% zoom.

## 7. AI interaction rules

1. AI summaries distinguish observation, inference, uncertainty, and recommended action.
2. Every factual claim cites on-screen evidence or clearly says it is unavailable.
3. AI never changes alert/case state or dispatches response work as a side effect of chat.
4. Action cards show target count, blast radius, approval requirement, required permission, expiry, and rollback capability.
5. A failed, delayed, or unavailable AI provider degrades to a clear status; it never hides manual investigation controls.

## 8. Phased delivery

| Phase | Deliverable | Dependencies |
|---|---|---|
| 1 | Reconcile `DESIGN.md`, tokens, shell primitives, and command palette | existing dashboard APIs |
| 2 | Command Center with priority queue and operational-health states | existing alerts/metrics/agent APIs; explicit empty/error behavior |
| 3 | Investigation workspace and AI evidence rail | case timeline, entity pivots, assistant context |
| 4 | Agent Fleet overview/detail | P0 agent telemetry API contract |
| 5 | Automation/approval workspace | SOAR execution lifecycle and task-runner repair |
| 6 | Remaining pages adopt primitives; full responsive/accessibility visual sweep | preceding reusable primitives |

## 9. Verification contract

Every phase requires:

1. Type check and production build.
2. API contract coverage for any new data state.
3. Real-browser visual QA at 375px, 768px, and 1280px covering loading, error, empty, populated, focused, and action-review states.
4. Keyboard-only and reduced-motion checks for each new interactive surface.
5. Evidence that AI unavailable/stale/error states preserve manual SOC workflow.
6. `CHANGELOG.md` and `docs/IMPLEMENTATION_STATUS.md` updates stating what changed, what remains, and where verification evidence lives.

## 10. Explicit non-goals

- A dashboard-wide rewrite before core workflow surfaces prove useful.
- Replacing existing RBAC/tenant guards with client-side checks.
- Requiring AI availability to investigate or close an incident.
- Introducing a generic remote shell or autonomous destructive remediation.
- Fabricating operational trend data where the backend does not provide it.
