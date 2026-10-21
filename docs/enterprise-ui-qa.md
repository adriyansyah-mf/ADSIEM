# Enterprise workspace — first implementation

Date: 2026-10-21. Branch: `feat/enterprise-ui`.

## Implemented scope

Shared tokens, navigation shell, common table/badges/query states, Operations
overview, Alerts queue and case-detail presentation. Specialized screens retain
their workflows and inherit the foundation; they are not a completed redesign.
The visual direction and reusable component contract are recorded in `DESIGN.md`.

## Verification

- `npm run build -- --outDir /tmp/adsiem-enterprise-build-20261021`: passed,
  including TypeScript project checking. Vite still warns about the large main
  bundle (approximately 1.89 MB before gzip); bundle splitting is not part of this change.
- `DASHBOARD_TEST_URL=http://127.0.0.1:44791 python -m pytest
  tests/dashboard/test_enterprise_ui.py -q
  --basetemp=/tmp/adsiem-enterprise-final-evidence`: **20 passed**.
- `git diff --check`: passed.

The browser tests ran against the actual production build served locally, with
all HTTP API requests intercepted by synthetic fixtures. No production database,
endpoint agent, enrollment, case response action or real analyst account was modified.
To repeat, serve the dashboard locally and set `DASHBOARD_TEST_URL` accordingly;
the test suite supplies its own API fixtures.

## Coverage and findings

- Overview, Alerts and case detail: 390, 768, 1440 and 1920 CSS-pixel widths;
  initial and end-of-scroll PNGs. No document or main-content horizontal overflow.
  Large tables retain their own horizontal scrolling.
- Verified URL severity/search filters, compact row density, column visibility,
  keyboard row opening, mobile navigation Escape/focus return, empty/error states,
  aggregate metric values, global search dismissal, and search browser-history restoration.
- Light and dark OS preference both retain the intentional dark-only workspace.
  Reduced-motion preference is included in browser coverage.
- An actual Alerts overflow at phone/tablet widths was caught and fixed by
  allowing workspace grid children to shrink. Tests failed before that fix.
- Initial test selector mistakes and an incomplete timestamp fixture were fixed
  in the test harness, not hidden by weakening production error checks.

Fresh screenshot evidence is in `/tmp/adsiem-enterprise-final-evidence/`, grouped
by pytest test identifier. Temporary evidence is not committed as product assets.
Earlier omowright captures labelled as phone were rejected: this installed
agent-tab helper kept re-pinning 1440px. Responsive evidence above was regenerated
using Playwright Chromium with measured viewport widths and assertions.

## Limits / follow-up

This is targeted fixture-backed verification, not a full application QA or WCAG
certification. Other routes sharing the shell/table have not received exhaustive
visual and workflow testing. Real backend integration, WebSocket reconnection,
TI provider calls, AI investigation and destructive response operations were not
exercised. No independent reviewer or pixel-reference comparison was used.
No release, deployment, commit or push was performed.

## Second implementation — Cases and Agents

Continued on the same branch on 2026-10-21:

- Cases now uses the shared table, severity/status badges, named filters and URL
  state. Server-filtered totals replace the misleading page-local open/escalated
  counts. Expandable rows preserve assignment, escalation and closing; closing
  requires confirmation naming the case. Viewer users do not receive mutation controls.
- Agents now uses the same list system. Endpoint connection, approval and isolation
  states remain separate. Expandable response actions keep telemetry rows compact.
  Approving, isolating and lifting isolation require a named-host confirmation;
  failed requests remain retryable. No endpoint API contract was changed.
- `WorkspaceDialog` provides native focus containment, Escape and focus return.
  Deployment and sensitive uninstall-token dialogs use it; deployment grids reflow
  on phones. Token retrieval stays opt-in and uncached after unmount.
- `useWorkspaceFilters` keeps new list filters shareable and restores search when
  navigating browser history. Existing Alerts behavior is retained.

Fresh verification against `/tmp/adsiem-enterprise-stage2-build`:

```text
npm run build -- --outDir /tmp/adsiem-enterprise-stage2-build
PASS (TypeScript + Vite; the existing large-main-bundle warning remains)

DASHBOARD_TEST_URL=http://127.0.0.1:33341 python -m pytest \
  tests/dashboard/test_enterprise_ui.py -q --tb=short \
  --basetemp=/tmp/adsiem-ui-stage2-final
46 passed in 65.40s

check-accent-stripes: 7 file(s), no accent stripes
git diff --check: PASS
```

The cases deep-link regression was also run against the prior production build
and failed on the missing filter state before passing against this implementation.
The suite intercepts the exact origin's `/api/` prefix; a broad glob also matched
Vite's `/src/api/client.ts` during an early development run and was corrected.
Final evidence is from an immutable production build, not concurrent HMR edits.

PNG evidence: `/tmp/adsiem-ui-stage2-final/`. It includes the five primary routes
(overview, Alerts, case detail, Cases, Agents) at 390/768/1440/1920px with end-scroll
captures; desktop/phone deployment, token, isolation and case-closing dialogs;
and empty/error list states. Screenshots were visually inspected for the new list
and modal layouts. All accounts, tokens, network operations and endpoint state in
this verification are synthetic fixtures.

Limits remain: no real endpoint response, real token retrieval or backend
integration was exercised. Approval and lift-isolation use the existing routes
but their full endpoint lifecycle was not tested here. This is not a Lighthouse,
whole-application, independent-review or WCAG-certification pass. Specialized
pages outside the five listed routes still need a dedicated redesign/review.
No dependencies, backend code, release artifacts or deployment were changed in
this second implementation. Changes remain uncommitted.

## Third implementation — Logs and Events

Continued on the same branch on 2026-10-21, following the existing `DESIGN.md`
tokens and investigation-workspace direction:

- Shared `TelemetryExplorer` now provides explicit Lucene search, `?q=` deep
  links/history restoration, named advanced filters and the existing 15-second
  polling. Draft filter edits are separate from the applied query.
- Sequential pagination follows the server's `next_after`, not total-based page
  estimates. New searches/filter trees reset the cursor chain, page-size choices
  survive query changes, and placeholder responses cannot seed another page's
  cursor. Existing Logs/Events hooks delegate to the shared query implementation.
- Read-only evidence dialogs expose complete original messages or decoded JSON,
  metadata and timestamps. Long unbroken content wraps without changing the data.
  Keyboard Enter opens rows; Escape closes and restores focus. Preventing the
  row's default Enter action fixes an observed immediate close-button activation.
- Empty/error states preserve the query; retry, refresh, density, column selection
  and current-page CSV export remain available. CSV column keys now match API
  field names rather than presentation aliases.

The Lucene-search regression failed against the prior stage's production build
before passing against this implementation. Initial modal-keyboard failures were
reproduced and fixed; a test selector was separately corrected because inputs
with a datalist have the combobox role, not textbox.

Fresh verification against `/tmp/adsiem-enterprise-stage3-build`:

```text
npm run build -- --outDir /tmp/adsiem-enterprise-stage3-build
PASS (TypeScript + Vite; existing large-main-bundle warning)

DASHBOARD_TEST_URL=http://127.0.0.1:41433 python -m pytest \
  tests/dashboard/test_enterprise_ui.py -q --tb=short \
  --basetemp=/tmp/adsiem-ui-stage3-final
71 passed in 83.59s

check-accent-stripes: 5 file(s), no accent stripes
git diff --check: PASS
```

PNG evidence: `/tmp/adsiem-ui-stage3-final/`. The seven primary routes are captured
at 390/768/1440/1920px, with end-scroll captures; Logs/Events evidence dialogs are
also covered at 390/1440px, including end-of-content, and advanced filters at 390px.
Logs/Events desktop/phone screens and dialog/filter captures were visually
inspected. Existing responsive assertions check document/main overflow; dialogs
also check their own horizontal overflow.

All HTTP API traffic in these browser tests is intercepted by synthetic fixtures.
No real Elasticsearch search, backend integration, agent response or production
data was exercised. Other specialized pages remain outside dedicated redesign
coverage. The existing approximately 1.89 MB main-bundle warning remains; this is
not a bundle-performance, Lighthouse, full-app or WCAG-certification pass. No
dependencies, backend API contracts, release artifacts or deployment were changed.
Changes remain uncommitted; no push was performed.

## Fourth implementation — Threat hunting

Continued after the approved enterprise foundation was pushed as `f2de8cf`.
This stage applies the same token system to `/hunts` only:

- Labelled IOC submission trims input, rejects whitespace, preserves failed
  drafts, and locks fields during a pending request. Existing IOC types and API
  contracts are unchanged.
- Scheduled hunts use the common table and separate enabled/paused status.
  Creation has a labelled, responsive form and whole-hour interval validation
  (1–168 hours, retaining the previous UI range). Pause/resume keeps the existing
  endpoint; deletion names the schedule, requires confirmation, retains prior
  results, and keeps failed requests retryable inside the dialog.
- Recent hunts describe the API's latest-50 window rather than an inferred
  system-wide total. Status and risk are separate. Keyboard row opening exposes
  read-only AI analysis, MITRE, recommendations, timestamps, FIM counts and full
  wrapping evidence. Open details follow the existing eight-second list polling.
  Malformed analysis is shown as original text; unexpected structured field
  types do not crash the view. AI assessment is explicitly labelled for review.
  CSV evidence values include alert, event and FIM counts rather than exporting
  only the first backing field.
- Schedule network state now lives in dedicated TanStack Query hooks rather than
  inside the page. No backend routes, permissions, dependencies or agents changed.

Two initial browser regressions failed against the prior production build on the
missing labelled controls/confirmation. A separate delayed-request regression
caught editable pending drafts before the fields were disabled. One test selector
was corrected to include the indicator type subtitle in a table cell's accessible
name; production behavior was not weakened to accommodate it.
The CSV-count regression also failed against the initial implementation before
adding the composite export value.

Fresh verification against the final production build:

```text
npm run build -- --outDir /tmp/adsiem-enterprise-stage4-build
PASS (TypeScript + Vite; main JS 1,893.72 kB, gzip 563.84 kB)

DASHBOARD_TEST_URL=http://127.0.0.1:33421 python -m pytest \
  tests/dashboard/test_enterprise_ui.py -q --tb=short \
  --basetemp=/tmp/adsiem-ui-stage4-verified
92 passed in 117.39s

check-accent-stripes: 3 file(s), no accent stripes
git diff --check: PASS
```

Evidence: `/tmp/adsiem-ui-stage4-verified/`. Primary route captures include `/hunts`
at 390/768/1440/1920px with end-scroll screenshots. Hunt detail and schedule-delete
dialogs are captured at phone/desktop sizes; the schedule form's failed draft is
captured on a phone. Tests also cover polling completion, malformed/failed
analysis, whitespace rejection, interval limits and schedule mutations.

Browser requests use synthetic fixtures, including mutations. No real hunt,
schedule, Elasticsearch query, AI/provider call, database or endpoint action was
executed. This is targeted browser QA, not full backend integration, a performance
audit or WCAG certification. The existing large-main-bundle warning remains.
Other specialized screens still need dedicated redesign. This stage is local,
not committed, pushed or deployed.

## Fifth implementation — Behavior analytics / UEBA

The existing `/ueba` flow now follows the same approved enterprise design system:

- Common heading, labelled entity/minimum-risk filters, and a shared table with
  density, column selection and CSV. Counts explicitly describe the returned
  top-50 set, not global totals. Raw numerical risks remain unchanged; display
  severity bands use the prior 40/60/80 color boundaries.
- A model-status panel separates pending, failed, ready and baseline-collection
  states. Failed/pending status requests cannot produce a collecting-data claim
  or zero snapshot counts. Snapshot observations are no longer presented as a
  fixed elapsed-hour estimate. Model queries and entity queries fail independently.
- Keyboard-accessible read-only entity dialogs retain complete reasons, MITRE,
  AI assessment, case/alert navigation, numerical feature values, timestamps and
  recent anomaly records. Risk score and model anomaly score are labelled
  separately. Existing feature-display thresholds are retained and labelled;
  they do not change the model risk calculation.
- A typed history hook replaces the page's untyped inline request and encodes
  entity identifiers consistently. Details/history have separate retryable error
  states and preserve their existing endpoints. A responsive 30-day daily-maximum
  chart has fixed-size readable axis labels and an expandable data-table
  alternative. Empty and single-day histories are handled explicitly; missing
  days are not inserted as zero risk.

The status-failure regression was first run against the prior production build:
it failed while that build displayed collecting data and zero snapshots. The
initial implementation then passed all 13 targeted UEBA cases. Phone visual
inspection caught unreadably scaled SVG-axis text; axis labels were moved into
fixed-size HTML before the final regression run. Browser coverage also exercises
encoded user identifiers, filter query parameters, full long evidence, Escape
and focus return, open feature/daily-value tables, CSV raw numeric values,
independent query retries, and model-pending behavior.

Fresh verification against the final production build:

```text
npm run build -- --outDir /tmp/adsiem-enterprise-stage5-build
PASS (TypeScript + Vite; main JS 1,892.25 kB, gzip 564.35 kB)

DASHBOARD_TEST_URL=http://127.0.0.1:33601 python -m pytest \
  tests/dashboard/test_enterprise_ui.py -q --tb=short \
  --basetemp=/tmp/adsiem-ui-stage5-verified
109 passed in 173.81s

check-accent-stripes: 3 file(s), no accent stripes
git diff --check: PASS
```

Evidence: `/tmp/adsiem-ui-stage5-verified/`. UEBA and the eight earlier primary
routes are captured at 390/768/1440/1920px with end-scroll images. UEBA dialogs
are captured at 390/1440px, including complete long evidence. Desktop/phone
captures were visually inspected; table/modal overflow is checked by assertions.

All browser API requests are intercepted by synthetic fixtures. No real model
training/scoring, Redis, database, provider, endpoint or response action was
exercised. Backend permission/group-scoping contracts and dependencies are
unchanged. The existing approximately 1.89 MB main-bundle warning remains.
This is not an independent review, backend integration, performance audit, or
whole-application/WCAG certification. Hunting and UEBA remain local changes,
not committed, pushed or deployed.
