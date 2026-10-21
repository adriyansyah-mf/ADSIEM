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
