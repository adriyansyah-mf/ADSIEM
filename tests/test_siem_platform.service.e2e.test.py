# tests/test_siem_platform.service.e2e.test.py
# SIEM Platform Service-Integration E2E Tests
# Design Doc: docs/superpowers/specs/2026-05-21-siem-platform-design.md
# Generated: 2026-05-30 | Budget Used: integration 3/3, fixture-e2e 3/3, service-e2e 1/2
#
# Scope: Verifies the login → dashboard journey against the RUNNING LOCAL STACK
# (docker-compose.dev.yml). Real JWT is issued by the real server-api, real user
# row is looked up in the real PostgreSQL instance, and the real nginx proxy routes
# the request. This cannot be faked safely in fixture-e2e because:
#   - Real DB constraint on users.username uniqueness must hold
#   - Real argon2 password verification happens in server-api
#   - Real JWT signing with the actual JWT_SECRET env var is exercised
#
# Pre-conditions:
#   1. `docker-compose -f docker-compose.dev.yml up -d` is running
#   2. DB has been seeded (default admin user exists: username='admin', password='admin123')
#   3. Dashboard is accessible at http://localhost (nginx on port 80)
#   4. server-api is accessible at http://localhost/api
#
# Framework: Playwright (Python bindings). Install: pip install playwright && playwright install chromium

import pytest

BASE_URL = "http://localhost"
SEED_USERNAME = "admin"
SEED_PASSWORD = "admin123"


# ---------------------------------------------------------------------------
# Test 1: Login → Dashboard with real auth service stack (RESERVED SLOT)
# ---------------------------------------------------------------------------

# AC: When a user submits valid credentials on the live SIEM platform (seeded
#     admin/admin123), the real server-api validates the argon2 hash in PostgreSQL,
#     issues a real JWT access token (15-min expiry), and the browser navigates to
#     the dashboard at '/'. The dashboard fetches real alert data from the running
#     service.
# ROI: 100 (BV:10 × Freq:10 + Legal:0 + Defect:9) — RESERVED service-integration slot
# Behavior:
#   Step 1: Browser navigates to http://localhost/login
#   Step 2: Credentials submitted → POST /api/auth/login hits real server-api → real JWT returned
#   Step 3: GET /api/auth/me with real Bearer token → real user data from PostgreSQL
#   Step 4: Browser at '/' — dashboard renders with data from live services
# @category: service-integration-e2e
# @lane: service-integration-e2e
# @real-dependency: PostgreSQL (real user row lookup + argon2 verify), server-api (real JWT signing), nginx (real reverse proxy routing)
# @dependency: full-system
# @complexity: high

@pytest.mark.service_e2e
class TestLoginDashboardRealStack:
    """
    Multi-step user journey:
    - 2 distinct route boundaries: /login → /
    - State carries: access_token from POST /api/auth/login used in subsequent GET /api/auth/me
    - Completion point: Dashboard page rendered at '/' with data from live services
    """

    def test_login_with_seed_credentials_issues_real_jwt_and_loads_dashboard(self, page):
        """
        Arrange:
        - Live docker-compose stack is running (pre-condition — no mocks applied)
        - Seed user exists: username='admin', password='admin123', role='superadmin'

        Act:
        - page.goto(f"{BASE_URL}/login")
        - Fill username field with SEED_USERNAME
        - Fill password field with SEED_PASSWORD
        - Click submit button / trigger form submission

        Verification items:
        - POST /api/auth/login returns HTTP 200 with a non-empty access_token string
          (verify by intercepting network response in Playwright, not mocking it)
        - GET /api/auth/me returns HTTP 200 with username == 'admin' and role == 'superadmin'
        - Browser URL navigates to BASE_URL + '/' within 10 seconds
        - Dashboard page DOM contains at least one element identifying the authenticated
          application (e.g., sidebar with nav items, or the username 'admin' in the header)
        - No error message is displayed on screen

        Expected result:
        - page.url == BASE_URL + '/' after navigation
        - Network response for POST /api/auth/login has status 200
        - Network response body contains key 'access_token' with value length > 20

        Pass criteria:
        - All four verification items pass against the live system within 30s timeout
        - The access_token in the real response is a valid JWT (three dot-separated base64 segments)
        - The dashboard page is not the /login page (no redirect loop)

        Notes:
        - This test MUST NOT mock any API calls — it exercises the real auth stack
        - Run only in a local dev environment with the stack started via docker-compose.dev.yml
        - Tag this test with @pytest.mark.service_e2e for selective CI execution
        """
        pass
