# tests/dashboard/conftest.py
# Playwright sync fixtures for SIEM dashboard fixture-e2e tests.
# Uses synchronous Playwright (sync_playwright) to match the sync class-based
# test methods in test_siem_platform.fixture.e2e.test.py.

import json
from typing import Generator

import pytest
from playwright.sync_api import Page, Route, sync_playwright


# ---------------------------------------------------------------------------
# page fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="function")
def page() -> Generator[Page, None, None]:
    """
    Launch a headless Chromium browser, yield a single Page, then close.

    Scope is function-level so each test gets a fresh browser context with no
    shared cookies, localStorage, or network state.
    """
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context()
        pg = context.new_page()
        yield pg
        context.close()
        browser.close()


# ---------------------------------------------------------------------------
# mock_api fixture
# ---------------------------------------------------------------------------

class MockAPI:
    """
    Thin helper that wraps ``page.route()`` to register URL pattern → response
    stubs.  Tests call ``mock_api.register(url_pattern, method, body, status)``
    (or the convenience shortcuts) to intercept fetch/XHR calls made by the
    dashboard SPA.
    """

    def __init__(self, page: Page) -> None:
        self._page = page
        # Keep track of registered handlers so tests can inspect call counts.
        self._handlers: dict[str, list[dict]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register(
        self,
        url_pattern: str,
        *,
        method: str = "*",
        body: dict | list | None = None,
        status: int = 200,
    ) -> None:
        """
        Intercept all requests whose URL matches *url_pattern* (glob or regex
        string) and respond with *body* serialised as JSON.

        Args:
            url_pattern: Glob pattern or URL substring matched by
                         ``page.route()``.  E.g. ``"**/api/auth/login"``.
            method:      HTTP verb to match (case-insensitive).  ``"*"``
                         matches any method.
            body:        Python dict/list that is JSON-serialised into the
                         response body.  ``None`` produces an empty body.
            status:      HTTP status code for the stubbed response.

        Note: Calling register() twice with the same url_pattern and method
        adds a second Playwright route handler — it does NOT override the first.
        Playwright uses the first matching handler, so call_count() tracks
        only the most recent registration for that key.
        """
        key = f"{method.upper()}:{url_pattern}"
        self._handlers.setdefault(key, [])

        def _handler(route: Route) -> None:
            req_method = route.request.method.upper()
            if method != "*" and req_method != method.upper():
                route.continue_()
                return

            self._handlers[key].append(
                {
                    "method": req_method,
                    "url": route.request.url,
                    "post_data": route.request.post_data,
                }
            )

            response_body = json.dumps(body) if body is not None else ""
            route.fulfill(
                status=status,
                content_type="application/json",
                body=response_body,
            )

        self._page.route(url_pattern, _handler)

    def calls(self, url_pattern: str, method: str = "*") -> list[dict]:
        """Return the list of recorded call dicts for *url_pattern*."""
        key = f"{method.upper()}:{url_pattern}"
        return self._handlers.get(key, [])

    def call_count(self, url_pattern: str, method: str = "*") -> int:
        """Return how many times a given route was matched."""
        return len(self.calls(url_pattern, method))


@pytest.fixture(scope="function")
def mock_api(page: Page) -> MockAPI:
    """
    Return a :class:`MockAPI` bound to *page*.

    Tests use this fixture to stub backend responses:

    .. code-block:: python

        def test_something(self, page, mock_api):
            mock_api.register(
                "**/api/auth/login",
                method="POST",
                body={"access_token": "tok"},
            )
    """
    return MockAPI(page)
