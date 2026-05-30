# tests/conftest.py
# SIEM Platform pytest configuration
# Registers pytest markers and auto-skips service_e2e tests when docker-compose stack is down

import socket
from typing import Generator

import pytest
from playwright.sync_api import Page, sync_playwright


# ---------------------------------------------------------------------------
# page fixture (function-scoped headless Chromium — used by service_e2e tests)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="function")
def page() -> Generator[Page, None, None]:
    """
    Launch a headless Chromium browser, yield a single Page, then close.

    Scope is function-level so each test gets a fresh browser context with no
    shared cookies, localStorage, or network state.

    Available to all tests under tests/ (including service_e2e tests that live
    at the top level, outside tests/dashboard/).
    """
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context()
        pg = context.new_page()
        yield pg
        context.close()
        browser.close()


def pytest_configure(config):
    """Register custom pytest markers."""
    config.addinivalue_line(
        "markers",
        "service_e2e: mark test as service-integration E2E (requires docker-compose stack running)"
    )


def is_stack_running():
    """
    Check if the docker-compose stack is running by attempting to connect to localhost:80 (nginx).
    Returns True if the stack is up, False otherwise.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(("127.0.0.1", 80))
        sock.close()
        return result == 0
    except Exception:
        return False


def pytest_collection_modifyitems(config, items):
    """
    Automatically skip @pytest.mark.service_e2e tests if the docker-compose stack is not running.
    """
    stack_up = is_stack_running()

    for item in items:
        if item.get_closest_marker("service_e2e"):
            if not stack_up:
                skip_reason = (
                    "docker-compose stack is not running (http://localhost/health unreachable). "
                    "Start the stack with: docker-compose -f docker-compose.dev.yml up -d"
                )
                item.add_marker(pytest.mark.skip(reason=skip_reason))
