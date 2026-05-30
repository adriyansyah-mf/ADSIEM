# tests/worker/conftest.py
# Pytest configuration for worker integration tests

import pytest


pytest_plugins = ("pytest_asyncio",)


def pytest_configure(config):
    """Configure pytest-asyncio mode for worker tests."""
    # Use auto mode to automatically apply @pytest.mark.asyncio to async test functions
    config.option.asyncio_mode = "auto"
    config.option.asyncio_default_fixture_loop_scope = "function"
