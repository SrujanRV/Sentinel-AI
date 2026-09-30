"""Shared pytest fixtures available to all tests."""

import pytest


@pytest.fixture(autouse=True)
def _patch_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Inject dummy secrets so pydantic-settings never needs a real .env.

    This fixture is *autouse* so every test gets it automatically.
    Tests that need different values can call monkeypatch.setenv() again
    inside the test body (last write wins).
    """
    monkeypatch.setenv("OPENAI_API_KEY", "test-key-not-real")
    monkeypatch.setenv("SENTINEL_API_KEY", "test-sentinel-key")
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
