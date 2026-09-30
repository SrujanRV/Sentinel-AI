"""Shared pytest fixtures available to all tests.

Environment variables are set at *module load time* (before any app.*
import) so that pydantic-settings can build the Settings object during
collection without a real .env file.  The autouse fixture then refreshes
the lru_cache before every test so per-test monkeypatches take effect.
"""

import os

# ── Must precede any app.* import ─────────────────────────────────────────
os.environ.setdefault("OPENAI_API_KEY", "test-key-not-real")
os.environ.setdefault("SENTINEL_API_KEYS", "test-sentinel-key")
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("LOG_LEVEL", "DEBUG")
# ──────────────────────────────────────────────────────────────────────────

import pytest

from app.config import get_settings
from app.main import app


@pytest.fixture()
def client():
    """Shared ASGI test client; imported lazily so env vars are set first."""
    from fastapi.testclient import TestClient

    return TestClient(app)


@pytest.fixture(autouse=True)
def _patch_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set dummy secrets and clear the settings cache before every test.

    This guarantees:
    - No real API key is ever read.
    - Any per-test monkeypatch.setenv() call is picked up by get_settings().
    """
    monkeypatch.setenv("OPENAI_API_KEY", "test-key-not-real")
    monkeypatch.setenv("SENTINEL_API_KEYS", "test-sentinel-key")
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    get_settings.cache_clear()
