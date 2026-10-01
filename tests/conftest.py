"""Shared pytest fixtures available to all tests.

Environment variables are set at *module load time* (before any app.*
import) so that pydantic-settings can build the Settings object during
collection without a real .env file.  The autouse fixture then refreshes
the lru_cache before every test so per-test monkeypatches take effect.
"""

import os
from typing import Any, TypeVar

# ── Must precede any app.* import ─────────────────────────────────────────
os.environ.setdefault("OPENAI_API_KEY", "test-key-not-real")
os.environ.setdefault("SENTINEL_API_KEYS", "test-sentinel-key")
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("LOG_LEVEL", "DEBUG")
# ──────────────────────────────────────────────────────────────────────────

import pytest
from pydantic import BaseModel

from app.analyzer import LLMAnalysisResult
from app.config import get_settings
from app.llm import get_llm_client
from app.main import app
from app.rag import BaseRetriever, TechniqueCandidate, get_retriever
from app.schemas import Severity

_T = TypeVar("_T", bound=BaseModel)


class FakeLLMClient:
    """In-memory fake replacing the real AsyncOpenAI LLMClient during tests."""

    def __init__(
        self,
        result: LLMAnalysisResult | None = None,
        exception: Exception | None = None,
        side_effects: list[Any] | None = None,
        tool_requests: list[list[dict[str, Any]]] | None = None,
    ) -> None:
        self.result = result or LLMAnalysisResult(
            severity=Severity.info,
            summary="Stub: benign log activity.",
            evidence=[],
            techniques=[],
            injection_flagged=False,
        )
        self.exception = exception
        self.side_effects: list[Any] = list(side_effects) if side_effects else []
        self.tool_requests: list[list[dict[str, Any]]] = (
            list(tool_requests) if tool_requests else []
        )
        self.calls: list[dict[str, Any]] = []
        self.tool_call_queries: list[dict[str, Any]] = []

    async def request_tools(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        self.tool_call_queries.append({"messages": messages, "tools": tools})
        if self.tool_requests:
            return self.tool_requests.pop(0)
        return []

    async def complete_messages(
        self,
        messages: list[dict[str, Any]],
        response_model: type[_T],
    ) -> _T:
        system = ""
        user = ""
        for m in messages:
            if m.get("role") == "system":
                system = str(m.get("content", ""))
            elif m.get("role") == "user":
                user = str(m.get("content", ""))

        self.calls.append(
            {
                "system": system,
                "user": user,
                "messages": messages,
                "response_model": response_model,
            }
        )
        if self.side_effects:
            item = self.side_effects.pop(0)
            if isinstance(item, Exception):
                raise item
            return item  # type: ignore[return-value]
        if self.exception is not None:
            raise self.exception
        return self.result  # type: ignore[return-value]

    async def complete(
        self,
        system: str,
        user: str,
        response_model: type[_T],
    ) -> _T:
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        return await self.complete_messages(messages, response_model)


class FakeRetriever(BaseRetriever):
    """In-memory fake replacing ChromaRetriever during tests."""

    def __init__(self, candidates: list[TechniqueCandidate] | None = None) -> None:
        self.candidates: list[TechniqueCandidate] = (
            list(candidates) if candidates is not None else []
        )
        self.queries: list[str] = []

    async def retrieve(
        self, query: str, top_k: int = 5
    ) -> list[TechniqueCandidate]:
        self.queries.append(query)
        return self.candidates[:top_k]


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


@pytest.fixture(autouse=True)
def fake_llm() -> FakeLLMClient:
    """Inject a FakeLLMClient by default for all tests to protect the network."""
    fake = FakeLLMClient()
    app.dependency_overrides[get_llm_client] = lambda: fake
    yield fake
    app.dependency_overrides.pop(get_llm_client, None)


@pytest.fixture(autouse=True)
def fake_retriever() -> FakeRetriever:
    """Inject a FakeRetriever by default for all tests."""
    fake = FakeRetriever()
    app.dependency_overrides[get_retriever] = lambda: fake
    yield fake
    app.dependency_overrides.pop(get_retriever, None)
