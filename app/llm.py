"""Injectable OpenAI LLM client.

Keep this module thin: one class, one dependency function.
Tests substitute a FakeLLMClient via FastAPI dependency_overrides so the
real API is never called during test runs.
"""

from typing import TypeVar

from fastapi import Depends
from openai import AsyncOpenAI
from pydantic import BaseModel

from app.config import Settings, get_settings

_T = TypeVar("_T", bound=BaseModel)


class LLMClient:
    """Wraps AsyncOpenAI SDK with structured-output (Pydantic) parsing.

    One instance per request via get_llm_client so tests can inject a fake
    without any monkey-patching of module globals.
    """

    def __init__(self, settings: Settings) -> None:
        self._client = AsyncOpenAI(api_key=settings.openai_api_key)
        self._model = settings.openai_model

    async def complete(
        self,
        system: str,
        user: str,
        response_model: type[_T],
    ) -> _T:
        """Call the chat completion API and parse the response into *response_model*.

        Args:
            system: System-prompt text (static, trusted).
            user:   User-turn text (contains sanitized log content only).
            response_model: Pydantic model class for structured output.

        Returns:
            An instance of *response_model* populated from the model's reply.

        Raises:
            ValueError: If the model returns null structured output (refusal).
            openai.APIError: On network or API-level failures.
        """
        response = await self._client.beta.chat.completions.parse(
            model=self._model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            response_format=response_model,
            temperature=0.0,
        )
        parsed = response.choices[0].message.parsed
        if parsed is None:
            raise ValueError(
                "LLM returned null structured output "
                "(model may have refused the request)."
            )
        return parsed  # type: ignore[return-value]


def get_llm_client(settings: Settings = Depends(get_settings)) -> LLMClient:
    """FastAPI dependency: return a fresh LLMClient for the current request."""
    return LLMClient(settings)
