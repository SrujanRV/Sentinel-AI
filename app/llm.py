"""Injectable OpenAI LLM client.

Keep this module thin: one class, one dependency function.
Tests substitute a FakeLLMClient via FastAPI dependency_overrides so the
real API is never called during test runs.
"""

import json
from typing import Any, TypeVar

from fastapi import Depends
from openai import AsyncOpenAI
from pydantic import BaseModel

from app.config import Settings, get_settings

_T = TypeVar("_T", bound=BaseModel)


class LLMClient:
    """Wraps AsyncOpenAI SDK with structured-output and tool calling capabilities."""

    def __init__(self, settings: Settings) -> None:
        self._client = AsyncOpenAI(api_key=settings.openai_api_key)
        self._model = settings.openai_model

    async def request_tools(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Call the model with available tools and return any requested tool calls."""
        response = await self._client.chat.completions.create(
            model=self._model,
            messages=messages,  # type: ignore[arg-type]
            tools=tools,  # type: ignore[arg-type]
            temperature=0.0,
        )
        choice = response.choices[0].message
        if not choice.tool_calls:
            return []

        calls: list[dict[str, Any]] = []
        for tc in choice.tool_calls:
            try:
                args = json.loads(tc.function.arguments)
            except (json.JSONDecodeError, TypeError):
                args = tc.function.arguments
            calls.append(
                {
                    "id": tc.id,
                    "name": tc.function.name,
                    "args": args,
                }
            )
        return calls

    async def complete_messages(
        self,
        messages: list[dict[str, Any]],
        response_model: type[_T],
    ) -> _T:
        """Parse structured output from a conversation history."""
        response = await self._client.beta.chat.completions.parse(
            model=self._model,
            messages=messages,  # type: ignore[arg-type]
            response_format=response_model,
            temperature=0.0,
        )
        parsed = response.choices[0].message.parsed
        if parsed is None:
            raise ValueError(
                "LLM returned null structured output (model may have refused)."
            )
        return parsed  # type: ignore[return-value]

    async def complete(
        self,
        system: str,
        user: str,
        response_model: type[_T],
    ) -> _T:
        """Convenience method calling complete_messages with system and user turns."""
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        return await self.complete_messages(messages, response_model)


def get_llm_client(settings: Settings = Depends(get_settings)) -> LLMClient:
    """FastAPI dependency: return a fresh LLMClient for the current request."""
    return LLMClient(settings)
