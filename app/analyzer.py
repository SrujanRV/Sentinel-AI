"""Log event analysis pipeline with RAG retrieval and tool calling loop.

Responsibility chain:
    sanitize each field -> retrieve top technique candidates (RAG) ->
    build numbered <logs> & <candidate_techniques> blocks ->
    run tool execution loop (policy-checked) -> call LLM for assessment ->
    drop hallucinated technique IDs -> merge injection flags -> return AlertAnalysis.
"""

import json
from typing import Any

from pydantic import BaseModel, Field

from app.config import Settings, get_settings
from app.llm import LLMClient
from app.prompts import SYSTEM_PROMPT, USER_PROMPT_TEMPLATE
from app.rag import BaseRetriever, TechniqueCandidate
from app.sanitize import sanitize
from app.schemas import AlertAnalysis, LogEvent, Severity, TechniqueMatch
from app.tools import (
    MAX_TOOL_CALLS,
    TOOL_DEFINITIONS,
    ToolExecutor,
    create_tool_executor,
    extract_observed_ips,
)

_MAX_ATTEMPTS = 2


# ── Domain types ───────────────────────────────────────────────────────────────


class AnalysisError(Exception):
    """Raised when the LLM pipeline fails after all retry attempts."""


class LLMAnalysisResult(BaseModel):
    """Structured output contract between the LLM and the analyzer."""

    severity: Severity
    summary: str = Field(..., description="1-3 sentence plain-English assessment.")
    evidence: list[str] = Field(
        default_factory=list,
        description="Short excerpts (<= 80 chars each) from the log lines.",
    )
    techniques: list[TechniqueMatch] = Field(
        default_factory=list,
        description="Matched techniques selected from candidate_techniques.",
    )
    injection_flagged: bool = Field(
        ...,
        description="True if the model detected prompt-injection in the log content.",
    )


# ── Internal helpers ───────────────────────────────────────────────────────────


def _build_log_block(events: list[LogEvent]) -> tuple[str, bool, str]:
    """Sanitize every text field and build the log block and search query.

    Returns:
        (log_block_string, sanitizer_injection_flagged, query_text)
    """
    sanitizer_flagged = False
    lines: list[str] = []
    messages: list[str] = []

    for idx, event in enumerate(events, start=1):
        sanitized: dict[str, str] = {}
        for field_name, raw in (
            ("source", event.source),
            ("host", event.host),
            ("user", event.user or ""),
            ("msg", event.message),
        ):
            if raw:
                result = sanitize(raw)
                sanitized[field_name] = result.text
                if result.injection_flagged:
                    sanitizer_flagged = True
            else:
                sanitized[field_name] = ""

        if sanitized["msg"]:
            messages.append(sanitized["msg"])

        parts: list[str] = [f"[{idx}]", event.timestamp.isoformat()]
        parts.append(f"source={sanitized['source']}")
        parts.append(f"host={sanitized['host']}")
        if sanitized["user"]:
            parts.append(f"user={sanitized['user']}")
        if event.src_ip:
            parts.append(f"src_ip={event.src_ip}")
        parts.append(f"msg={sanitized['msg']}")
        lines.append(" | ".join(parts))

    query_text = " ".join(messages[:10])
    return "\n".join(lines), sanitizer_flagged, query_text


def _format_candidates_block(candidates: list[TechniqueCandidate]) -> str:
    """Format candidate techniques for inclusion in the user prompt."""
    if not candidates:
        return "No candidate techniques available. Return empty techniques list []."
    return "\n\n".join(c.to_context_str() for c in candidates)


# ── Public API ─────────────────────────────────────────────────────────────────


async def analyze_events(
    events: list[LogEvent],
    client: LLMClient,
    retriever: BaseRetriever,
    tool_executor: ToolExecutor | None = None,
    settings: Settings | None = None,
) -> AlertAnalysis:
    """Sanitize events, retrieve candidates, execute tool loop, return analysis."""
    log_block, sanitizer_flagged, query_text = _build_log_block(events)

    # 1. Retrieve candidate techniques via RAG
    candidates = await retriever.retrieve(query=query_text, top_k=5)
    candidates_block = _format_candidates_block(candidates)

    user_content = USER_PROMPT_TEMPLATE.format(
        log_block=log_block,
        candidates_block=candidates_block,
    )

    # 2. Initialize tool executor if not injected
    if tool_executor is None:
        if settings is None:
            settings = get_settings()
        allowed_ips = extract_observed_ips(events)
        tool_executor = create_tool_executor(
            settings=settings,
            allowed_ips=allowed_ips,
            injection_flagged=sanitizer_flagged,
        )

    # 3. Tool execution loop (LLM can request tools, policy validates/executes)
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]
    tool_actions: list[dict[str, Any]] = []

    for _ in range(MAX_TOOL_CALLS):
        tool_requests = await client.request_tools(messages, tools=TOOL_DEFINITIONS)
        if not tool_requests:
            break

        for req in tool_requests:
            name = req["name"]
            raw_args = req["args"]
            call_id = req.get("id", f"call_{len(tool_actions) + 1}")

            action_record = await tool_executor.execute(name, raw_args)
            tool_actions.append(action_record)

            # Record assistant call turn
            formatted_args = (
                json.dumps(raw_args)
                if not isinstance(raw_args, str)
                else raw_args
            )
            messages.append(
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": call_id,
                            "type": "function",
                            "function": {"name": name, "arguments": formatted_args},
                        }
                    ],
                }
            )

            # Feed tool result back as untrusted data
            result_payload = (
                action_record["result"]
                if action_record["status"] == "executed"
                else {"denial_reason": action_record["denial_reason"]}
            )
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": call_id,
                    "content": json.dumps(result_payload),
                }
            )

        if tool_executor.policy.call_count >= tool_executor.policy.max_calls:
            break

    # 4. Final structured assessment from conversation history
    llm_result: LLMAnalysisResult | None = None
    last_exc: BaseException | None = None

    for _ in range(_MAX_ATTEMPTS):
        try:
            llm_result = await client.complete_messages(
                messages, LLMAnalysisResult
            )
            break
        except Exception as exc:
            last_exc = exc

    if llm_result is None:
        raise AnalysisError("LLM pipeline failed after retries.") from last_exc

    # 5. Anti-hallucination guard: DROP any technique not in retrieved candidates
    valid_ids = {c.technique_id for c in candidates}
    verified_techniques = [
        t for t in llm_result.techniques if t.technique_id in valid_ids
    ]

    return AlertAnalysis(
        severity=llm_result.severity,
        summary=llm_result.summary,
        evidence=llm_result.evidence,
        techniques=verified_techniques,
        injection_flagged=sanitizer_flagged or llm_result.injection_flagged,
        tool_actions=tool_actions,
    )
