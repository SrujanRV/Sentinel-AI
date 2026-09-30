"""Log event analysis pipeline.

Responsibility chain:
    sanitize each field -> build numbered <logs> block -> call LLM ->
    merge injection flags (sanitizer OR model) -> return AlertAnalysis.
"""

from pydantic import BaseModel, Field

from app.llm import LLMClient
from app.prompts import SYSTEM_PROMPT, USER_PROMPT_TEMPLATE
from app.sanitize import sanitize
from app.schemas import AlertAnalysis, LogEvent, Severity

_MAX_ATTEMPTS = 2


# ── Domain types ───────────────────────────────────────────────────────────────


class AnalysisError(Exception):
    """Raised when the LLM pipeline fails after all retry attempts."""


class LLMAnalysisResult(BaseModel):
    """Structured output contract between the LLM and the analyzer.

    The model must populate every field.  Techniques are intentionally absent
    here - they are resolved via RAG in a later step.
    """

    severity: Severity
    summary: str = Field(..., description="1-3 sentence plain-English assessment.")
    evidence: list[str] = Field(
        default_factory=list,
        description="Short excerpts (<= 80 chars each) from the log lines.",
    )
    injection_flagged: bool = Field(
        ...,
        description="True if the model detected prompt-injection in the log content.",
    )


# ── Internal helpers ───────────────────────────────────────────────────────────


def _build_log_block(events: list[LogEvent]) -> tuple[str, bool]:
    """Sanitize every text field and build the numbered log block for the prompt.

    Returns:
        (log_block_string, sanitizer_injection_flagged)
        where sanitizer_injection_flagged is True if any field triggered an
        injection heuristic.
    """
    sanitizer_flagged = False
    lines: list[str] = []

    for idx, event in enumerate(events, start=1):
        # All text fields that carry untrusted user content must be sanitized.
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

        # Build one human-readable line per event; omit empty optional fields.
        parts: list[str] = [f"[{idx}]", event.timestamp.isoformat()]
        parts.append(f"source={sanitized['source']}")
        parts.append(f"host={sanitized['host']}")
        if sanitized["user"]:
            parts.append(f"user={sanitized['user']}")
        if event.src_ip:
            # IPs are safe to include verbatim (not redacted by design).
            parts.append(f"src_ip={event.src_ip}")
        parts.append(f"msg={sanitized['msg']}")
        lines.append(" | ".join(parts))

    return "\n".join(lines), sanitizer_flagged


# ── Public API ─────────────────────────────────────────────────────────────────


async def analyze_events(
    events: list[LogEvent],
    client: LLMClient,
) -> AlertAnalysis:
    """Sanitize events, call the LLM with one retry, and return AlertAnalysis.

    injection_flagged in the result is the logical OR of the sanitizer flag
    (detected before LLM call) and the model's own flag (detected in context).
    Either source alone is sufficient to raise the flag.

    Args:
        events: Raw, untrusted log events from the API request.
        client: LLMClient instance (real or test double).

    Returns:
        A fully populated AlertAnalysis (techniques list is empty at this step).

    Raises:
        AnalysisError: When the LLM call fails after all retry attempts.
                       Caller is responsible for mapping this to HTTP 502.
    """
    log_block, sanitizer_flagged = _build_log_block(events)
    user_content = USER_PROMPT_TEMPLATE.format(log_block=log_block)

    llm_result: LLMAnalysisResult | None = None
    last_exc: BaseException | None = None

    for _ in range(_MAX_ATTEMPTS):
        try:
            llm_result = await client.complete(
                SYSTEM_PROMPT, user_content, LLMAnalysisResult
            )
            break
        except Exception as exc:
            last_exc = exc

    if llm_result is None:
        raise AnalysisError("LLM pipeline failed after retries.") from last_exc

    return AlertAnalysis(
        severity=llm_result.severity,
        summary=llm_result.summary,
        evidence=llm_result.evidence,
        techniques=[],  # populated by the RAG step in the next prompt
        injection_flagged=sanitizer_flagged or llm_result.injection_flagged,
        tool_actions=[],
    )
