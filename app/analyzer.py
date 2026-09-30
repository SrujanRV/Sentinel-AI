"""Log event analysis pipeline.

Responsibility chain:
    sanitize each field -> retrieve top technique candidates (RAG) ->
    build numbered <logs> & <candidate_techniques> blocks -> call LLM ->
    drop hallucinated technique IDs -> merge injection flags -> return AlertAnalysis.
"""

from pydantic import BaseModel, Field

from app.llm import LLMClient
from app.prompts import SYSTEM_PROMPT, USER_PROMPT_TEMPLATE
from app.rag import BaseRetriever, TechniqueCandidate
from app.sanitize import sanitize
from app.schemas import AlertAnalysis, LogEvent, Severity, TechniqueMatch

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

    query_text = " ".join(messages[:10])  # Use sanitized messages for query
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
) -> AlertAnalysis:
    """Sanitize events, retrieve candidates, call LLM with retry.

    Technique IDs returned by the model are strictly validated against retrieved
    candidates; any hallucinated ID not present in the candidate set is dropped.
    """
    log_block, sanitizer_flagged, query_text = _build_log_block(events)

    # Retrieve candidate techniques via RAG
    candidates = await retriever.retrieve(query=query_text, top_k=5)
    candidates_block = _format_candidates_block(candidates)

    user_content = USER_PROMPT_TEMPLATE.format(
        log_block=log_block,
        candidates_block=candidates_block,
    )

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

    # Anti-hallucination guard: DROP any technique not in retrieved candidates
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
        tool_actions=[],
    )
