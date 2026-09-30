"""SentinelAI FastAPI application entry point."""

from fastapi import Depends, FastAPI

from app.dependencies import verify_api_key
from app.sanitize import sanitize
from app.schemas import AlertAnalysis, AnalyzeRequest, Severity

app = FastAPI(
    title="SentinelAI",
    description="AI-powered log analysis and threat detection.",
    version="0.1.0",
)


@app.get("/health", tags=["meta"])
async def health() -> dict[str, str]:
    """Liveness probe - returns 200 when the service is up."""
    return {"status": "ok"}


@app.post(
    "/analyze",
    response_model=AlertAnalysis,
    tags=["analysis"],
    dependencies=[Depends(verify_api_key)],
    status_code=200,
)
async def analyze(request: AnalyzeRequest) -> AlertAnalysis:
    """Classify and summarize log events.

    Every event field is sanitized (normalized + injection-detected +
    redacted) before any further processing.  The LLM pipeline is wired
    in the next step; for now a stub response is returned.
    """
    injection_flagged = False

    for event in request.events:
        # Sanitize every text field that carries untrusted log content.
        fields_to_check = [event.message, event.source, event.host]
        if event.user:
            fields_to_check.append(event.user)

        for raw in fields_to_check:
            result = sanitize(raw)
            if result.injection_flagged:
                injection_flagged = True

    return AlertAnalysis(
        severity=Severity.info,
        summary="Stub: analysis pipeline not yet implemented.",
        evidence=[],
        techniques=[],
        injection_flagged=injection_flagged,
        tool_actions=[],
    )
