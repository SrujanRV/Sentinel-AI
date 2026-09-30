"""SentinelAI FastAPI application entry point."""

from fastapi import Depends, FastAPI

from app.dependencies import verify_api_key
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

    Stub response until the LLM pipeline is wired in the next step.
    Auth is enforced via the X-API-Key header dependency above.
    """
    return AlertAnalysis(
        severity=Severity.info,
        summary="Stub: analysis pipeline not yet implemented.",
        evidence=[],
        techniques=[],
        injection_flagged=False,
        tool_actions=[],
    )
