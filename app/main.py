"""SentinelAI FastAPI application entry point."""

from fastapi import FastAPI

app = FastAPI(
    title="SentinelAI",
    description="AI-powered log analysis and threat detection.",
    version="0.1.0",
)


@app.get("/health", tags=["meta"])
async def health() -> dict[str, str]:
    """Liveness probe - returns 200 when the service is up."""
    return {"status": "ok"}
