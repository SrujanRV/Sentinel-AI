"""SentinelAI FastAPI application entry point."""

from fastapi import Depends, FastAPI, HTTPException, status

from app.analyzer import AnalysisError, analyze_events
from app.dependencies import verify_api_key
from app.llm import LLMClient, get_llm_client
from app.rag import BaseRetriever, get_retriever
from app.schemas import AlertAnalysis, AnalyzeRequest

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
async def analyze(
    request: AnalyzeRequest,
    llm_client: LLMClient = Depends(get_llm_client),
    retriever: BaseRetriever = Depends(get_retriever),
) -> AlertAnalysis:
    """Classify and summarize log events using the LLM and RAG pipeline."""
    try:
        return await analyze_events(request.events, llm_client, retriever)
    except AnalysisError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Analysis service unavailable.",
        ) from exc
