"""Pydantic v2 request / response schemas for SentinelAI."""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Threat severity levels, ordered from lowest to highest."""

    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class LogEvent(BaseModel):
    """A single parsed log entry submitted for analysis.

    The message field is capped at 4 000 characters to bound prompt size.
    All fields are treated as UNTRUSTED DATA and must be sanitized before
    reaching any LLM call.
    """

    timestamp: datetime
    source: str = Field(..., description="Log source / collector name.")
    host: str = Field(..., description="Originating host or FQDN.")
    user: str | None = Field(None, description="Associated username, if present.")
    src_ip: str | None = Field(None, description="Source IP address, if present.")
    message: str = Field(
        ...,
        max_length=4000,
        description="Raw log message (max 4 000 chars).",
    )


class AnalyzeRequest(BaseModel):
    """Payload for POST /analyze."""

    events: list[LogEvent] = Field(
        ...,
        min_length=1,
        max_length=200,
        description="Between 1 and 200 log events to analyze.",
    )


class TechniqueMatch(BaseModel):
    """A MITRE ATT&CK or OWASP technique linked to the analyzed events."""

    technique_id: str = Field(..., description="e.g. T1078 or A01:2021.")
    name: str = Field(..., description="Human-readable technique name.")
    rationale: str = Field(..., description="Why this technique was matched.")


class AlertAnalysis(BaseModel):
    """Full analysis result returned by POST /analyze."""

    severity: Severity
    summary: str = Field(..., description="One-paragraph plain-English summary.")
    evidence: list[str] = Field(
        ..., description="Quoted log snippets that support the verdict."
    )
    techniques: list[TechniqueMatch] = Field(
        ..., description="Mapped ATT&CK / OWASP techniques."
    )
    injection_flagged: bool = Field(
        ..., description="True if prompt-injection attempt was detected."
    )
    tool_actions: list[dict] = Field(
        default_factory=list,
        description="Tool calls the agent executed (populated in later steps).",
    )
