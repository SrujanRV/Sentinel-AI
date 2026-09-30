"""Tests for RAG retrieval, candidate technique mapping, and index script parsing."""

from fastapi.testclient import TestClient
from scripts.build_index import parse_mitre_stix, parse_owasp_markdown

from app.analyzer import LLMAnalysisResult
from app.rag import TechniqueCandidate
from app.schemas import Severity, TechniqueMatch
from tests.conftest import FakeLLMClient, FakeRetriever

VALID_KEY = "test-sentinel-key"
AUTH = {"X-API-Key": VALID_KEY}


def _event(**overrides) -> dict:
    """Return a minimal valid LogEvent dict with optional overrides."""
    base = {
        "timestamp": "2024-01-15T10:30:00Z",
        "source": "auth",
        "host": "server-01",
        "message": "Failed login attempt for user root",
    }
    return {**base, **overrides}


# ── RAG Integration & Anti-Hallucination Tests ───────────────────────────────


def test_rag_valid_technique_mapping(
    client: TestClient,
    fake_llm: FakeLLMClient,
    fake_retriever: FakeRetriever,
) -> None:
    """Retrieved candidate matched by LLM is included in the final analysis."""
    candidate = TechniqueCandidate(
        technique_id="T1110",
        name="Brute Force",
        framework="MITRE ATT&CK",
        tactics=["credential-access"],
        description="Adversaries may use brute force techniques to gain access.",
        detection="Monitor authentication logs for failure bursts.",
    )
    fake_retriever.candidates = [candidate]

    fake_llm.result = LLMAnalysisResult(
        severity=Severity.high,
        summary="Brute force authentication attack observed.",
        evidence=["Failed login attempt for user root"],
        techniques=[
            TechniqueMatch(
                technique_id="T1110",
                name="Brute Force",
                rationale="Repeated failed authentications against root account.",
            )
        ],
        injection_flagged=False,
    )

    resp = client.post("/analyze", json={"events": [_event()]}, headers=AUTH)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["techniques"]) == 1
    tech = data["techniques"][0]
    assert tech["technique_id"] == "T1110"
    assert tech["name"] == "Brute Force"
    assert "Repeated failed authentications" in tech["rationale"]

    # Verify retriever was queried with sanitized text
    assert len(fake_retriever.queries) == 1
    assert "Failed login attempt" in fake_retriever.queries[0]


def test_hallucinated_technique_id_is_dropped(
    client: TestClient,
    fake_llm: FakeLLMClient,
    fake_retriever: FakeRetriever,
) -> None:
    """Any technique returned by LLM not in retrieved candidates must be dropped."""
    valid_candidate = TechniqueCandidate(
        technique_id="T1078",
        name="Valid Accounts",
        framework="MITRE ATT&CK",
        tactics=["initial-access"],
        description="Adversaries may obtain credentials of existing accounts.",
    )
    fake_retriever.candidates = [valid_candidate]

    # LLM hallucinates T9999 which was NOT in candidate list, but also returns T1078
    fake_llm.result = LLMAnalysisResult(
        severity=Severity.medium,
        summary="Suspicious account activity.",
        evidence=["Failed login attempt"],
        techniques=[
            TechniqueMatch(
                technique_id="T9999",
                name="Hallucinated Technique",
                rationale="Invented technique ID by model.",
            ),
            TechniqueMatch(
                technique_id="T1078",
                name="Valid Accounts",
                rationale="Matched valid candidate.",
            ),
        ],
        injection_flagged=False,
    )

    resp = client.post("/analyze", json={"events": [_event()]}, headers=AUTH)
    assert resp.status_code == 200
    data = resp.json()
    # T9999 must be dropped; only T1078 survives
    assert len(data["techniques"]) == 1
    assert data["techniques"][0]["technique_id"] == "T1078"


def test_empty_retrieval_returns_empty_techniques_not_error(
    client: TestClient,
    fake_llm: FakeLLMClient,
    fake_retriever: FakeRetriever,
) -> None:
    """When retriever yields zero candidates, techniques list is empty without error."""
    fake_retriever.candidates = []

    fake_llm.result = LLMAnalysisResult(
        severity=Severity.low,
        summary="Benign operational log.",
        evidence=[],
        techniques=[
            TechniqueMatch(
                technique_id="T1059",
                name="Command and Scripting Interpreter",
                rationale="Unsolicited technique.",
            )
        ],
        injection_flagged=False,
    )

    resp = client.post("/analyze", json={"events": [_event()]}, headers=AUTH)
    assert resp.status_code == 200
    data = resp.json()
    assert data["techniques"] == []


# ── Index Script Parsing Tests ───────────────────────────────────────────────


def test_parse_mitre_stix_fixture() -> None:
    """Verify STIX parsing extracts techniques and skips revoked/deprecated ones."""
    sample_stix = {
        "objects": [
            # 1. Valid technique
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1111",
                "name": "Valid Accounts",
                "description": "Adversaries may steal credentials.",
                "x_mitre_detection": "Monitor authentication services.",
                "x_mitre_deprecated": False,
                "revoked": False,
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "persistence"},
                    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"},
                ],
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1078"}
                ],
            },
            # 2. Revoked technique (should be skipped)
            {
                "type": "attack-pattern",
                "id": "attack-pattern--2222",
                "name": "Old Revoked Technique",
                "revoked": True,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1000"}
                ],
            },
            # 3. Deprecated technique (should be skipped)
            {
                "type": "attack-pattern",
                "id": "attack-pattern--3333",
                "name": "Deprecated Technique",
                "x_mitre_deprecated": True,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1001"}
                ],
            },
            # 4. Non-attack-pattern object (e.g. malware - should be skipped)
            {
                "type": "malware",
                "id": "malware--4444",
                "name": "SomeMalware",
            },
        ]
    }

    candidates = parse_mitre_stix(sample_stix)
    assert len(candidates) == 1
    t = candidates[0]
    assert t.technique_id == "T1078"
    assert t.name == "Valid Accounts"
    assert t.framework == "MITRE ATT&CK"
    assert "persistence" in t.tactics
    assert "initial-access" in t.tactics
    assert "Adversaries may steal credentials." in t.description
    assert "Monitor authentication services." in t.detection


def test_parse_owasp_markdown_fixture() -> None:
    """Verify OWASP markdown parsing extracts category ID, title, and description."""
    filename = "A03_2021-Injection.md"
    markdown_content = """\
# A03:2021 - Injection

## Overview
Injection flaws, such as SQL, NoSQL, OS, and LDAP injection, occur when
untrusted data is sent to an interpreter as part of a command or query.
The attacker's hostile data can trick the interpreter into executing
unintended commands or accessing data without proper authorization.

## How to Prevent
Preventing injection requires keeping data separate from commands and queries.
"""

    candidate = parse_owasp_markdown(filename, markdown_content)
    assert candidate.technique_id == "A03:2021"
    assert "Injection" in candidate.name
    assert candidate.framework == "OWASP Top 10"
    assert "web-application-security" in candidate.tactics
    assert "Injection flaws, such as SQL" in candidate.description
