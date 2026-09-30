"""Tests for POST /analyze - authentication and input validation."""

from fastapi.testclient import TestClient

VALID_KEY = "test-sentinel-key"
AUTH = {"X-API-Key": VALID_KEY}


def _event(**overrides) -> dict:
    """Return a minimal valid LogEvent dict, with optional field overrides."""
    base = {
        "timestamp": "2024-01-15T10:30:00Z",
        "source": "auth",
        "host": "server-01",
        "message": "User login attempt from 192.168.1.100",
    }
    return {**base, **overrides}


# ── Authentication ─────────────────────────────────────────────────────────

class TestAuthentication:
    def test_no_key_returns_401(self, client: TestClient) -> None:
        resp = client.post("/analyze", json={"events": [_event()]})
        assert resp.status_code == 401

    def test_wrong_key_returns_401(self, client: TestClient) -> None:
        resp = client.post(
            "/analyze",
            json={"events": [_event()]},
            headers={"X-API-Key": "totally-wrong"},
        )
        assert resp.status_code == 401

    def test_empty_key_returns_401(self, client: TestClient) -> None:
        resp = client.post(
            "/analyze",
            json={"events": [_event()]},
            headers={"X-API-Key": ""},
        )
        assert resp.status_code == 401

    def test_valid_key_returns_200(self, client: TestClient) -> None:
        resp = client.post("/analyze", json={"events": [_event()]}, headers=AUTH)
        assert resp.status_code == 200


# ── Input validation ───────────────────────────────────────────────────────

class TestInputValidation:
    def test_empty_events_returns_422(self, client: TestClient) -> None:
        resp = client.post("/analyze", json={"events": []}, headers=AUTH)
        assert resp.status_code == 422

    def test_too_many_events_returns_422(self, client: TestClient) -> None:
        resp = client.post(
            "/analyze",
            json={"events": [_event() for _ in range(201)]},
            headers=AUTH,
        )
        assert resp.status_code == 422

    def test_message_too_long_returns_422(self, client: TestClient) -> None:
        resp = client.post(
            "/analyze",
            json={"events": [_event(message="x" * 4001)]},
            headers=AUTH,
        )
        assert resp.status_code == 422

    def test_missing_message_returns_422(self, client: TestClient) -> None:
        bad = {"timestamp": "2024-01-15T10:30:00Z", "source": "auth", "host": "s1"}
        resp = client.post("/analyze", json={"events": [bad]}, headers=AUTH)
        assert resp.status_code == 422

    def test_missing_events_field_returns_422(self, client: TestClient) -> None:
        resp = client.post("/analyze", json={}, headers=AUTH)
        assert resp.status_code == 422


# ── Stub response shape ────────────────────────────────────────────────────

class TestStubResponse:
    def test_response_has_required_fields(self, client: TestClient) -> None:
        resp = client.post("/analyze", json={"events": [_event()]}, headers=AUTH)
        assert resp.status_code == 200
        body = resp.json()
        for field in ("severity", "summary", "evidence", "techniques",
                      "injection_flagged", "tool_actions"):
            assert field in body, f"Missing field: {field}"

    def test_tool_actions_defaults_to_empty_list(self, client: TestClient) -> None:
        resp = client.post("/analyze", json={"events": [_event()]}, headers=AUTH)
        assert resp.json()["tool_actions"] == []

    def test_exactly_200_events_is_accepted(self, client: TestClient) -> None:
        resp = client.post(
            "/analyze",
            json={"events": [_event() for _ in range(200)]},
            headers=AUTH,
        )
        assert resp.status_code == 200
