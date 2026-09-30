"""Tests for the /health endpoint and basic app setup."""

import importlib

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client() -> TestClient:
    # Import here so the autouse env-patch fixture runs first.
    main = importlib.import_module("app.main")
    return TestClient(main.app)


def test_health_returns_200(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200


def test_health_body(client: TestClient) -> None:
    response = client.get("/health")
    assert response.json() == {"status": "ok"}


def test_openapi_schema_reachable(client: TestClient) -> None:
    response = client.get("/openapi.json")
    assert response.status_code == 200
    assert response.json()["info"]["title"] == "SentinelAI"
