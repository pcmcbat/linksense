"""Tests for the FastAPI API endpoints (no real provider keys needed)."""

from fastapi.testclient import TestClient

from app.main import app


def test_health():
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert "ml_available" in data
    assert "providers" in data


def test_model_info():
    client = TestClient(app)
    resp = client.get("/api/model/info")
    assert resp.status_code == 200
    data = resp.json()
    assert "model_name" in data


def test_scan_invalid_url():
    client = TestClient(app)
    resp = client.post("/api/scan", json={"url": "ftp://example.com"})
    assert resp.status_code == 422  # FastAPI validation error for bad scheme


def test_scan_private_ip():
    client = TestClient(app)
    resp = client.post("/api/scan", json={"url": "http://127.0.0.1/"})
    assert resp.status_code == 400


def test_scan_returns_structured_result():
    client = TestClient(app)
    resp = client.post("/api/scan", json={"url": "https://example.com"})
    assert resp.status_code == 200
    data = resp.json()
    result = data["result"]
    assert result["verdict"] in ("safe", "suspicious", "malicious")
    assert 0 <= result["risk_score"] <= 100
    assert 0.0 <= result["ml_probability"] <= 1.0
    assert result["classification"] in ("Safe", "Suspicious", "Malicious")
    assert "explanation" in result
    assert "ml" in result
    assert "heuristic" in result
    assert "reputation" in result


def test_legacy_scan_contract():
    client = TestClient(app)
    resp = client.post("/scan", json={"url": "https://example.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] in ("safe", "suspicious", "malicious")
    assert "consensusVerdict" in data
    assert "riskVerdict" in data
    assert "providers" in data
    assert "consensus" in data
    assert "risk_score" in data
    assert "explanation" in data

