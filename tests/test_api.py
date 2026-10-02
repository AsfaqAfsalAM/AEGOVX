"""
tests/test_api.py
~~~~~~~~~~~~~~~~~
Tests for Flask REST API endpoints and error handling.
"""

from unittest.mock import patch
import pytest
from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_index_page(client):
    res = client.get("/")
    assert res.status_code == 200
    assert b"AEGOVX" in res.data


def test_api_scan_missing_url(client):
    res = client.post("/api/v1/scan", json={})
    assert res.status_code == 400
    data = res.get_json()
    assert "error" in data


def test_api_scan_invalid_url(client):
    res = client.post("/api/v1/scan", json={"url": "http://127.0.0.1:8000"})
    assert res.status_code == 400
    data = res.get_json()
    assert "error" in data
    assert "internal" in data["error"].lower() or "blocked" in data["error"].lower()


def test_api_scan_mocked_success(client):
    mock_scan_result = {
        "scan_id": "SCAN-2026-10-01-A1B2C3",
        "timestamp": "2026-10-01T12:00:00Z",
        "original_url": "https://example.com",
        "normalized_url": "https://example.com/",
        "final_url": "https://example.com/",
        "status_code": 200,
        "risk_level": "LOW RISK",
        "risk_label": "LOW RISK",
        "risk_description": "Clean scan",
        "risk_score": 15,
        "confidence": "HIGH",
        "confidence_score": 85,
        "breakdown": {},
        "findings": [],
        "finding_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0},
        "score": 85,
        "grade": "A",
        "scored_headers": [],
        "info_headers": [],
    }

    with patch("app.run_full_scan", return_value=mock_scan_result):
        res = client.post("/api/v1/scan", json={"url": "https://example.com"})
        assert res.status_code == 200
        data = res.get_json()
        assert data["scan_id"] == "SCAN-2026-10-01-A1B2C3"
        assert data["risk_level"] == "LOW RISK"

        # Check retrieval endpoint GET /api/v1/scan/<scan_id>
        res_get = client.get("/api/v1/scan/SCAN-2026-10-01-A1B2C3")
        assert res_get.status_code == 200
        get_data = res_get.get_json()
        assert get_data["scan_id"] == "SCAN-2026-10-01-A1B2C3"

        # Check non-existent scan ID
        res_404 = client.get("/api/v1/scan/NONEXISTENT-ID")
        assert res_404.status_code == 404
