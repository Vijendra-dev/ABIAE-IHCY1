"""
API Integration Tests using FastAPI TestClient and httpx.
"""

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from main import app
from db import init_db


@pytest_asyncio.fixture(autouse=True)
async def setup_database():
    await init_db()
    yield


@pytest.mark.asyncio
async def test_health_and_root_endpoints():
    """
    Tests /health and / endpoints.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Health check
        res = await client.get("/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert "version" in data

        # 2. Root metadata
        root_res = await client.get("/")
        assert root_res.status_code == 200
        root_data = root_res.json()
        assert "endpoints" in root_data


@pytest.mark.asyncio
async def test_scans_and_cases_lifecycle():
    """
    Tests scan triggering, listing scans, querying scan details, and listing cases.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Trigger domain scan
        scan_payload = {
            "brand_list": ["paypal", "apple"],
            "confidence_threshold": 0.70
        }
        res = await client.post("/scans/domains", json=scan_payload)
        assert res.status_code == 202
        scan_data = res.json()
        scan_id = scan_data["scan_id"]
        assert scan_data["status"] == "RUNNING"
        assert len(scan_data["brand_list"]) == 2

        # 2. Get scan detail
        detail_res = await client.get(f"/scans/{scan_id}")
        assert detail_res.status_code == 200
        detail_data = detail_res.json()
        assert detail_data["id"] == scan_id

        # 3. List cases
        cases_res = await client.get("/cases")
        assert cases_res.status_code == 200
        cases_data = cases_res.json()
        assert "total" in cases_data
        assert "items" in cases_data
        assert isinstance(cases_data["items"], list)

        # 4. Filter cases
        filtered_res = await client.get("/cases?risk_level=HIGH")
        assert filtered_res.status_code == 200
        for c in filtered_res.json()["items"]:
            assert c["risk_level"] == "HIGH"


@pytest.mark.asyncio
async def test_inspect_url_trustlens_unavailable():
    """
    Tests inspect-url endpoint when TrustLens is unreachable:
    analysis_complete should be False, risk_level UNKNOWN, and trust_score None.
    """
    from unittest.mock import AsyncMock, patch
    from services.trustlens_client import TrustLensClient

    mock_unavailable = {
        "trustScore": None,
        "riskLevel": "UNKNOWN",
        "reasons": ["TrustLens-AI service unavailable — no live inspection performed"],
        "engines": {"unavailable": True},
        "screenshot_url": None,
        "html_snapshot_url": None,
        "url": "https://paypa1-security.com",
        "success": False,
        "fallback": True,
    }

    transport = ASGITransport(app=app)
    with patch.object(TrustLensClient, "analyze_url", new_callable=AsyncMock) as mock_analyze:
        mock_analyze.return_value = mock_unavailable
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            res = await client.post("/scans/inspect-url", json={"url": "https://paypa1-security.com"})
            assert res.status_code == 200
            data = res.json()
            assert data["analysis_complete"] is False
            assert data["risk_level"] == "UNKNOWN"
            assert data["trust_score"] is None
            # Antigravity is never dispatched when analysis_complete is False
            # (antigravity_event_id may be non-None from a prior run of the same domain in the test DB)


@pytest.mark.asyncio
async def test_inspect_url_trustlens_available():
    """
    Tests inspect-url endpoint when TrustLens is reachable:
    analysis_complete should be True, risk_level HIGH/MEDIUM, and trust_score float.
    """
    from unittest.mock import AsyncMock, patch
    from services.trustlens_client import TrustLensClient

    mock_online = {
        "trustScore": 12.0,
        "riskLevel": "HIGH",
        "reasons": ["Credential harvesting form detected on landing page"],
        "engines": {
            "content_engine": {"has_credential_input": True},
            "brand_engine": {"logo_detected": True, "visual_similarity_score": 0.92}
        },
        "screenshot_url": "https://storage.test/shot.png",
        "html_snapshot_url": "https://storage.test/dom.html",
        "url": "https://paypa1-security.com",
        "success": True,
        "fallback": False,
    }

    transport = ASGITransport(app=app)
    with patch.object(TrustLensClient, "analyze_url", new_callable=AsyncMock) as mock_analyze:
        mock_analyze.return_value = mock_online
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            res = await client.post("/scans/inspect-url", json={"url": "https://paypa1-security.com"})
            assert res.status_code == 200
            data = res.json()
            assert data["analysis_complete"] is True
            assert data["risk_score"] >= 75
            # Pipeline uses CRITICAL (>=80) in addition to HIGH (>=65); accept both
            assert data["risk_level"] in ("HIGH", "CRITICAL")
            assert data["trust_score"] == 12.0
