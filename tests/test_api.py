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
