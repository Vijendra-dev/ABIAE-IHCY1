"""
Unit and integration tests for Antigravity Risk Event Client (services/antigravity_client.py).
"""

import pytest
from unittest.mock import AsyncMock, patch
import httpx

from schemas import AntigravityRiskEventPayload
from services.antigravity_client import AntigravityClient


@pytest.mark.asyncio
async def test_antigravity_client_success():
    """
    Tests successful risk event dispatch to Antigravity API.
    """
    client = AntigravityClient(
        base_url="https://antigravity.test",
        api_key="test_api_key_123"
    )

    payload = AntigravityRiskEventPayload(
        case_id="case_abc_123",
        channel="web_domain",
        target="https://paypa1-security.com",
        risk_score=88,
        risk_level="HIGH",
        reasons=["Critical brand lookalike", "Phishing form detected"],
        evidence={"screenshot_url": "https://storage.test/shot.png"},
        recommended_action="takedown_phishing",
    )

    mock_response = httpx.Response(
        status_code=200,
        json={"success": True, "event_id": "ag_evt_99887766"},
        request=httpx.Request("POST", "https://antigravity.test/api/brand-risk-events"),
    )

    with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response

        res = await client.send_risk_event(payload)

        assert res["success"] is True
        assert res["event_id"] == "ag_evt_99887766"
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert args[0] == "https://antigravity.test/api/brand-risk-events"
        assert kwargs["headers"]["Authorization"] == "Bearer test_api_key_123"
        assert kwargs["json"]["case_id"] == "case_abc_123"
        assert kwargs["json"]["risk_score"] == 88


@pytest.mark.asyncio
async def test_antigravity_client_offline_fallback():
    """
    Tests graceful fallback behavior when the Antigravity endpoint is unreachable.
    """
    client = AntigravityClient(
        base_url="https://non-existent-antigravity.internal",
        api_key="key"
    )

    payload = AntigravityRiskEventPayload(
        case_id="case_test_999",
        channel="web_domain",
        target="https://apple-login-verify.site",
        risk_score=92,
        risk_level="HIGH",
        reasons=["High domain similarity"],
        evidence={},
        recommended_action="takedown_phishing",
    )

    with patch.object(httpx.AsyncClient, "post", side_effect=httpx.ConnectError("Connection refused")):
        res = await client.send_risk_event(payload)

        assert res["success"] is False
        assert "event_id" in res
        assert res["event_id"].startswith("ag_offline_")
        assert res.get("offline_fallback") is True
