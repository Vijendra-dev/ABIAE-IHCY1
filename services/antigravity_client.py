"""
Antigravity Platform Risk Event Dispatcher Client.
Dispatches high-risk brand impersonation events to the external Antigravity system via HTTP POST.
"""

import logging
import uuid
from typing import Any, Dict, Optional
import httpx

from config import settings
from schemas import AntigravityRiskEventPayload

logger = logging.getLogger(__name__)


class AntigravityClient:
    """
    HTTP Client for dispatching brand risk incidents to the Antigravity Security & Takedown Platform.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = 15.0
    ):
        self.base_url = (base_url or settings.ANTIGRAVITY_BASE_URL).rstrip("/")
        self.api_key = api_key or settings.ANTIGRAVITY_API_KEY
        self.timeout = timeout

    async def send_risk_event(self, payload: AntigravityRiskEventPayload) -> Dict[str, Any]:
        """
        Sends brand risk event to Antigravity API.
        Endpoint: POST {ANTIGRAVITY_BASE_URL}/api/brand-risk-events
        Headers: Authorization: Bearer {ANTIGRAVITY_API_KEY}
        """
        endpoint = f"{self.base_url}/api/brand-risk-events"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": f"BrandIntelligenceBackend/{settings.APP_VERSION}",
        }

        data = payload.model_dump()
        logger.info(
            "Dispatching risk event to Antigravity for Case %s (Score: %d, Target: %s)",
            payload.case_id,
            payload.risk_score,
            payload.target,
        )

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(endpoint, json=data, headers=headers)
                if response.status_code in (200, 201, 202):
                    res_json = response.json()
                    event_id = res_json.get("event_id", res_json.get("id", f"ag_evt_{uuid.uuid4().hex[:12]}"))
                    logger.info("Successfully registered Antigravity event: %s for Case: %s", event_id, payload.case_id)
                    return {
                        "success": True,
                        "event_id": event_id,
                        "status_code": response.status_code,
                        "response": res_json,
                    }
                else:
                    logger.warning(
                        "Antigravity API returned status %d: %s. Generating local reference ID.",
                        response.status_code,
                        response.text[:200]
                    )
                    local_evt_id = f"ag_mock_{uuid.uuid4().hex[:12]}"
                    return {
                        "success": False,
                        "event_id": local_evt_id,
                        "error": f"HTTP {response.status_code}",
                        "status_code": response.status_code,
                    }

        except (httpx.ConnectError, httpx.TimeoutException, httpx.RequestError) as e:
            logger.warning(
                "Unable to connect to Antigravity endpoint at %s (%s). Generating fallback event ID for tracing.",
                endpoint,
                str(e),
            )
            # Produce deterministic or traceable synthetic event ID when remote endpoint is not hosted locally
            synthetic_id = f"ag_offline_{uuid.uuid4().hex[:12]}"
            return {
                "success": False,
                "event_id": synthetic_id,
                "error": str(e),
                "offline_fallback": True,
            }
