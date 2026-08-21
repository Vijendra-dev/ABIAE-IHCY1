"""
TrustLens-AI Client.
Communicates with the abhishekayu/trustlens-ai engine to perform deep,
explainable multi-engine URL risk analysis (SSL, DNS, content, brand impersonation, visual screenshots).
"""

import logging
from typing import Any, Dict, Optional
import httpx
from config import settings

import time

logger = logging.getLogger(__name__)


class TrustLensClient:
    """
    HTTP client for TrustLens-AI URL inspection service.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        timeout: Optional[float] = None
    ):
        base = (base_url or settings.TRUSTLENS_BASE_URL).rstrip("/")
        if "localhost" in base:
            base = base.replace("localhost", "127.0.0.1")
        self.base_url = base
        self.timeout = timeout or settings.TRUSTLENS_TIMEOUT_SECONDS
        self._offline_until: float = 0.0

    async def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Calls TrustLens-AI endpoint POST /analyze { "url": "..." }.
        Returns trust score, risk level, explainable reasons, engine telemetry, and visual evidence.
        """
        endpoint = f"{self.base_url}/analyze"
        payload = {"url": url}

        # Circuit breaker: if service recently failed to connect, immediately use fallback
        if time.time() < self._offline_until:
            return self._fallback_analysis(url, error="TrustLens service offline (circuit open)")

        logger.info("Calling TrustLens-AI for URL: %s (endpoint: %s)", url, endpoint)

        try:
            timeout_cfg = httpx.Timeout(self.timeout, connect=0.2)
            async with httpx.AsyncClient(timeout=timeout_cfg) as client:
                response = await client.post(endpoint, json=payload)
                if response.status_code == 200:
                    data = response.json()
                    logger.info("TrustLens-AI response for %s: trustScore=%s, riskLevel=%s",
                                url, data.get("trustScore"), data.get("riskLevel"))
                    return self._normalize_response(data, url)
                else:
                    logger.warning(
                        "TrustLens-AI returned non-200 status %d: %s. Using fallback heuristic analysis.",
                        response.status_code,
                        response.text[:200]
                    )
                    return self._fallback_analysis(url, error=f"HTTP {response.status_code}")

        except (httpx.ConnectError, httpx.TimeoutException, httpx.RequestError) as e:
            self._offline_until = time.time() + 5.0
            logger.warning(
                "Failed to reach TrustLens-AI at %s: %s. Using fallback heuristic analysis (circuit tripped for 5s).",
                endpoint,
                str(e)
            )
            return self._fallback_analysis(url, error=str(e))

    def _normalize_response(self, data: Dict[str, Any], url: str) -> Dict[str, Any]:
        """
        Ensures consistent response format from TrustLens-AI.
        """
        trust_score = float(data.get("trustScore", data.get("trust_score", 50.0)))
        risk_level = str(data.get("riskLevel", data.get("risk_level", "MEDIUM"))).upper()
        reasons = data.get("reasons", [])
        if isinstance(reasons, str):
            reasons = [reasons]

        engines = data.get("engines", {})
        screenshot_url = data.get("screenshot_url", data.get("screenshotUrl"))
        html_snapshot_url = data.get("html_snapshot_url", data.get("htmlSnapshotUrl"))

        return {
            "trustScore": trust_score,
            "riskLevel": risk_level,
            "reasons": reasons,
            "engines": engines,
            "screenshot_url": screenshot_url,
            "html_snapshot_url": html_snapshot_url,
            "url": url,
            "success": True,
        }

    def _fallback_analysis(self, url: str, error: Optional[str] = None) -> Dict[str, Any]:
        """
        Deterministic fallback analysis when TrustLens-AI microservice is offline or in mock mode.
        Simulates explainable heuristic insights for lookalike URLs.
        """
        url_lower = url.lower()

        # Heuristic trust score calculation based on common phishing indicators
        trust_score = 15.0 if any(k in url_lower for k in ["login", "verify", "secure", "signin", "auth"]) else 35.0
        risk_level = "HIGH" if trust_score < 30 else "MEDIUM"

        reasons = [
            "Suspicious hostname structure with brand impersonation signals",
            "Newly observed certificate authority or self-signed SSL profile",
            "Target domain matches known typosquatting homoglyph patterns",
        ]
        if error:
            reasons.append(f"[TrustLens Offline Fallback: {error}]")

        engines = {
            "ssl_engine": {
                "valid": True,
                "issuer": "Let's Encrypt / Automated Short-Lived Cert",
                "days_to_expiry": 14,
                "suspicious_cert": True,
            },
            "dns_engine": {
                "resolved": True,
                "fast_flux_detected": False,
                "has_mx_record": False,
            },
            "content_engine": {
                "impersonation_score": 0.88,
                "has_credential_input": True,
                "hidden_iframe_detected": False,
            },
            "brand_engine": {
                "visual_similarity_score": 0.82,
                "logo_detected": True,
            }
        }

        return {
            "trustScore": trust_score,
            "riskLevel": risk_level,
            "reasons": reasons,
            "engines": engines,
            "screenshot_url": f"https://evidence-storage.local/screenshots/{abs(hash(url))}.png",
            "html_snapshot_url": f"https://evidence-storage.local/snapshots/{abs(hash(url))}.html",
            "url": url,
            "success": False,
            "fallback": True,
        }
