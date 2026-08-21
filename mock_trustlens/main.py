"""
Reference / Mock TrustLens-AI Service.
Implements the abhishekayu/trustlens-ai API specification (POST /analyze).
"""

from typing import Any, Dict, List, Optional
from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="TrustLens-AI Engine (Reference / Mock Service)", version="1.0.0")


class AnalyzeRequest(BaseModel):
    url: str


class AnalyzeResponse(BaseModel):
    trustScore: float
    riskLevel: str
    reasons: List[str]
    engines: Dict[str, Any]
    screenshot_url: Optional[str] = None
    html_snapshot_url: Optional[str] = None


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_url(req: AnalyzeRequest):
    url = req.url.lower()

    # Determine risk indicators from domain/URL structure
    has_phish_kw = any(kw in url for kw in ["login", "verify", "secure", "signin", "auth", "account", "update"])
    is_suspicious_tld = any(tld in url for tld in [".xyz", ".top", ".club", ".icu", ".vip"])

    if has_phish_kw:
        trust_score = 12.0
        risk_level = "HIGH"
        reasons = [
            "Credential harvesting form detected on landing page",
            "Impersonation of brand login portal with deceptive CSS layout",
            "Mismatched SSL certificate subject alternative names (SAN)",
            "Newly registered domain (under 14 days active)",
        ]
    elif is_suspicious_tld:
        trust_score = 38.0
        risk_level = "MEDIUM"
        reasons = [
            "Low-reputation top level domain (TLD) observed",
            "No valid MX records configured for corporate domain",
            "High homoglyph distance from official brand entity",
        ]
    else:
        trust_score = 45.0
        risk_level = "MEDIUM"
        reasons = [
            "Domain name closely resembles protected brand entity",
            "Domain parked or active redirection in place",
        ]

    url_hash = abs(hash(req.url))
    return AnalyzeResponse(
        trustScore=trust_score,
        riskLevel=risk_level,
        reasons=reasons,
        engines={
            "ssl_engine": {
                "valid": True,
                "issuer": "Let's Encrypt Authority X3",
                "days_to_expiry": 28,
                "san_match": False,
            },
            "dns_engine": {
                "resolved": True,
                "ip": "198.51.100.42",
                "hosting": "Cloudflare / Bulletproof VPS",
                "has_mx": False,
            },
            "content_engine": {
                "impersonation_detected": has_phish_kw,
                "has_password_field": has_phish_kw,
                "logo_match_confidence": 0.94 if has_phish_kw else 0.40,
            },
            "brand_engine": {
                "visual_similarity": 0.89 if has_phish_kw else 0.35,
            }
        },
        screenshot_url=f"https://trustlens-evidence.storage.com/screenshots/{url_hash}.png",
        html_snapshot_url=f"https://trustlens-evidence.storage.com/dom/{url_hash}.html",
    )


@app.get("/health")
async def health():
    return {"status": "ok", "service": "trustlens-ai"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
