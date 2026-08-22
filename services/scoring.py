"""
Risk Scoring Engine.
Synthesizes openSquat typosquatting signals and TrustLens-AI explainable trust intelligence
into a unified Case risk score (0-100), risk level (LOW/MEDIUM/HIGH), and consolidated evidence package.
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class RiskScorer:
    """
    Combines domain similarity, threat feeds, and multi-engine deep URL inspection.
    """

    @staticmethod
    def calculate_combined_risk(
        similarity_score: float,
        trustlens_score: Optional[float] = None,
        vt_reputation: Dict[str, Any] = None,
        engine_details: Dict[str, Any] = None,
        trustlens_available: bool = True,
    ) -> Tuple[int, str]:
        """
        Calculates unified Case risk score (0-100) and risk level category.
        When trustlens_available is False (or trustlens_score is None), relies only
        on openSquat domain similarity and returns risk_level="UNKNOWN" without
        fabricating evidence.

        Formula:
        - Squat Risk: similarity_score (0.0 to 1.0) scaled to 0-100.
        - Trust Risk: (100.0 - trustlens_score) (since low trust = high risk).
        - Reputation bonus: +5 to +15 if malicious votes or blacklist hits.
        - Credential theft / impersonation boost: +10 if forms or visual impersonation detected.

        Weighted Average:
            base_risk = (0.45 * squat_risk) + (0.55 * trust_risk)
        """
        # Normalize inputs
        sim = max(0.0, min(1.0, float(similarity_score)))
        squat_risk = sim * 100.0

        if not trustlens_available or trustlens_score is None:
            # Degraded calculation: based solely on domain similarity without fabricated evidence
            final_score = int(round(min(100.0, max(0.0, squat_risk))))
            return final_score, "UNKNOWN"

        trust = max(0.0, min(100.0, float(trustlens_score)))
        trust_risk = 100.0 - trust

        weighted_risk = (0.45 * squat_risk) + (0.55 * trust_risk)

        # Apply threat multipliers / bonuses
        bonus = 0.0
        if vt_reputation:
            malicious_votes = vt_reputation.get("malicious_votes", 0)
            if malicious_votes > 0:
                bonus += min(15.0, malicious_votes * 5.0)

        if engine_details and trustlens_available:
            content_engine = engine_details.get("content_engine", {})
            if content_engine.get("has_credential_input") or content_engine.get("suspicious_form_detected"):
                bonus += 8.0
            brand_engine = engine_details.get("brand_engine", {})
            if brand_engine.get("logo_detected") or brand_engine.get("visual_similarity_score", 0) > 0.8:
                bonus += 7.0

        final_score = int(round(min(100.0, max(0.0, weighted_risk + bonus))))

        # Determine risk level category
        if final_score >= 75:
            risk_level = "HIGH"
        elif final_score >= 45:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return final_score, risk_level

    @staticmethod
    def aggregate_reasons(
        brand: str,
        domain: str,
        similarity_score: float,
        trustlens_reasons: List[str],
        vt_reputation: Dict[str, Any] = None,
        engine_details: Dict[str, Any] = None,
        trustlens_available: bool = True,
    ) -> List[str]:
        """
        Produces a deduplicated, prioritized list of human-readable risk reasons.
        """
        reasons: List[str] = []

        # 1. Typosquatting / domain similarity reasons
        sim_pct = int(round(similarity_score * 100))
        if similarity_score >= 0.85:
            reasons.append(f"Critical brand lookalike domain detected ({sim_pct}% Levenshtein match for '{brand}')")
        elif similarity_score >= 0.70:
            reasons.append(f"High domain name similarity with brand '{brand}' ({sim_pct}% match)")

        # 2. VirusTotal / Feed Reputation reasons
        if vt_reputation:
            mal = vt_reputation.get("malicious_votes", 0)
            if mal > 0:
                reasons.append(f"Flagged as malicious by {mal} external threat intelligence vendor(s)")
            categories = vt_reputation.get("categories", [])
            if "phishing" in categories:
                reasons.append("Identified in active phishing and credential harvesting feeds")

        # 3. TrustLens Explainable AI reasons
        if trustlens_reasons:
            for r in trustlens_reasons:
                clean_r = str(r).strip()
                if clean_r and clean_r not in reasons:
                    reasons.append(clean_r)

        # 4. Engine-specific signals
        if engine_details and trustlens_available:
            content_eng = engine_details.get("content_engine", {})
            if content_eng.get("has_credential_input"):
                reasons.append("Phishing credential capture form discovered on active landing page")
            ssl_eng = engine_details.get("ssl_engine", {})
            if ssl_eng.get("suspicious_cert"):
                reasons.append("Ephemeral or mismatched SSL certificate profile detected")

        # Deduplicate while preserving order
        unique_reasons = []
        for r in reasons:
            if r not in unique_reasons:
                unique_reasons.append(r)

        return unique_reasons

    @classmethod
    def build_evidence_package(
        cls,
        domain: str,
        brand: str,
        similarity_score: float,
        registration_date: str,
        vt_reputation: Dict[str, Any],
        trustlens_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Constructs the comprehensive Case evidence object.
        """
        engines = trustlens_data.get("engines", {})

        return {
            "target_domain": domain,
            "protected_brand": brand,
            "similarity_score": similarity_score,
            "registration_date": registration_date,
            "screenshot_url": trustlens_data.get("screenshot_url"),
            "html_snapshot_url": trustlens_data.get("html_snapshot_url"),
            "engines": engines,
            "ssl": engines.get("ssl_engine", {}),
            "dns": engines.get("dns_engine", {}),
            "content": engines.get("content_engine", {}),
            "brand_inspection": engines.get("brand_engine", {}),
            "whois": {
                "registrar": engines.get("whois", {}).get("registrar", "Unknown/Privacy Protected"),
                "registration_date": registration_date,
            },
            "reputation": vt_reputation or {},
        }
