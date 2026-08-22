"""
Unit tests for Risk Scoring Engine (services/scoring.py).
"""

import pytest
from services.scoring import RiskScorer


def test_scoring_high_risk_impersonation():
    """
    Tests high-risk scenario: high domain similarity + low trust score + phishing forms.
    """
    similarity_score = 0.92  # 92% Levenshtein match
    trustlens_score = 10.0   # 10/100 trust score (very unsafe)
    vt_reputation = {
        "malicious_votes": 3,
        "categories": ["phishing", "brand-squatting"]
    }
    engine_details = {
        "content_engine": {"has_credential_input": True},
        "brand_engine": {"logo_detected": True, "visual_similarity_score": 0.95}
    }

    score, level = RiskScorer.calculate_combined_risk(
        similarity_score=similarity_score,
        trustlens_score=trustlens_score,
        vt_reputation=vt_reputation,
        engine_details=engine_details,
    )

    assert score >= 75
    assert level == "HIGH"
    assert score <= 100


def test_scoring_low_risk():
    """
    Tests low-risk scenario: low similarity + high trust score.
    """
    similarity_score = 0.20
    trustlens_score = 95.0
    vt_reputation = {"malicious_votes": 0}
    engine_details = {}

    score, level = RiskScorer.calculate_combined_risk(
        similarity_score=similarity_score,
        trustlens_score=trustlens_score,
        vt_reputation=vt_reputation,
        engine_details=engine_details,
    )

    assert score < 45
    assert level == "LOW"
    assert score >= 0


def test_scoring_medium_risk():
    """
    Tests medium risk scenario.
    """
    similarity_score = 0.72
    trustlens_score = 50.0

    score, level = RiskScorer.calculate_combined_risk(
        similarity_score=similarity_score,
        trustlens_score=trustlens_score,
    )

    assert 45 <= score < 75
    assert level == "MEDIUM"


def test_scoring_trustlens_unavailable_no_fabricated_evidence():
    """
    Tests that when TrustLens is unavailable, no fabricated high-risk score
    or engine bonuses are applied, and risk level is 'UNKNOWN'.
    """
    similarity_score = 0.50
    trustlens_score = None
    engine_details = {
        "content_engine": {"has_credential_input": True},
        "brand_engine": {"logo_detected": True, "visual_similarity_score": 0.95}
    }

    score, level = RiskScorer.calculate_combined_risk(
        similarity_score=similarity_score,
        trustlens_score=trustlens_score,
        engine_details=engine_details,
        trustlens_available=False,
    )

    # Score should be purely based on similarity_score (50) without credential/brand bonuses
    assert score == 50
    assert level == "UNKNOWN"


def test_aggregate_reasons_trustlens_unavailable():
    """
    Tests that reason aggregation ignores engine_details when trustlens_available is False.
    """
    brand = "PayPal"
    domain = "paypa1-security.com"
    similarity = 0.88
    trust_reasons = ["TrustLens-AI service unavailable — no live inspection performed"]
    engine_details = {"content_engine": {"has_credential_input": True}}

    reasons = RiskScorer.aggregate_reasons(
        brand=brand,
        domain=domain,
        similarity_score=similarity,
        trustlens_reasons=trust_reasons,
        engine_details=engine_details,
        trustlens_available=False,
    )

    assert any("PayPal" in r for r in reasons)
    assert any("unavailable" in r.lower() for r in reasons)
    # Phishing form reason should NOT be present since engine_details are unverified
    assert not any("phishing credential capture form" in r.lower() for r in reasons)


def test_aggregate_reasons_deduplication():
    """
    Tests reason aggregation logic and deduplication.
    """
    brand = "PayPal"
    domain = "paypa1-security.com"
    similarity = 0.88
    trust_reasons = [
        "Suspicious hostname structure with brand impersonation signals",
        "Newly observed certificate authority",
    ]
    vt_reputation = {"malicious_votes": 2, "categories": ["phishing"]}
    engine_details = {"content_engine": {"has_credential_input": True}}

    reasons = RiskScorer.aggregate_reasons(
        brand=brand,
        domain=domain,
        similarity_score=similarity,
        trustlens_reasons=trust_reasons,
        vt_reputation=vt_reputation,
        engine_details=engine_details,
        trustlens_available=True,
    )

    assert len(reasons) >= 3
    assert any("PayPal" in r for r in reasons)
    assert any("phishing" in r.lower() or "credential" in r.lower() for r in reasons)
    # Check deduplication
    assert len(reasons) == len(set(reasons))
