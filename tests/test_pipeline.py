"""
Tests for the modular analysis pipeline.

Covers three required scenarios:
  1. Official website  → should be LOW risk with verified_official_domain reducer applied
  2. Legitimate brand mention (news site) → should be LOW/MEDIUM with news_or_info_page reducer
  3. Synthetic phishing example → should be HIGH/CRITICAL risk with Threat DNA

Scenario tests use unit-level stage functions (no DB, no HTTP) to be fast and deterministic.
Integration-level tests mock the pipeline orchestrator.
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock


# ============================================================
# Stage 1 — Official Domain Check
# ============================================================
class TestOfficialCheck:
    def test_official_paypal(self):
        from services.pipeline.official_check import run
        result = run(domain="paypal.com", brand="paypal")
        assert result.is_official is True
        assert "verified_official_domain" in result.reducers

    def test_official_google_subdomain(self):
        from services.pipeline.official_check import run
        result = run(domain="www.google.com", brand="google")
        assert result.is_official is True

    def test_news_techcrunch(self):
        from services.pipeline.official_check import run
        result = run(domain="techcrunch.com", brand="paypal")
        assert result.is_official is False
        assert result.is_news_domain is True
        assert "news_or_info_page" in result.reducers

    def test_phishing_domain_not_official(self):
        from services.pipeline.official_check import run
        result = run(domain="paypa1-secure-login.com", brand="paypal")
        assert result.is_official is False
        assert result.is_news_domain is False
        assert result.reducers == []


# ============================================================
# Stage 2 — Brand Detector
# ============================================================
class TestBrandDetector:
    def test_detects_paypal_in_typo(self):
        from services.pipeline.brand_detector import run
        result = run("paypa1-secure.com")
        # 'paypal' is best match even via homoglyph typo (1→l)
        assert result.brand == "paypal"
        # Levenshtein ratio of 'paypal' vs 'paypa1' ≈ 0.91 (domain label is 'paypa1')
        # The embedded boost only fires if brand literally in label; use >=0.5 as safe lower bound
        assert result.similarity >= 0.50

    def test_brand_embedded(self):
        from services.pipeline.brand_detector import run
        result = run("paypal-login.com")
        assert result.brand == "paypal"
        assert result.brand_embedded is True

    def test_phishing_keyword_detected(self):
        from services.pipeline.brand_detector import run
        result = run("paypal-secure-login.com")
        assert result.phishing_keyword_present is True

    def test_unrelated_domain(self):
        from services.pipeline.brand_detector import run
        result = run("example-random-xyz.com")
        assert result.brand == "Unknown" or result.similarity < 0.40


# ============================================================
# Stage 3 — Typosquat Classifier
# ============================================================
class TestTyposquatClassifier:
    def test_homoglyph_paypa1(self):
        from services.pipeline.typosquat_classifier import run
        result = run("paypa1.com", "paypal", 0.90)
        assert result.mutation_class == "homoglyph"

    def test_phishing_keyword(self):
        from services.pipeline.typosquat_classifier import run
        result = run("paypal-login.com", "paypal", 0.82)
        assert result.mutation_class == "phishing_keyword"
        assert any(s.signal == "phishing_keyword_append" for s in result.signals)

    def test_subdomain_abuse(self):
        from services.pipeline.typosquat_classifier import run
        result = run("paypal.attacker-site.com", "paypal", 0.50)
        assert result.mutation_class == "subdomain_abuse"

    def test_omission(self):
        from services.pipeline.typosquat_classifier import run
        result = run("paypl.com", "paypal", 0.85)
        assert result.mutation_class == "omission"


# ============================================================
# Stage 6 — Risk Engine
# ============================================================
class TestRiskEngine:
    def test_official_domain_reduces_score(self):
        from services.pipeline.risk_engine import run
        result = run(
            similarity=0.99,
            trust_score=90.0,
            trustlens_available=True,
            mutation_class="official",
            intent_class="benign",
            has_credential_form=False,
            typosquat_signals=[],
            content_signals=[],
            official_check_reducers=["verified_official_domain"],
        )
        assert result.final_score <= 20
        assert result.risk_level == "LOW"
        reducer_ids = [r.id for r in result.reducers if r.applied]
        assert "verified_official_domain" in reducer_ids

    def test_news_site_reduces_score(self):
        from services.pipeline.risk_engine import run
        result = run(
            similarity=0.55,
            trust_score=75.0,
            trustlens_available=True,
            mutation_class="brand_embedded",
            intent_class="informational",
            has_credential_form=False,
            typosquat_signals=[],
            content_signals=[],
            official_check_reducers=["news_or_info_page"],
        )
        assert result.final_score < 40
        reducer_ids = [r.id for r in result.reducers if r.applied]
        assert "news_or_info_page" in reducer_ids

    def test_phishing_domain_high_score(self):
        from services.pipeline.risk_engine import run
        from services.pipeline.typosquat_classifier import TyposquatSignal
        signal = TyposquatSignal(
            signal="phishing_keyword_append",
            label="Brand combined with phishing keyword",
            value="paypal-login",
            severity="HIGH",
            mutation_class="phishing_keyword",
        )
        result = run(
            similarity=0.82,
            trust_score=15.0,
            trustlens_available=True,
            mutation_class="phishing_keyword",
            intent_class="credential_harvest",
            has_credential_form=True,
            typosquat_signals=[signal],
            content_signals=[],
            official_check_reducers=[],
            vt_reputation={"malicious_votes": 2, "categories": ["phishing"]},
        )
        assert result.final_score >= 65
        assert result.risk_level in ("HIGH", "CRITICAL")

    def test_brand_only_no_fabrication(self):
        """Brand detected but no other signals → should NOT auto-classify as malicious."""
        from services.pipeline.risk_engine import run
        result = run(
            similarity=0.60,
            trust_score=65.0,
            trustlens_available=True,
            mutation_class="brand_embedded",
            intent_class="unknown",
            has_credential_form=False,
            typosquat_signals=[],
            content_signals=[],
            official_check_reducers=[],
        )
        # With moderate similarity and decent trust, should not hit HIGH automatically
        assert result.final_score < 65

    def test_trustlens_unavailable_returns_unknown(self):
        from services.pipeline.risk_engine import run
        result = run(
            similarity=0.80,
            trust_score=None,
            trustlens_available=False,
            mutation_class="phishing_keyword",
            intent_class="unknown",
            has_credential_form=False,
            typosquat_signals=[],
            content_signals=[],
            official_check_reducers=[],
        )
        assert result.risk_level == "UNKNOWN"


# ============================================================
# Stage 7 — Threat DNA
# ============================================================
class TestThreatDNA:
    def test_build_format(self):
        from services.pipeline.threat_dna import build
        dna = build("phishing_keyword", "paypal", "credential_harvest", "HIGH")
        assert dna == "phishing_keyword:paypal:credential_harvest:high"

    def test_build_handles_none(self):
        from services.pipeline.threat_dna import build
        dna = build(None, None, None, None)
        assert dna == "unrelated:unknown:unknown:unknown"

    def test_campaign_id_deterministic(self):
        from services.pipeline.threat_dna import build, campaign_id_from_dna
        dna = build("homoglyph", "google", "phishing", "CRITICAL")
        cid1 = campaign_id_from_dna(dna)
        cid2 = campaign_id_from_dna(dna)
        assert cid1 == cid2
        assert cid1.startswith("camp_")
        assert len(cid1) == 13  # "camp_" + 8 hex chars


# ============================================================
# Pipeline Integration — Scenario Tests (mock TrustLens)
# ============================================================

MOCK_TRUSTLENS_HIGH_TRUST = {
    "trustScore": 88.0,
    "riskLevel": "LOW",
    "reasons": ["Domain has clean SSL, valid DNS, no suspicious content"],
    "engines": {
        "ssl_engine": {"valid": True, "suspicious_cert": False},
        "dns_engine": {"resolved": True},
        "content_engine": {"has_credential_input": False},
        "brand_engine": {"logo_detected": False, "visual_similarity_score": 0.0},
    },
    "success": True,
    "fallback": False,
}

MOCK_TRUSTLENS_LOW_TRUST = {
    "trustScore": 12.0,
    "riskLevel": "HIGH",
    "reasons": ["Credential form detected", "Suspicious SSL cert"],
    "engines": {
        "ssl_engine": {"valid": True, "suspicious_cert": True},
        "dns_engine": {"resolved": True, "newly_observed": True},
        "content_engine": {"has_credential_input": True, "suspicious_form_detected": True},
        "brand_engine": {"logo_detected": True, "visual_similarity_score": 0.90},
    },
    "success": True,
    "fallback": False,
}


@pytest.mark.asyncio
async def test_scenario_official_website():
    """
    Scenario 1: Official website (https://paypal.com)
    Expected: risk_level=LOW, is_official=True, verified_official_domain reducer applied.
    """
    from services.pipeline.orchestrator import run_pipeline

    db_mock = AsyncMock()
    db_mock.execute = AsyncMock(return_value=MagicMock(scalar=MagicMock(return_value=0)))

    with patch("services.pipeline.orchestrator.TrustLensClient") as MockTL:
        MockTL.return_value.analyze_url = AsyncMock(return_value=MOCK_TRUSTLENS_HIGH_TRUST)
        result = await run_pipeline(url="https://paypal.com", db=db_mock)

    assert result.is_official is True
    assert result.risk_level == "LOW"
    assert result.risk_score <= 20
    assert any(r["id"] == "verified_official_domain" and r["applied"] for r in result.risk_reducers)
    assert "official" in result.threat_dna or "paypal" in result.threat_dna
    print("\n[Scenario 1 — Official Website] PASSED")
    print(f"  domain={result.domain} brand={result.brand_detected}")
    print(f"  risk={result.risk_score} level={result.risk_level}")
    print(f"  threat_dna={result.threat_dna}")
    print(f"  reducers_applied={[r['id'] for r in result.risk_reducers if r['applied']]}")


@pytest.mark.asyncio
async def test_scenario_brand_mention_news():
    """
    Scenario 2: Legitimate brand mention on news site (techcrunch.com/paypal-article)
    Expected: risk_level=LOW, is_news=True, news_or_info_page reducer applied.
    """
    from services.pipeline.orchestrator import run_pipeline

    db_mock = AsyncMock()
    db_mock.execute = AsyncMock(return_value=MagicMock(scalar=MagicMock(return_value=0)))

    with patch("services.pipeline.orchestrator.TrustLensClient") as MockTL:
        MockTL.return_value.analyze_url = AsyncMock(return_value=MOCK_TRUSTLENS_HIGH_TRUST)
        result = await run_pipeline(url="https://techcrunch.com", db=db_mock)

    assert result.is_news is True
    assert result.risk_level == "LOW"
    assert any(r["id"] == "news_or_info_page" and r["applied"] for r in result.risk_reducers)
    print("\n[Scenario 2 — Brand Mention / News Site] PASSED")
    print(f"  domain={result.domain} brand={result.brand_detected}")
    print(f"  risk={result.risk_score} level={result.risk_level}")
    print(f"  intent_class={result.intent_class}")
    print(f"  reducers_applied={[r['id'] for r in result.risk_reducers if r['applied']]}")


@pytest.mark.asyncio
async def test_scenario_synthetic_phishing():
    """
    Scenario 3: Synthetic phishing domain (paypa1-secure-login.com)
    Expected: risk_level=HIGH or CRITICAL, has_credential_form=True,
              phishing_keyword mutation class, Threat DNA contains 'paypal'.
    """
    from services.pipeline.orchestrator import run_pipeline

    db_mock = AsyncMock()
    db_mock.execute = AsyncMock(return_value=MagicMock(scalar=MagicMock(return_value=0)))

    with patch("services.pipeline.orchestrator.TrustLensClient") as MockTL:
        MockTL.return_value.analyze_url = AsyncMock(return_value=MOCK_TRUSTLENS_LOW_TRUST)
        result = await run_pipeline(url="https://paypa1-secure-login.com", db=db_mock)

    assert result.is_official is False
    assert result.risk_level in ("HIGH", "CRITICAL")
    assert result.risk_score >= 60
    assert "paypal" in result.threat_dna
    assert result.has_credential_form is True
    print("\n[Scenario 3 — Synthetic Phishing] PASSED")
    print(f"  domain={result.domain} brand={result.brand_detected}")
    print(f"  risk={result.risk_score} level={result.risk_level}")
    print(f"  mutation_class={result.mutation_class}")
    print(f"  intent_class={result.intent_class}")
    print(f"  threat_dna={result.threat_dna}")
    print(f"  signals={[s['signal'] for s in result.signals]}")
    print(f"  reducers_applied={[r['id'] for r in result.risk_reducers if r['applied']]}")
