"""
Pipeline Orchestrator.

Ties all 9 stages together and exposes a single async function:
    run_pipeline(url, db, brands=None) -> PipelineResult

All stages are run in sequence. The orchestrator:
  - Handles TrustLens unavailability gracefully
  - Passes outputs of each stage as inputs to the next
  - Builds the unified reasons list from all stages
  - Persists threat_dna + campaign_id on the Case record
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import tldextract
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from services.trustlens_client import TrustLensClient

from . import official_check as stage1
from . import brand_detector as stage2
from . import typosquat_classifier as stage3
from . import content_analyzer as stage4
from . import risk_engine as stage6
from . import threat_dna as stage7
from . import campaign_linker as stage8

logger = logging.getLogger(__name__)

PIPELINE_STAGES = [
    "official_check",
    "brand_detection",
    "typosquat_classification",
    "content_intent_analysis",
    "credential_form_detection",
    "risk_engine",
    "threat_dna",
    "campaign_linking",
]


@dataclass
class PipelineResult:
    # Core fields (preserved for existing routes)
    target_url: str
    domain: str
    brand_detected: str
    similarity_score: float
    trust_score: Optional[float]
    risk_score: int
    risk_level: str
    analysis_complete: bool

    # Extended pipeline fields
    threat_dna: str
    campaign_id: Optional[str]
    campaign_hits: int
    mutation_class: str
    intent_class: str
    has_credential_form: bool
    pipeline_stages: List[str]

    # Audit trail
    signals: List[Dict[str, Any]] = field(default_factory=list)
    risk_reducers: List[Dict[str, Any]] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)

    # Metadata
    is_official: bool = False
    is_news: bool = False
    is_authorized_partner: bool = False


async def run_pipeline(
    url: str,
    db: AsyncSession,
    brands: Optional[List[str]] = None,
    existing_case_id: Optional[str] = None,
) -> PipelineResult:
    """
    Execute the full 9-stage analysis pipeline.

    Parameters
    ----------
    url              : full URL to analyse (with or without scheme)
    db               : async SQLAlchemy session (for campaign lookup)
    brands           : override brand list (defaults to settings.BRAND_LIST + extended set)
    existing_case_id : exclude this case ID from campaign hit count

    Returns
    -------
    PipelineResult
    """
    # --- Normalise URL ---
    if not url.startswith("http://") and not url.startswith("https://"):
        target_url = f"https://{url}"
    else:
        target_url = url
    domain_str = target_url.split("://")[-1].split("/")[0]

    ext = tldextract.extract(domain_str)
    apex_domain = f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else domain_str.lower()

    target_brands = brands or (
        settings.BRAND_LIST
        if isinstance(settings.BRAND_LIST, list)
        else ["google", "paypal", "microsoft", "apple", "netflix"]
    )

    logger.info("[Pipeline] Starting analysis for %s", target_url)

    # -----------------------------------------------------------------------
    # Stage 2 — Brand Detection
    # -----------------------------------------------------------------------
    brand_result = stage2.run(domain_str, brands=target_brands)
    brand = brand_result.brand
    similarity = brand_result.similarity

    logger.info("[Pipeline:brand_detection] brand=%s sim=%.2f", brand, similarity)

    # -----------------------------------------------------------------------
    # Stage 1 — Official Domain Check (needs brand from Stage 2)
    # -----------------------------------------------------------------------
    official_result = stage1.run(domain=domain_str, brand=brand)

    logger.info("[Pipeline:official_check] is_official=%s is_news=%s",
                official_result.is_official, official_result.is_news_domain)

    # -----------------------------------------------------------------------
    # Call TrustLens-AI
    # -----------------------------------------------------------------------
    trustlens_client = TrustLensClient()
    trustlens_data = await trustlens_client.analyze_url(target_url)
    is_available = (
        bool(trustlens_data.get("success", False))
        and not bool(trustlens_data.get("fallback", False))
    )
    trust_score = trustlens_data.get("trustScore")
    trust_reasons: List[str] = trustlens_data.get("reasons", [])

    # -----------------------------------------------------------------------
    # Stage 3 — Typosquatting Classification
    # -----------------------------------------------------------------------
    typosquat_result = stage3.run(
        domain=domain_str,
        brand=brand,
        similarity=similarity,
    )
    mutation_class = typosquat_result.mutation_class

    # -----------------------------------------------------------------------
    # Stages 4 & 5 — Content / Intent Analysis + Credential Form Detection
    # -----------------------------------------------------------------------
    content_result = stage4.run(
        trustlens_data=trustlens_data,
        is_official=official_result.is_official,
        is_news=official_result.is_news_domain,
    )
    intent_class = content_result.intent_class
    has_credential_form = content_result.has_credential_form

    # -----------------------------------------------------------------------
    # Stage 6 — Risk Engine
    # -----------------------------------------------------------------------
    vt_reputation = _build_vt_reputation(similarity, brand_result.brand_embedded)

    risk_result = stage6.run(
        similarity=similarity,
        trust_score=trust_score,
        trustlens_available=is_available,
        mutation_class=mutation_class,
        intent_class=intent_class,
        has_credential_form=has_credential_form,
        typosquat_signals=typosquat_result.signals,
        content_signals=content_result.signals,
        official_check_reducers=official_result.reducers,
        vt_reputation=vt_reputation,
        brand_embedded=brand_result.brand_embedded,
    )
    final_score = risk_result.final_score
    risk_level = risk_result.risk_level

    # -----------------------------------------------------------------------
    # Stage 7 — Threat DNA
    # -----------------------------------------------------------------------
    dna = stage7.build(
        mutation_class=mutation_class,
        brand=brand,
        intent_class=intent_class,
        risk_level=risk_level,
    )

    # -----------------------------------------------------------------------
    # Stage 8 — Campaign Linker
    # -----------------------------------------------------------------------
    campaign_result = await stage8.run(
        db=db,
        threat_dna=dna,
        exclude_case_id=existing_case_id,
    )

    # -----------------------------------------------------------------------
    # Stage 9 — Response Builder
    # -----------------------------------------------------------------------
    all_signals = (
        [_signal_to_dict(s) for s in typosquat_result.signals]
        + [_signal_to_dict(s) for s in content_result.signals]
        + [_risksig_to_dict(s) for s in risk_result.signals]
    )
    reducers_out = [_reducer_to_dict(r) for r in risk_result.reducers]
    reasons = _build_reasons(
        brand=brand,
        domain=domain_str,
        similarity=similarity,
        typosquat_signals=typosquat_result.signals,
        content_signals=content_result.signals,
        risk_reducers=risk_result.reducers,
        trust_reasons=trust_reasons,
        is_official=official_result.is_official,
        is_news=official_result.is_news_domain,
    )

    evidence = _build_evidence(
        domain=domain_str,
        brand=brand,
        similarity=similarity,
        trustlens_data=trustlens_data,
        vt_reputation=vt_reputation,
        dna=dna,
        campaign_id=campaign_result.campaign_id,
        mutation_class=mutation_class,
        intent_class=intent_class,
    )

    logger.info("[Pipeline] Complete: score=%d level=%s dna=%s campaign=%s",
                final_score, risk_level, dna, campaign_result.campaign_id)

    return PipelineResult(
        target_url=target_url,
        domain=domain_str,
        brand_detected=brand,
        similarity_score=similarity,
        trust_score=trust_score,
        risk_score=final_score,
        risk_level=risk_level,
        analysis_complete=is_available,
        threat_dna=dna,
        campaign_id=campaign_result.campaign_id,
        campaign_hits=campaign_result.campaign_hits,
        mutation_class=mutation_class,
        intent_class=intent_class,
        has_credential_form=has_credential_form,
        pipeline_stages=PIPELINE_STAGES,
        signals=all_signals,
        risk_reducers=reducers_out,
        reasons=reasons,
        evidence=evidence,
        is_official=official_result.is_official,
        is_news=official_result.is_news_domain,
        is_authorized_partner=official_result.is_authorized_partner,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_vt_reputation(similarity: float, brand_embedded: bool) -> Dict[str, Any]:
    """Heuristic VT-like reputation (used when no real VT integration is configured)."""
    if similarity >= 0.85 or brand_embedded:
        return {
            "malicious_votes": 2,
            "suspicious_votes": 3,
            "categories": ["phishing", "brand-squatting"],
        }
    if similarity >= 0.70:
        return {
            "malicious_votes": 0,
            "suspicious_votes": 2,
            "categories": ["newly-registered"],
        }
    return {
        "malicious_votes": 0,
        "suspicious_votes": 0,
        "categories": ["general-web"],
    }


def _signal_to_dict(s) -> Dict[str, Any]:
    return {
        "stage": getattr(s, "stage", ""),
        "signal": getattr(s, "signal", ""),
        "label": getattr(s, "label", ""),
        "value": getattr(s, "value", None),
        "severity": getattr(s, "severity", "INFO"),
    }


def _risksig_to_dict(s) -> Dict[str, Any]:
    return {
        "stage": getattr(s, "stage", "risk_engine"),
        "signal": getattr(s, "signal", ""),
        "label": getattr(s, "label", ""),
        "value": getattr(s, "value", None),
        "severity": getattr(s, "severity", "INFO"),
        "score_contribution": getattr(s, "score_contribution", 0),
    }


def _reducer_to_dict(r) -> Dict[str, Any]:
    return {
        "id": r.id,
        "label": r.label,
        "applied": r.applied,
        "score_delta": r.score_delta,
        "reason": r.reason,
    }


def _build_reasons(
    brand: str,
    domain: str,
    similarity: float,
    typosquat_signals: list,
    content_signals: list,
    risk_reducers: list,
    trust_reasons: List[str],
    is_official: bool,
    is_news: bool,
) -> List[str]:
    reasons: List[str] = []
    sim_pct = int(round(similarity * 100))

    # Official / news overrides come first
    if is_official:
        reasons.append(f"Verified official {brand.capitalize()} domain — no threat detected")
        return reasons
    if is_news:
        reasons.append(f"Known press/news website — brand mention, not impersonation")

    # Typosquat signals
    for sig in typosquat_signals:
        lbl = getattr(sig, "label", "")
        if lbl and lbl not in reasons:
            reasons.append(lbl)

    # Content signals (only negative ones)
    for sig in content_signals:
        sev = getattr(sig, "severity", "INFO")
        lbl = getattr(sig, "label", "")
        if sev in ("CRITICAL", "HIGH", "MEDIUM") and lbl and lbl not in reasons:
            reasons.append(lbl)

    # TrustLens reasons
    for r in trust_reasons:
        clean = str(r).strip()
        if clean and clean not in reasons:
            reasons.append(clean)

    # Applied reducers as positive/mitigating statements
    for rd in risk_reducers:
        if getattr(rd, "applied", False):
            lbl = getattr(rd, "label", "")
            if lbl and lbl not in reasons:
                reasons.append(f"[Mitigating] {lbl}")

    # Similarity note
    if similarity >= 0.70 and not is_official:
        reasons.append(f"Domain name is {sim_pct}% similar to brand '{brand}'")

    return list(dict.fromkeys(reasons))  # preserve order, deduplicate


def _build_evidence(
    domain: str,
    brand: str,
    similarity: float,
    trustlens_data: Dict[str, Any],
    vt_reputation: Dict[str, Any],
    dna: str,
    campaign_id: Optional[str],
    mutation_class: str,
    intent_class: str,
) -> Dict[str, Any]:
    engines = trustlens_data.get("engines", {}) or {}
    return {
        "target_domain": domain,
        "protected_brand": brand,
        "similarity_score": similarity,
        "registration_date": "Active / Observed",
        "screenshot_url": trustlens_data.get("screenshot_url"),
        "html_snapshot_url": trustlens_data.get("html_snapshot_url"),
        "engines": engines,
        "ssl": engines.get("ssl_engine", {}),
        "dns": engines.get("dns_engine", {}),
        "content": engines.get("content_engine", {}),
        "brand_inspection": engines.get("brand_engine", {}),
        "whois": {
            "registrar": engines.get("whois", {}).get("registrar", "Unknown/Privacy Protected"),
            "registration_date": "Active / Observed",
        },
        "reputation": vt_reputation,
        "threat_dna": dna,
        "campaign_id": campaign_id,
        "mutation_class": mutation_class,
        "intent_class": intent_class,
    }
