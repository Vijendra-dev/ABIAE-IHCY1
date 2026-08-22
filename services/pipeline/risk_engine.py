"""
Stage 6 — Risk Engine.

Replaces the flat scoring logic in services/scoring.py with a
weighted multi-signal scoring model that:

  1. Computes a base score from domain similarity + TrustLens trust
  2. Adds signal bonuses from typosquat and content stages
  3. Applies EXPLICIT risk reducers that lower the score
  4. Returns final score (0-100), risk_level, and a full audit trail
     of every reducer applied with its score delta

Explicit reducers:
  verified_official_domain  → -80 (floors at 0)
  high_trust_score          → -15
  news_or_info_page         → -10 (only if no credential form)
  authorized_partner        → -25
  low_similarity            → -10 (sim < 0.40 AND brand not embedded)
  benign_intent             → -12 (intent_class == 'benign')
  informational_intent      → -8  (intent_class == 'informational')

Rule: "brand detected + unofficial domain = malicious" is never applied.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional

RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"]


@dataclass
class RiskReducer:
    id: str
    label: str
    applied: bool
    score_delta: int   # always ≤ 0
    reason: str = ""


@dataclass
class RiskSignal:
    stage: str
    signal: str
    label: str
    value: Any
    severity: str
    score_contribution: int = 0


@dataclass
class RiskEngineResult:
    raw_score: int             # score before reducers
    final_score: int           # score after reducers
    risk_level: RiskLevel
    reducers: List[RiskReducer] = field(default_factory=list)
    signals: List[RiskSignal] = field(default_factory=list)
    total_reduction: int = 0


def run(
    similarity: float,
    trust_score: Optional[float],
    trustlens_available: bool,
    mutation_class: str,
    intent_class: str,
    has_credential_form: bool,
    typosquat_signals: list,
    content_signals: list,
    official_check_reducers: List[str],
    vt_reputation: Optional[Dict[str, Any]] = None,
    brand_embedded: bool = False,
) -> RiskEngineResult:
    """
    Compute final risk score with full reducer audit trail.
    """
    signals: List[RiskSignal] = []
    reducers: List[RiskReducer] = []

    # ------------------------------------------------------------------
    # 1. Base score components
    # ------------------------------------------------------------------
    sim = max(0.0, min(1.0, float(similarity)))
    squat_risk = sim * 100.0   # 0-100

    if not trustlens_available or trust_score is None:
        # Degraded: similarity-only, no fabricated evidence
        return RiskEngineResult(
            raw_score=int(round(squat_risk)),
            final_score=int(round(squat_risk)),
            risk_level="UNKNOWN",
            reducers=[RiskReducer(
                id="trustlens_unavailable",
                label="TrustLens unavailable — similarity-only score",
                applied=True,
                score_delta=0,
                reason="Cannot determine authoritative risk without live engine data",
            )],
            signals=[],
            total_reduction=0,
        )

    trust = max(0.0, min(100.0, float(trust_score)))
    trust_risk = 100.0 - trust

    # Weighted base (45% domain similarity, 55% trust risk)
    base = (0.45 * squat_risk) + (0.55 * trust_risk)

    # ------------------------------------------------------------------
    # 2. Signal bonuses (only additive signals)
    # ------------------------------------------------------------------
    bonus = 0

    # VirusTotal reputation
    if vt_reputation:
        mal_votes = int(vt_reputation.get("malicious_votes", 0))
        if mal_votes > 0:
            contribution = min(15, mal_votes * 5)
            bonus += contribution
            signals.append(RiskSignal(
                stage="reputation",
                signal="vt_malicious_votes",
                label=f"Flagged by {mal_votes} threat intelligence vendor(s)",
                value=mal_votes,
                severity="HIGH",
                score_contribution=contribution,
            ))

    # Credential form
    if has_credential_form:
        bonus += 10
        signals.append(RiskSignal(
            stage="content",
            signal="credential_form_bonus",
            label="Credential capture form increases risk",
            value=True,
            severity="CRITICAL",
            score_contribution=10,
        ))

    # Typosquat signals
    for ts in typosquat_signals:
        severity = getattr(ts, "severity", "MEDIUM")
        contrib = {"CRITICAL": 8, "HIGH": 6, "MEDIUM": 3, "LOW": 1, "INFO": 0}.get(severity, 2)
        bonus += contrib
        signals.append(RiskSignal(
            stage="typosquatting",
            signal=getattr(ts, "signal", ""),
            label=getattr(ts, "label", ""),
            value=getattr(ts, "value", ""),
            severity=severity,
            score_contribution=contrib,
        ))

    raw_score = int(round(min(100.0, max(0.0, base + bonus))))

    # ------------------------------------------------------------------
    # 3. Risk reducers (explicit, auditable)
    # ------------------------------------------------------------------
    reduction = 0

    # verified_official_domain → -80
    _apply_reducer(
        reducers=reducers,
        rid="verified_official_domain",
        label="Verified official brand domain",
        condition="verified_official_domain" in official_check_reducers,
        delta=-80,
        reason="Domain is in the curated official domain registry for this brand",
        reduction=reduction,
    )
    if reducers and reducers[-1].applied:
        reduction += 80

    # authorized_partner → -25
    _apply_reducer(
        reducers=reducers,
        rid="authorized_partner",
        label="Authorized brand partner or CDN",
        condition="authorized_partner" in official_check_reducers,
        delta=-25,
        reason="Domain is a known authorized partner, affiliate, or CDN for this brand",
        reduction=reduction,
    )
    if reducers and reducers[-1].applied and reducers[-1].id == "authorized_partner":
        reduction += 25

    # news_or_info_page → -10 (only when no credential form)
    _apply_reducer(
        reducers=reducers,
        rid="news_or_info_page",
        label="Known news or informational website",
        condition=("news_or_info_page" in official_check_reducers or intent_class == "informational")
                  and not has_credential_form,
        delta=-10,
        reason="Domain is a known press/news site with no credential harvesting",
        reduction=reduction,
    )
    if reducers and reducers[-1].applied and reducers[-1].id == "news_or_info_page":
        reduction += 10

    # high_trust_score → -15
    _apply_reducer(
        reducers=reducers,
        rid="high_trust_score",
        label="High TrustLens trust score (≥70)",
        condition=trust_score is not None and trust_score >= 70,
        delta=-15,
        reason=f"TrustLens returned trust score {trust_score}/100",
        reduction=reduction,
    )
    if reducers and reducers[-1].applied and reducers[-1].id == "high_trust_score":
        reduction += 15

    # benign_intent → -12
    _apply_reducer(
        reducers=reducers,
        rid="benign_intent",
        label="Intent classified as benign by content engine",
        condition=intent_class == "benign",
        delta=-12,
        reason="Content analysis found no phishing indicators",
        reduction=reduction,
    )
    if reducers and reducers[-1].applied and reducers[-1].id == "benign_intent":
        reduction += 12

    # informational_intent → -8
    _apply_reducer(
        reducers=reducers,
        rid="informational_intent",
        label="Intent classified as informational",
        condition=intent_class == "informational" and not has_credential_form,
        delta=-8,
        reason="Page intent appears informational with no active threat signals",
        reduction=reduction,
    )
    if reducers and reducers[-1].applied and reducers[-1].id == "informational_intent":
        reduction += 8

    # low_similarity → -10
    _apply_reducer(
        reducers=reducers,
        rid="low_similarity",
        label="Low domain similarity to brand (< 40%)",
        condition=similarity < 0.40 and not brand_embedded,
        delta=-10,
        reason=f"Domain similarity is only {int(similarity*100)}% with brand not embedded",
        reduction=reduction,
    )
    if reducers and reducers[-1].applied and reducers[-1].id == "low_similarity":
        reduction += 10

    # ------------------------------------------------------------------
    # 4. Final score & risk level
    # ------------------------------------------------------------------
    final_score = max(0, min(100, raw_score - reduction))

    if final_score >= 80:
        risk_level: RiskLevel = "CRITICAL"
    elif final_score >= 65:
        risk_level = "HIGH"
    elif final_score >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return RiskEngineResult(
        raw_score=raw_score,
        final_score=final_score,
        risk_level=risk_level,
        reducers=reducers,
        signals=signals,
        total_reduction=reduction,
    )


def _apply_reducer(
    reducers: List[RiskReducer],
    rid: str,
    label: str,
    condition: bool,
    delta: int,
    reason: str,
    reduction: int,
):
    """Helper: appends a reducer with applied=True/False."""
    reducers.append(RiskReducer(
        id=rid,
        label=label,
        applied=condition,
        score_delta=delta if condition else 0,
        reason=reason if condition else "",
    ))
