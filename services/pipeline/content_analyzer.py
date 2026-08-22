"""
Stages 4 & 5 — Content / Intent Analysis + Credential Form Detection.

Consumes TrustLens engine telemetry and produces:
  - intent_class: phishing | credential_harvest | informational | brand_mention | benign | unknown
  - content signals list
  - has_credential_form flag
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional

IntentClass = Literal[
    "phishing",
    "credential_harvest",
    "informational",
    "brand_mention",
    "benign",
    "unknown",
]

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


@dataclass
class ContentSignal:
    stage: str = "content"
    signal: str = ""
    label: str = ""
    value: Any = None
    severity: Severity = "MEDIUM"


@dataclass
class ContentResult:
    intent_class: IntentClass
    has_credential_form: bool
    trust_score: Optional[float]
    signals: List[ContentSignal] = field(default_factory=list)
    ssl_valid: Optional[bool] = None
    dns_resolved: Optional[bool] = None


def run(
    trustlens_data: Dict[str, Any],
    is_official: bool = False,
    is_news: bool = False,
) -> ContentResult:
    """
    Analyse TrustLens engine telemetry and classify intent.

    Parameters
    ----------
    trustlens_data : raw dict from TrustLensClient.analyze_url()
    is_official    : already confirmed official domain (Stage 1)
    is_news        : already confirmed news domain (Stage 1)
    """
    engines = trustlens_data.get("engines", {}) or {}
    trust_score: Optional[float] = trustlens_data.get("trustScore")
    tl_available = trustlens_data.get("success", False) and not trustlens_data.get("fallback", False)

    signals: List[ContentSignal] = []
    has_credential_form = False
    ssl_valid: Optional[bool] = None
    dns_resolved: Optional[bool] = None

    # --- Short-circuit for known good domains ---
    if is_official:
        return ContentResult(
            intent_class="benign",
            has_credential_form=False,
            trust_score=trust_score,
            signals=[ContentSignal(
                stage="content",
                signal="official_domain_bypass",
                label="Verified official domain — content analysis bypassed",
                value=True,
                severity="INFO",
            )],
        )

    if is_news:
        return ContentResult(
            intent_class="informational",
            has_credential_form=False,
            trust_score=trust_score,
            signals=[ContentSignal(
                stage="content",
                signal="news_domain_bypass",
                label="Known press/news domain — classified as informational",
                value=True,
                severity="INFO",
            )],
        )

    # --- TrustLens engine signals (only when live data available) ---
    if tl_available:
        content_eng = engines.get("content_engine", {}) or {}
        ssl_eng = engines.get("ssl_engine", {}) or {}
        dns_eng = engines.get("dns_engine", {}) or {}
        brand_eng = engines.get("brand_engine", {}) or {}

        # Credential form detection (Stage 5)
        if content_eng.get("has_credential_input") or content_eng.get("suspicious_form_detected"):
            has_credential_form = True
            signals.append(ContentSignal(
                signal="credential_form_detected",
                label="Login/credential capture form found on page",
                value=True,
                severity="CRITICAL",
            ))

        if content_eng.get("has_redirect_chain"):
            signals.append(ContentSignal(
                signal="redirect_chain",
                label="Multiple URL redirects detected (common evasion technique)",
                value=content_eng.get("redirect_count", "unknown"),
                severity="HIGH",
            ))

        # SSL signals
        ssl_valid = ssl_eng.get("valid")
        if ssl_eng.get("suspicious_cert") or ssl_eng.get("mismatched_san"):
            signals.append(ContentSignal(
                signal="suspicious_ssl_cert",
                label="Ephemeral or mismatched SSL certificate detected",
                value=ssl_eng.get("issuer", "unknown"),
                severity="HIGH",
            ))
        elif ssl_valid is False:
            signals.append(ContentSignal(
                signal="invalid_ssl",
                label="No valid SSL certificate",
                value=False,
                severity="MEDIUM",
            ))

        # DNS signals
        dns_resolved = dns_eng.get("resolved")
        if dns_eng.get("newly_observed"):
            signals.append(ContentSignal(
                signal="newly_observed_domain",
                label="Domain first observed within last 14 days",
                value=True,
                severity="HIGH",
            ))

        # Brand impersonation in page content
        vis_sim = brand_eng.get("visual_similarity_score", 0)
        if brand_eng.get("logo_detected") and vis_sim > 0.75:
            signals.append(ContentSignal(
                signal="brand_logo_impersonation",
                label=f"Detected brand logo with {int(vis_sim*100)}% visual similarity",
                value=vis_sim,
                severity="HIGH",
            ))

        # Trust score signal
        if trust_score is not None:
            if trust_score < 20:
                signals.append(ContentSignal(
                    signal="very_low_trust_score",
                    label=f"Very low TrustLens trust score: {trust_score}/100",
                    value=trust_score,
                    severity="HIGH",
                ))
            elif trust_score >= 70:
                signals.append(ContentSignal(
                    signal="high_trust_score",
                    label=f"High TrustLens trust score: {trust_score}/100",
                    value=trust_score,
                    severity="INFO",
                ))

    # --- Classify intent from signals ---
    intent_class = _classify_intent(signals, trust_score, has_credential_form, tl_available)

    return ContentResult(
        intent_class=intent_class,
        has_credential_form=has_credential_form,
        trust_score=trust_score,
        signals=signals,
        ssl_valid=ssl_valid,
        dns_resolved=dns_resolved,
    )


def _classify_intent(
    signals: List[ContentSignal],
    trust_score: Optional[float],
    has_credential_form: bool,
    tl_available: bool,
) -> IntentClass:
    if not tl_available:
        return "unknown"

    signal_ids = {s.signal for s in signals}

    if has_credential_form and "brand_logo_impersonation" in signal_ids:
        return "phishing"

    if has_credential_form:
        return "credential_harvest"

    if "high_trust_score" in signal_ids and trust_score is not None and trust_score >= 70:
        return "benign"

    if trust_score is not None and trust_score < 25:
        return "phishing"

    if "brand_logo_impersonation" in signal_ids:
        return "brand_mention"

    return "unknown"
