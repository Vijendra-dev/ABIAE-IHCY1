"""
Stage 2 — Brand Detector.

Wraps the existing OpenSquatRunner.calculate_similarity logic and returns
a ranked list of brand matches with their scores.
Also detects whether the brand name is literally embedded inside the domain
(e.g. 'paypal' inside 'paypal-secure-login.com').
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

import Levenshtein
import tldextract

# All brands we protect — extended default set
DEFAULT_BRANDS: List[str] = [
    "paypal", "google", "microsoft", "apple", "netflix",
    "amazon", "facebook", "instagram", "twitter", "chase",
    "bankofamerica", "wellsfargo", "ebay", "dropbox", "adobe",
    "linkedin", "github", "cloudflare", "stripe", "shopify",
    "zoom", "salesforce", "docusign",
]

PHISHING_KEYWORDS: List[str] = [
    "login", "signin", "verify", "secure", "account", "update",
    "support", "portal", "auth", "security", "wallet", "recovery",
    "app", "service", "confirm", "access", "help", "billing",
    "payment", "checkout",
]


@dataclass
class BrandMatch:
    brand: str
    similarity: float          # 0.0–1.0
    brand_embedded: bool       # brand literally inside domain label
    phishing_keyword_present: bool
    all_scores: dict[str, float] = field(default_factory=dict)


def _extract_domain_label(domain: str) -> str:
    ext = tldextract.extract(domain)
    return ext.domain.lower()


def run(domain: str, brands: Optional[List[str]] = None) -> BrandMatch:
    """
    Find the best-matching brand for *domain*.

    Scoring rules (same as OpenSquatRunner but annotated):
    - Base: Levenshtein.ratio(brand, domain_label)
    - Boost to ≥ 0.82 if brand is literally embedded in label
      and domain_label is not identical to brand
    """
    target_brands = brands or DEFAULT_BRANDS
    label = _extract_domain_label(domain)

    best_brand = "Unknown"
    best_sim = 0.0
    all_scores: dict[str, float] = {}

    for b in target_brands:
        b_lower = b.lower()
        ratio = Levenshtein.ratio(b_lower, label)
        # Brand embedded boost
        if b_lower in label and b_lower != label:
            ratio = max(ratio, 0.82)
        ratio = round(ratio, 4)
        all_scores[b_lower] = ratio
        if ratio > best_sim:
            best_sim = ratio
            best_brand = b_lower

    if best_sim < 0.35:
        best_brand = "Unknown"

    brand_embedded = best_brand != "Unknown" and best_brand in label and best_brand != label
    phishing_kw = any(kw in label for kw in PHISHING_KEYWORDS)

    return BrandMatch(
        brand=best_brand,
        similarity=best_sim,
        brand_embedded=brand_embedded,
        phishing_keyword_present=phishing_kw,
        all_scores=all_scores,
    )
