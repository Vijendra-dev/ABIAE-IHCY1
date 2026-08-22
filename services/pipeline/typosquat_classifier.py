"""
Stage 3 — Typosquatting Classifier.

Classifies the mutation class of a suspicious domain relative to the
detected brand. Outputs a list of signals with severity ratings.

Mutation classes:
  official           — exact official domain (handled in Stage 1, but kept for completeness)
  homoglyph          — visual character substitution (a→4, o→0, i→1 etc.)
  omission           — character removed from brand name
  duplication        — character doubled in brand name
  transposition      — adjacent characters swapped
  phishing_keyword   — brand + phishing keyword appended/prepended
  subdomain_abuse    — brand used as subdomain of attacker domain
  tld_variation      — same label, different TLD
  brand_embedded     — brand string inside longer label with modifiers
  unrelated          — no detectable mutation pattern (generic/unrelated)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Literal

import tldextract

MutationClass = Literal[
    "official", "homoglyph", "omission", "duplication",
    "transposition", "phishing_keyword", "subdomain_abuse",
    "tld_variation", "brand_embedded", "unrelated",
]

HOMOGLYPHS: dict[str, list[str]] = {
    "a": ["4", "@", "q", "à", "á"],
    "e": ["3", "€", "è", "é"],
    "i": ["1", "l", "!", "|", "í"],
    "l": ["1", "i", "|"],
    "o": ["0", "q", "ø"],
    "s": ["5", "$", "ß"],
    "t": ["7", "+"],
    "g": ["9", "q"],
    "m": ["rn", "nn"],
    "w": ["vv", "uu"],
    "n": ["m", "ri"],
    "u": ["v", "ü"],
    "b": ["d", "6"],
    "p": ["q"],
}

PHISHING_KEYWORDS: list[str] = [
    "login", "signin", "verify", "secure", "account", "update",
    "support", "portal", "auth", "security", "wallet", "recovery",
    "app", "service", "confirm", "access", "help", "billing",
    "payment", "checkout", "customer", "online", "web", "my",
]

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


@dataclass
class TyposquatSignal:
    stage: str = "typosquatting"
    signal: str = ""          # machine-readable signal id
    label: str = ""           # human-readable label
    value: str = ""           # observed value
    severity: Severity = "MEDIUM"
    mutation_class: MutationClass = "unrelated"


@dataclass
class TyposquatResult:
    mutation_class: MutationClass
    signals: List[TyposquatSignal] = field(default_factory=list)


def _extract_parts(domain: str):
    ext = tldextract.extract(domain)
    return ext.subdomain.lower(), ext.domain.lower(), ext.suffix.lower()


def _has_homoglyph(brand: str, label: str) -> bool:
    """Check whether label could be derived from brand via homoglyph substitution."""
    if len(brand) != len(label):
        # Allow ±1 for compound substitutions like m→rn
        if abs(len(brand) - len(label)) > 2:
            return False
    for i, ch in enumerate(brand):
        if ch in HOMOGLYPHS:
            for sub in HOMOGLYPHS[ch]:
                candidate = brand[:i] + sub + brand[i + 1:]
                if candidate == label:
                    return True
    return False


def _has_omission(brand: str, label: str) -> bool:
    if len(label) != len(brand) - 1:
        return False
    for i in range(len(brand)):
        if brand[:i] + brand[i + 1:] == label:
            return True
    return False


def _has_duplication(brand: str, label: str) -> bool:
    if len(label) != len(brand) + 1:
        return False
    for i in range(len(brand)):
        if brand[:i] + brand[i] + brand[i:] == label:
            return True
    return False


def _has_transposition(brand: str, label: str) -> bool:
    if len(brand) != len(label):
        return False
    for i in range(len(brand) - 1):
        t = brand[:i] + brand[i + 1] + brand[i] + brand[i + 2:]
        if t == label:
            return True
    return False


def run(domain: str, brand: str, similarity: float) -> TyposquatResult:
    """
    Classify the mutation type and return all detected signals.
    """
    signals: List[TyposquatSignal] = []
    sub, label, tld = _extract_parts(domain)
    b = brand.lower()

    # --- Subdomain abuse: brand used as subdomain of attacker domain ---
    if sub and b in sub and b != label:
        signals.append(TyposquatSignal(
            signal="subdomain_brand_abuse",
            label="Brand name used as subdomain of attacker-controlled domain",
            value=f"{sub}.{label}.{tld}",
            severity="CRITICAL",
            mutation_class="subdomain_abuse",
        ))
        return TyposquatResult(mutation_class="subdomain_abuse", signals=signals)

    # --- TLD variation: label identical to brand but different TLD ---
    if label == b and tld not in ("com", "org", "net"):
        signals.append(TyposquatSignal(
            signal="tld_variation",
            label="Exact brand name registered under alternate TLD",
            value=f"{label}.{tld}",
            severity="HIGH",
            mutation_class="tld_variation",
        ))

    # --- Phishing keyword combined with brand ---
    present_kws = [kw for kw in PHISHING_KEYWORDS if kw in label]
    if b in label and b != label and present_kws:
        for kw in present_kws:
            signals.append(TyposquatSignal(
                signal="phishing_keyword_append",
                label=f"Brand '{b}' combined with phishing keyword '{kw}'",
                value=label,
                severity="HIGH",
                mutation_class="phishing_keyword",
            ))

    # --- Homoglyph substitution ---
    if _has_homoglyph(b, label):
        signals.append(TyposquatSignal(
            signal="homoglyph_substitution",
            label="Visual character substitution to impersonate brand",
            value=label,
            severity="HIGH",
            mutation_class="homoglyph",
        ))

    # --- Character omission ---
    if _has_omission(b, label):
        signals.append(TyposquatSignal(
            signal="character_omission",
            label="Single character removed from brand name",
            value=label,
            severity="MEDIUM",
            mutation_class="omission",
        ))

    # --- Character duplication ---
    if _has_duplication(b, label):
        signals.append(TyposquatSignal(
            signal="character_duplication",
            label="Single character doubled in brand name",
            value=label,
            severity="MEDIUM",
            mutation_class="duplication",
        ))

    # --- Transposition ---
    if _has_transposition(b, label):
        signals.append(TyposquatSignal(
            signal="character_transposition",
            label="Adjacent characters swapped in brand name",
            value=label,
            severity="MEDIUM",
            mutation_class="transposition",
        ))

    # --- Brand embedded inside longer label ---
    if b in label and b != label and not present_kws:
        signals.append(TyposquatSignal(
            signal="brand_embedded",
            label=f"Brand '{b}' embedded in unrelated domain label",
            value=label,
            severity="MEDIUM",
            mutation_class="brand_embedded",
        ))

    # --- High similarity without clear mutation class ---
    if similarity >= 0.70 and not signals:
        signals.append(TyposquatSignal(
            signal="high_levenshtein_similarity",
            label=f"High string similarity ({int(similarity*100)}%) to brand '{b}'",
            value=label,
            severity="MEDIUM",
            mutation_class="unrelated",
        ))

    # Determine dominant mutation class (first signal wins)
    dominant = signals[0].mutation_class if signals else "unrelated"
    return TyposquatResult(mutation_class=dominant, signals=signals)
